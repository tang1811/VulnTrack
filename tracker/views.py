import csv
from datetime import date

from django.contrib import messages
from django.core.paginator import Paginator
from django.db.models import Case, Count, IntegerField, Q, Value, When
from django.db.models.deletion import ProtectedError
from django.http import HttpResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone
from django.utils.http import url_has_allowed_host_and_scheme
from django.views.decorators.http import require_POST

from accounts.roles import role_required

from .forms import AssetForm, ImportForm, StatusForm, VulnerabilityForm
from .models import SEVERITY_ORDER, Asset, ImportLog, Severity, Status, StatusHistory, Vulnerability
from .services import CHANGED, CONFLICT, IMPORT_COLUMNS, change_status, import_scan_file, record_created

THAI_MONTHS = ['ม.ค.', 'ก.พ.', 'มี.ค.', 'เม.ย.', 'พ.ค.', 'มิ.ย.', 'ก.ค.', 'ส.ค.', 'ก.ย.', 'ต.ค.', 'พ.ย.', 'ธ.ค.']
PENDING = [Status.OPEN, Status.IN_PROGRESS]  # ยังแก้ไม่เสร็จ


def severity_rank():
    return Case(
        *[When(severity=s, then=Value(i)) for i, s in enumerate(SEVERITY_ORDER)],
        output_field=IntegerField(),
    )


def severity_counts(qs):
    counts = dict(qs.values_list('severity').annotate(n=Count('id')))
    return [{'value': s.value, 'label': s.label, 'count': counts.get(s.value, 0)} for s in SEVERITY_ORDER]


def last_months(n):
    today = timezone.localdate()
    months = []
    y, m = today.year, today.month
    for _ in range(n):
        months.append((y, m))
        m -= 1
        if m == 0:
            y, m = y - 1, 12
    return list(reversed(months))


# ---------- แดชบอร์ด (ทุกบทบาท) ----------

@role_required('view_dashboard')
def dashboard(request):
    all_vulns = Vulnerability.objects.all()
    pending = all_vulns.filter(status__in=PENDING)
    total = all_vulns.count()
    fixed_total = all_vulns.filter(status=Status.FIXED).count()
    now = timezone.localtime()
    month_start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)

    sev = severity_counts(pending)
    sev_map = {s['value']: s['count'] for s in sev}

    # ช่องโหว่ค้างแยกตามห้อง/พื้นที่ (6 อันดับแรก)
    loc_rows = pending.values_list('asset__location', 'severity').annotate(n=Count('id'))
    by_loc = {}
    for loc, s, n in loc_rows:
        by_loc.setdefault(loc, {x.value: 0 for x in SEVERITY_ORDER})[s] = n
    top_locs = sorted(by_loc.items(), key=lambda kv: -sum(kv[1].values()))[:6]

    # แนวโน้ม 6 เดือน: พบใหม่ vs แก้ไขแล้ว
    months = last_months(6)
    first = date(months[0][0], months[0][1], 1)
    found_dates = all_vulns.filter(found_at__gte=first).values_list('found_at', flat=True)
    fixed_dates = all_vulns.filter(fixed_at__isnull=False).values_list('fixed_at', flat=True)
    found_by = {k: 0 for k in months}
    fixed_by = {k: 0 for k in months}
    for d in found_dates:
        if (d.year, d.month) in found_by:
            found_by[(d.year, d.month)] += 1
    for dt in fixed_dates:
        d = timezone.localtime(dt)
        if (d.year, d.month) in fixed_by:
            fixed_by[(d.year, d.month)] += 1

    chart = {
        'severity': {'labels': [s['label'] for s in sev], 'data': [s['count'] for s in sev]},
        'locations': {
            'labels': [loc for loc, _ in top_locs],
            'series': [
                {'label': s.label, 'key': s.value, 'data': [counts[s.value] for _, counts in top_locs]}
                for s in SEVERITY_ORDER
            ],
        },
        'trend': {
            'labels': [f'{THAI_MONTHS[m - 1]} {str(y + 543)[2:]}' for y, m in months],
            'found': [found_by[k] for k in months],
            'fixed': [fixed_by[k] for k in months],
        },
    }

    priority = (pending.filter(severity__in=[Severity.CRITICAL, Severity.HIGH])
                .select_related('asset').annotate(rank=severity_rank())
                .order_by('rank', '-cvss_score', 'found_at')[:8])

    context = {
        'section': 'dashboard',
        'kpi': {
            'critical': sev_map[Severity.CRITICAL],
            'high': sev_map[Severity.HIGH],
            'pending': pending.count(),
            'in_progress': pending.filter(status=Status.IN_PROGRESS).count(),
            'assets_affected': pending.values('asset').distinct().count(),
            'assets_total': Asset.objects.filter(is_active=True).count(),
            'fixed_pct': round(fixed_total * 100 / total) if total else 0,
            'fixed_total': fixed_total,
            'total': total,
            'fixed_this_month': all_vulns.filter(fixed_at__gte=month_start).count(),
        },
        'severity': sev,
        'chart': chart,
        'priority': priority,
        'last_update': all_vulns.order_by('-updated_at').values_list('updated_at', flat=True).first(),
    }
    return render(request, 'tracker/dashboard.html', context)


# ---------- ช่องโหว่ ----------

@role_required('view_vulns')
def vuln_list(request):
    qs = Vulnerability.objects.select_related('asset').annotate(rank=severity_rank())
    f = {k: request.GET.get(k, '').strip() for k in ('q', 'severity', 'status', 'location', 'asset', 'sort')}
    if f['q']:
        qs = qs.filter(Q(cve_id__icontains=f['q']) | Q(title__icontains=f['q']) | Q(asset__hostname__icontains=f['q']))
    if f['severity'] in Severity.values:
        qs = qs.filter(severity=f['severity'])
    if f['status'] == 'pending':
        qs = qs.filter(status__in=PENDING)
    elif f['status'] in Status.values:
        qs = qs.filter(status=f['status'])
    if f['location']:
        qs = qs.filter(asset__location=f['location'])
    if f['asset'].isdigit():
        qs = qs.filter(asset_id=int(f['asset']))
    sorts = {
        'severity': ('rank', '-cvss_score', '-found_at'),
        'newest': ('-found_at', 'rank'),
        'updated': ('-updated_at',),
        'host': ('asset__hostname', 'rank'),
    }
    qs = qs.order_by(*sorts.get(f['sort'], sorts['severity']))
    page = Paginator(qs, 20).get_page(request.GET.get('page'))
    params = request.GET.copy()
    params.pop('page', None)
    return render(request, 'tracker/vuln_list.html', {
        'section': 'vulns',
        'page': page,
        'f': f,
        'querystring': params.urlencode(),
        'severities': Severity.choices,
        'statuses': Status.choices,
        'locations': Asset.objects.order_by('location').values_list('location', flat=True).distinct(),
        'has_filter': any(f[k] for k in ('q', 'severity', 'status', 'location', 'asset')),
    })


@role_required('view_vulns')
def vuln_detail(request, pk):
    vuln = get_object_or_404(Vulnerability.objects.select_related('asset', 'created_by'), pk=pk)
    return render(request, 'tracker/vuln_detail.html', {
        'section': 'vulns',
        'v': vuln,
        'history': vuln.history.select_related('changed_by'),
        'status_form': StatusForm(initial={'status': vuln.status, 'from_status': vuln.status}),
    })


@require_POST
@role_required('edit_vulns')
def vuln_status(request, pk):
    vuln = get_object_or_404(Vulnerability, pk=pk)
    form = StatusForm(request.POST)
    if form.is_valid():
        result, vuln = change_status(vuln, form.cleaned_data['status'], request.user,
                                     form.cleaned_data['note'], form.cleaned_data['from_status'] or None)
        if result == CHANGED:
            messages.success(request, f'อัปเดต {vuln.cve_id} เป็น "{vuln.get_status_display()}" แล้ว และบันทึกลงประวัติเรียบร้อย')
        elif result == CONFLICT:
            messages.warning(request, f'{vuln.cve_id} ถูกเปลี่ยนเป็น "{vuln.get_status_display()}" โดยผู้อื่นไปแล้ว '
                                      'จึงไม่ได้บันทึกซ้ำ โปรดตรวจสอบอีกครั้ง')
        else:
            messages.info(request, 'สถานะเหมือนเดิม ไม่มีการเปลี่ยนแปลง')
    else:
        messages.error(request, 'ข้อมูลสถานะไม่ถูกต้อง')
    next_url = request.POST.get('next')
    if next_url and url_has_allowed_host_and_scheme(next_url, allowed_hosts={request.get_host()},
                                                    require_https=request.is_secure()):
        return redirect(next_url)
    return redirect('vuln_detail', pk=pk)


@role_required('edit_vulns')
def vuln_form(request, pk=None):
    instance = get_object_or_404(Vulnerability, pk=pk) if pk else None
    initial = {'found_at': timezone.localdate()}
    if request.GET.get('asset', '').isdigit():
        initial['asset'] = int(request.GET['asset'])
    form = VulnerabilityForm(request.POST or None, instance=instance, initial=initial)
    if request.method == 'POST' and form.is_valid():
        vuln = form.save(commit=False)
        if not instance:
            vuln.created_by = request.user
        vuln.save()
        if not instance:
            record_created(vuln, request.user)
        messages.success(request, f'บันทึก {vuln.cve_id} เรียบร้อย')
        return redirect('vuln_detail', pk=vuln.pk)
    return render(request, 'tracker/form.html', {
        'section': 'vulns',
        'form': form,
        'title': f'แก้ไขช่องโหว่ {instance.cve_id}' if instance else 'เพิ่มช่องโหว่',
        'back_url': 'vuln_list',
    })


@role_required('delete_vulns')
def vuln_delete(request, pk):
    vuln = get_object_or_404(Vulnerability.objects.select_related('asset'), pk=pk)
    if request.method == 'POST':
        label = str(vuln)
        vuln.delete()
        messages.success(request, f'ลบ {label} แล้ว')
        return redirect('vuln_list')
    return render(request, 'tracker/confirm_delete.html', {
        'section': 'vulns', 'object_label': f'{vuln.cve_id} บน {vuln.asset.hostname}',
        'warning': 'ประวัติการเปลี่ยนสถานะของรายการนี้จะถูกลบไปด้วย',
        'cancel_name': 'vuln_detail', 'cancel_pk': vuln.pk,
    })


# ---------- อุปกรณ์ ----------

def pending_counts():
    return {
        f'n_{s.value}': Count('vulnerabilities', filter=Q(vulnerabilities__severity=s, vulnerabilities__status__in=PENDING))
        for s in SEVERITY_ORDER
    }


@role_required('view_assets')
def asset_list(request):
    qs = Asset.objects.annotate(
        **pending_counts(), n_pending=Count('vulnerabilities', filter=Q(vulnerabilities__status__in=PENDING)),
    )
    f = {k: request.GET.get(k, '').strip() for k in ('q', 'location', 'type')}
    if f['q']:
        qs = qs.filter(Q(hostname__icontains=f['q']) | Q(ip_address__icontains=f['q']) | Q(owner__icontains=f['q']))
    if f['location']:
        qs = qs.filter(location=f['location'])
    if f['type'] in Asset.AssetType.values:
        qs = qs.filter(asset_type=f['type'])
    qs = qs.order_by('-n_critical', '-n_high', '-n_pending', 'hostname')
    page = Paginator(qs, 20).get_page(request.GET.get('page'))
    params = request.GET.copy()
    params.pop('page', None)
    return render(request, 'tracker/asset_list.html', {
        'section': 'assets', 'page': page, 'f': f, 'querystring': params.urlencode(),
        'locations': Asset.objects.order_by('location').values_list('location', flat=True).distinct(),
        'types': Asset.AssetType.choices,
        'has_filter': any(f.values()),
    })


@role_required('view_assets')
def asset_detail(request, pk):
    asset = get_object_or_404(Asset, pk=pk)
    vulns = asset.vulnerabilities.annotate(rank=severity_rank()).order_by('status', 'rank', '-cvss_score')
    return render(request, 'tracker/asset_detail.html', {
        'section': 'assets', 'asset': asset, 'vulns': vulns,
        'severity': severity_counts(asset.vulnerabilities.filter(status__in=PENDING)),
    })


@role_required('edit_assets')
def asset_form(request, pk=None):
    instance = get_object_or_404(Asset, pk=pk) if pk else None
    form = AssetForm(request.POST or None, instance=instance)
    if request.method == 'POST' and form.is_valid():
        asset = form.save()
        messages.success(request, f'บันทึกอุปกรณ์ {asset.hostname} เรียบร้อย')
        return redirect('asset_detail', pk=asset.pk)
    return render(request, 'tracker/form.html', {
        'section': 'assets', 'form': form,
        'title': f'แก้ไขอุปกรณ์ {instance.hostname}' if instance else 'เพิ่มอุปกรณ์',
        'back_url': 'asset_list',
    })


@role_required('edit_assets')
def asset_delete(request, pk):
    asset = get_object_or_404(Asset, pk=pk)
    count = asset.vulnerabilities.count()
    if request.method == 'POST':
        try:
            asset.delete()
        except ProtectedError:
            messages.error(request, 'ลบไม่ได้ เพราะยังมีช่องโหว่ผูกกับอุปกรณ์นี้')
            return redirect('asset_detail', pk=pk)
        messages.success(request, f'ลบอุปกรณ์ {asset.hostname} แล้ว')
        return redirect('asset_list')
    return render(request, 'tracker/confirm_delete.html', {
        'section': 'assets', 'object_label': asset.hostname, 'blocked': count > 0,
        'warning': (f'อุปกรณ์นี้มีช่องโหว่ผูกอยู่ {count} รายการ ต้องลบช่องโหว่ก่อน หรือเปลี่ยนเป็น "เลิกใช้งาน" แทน'
                    if count else 'การลบไม่สามารถย้อนกลับได้'),
        'cancel_name': 'asset_detail', 'cancel_pk': asset.pk,
    })


# ---------- นำเข้าไฟล์ผลสแกน ----------

@role_required('import_scans')
def import_scan(request):
    form = ImportForm(request.POST or None, request.FILES or None)
    result = None
    if request.method == 'POST' and form.is_valid():
        try:
            result = import_scan_file(form.cleaned_data['file'], request.user)
        except ValueError as exc:
            form.add_error('file', str(exc))
        else:
            if result.created_count:
                messages.success(request, f'นำเข้าสำเร็จ {result.created_count} รายการ')
            else:
                messages.warning(request, 'ไม่มีรายการใหม่ถูกนำเข้า')
    return render(request, 'tracker/import.html', {
        'section': 'import', 'form': form, 'result': result, 'columns': IMPORT_COLUMNS,
        'logs': ImportLog.objects.select_related('imported_by')[:10],
    })


@role_required('import_scans')
def import_template(request):
    response = HttpResponse(content_type='text/csv; charset=utf-8')
    response['Content-Disposition'] = 'attachment; filename="vulntrack-import-template.csv"'
    response.write('﻿')
    writer = csv.writer(response)
    writer.writerow(IMPORT_COLUMNS)
    writer.writerow(['CVE-2024-38063', 'Windows TCP/IP IPv6 Remote Code Execution', 'critical', '9.8',
                     'LAB301-PC01', timezone.localdate().isoformat(), 'ช่องโหว่ในสแตก IPv6', 'ติดตั้งแพตช์ KB5041578'])
    return response


# ---------- รายงาน ----------

@role_required('view_reports')
def reports(request):
    vulns = Vulnerability.objects.all()
    total = vulns.count()
    matrix_rows = dict(
        ((s, st), n) for s, st, n in vulns.values_list('severity', 'status').annotate(n=Count('id'))
    )
    matrix = []
    for s in SEVERITY_ORDER:
        cells = [matrix_rows.get((s.value, st.value), 0) for st in Status]
        row_total = sum(cells)
        matrix.append({'value': s.value, 'label': s.label, 'cells': cells, 'total': row_total,
                       'pct': round(cells[2] * 100 / row_total) if row_total else 0})
    status_totals = [sum(r['cells'][i] for r in matrix) for i in range(len(Status))]

    locations = []
    for row in (vulns.values('asset__location')
                .annotate(total=Count('id'), fixed=Count('id', filter=Q(status=Status.FIXED)),
                          critical=Count('id', filter=Q(severity=Severity.CRITICAL, status__in=PENDING)))
                .order_by('asset__location')):
        row['pending'] = row['total'] - row['fixed']
        row['pct'] = round(row['fixed'] * 100 / row['total']) if row['total'] else 0
        locations.append(row)

    # เวลาเฉลี่ยตั้งแต่พบจนแก้ไขเสร็จ (วัน) แยกตามความรุนแรง
    days_by_sev = {s.value: [] for s in SEVERITY_ORDER}
    for s, fd, fx in vulns.filter(status=Status.FIXED, fixed_at__isnull=False).values_list('severity', 'found_at', 'fixed_at'):
        days_by_sev[s].append(max(0, (timezone.localtime(fx).date() - fd).days))
    for row in matrix:
        d = days_by_sev[row['value']]
        row['mttr'] = round(sum(d) / len(d), 1) if d else None
    days = [d for ds in days_by_sev.values() for d in ds]

    open_critical = (vulns.filter(status__in=PENDING, severity__in=[Severity.CRITICAL, Severity.HIGH])
                     .select_related('asset').annotate(rank=severity_rank())
                     .order_by('rank', '-cvss_score', 'found_at'))

    return render(request, 'tracker/reports.html', {
        'section': 'reports',
        'generated_at': timezone.localtime(),
        'total': total,
        'fixed_pct': round(status_totals[2] * 100 / total) if total else 0,
        'status_labels': Status.labels,
        'status_summary': list(zip(Status.labels, status_totals)),
        'matrix': matrix,
        'locations': locations,
        'mttr_all': round(sum(days) / len(days), 1) if days else None,
        'open_critical': open_critical,
        'assets_total': Asset.objects.filter(is_active=True).count(),
    })


@role_required('view_reports')
def report_csv(request):
    response = HttpResponse(content_type='text/csv; charset=utf-8')
    stamp = timezone.localdate().isoformat()
    response['Content-Disposition'] = f'attachment; filename="vulntrack-report-{stamp}.csv"'
    response.write('﻿')  # BOM ให้ Excel อ่านภาษาไทยได้
    writer = csv.writer(response)
    writer.writerow(['รหัส CVE', 'ชื่อช่องโหว่', 'ระดับความรุนแรง', 'CVSS', 'อุปกรณ์', 'ห้อง/พื้นที่',
                     'สถานะ', 'วันที่พบ', 'วันที่แก้ไขเสร็จ'])
    qs = Vulnerability.objects.select_related('asset').annotate(rank=severity_rank()).order_by('rank', 'asset__hostname')
    for v in qs:
        writer.writerow([
            v.cve_id, v.title, v.get_severity_display(), '' if v.cvss_score is None else v.cvss_score,
            v.asset.hostname, v.asset.location,
            v.get_status_display(), v.found_at.isoformat(),
            timezone.localtime(v.fixed_at).strftime('%Y-%m-%d %H:%M') if v.fixed_at else '',
        ])
    return response


# ---------- ประวัติการเปลี่ยนสถานะ (ผู้ดูแลระบบ) ----------

@role_required('view_history')
def history(request):
    qs = StatusHistory.objects.select_related('vulnerability__asset', 'changed_by')
    status = request.GET.get('status', '')
    if status in Status.values:
        qs = qs.filter(new_status=status)
    page = Paginator(qs, 30).get_page(request.GET.get('page'))
    return render(request, 'tracker/history.html', {
        'section': 'history', 'page': page, 'status': status, 'statuses': Status.choices,
        'querystring': f'status={status}' if status else '',
    })


def home(request):
    return redirect('dashboard')
