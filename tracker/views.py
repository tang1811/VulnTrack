import csv
from datetime import date

from django.contrib import messages
from django.contrib.auth import get_user_model
from django.core.exceptions import PermissionDenied
from django.core.cache import cache
from django.core.paginator import Paginator
from django.db.models import Count, F, Max, Q
from django.db import transaction
from django.db.models.deletion import ProtectedError
from django.http import HttpResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone
from django.utils.http import url_has_allowed_host_and_scheme
from django.views.decorators.http import require_POST

from accounts.roles import ASSIGNABLE_ROLES, can_work_on, has_perm, role_required

from .forms import AssetForm, AssignForm, CategoryForm, ImportForm, StatusForm, VulnerabilityForm, assignable_users
from .models import (RISK_LEVELS, SEVERITY_ORDER, SEVERITY_SLUG, Asset, ImportLog, Severity, Status, StatusHistory,
                     Vulnerability, VulnCategory)
from .services import (CHANGED, CONFLICT, FORBIDDEN, IMPORT_COLUMNS, assign, change_status, import_scan_file,
                       record_created)

THAI_MONTHS = ['ม.ค.', 'ก.พ.', 'มี.ค.', 'เม.ย.', 'พ.ค.', 'มิ.ย.', 'ก.ค.', 'ส.ค.', 'ก.ย.', 'ต.ค.', 'พ.ย.', 'ธ.ค.']
PENDING = [Status.OPEN, Status.IN_PROGRESS]  # ยังแก้ไม่เสร็จ


# ความรุนแรงเป็นตัวเลข 1-5 เรียงจากมากไปน้อยได้ตรง ๆ
BY_SEVERITY = ('-severity', '-cvss_score')


def severity_counts(qs):
    counts = dict(qs.values_list('severity').annotate(n=Count('id')))
    return [{'value': s.value, 'slug': SEVERITY_SLUG[s], 'label': s.label, 'count': counts.get(s.value, 0)}
            for s in SEVERITY_ORDER]


def vuln_queryset():
    return Vulnerability.objects.select_related('asset', 'category', 'assigned_to', 'fixed_by')


def with_risk(qs):
    """เพิ่มคอลัมน์ risk = Likelihood x Impact ให้ใช้กรอง/เรียงในฐานข้อมูล (ยังไม่ประเมิน = NULL)"""
    return qs.annotate(risk=F('likelihood') * F('impact'))


# ช่วงคะแนนของแต่ละระดับความเสี่ยง {slug: (ต่ำสุด, สูงสุด)} ใช้กรองรายการ
RISK_RANGES = {slug: (minimum, (RISK_LEVELS[i - 1][0] - 1) if i else 25)
               for i, (minimum, slug, _label) in enumerate(RISK_LEVELS)}


def risk_counts(qs):
    """จำนวนช่องโหว่แยกตามระดับความเสี่ยง (เรียงจากมากไปน้อย) และจำนวนที่ยังไม่ประเมิน"""
    agg = with_risk(qs).aggregate(
        unassessed=Count('id', filter=Q(risk__isnull=True)),
        **{slug: Count('id', filter=Q(risk__gte=lo, risk__lte=hi)) for slug, (lo, hi) in RISK_RANGES.items()},
    )
    levels = [{'slug': slug, 'label': label, 'min': minimum, 'max': RISK_RANGES[slug][1], 'count': agg[slug]}
              for minimum, slug, label in RISK_LEVELS]
    return levels, agg['unassessed']


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

DASHBOARD_CACHE_SECONDS = 300


def dashboard_cache_key():
    """
    คีย์ cache ของตัวเลขสรุปบนแดชบอร์ด ผูกกับจำนวนและเวลาแก้ไขล่าสุดของช่องโหว่/อุปกรณ์
    เมื่อมีการเพิ่ม แก้ไข ลบ เปลี่ยนสถานะ หรือนำเข้าไฟล์ คีย์จะเปลี่ยนเอง จึงไม่แสดงข้อมูลเก่า
    (ใส่วันที่ด้วย เพื่อให้ตัวเลข "เดือนนี้" และแนวโน้ม 6 เดือนเปลี่ยนตามวันจริง)
    """
    v = Vulnerability.objects.aggregate(n=Count('id'), last=Max('updated_at'))
    a = Asset.objects.aggregate(n=Count('id'), last=Max('updated_at'))
    stamp = lambda d: d.isoformat() if d else '-'  # noqa: E731
    return (f'dashboard:v1:{timezone.localdate().isoformat()}:'
            f'{v["n"]}:{stamp(v["last"])}:{a["n"]}:{stamp(a["last"])}')


def dashboard_summary():
    """ตัวเลขสรุปที่ทุกคนเห็นเหมือนกัน (คำนวณหนักที่สุดของหน้า) เก็บใน cache ไว้ 5 นาที"""
    key = dashboard_cache_key()
    summary = cache.get(key)
    if summary is None:
        summary = _build_dashboard_summary()
        cache.set(key, summary, DASHBOARD_CACHE_SECONDS)
    return summary


def _build_dashboard_summary():
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
        'severity': {'labels': [s['label'] for s in sev], 'data': [s['count'] for s in sev],
                     'keys': [s['slug'] for s in sev]},
        'locations': {
            'labels': [loc for loc, _ in top_locs],
            'series': [
                {'label': s.label, 'key': SEVERITY_SLUG[s], 'data': [counts[s.value] for _, counts in top_locs]}
                for s in SEVERITY_ORDER
            ],
        },
        'trend': {
            'labels': [f'{THAI_MONTHS[m - 1]} {str(y + 543)[2:]}' for y, m in months],
            'found': [found_by[k] for k in months],
            'fixed': [fixed_by[k] for k in months],
        },
    }

    risk, risk_unassessed = risk_counts(pending)

    return {
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
        'risk': risk,
        'risk_unassessed': risk_unassessed,
        'chart': chart,
        'last_update': all_vulns.order_by('-updated_at').values_list('updated_at', flat=True).first(),
    }


@role_required('view_dashboard')
def dashboard(request):
    pending = Vulnerability.objects.filter(status__in=PENDING)
    # รายการด่วน: ระดับ 4-5 ที่ยังค้าง เรียงตามความรุนแรง แล้วตามคะแนนความเสี่ยง (Likelihood x Impact)
    priority = (with_risk(pending.filter(severity__gte=Severity.HIGH)).select_related('asset', 'assigned_to')
                .order_by('-severity', F('risk').desc(nulls_last=True), '-cvss_score', 'found_at')[:8])
    # ช่องโหว่ล่าสุด เรียงตามวันที่พบใหม่สุดก่อน (วันเดียวกันเรียงตามเวลาที่บันทึก)
    latest = vuln_queryset().order_by('-found_at', '-created_at')[:10]

    context = {
        **dashboard_summary(),
        'section': 'dashboard',
        'priority': priority,
        'latest': latest,
        # ข้อมูลเฉพาะผู้ใช้ และจำนวนที่เปลี่ยนได้โดยไม่แตะ updated_at (เช่น ลบผู้ใช้ -> SET_NULL) ไม่เก็บใน cache
        'my_pending': pending.filter(assigned_to=request.user).count(),
        'unassigned': pending.filter(assigned_to__isnull=True).count(),
    }
    return render(request, 'tracker/dashboard.html', context)


# ---------- ช่องโหว่ ----------

@role_required('view_vulns')
def vuln_list(request):
    qs = with_risk(vuln_queryset())
    f = {k: request.GET.get(k, '').strip()
         for k in ('q', 'severity', 'risk', 'status', 'category', 'assignee', 'location', 'asset', 'sort')}
    if f['q']:
        qs = qs.filter(Q(cve_id__icontains=f['q']) | Q(title__icontains=f['q']) | Q(asset__hostname__icontains=f['q']))
    if f['severity'].isdigit() and int(f['severity']) in Severity.values:
        qs = qs.filter(severity=int(f['severity']))
    if f['risk'] == 'none':
        qs = qs.filter(risk__isnull=True)
    elif f['risk'] in RISK_RANGES:
        lo, hi = RISK_RANGES[f['risk']]
        qs = qs.filter(risk__gte=lo, risk__lte=hi)
    if f['status'] == 'pending':
        qs = qs.filter(status__in=PENDING)
    elif f['status'] in Status.values:
        qs = qs.filter(status=f['status'])
    if f['category'] == 'none':
        qs = qs.filter(category__isnull=True)
    elif f['category'].isdigit():
        qs = qs.filter(category_id=int(f['category']))
    if f['assignee'] == 'me':
        qs = qs.filter(assigned_to=request.user)
    elif f['assignee'] == 'none':
        qs = qs.filter(assigned_to__isnull=True)
    elif f['assignee'].isdigit():
        qs = qs.filter(assigned_to_id=int(f['assignee']))
    if f['location']:
        qs = qs.filter(asset__location=f['location'])
    if f['asset'].isdigit():
        qs = qs.filter(asset_id=int(f['asset']))
    sorts = {
        'severity': (*BY_SEVERITY, '-found_at'),
        'risk': (F('risk').desc(nulls_last=True), '-severity', '-cvss_score', '-found_at'),
        'newest': ('-found_at', '-created_at'),
        'updated': ('-updated_at',),
        'host': ('asset__hostname', '-severity'),
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
        'risk_levels': [(slug, label, RISK_RANGES[slug]) for _minimum, slug, label in RISK_LEVELS],
        'statuses': Status.choices,
        'categories': VulnCategory.objects.all(),
        'assignees': assignable_users(),
        'locations': Asset.objects.order_by('location').values_list('location', flat=True).distinct(),
        'has_filter': any(f[k] for k in ('q', 'severity', 'risk', 'status', 'category', 'assignee', 'location',
                                         'asset')),
    })


@role_required('view_vulns')
def vuln_detail(request, pk):
    vuln = get_object_or_404(vuln_queryset().select_related('created_by'), pk=pk)
    return render(request, 'tracker/vuln_detail.html', {
        'section': 'vulns',
        'v': vuln,
        'history': vuln.history.select_related('changed_by'),
        'status_form': StatusForm(initial={'status': vuln.status, 'from_status': vuln.status}),
        'can_work': can_work_on(request.user, vuln),
        'assign_form': (AssignForm(current_id=vuln.assigned_to_id, initial={'assigned_to': vuln.assigned_to_id})
                        if has_perm(request.user, 'assign_vulns') else None),
    })


def _redirect_back(request, pk):
    next_url = request.POST.get('next')
    if next_url and url_has_allowed_host_and_scheme(next_url, allowed_hosts={request.get_host()},
                                                    require_https=request.is_secure()):
        return redirect(next_url)
    return redirect('vuln_detail', pk=pk)


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
        elif result == FORBIDDEN:
            owner = vuln.assigned_to.display_name if vuln.assigned_to else 'ผู้อื่น'
            messages.error(request, f'{vuln.cve_id} มอบหมายให้ {owner} แล้ว '
                                    'คุณเปลี่ยนสถานะได้เฉพาะงานของตัวเองหรืองานที่ยังไม่มีผู้รับผิดชอบ')
        elif result == CONFLICT:
            messages.warning(request, f'{vuln.cve_id} ถูกเปลี่ยนเป็น "{vuln.get_status_display()}" โดยผู้อื่นไปแล้ว '
                                      'จึงไม่ได้บันทึกซ้ำ โปรดตรวจสอบอีกครั้ง')
        else:
            messages.info(request, 'สถานะเหมือนเดิม ไม่มีการเปลี่ยนแปลง')
    else:
        messages.error(request, 'ข้อมูลสถานะไม่ถูกต้อง')
    return _redirect_back(request, pk)


@require_POST
@role_required('edit_vulns')
def vuln_assign(request, pk):
    """
    ผู้ดูแลระบบ: มอบหมาย/เปลี่ยน/ยกเลิกผู้รับผิดชอบ
    เจ้าหน้าที่เทคนิค: action=claim รับงานที่ยังไม่มีผู้รับผิดชอบ, action=release คืนงานของตัวเอง
    """
    vuln = get_object_or_404(Vulnerability, pk=pk)
    action = request.POST.get('action')
    if action in ('claim', 'release') and vuln.status == Status.FIXED:
        # งานที่แก้ไขเสร็จแล้วรับ/คืนไม่ได้ กันการคืนงานแล้วให้คนอื่นเปิดกลับมาลบชื่อผู้แก้ไข
        messages.error(request, f'{vuln.cve_id} แก้ไขเสร็จแล้ว รับหรือคืนงานไม่ได้')
        return _redirect_back(request, pk)
    if action == 'claim':
        if not can_work_on(request.user, vuln) or request.user.role not in ASSIGNABLE_ROLES:
            raise PermissionDenied
        changed = assign(vuln, request.user, request.user, 'รับงานเอง', only_if_unassigned=True, allow_fixed=False)
    elif action == 'release':
        if vuln.assigned_to_id != request.user.pk:
            raise PermissionDenied
        changed = assign(vuln, None, request.user, 'คืนงาน', expected_assignee_id=request.user.pk,
                         allow_fixed=False)
    else:
        if not has_perm(request.user, 'assign_vulns'):
            raise PermissionDenied
        form = AssignForm(request.POST, current_id=vuln.assigned_to_id)
        if not form.is_valid():
            messages.error(request, 'เลือกผู้รับผิดชอบไม่ถูกต้อง')
            return _redirect_back(request, pk)
        changed = assign(vuln, form.cleaned_data['assigned_to'], request.user, form.cleaned_data['note'])
    vuln.refresh_from_db()
    if changed:
        who = vuln.assigned_to.display_name if vuln.assigned_to else 'ไม่มี'
        messages.success(request, f'{vuln.cve_id}: ผู้รับผิดชอบ = {who} และบันทึกลงประวัติแล้ว')
    elif action == 'claim' and vuln.assigned_to_id != request.user.pk:
        messages.warning(request, f'{vuln.cve_id} มีผู้รับงานไปก่อนแล้ว')
    else:
        messages.info(request, 'ผู้รับผิดชอบเหมือนเดิม ไม่มีการเปลี่ยนแปลง')
    return _redirect_back(request, pk)


@role_required('edit_vulns')
def vuln_form(request, pk=None):
    instance = get_object_or_404(Vulnerability, pk=pk) if pk else None
    if instance and not can_work_on(request.user, instance):
        raise PermissionDenied
    initial = {'found_at': timezone.localdate()}
    if request.GET.get('asset', '').isdigit():
        initial['asset'] = int(request.GET['asset'])
    form = VulnerabilityForm(request.POST or None, instance=instance, initial=initial, user=request.user)
    if request.method == 'POST' and form.is_valid():
        with transaction.atomic():
            if instance:
                # ตรวจสิทธิ์ซ้ำบนแถวที่ล็อกแล้ว กันกรณีถูกมอบหมายให้คนอื่นระหว่างส่งฟอร์ม
                locked = Vulnerability.objects.select_for_update().get(pk=instance.pk)
                if not can_work_on(request.user, locked):
                    raise PermissionDenied
            vuln = form.save(commit=False)
            if instance:
                vuln.save(update_fields=[*form.fields, 'updated_at'])
            else:
                vuln.created_by = request.user
                # เจ้าหน้าที่ที่บันทึกช่องโหว่เองเป็นผู้รับผิดชอบโดยอัตโนมัติ
                if 'assigned_to' not in form.fields and request.user.role in ASSIGNABLE_ROLES:
                    vuln.assigned_to = request.user
                vuln.save()
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
        f'n_{SEVERITY_SLUG[s]}': Count('vulnerabilities', filter=Q(vulnerabilities__severity=s, vulnerabilities__status__in=PENDING))
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
    vulns = (asset.vulnerabilities.select_related('category', 'assigned_to')
             .order_by('status', *BY_SEVERITY))
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
    writer.writerow(['CVE-2024-38063', 'Windows TCP/IP IPv6 Remote Code Execution', '5', '9.8',
                     'LAB301-PC01', timezone.localdate().isoformat(), 'rce', 'ช่องโหว่ในสแตก IPv6',
                     'ติดตั้งแพตช์ KB5041578', '4', '5'])
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
        matrix.append({'value': s.value, 'slug': SEVERITY_SLUG[s], 'label': s.label, 'cells': cells, 'total': row_total,
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

    open_critical = (vulns.filter(status__in=PENDING, severity__gte=Severity.HIGH)
                     .select_related('asset', 'category', 'assigned_to').order_by(*BY_SEVERITY, 'found_at'))

    # สรุปตามประเภทช่องโหว่ (ไม่ระบุประเภท = รายการเก่าก่อนมีการแบ่งประเภท)
    by_category = []
    for row in (vulns.values('category__name')
                .annotate(total=Count('id'), fixed=Count('id', filter=Q(status=Status.FIXED)),
                          high=Count('id', filter=Q(severity__gte=Severity.HIGH, status__in=PENDING)))
                .order_by('-total', 'category__name')):
        row['pending'] = row['total'] - row['fixed']
        row['pct'] = round(row['fixed'] * 100 / row['total']) if row['total'] else 0
        by_category.append(row)

    # ภาระงานรายบุคคล: งานที่รับผิดชอบค้างอยู่ และจำนวนที่แก้ไขเสร็จ
    User = get_user_model()
    people = (User.objects.filter(Q(assigned_vulnerabilities__isnull=False) | Q(fixed_vulnerabilities__isnull=False))
              .distinct()
              .annotate(
                  n_pending=Count('assigned_vulnerabilities', filter=Q(assigned_vulnerabilities__status__in=PENDING),
                                  distinct=True),
                  n_fixed=Count('fixed_vulnerabilities', distinct=True))
              .order_by('-n_pending', '-n_fixed', 'username'))
    unassigned = vulns.filter(status__in=PENDING, assigned_to__isnull=True).count()

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
        'by_category': by_category,
        'people': people,
        'unassigned': unassigned,
        'assets_total': Asset.objects.filter(is_active=True).count(),
    })


@role_required('view_reports')
def report_csv(request):
    response = HttpResponse(content_type='text/csv; charset=utf-8')
    stamp = timezone.localdate().isoformat()
    response['Content-Disposition'] = f'attachment; filename="vulntrack-report-{stamp}.csv"'
    response.write('﻿')  # BOM ให้ Excel อ่านภาษาไทยได้
    writer = csv.writer(response)
    writer.writerow(['รหัส CVE', 'ชื่อช่องโหว่', 'ระดับ (1-5)', 'ระดับความรุนแรง', 'ประเภท', 'CVSS',
                     'Likelihood (1-5)', 'Impact (1-5)', 'คะแนนความเสี่ยง (1-25)', 'ระดับความเสี่ยง', 'อุปกรณ์',
                     'ห้อง/พื้นที่', 'สถานะ', 'ผู้รับผิดชอบ', 'ผู้แก้ไข', 'วันที่พบ', 'วันที่แก้ไขเสร็จ'])
    for v in vuln_queryset().order_by('-severity', 'asset__hostname'):
        writer.writerow([
            v.cve_id, v.title, v.severity, v.get_severity_display(), v.category.name if v.category else '',
            '' if v.cvss_score is None else v.cvss_score,
            v.likelihood or '', v.impact or '', v.risk_score or '', v.risk_level,
            v.asset.hostname, v.asset.location,
            v.get_status_display(), v.assigned_to.display_name if v.assigned_to else '',
            v.fixed_by.display_name if v.fixed_by else '', v.found_at.isoformat(),
            timezone.localtime(v.fixed_at).strftime('%Y-%m-%d %H:%M') if v.fixed_at else '',
        ])
    return response


# ---------- ประวัติการเปลี่ยนสถานะ (ผู้ดูแลระบบ) ----------

@role_required('view_history')
def history(request):
    qs = StatusHistory.objects.select_related('vulnerability__asset', 'changed_by')
    status = request.GET.get('status', '')
    if status == 'assign':
        qs = qs.filter(old_status=F('new_status'))
    elif status in Status.values:
        # ไม่รวมรายการเปลี่ยนผู้รับผิดชอบ (สถานะเดิม = สถานะใหม่)
        qs = qs.filter(new_status=status).exclude(old_status=F('new_status'))
    page = Paginator(qs, 30).get_page(request.GET.get('page'))
    return render(request, 'tracker/history.html', {
        'section': 'history', 'page': page, 'status': status, 'statuses': Status.choices,
        'querystring': f'status={status}' if status else '',
    })


# ---------- ประเภทช่องโหว่ (ผู้ดูแลระบบ) ----------

@role_required('manage_categories')
def category_list(request):
    categories = VulnCategory.objects.annotate(
        n_total=Count('vulnerabilities'),
        n_pending=Count('vulnerabilities', filter=Q(vulnerabilities__status__in=PENDING)),
    )
    return render(request, 'tracker/category_list.html', {
        'section': 'categories', 'categories': categories,
        'uncategorized': Vulnerability.objects.filter(category__isnull=True).count(),
    })


@role_required('manage_categories')
def category_form(request, pk=None):
    instance = get_object_or_404(VulnCategory, pk=pk) if pk else None
    form = CategoryForm(request.POST or None, instance=instance)
    if request.method == 'POST' and form.is_valid():
        category = form.save()
        messages.success(request, f'บันทึกประเภท "{category.name}" เรียบร้อย')
        return redirect('category_list')
    return render(request, 'tracker/form.html', {
        'section': 'categories', 'form': form,
        'title': f'แก้ไขประเภท {instance.name}' if instance else 'เพิ่มประเภทช่องโหว่',
        'back_url': 'category_list',
    })


@role_required('manage_categories')
def category_delete(request, pk):
    category = get_object_or_404(VulnCategory, pk=pk)
    count = category.vulnerabilities.count()
    if request.method == 'POST':
        try:
            category.delete()
        except ProtectedError:
            messages.error(request, 'ลบไม่ได้ เพราะยังมีช่องโหว่ใช้ประเภทนี้อยู่ ให้ปิดการใช้งานแทน')
            return redirect('category_list')
        messages.success(request, f'ลบประเภท "{category.name}" แล้ว')
        return redirect('category_list')
    return render(request, 'tracker/confirm_delete.html', {
        'section': 'categories', 'object_label': category.name, 'blocked': count > 0,
        'warning': (f'มีช่องโหว่ใช้ประเภทนี้อยู่ {count} รายการ ลบไม่ได้ ให้แก้ไขแล้วปิด "ใช้งานอยู่" แทน'
                    if count else 'การลบไม่สามารถย้อนกลับได้'),
        'cancel_name': 'category_list',
    })


def home(request):
    return redirect('dashboard')
