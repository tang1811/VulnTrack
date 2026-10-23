"""ตรรกะหลักที่หลายหน้าใช้ร่วมกัน: เปลี่ยนสถานะ (พร้อมบันทึกประวัติ) และนำเข้าไฟล์ผลสแกน"""

import csv
import io
import json
from datetime import date

from django.db import DatabaseError, transaction
from django.utils import timezone

from .models import Asset, ImportLog, Severity, Status, StatusHistory, Vulnerability, cve_validator

IMPORT_COLUMNS = ['cve_id', 'title', 'severity', 'cvss_score', 'hostname', 'found_at', 'description', 'solution']
REQUIRED_COLUMNS = ['cve_id', 'title', 'severity', 'hostname']
CVE_MAX_LENGTH = Vulnerability._meta.get_field('cve_id').max_length

# ผลลัพธ์ของ change_status
CHANGED, UNCHANGED, CONFLICT = 'changed', 'unchanged', 'conflict'


@transaction.atomic
def change_status(vuln, new_status, user, note='', expected_status=None):
    """
    เปลี่ยนสถานะช่องโหว่และบันทึกประวัติในธุรกรรมเดียวกัน
    expected_status = สถานะที่ผู้ใช้เห็นบนหน้าจอ ถ้ามีคนเปลี่ยนไปก่อนแล้วจะไม่ทับ (คืนค่า CONFLICT)
    """
    vuln = Vulnerability.objects.select_for_update().get(pk=vuln.pk)
    if expected_status and vuln.status != expected_status:
        return CONFLICT, vuln
    if new_status not in Status.values or new_status == vuln.status:
        return UNCHANGED, vuln
    old_status = vuln.status
    vuln.status = new_status
    vuln.fixed_at = timezone.now() if new_status == Status.FIXED else None
    vuln.save(update_fields=['status', 'fixed_at', 'updated_at'])
    StatusHistory.objects.create(
        vulnerability=vuln, old_status=old_status, new_status=new_status,
        note=note, changed_by=user, changed_at=timezone.now(),
    )
    return CHANGED, vuln


def record_created(vuln, user, note='บันทึกช่องโหว่เข้าระบบ'):
    StatusHistory.objects.create(
        vulnerability=vuln, old_status='', new_status=vuln.status,
        note=note, changed_by=user, changed_at=timezone.now(),
    )


def _read_rows(uploaded):
    """คืนค่ารายการ (ตำแหน่งสำหรับแจ้งผู้ใช้, แถวข้อมูล)"""
    raw = uploaded.read()
    try:
        text = raw.decode('utf-8-sig')
    except UnicodeDecodeError:
        raise ValueError('ไฟล์ต้องเข้ารหัส UTF-8')
    name = uploaded.name.lower()
    if name.endswith('.json'):
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            raise ValueError(f'ไฟล์ JSON ไม่ถูกต้อง: {exc.msg} (บรรทัด {exc.lineno})')
        if isinstance(data, dict):
            if not isinstance(data.get('vulnerabilities'), list):
                raise ValueError('ไฟล์ JSON ต้องเป็น array หรือ object ที่มีคีย์ "vulnerabilities" เป็น array')
            data = data['vulnerabilities']
        if not isinstance(data, list) or not all(isinstance(r, dict) for r in data):
            raise ValueError('ไฟล์ JSON ต้องเป็นรายการ (array) ของ object')
        return [(f'รายการที่ {i}', row) for i, row in enumerate(data, start=1)]
    reader = csv.DictReader(io.StringIO(text))
    missing = [c for c in REQUIRED_COLUMNS if c not in (reader.fieldnames or [])]
    if missing:
        raise ValueError('ไฟล์ CSV ขาดคอลัมน์: ' + ', '.join(missing))
    # line_num คือเลขบรรทัดจริงในไฟล์ (นับรวมบรรทัดว่างและข้อความหลายบรรทัด)
    return [(f'บรรทัด {reader.line_num}', row) for row in reader]


def _text(value):
    return '' if value is None else str(value).strip()


def _parse_row(row):
    clean = {k: _text(row.get(k)) for k in IMPORT_COLUMNS}
    for col in REQUIRED_COLUMNS:
        if not clean[col]:
            raise ValueError(f'ไม่มีค่า {col}')
    clean['cve_id'] = clean['cve_id'].upper()
    if len(clean['cve_id']) > CVE_MAX_LENGTH:
        raise ValueError(f'cve_id ยาวเกิน {CVE_MAX_LENGTH} ตัวอักษร')
    cve_validator(clean['cve_id'])
    severity = clean['severity'].lower()
    if severity not in Severity.values:
        raise ValueError(f'severity "{clean["severity"]}" ไม่ถูกต้อง (ใช้ critical, high, medium, low)')
    clean['severity'] = severity
    if clean['cvss_score']:
        try:
            score = float(clean['cvss_score'].replace(',', '.'))
        except ValueError:
            raise ValueError(f'cvss_score "{clean["cvss_score"]}" ไม่ใช่ตัวเลข')
        if not 0 <= score <= 10:
            raise ValueError('cvss_score ต้องอยู่ระหว่าง 0-10')
        clean['cvss_score'] = round(score, 1)
    else:
        clean['cvss_score'] = None
    if clean['found_at']:
        try:
            clean['found_at'] = date.fromisoformat(clean['found_at'])
        except ValueError:
            raise ValueError(f'found_at "{clean["found_at"]}" ต้องเป็นรูปแบบ YYYY-MM-DD')
        if clean['found_at'] > timezone.localdate():
            raise ValueError('found_at เป็นวันในอนาคตไม่ได้')
    else:
        clean['found_at'] = timezone.localdate()
    return clean


def import_scan_file(uploaded, user):
    """นำเข้าไฟล์ CSV/JSON ข้ามแถวที่ผิดรูปแบบหรือซ้ำ แล้วคืนค่า ImportLog"""
    rows = _read_rows(uploaded)
    assets = {a.hostname.lower(): a for a in Asset.objects.all()}
    created, skipped, errors = 0, 0, []
    with transaction.atomic():
        for where, row in rows:
            try:
                data = _parse_row(row)
            except Exception as exc:  # แถวผิดรูปแบบ ข้ามไปแถวถัดไป
                message = getattr(exc, 'messages', [str(exc)])[0]
                errors.append(f'{where}: {message}')
                skipped += 1
                continue
            asset = assets.get(data['hostname'].lower())
            if asset is None:
                errors.append(f'{where}: ไม่พบอุปกรณ์ชื่อ {data["hostname"]} ในระบบ')
                skipped += 1
                continue
            try:
                # savepoint แยกต่อแถว แถวที่บันทึกไม่ได้จะไม่ทำให้ทั้งไฟล์ล้มเหลว
                with transaction.atomic():
                    vuln, is_new = Vulnerability.objects.get_or_create(
                        cve_id=data['cve_id'], asset=asset,
                        defaults={
                            'title': data['title'][:255], 'severity': data['severity'],
                            'cvss_score': data['cvss_score'], 'found_at': data['found_at'],
                            'description': data['description'], 'solution': data['solution'], 'created_by': user,
                        },
                    )
                    if is_new:
                        record_created(vuln, user, f'นำเข้าจากไฟล์ {uploaded.name}')
            except DatabaseError:
                errors.append(f'{where}: บันทึกลงฐานข้อมูลไม่ได้ (ข้อมูลยาวหรือผิดรูปแบบ)')
                skipped += 1
                continue
            if is_new:
                created += 1
            else:
                errors.append(f'{where}: {data["cve_id"]} บน {asset.hostname} มีอยู่แล้ว')
                skipped += 1
        log = ImportLog.objects.create(
            file_name=uploaded.name[:255], total_rows=len(rows), created_count=created,
            skipped_count=skipped, errors='\n'.join(errors[:200]), imported_by=user,
        )
    return log
