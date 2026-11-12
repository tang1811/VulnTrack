"""
ตารางสิทธิ์ของแต่ละบทบาท (RBAC) — แก้ที่ไฟล์นี้ที่เดียว
ทั้งเมนู ปุ่ม และการตรวจสิทธิ์ฝั่งเซิร์ฟเวอร์อ่านค่าจากตารางนี้
"""

from functools import wraps

from django.core.exceptions import PermissionDenied

ADMIN = 'admin'
TECHNICIAN = 'technician'
EXECUTIVE = 'executive'

PERMISSIONS = {
    'view_dashboard': {ADMIN, TECHNICIAN, EXECUTIVE},
    'view_vulns': {ADMIN, TECHNICIAN},
    'edit_vulns': {ADMIN, TECHNICIAN},     # เพิ่ม/แก้ไขช่องโหว่ และเปลี่ยนสถานะ (ช่างแก้ได้เฉพาะงานของตัวเอง ดู can_work_on)
    'assign_vulns': {ADMIN},               # มอบหมาย/เปลี่ยนผู้รับผิดชอบให้ผู้อื่น
    'work_any_vuln': {ADMIN},              # แก้ไข/เปลี่ยนสถานะงานที่มอบหมายให้คนอื่นได้
    'delete_vulns': {ADMIN},
    'view_assets': {ADMIN, TECHNICIAN},
    'edit_assets': {ADMIN},                # เพิ่ม/แก้ไข/ลบอุปกรณ์
    'import_scans': {ADMIN, TECHNICIAN},
    'view_reports': {ADMIN, EXECUTIVE},
    'view_history': {ADMIN},               # ประวัติการเปลี่ยนสถานะทั้งระบบ
    'manage_users': {ADMIN},
    'manage_categories': {ADMIN},          # เพิ่ม/แก้ไขประเภทช่องโหว่
}

# บทบาทที่รับมอบหมายงานแก้ช่องโหว่ได้
ASSIGNABLE_ROLES = (ADMIN, TECHNICIAN)


def has_perm(user, perm):
    if not user.is_authenticated or not user.is_active:
        return False
    return getattr(user, 'role', None) in PERMISSIONS[perm]


def can_work_on(user, vuln):
    """
    สิทธิ์ระดับรายการ: แก้ไข/เปลี่ยนสถานะช่องโหว่รายการนี้ได้หรือไม่
    ผู้ดูแลระบบทำได้ทุกรายการ ส่วนเจ้าหน้าที่เทคนิคทำได้เฉพาะงานที่มอบหมายให้ตัวเอง หรืองานที่ยังไม่มีผู้รับผิดชอบ
    """
    if not has_perm(user, 'edit_vulns'):
        return False
    if has_perm(user, 'work_any_vuln'):
        return True
    return vuln.assigned_to_id in (None, user.pk)


def user_perms(user):
    return {perm: has_perm(user, perm) for perm in PERMISSIONS}


def role_required(perm):
    """ใส่บน view เพื่อบังคับสิทธิ์ ถ้าไม่มีสิทธิ์จะได้หน้า 403"""
    if perm not in PERMISSIONS:
        raise ValueError(f'ไม่รู้จักสิทธิ์ {perm}')

    def decorator(view):
        @wraps(view)
        def wrapper(request, *args, **kwargs):
            if not has_perm(request.user, perm):
                raise PermissionDenied
            return view(request, *args, **kwargs)
        return wrapper
    return decorator
