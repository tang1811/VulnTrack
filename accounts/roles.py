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
    'edit_vulns': {ADMIN, TECHNICIAN},     # เพิ่ม/แก้ไขช่องโหว่ และเปลี่ยนสถานะ
    'delete_vulns': {ADMIN},
    'view_assets': {ADMIN, TECHNICIAN},
    'edit_assets': {ADMIN},                # เพิ่ม/แก้ไข/ลบอุปกรณ์
    'import_scans': {ADMIN, TECHNICIAN},
    'view_reports': {ADMIN, EXECUTIVE},
    'view_history': {ADMIN},               # ประวัติการเปลี่ยนสถานะทั้งระบบ
    'manage_users': {ADMIN},
}


def has_perm(user, perm):
    if not user.is_authenticated or not user.is_active:
        return False
    return getattr(user, 'role', None) in PERMISSIONS[perm]


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
