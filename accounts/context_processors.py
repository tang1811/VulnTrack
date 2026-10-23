from .roles import user_perms


def role_permissions(request):
    """ส่งตัวแปร can ไปทุก template เช่น {% if can.manage_users %} และจำนวน Critical ที่ค้างสำหรับเมนู"""
    can = user_perms(request.user)
    context = {'can': can}
    if can['view_vulns']:
        from tracker.models import Severity, Status, Vulnerability

        context['nav_critical'] = Vulnerability.objects.filter(
            severity=Severity.CRITICAL, status__in=[Status.OPEN, Status.IN_PROGRESS]
        ).count()
    return context
