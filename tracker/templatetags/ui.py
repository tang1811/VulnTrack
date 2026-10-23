from django import template
from django.utils import timezone
from django.utils.html import format_html

from tracker.models import Severity, Status

register = template.Library()

THAI_MONTHS = ['ม.ค.', 'ก.พ.', 'มี.ค.', 'เม.ย.', 'พ.ค.', 'มิ.ย.', 'ก.ค.', 'ส.ค.', 'ก.ย.', 'ต.ค.', 'พ.ย.', 'ธ.ค.']

SEVERITY_ICON = {
    'critical': '<polygon points="7.86 2 16.14 2 22 7.86 22 16.14 16.14 22 7.86 22 2 16.14 2 7.86"/><path d="M12 8v4M12 16h.01"/>',
    'high': '<path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3"/><path d="M12 9v4M12 17h.01"/>',
    'medium': '<circle cx="12" cy="12" r="9"/><path d="M12 8v4M12 16h.01"/>',
    'low': '<circle cx="12" cy="12" r="9"/><path d="M12 16v-4M12 8h.01"/>',
}


ICONS = {
    'shield': '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="m9 12 2 2 4-4"/>',
    'shield-alert': '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="M12 8v4M12 16h.01"/>',
    'dashboard': '<rect x="3" y="3" width="7" height="9" rx="1"/><rect x="14" y="3" width="7" height="5" rx="1"/><rect x="14" y="12" width="7" height="9" rx="1"/><rect x="3" y="16" width="7" height="5" rx="1"/>',
    'monitor': '<rect x="2" y="3" width="20" height="14" rx="2"/><path d="M8 21h8M12 17v4"/>',
    'upload': '<path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><path d="m17 8-5-5-5 5M12 3v12"/>',
    'download': '<path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><path d="m7 10 5 5 5-5M12 15V3"/>',
    'report': '<path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><path d="M14 2v6h6M8 13h8M8 17h5"/>',
    'history': '<path d="M3 12a9 9 0 1 0 3-6.7L3 8"/><path d="M3 3v5h5M12 7v5l3 2"/>',
    'users': '<path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M22 21v-2a4 4 0 0 0-3-3.87M16 3.13a4 4 0 0 1 0 7.75"/>',
    'logout': '<path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><path d="m16 17 5-5-5-5M21 12H9"/>',
    'plus': '<path d="M12 5v14M5 12h14"/>',
    'search': '<circle cx="11" cy="11" r="7"/><path d="m21 21-4.3-4.3"/>',
    'edit': '<path d="M12 20h9"/><path d="M16.5 3.5a2.1 2.1 0 0 1 3 3L7 19l-4 1 1-4z"/>',
    'trash': '<path d="M3 6h18M8 6V4h8v2M19 6l-1 14H6L5 6"/>',
    'check': '<circle cx="12" cy="12" r="9"/><path d="m9 12 2 2 4-4"/>',
    'target': '<circle cx="12" cy="12" r="9"/><circle cx="12" cy="12" r="2"/>',
    'alert': '<circle cx="12" cy="12" r="9"/><path d="M12 8v4M12 16h.01"/>',
    'info': '<circle cx="12" cy="12" r="9"/><path d="M12 16v-4M12 8h.01"/>',
    'menu': '<path d="M3 6h18M3 12h18M3 18h18"/>',
    'lock': '<rect x="4" y="11" width="16" height="10" rx="2"/><path d="M8 11V7a4 4 0 0 1 8 0v4"/>',
    'printer': '<path d="M6 9V2h12v7"/><rect x="6" y="14" width="12" height="8"/><path d="M6 18H4a2 2 0 0 1-2-2v-5a2 2 0 0 1 2-2h16a2 2 0 0 1 2 2v5a2 2 0 0 1-2 2h-2"/>',
    'arrow-left': '<path d="M19 12H5M12 19l-7-7 7-7"/>',
    'inbox': '<path d="M22 12h-6l-2 3h-4l-2-3H2"/><path d="M5.45 5.11 2 12v6a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2v-6l-3.45-6.89A2 2 0 0 0 16.76 4H7.24a2 2 0 0 0-1.79 1.11z"/>',
}


@register.simple_tag
def icon(name, cls=''):
    return format_html('<svg class="ico {}" viewBox="0 0 24 24" aria-hidden="true">{}</svg>', cls, format_html(ICONS[name]))


@register.simple_tag
def severity_badge(value):
    label = Severity(value).label if value in Severity.values else value
    return format_html(
        '<span class="badge sev-{}"><svg class="ico" viewBox="0 0 24 24" aria-hidden="true">{}</svg>{}</span>',
        value, format_html(SEVERITY_ICON.get(value, '')), label,
    )


@register.simple_tag
def status_badge(value):
    label = Status(value).label if value in Status.values else value
    return format_html('<span class="pill st-{}"><span class="dot"></span>{}</span>', value, label)


@register.filter
def thai_date(value, with_time=False):
    """แสดงวันที่แบบไทย เช่น 23 ต.ค. 2569"""
    if not value:
        return '-'
    if hasattr(value, 'tzinfo') and hasattr(value, 'hour'):
        value = timezone.localtime(value)
        text = f'{value.day} {THAI_MONTHS[value.month - 1]} {value.year + 543}'
        return f'{text} {value:%H:%M} น.' if with_time else text
    return f'{value.day} {THAI_MONTHS[value.month - 1]} {value.year + 543}'


@register.simple_tag
def page_url(querystring, number):
    return f'?{querystring}&page={number}' if querystring else f'?page={number}'


@register.filter
def percent_of(part, whole):
    return round(part * 100 / whole) if whole else 0
