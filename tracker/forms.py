from django import forms
from django.contrib.auth import get_user_model
from django.utils import timezone

from accounts.roles import ASSIGNABLE_ROLES, has_perm

from .models import Asset, Status, Vulnerability, VulnCategory


def assignable_users(current_id=None):
    """ผู้ที่รับมอบหมายงานได้: ผู้ดูแลระบบและเจ้าหน้าที่เทคนิคที่บัญชียังใช้งานอยู่ (รวมคนปัจจุบันไว้ด้วยเสมอ)"""
    User = get_user_model()
    qs = User.objects.filter(is_active=True, role__in=ASSIGNABLE_ROLES)
    if current_id:
        qs = qs | User.objects.filter(pk=current_id)
    return qs.distinct().order_by('first_name', 'username')


class UserChoiceField(forms.ModelChoiceField):
    def label_from_instance(self, obj):
        return f'{obj.display_name} ({obj.get_role_display()})'


class DateInput(forms.DateInput):
    input_type = 'date'


class VulnerabilityForm(forms.ModelForm):
    class Meta:
        model = Vulnerability
        fields = ['cve_id', 'title', 'severity', 'category', 'cvss_score', 'likelihood', 'impact', 'asset',
                  'assigned_to', 'found_at', 'description', 'solution']
        field_classes = {'assigned_to': UserChoiceField}
        widgets = {
            'cve_id': forms.TextInput(attrs={'placeholder': 'CVE-2024-3094', 'class': 'mono'}),
            'found_at': DateInput(),
            'description': forms.Textarea(attrs={'rows': 3}),
            'solution': forms.Textarea(attrs={'rows': 3}),
        }

    def __init__(self, *args, user=None, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['severity'].choices = [('', '— เลือกระดับ —')] + [
            (value, f'{value} - {label}') for value, label in self.fields['severity'].choices if value != ''
        ]
        # ประเมินความเสี่ยงเป็นข้อมูลบังคับเมื่อบันทึกผ่านฟอร์ม (ข้อมูลเก่า/นำเข้าที่ยังไม่ประเมินเว้นว่างได้)
        for name in ('likelihood', 'impact'):
            field = self.fields[name]
            field.required = True
            field.choices = [('', '— เลือก 1-5 —')] + [
                (value, f'{value} - {label}') for value, label in field.choices if value != ''
            ]
            field.widget.attrs['data-risk-input'] = name
        category = self.fields['category']
        category.queryset = VulnCategory.objects.filter(is_active=True) | VulnCategory.objects.filter(
            pk=getattr(self.instance, 'category_id', None)
        )
        category.required = True
        category.empty_label = '— เลือกประเภท —'
        # เลือกผู้รับผิดชอบได้เฉพาะตอนเพิ่มใหม่ และเฉพาะผู้มีสิทธิ์มอบหมายงาน
        # การเปลี่ยนผู้รับผิดชอบภายหลังทำที่หน้ารายละเอียด (services.assign ล็อกแถวและบันทึกประวัติ)
        if user is not None and has_perm(user, 'assign_vulns') and not self.instance.pk:
            self.fields['assigned_to'].queryset = assignable_users(getattr(self.instance, 'assigned_to_id', None))
            self.fields['assigned_to'].empty_label = '— ยังไม่มอบหมาย —'
        else:
            del self.fields['assigned_to']
        self.fields['asset'].queryset = Asset.objects.filter(is_active=True) | Asset.objects.filter(
            pk=getattr(self.instance, 'asset_id', None)
        )

    def clean_cve_id(self):
        return self.cleaned_data['cve_id'].strip().upper()

    def clean_found_at(self):
        found_at = self.cleaned_data['found_at']
        if found_at > timezone.localdate():
            raise forms.ValidationError('วันที่พบเป็นวันในอนาคตไม่ได้')
        fixed_at = self.instance.fixed_at
        if fixed_at and found_at > timezone.localtime(fixed_at).date():
            raise forms.ValidationError('วันที่พบต้องไม่หลังวันที่แก้ไขเสร็จ')
        return found_at


class AssignForm(forms.Form):
    assigned_to = UserChoiceField(label='ผู้รับผิดชอบ', queryset=None, required=False, empty_label='— ยังไม่มอบหมาย —')
    note = forms.CharField(label='หมายเหตุ', required=False, max_length=500)

    def __init__(self, *args, current_id=None, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['assigned_to'].queryset = assignable_users(current_id)


class CategoryForm(forms.ModelForm):
    class Meta:
        model = VulnCategory
        fields = ['name', 'code', 'description', 'sort_order', 'is_active']
        widgets = {'code': forms.TextInput(attrs={'class': 'mono', 'placeholder': 'web-application'})}

    def clean_code(self):
        return self.cleaned_data['code'].strip().lower()

    def clean_name(self):
        return self.cleaned_data['name'].strip()


class AssetForm(forms.ModelForm):
    class Meta:
        model = Asset
        fields = ['hostname', 'ip_address', 'asset_type', 'operating_system', 'location', 'owner', 'is_active']
        widgets = {
            'hostname': forms.TextInput(attrs={'placeholder': 'LAB301-PC01', 'class': 'mono'}),
            'ip_address': forms.TextInput(attrs={'placeholder': '10.10.3.11', 'class': 'mono'}),
        }

    def clean_hostname(self):
        return self.cleaned_data['hostname'].strip().upper()


class StatusForm(forms.Form):
    status = forms.ChoiceField(label='สถานะใหม่', choices=Status.choices, widget=forms.RadioSelect)
    # สถานะที่ผู้ใช้เห็นตอนเปิดหน้า ใช้กันการบันทึกทับเมื่อมีคนเปลี่ยนไปก่อน
    from_status = forms.ChoiceField(choices=Status.choices, required=False, widget=forms.HiddenInput)
    note = forms.CharField(label='หมายเหตุ / สิ่งที่ทำ', required=False, max_length=1000,
                           widget=forms.Textarea(attrs={'rows': 2, 'placeholder': 'เช่น อัปเดตแพตช์ KB5041578 แล้ว'}))


class ImportForm(forms.Form):
    file = forms.FileField(label='ไฟล์ผลสแกน (.csv หรือ .json)')

    def clean_file(self):
        from django.conf import settings

        f = self.cleaned_data['file']
        if not f.name.lower().endswith(('.csv', '.json')):
            raise forms.ValidationError('รองรับเฉพาะไฟล์ .csv และ .json')
        if f.size > settings.MAX_IMPORT_FILE_SIZE:
            raise forms.ValidationError('ไฟล์ต้องมีขนาดไม่เกิน 2 MB')
        return f
