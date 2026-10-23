from django import forms
from django.utils import timezone

from .models import Asset, Status, Vulnerability


class DateInput(forms.DateInput):
    input_type = 'date'


class VulnerabilityForm(forms.ModelForm):
    class Meta:
        model = Vulnerability
        fields = ['cve_id', 'title', 'severity', 'cvss_score', 'asset', 'found_at', 'description', 'solution']
        widgets = {
            'cve_id': forms.TextInput(attrs={'placeholder': 'CVE-2024-3094', 'class': 'mono'}),
            'found_at': DateInput(),
            'description': forms.Textarea(attrs={'rows': 3}),
            'solution': forms.Textarea(attrs={'rows': 3}),
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
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
