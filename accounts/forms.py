from django import forms
from django.contrib.auth.forms import AuthenticationForm
from django.contrib.auth.password_validation import validate_password

from .models import User


class LoginForm(AuthenticationForm):
    username = forms.CharField(label='ชื่อผู้ใช้', widget=forms.TextInput(attrs={'autofocus': True, 'autocomplete': 'username'}))
    password = forms.CharField(label='รหัสผ่าน', strip=False, widget=forms.PasswordInput(attrs={'autocomplete': 'current-password'}))

    error_messages = {
        'invalid_login': 'ชื่อผู้ใช้หรือรหัสผ่านไม่ถูกต้อง',
        'inactive': 'บัญชีนี้ถูกระงับการใช้งาน',
    }


class UserForm(forms.ModelForm):
    password = forms.CharField(
        label='รหัสผ่าน', required=False, strip=False, widget=forms.PasswordInput(attrs={'autocomplete': 'new-password'}),
        help_text='อย่างน้อย 8 ตัวอักษร ไม่ใช่ตัวเลขล้วน (เว้นว่างไว้ถ้าไม่ต้องการเปลี่ยน)',
    )

    class Meta:
        model = User
        fields = ['username', 'first_name', 'last_name', 'email', 'department', 'role', 'is_active']
        labels = {
            'username': 'ชื่อผู้ใช้',
            'first_name': 'ชื่อ',
            'last_name': 'นามสกุล',
            'email': 'อีเมล',
            'is_active': 'เปิดใช้งานบัญชี',
        }
        help_texts = {'username': 'ภาษาอังกฤษ ตัวเลข และ @ . + - _ เท่านั้น'}

    def __init__(self, *args, editor=None, **kwargs):
        super().__init__(*args, **kwargs)
        self.editor = editor
        if not self.instance.pk:
            self.fields['password'].required = True
            self.fields['password'].help_text = 'อย่างน้อย 8 ตัวอักษร ไม่ใช่ตัวเลขล้วน'
        # ห้ามผู้ดูแลลดสิทธิ์หรือปิดบัญชีของตัวเอง กันระบบไม่มีผู้ดูแลเหลืออยู่
        if editor and self.instance.pk == editor.pk:
            self.fields['role'].disabled = True
            self.fields['is_active'].disabled = True

    def clean_password(self):
        password = self.cleaned_data.get('password')
        if password:
            validate_password(password, self.instance)
        return password

    def save(self, commit=True):
        user = super().save(commit=False)
        # สิทธิ์เข้าหน้า Django admin ต้องตรงกับบทบาทเสมอ กันผู้ที่ถูกลดสิทธิ์ยังเข้า /dev-admin/ ได้
        user.is_staff = user.is_superuser = (user.role == User.Role.ADMIN)
        password = self.cleaned_data.get('password')
        if password:
            user.set_password(password)
        if commit:
            user.save()
        return user
