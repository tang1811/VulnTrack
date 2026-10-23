from django.conf import settings
from django.contrib import messages
from django.contrib.auth import update_session_auth_hash
from django.contrib.auth import views as auth_views
from django.contrib.auth.decorators import login_not_required
from django.db.models import Count, Q
from django.shortcuts import get_object_or_404, redirect, render
from django.utils.decorators import method_decorator

from .forms import LoginForm, UserForm
from .models import User
from .roles import role_required


@method_decorator(login_not_required, name='dispatch')
class LoginView(auth_views.LoginView):
    template_name = 'registration/login.html'
    authentication_form = LoginForm
    redirect_authenticated_user = True

    def get_context_data(self, **kwargs):
        # แสดงกล่องบัญชีทดลองเฉพาะตอนพัฒนา (DEBUG=True)
        return super().get_context_data(show_demo=settings.DEBUG, **kwargs)


def permission_denied(request, exception=None):
    return render(request, '403.html', status=403)


@role_required('manage_users')
def user_list(request):
    users = User.objects.order_by('role', 'username')
    counts = dict(User.objects.values_list('role').annotate(n=Count('id')))
    roles = [
        {'value': value, 'label': label, 'count': counts.get(value, 0)}
        for value, label in User.Role.choices
    ]
    return render(request, 'accounts/user_list.html', {'users': users, 'roles': roles, 'section': 'users'})


@role_required('manage_users')
def user_form(request, pk=None):
    instance = get_object_or_404(User, pk=pk) if pk else None
    form = UserForm(request.POST or None, instance=instance, editor=request.user)
    if request.method == 'POST' and form.is_valid():
        user = form.save()
        if user.pk == request.user.pk and form.cleaned_data.get('password'):
            update_session_auth_hash(request, user)  # เปลี่ยนรหัสผ่านตัวเองแล้วไม่ถูกออกจากระบบ
        messages.success(request, f'บันทึกข้อมูลผู้ใช้ {user.username} เรียบร้อย')
        return redirect('user_list')
    return render(request, 'tracker/form.html', {
        'form': form,
        'title': f'แก้ไขผู้ใช้ {instance.username}' if instance else 'เพิ่มผู้ใช้',
        'back_url': 'user_list',
        'section': 'users',
    })
