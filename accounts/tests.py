from datetime import date

from django.test import TestCase
from django.urls import reverse

from accounts.models import User
from tracker.models import Asset, Vulnerability

ADMIN, TECH, EXEC = 'admin', 'technician', 'executive'

# (ชื่อ url, kwargs, บทบาทที่เข้าได้)
PAGES = [
    ('dashboard', {}, {ADMIN, TECH, EXEC}),
    ('vuln_list', {}, {ADMIN, TECH}),
    ('vuln_detail', {'pk': 'vuln'}, {ADMIN, TECH}),
    ('vuln_create', {}, {ADMIN, TECH}),
    ('vuln_edit', {'pk': 'vuln'}, {ADMIN, TECH}),
    ('vuln_delete', {'pk': 'vuln'}, {ADMIN}),
    ('asset_list', {}, {ADMIN, TECH}),
    ('asset_detail', {'pk': 'asset'}, {ADMIN, TECH}),
    ('asset_create', {}, {ADMIN}),
    ('asset_edit', {'pk': 'asset'}, {ADMIN}),
    ('asset_delete', {'pk': 'asset'}, {ADMIN}),
    ('import_scan', {}, {ADMIN, TECH}),
    ('import_template', {}, {ADMIN, TECH}),
    ('reports', {}, {ADMIN, EXEC}),
    ('report_csv', {}, {ADMIN, EXEC}),
    ('history', {}, {ADMIN}),
    ('user_list', {}, {ADMIN}),
    ('user_create', {}, {ADMIN}),
    ('category_list', {}, {ADMIN}),
    ('category_create', {}, {ADMIN}),
]

# ข้อความเมนูที่ต้องแสดง/ซ่อนตามบทบาท
MENU = {
    'href="/vulnerabilities/"': {ADMIN, TECH},
    'href="/assets/"': {ADMIN, TECH},
    'href="/import/"': {ADMIN, TECH},
    'href="/reports/"': {ADMIN, EXEC},
    'href="/history/"': {ADMIN},
    'href="/users/"': {ADMIN},
    'href="/categories/"': {ADMIN},
}


class RoleAccessTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.users = {role: User.objects.create_user(f'u_{role}', password='x-Pass-12345', role=role) for role in (ADMIN, TECH, EXEC)}
        cls.asset = Asset.objects.create(hostname='LAB301-PC01', location='ห้องปฏิบัติการ 301')
        cls.vuln = Vulnerability.objects.create(cve_id='CVE-2024-3094', title='XZ', severity=5,
                                                asset=cls.asset, found_at=date(2026, 9, 1))

    def url(self, name, kwargs):
        resolved = {k: {'vuln': self.vuln.pk, 'asset': self.asset.pk}[v] for k, v in kwargs.items()}
        return reverse(name, kwargs=resolved)

    def test_anonymous_redirected_to_login(self):
        for name, kwargs, _ in PAGES:
            response = self.client.get(self.url(name, kwargs))
            self.assertEqual(response.status_code, 302, name)
            self.assertIn(reverse('login'), response['Location'])

    def test_page_access_matrix(self):
        for role, user in self.users.items():
            self.client.force_login(user)
            for name, kwargs, allowed in PAGES:
                response = self.client.get(self.url(name, kwargs))
                expected = 200 if role in allowed else 403
                self.assertEqual(response.status_code, expected, f'{role} -> {name}')

    def test_menu_only_shows_allowed_pages(self):
        for role, user in self.users.items():
            self.client.force_login(user)
            html = self.client.get(reverse('dashboard')).content.decode()
            for snippet, allowed in MENU.items():
                if role in allowed:
                    self.assertIn(snippet, html, f'{role} ควรเห็น {snippet}')
                else:
                    self.assertNotIn(snippet, html, f'{role} ไม่ควรเห็น {snippet}')

    def test_executive_dashboard_has_no_edit_controls(self):
        self.client.force_login(self.users[EXEC])
        html = self.client.get(reverse('dashboard')).content.decode()
        self.assertNotIn('/status/', html)
        self.assertNotIn('/vulnerabilities/new/', html)
        self.assertNotIn(f'/vulnerabilities/{self.vuln.pk}/', html)

    def test_technician_cannot_see_delete_or_asset_edit_buttons(self):
        self.client.force_login(self.users[TECH])
        html = self.client.get(reverse('vuln_detail', args=[self.vuln.pk])).content.decode()
        self.assertNotIn(reverse('vuln_delete', args=[self.vuln.pk]), html)
        html = self.client.get(reverse('asset_detail', args=[self.asset.pk])).content.decode()
        self.assertNotIn(reverse('asset_edit', args=[self.asset.pk]), html)

    def test_executive_cannot_change_status_by_post(self):
        self.client.force_login(self.users[EXEC])
        response = self.client.post(reverse('vuln_status', args=[self.vuln.pk]), {'status': 'fixed'})
        self.assertEqual(response.status_code, 403)
        self.vuln.refresh_from_db()
        self.assertEqual(self.vuln.status, 'open')

    def test_technician_cannot_delete_by_post(self):
        self.client.force_login(self.users[TECH])
        response = self.client.post(reverse('vuln_delete', args=[self.vuln.pk]))
        self.assertEqual(response.status_code, 403)
        self.assertTrue(Vulnerability.objects.filter(pk=self.vuln.pk).exists())

    def test_inactive_user_cannot_log_in(self):
        user = self.users[TECH]
        user.is_active = False
        user.save()
        response = self.client.post(reverse('login'), {'username': user.username, 'password': 'x-Pass-12345'})
        self.assertEqual(response.status_code, 200)
        self.assertNotIn('_auth_user_id', self.client.session)


class UserManagementTests(TestCase):
    def setUp(self):
        self.admin = User.objects.create_user('boss', password='x-Pass-12345', role=ADMIN)
        self.client.force_login(self.admin)

    def test_admin_cannot_demote_self(self):
        self.client.post(reverse('user_edit', args=[self.admin.pk]), {
            'username': 'boss', 'role': EXEC, 'is_active': '',
        })
        self.admin.refresh_from_db()
        self.assertEqual(self.admin.role, ADMIN)
        self.assertTrue(self.admin.is_active)

    def test_demoted_admin_loses_django_admin_access(self):
        other = User.objects.create_user('old_admin', password='x-Pass-12345', role=ADMIN,
                                         is_staff=True, is_superuser=True)
        self.client.post(reverse('user_edit', args=[other.pk]), {
            'username': 'old_admin', 'role': TECH, 'is_active': 'on'})
        other.refresh_from_db()
        self.assertEqual(other.role, TECH)
        self.assertFalse(other.is_staff or other.is_superuser)

    def test_changing_own_password_keeps_session(self):
        self.client.post(reverse('user_edit', args=[self.admin.pk]), {
            'username': 'boss', 'role': ADMIN, 'is_active': 'on', 'password': 'New-Admin-Pass-2569'})
        self.assertEqual(self.client.get(reverse('user_list')).status_code, 200)

    def test_create_user_hashes_password(self):
        self.client.post(reverse('user_create'), {
            'username': 'newtech', 'role': TECH, 'is_active': 'on', 'password': 'Lab-Tech-2569',
        })
        user = User.objects.get(username='newtech')
        self.assertTrue(user.check_password('Lab-Tech-2569'))
        self.assertNotEqual(user.password, 'Lab-Tech-2569')

    def test_weak_password_rejected(self):
        response = self.client.post(reverse('user_create'), {'username': 'weak', 'role': TECH, 'password': '12345678'})
        self.assertEqual(response.status_code, 200)
        self.assertFalse(User.objects.filter(username='weak').exists())
