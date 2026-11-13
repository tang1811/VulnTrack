"""ทดสอบฟีเจอร์ตามใบงาน 5-7: คะแนนความเสี่ยง Likelihood x Impact, cache แดชบอร์ด, bcrypt และกรณีทดสอบ T-01 ถึง T-05"""

from datetime import date

from django.core.cache import cache
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import TestCase
from django.urls import reverse

from accounts.models import User
from tracker.models import Asset, Vulnerability, VulnCategory, risk_level
from tracker.views import dashboard_cache_key


def make_vuln(asset, cve='CVE-2024-0001', **kw):
    data = {'title': 'x', 'severity': 3, 'found_at': date(2026, 9, 1)} | kw
    return Vulnerability.objects.create(cve_id=cve, asset=asset, **data)


class RiskScoreTests(TestCase):
    def setUp(self):
        cache.clear()
        self.tech = User.objects.create_user('tech', password='x-Pass-12345', role='technician')
        self.asset = Asset.objects.create(hostname='LAB301-PC01', location='ห้องปฏิบัติการ 301')
        self.category = VulnCategory.objects.create(code='test-risk', name='ทดสอบความเสี่ยง')
        self.client.force_login(self.tech)

    def form_data(self, **kw):
        return {'cve_id': 'CVE-2024-3094', 'title': 'XZ backdoor', 'severity': 5, 'category': self.category.pk,
                'asset': self.asset.pk, 'found_at': '2026-10-01', 'likelihood': 4, 'impact': 5} | kw

    def test_level_boundaries(self):
        self.assertEqual([risk_level(s)[1] for s in (1, 4, 5, 9, 10, 14, 15, 25)],
                         ['ต่ำ', 'ต่ำ', 'ปานกลาง', 'ปานกลาง', 'สูง', 'สูง', 'วิกฤต', 'วิกฤต'])
        self.assertIsNone(risk_level(None))

    def test_score_is_likelihood_times_impact(self):
        v = make_vuln(self.asset, likelihood=4, impact=3)
        self.assertEqual((v.risk_score, v.risk_level), (12, 'สูง'))
        self.assertIsNone(make_vuln(self.asset, 'CVE-2024-0002').risk_score)

    def test_form_requires_likelihood_and_impact_in_range(self):
        response = self.client.post(reverse('vuln_create'), self.form_data(likelihood='', impact=6))
        self.assertEqual(response.status_code, 200)
        self.assertIn('likelihood', response.context['form'].errors)
        self.assertIn('impact', response.context['form'].errors)
        self.assertFalse(Vulnerability.objects.exists())

    def test_form_saves_and_detail_shows_score(self):
        self.client.post(reverse('vuln_create'), self.form_data())
        v = Vulnerability.objects.get()
        self.assertEqual((v.likelihood, v.impact, v.risk_score), (4, 5, 20))
        html = self.client.get(reverse('vuln_detail', args=[v.pk])).content.decode()
        self.assertIn('คะแนนความเสี่ยง 20 จาก 25', html)

    def test_form_page_has_live_calculator(self):
        html = self.client.get(reverse('vuln_create')).content.decode()
        self.assertIn('data-risk-output', html)
        self.assertIn('data-risk-input="likelihood"', html)
        self.assertIn('data-risk-input="impact"', html)

    def test_list_filter_and_sort_by_risk(self):
        make_vuln(self.asset, 'CVE-2024-0001', likelihood=1, impact=2)   # 2 ต่ำ
        make_vuln(self.asset, 'CVE-2024-0002', likelihood=5, impact=5)   # 25 วิกฤต
        make_vuln(self.asset, 'CVE-2024-0003', likelihood=3, impact=4)   # 12 สูง
        make_vuln(self.asset, 'CVE-2024-0004')                           # ยังไม่ประเมิน
        page = self.client.get(reverse('vuln_list') + '?sort=risk').context['page']
        self.assertEqual([v.cve_id[-1] for v in page.object_list], ['2', '3', '1', '4'])
        page = self.client.get(reverse('vuln_list') + '?risk=high').context['page']
        self.assertEqual([v.cve_id for v in page.object_list], ['CVE-2024-0003'])
        page = self.client.get(reverse('vuln_list') + '?risk=none').context['page']
        self.assertEqual([v.cve_id for v in page.object_list], ['CVE-2024-0004'])

    def test_import_optional_pair(self):
        csv = ('cve_id,title,severity,hostname,likelihood,impact\n'
               'CVE-2024-0001,a,5,LAB301-PC01,5,4\n'
               'CVE-2024-0002,b,3,LAB301-PC01,,\n'
               'CVE-2024-0003,c,3,LAB301-PC01,3,\n'
               'CVE-2024-0004,d,3,LAB301-PC01,0,2\n')
        self.client.post(reverse('import_scan'), {'file': SimpleUploadedFile('scan.csv', csv.encode())})
        got = {c: (l, i) for c, l, i in Vulnerability.objects.values_list('cve_id', 'likelihood', 'impact')}
        self.assertEqual(got, {'CVE-2024-0001': (5, 4), 'CVE-2024-0002': (None, None)})

    def test_report_csv_has_risk_columns(self):
        boss = User.objects.create_user('boss', password='x-Pass-12345', role='admin')
        self.client.force_login(boss)
        make_vuln(self.asset, likelihood=2, impact=3)
        text = self.client.get(reverse('report_csv')).content.decode('utf-8-sig')
        header, row = text.splitlines()[:2]
        self.assertIn('คะแนนความเสี่ยง (1-25)', header)
        self.assertIn(',2,3,6,ปานกลาง,', row)


class DashboardCacheTests(TestCase):
    def setUp(self):
        cache.clear()
        self.boss = User.objects.create_user('boss', password='x-Pass-12345', role='admin')
        self.asset = Asset.objects.create(hostname='LAB301-PC01', location='ห้องปฏิบัติการ 301')
        self.client.force_login(self.boss)

    def kpi(self):
        return self.client.get(reverse('dashboard')).context['kpi']

    def test_second_load_uses_cache(self):
        make_vuln(self.asset, severity=5)
        from django.db import connection
        from django.test.utils import CaptureQueriesContext
        with CaptureQueriesContext(connection) as first:
            self.client.get(reverse('dashboard'))
        self.assertIsNotNone(cache.get(dashboard_cache_key()))
        with CaptureQueriesContext(connection) as second:
            self.client.get(reverse('dashboard'))
        # โหลดครั้งที่สองไม่ต้องคำนวณตัวเลขสรุปใหม่ จึงใช้คำสั่ง SQL น้อยลงชัดเจน
        self.assertLess(len(second), len(first) - 8)

    def test_cache_refreshes_after_any_change(self):
        v = make_vuln(self.asset, severity=5, likelihood=5, impact=5)
        self.assertEqual(self.kpi()['critical'], 1)
        self.client.post(reverse('vuln_status', args=[v.pk]), {'status': 'fixed', 'from_status': 'open'})
        self.assertEqual(self.kpi()['critical'], 0)
        make_vuln(self.asset, 'CVE-2024-0002', severity=5)
        self.assertEqual(self.kpi()['critical'], 1)
        Vulnerability.objects.get(cve_id='CVE-2024-0002').delete()
        self.assertEqual(self.kpi()['critical'], 0)

    def test_risk_summary_counts_pending_only(self):
        make_vuln(self.asset, 'CVE-2024-0001', likelihood=5, impact=4)
        make_vuln(self.asset, 'CVE-2024-0002', likelihood=5, impact=4, status='fixed')
        make_vuln(self.asset, 'CVE-2024-0003')
        ctx = self.client.get(reverse('dashboard')).context
        self.assertEqual({r['slug']: r['count'] for r in ctx['risk']}, {'critical': 1, 'high': 0, 'medium': 0, 'low': 0})
        self.assertEqual(ctx['risk_unassessed'], 1)

    def test_my_pending_is_not_shared_between_users(self):
        tech = User.objects.create_user('tech', password='x-Pass-12345', role='technician')
        make_vuln(self.asset, assigned_to=tech)
        self.assertEqual(self.client.get(reverse('dashboard')).context['my_pending'], 0)
        self.client.force_login(tech)
        self.assertEqual(self.client.get(reverse('dashboard')).context['my_pending'], 1)


class WorksheetTestCases(TestCase):
    """กรณีทดสอบตามใบงานที่ 6 (T-01 ถึง T-05)"""

    def setUp(self):
        cache.clear()
        self.tech = User.objects.create_user('tech', password='x-Pass-12345', role='technician')
        self.exec = User.objects.create_user('exec', password='x-Pass-12345', role='executive')
        self.asset = Asset.objects.create(hostname='LAB301-PC01', location='ห้องปฏิบัติการ 301')
        self.category = VulnCategory.objects.create(code='test-ws', name='ทดสอบใบงาน')

    def post_vuln(self, title):
        return self.client.post(reverse('vuln_create'), {
            'cve_id': 'CVE-2024-0001', 'title': title, 'severity': 4, 'category': self.category.pk,
            'asset': self.asset.pk, 'found_at': '2026-10-01', 'likelihood': 3, 'impact': 4})

    def test_t01_create_and_show_in_list(self):
        self.client.force_login(self.tech)
        self.post_vuln('Apache path traversal')
        self.assertContains(self.client.get(reverse('vuln_list')), 'Apache path traversal')

    def test_t02_script_is_escaped(self):
        self.client.force_login(self.tech)
        self.post_vuln('<script>alert(1)</script>')
        v = Vulnerability.objects.get()
        for url in (reverse('vuln_list'), reverse('vuln_detail', args=[v.pk]), reverse('dashboard')):
            html = self.client.get(url).content.decode()
            self.assertNotIn('<script>alert(1)</script>', html)
            self.assertIn('&lt;script&gt;alert(1)&lt;/script&gt;', html)

    def test_t03_other_roles_get_403(self):
        self.client.force_login(self.tech)
        self.assertEqual(self.client.get(reverse('user_list')).status_code, 403)
        v = make_vuln(self.asset)
        self.assertEqual(self.client.get(reverse('vuln_delete', args=[v.pk])).status_code, 403)
        self.client.force_login(self.exec)
        self.assertEqual(self.client.get(reverse('vuln_list')).status_code, 403)
        self.client.logout()
        self.assertEqual(self.client.get(reverse('vuln_list')).status_code, 302)

    def test_t04_password_stored_as_bcrypt_hash(self):
        password = User.objects.get(username='tech').password
        self.assertTrue(password.startswith('bcrypt_sha256$'))
        self.assertNotIn('x-Pass-12345', password)
        self.assertTrue(User.objects.get(username='tech').check_password('x-Pass-12345'))

    def test_t04_old_pbkdf2_password_upgraded_on_login(self):
        from django.contrib.auth.hashers import make_password
        User.objects.filter(username='tech').update(password=make_password('x-Pass-12345', hasher='pbkdf2_sha256'))
        self.assertTrue(self.client.login(username='tech', password='x-Pass-12345'))
        self.assertTrue(User.objects.get(username='tech').password.startswith('bcrypt_sha256$'))

    def test_t05_dashboard_updates_after_new_vuln(self):
        self.client.force_login(self.tech)
        self.assertEqual(self.client.get(reverse('dashboard')).context['kpi']['pending'], 0)
        self.post_vuln('new one')
        ctx = self.client.get(reverse('dashboard')).context
        self.assertEqual(ctx['kpi']['pending'], 1)
        self.assertEqual({r['slug']: r['count'] for r in ctx['risk']}['high'], 1)
