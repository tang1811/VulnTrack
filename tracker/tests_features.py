"""ทดสอบฟีเจอร์: ความรุนแรง 1-5, แดชบอร์ดเรียงตามวันที่, ประเภทช่องโหว่, ผู้รับผิดชอบ/ผู้แก้ไข และสิทธิ์ระดับรายการ"""

from datetime import date

from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import TestCase
from django.urls import reverse

from accounts.models import User
from tracker.forms import VulnerabilityForm
from tracker.models import Asset, ImportLog, StatusHistory, Vulnerability, VulnCategory, severity_from_cvss


def upload_csv(client, text):
    return client.post(reverse('import_scan'), {'file': SimpleUploadedFile('scan.csv', text.encode('utf-8'))})


class SeverityLevelTests(TestCase):
    """ข้อ 1: ความรุนแรง 1-5"""

    def setUp(self):
        self.tech = User.objects.create_user('tech', password='x-Pass-12345', role='technician')
        self.asset = Asset.objects.create(hostname='LAB301-PC01', location='ห้องปฏิบัติการ 301')
        self.client.force_login(self.tech)

    def test_cvss_mapping(self):
        self.assertEqual([severity_from_cvss(x) for x in (10, 9.0, 8.9, 7.0, 6.9, 4.0, 3.9, 0.1, 0)],
                         [5, 5, 4, 4, 3, 3, 2, 2, 1])

    def test_import_accepts_numbers_and_legacy_names(self):
        rows = ['CVE-2024-0005,a,5', 'CVE-2024-0004,b,high', 'CVE-2024-0001,c,1', 'CVE-2024-0002,d,INFO',
                'CVE-2024-0006,e,6', 'CVE-2024-0007,f,0', 'CVE-2024-0008,g,4.5']
        upload_csv(self.client, 'cve_id,title,severity,hostname\n' + ''.join(f'{r},LAB301-PC01\n' for r in rows))
        got = dict(Vulnerability.objects.values_list('cve_id', 'severity'))
        self.assertEqual(got, {'CVE-2024-0005': 5, 'CVE-2024-0004': 4, 'CVE-2024-0001': 1, 'CVE-2024-0002': 1})
        self.assertEqual(ImportLog.objects.get().skipped_count, 3)

    def test_json_numeric_severity(self):
        self.client.post(reverse('import_scan'), {'file': SimpleUploadedFile(
            'scan.json', b'[{"cve_id": "CVE-2024-0001", "title": "x", "severity": 2, "hostname": "LAB301-PC01"}]')})
        self.assertEqual(Vulnerability.objects.get().severity, 2)

    def test_list_sorted_most_severe_first_and_filter(self):
        for i, level in enumerate([2, 5, 1, 4, 3]):
            Vulnerability.objects.create(cve_id=f'CVE-2024-100{i}', title='x', severity=level,
                                         asset=self.asset, found_at=date(2026, 9, 1))
        page = self.client.get(reverse('vuln_list')).context['page']
        self.assertEqual([v.severity for v in page.object_list], [5, 4, 3, 2, 1])
        page = self.client.get(reverse('vuln_list') + '?severity=1').context['page']
        self.assertEqual([v.severity for v in page.object_list], [1])
        self.assertEqual(self.client.get(reverse('vuln_list') + '?severity=abc').status_code, 200)

    def test_badge_shows_number_and_label(self):
        Vulnerability.objects.create(cve_id='CVE-2024-2000', title='x', severity=1, asset=self.asset,
                                     found_at=date(2026, 9, 1))
        html = self.client.get(reverse('vuln_list')).content.decode()
        self.assertIn('sev-info', html)
        self.assertIn('<span class="sev-num">1</span>เล็กน้อย', html)


class DashboardLatestTests(TestCase):
    """ข้อ 2: แดชบอร์ดเรียงตามวันที่ล่าสุด"""

    def test_latest_table_newest_first_all_severities(self):
        user = User.objects.create_user('exec', password='x-Pass-12345', role='executive')
        asset = Asset.objects.create(hostname='SRV-1', location='ห้องเซิร์ฟเวอร์')
        for cve, found, level in [('CVE-2024-0001', date(2026, 8, 1), 5), ('CVE-2024-0002', date(2026, 10, 5), 1),
                                  ('CVE-2024-0003', date(2026, 9, 9), 3)]:
            Vulnerability.objects.create(cve_id=cve, title='x', severity=level, asset=asset, found_at=found,
                                         status='fixed' if level == 3 else 'open')
        self.client.force_login(user)
        response = self.client.get(reverse('dashboard'))
        self.assertEqual([v.cve_id for v in response.context['latest']],
                         ['CVE-2024-0002', 'CVE-2024-0003', 'CVE-2024-0001'])
        self.assertContains(response, 'ช่องโหว่ที่พบล่าสุด')
        # ผู้บริหารไม่เห็นลิงก์ไปหน้ารายละเอียด
        self.assertNotContains(response, '/vulnerabilities/')


class CategoryTests(TestCase):
    """ข้อ 5: ประเภทช่องโหว่"""

    def setUp(self):
        self.admin = User.objects.create_user('boss', password='x-Pass-12345', role='admin')
        self.tech = User.objects.create_user('tech', password='x-Pass-12345', role='technician')
        self.asset = Asset.objects.create(hostname='LAB301-PC01', location='ห้องปฏิบัติการ 301')

    def test_default_categories_seeded_by_migration(self):
        self.assertTrue(VulnCategory.objects.filter(code='rce').exists())
        self.assertTrue(VulnCategory.objects.filter(code='other').exists())

    def test_import_by_code_or_name_and_unknown_skipped(self):
        self.client.force_login(self.tech)
        name = VulnCategory.objects.get(code='weak-crypto').name
        upload_csv(self.client, 'cve_id,title,severity,hostname,category\n'
                                'CVE-2024-0001,a,5,LAB301-PC01,RCE\n'
                                f'CVE-2024-0002,b,3,LAB301-PC01,{name}\n'
                                'CVE-2024-0003,c,3,LAB301-PC01,\n'
                                'CVE-2024-0004,d,3,LAB301-PC01,no-such-type\n')
        got = dict(Vulnerability.objects.values_list('cve_id', 'category__code'))
        self.assertEqual(got, {'CVE-2024-0001': 'rce', 'CVE-2024-0002': 'weak-crypto', 'CVE-2024-0003': None})
        self.assertIn('no-such-type', ImportLog.objects.get().errors)

    def test_import_code_takes_precedence_over_name(self):
        """รีวิว: ชื่อของประเภทหนึ่งตรงกับรหัสของอีกประเภท ต้องจับคู่ตามรหัส"""
        VulnCategory.objects.create(code='custom', name='rce')
        self.client.force_login(self.tech)
        upload_csv(self.client, 'cve_id,title,severity,hostname,category\nCVE-2024-0001,a,5,LAB301-PC01,rce\n')
        self.assertEqual(Vulnerability.objects.get().category.code, 'rce')

    def test_inactive_category_not_selectable_but_kept_on_edit(self):
        cat = VulnCategory.objects.get(code='spoofing')
        vuln = Vulnerability.objects.create(cve_id='CVE-2024-0001', title='x', severity=3, asset=self.asset,
                                            found_at=date(2026, 9, 1), category=cat)
        cat.is_active = False
        cat.save()
        self.assertNotIn(cat, VulnerabilityForm(user=self.admin).fields['category'].queryset)
        self.assertIn(cat, VulnerabilityForm(user=self.admin, instance=vuln).fields['category'].queryset)

    def test_form_requires_category(self):
        self.client.force_login(self.tech)
        response = self.client.post(reverse('vuln_create'), {
            'cve_id': 'CVE-2024-3094', 'title': 'XZ', 'severity': '5', 'asset': self.asset.pk,
            'found_at': '2026-10-01'})
        self.assertEqual(response.status_code, 200)
        self.assertFalse(Vulnerability.objects.exists())

    def test_admin_crud_and_protected_delete(self):
        self.client.force_login(self.admin)
        self.client.post(reverse('category_create'), {'name': 'ทดสอบ', 'code': 'Test-Type', 'sort_order': 5,
                                                      'is_active': 'on'})
        cat = VulnCategory.objects.get(code='test-type')
        Vulnerability.objects.create(cve_id='CVE-2024-0001', title='x', severity=3, asset=self.asset,
                                     found_at=date(2026, 9, 1), category=cat)
        self.client.post(reverse('category_delete', args=[cat.pk]))
        self.assertTrue(VulnCategory.objects.filter(pk=cat.pk).exists())
        self.assertEqual(self.client.get(reverse('category_list')).status_code, 200)
        self.assertEqual(self.client.get(reverse('category_delete', args=[cat.pk])).status_code, 200)
        unused = VulnCategory.objects.get(code='other')
        self.client.post(reverse('category_delete', args=[unused.pk]))
        self.assertFalse(VulnCategory.objects.filter(pk=unused.pk).exists())

    def test_technician_cannot_manage_categories(self):
        self.client.force_login(self.tech)
        self.assertEqual(self.client.post(reverse('category_create'), {'name': 'x', 'code': 'x'}).status_code, 403)

    def test_vuln_list_filter_by_category(self):
        rce = VulnCategory.objects.get(code='rce')
        Vulnerability.objects.create(cve_id='CVE-2024-0001', title='x', severity=3, asset=self.asset,
                                     found_at=date(2026, 9, 1), category=rce)
        Vulnerability.objects.create(cve_id='CVE-2024-0002', title='y', severity=3, asset=self.asset,
                                     found_at=date(2026, 9, 1))
        self.client.force_login(self.tech)
        page = self.client.get(reverse('vuln_list') + f'?category={rce.pk}').context['page']
        self.assertEqual([v.cve_id for v in page.object_list], ['CVE-2024-0001'])
        page = self.client.get(reverse('vuln_list') + '?category=none').context['page']
        self.assertEqual([v.cve_id for v in page.object_list], ['CVE-2024-0002'])


class AssignmentTests(TestCase):
    """ข้อ 3-4: ผู้รับผิดชอบ ผู้แก้ไข และสิทธิ์ระดับรายการ"""

    def setUp(self):
        self.admin = User.objects.create_user('boss', password='x-Pass-12345', role='admin')
        self.tech1 = User.objects.create_user('tech1', password='x-Pass-12345', role='technician')
        self.tech2 = User.objects.create_user('tech2', password='x-Pass-12345', role='technician')
        self.exec = User.objects.create_user('exec', password='x-Pass-12345', role='executive')
        self.asset = Asset.objects.create(hostname='SRV-1', location='ห้องเซิร์ฟเวอร์')
        self.vuln = Vulnerability.objects.create(cve_id='CVE-2024-6387', title='x', severity=4, asset=self.asset,
                                                 found_at=date(2026, 9, 1))

    def give(self, user):
        self.vuln.assigned_to = user
        self.vuln.save()

    def status(self, user, status):
        self.client.force_login(user)
        return self.client.post(reverse('vuln_status', args=[self.vuln.pk]), {'status': status})

    def test_fixing_records_fixer_and_reopen_clears(self):
        self.give(self.tech1)
        self.status(self.tech1, 'fixed')
        self.vuln.refresh_from_db()
        self.assertEqual(self.vuln.fixed_by, self.tech1)
        self.status(self.admin, 'open')
        self.vuln.refresh_from_db()
        self.assertIsNone(self.vuln.fixed_by)
        self.assertIsNone(self.vuln.fixed_at)

    def test_starting_unassigned_work_assigns_self(self):
        self.status(self.tech1, 'in_progress')
        self.vuln.refresh_from_db()
        self.assertEqual(self.vuln.assigned_to, self.tech1)

    def test_technician_cannot_change_others_work(self):
        self.give(self.tech1)
        self.status(self.tech2, 'fixed')
        self.vuln.refresh_from_db()
        self.assertEqual(self.vuln.status, 'open')
        self.assertFalse(StatusHistory.objects.exists())
        self.client.force_login(self.tech2)
        self.assertEqual(self.client.get(reverse('vuln_edit', args=[self.vuln.pk])).status_code, 403)
        status_form = f'action="{reverse("vuln_status", args=[self.vuln.pk])}"'
        html = self.client.get(reverse('vuln_detail', args=[self.vuln.pk])).content.decode()
        self.assertNotIn(reverse('vuln_edit', args=[self.vuln.pk]), html)
        self.assertNotIn(status_form, html)
        self.assertNotIn(status_form, self.client.get(reverse('vuln_list')).content.decode())

    def test_admin_can_change_anyones_work_and_fixer_is_admin(self):
        self.give(self.tech1)
        self.status(self.admin, 'fixed')
        self.vuln.refresh_from_db()
        self.assertEqual((self.vuln.status, self.vuln.fixed_by, self.vuln.assigned_to),
                         ('fixed', self.admin, self.tech1))

    def test_claim_and_release(self):
        url = reverse('vuln_assign', args=[self.vuln.pk])
        self.client.force_login(self.tech1)
        self.client.post(url, {'action': 'claim'})
        self.vuln.refresh_from_db()
        self.assertEqual(self.vuln.assigned_to, self.tech1)
        # คนอื่นแย่งรับหรือคืนงานที่มีเจ้าของแล้วไม่ได้
        self.client.force_login(self.tech2)
        self.assertEqual(self.client.post(url, {'action': 'claim'}).status_code, 403)
        self.assertEqual(self.client.post(url, {'action': 'release'}).status_code, 403)
        self.client.force_login(self.tech1)
        self.client.post(url, {'action': 'release'})
        self.vuln.refresh_from_db()
        self.assertIsNone(self.vuln.assigned_to)
        self.assertEqual(self.vuln.history.count(), 2)

    def test_only_admin_assigns_others(self):
        url = reverse('vuln_assign', args=[self.vuln.pk])
        self.client.force_login(self.tech1)
        self.assertEqual(self.client.post(url, {'assigned_to': self.tech2.pk}).status_code, 403)
        self.client.force_login(self.exec)
        self.assertEqual(self.client.post(url, {'action': 'claim'}).status_code, 403)
        self.client.force_login(self.admin)
        self.client.post(url, {'assigned_to': self.tech2.pk, 'note': 'ด่วน'})
        self.vuln.refresh_from_db()
        self.assertEqual(self.vuln.assigned_to, self.tech2)
        self.assertIn('ด่วน', self.vuln.history.get().note)
        # มอบหมายให้ผู้บริหาร (ไม่ใช่ผู้ปฏิบัติงาน) ไม่ได้
        self.client.post(url, {'assigned_to': self.exec.pk})
        self.vuln.refresh_from_db()
        self.assertEqual(self.vuln.assigned_to, self.tech2)

    def test_create_by_technician_assigns_self_admin_can_choose(self):
        rce = VulnCategory.objects.get(code='rce')
        data = {'cve_id': 'CVE-2024-3094', 'title': 'XZ', 'severity': '5', 'category': rce.pk,
                'asset': self.asset.pk, 'found_at': '2026-10-01'}
        self.client.force_login(self.tech1)
        self.client.post(reverse('vuln_create'), {**data, 'assigned_to': self.tech2.pk})
        self.assertEqual(Vulnerability.objects.get(cve_id='CVE-2024-3094').assigned_to, self.tech1)
        self.client.force_login(self.admin)
        self.client.post(reverse('vuln_create'), {**data, 'cve_id': 'CVE-2024-3095', 'assigned_to': self.tech2.pk})
        self.assertEqual(Vulnerability.objects.get(cve_id='CVE-2024-3095').assigned_to, self.tech2)

    def test_editing_does_not_let_technician_reassign(self):
        self.vuln.category = VulnCategory.objects.get(code='rce')
        self.give(self.tech1)
        self.client.force_login(self.tech1)
        self.client.post(reverse('vuln_edit', args=[self.vuln.pk]), {
            'cve_id': self.vuln.cve_id, 'title': 'new title', 'severity': '4', 'category': self.vuln.category_id,
            'asset': self.asset.pk, 'found_at': '2026-09-01', 'assigned_to': self.tech2.pk})
        self.vuln.refresh_from_db()
        self.assertEqual((self.vuln.title, self.vuln.assigned_to), ('new title', self.tech1))

    def test_cannot_release_or_claim_fixed_work(self):
        """รีวิว: คืนงานที่แก้เสร็จแล้วได้ ทำให้คนอื่นเปิดกลับแล้วลบชื่อผู้แก้ไข"""
        self.give(self.tech1)
        self.status(self.tech1, 'fixed')
        url = reverse('vuln_assign', args=[self.vuln.pk])
        self.client.post(url, {'action': 'release'})
        self.status(self.tech2, 'open')
        self.vuln.refresh_from_db()
        self.assertEqual((self.vuln.status, self.vuln.fixed_by, self.vuln.assigned_to),
                         ('fixed', self.tech1, self.tech1))

    def test_admin_edit_form_cannot_change_assignee(self):
        """รีวิว: เปลี่ยนผู้รับผิดชอบผ่านฟอร์มแก้ไขไม่ถูกบันทึกประวัติ — ตอนนี้ต้องใช้หน้ารายละเอียดเท่านั้น"""
        self.vuln.category = VulnCategory.objects.get(code='rce')
        self.give(self.tech1)
        self.client.force_login(self.admin)
        self.assertNotIn('assigned_to', self.client.get(reverse('vuln_edit', args=[self.vuln.pk])).context['form'].fields)
        self.client.post(reverse('vuln_edit', args=[self.vuln.pk]), {
            'cve_id': self.vuln.cve_id, 'title': 'แก้ชื่อ', 'severity': '4', 'category': self.vuln.category_id,
            'asset': self.asset.pk, 'found_at': '2026-09-01', 'assigned_to': self.tech2.pk})
        self.vuln.refresh_from_db()
        self.assertEqual((self.vuln.title, self.vuln.assigned_to), ('แก้ชื่อ', self.tech1))

    def test_edit_does_not_overwrite_status_or_people(self):
        """รีวิว: บันทึกฟอร์มแก้ไขเขียนทับสถานะ/ผู้แก้ไขที่เปลี่ยนไประหว่างนั้น — บันทึกเฉพาะช่องในฟอร์ม"""
        from unittest import mock
        from tracker.forms import VulnerabilityForm as Form
        from tracker.services import change_status
        self.vuln.category = VulnCategory.objects.get(code='rce')
        self.give(self.tech1)
        original = Form.is_valid

        def concurrent_fix(form):
            change_status(self.vuln, 'fixed', self.admin)
            return original(form)

        self.client.force_login(self.tech1)
        with mock.patch.object(Form, 'is_valid', concurrent_fix):
            self.client.post(reverse('vuln_edit', args=[self.vuln.pk]), {
                'cve_id': self.vuln.cve_id, 'title': 'แก้ชื่อ', 'severity': '4',
                'category': self.vuln.category_id, 'asset': self.asset.pk, 'found_at': '2026-09-01'})
        self.vuln.refresh_from_db()
        self.assertEqual((self.vuln.title, self.vuln.status, self.vuln.fixed_by), ('แก้ชื่อ', 'fixed', self.admin))

    def test_history_page_shows_and_filters_assignments(self):
        self.client.force_login(self.admin)
        self.client.post(reverse('vuln_assign', args=[self.vuln.pk]), {'assigned_to': self.tech1.pk})
        self.status(self.admin, 'in_progress')
        self.client.force_login(self.admin)
        self.assertContains(self.client.get(reverse('history')), 'เปลี่ยนผู้รับผิดชอบ')
        rows = self.client.get(reverse('history') + '?status=open').context['page'].object_list
        self.assertEqual(len(rows), 0)
        rows = self.client.get(reverse('history') + '?status=assign').context['page'].object_list
        self.assertEqual(len(rows), 1)

    def test_assignee_filter(self):
        self.give(self.tech1)
        self.client.force_login(self.tech1)
        page = self.client.get(reverse('vuln_list') + '?assignee=me').context['page']
        self.assertEqual(len(page.object_list), 1)
        page = self.client.get(reverse('vuln_list') + '?assignee=none').context['page']
        self.assertEqual(len(page.object_list), 0)

    def test_reports_and_csv_show_people(self):
        self.give(self.tech1)
        self.status(self.tech1, 'fixed')
        self.client.force_login(self.exec)
        response = self.client.get(reverse('reports'))
        self.assertContains(response, 'ผู้รับผิดชอบและผู้แก้ไข')
        self.assertEqual(response.context['people'][0].n_fixed, 1)
        lines = self.client.get(reverse('report_csv')).content.decode('utf-8-sig').splitlines()
        self.assertIn('ผู้แก้ไข', lines[0])
        self.assertIn('tech1', lines[1])
