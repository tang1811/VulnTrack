from datetime import date
from io import StringIO

from django.core.files.uploadedfile import SimpleUploadedFile
from django.core.management import call_command
from django.test import TestCase
from django.urls import reverse

from accounts.models import User
from tracker.models import Asset, ImportLog, StatusHistory, Vulnerability, VulnCategory


class StatusChangeTests(TestCase):
    def setUp(self):
        self.tech = User.objects.create_user('tech', password='x-Pass-12345', role='technician')
        self.asset = Asset.objects.create(hostname='SRV-WEB-01', location='ห้องเซิร์ฟเวอร์')
        self.vuln = Vulnerability.objects.create(cve_id='CVE-2024-6387', title='regreSSHion', severity=4,
                                                 asset=self.asset, found_at=date(2026, 9, 1))
        self.cat = VulnCategory.objects.get(code='rce')
        self.client.force_login(self.tech)

    def test_status_change_records_history(self):
        self.client.post(reverse('vuln_status', args=[self.vuln.pk]), {'status': 'in_progress', 'note': 'เริ่มแพตช์'})
        self.client.post(reverse('vuln_status', args=[self.vuln.pk]), {'status': 'fixed', 'note': 'อัปเดต OpenSSH 9.8p1'})
        self.vuln.refresh_from_db()
        self.assertEqual(self.vuln.status, 'fixed')
        self.assertIsNotNone(self.vuln.fixed_at)
        steps = list(StatusHistory.objects.order_by('changed_at').values_list('old_status', 'new_status', 'changed_by'))
        self.assertEqual(steps, [('open', 'in_progress', self.tech.pk), ('in_progress', 'fixed', self.tech.pk)])

    def test_reopen_clears_fixed_at(self):
        self.client.post(reverse('vuln_status', args=[self.vuln.pk]), {'status': 'fixed'})
        self.client.post(reverse('vuln_status', args=[self.vuln.pk]), {'status': 'open'})
        self.vuln.refresh_from_db()
        self.assertIsNone(self.vuln.fixed_at)

    def test_invalid_status_ignored(self):
        self.client.post(reverse('vuln_status', args=[self.vuln.pk]), {'status': 'hacked'})
        self.vuln.refresh_from_db()
        self.assertEqual(self.vuln.status, 'open')
        self.assertFalse(StatusHistory.objects.exists())

    def test_open_redirect_blocked(self):
        response = self.client.post(reverse('vuln_status', args=[self.vuln.pk]),
                                    {'status': 'in_progress', 'next': '//evil.example.com/'})
        self.assertEqual(response['Location'], reverse('vuln_detail', args=[self.vuln.pk]))

    def test_stale_page_does_not_overwrite_newer_status(self):
        self.client.post(reverse('vuln_status', args=[self.vuln.pk]), {'status': 'fixed', 'from_status': 'open'})
        # หน้าเก่ายังเห็นเป็น "ยังไม่แก้ไข" แล้วกด "เริ่มแก้ไข"
        self.client.post(reverse('vuln_status', args=[self.vuln.pk]), {'status': 'in_progress', 'from_status': 'open'})
        self.vuln.refresh_from_db()
        self.assertEqual(self.vuln.status, 'fixed')
        self.assertIsNotNone(self.vuln.fixed_at)
        self.assertEqual(StatusHistory.objects.count(), 1)

    def test_future_found_at_rejected(self):
        response = self.client.post(reverse('vuln_create'), {
            'cve_id': 'CVE-2024-3094', 'title': 'XZ', 'severity': '5', 'category': self.cat.pk, 'asset': self.asset.pk,
            'found_at': '2999-01-01'})
        self.assertEqual(response.status_code, 200)
        self.assertFalse(Vulnerability.objects.filter(cve_id='CVE-2024-3094').exists())

    def test_get_not_allowed_for_status_change(self):
        response = self.client.get(reverse('vuln_status', args=[self.vuln.pk]))
        self.assertEqual(response.status_code, 405)

    def test_create_vuln_records_history_and_rejects_duplicate(self):
        data = {'cve_id': 'cve-2024-3094', 'title': 'XZ backdoor', 'severity': '5', 'category': self.cat.pk, 'cvss_score': '10.0',
                'asset': self.asset.pk, 'found_at': '2026-10-01'}
        self.client.post(reverse('vuln_create'), data)
        vuln = Vulnerability.objects.get(cve_id='CVE-2024-3094')
        self.assertEqual(vuln.history.count(), 1)
        response = self.client.post(reverse('vuln_create'), data)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(Vulnerability.objects.filter(cve_id='CVE-2024-3094').count(), 1)


class ImportTests(TestCase):
    def setUp(self):
        self.tech = User.objects.create_user('tech', password='x-Pass-12345', role='technician')
        Asset.objects.create(hostname='LAB301-PC01', location='ห้องปฏิบัติการ 301')
        self.client.force_login(self.tech)

    def upload(self, name, content):
        return self.client.post(reverse('import_scan'), {'file': SimpleUploadedFile(name, content.encode('utf-8'))})

    def test_csv_import_skips_bad_rows(self):
        csv_text = (
            'cve_id,title,severity,cvss_score,hostname,found_at\n'
            'CVE-2024-38063,IPv6 RCE,critical,9.8,lab301-pc01,2026-10-01\n'
            'CVE-2024-38063,IPv6 RCE,critical,9.8,LAB301-PC01,2026-10-01\n'
            'BAD-ID,Bad,high,,LAB301-PC01,\n'
            'CVE-2023-4863,libwebp,urgent,,LAB301-PC01,\n'
            'CVE-2023-4863,libwebp,high,8.8,UNKNOWN-PC,\n'
        )
        self.upload('scan.csv', csv_text)
        log = ImportLog.objects.get()
        self.assertEqual((log.total_rows, log.created_count, log.skipped_count), (5, 1, 4))
        self.assertEqual(Vulnerability.objects.count(), 1)

    def test_json_import(self):
        self.upload('scan.json', '{"vulnerabilities": [{"cve_id": "CVE-2024-6387", "title": "OpenSSH", '
                                 '"severity": "HIGH", "hostname": "LAB301-PC01"}]}')
        self.assertEqual(Vulnerability.objects.get().severity, 4)

    def test_long_cve_and_bad_values_are_skipped_not_crashing(self):
        self.upload('scan.csv', (
            'cve_id,title,severity,cvss_score,hostname,found_at\n'
            'CVE-2024-123456789012345,Too long,low,,LAB301-PC01,\n'
            'CVE-2024-38063,ok,high,"9,8",LAB301-PC01,\n'
            'CVE-2024-6387,bad score,high,abc,LAB301-PC01,\n'
            'CVE-2023-4863,future,high,,LAB301-PC01,2999-01-01\n'
        ))
        log = ImportLog.objects.get()
        self.assertEqual((log.created_count, log.skipped_count), (1, 3))
        self.assertEqual(str(Vulnerability.objects.get().cvss_score), '9.8')
        self.assertIn('บรรทัด 2', log.errors)

    def test_cvss_zero_kept(self):
        self.upload('scan.json', '[{"cve_id": "CVE-2024-0001", "title": "x", "severity": "low", '
                                 '"cvss_score": 0, "hostname": "LAB301-PC01"}]')
        self.assertEqual(Vulnerability.objects.get().cvss_score, 0)

    def test_json_object_without_key_is_error(self):
        response = self.upload('scan.json', '{"items": []}')
        self.assertContains(response, 'vulnerabilities')
        self.assertFalse(ImportLog.objects.exists())

    def test_rejects_other_file_types(self):
        response = self.upload('scan.exe', 'MZ')
        self.assertContains(response, 'รองรับเฉพาะไฟล์ .csv และ .json')
        self.assertFalse(ImportLog.objects.exists())

    def test_csv_missing_columns(self):
        response = self.upload('scan.csv', 'cve,name\nCVE-2024-1,x\n')
        self.assertContains(response, 'ขาดคอลัมน์')


class DemoDataTests(TestCase):
    def test_seed_and_render_all_pages(self):
        call_command('seed_demo', '--reset', stdout=StringIO())
        self.assertGreater(Vulnerability.objects.count(), 50)
        admin = User.objects.get(username='admin')
        self.client.force_login(admin)
        vuln = Vulnerability.objects.first()
        for url in [reverse('dashboard'), reverse('vuln_list') + '?status=pending&severity=5',
                    reverse('vuln_detail', args=[vuln.pk]), reverse('asset_list'),
                    reverse('asset_detail', args=[vuln.asset_id]), reverse('reports'), reverse('history'),
                    reverse('user_list'), reverse('import_scan')]:
            self.assertEqual(self.client.get(url).status_code, 200, url)
        csv_response = self.client.get(reverse('report_csv'))
        self.assertTrue(csv_response.content.startswith('﻿'.encode('utf-8')))
