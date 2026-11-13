"""
สร้างข้อมูลตัวอย่าง (mockup) สำหรับทดลองระบบ
    python manage.py seed_demo          # สร้างข้อมูล (ถ้ายังไม่มี)
    python manage.py seed_demo --reset  # ลบข้อมูลเดิมแล้วสร้างใหม่
รหัส CVE ชื่อ และคะแนน CVSS เป็นข้อมูลจริงจาก NVD ส่วนอุปกรณ์และสถานะเป็นข้อมูลสมมติ
"""

import random
from datetime import datetime, time, timedelta

from django.core.management.base import BaseCommand
from django.db import transaction
from django.utils import timezone

from accounts.models import User
from tracker.models import Asset, ImportLog, Severity, Status, StatusHistory, Vulnerability, VulnCategory, severity_from_cvss

DEMO_PASSWORD = 'Eec@2569demo'

USERS = [
    ('admin', 'สมชาย', 'ใจดี', User.Role.ADMIN, 'งานศูนย์คอมพิวเตอร์และเครือข่าย'),
    ('tech1', 'วิภา', 'ช่างคิด', User.Role.TECHNICIAN, 'ห้องปฏิบัติการคอมพิวเตอร์'),
    ('tech2', 'ธนา', 'ตั้งใจ', User.Role.TECHNICIAN, 'ห้องปฏิบัติการคอมพิวเตอร์'),
    ('exec', 'ประเสริฐ', 'มั่นคง', User.Role.EXECUTIVE, 'ฝ่ายบริหาร'),
]

# (hostname, ip, ประเภท, OS, ห้อง, กลุ่มซอฟต์แวร์)
SERVERS = [
    ('SRV-WEB-01', '10.10.1.10', 'server', 'Ubuntu Server 22.04 LTS', 'ห้องเซิร์ฟเวอร์', 'linux web'),
    ('SRV-MOODLE-01', '10.10.1.11', 'server', 'Ubuntu Server 20.04 LTS', 'ห้องเซิร์ฟเวอร์', 'linux web moodle'),
    ('SRV-DB-01', '10.10.1.20', 'server', 'Ubuntu Server 22.04 LTS', 'ห้องเซิร์ฟเวอร์', 'linux db'),
    ('SRV-FILE-01', '10.10.1.30', 'server', 'Windows Server 2019', 'ห้องเซิร์ฟเวอร์', 'winsrv'),
    ('SRV-AD-01', '10.10.1.31', 'server', 'Windows Server 2022', 'ห้องเซิร์ฟเวอร์', 'winsrv'),
    ('SW-CORE-01', '10.10.0.2', 'network', 'Cisco IOS XE 17.6', 'ห้องเซิร์ฟเวอร์', 'cisco tls'),
    ('FW-EDGE-01', '10.10.0.1', 'network', 'FortiOS 7.2', 'ห้องเซิร์ฟเวอร์', 'forti tls'),
]
LABS = [
    ('LAB301', 'ห้องปฏิบัติการ 301', 10, 'Windows 11 23H2', '10.10.3.'),
    ('LAB302', 'ห้องปฏิบัติการ 302', 10, 'Windows 10 22H2', '10.10.4.'),
    ('LAB303', 'ห้องปฏิบัติการ 303', 8, 'Windows 11 23H2', '10.10.5.'),
    ('LAB201', 'ห้องปฏิบัติการ 201', 8, 'Windows 10 22H2', '10.10.2.'),
    ('OFFICE', 'ห้องสำนักงาน', 5, 'Windows 11 23H2', '10.10.6.'),
    ('LIB', 'ห้องสมุด', 3, 'Windows 10 22H2', '10.10.7.'),
]

# (CVE, ชื่อ, CVSS, กลุ่มที่ได้รับผลกระทบ, คำอธิบาย, วิธีแก้)
CVES = [
    ('CVE-2024-38063', 'Windows TCP/IP IPv6 Remote Code Execution', 9.8, 'win winsrv',
     'ส่งแพ็กเก็ต IPv6 ที่สร้างขึ้นพิเศษเพื่อรันโค้ดจากระยะไกลได้โดยไม่ต้องยืนยันตัวตน', 'ติดตั้งอัปเดตความปลอดภัย Windows เดือนสิงหาคม 2024'),
    ('CVE-2024-21413', 'Microsoft Outlook Remote Code Execution (MonikerLink)', 9.8, 'office',
     'ลิงก์ในอีเมลสามารถข้ามโหมด Protected View และรันโค้ดได้', 'อัปเดต Microsoft Office / Outlook เป็นเวอร์ชันล่าสุด'),
    ('CVE-2023-21716', 'Microsoft Word RTF Remote Code Execution', 9.8, 'office',
     'เปิดไฟล์ RTF ที่สร้างขึ้นพิเศษแล้วถูกรันโค้ดได้', 'อัปเดต Microsoft Office'),
    ('CVE-2023-36884', 'Office and Windows HTML Remote Code Execution', 8.8, 'office',
     'เอกสาร Office ที่แนบมาสามารถรันโค้ดผ่าน HTML ได้', 'ติดตั้งอัปเดตความปลอดภัยของ Windows และ Office'),
    ('CVE-2024-30088', 'Windows Kernel Elevation of Privilege', 7.0, 'win winsrv',
     'ผู้ใช้ทั่วไปยกระดับสิทธิ์เป็น SYSTEM ได้', 'ติดตั้งอัปเดต Windows เดือนมิถุนายน 2024'),
    ('CVE-2024-21338', 'Windows Kernel Elevation of Privilege (appid.sys)', 7.8, 'win winsrv',
     'ช่องโหว่ในไดรเวอร์ AppLocker ทำให้ยกระดับสิทธิ์ได้', 'ติดตั้งอัปเดต Windows เดือนกุมภาพันธ์ 2024'),
    ('CVE-2024-38112', 'Windows MSHTML Platform Spoofing', 7.5, 'win',
     'ไฟล์ .url สามารถเปิด Internet Explorer เพื่อหลอกให้รันไฟล์อันตราย', 'ติดตั้งอัปเดต Windows เดือนกรกฎาคม 2024'),
    ('CVE-2024-21412', 'Internet Shortcut Files Security Feature Bypass', 8.1, 'win',
     'ไฟล์ shortcut ข้ามการแจ้งเตือนความปลอดภัยของ SmartScreen ได้', 'ติดตั้งอัปเดต Windows'),
    ('CVE-2023-36025', 'Windows SmartScreen Security Feature Bypass', 8.8, 'win',
     'ไฟล์ .url ข้ามการตรวจสอบของ SmartScreen ได้', 'ติดตั้งอัปเดต Windows'),
    ('CVE-2024-38178', 'Scripting Engine Memory Corruption', 7.5, 'win',
     'เว็บไซต์อันตรายทำให้หน่วยความจำเสียหายและรันโค้ดได้', 'ติดตั้งอัปเดต Windows'),
    ('CVE-2023-4863', 'libwebp Heap Buffer Overflow (Google Chrome)', 8.8, 'chrome',
     'เปิดรูปภาพ WebP ที่สร้างขึ้นพิเศษแล้วถูกรันโค้ดได้', 'อัปเดต Google Chrome เป็นเวอร์ชัน 116.0.5845.187 ขึ้นไป'),
    ('CVE-2024-7971', 'Google Chrome V8 Type Confusion', 8.8, 'chrome',
     'หน้าเว็บอันตรายทำให้หน่วยความจำ heap เสียหาย', 'อัปเดต Google Chrome เป็นเวอร์ชัน 128.0.6613.84 ขึ้นไป'),
    ('CVE-2023-38831', 'WinRAR Code Execution via ZIP archive', 7.8, 'win',
     'เปิดไฟล์ในไฟล์ ZIP ที่สร้างขึ้นพิเศษแล้วถูกรันสคริปต์', 'อัปเดต WinRAR เป็นเวอร์ชัน 6.23 ขึ้นไป'),
    ('CVE-2023-24932', 'Secure Boot Security Feature Bypass (BlackLotus)', 6.7, 'win winsrv',
     'ผู้ที่มีสิทธิ์ผู้ดูแลเครื่องข้าม Secure Boot ได้', 'ติดตั้งอัปเดตและเปิดใช้การป้องกันตามคู่มือ KB5025885'),
    ('CVE-2024-20666', 'BitLocker Security Feature Bypass', 6.6, 'win',
     'ผู้ที่เข้าถึงเครื่องได้จริงสามารถเข้าถึงข้อมูลที่เข้ารหัสได้', 'อัปเดต WinRE ตามคู่มือ KB5034441'),
    ('CVE-2024-21320', 'Windows Themes Spoofing', 6.5, 'win',
     'ไฟล์ธีมอันตรายทำให้ข้อมูล NTLM รั่วไหล', 'ติดตั้งอัปเดต Windows เดือนมกราคม 2024'),
    ('CVE-2024-38213', 'Windows Mark of the Web Security Feature Bypass', 6.5, 'win',
     'ไฟล์ที่ดาวน์โหลดมาข้ามการตรวจสอบ Mark of the Web ได้', 'ติดตั้งอัปเดต Windows'),
    ('CVE-2024-3094', 'XZ Utils Backdoor (liblzma)', 10.0, 'linux',
     'ไลบรารี liblzma เวอร์ชัน 5.6.0-5.6.1 ถูกฝังโค้ดอันตรายที่กระทบ SSH', 'ดาวน์เกรดหรืออัปเดต xz-utils เป็นเวอร์ชันที่ปลอดภัย'),
    ('CVE-2024-6387', 'OpenSSH regreSSHion Race Condition', 8.1, 'linux',
     'race condition ใน signal handler ของ sshd ทำให้รันโค้ดในฐานะ root ได้', 'อัปเดต OpenSSH เป็นเวอร์ชัน 9.8p1 ขึ้นไป'),
    ('CVE-2023-48795', 'SSH Terrapin Prefix Truncation Attack', 5.9, 'linux cisco',
     'ผู้โจมตีแบบ man-in-the-middle ลดระดับความปลอดภัยของการเชื่อมต่อ SSH ได้', 'อัปเดต OpenSSH และปิด cipher ChaCha20-Poly1305'),
    ('CVE-2016-20012', 'OpenSSH User Enumeration via Public Key', 5.3, 'linux',
     'ผู้โจมตีตรวจสอบได้ว่าชื่อผู้ใช้ใดมีอยู่ในระบบ', 'จำกัดการเข้าถึง SSH เฉพาะเครือข่ายภายใน'),
    ('CVE-2024-1086', 'Linux Kernel netfilter Use-After-Free', 7.8, 'linux',
     'ผู้ใช้ในเครื่องยกระดับสิทธิ์เป็น root ได้', 'อัปเดต Linux kernel และรีบูตเครื่อง'),
    ('CVE-2023-4911', 'glibc Looney Tunables Buffer Overflow', 7.8, 'linux',
     'ตัวแปร GLIBC_TUNABLES ทำให้ยกระดับสิทธิ์ได้', 'อัปเดตแพ็กเกจ glibc'),
    ('CVE-2022-0847', 'Linux Kernel Dirty Pipe', 7.8, 'linux',
     'เขียนทับไฟล์ที่เป็น read-only ได้และยกระดับสิทธิ์', 'อัปเดต Linux kernel เป็นเวอร์ชัน 5.16.11 / 5.15.25 ขึ้นไป'),
    ('CVE-2023-38545', 'curl SOCKS5 Heap Buffer Overflow', 9.8, 'linux',
     'การเชื่อมต่อผ่าน SOCKS5 proxy ทำให้ heap overflow', 'อัปเดต curl เป็นเวอร์ชัน 8.4.0 ขึ้นไป'),
    ('CVE-2023-38546', 'curl Cookie Injection with None File', 3.7, 'linux',
     'ผู้โจมตีแทรก cookie ได้ในเงื่อนไขเฉพาะ', 'อัปเดต curl เป็นเวอร์ชัน 8.4.0 ขึ้นไป'),
    ('CVE-2023-28322', 'curl More POST-after-PUT Confusion', 3.7, 'linux',
     'การใช้ handle ซ้ำอาจส่งข้อมูลผิดคำขอ', 'อัปเดต curl เป็นเวอร์ชัน 8.1.0 ขึ้นไป'),
    ('CVE-2023-0464', 'OpenSSL X.509 Policy Constraints DoS', 7.5, 'linux',
     'ใบรับรองที่สร้างขึ้นพิเศษทำให้ใช้ทรัพยากรจนบริการล่ม', 'อัปเดต OpenSSL'),
    ('CVE-2024-0727', 'OpenSSL PKCS12 NULL Pointer Dereference', 5.5, 'linux',
     'ไฟล์ PKCS12 ที่ผิดรูปแบบทำให้โปรแกรมหยุดทำงาน', 'อัปเดต OpenSSL'),
    ('CVE-2023-44487', 'HTTP/2 Rapid Reset Denial of Service', 7.5, 'web',
     'ส่งคำขอ HTTP/2 แล้วยกเลิกซ้ำ ๆ จนเว็บเซิร์ฟเวอร์ใช้งานไม่ได้', 'อัปเดต Nginx/Apache และจำกัดจำนวน stream'),
    ('CVE-2024-4577', 'PHP-CGI Argument Injection', 9.8, 'web',
     'ส่งพารามิเตอร์ผ่าน URL เพื่อรันโค้ด PHP บนเซิร์ฟเวอร์ได้', 'อัปเดต PHP เป็นเวอร์ชัน 8.3.8 / 8.2.20 ขึ้นไป'),
    ('CVE-2023-25690', 'Apache HTTP Server mod_proxy Request Smuggling', 9.8, 'web',
     'การตั้งค่า RewriteRule บางแบบทำให้ลักลอบส่งคำขอได้', 'อัปเดต Apache HTTP Server เป็นเวอร์ชัน 2.4.56 ขึ้นไป'),
    ('CVE-2021-44228', 'Apache Log4j2 Remote Code Execution (Log4Shell)', 10.0, 'web',
     'ข้อความ JNDI ใน log ทำให้รันโค้ดจากระยะไกลได้', 'อัปเดต Log4j เป็นเวอร์ชัน 2.17.1 ขึ้นไป'),
    ('CVE-2024-43425', 'Moodle Remote Code Execution via Calculated Questions', 9.8, 'moodle',
     'ผู้มีสิทธิ์สร้างแบบทดสอบสามารถรันโค้ดบนเซิร์ฟเวอร์ได้', 'อัปเดต Moodle เป็นเวอร์ชัน 4.4.2 / 4.3.6 ขึ้นไป'),
    ('CVE-2024-21096', 'MySQL Server mysqldump Vulnerability', 4.9, 'db',
     'ช่องโหว่ในโปรแกรม mysqldump กระทบความถูกต้องของข้อมูล', 'อัปเดต MySQL Server เป็นเวอร์ชันล่าสุด'),
    ('CVE-2016-2183', 'SWEET32 Birthday Attack on 3DES (TLS)', 7.5, 'tls winsrv',
     'การใช้ cipher 3DES ทำให้ถอดรหัสข้อมูลบางส่วนได้เมื่อเชื่อมต่อนาน', 'ปิดการใช้ cipher 3DES/DES ในการตั้งค่า TLS'),
    ('CVE-2015-4000', 'TLS Logjam (DHE_EXPORT Downgrade)', 3.7, 'tls',
     'ผู้โจมตีลดระดับการเข้ารหัสเป็น 512-bit ได้', 'ปิด DHE_EXPORT และใช้กลุ่ม DH อย่างน้อย 2048-bit'),
    ('CVE-2014-3566', 'SSLv3 POODLE Padding Oracle', 3.4, 'tls',
     'ถอดรหัสข้อมูลที่ส่งผ่าน SSLv3 ได้', 'ปิดการใช้ SSLv3'),
    ('CVE-2023-20198', 'Cisco IOS XE Web UI Privilege Escalation', 10.0, 'cisco',
     'ผู้โจมตีสร้างบัญชีระดับสูงสุดผ่านหน้า Web UI ได้', 'ปิด HTTP server บนอุปกรณ์ และอัปเดต IOS XE'),
    ('CVE-2024-21762', 'FortiOS SSL VPN Out-of-Bound Write', 9.8, 'forti',
     'ส่งคำขอ HTTP ที่สร้างขึ้นพิเศษไปยัง SSL VPN เพื่อรันโค้ดได้', 'อัปเดต FortiOS เป็นเวอร์ชัน 7.2.7 ขึ้นไป'),
    ('CVE-2023-27997', 'FortiOS SSL VPN Heap Buffer Overflow', 9.8, 'forti',
     'heap overflow ใน SSL VPN ทำให้รันโค้ดจากระยะไกลได้', 'อัปเดต FortiOS เป็นเวอร์ชัน 7.2.5 ขึ้นไป'),
]


# ประเภทของ CVE ตัวอย่าง (รหัสประเภทจาก migration 0002)
CATEGORY_OF = {
    'CVE-2024-38063': 'rce', 'CVE-2024-21413': 'rce', 'CVE-2023-21716': 'rce', 'CVE-2023-36884': 'rce',
    'CVE-2024-30088': 'privilege-escalation', 'CVE-2024-21338': 'privilege-escalation',
    'CVE-2024-38112': 'spoofing', 'CVE-2024-21412': 'security-bypass', 'CVE-2023-36025': 'security-bypass',
    'CVE-2024-38178': 'rce', 'CVE-2023-4863': 'rce', 'CVE-2024-7971': 'rce', 'CVE-2023-38831': 'rce',
    'CVE-2023-24932': 'security-bypass', 'CVE-2024-20666': 'security-bypass', 'CVE-2024-21320': 'spoofing',
    'CVE-2024-38213': 'security-bypass', 'CVE-2024-3094': 'malware-backdoor', 'CVE-2024-6387': 'rce',
    'CVE-2023-48795': 'weak-crypto', 'CVE-2016-20012': 'information-disclosure',
    'CVE-2024-1086': 'privilege-escalation', 'CVE-2023-4911': 'privilege-escalation',
    'CVE-2022-0847': 'privilege-escalation', 'CVE-2023-38545': 'rce', 'CVE-2023-38546': 'web-application',
    'CVE-2023-28322': 'information-disclosure', 'CVE-2023-0464': 'denial-of-service',
    'CVE-2024-0727': 'denial-of-service', 'CVE-2023-44487': 'denial-of-service', 'CVE-2024-4577': 'web-application',
    'CVE-2023-25690': 'web-application', 'CVE-2021-44228': 'rce', 'CVE-2024-43425': 'web-application',
    'CVE-2024-21096': 'other', 'CVE-2016-2183': 'weak-crypto', 'CVE-2015-4000': 'weak-crypto',
    'CVE-2014-3566': 'weak-crypto', 'CVE-2023-20198': 'privilege-escalation', 'CVE-2024-21762': 'rce',
    'CVE-2023-27997': 'rce',
}


class Command(BaseCommand):
    help = 'สร้างข้อมูลตัวอย่างสำหรับทดลองระบบ'

    def add_arguments(self, parser):
        parser.add_argument('--reset', action='store_true', help='ลบข้อมูลเดิมทั้งหมดก่อนสร้างใหม่')

    @transaction.atomic
    def handle(self, *args, reset=False, **options):
        if reset:
            StatusHistory.objects.all().delete()
            ImportLog.objects.all().delete()
            Vulnerability.objects.all().delete()
            Asset.objects.all().delete()
            User.objects.filter(username__in=[u[0] for u in USERS]).delete()
        elif (Vulnerability.objects.exists() or Asset.objects.exists()
              or User.objects.filter(username__in=[u[0] for u in USERS]).exists()):
            self.stdout.write(self.style.WARNING('มีข้อมูลอยู่แล้ว ใช้ --reset ถ้าต้องการลบแล้วสร้างใหม่'))
            return

        rng = random.Random(2569)
        users = {}
        for username, first, last, role, dept in USERS:
            user = User(username=username, first_name=first, last_name=last, role=role, department=dept,
                        email=f'{username}@example.ac.th', is_staff=(role == User.Role.ADMIN),
                        is_superuser=(role == User.Role.ADMIN))
            user.set_password(DEMO_PASSWORD)
            user.save()
            users[username] = user
        staff = [users['admin'], users['tech1'], users['tech2']]
        techs = [users['tech1'], users['tech2']]
        categories = {c.code: c for c in VulnCategory.objects.all()}

        assets = []
        for host, ip, kind, os_name, loc, groups in SERVERS:
            assets.append((Asset.objects.create(hostname=host, ip_address=ip, asset_type=kind, operating_system=os_name,
                                                location=loc, owner='สมชาย ใจดี'), groups))
        for prefix, loc, count, os_name, net in LABS:
            owner = 'วิภา ช่างคิด' if prefix in ('LAB301', 'LAB302', 'LIB') else 'ธนา ตั้งใจ'
            for i in range(1, count + 1):
                asset = Asset.objects.create(hostname=f'{prefix}-PC{i:02d}', ip_address=f'{net}{10 + i}', asset_type='pc',
                                             operating_system=os_name, location=loc, owner=owner)
                assets.append((asset, 'win chrome office'))

        tz = timezone.get_current_timezone()
        today = timezone.localdate()

        now = timezone.now()

        def at(day, hour):
            # ไม่ให้เวลาในข้อมูลตัวอย่างเลยเวลาปัจจุบัน
            return min(now, timezone.make_aware(datetime.combine(day, time(hour, rng.randint(0, 59))), tz))

        created = 0
        for asset, groups in assets:
            group_set = set(groups.split())
            pool = [c for c in CVES if group_set & set(c[3].split())]
            k = rng.randint(3, 6) if asset.asset_type != 'pc' else rng.randint(1, 3)
            for cve, title, score, _, desc, fix in rng.sample(pool, min(k, len(pool))):
                severity = severity_from_cvss(score)
                # ตัวอย่างระดับ 1 (เล็กน้อย): ช่องโหว่ CVSS ต่ำบนอุปกรณ์เครือข่ายที่ประเมินแล้วว่าผลกระทบน้อย
                if score < 4.0 and asset.asset_type == 'network':
                    severity = Severity.INFO
                found = today - timedelta(days=rng.randint(0, 175))
                age = (today - found).days
                fix_chance = min(0.9, age / 120 + (0.25 if severity >= Severity.HIGH else 0))
                roll = rng.random()
                status = Status.FIXED if roll < fix_chance else Status.IN_PROGRESS if roll < fix_chance + 0.15 else Status.OPEN
                # งานที่เริ่มแล้วมีผู้รับผิดชอบเสมอ งานที่ยังไม่เริ่มมอบหมายไว้บางส่วน
                assignee = rng.choice(techs) if status != Status.OPEN or rng.random() < 0.5 else None
                # ประเมินความเสี่ยงตัวอย่าง: โอกาสเกิดตามความรุนแรง ผลกระทบตามความสำคัญของอุปกรณ์
                # ใช้ตัวสุ่มแยก เพื่อไม่ให้ข้อมูลส่วนอื่นเปลี่ยนไปจากเดิม
                risk_rng = random.Random(f'{cve}@{asset.hostname}')
                likelihood = max(1, min(5, int(severity) + risk_rng.choice((-1, 0, 0, 1))))
                base_impact = 4 if asset.asset_type in ('server', 'network') else 2
                impact = max(1, min(5, base_impact + risk_rng.choice((-1, 0, 1))))
                vuln = Vulnerability.objects.create(
                    likelihood=likelihood, impact=impact,
                    cve_id=cve, title=title, description=desc, solution=fix, severity=severity, cvss_score=score,
                    category=categories.get(CATEGORY_OF.get(cve, 'other')),
                    asset=asset, status=status, found_at=found, created_by=rng.choice(staff), assigned_to=assignee,
                )
                history = [('', Status.OPEN, 'บันทึกจากผลการสแกนประจำเดือน', at(found, 9))]
                if status in (Status.IN_PROGRESS, Status.FIXED):
                    start = min(today, found + timedelta(days=rng.randint(0, max(1, age // 3))))
                    history.append((Status.OPEN, Status.IN_PROGRESS, 'กำลังดำเนินการติดตั้งแพตช์', at(start, 13)))
                    if status == Status.FIXED:
                        done = min(today, start + timedelta(days=rng.randint(0, max(1, (today - start).days))))
                        history.append((Status.IN_PROGRESS, Status.FIXED, fix, at(done, 16)))
                        vuln.fixed_at = history[-1][3]
                        vuln.fixed_by = assignee
                        vuln.save(update_fields=['fixed_at', 'fixed_by'])
                for old, new, note, when in history:
                    # ขั้นแรกบันทึกโดยใครก็ได้ ขั้นต่อจากนั้นทำโดยผู้รับผิดชอบ
                    by = assignee if old and assignee else rng.choice(staff)
                    StatusHistory.objects.create(vulnerability=vuln, old_status=old, new_status=new, note=note,
                                                 changed_by=by, changed_at=when)
                created += 1

        self.stdout.write(self.style.SUCCESS(
            f'สร้างผู้ใช้ {len(users)} คน, อุปกรณ์ {len(assets)} เครื่อง, ช่องโหว่ {created} รายการ'
        ))
        self.stdout.write(f'รหัสผ่านของทุกบัญชีตัวอย่าง: {DEMO_PASSWORD}')
