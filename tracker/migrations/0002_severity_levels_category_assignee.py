"""
1) ระดับความรุนแรงจากข้อความ 4 ระดับ เป็นตัวเลข 1-5 (critical=5, high=4, medium=3, low=2, เพิ่ม 1=เล็กน้อย)
2) ประเภทช่องโหว่ (VulnCategory) พร้อมรายการเริ่มต้น
3) ผู้รับผิดชอบ (assigned_to) และผู้แก้ไข (fixed_by) — ผู้แก้ไขของข้อมูลเดิมดึงจากประวัติการเปลี่ยนสถานะ
"""

import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models

OLD_TO_LEVEL = {'critical': 5, 'high': 4, 'medium': 3, 'low': 2}
LEVEL_TO_OLD = {v: k for k, v in OLD_TO_LEVEL.items()}

# (code, name, description, sort_order)
DEFAULT_CATEGORIES = [
    ('rce', 'การรันโค้ดจากระยะไกล (RCE)', 'ผู้โจมตีสั่งรันโปรแกรมบนเครื่องได้ เช่น buffer overflow, เปิดไฟล์อันตรายแล้วถูกรันโค้ด', 10),
    ('privilege-escalation', 'การยกระดับสิทธิ์', 'ผู้ใช้ทั่วไปได้สิทธิ์ผู้ดูแลระบบหรือ root', 20),
    ('security-bypass', 'การข้ามกลไกความปลอดภัย', 'หลบการตรวจสอบ เช่น SmartScreen, Secure Boot, BitLocker', 30),
    ('web-application', 'เว็บแอปพลิเคชัน', 'SQL Injection, XSS, request smuggling และช่องโหว่ของระบบเว็บ', 40),
    ('weak-crypto', 'การเข้ารหัส / โปรโตคอลไม่ปลอดภัย', 'TLS/SSL/SSH รุ่นเก่า หรือ cipher ที่อ่อนแอ', 50),
    ('denial-of-service', 'การทำให้บริการหยุดทำงาน (DoS)', 'ทำให้ระบบหรือบริการล่มหรือใช้งานไม่ได้', 60),
    ('information-disclosure', 'การเปิดเผยข้อมูล', 'ข้อมูลหรือรหัสผ่านรั่วไหล ตรวจสอบชื่อผู้ใช้ได้', 70),
    ('spoofing', 'การปลอมแปลง', 'หลอกผู้ใช้หรือปลอมตัวตน เช่น ไฟล์ shortcut/ธีมอันตราย', 80),
    ('misconfiguration', 'การตั้งค่าไม่ปลอดภัย', 'เปิดบริการที่ไม่จำเป็น รหัสผ่านเริ่มต้น สิทธิ์ไฟล์ไม่เหมาะสม', 90),
    ('malware-backdoor', 'มัลแวร์ / ประตูหลัง', 'ซอฟต์แวร์ถูกฝังโค้ดอันตราย', 100),
    ('other', 'อื่น ๆ', 'ไม่เข้าประเภทข้างต้น', 999),
]


def severity_forward(apps, schema_editor):
    Vulnerability = apps.get_model('tracker', 'Vulnerability')
    for old, level in OLD_TO_LEVEL.items():
        Vulnerability.objects.filter(severity=old).update(severity_level=level)
    # ค่าที่ไม่รู้จัก (ไม่ควรมี) ให้เป็นระดับปานกลางไว้ก่อน แทนที่จะทำให้ migrate ล้มเหลว
    Vulnerability.objects.filter(severity_level__isnull=True).update(severity_level=3)


def severity_backward(apps, schema_editor):
    Vulnerability = apps.get_model('tracker', 'Vulnerability')
    for level, old in LEVEL_TO_OLD.items():
        Vulnerability.objects.filter(severity_level=level).update(severity=old)
    Vulnerability.objects.filter(severity_level=1).update(severity='low')


def seed_categories_and_fixed_by(apps, schema_editor):
    VulnCategory = apps.get_model('tracker', 'VulnCategory')
    Vulnerability = apps.get_model('tracker', 'Vulnerability')
    StatusHistory = apps.get_model('tracker', 'StatusHistory')
    for code, name, description, order in DEFAULT_CATEGORIES:
        VulnCategory.objects.get_or_create(code=code, defaults={
            'name': name, 'description': description, 'sort_order': order,
        })
    # ผู้แก้ไขของรายการที่แก้ไขแล้ว = คนล่าสุดที่เปลี่ยนสถานะเป็น "แก้ไขแล้ว"
    for vuln in Vulnerability.objects.filter(status='fixed', fixed_by__isnull=True).only('pk'):
        user_id = (StatusHistory.objects.filter(vulnerability_id=vuln.pk, new_status='fixed')
                   .order_by('-changed_at').values_list('changed_by_id', flat=True).first())
        if user_id:
            Vulnerability.objects.filter(pk=vuln.pk).update(fixed_by_id=user_id)


class Migration(migrations.Migration):

    dependencies = [
        ('tracker', '0001_initial'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        # ---- ความรุนแรง 1-5 ----
        migrations.RemoveIndex(model_name='vulnerability', name='tracker_vul_status_1c1912_idx'),
        migrations.AddField(
            model_name='vulnerability', name='severity_level',
            field=models.PositiveSmallIntegerField(null=True),
        ),
        # ให้คอลัมน์เดิมเป็น null ได้ก่อนลบ เพื่อให้ย้อน migration กลับได้ (สร้างคอลัมน์คืนแล้วเติมค่าจาก severity_backward)
        migrations.AlterField(
            model_name='vulnerability', name='severity',
            field=models.CharField(max_length=10, null=True),
        ),
        migrations.RunPython(severity_forward, severity_backward),
        migrations.RemoveField(model_name='vulnerability', name='severity'),
        migrations.RenameField(model_name='vulnerability', old_name='severity_level', new_name='severity'),
        migrations.AlterField(
            model_name='vulnerability', name='severity',
            field=models.PositiveSmallIntegerField(
                choices=[(5, 'วิกฤต'), (4, 'สูง'), (3, 'ปานกลาง'), (2, 'ต่ำ'), (1, 'เล็กน้อย')],
                help_text='5 = วิกฤต, 4 = สูง, 3 = ปานกลาง, 2 = ต่ำ, 1 = เล็กน้อย',
                verbose_name='ระดับความรุนแรง',
            ),
        ),
        migrations.AddIndex(
            model_name='vulnerability',
            index=models.Index(fields=['status', 'severity'], name='tracker_vul_status_1c1912_idx'),
        ),

        # ---- ประเภทช่องโหว่ ----
        migrations.CreateModel(
            name='VulnCategory',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('code', models.SlugField(help_text='ภาษาอังกฤษตัวเล็ก ตัวเลข และ - ใช้อ้างอิงในไฟล์นำเข้า เช่น rce', max_length=40, unique=True, verbose_name='รหัสประเภท')),
                ('name', models.CharField(max_length=100, unique=True, verbose_name='ชื่อประเภท')),
                ('description', models.CharField(blank=True, max_length=255, verbose_name='คำอธิบาย')),
                ('sort_order', models.PositiveSmallIntegerField(default=100, verbose_name='ลำดับการแสดง')),
                ('is_active', models.BooleanField(default=True, help_text='ปิดไว้ถ้าไม่ต้องการให้เลือกประเภทนี้อีก (ข้อมูลเดิมยังอยู่)', verbose_name='ใช้งานอยู่')),
            ],
            options={
                'verbose_name': 'ประเภทช่องโหว่',
                'verbose_name_plural': 'ประเภทช่องโหว่',
                'ordering': ['sort_order', 'name'],
            },
        ),
        migrations.AddField(
            model_name='vulnerability', name='category',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.PROTECT,
                                    related_name='vulnerabilities', to='tracker.vulncategory',
                                    verbose_name='ประเภทช่องโหว่'),
        ),

        # ---- ผู้รับผิดชอบ / ผู้แก้ไข ----
        migrations.AddField(
            model_name='vulnerability', name='assigned_to',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL,
                                    related_name='assigned_vulnerabilities', to=settings.AUTH_USER_MODEL,
                                    verbose_name='ผู้รับผิดชอบ'),
        ),
        migrations.AddField(
            model_name='vulnerability', name='fixed_by',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL,
                                    related_name='fixed_vulnerabilities', to=settings.AUTH_USER_MODEL,
                                    verbose_name='ผู้แก้ไข'),
        ),
        migrations.AddIndex(
            model_name='vulnerability',
            index=models.Index(fields=['assigned_to', 'status'], name='tracker_vul_assigne_208d69_idx'),
        ),
        migrations.RunPython(seed_categories_and_fixed_by, migrations.RunPython.noop),
    ]
