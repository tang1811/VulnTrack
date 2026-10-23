from django.conf import settings
from django.core.validators import MaxValueValidator, MinValueValidator, RegexValidator
from django.db import models


class Severity(models.TextChoices):
    CRITICAL = 'critical', 'วิกฤต'
    HIGH = 'high', 'สูง'
    MEDIUM = 'medium', 'ปานกลาง'
    LOW = 'low', 'ต่ำ'


# ลำดับความรุนแรง ใช้เรียงข้อมูลจากรุนแรงมากไปน้อย
SEVERITY_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]


class Status(models.TextChoices):
    OPEN = 'open', 'ยังไม่แก้ไข'
    IN_PROGRESS = 'in_progress', 'กำลังแก้ไข'
    FIXED = 'fixed', 'แก้ไขแล้ว'


class Asset(models.Model):
    class AssetType(models.TextChoices):
        SERVER = 'server', 'เซิร์ฟเวอร์'
        PC = 'pc', 'คอมพิวเตอร์'
        NETWORK = 'network', 'อุปกรณ์เครือข่าย'
        OTHER = 'other', 'อื่น ๆ'

    hostname = models.CharField('ชื่อเครื่อง (Hostname)', max_length=100, unique=True)
    ip_address = models.GenericIPAddressField('IP Address', protocol='IPv4', blank=True, null=True)
    asset_type = models.CharField('ประเภท', max_length=20, choices=AssetType.choices, default=AssetType.PC)
    operating_system = models.CharField('ระบบปฏิบัติการ', max_length=100, blank=True)
    location = models.CharField('ห้อง / พื้นที่', max_length=100)
    owner = models.CharField('ผู้รับผิดชอบ', max_length=100, blank=True)
    is_active = models.BooleanField('ใช้งานอยู่', default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['location', 'hostname']
        verbose_name = 'อุปกรณ์'
        verbose_name_plural = 'อุปกรณ์'

    def __str__(self):
        return self.hostname


cve_validator = RegexValidator(r'^CVE-\d{4}-\d{4,}$', 'รูปแบบต้องเป็น CVE-ปี-เลข เช่น CVE-2024-3094')


class Vulnerability(models.Model):
    """ช่องโหว่ 1 รายการ = CVE 1 ตัวที่พบบนอุปกรณ์ 1 เครื่อง"""

    cve_id = models.CharField('รหัส CVE', max_length=20, validators=[cve_validator])
    title = models.CharField('ชื่อช่องโหว่', max_length=255)
    description = models.TextField('รายละเอียด', blank=True)
    severity = models.CharField('ระดับความรุนแรง', max_length=10, choices=Severity.choices)
    cvss_score = models.DecimalField(
        'คะแนน CVSS', max_digits=3, decimal_places=1, null=True, blank=True,
        validators=[MinValueValidator(0), MaxValueValidator(10)],
    )
    asset = models.ForeignKey(Asset, on_delete=models.PROTECT, related_name='vulnerabilities', verbose_name='อุปกรณ์ที่ได้รับผลกระทบ')
    status = models.CharField('สถานะ', max_length=20, choices=Status.choices, default=Status.OPEN)
    solution = models.TextField('วิธีแก้ไข', blank=True)
    found_at = models.DateField('วันที่พบ')
    fixed_at = models.DateTimeField('วันที่แก้ไขเสร็จ', null=True, blank=True)
    created_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True, related_name='+')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-updated_at']
        verbose_name = 'ช่องโหว่'
        verbose_name_plural = 'ช่องโหว่'
        constraints = [
            models.UniqueConstraint(
                fields=['cve_id', 'asset'], name='unique_cve_per_asset',
                violation_error_message='อุปกรณ์เครื่องนี้มีช่องโหว่ CVE นี้อยู่แล้ว',
            ),
        ]
        indexes = [
            models.Index(fields=['status', 'severity']),
            models.Index(fields=['found_at']),
        ]

    def __str__(self):
        return f'{self.cve_id} @ {self.asset}'


class StatusHistory(models.Model):
    vulnerability = models.ForeignKey(Vulnerability, on_delete=models.CASCADE, related_name='history')
    old_status = models.CharField(max_length=20, choices=Status.choices, blank=True)
    new_status = models.CharField(max_length=20, choices=Status.choices)
    note = models.TextField('หมายเหตุ', blank=True)
    changed_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, related_name='+')
    changed_at = models.DateTimeField()

    class Meta:
        ordering = ['-changed_at']
        verbose_name = 'ประวัติการเปลี่ยนสถานะ'
        verbose_name_plural = 'ประวัติการเปลี่ยนสถานะ'


class ImportLog(models.Model):
    file_name = models.CharField(max_length=255)
    total_rows = models.PositiveIntegerField(default=0)
    created_count = models.PositiveIntegerField(default=0)
    skipped_count = models.PositiveIntegerField(default=0)
    errors = models.TextField(blank=True)
    imported_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, related_name='+')
    imported_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-imported_at']

    @property
    def error_lines(self):
        return [line for line in self.errors.splitlines() if line]
