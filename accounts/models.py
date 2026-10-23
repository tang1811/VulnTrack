from django.contrib.auth.models import AbstractUser
from django.db import models


class User(AbstractUser):
    class Role(models.TextChoices):
        ADMIN = 'admin', 'ผู้ดูแลระบบ'
        TECHNICIAN = 'technician', 'เจ้าหน้าที่เทคนิค'
        EXECUTIVE = 'executive', 'ผู้บริหาร'

    role = models.CharField('บทบาท', max_length=20, choices=Role.choices, default=Role.TECHNICIAN)
    department = models.CharField('หน่วยงาน', max_length=100, blank=True)

    class Meta:
        verbose_name = 'ผู้ใช้'
        verbose_name_plural = 'ผู้ใช้'

    @property
    def display_name(self):
        return self.get_full_name() or self.username

    @property
    def initial(self):
        return (self.first_name or self.username)[:1].upper()
