# คู่มือพัฒนาต่อ

## ทำงานสลับหลายเครื่องด้วย Git

ตั้งชื่อผู้ commit ครั้งแรกบนเครื่องใหม่ (ทำครั้งเดียวต่อเครื่อง)

```bat
git config --global user.name "ชื่อของคุณ"
git config --global user.email "อีเมลที่ใช้กับ GitHub"
```

รอบการทำงานทุกครั้ง

```bat
git pull
:: แก้โค้ด แล้วลองรัน run.bat
git status
git add .
git commit -m "เพิ่มหน้า ..."
git push
```

1. `git pull` — ก่อนเริ่มงาน ดึงโค้ดล่าสุดที่ push มาจากอีกเครื่อง
2. แก้โค้ด แล้วลองรัน `run.bat`
3. `git status` — ดูว่าแก้ไฟล์อะไรไปบ้าง
4. `git add .` + `git commit -m "..."` — บันทึกพร้อมข้อความสั้น ๆ ว่าทำอะไร
5. `git push` — ส่งขึ้น GitHub

หลัง `git pull` ถ้ามีการแก้ `requirements.txt` ให้รัน `setup.bat` ใหม่ ส่วนการแก้ `models.py` ไม่ต้องทำอะไร เพราะ `run.bat` รัน migrate ให้ทุกครั้ง

ครั้งแรกที่ `git push` จะมีหน้าต่างให้ล็อกอิน GitHub ในเบราว์เซอร์ ทำครั้งเดียวต่อเครื่อง

**ทำงานเป็นทีม:** แนะนำให้แยก branch ต่อฟีเจอร์ แล้วเปิด Pull Request บน GitHub

```bat
git switch -c feature/pdf-report
:: แก้โค้ด, commit
git push -u origin feature/pdf-report
```

**ถ้า `git pull` แจ้ง conflict:** เปิดไฟล์ที่แจ้ง (VS Code จะไฮไลต์ส่วนที่ชน) เลือกโค้ดที่ถูก แล้ว `git add .` และ `git commit`

## คำสั่ง Django

ทุกคำสั่งต้องรันใน virtual environment

```bat
.venv\Scripts\activate
python manage.py <คำสั่ง>
```

| คำสั่ง | ใช้ทำอะไร |
|---|---|
| `runserver` | เปิดเว็บที่ http://127.0.0.1:8000 (แก้โค้ดแล้วรีโหลดเอง) |
| `test` | รันชุดทดสอบทั้งหมด 75 รายการ (ควรผ่านก่อน push ทุกครั้ง) · รันเฉพาะไฟล์: `test tracker.tests_risk` |
| `makemigrations` | สร้างไฟล์ migration หลังแก้ `models.py` |
| `migrate` | อัปเดตตารางในฐานข้อมูลตาม migration |
| `seed_demo --reset` | ล้างข้อมูลแล้วสร้างข้อมูลตัวอย่างใหม่ |
| `createsuperuser` | สร้างผู้ใช้ใหม่จาก command line |
| `shell` | เปิด Python พร้อมโหลดโปรเจกต์ (ลองคิวรีข้อมูล) |

หน้า Django Admin สำหรับดู/แก้ข้อมูลดิบ: http://127.0.0.1:8000/dev-admin/ (ล็อกอินด้วย `admin`)

## โครงสร้างโค้ด

```
config/settings.py       ตั้งค่าทั้งหมด อ่านค่าลับจาก .env
accounts/
  models.py              User + ฟิลด์ role (admin / technician / executive)
  roles.py               ตารางสิทธิ์ PERMISSIONS + @role_required + can_work_on (สิทธิ์ระดับรายการ)  ← แก้สิทธิ์ที่นี่ที่เดียว
  context_processors.py  ส่งตัวแปร can.* ให้ทุก template ใช้ซ่อนเมนู/ปุ่ม
  views.py, forms.py     ล็อกอิน, จัดการผู้ใช้
tracker/
  models.py              Asset, Vulnerability, StatusHistory, ImportLog + Likelihood, Impact, RISK_LEVELS, risk_level()
  services.py            change_status() เปลี่ยนสถานะ+บันทึกประวัติ, import_scan_file() (IMPORT_COLUMNS, _parse_row)
  views.py               ทุกหน้าของระบบหลัก + with_risk(), RISK_RANGES, dashboard_cache_key(), dashboard_summary()
  forms.py               ฟอร์มช่องโหว่ อุปกรณ์ สถานะ นำเข้าไฟล์
  urls.py                URL ทั้งหมด
  templatetags/ui.py     {% icon %}, {% severity_badge %}, {% status_badge %}, {% person %}, |thai_date, |can_work
  management/commands/seed_demo.py   ข้อมูลตัวอย่าง
  tests.py, tests_features.py, tests_risk.py   ชุดทดสอบ (tests_risk.py = คะแนนความเสี่ยง, cache แดชบอร์ด, กรณีทดสอบใบงาน T-01..T-05)
templates/base.html      โครงหน้า + เมนูด้านซ้าย
templates/tracker/       หน้าต่าง ๆ ของระบบ
static/css/app.css       Design System (สี ตัวอักษร ระยะห่าง อยู่ใน :root ด้านบนไฟล์)
static/js/app.js         กราฟ Chart.js + เมนูมือถือ + คำนวณคะแนนความเสี่ยงสดบนฟอร์มช่องโหว่
```

## สูตรเพิ่มหน้าใหม่ (ตัวอย่าง)

1. **กำหนดสิทธิ์** — เพิ่มชื่อสิทธิ์ใน `accounts/roles.py`
   ```python
   'view_audit': {Role.ADMIN, Role.EXECUTIVE},
   ```
2. **เขียน view** — ใน `tracker/views.py` ใส่ decorator ทุกครั้ง (ไม่ใส่ = ทุกคนที่ล็อกอินเข้าได้)
   ```python
   @role_required('view_audit')
   def audit(request):
       return render(request, 'tracker/audit.html', {'section': 'audit'})
   ```
3. **เพิ่ม URL** — `tracker/urls.py`: `path('audit/', views.audit, name='audit')`
4. **สร้าง template** — `templates/tracker/audit.html` เริ่มด้วย `{% extends 'base.html' %}` (ดูหน้าอื่นเป็นตัวอย่าง)
5. **เพิ่มเมนู** — ใน `templates/base.html` ครอบด้วย `{% if can.view_audit %} ... {% endif %}` เพื่อซ่อนจากคนที่ไม่มีสิทธิ์
6. **เพิ่มเทสต์** — เพิ่มหน้าใหม่ในตาราง `PAGES` ของ `accounts/tests.py` ว่าบทบาทไหนเข้าได้ แล้วรัน `python manage.py test`

## แก้ฐานข้อมูล

1. แก้ `tracker/models.py`
2. `python manage.py makemigrations`
3. `python manage.py migrate`
4. commit ไฟล์ใน `tracker/migrations/` ขึ้น Git ด้วยเสมอ อีกเครื่องจะได้ตารางตรงกัน

ห้ามแก้หรือลบไฟล์ migration ที่ push ไปแล้ว ถ้าต้องเปลี่ยนให้สร้าง migration ใหม่

## คะแนนความเสี่ยง (Likelihood × Impact)

- ฟิลด์ `likelihood`, `impact` ใน `Vulnerability` เป็น 1-5 แบบ `null=True` (ข้อมูลเก่า/นำเข้าที่ยังไม่ประเมินเป็นค่าว่าง) แต่ `VulnerabilityForm` บังคับกรอก — migration `0003_risk_likelihood_impact`
- คะแนนไม่ได้เก็บเป็นคอลัมน์ ใช้ `risk_score` (property) ในโค้ด Python และ `with_risk(qs)` (annotate `risk = F('likelihood') * F('impact')`) เวลากรอง/เรียง/นับในฐานข้อมูล
- เกณฑ์ระดับอยู่ที่ `RISK_LEVELS` ใน `tracker/models.py` ที่เดียว (`RISK_RANGES` ใน views สร้างจากค่านี้): ต่ำ 1-4, ปานกลาง 5-9, สูง 10-14, วิกฤต 15-25
- **เกณฑ์ชุดเดียวกันถูกเขียนซ้ำใน `static/js/app.js`** (ตัวแปร `LEVELS` ของตัวคำนวณสดบนฟอร์ม) ถ้าแก้ `RISK_LEVELS` ต้องแก้ใน `app.js` ให้ตรงกันด้วย
  (ค่าที่บันทึกและแสดงหลังบันทึกคำนวณฝั่งเซิร์ฟเวอร์เสมอ JS ใช้แค่แสดงผลก่อนกดบันทึก)
- นำเข้าไฟล์: `likelihood`, `impact` อยู่ท้าย `IMPORT_COLUMNS` (ไฟล์ตัวอย่างดาวน์โหลดใช้ลำดับนี้) `_parse_row` รับ 1-5 และบังคับให้ใส่คู่กันหรือว่างทั้งคู่

## Cache แดชบอร์ด

- `CACHES` ใน `config/settings.py` ใช้ `LocMemCache` (หน่วยความจำของ process ไม่ต้องติดตั้งเพิ่ม แต่ละ process มี cache ของตัวเอง)
- `dashboard_summary()` เก็บตัวเลขสรุปที่ทุกคนเห็นเหมือนกันไว้ `DASHBOARD_CACHE_SECONDS = 300` (5 นาที) ตัวเลขเฉพาะคน (งานของฉัน, งานที่ยังว่าง) คำนวณใหม่ทุกครั้งและไม่ใส่ใน cache
- ไม่ได้ลบ cache ตอนบันทึก แต่ใช้ **คีย์ที่เปลี่ยนเองเมื่อข้อมูลเปลี่ยน**: `dashboard_cache_key()` ประกอบจากวันที่ปัจจุบัน + จำนวนแถวและ `Max(updated_at)` ของ `Vulnerability` และ `Asset`
  เพิ่ม/ลบ → จำนวนเปลี่ยน, แก้ไข/เปลี่ยนสถานะ/นำเข้า → `updated_at` (auto_now) เปลี่ยน, ข้ามวัน → วันที่เปลี่ยน (ตัวเลข "เดือนนี้" และแนวโน้มจึงไม่ค้าง)
- **ข้อควรระวัง:** `QuerySet.update()` และ `bulk_update()` **ไม่** อัปเดต `auto_now` ถ้าเพิ่มโค้ดแก้ข้อมูลแบบกลุ่มในอนาคต ต้องใส่ `updated_at=timezone.now()` ไปด้วย
  หรือเรียก `cache.clear()` หลังแก้ ไม่อย่างนั้นแดชบอร์ดอาจแสดงตัวเลขเก่าได้ถึง 5 นาที
- ถ้าแก้โครงสร้างข้อมูลที่เก็บใน cache ให้เปลี่ยนเลขเวอร์ชันในคีย์ (`dashboard:v1:` → `v2`) และในเทสต์ให้เรียก `cache.clear()` ใน `setUp` (ดู `tests_risk.py`)

## รหัสผ่าน (bcrypt)

`PASSWORD_HASHERS` ใน `config/settings.py` ตั้ง `BCryptSHA256PasswordHasher` เป็นตัวแรก (ต้องมีแพ็กเกจ `bcrypt` ใน `requirements.txt` ถ้า import bcrypt ไม่ได้ settings จะตัดตัวนี้ออกและใช้ PBKDF2 แทน กันล็อกอินล้ม และ `run.bat` จะติดตั้งไลบรารีที่ขาดให้เอง) ตัวที่เหลือเก็บไว้ให้บัญชีเดิมที่เป็น PBKDF2 ยังล็อกอินได้
และ Django จะเปลี่ยน hash เป็น bcrypt ให้เองเมื่อล็อกอินสำเร็จครั้งถัดไป ห้ามลบ PBKDF2 ออกจากรายการจนกว่าทุกบัญชีจะเปลี่ยนแล้ว

## ข้อตกลงในโค้ด

- ข้อความที่ผู้ใช้เห็นเป็นภาษาไทย ชื่อตัวแปร/ฟังก์ชันเป็นภาษาอังกฤษ
- ตรวจสิทธิ์ที่ฝั่งเซิร์ฟเวอร์ (`@role_required`) เสมอ การซ่อนเมนูอย่างเดียวไม่พอ
- เปลี่ยนสถานะช่องโหว่ผ่าน `services.change_status()` เท่านั้น เพื่อให้มีประวัติทุกครั้ง
- ใช้สีและขนาดจากตัวแปร CSS ใน `:root` ของ `app.css` แทนการใส่ค่าสีตรง ๆ
- ห้าม commit `.env`, `db.sqlite3`, `.venv/`

## งานที่ยังทำต่อได้ (จากใบงาน)

- รายงาน PDF แบบสร้างไฟล์จริง (ตอนนี้ใช้ "พิมพ์ → บันทึกเป็น PDF" จากเบราว์เซอร์)
- ส่งออกข้อมูลเป็น JSON
- นอกขอบเขตใบงาน: เชื่อมต่อ Nessus/OpenVAS, แจ้งเตือน LINE/Telegram
