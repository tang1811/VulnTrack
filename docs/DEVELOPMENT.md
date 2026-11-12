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
| `test` | รันชุดทดสอบทั้งหมด (ควรผ่านก่อน push ทุกครั้ง) |
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
  models.py              Asset, Vulnerability, StatusHistory, ImportLog
  services.py            change_status() เปลี่ยนสถานะ+บันทึกประวัติ, import_scan_file()
  views.py               ทุกหน้าของระบบหลัก
  forms.py               ฟอร์มช่องโหว่ อุปกรณ์ สถานะ นำเข้าไฟล์
  urls.py                URL ทั้งหมด
  templatetags/ui.py     {% icon %}, {% severity_badge %}, {% status_badge %}, {% person %}, |thai_date, |can_work
  management/commands/seed_demo.py   ข้อมูลตัวอย่าง
templates/base.html      โครงหน้า + เมนูด้านซ้าย
templates/tracker/       หน้าต่าง ๆ ของระบบ
static/css/app.css       Design System (สี ตัวอักษร ระยะห่าง อยู่ใน :root ด้านบนไฟล์)
static/js/app.js         กราฟ Chart.js + เมนูมือถือ
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
