# คู่มือติดตั้งบนเครื่องใหม่

## สิ่งที่ต้องมี

| โปรแกรม | ใช้ทำอะไร | ดาวน์โหลด |
|---|---|---|
| Python 3.12 ขึ้นไป | รันเว็บ | https://www.python.org/downloads/ (ติ๊ก **Add python.exe to PATH**) |
| Git | ดึง/ส่งโค้ดกับ GitHub | https://git-scm.com/downloads |
| VS Code (ไม่บังคับ) | แก้โค้ด | https://code.visualstudio.com/ |
| MySQL 8 (ไม่บังคับ) | ฐานข้อมูลจริง ถ้าไม่ติดตั้งจะใช้ SQLite แทน | https://dev.mysql.com/downloads/installer/ |

ตรวจว่าติดตั้งครบ เปิด Command Prompt แล้วพิมพ์

```bat
python --version
git --version
```

## 1. ดึงโปรเจกต์จาก GitHub

```bat
cd %USERPROFILE%\Desktop
git clone https://github.com/tang1811/VulnTrack.git
cd VulnTrack
```

## 2. ติดตั้งและรัน

**Windows:** ดับเบิลคลิก `setup.bat` (ครั้งแรกครั้งเดียว) แล้วดับเบิลคลิก `run.bat` ทุกครั้งที่จะใช้งาน

**macOS / Linux หรืออยากพิมพ์คำสั่งเอง:**

```bash
python -m venv .venv
.venv\Scripts\activate            # macOS/Linux: source .venv/bin/activate
pip install -r requirements.txt
python manage.py migrate
python manage.py seed_demo
python manage.py runserver
```

เปิด http://127.0.0.1:8000 · บัญชีทดลอง `admin` / `tech1` / `tech2` / `exec` รหัสผ่าน `Eec@2569demo`

> ไฟล์ฐานข้อมูล `db.sqlite3` และโฟลเดอร์ `.venv` **ไม่ได้อยู่บน GitHub** (อยู่ใน `.gitignore`) แต่ละเครื่องสร้างของตัวเองด้วย `setup.bat` ข้อมูลที่เพิ่มบนเครื่องหนึ่งจึงไม่ตามไปอีกเครื่อง ถ้าต้องการข้อมูลชุดเดียวกันให้ใช้ `seed_demo` หรือใช้ MySQL เครื่องกลาง

## 3. ใช้ MySQL แทน SQLite (ไม่บังคับ)

1. ติดตั้ง MySQL 8 แล้วสร้างฐานข้อมูลที่รองรับภาษาไทย (ใน MySQL Workbench หรือ `mysql -u root -p`)
   ```sql
   CREATE DATABASE eec_vulntrack CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
   ```
2. คัดลอก `.env.example` เป็น `.env` แล้วแก้ค่า
   ```ini
   DB_ENGINE=mysql
   DB_NAME=eec_vulntrack
   DB_USER=root
   DB_PASSWORD=รหัสผ่าน MySQL ของเครื่องนี้
   DB_HOST=127.0.0.1
   DB_PORT=3306
   ```
3. รัน `setup.bat` อีกครั้ง (หรือ `python manage.py migrate` และ `python manage.py seed_demo`)

ไฟล์ `.env` เก็บรหัสผ่าน **ห้าม commit ขึ้น GitHub** (Git จะไม่สนใจไฟล์นี้อยู่แล้ว)

## แก้ปัญหาที่พบบ่อย

| อาการ | สาเหตุ / วิธีแก้ |
|---|---|
| `setup.bat` บอกว่าไม่พบ Python | ติดตั้ง Python ใหม่แล้วติ๊ก **Add python.exe to PATH** จากนั้นปิด-เปิดหน้าต่างใหม่ |
| `'git' is not recognized` | ยังไม่ได้ติดตั้ง Git หรือยังไม่ได้เปิด Command Prompt ใหม่หลังติดตั้ง |
| `Error: That port is already in use` | มีเว็บรันอยู่แล้ว ปิดหน้าต่าง `run.bat` เดิม หรือรัน `python manage.py runserver 8001` |
| ย้ายโฟลเดอร์แล้วรันไม่ได้ | ลบโฟลเดอร์ `.venv` แล้วรัน `setup.bat` ใหม่ (`.venv` ย้ายที่ไม่ได้) |
| `Access denied for user 'root'` | รหัสผ่านใน `.env` ไม่ตรงกับ MySQL |
| `Unknown database 'eec_vulntrack'` | ยังไม่ได้รันคำสั่ง `CREATE DATABASE` ในข้อ 3 |
| อยากล้างข้อมูลแล้วเริ่มใหม่ | `.venv\Scripts\python manage.py seed_demo --reset` (ลบข้อมูลทั้งหมดแล้วสร้างข้อมูลตัวอย่างใหม่) |
| ลืมรหัสผ่าน admin | `.venv\Scripts\python manage.py changepassword admin` |
