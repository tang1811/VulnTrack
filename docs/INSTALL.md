# คู่มือติดตั้งบนเครื่องใหม่

## สิ่งที่ต้องมี

| โปรแกรม | ใช้ทำอะไร | ดาวน์โหลด |
|---|---|---|
| Python 3.12 ขึ้นไป | รันเว็บ | https://www.python.org/downloads/ (ติ๊ก **Add python.exe to PATH**) |
| อินเทอร์เน็ต (ครั้งแรก) | ดาวน์โหลดไลบรารีใน `requirements.txt` | – |
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

**Windows:** ดับเบิลคลิก `run.bat` ได้เลย แม้เป็นเครื่องใหม่ — ถ้ายังไม่มี `.venv` จะเรียก `setup.bat` ให้อัตโนมัติ
(สร้าง `.venv` → `pip install -r requirements.txt` → `migrate` → `seed_demo`) แล้วเปิดเว็บต่อทันที ครั้งต่อไปดับเบิลคลิก `run.bat` อย่างเดียว

ไลบรารีที่ติดตั้ง (`requirements.txt`): Django 5.2, PyMySQL, python-dotenv และ **bcrypt** (ใช้เข้ารหัสรหัสผ่าน)

`run.bat` รัน `migrate` ให้ทุกครั้งก่อนเปิดเว็บ ฐานข้อมูลเดิมจึงได้ migration ใหม่ เช่น `0003_risk_likelihood_impact` (ช่อง Likelihood/Impact) โดยไม่ต้องทำอะไรเพิ่ม
ถ้ามี `.venv` อยู่แล้วแต่ไลบรารียังไม่ครบ (เช่น ติดตั้งไว้ก่อนอัปเดตนี้ ยังไม่มี bcrypt) `run.bat` จะตรวจพบและติดตั้งที่ขาดให้เอง (ต้องต่ออินเทอร์เน็ตครั้งนั้น) — ระหว่างที่ยังไม่มี bcrypt ระบบจะใช้ PBKDF2 ไปก่อน จึงยังล็อกอินได้
หรือรัน `.venv\Scripts\python -m pip install -r requirements.txt`

**macOS / Linux หรืออยากพิมพ์คำสั่งเอง:** (ไม่มีสคริปต์ `.sh` ให้ ใช้คำสั่งด้านล่าง บน macOS/Linux อาจต้องพิมพ์ `python3` แทน `python`)

```bash
python -m venv .venv
.venv\Scripts\activate            # macOS/Linux: source .venv/bin/activate
pip install -r requirements.txt    # รวม bcrypt
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
| `No module named 'bcrypt'` หรือ error เกี่ยวกับ `BCryptSHA256PasswordHasher` ตอนล็อกอิน | ยังไม่ได้ติดตั้ง bcrypt ดับเบิลคลิก `setup.bat` อีกครั้ง หรือ `.venv\Scripts\python -m pip install -r requirements.txt` |
| ช่องโหว่เดิมขึ้นความเสี่ยงว่า "ยังไม่ประเมิน" | ข้อมูลสร้างก่อนมีช่อง Likelihood/Impact เป็นเรื่องปกติ แก้ไขทีละรายการเพื่อใส่ค่า หรือสร้างข้อมูลตัวอย่างใหม่ด้วย `seed_demo --reset` (**ลบข้อมูลเดิมทั้งหมด**) |
| อยากล้างข้อมูลแล้วเริ่มใหม่ | `.venv\Scripts\python manage.py seed_demo --reset` (ลบข้อมูลทั้งหมดแล้วสร้างข้อมูลตัวอย่างใหม่) |
| ลืมรหัสผ่าน admin | `.venv\Scripts\python manage.py changepassword admin` |
