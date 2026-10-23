@echo off
chcp 65001 >nul
setlocal
cd /d "%~dp0"
title EEC VulnTrack - Setup

echo ============================================
echo   EEC VulnTrack : ติดตั้งระบบ (ทำครั้งแรกครั้งเดียว)
echo ============================================
echo.

rem ---- 1) หา Python 3.12 ขึ้นไป ----
set "PY="
python -c "import sys; sys.exit(0 if sys.version_info >= (3, 12) else 1)" >nul 2>&1 && set "PY=python"
if not defined PY (
    py -3 -c "import sys; sys.exit(0 if sys.version_info >= (3, 12) else 1)" >nul 2>&1 && set "PY=py -3"
)
if not defined PY (
    echo [ผิดพลาด] ไม่พบ Python 3.12 ขึ้นไปในเครื่องนี้
    echo   1. ดาวน์โหลดจาก https://www.python.org/downloads/
    echo   2. ตอนติดตั้งให้ติ๊ก "Add python.exe to PATH"
    echo   3. ปิดหน้าต่างนี้ แล้วดับเบิลคลิก setup.bat ใหม่
    goto :fail
)
for /f "delims=" %%v in ('%PY% --version') do echo [1/5] พบ %%v

rem ---- 2) สร้าง virtual environment ----
if exist ".venv\Scripts\python.exe" (
    echo [2/5] มี .venv อยู่แล้ว ข้ามขั้นตอนนี้
) else (
    echo [2/5] กำลังสร้าง .venv ...
    %PY% -m venv .venv || goto :fail
)

rem ---- 3) ติดตั้งไลบรารี ----
echo [3/5] กำลังติดตั้งไลบรารี (ต้องต่ออินเทอร์เน็ต) ...
".venv\Scripts\python.exe" -m pip install --disable-pip-version-check -q -r requirements.txt || goto :fail

rem ---- 4) สร้างตารางในฐานข้อมูล ----
echo [4/5] กำลังสร้างตารางในฐานข้อมูล ...
".venv\Scripts\python.exe" manage.py migrate -v 0 || goto :fail

rem ---- 5) ข้อมูลตัวอย่าง (ถ้ามีข้อมูลอยู่แล้วจะข้าม) ----
echo [5/5] กำลังสร้างข้อมูลตัวอย่าง ...
".venv\Scripts\python.exe" manage.py seed_demo || goto :fail

echo.
echo ============================================
echo   ติดตั้งเสร็จแล้ว  ดับเบิลคลิก run.bat เพื่อเปิดเว็บ
echo ============================================
if not defined NO_PAUSE pause
exit /b 0

:fail
echo.
echo การติดตั้งไม่สำเร็จ โปรดอ่านข้อความด้านบน
if not defined NO_PAUSE pause
exit /b 1
