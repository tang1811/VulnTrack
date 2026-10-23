@echo off
chcp 65001 >nul
setlocal
cd /d "%~dp0"
title EEC VulnTrack - Server

rem ยังไม่เคยติดตั้ง ให้รัน setup.bat ก่อน
if not exist ".venv\Scripts\python.exe" (
    echo ยังไม่ได้ติดตั้ง กำลังเรียก setup.bat ...
    set "NO_PAUSE=1"
    call setup.bat || (pause & exit /b 1)
)

rem อัปเดตตารางฐานข้อมูลเผื่อมีการแก้โค้ด
".venv\Scripts\python.exe" manage.py migrate -v 0 || (pause & exit /b 1)

echo ============================================
echo   EEC VulnTrack กำลังทำงานที่ http://127.0.0.1:8000
echo   บัญชีทดลอง: admin / tech1 / exec   รหัสผ่าน Eec@2569demo
echo   ปิดเว็บ: กด Ctrl+C หรือปิดหน้าต่างนี้
echo ============================================

rem เปิดเบราว์เซอร์หลังเซิร์ฟเวอร์เริ่มประมาณ 3 วินาที
start "" /b cmd /c "ping -n 4 127.0.0.1 >nul & start "" http://127.0.0.1:8000/"

".venv\Scripts\python.exe" manage.py runserver 127.0.0.1:8000
pause
