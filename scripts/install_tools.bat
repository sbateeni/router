@echo off
title INSTALLING EXTERNAL TOOLS
setlocal
cd /d "%~dp0\.."
set "ROOT=%CD%"
set "PY=%ROOT%\.venv\Scripts\python.exe"
if not exist "%PY%" set "PY=python"
cls
echo ======================================================
echo       DOWNLOADING EXTERNAL SECURITY TOOLS
echo ======================================================
echo.

:: انتقل لمجلد الأدوات
if not exist "tools" mkdir tools
cd tools

:: 1. RouterSploit - إطار استغلال الراوترات والأجهزة المدمجة
echo [1/5] Downloading RouterSploit...
if not exist "routersploit" (
    git clone https://github.com/threat9/routersploit.git
    echo [+] RouterSploit downloaded!
) else (
    echo [*] Updating RouterSploit...
    cd routersploit
    git pull --ff-only
    cd ..
)

:: 2. Ingram - ماسح كاميرات IP الشامل (Hikvision, Dahua, etc)
echo [2/5] Downloading Ingram Camera Scanner...
if not exist "ingram" (
    git clone https://github.com/jorhelp/Ingram.git ingram
    echo [+] Ingram downloaded!
) else (
    echo [*] Updating Ingram...
    cd ingram
    git pull --ff-only
    cd ..
)

:: 3. DefaultCreds - قاعدة بيانات ضخمة لكلمات المرور الافتراضية
echo [3/5] Downloading Default Credentials Database...
if not exist "DefaultCreds-cheat-sheet" (
    git clone https://github.com/ihebski/DefaultCreds-cheat-sheet.git
    echo [+] DefaultCreds downloaded!
) else (
    echo [*] Updating DefaultCreds...
    cd DefaultCreds-cheat-sheet
    git pull --ff-only
    cd ..
)

:: 4. Dirsearch - أداة البحث عن الملفات والمجلدات الحساسة
echo [4/5] Downloading Dirsearch...
if not exist "dirsearch" (
    git clone --depth 1 https://github.com/maurosoria/dirsearch.git
    echo [+] Dirsearch downloaded!
) else (
    echo [*] Updating Dirsearch...
    cd dirsearch
    git pull --ff-only
    cd ..
)

:: 5. Sqlmap - أداة فحص واستغلال ثغرات SQL Injection
echo [5/5] Downloading Sqlmap...
if not exist "sqlmap" (
    git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git
) else (
    echo [*] Updating Sqlmap...
    cd sqlmap
    git pull --ff-only
    cd ..
)

cd ..
echo.
echo [*] Setting up project virtualenv...
if not exist "%ROOT%\.venv\Scripts\python.exe" (
    python -m venv "%ROOT%\.venv"
)
set "PY=%ROOT%\.venv\Scripts\python.exe"

echo [*] Installing Python dependencies into .venv...
"%PY%" -m pip install -q -U pip setuptools wheel
if exist "requirements.txt" "%PY%" -m pip install -q -r requirements.txt
if exist "tools\routersploit\requirements.txt" "%PY%" -m pip install -q -r tools\routersploit\requirements.txt
if exist "tools\ingram\requirements.txt" "%PY%" -m pip install -q -r tools\ingram\requirements.txt

echo.
echo ======================================================
echo       ALL TOOLS DOWNLOADED SUCCESSFULLY!
echo ======================================================
echo.
echo Tools installed in: auto-pwn\tools\
echo   - routersploit     : Router exploitation framework
echo   - ingram           : IP camera mass scanner
echo   - DefaultCreds     : Default passwords database
echo   - dirsearch        : Web directory discovery
echo   - sqlmap           : SQL injection tool
echo.
pause
