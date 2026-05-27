@echo off
setlocal
cd /d "%~dp0"
set "PYTHONPATH=%~dp0"

where python >nul 2>&1 && set PY=python || set PY=py -3
if exist ".venv\Scripts\python.exe" set PY=.venv\Scripts\python.exe

if exist "scripts\telegram_service.sh" (
  bash scripts\telegram_service.sh start 2>nul
  set NUCLEI_TELEGRAM_EXTERNAL=1
)
set TG_EXTRA=
if "%NUCLEI_TELEGRAM_EXTERNAL%"=="1" set TG_EXTRA=--no-telegram

echo ======================================================
echo    AUTO-PWN UNIFIED — router + nuclei-dev engine
echo ======================================================
echo.
echo   [1] Full auto scan          bin\master_pwn.py -t IP --auto
echo   [2] Device engine only      bin\auto_pwn.py
echo   [3] Test router             tests\test_router_target.py
echo   [4] Test Hikvision          tests\test_hikvision_target.py
echo   [5] CVE report              tests\test_device_cve.py
echo   [8] Interactive menu        bin\master_pwn.py
echo   [9] Update from GitHub      scripts\update_tools.py
echo   [G] PyQt6 GUI               bin\gui_app.py
echo   [0] Exit
echo.
set /p choice="Select [0-9,G]: "

if "%choice%"=="0" exit /b 0
if /I "%choice%"=="G" (
  %PY% bin\gui_app.py
  pause
  exit /b 0
)
if "%choice%"=="9" (
  %PY% scripts\update_tools.py
  pause
  exit /b 0
)
if "%choice%"=="1" (
  set /p target_ip="Target IP: "
  set NUCLEI_SKIP_UPDATE=1
  %PY% bin\master_pwn.py %TG_EXTRA% -t %target_ip% --auto
) else if "%choice%"=="2" (
  set NUCLEI_SKIP_UPDATE=1
  %PY% bin\auto_pwn.py
) else if "%choice%"=="3" (
  set /p target_ip="Target IP: "
  %PY% tests\test_router_target.py -H %target_ip%
) else if "%choice%"=="4" (
  set /p target_ip="Target IP: "
  %PY% tests\test_hikvision_target.py -H %target_ip%
) else if "%choice%"=="5" (
  set /p target_ip="Target IP: "
  %PY% tests\test_device_cve.py -H %target_ip%
) else if "%choice%"=="8" (
  set NUCLEI_SKIP_UPDATE=1
  %PY% bin\master_pwn.py %TG_EXTRA%
) else (
  echo Invalid option.
)
pause
