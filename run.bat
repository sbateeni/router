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

echo ======================================================
echo    AUTO-PWN UNIFIED — GUI FIRST
echo ======================================================
echo.
echo   Launching PyQt6 GUI...
echo.
set NUCLEI_SKIP_UPDATE=1
set AUTOPWN_LIVE_WINDOW=0
%PY% bin\gui_app.py
pause
