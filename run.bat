@echo off
setlocal
cd /d "%~dp0"

where python >nul 2>&1 && set PY=python || set PY=py -3

echo ======================================================
echo    AUTO-PWN UNIFIED — router + nuclei-dev engine
echo ======================================================
echo.
echo   [1] Full auto scan          master_pwn.py -t IP --auto
echo   [2] Device engine only      auto_pwn.py
echo   [3] Test router             test_router_target.py
echo   [4] Test Hikvision          test_hikvision_target.py
echo   [5] CVE report              test_device_cve.py
echo   [6] Interactive menu        master_pwn.py
echo.
set /p choice="Select [1-6]: "

if "%choice%"=="1" (
  set /p target_ip="Target IP: "
  %PY% master_pwn.py -t %target_ip% --auto
) else if "%choice%"=="2" (
  %PY% auto_pwn.py
) else if "%choice%"=="3" (
  set /p target_ip="Target IP: "
  %PY% test_router_target.py -H %target_ip%
) else if "%choice%"=="4" (
  set /p target_ip="Target IP: "
  %PY% test_hikvision_target.py -H %target_ip%
) else if "%choice%"=="5" (
  set /p target_ip="Target IP: "
  %PY% test_device_cve.py -H %target_ip%
) else if "%choice%"=="6" (
  %PY% master_pwn.py
) else (
  echo Invalid option.
)
pause
