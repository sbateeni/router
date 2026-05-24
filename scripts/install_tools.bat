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

if not exist "tools" mkdir tools
cd tools

echo [1/10] RouterSploit...
if not exist "routersploit" (
    git clone https://github.com/threat9/routersploit.git
) else (
    cd routersploit && git pull --ff-only && cd ..
)

echo [2/10] Ingram...
if not exist "ingram" (
    git clone https://github.com/jorhelp/Ingram.git ingram
) else (
    cd ingram && git pull --ff-only && cd ..
)

echo [3/10] DefaultCreds...
if not exist "DefaultCreds-cheat-sheet" (
    git clone https://github.com/ihebski/DefaultCreds-cheat-sheet.git
) else (
    cd DefaultCreds-cheat-sheet && git pull --ff-only && cd ..
)

echo [4/10] Dirsearch...
if not exist "dirsearch" (
    git clone --depth 1 https://github.com/maurosoria/dirsearch.git
) else (
    cd dirsearch && git pull --ff-only && cd ..
)

echo [5/10] Sqlmap...
if not exist "sqlmap" (
    git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git
) else (
    cd sqlmap && git pull --ff-only && cd ..
)

echo [6/10] NetExec...
if not exist "netexec" (
    git clone --depth 1 https://github.com/Pennyw0rth/NetExec.git netexec
) else (
    cd netexec && git pull --ff-only && cd ..
)

echo [7/10] Nikto...
if not exist "nikto" (
    git clone --depth 1 https://github.com/sullo/nikto.git nikto
) else (
    cd nikto && git pull --ff-only && cd ..
)

echo [8/10] SpiderFoot...
if not exist "spiderfoot" (
    git clone --depth 1 https://github.com/smicallef/spiderfoot.git spiderfoot
) else (
    cd spiderfoot && git pull --ff-only && cd ..
)

echo [9/10] theHarvester...
if not exist "theHarvester" (
    git clone --depth 1 https://github.com/laramies/theHarvester.git theHarvester
) else (
    cd theHarvester && git pull --ff-only && cd ..
)

echo [10/10] Amass...
if not exist "amass" (
    git clone --depth 1 https://github.com/owasp-amass/amass.git amass
) else (
    cd amass && git pull --ff-only && cd ..
)

cd "%ROOT%"
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
if exist "tools\dirsearch\requirements.txt" "%PY%" -m pip install -q -r tools\dirsearch\requirements.txt
if exist "tools\theHarvester\pyproject.toml" "%PY%" -m pip install -q --no-deps tools\theHarvester
"%PY%" -m pip install -q "paramiko==2.12.0"
echo [i] NetExec: use system install on Kali (apt install netexec), not .venv - conflicts with RouterSploit

echo.
echo ======================================================
echo       ALL TOOLS DOWNLOADED SUCCESSFULLY!
echo ======================================================
echo.
echo Tools: %ROOT%\tools\
echo venv:  %ROOT%\.venv\
echo.
pause
