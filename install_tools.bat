@echo off
mkdir tools
cd tools

echo Cloning RouterSploit...
git clone https://github.com/threat9/routersploit.git

echo Cloning Ingram...
git clone https://github.com/jorhelp/Ingram.git ingram

echo Cloning Dirsearch...
git clone --depth 1 https://github.com/maurosoria/dirsearch.git

echo Cloning Sqlmap...
git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git

echo Downloading Nuclei...
powershell -Command "Invoke-WebRequest -Uri https://github.com/projectdiscovery/nuclei/releases/download/v3.3.0/nuclei_3.3.0_windows_amd64.zip -OutFile nuclei.zip"
powershell -Command "Expand-Archive -Path nuclei.zip -DestinationPath nuclei"

echo Done!
