import requests
import re
import os
import json
import shutil
from urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

def extract_ip(url):
    match = re.search(r'\d+\.\d+\.\d+\.\d+', url)
    return match.group() if match else None

def extract_credentials(url):
    """استخراج اسم المستخدم وكلمة المرور من الرابط إذا وجدا"""
    # Pattern: http://user:pass@ip
    match = re.search(r'://(.*?):(.*?)@', url)
    if match:
        return match.group(1), match.group(2)
    return None, None

def get_session():
    session = requests.Session()
    session.verify = False
    return session

def get_target_dir(ip):
    """Target workspace — uses ENGINE_WORKSPACE when set by router integration."""
    ws = os.environ.get("ENGINE_WORKSPACE")
    if ws:
        os.makedirs(ws, exist_ok=True)
        return ws
    path = f"targets/{ip}"
    if not os.path.exists(path):
        os.makedirs(path)
    return path

def log(message, type="INFO", ip=None):
    icons = {"INFO": "[*]", "SUCCESS": "[+]", "ERROR": "[!]", "PWN": "[$$$]"}
    formatted_msg = f"{icons.get(type, '[*]')} {message}"
    print(formatted_msg)
    
    # حفظ في السجل العام
    with open("pwn.log", "a", encoding="utf-8") as f:
        f.write(formatted_msg + "\n")
        f.flush()

    # إذا كان هناك أي بي، نحفظ في سجل الهدف الخاص أيضاً
    if ip:
        t_dir = get_target_dir(ip)
        with open(f"{t_dir}/session.log", "a", encoding="utf-8") as f:
            f.write(formatted_msg + "\n")

def clear_logs(ip=None):
    if not ip:
        with open("pwn.log", "w", encoding="utf-8") as f:
            f.write("--- NEW GLOBAL SESSION ---\n")
    else:
        t_dir = get_target_dir(ip)
        with open(f"{t_dir}/session.log", "w", encoding="utf-8") as f:
            f.write(f"--- SESSION FOR {ip} ---\n")

def save_success(ip, service, credentials):
    """حفظ الأهداف المخترقة بنجاح في ملف نصي وقاعدة بيانات JSON"""
    with open("pwned_targets.txt", "a", encoding="utf-8") as f:
        f.write(f"[{service}] Target: {ip} | Credentials: {credentials}\n")
    
    # تحديث قاعدة بيانات JSON
    data = get_target_data(ip)
    data["status"] = "PWNED"
    data.setdefault("pwned_services", []).append({"service": service, "creds": credentials})
    update_target_data(ip, data)
    
    log(f"Target {ip} saved to database", "SUCCESS")

def get_target_data(ip):
    """قراءة بيانات الهدف من قاعدة البيانات"""
    db_path = f"db/{ip}.json"
    if not os.path.exists("db"): os.makedirs("db")
    if os.path.exists(db_path):
        with open(db_path, "r", encoding="utf-8") as f:
            return json.load(f)
    return {"ip": ip, "status": "NEW", "pwned_services": []}

import sys

def _input_with_timeout_windows(prompt, timeout, default):
    import msvcrt
    import time

    start_time = time.time()
    while True:
        elapsed = time.time() - start_time
        if elapsed > timeout:
            print(f"\n[!] Timeout reached. Proceeding with default: {default}")
            return default

        remaining = int(timeout - elapsed)
        print(f"\r{prompt} (Auto-skip in {remaining}s, press 'y' to continue): ", end='', flush=True)

        if msvcrt.kbhit():
            char = msvcrt.getch().decode('utf-8', errors='ignore').lower()
            print(char)
            return char or default

        time.sleep(0.1)


def _input_with_timeout_unix(prompt, timeout, default):
    import select
    import termios
    import tty
    import time

    fd = sys.stdin.fileno()
    old_settings = termios.tcgetattr(fd)
    start_time = time.time()

    try:
        tty.setcbreak(fd)
        while True:
            elapsed = time.time() - start_time
            if elapsed > timeout:
                print(f"\n[!] Timeout reached. Proceeding with default: {default}")
                return default

            remaining = int(timeout - elapsed)
            print(f"\r{prompt} (Auto-skip in {remaining}s, press 'y' to continue): ", end='', flush=True)

            ready, _, _ = select.select([sys.stdin], [], [], 0.1)
            if ready:
                char = sys.stdin.read(1).lower()
                print(char)
                return char or default
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)


def input_with_timeout(prompt, timeout=10, default='n'):
    """إدخال مع مؤقت تنازلي (Windows / Linux)"""
    if os.name == 'nt':
        return _input_with_timeout_windows(prompt, timeout, default)
    return _input_with_timeout_unix(prompt, timeout, default)

def update_target_data(ip, data):
    """تحديث بيانات الهدف في قاعدة البيانات"""
    db_path = f"db/{ip}.json"
    if not os.path.exists("db"): os.makedirs("db")
    with open(db_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4)
