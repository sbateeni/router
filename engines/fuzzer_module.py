from engines.utils import log, get_session

class Fuzzer:
    def __init__(self, target_url):
        self.target_url = target_url
        self.session = get_session()
        self.important_paths = [
            "/.env", 
            "/storage/logs/laravel.log", 
            "/admin", 
            "/phpmyadmin", 
            "/config.php",
            "/.git/config",
            "/composer.json"
        ]

    def run(self):
        log("Starting Manual Path Fuzzing (as mentioned in Gemini)...")
        found_paths = []
        for path in self.important_paths:
            url = self.target_url + path
            try:
                r = self.session.get(url, timeout=5)
                if r.status_code == 200:
                    log(f"Sensitive Path Found: {url}", "PWN")
                    found_paths.append(path)
                elif r.status_code == 403:
                    log(f"Path exists but Forbidden (403): {path}", "INFO")
            except: pass
        return found_paths
