import os
import requests
from engines.utils import log
from dotenv import load_dotenv

load_dotenv()

class OSINTEngine:
    def __init__(self, target_ip):
        self.target_ip = target_ip
        self.shodan_api_key = (os.environ.get("SHODAN_API_KEY") or "").strip()
        self.api_base_url = "https://api.shodan.io"
        self.results = {
            "ports": [],
            "hostnames": [],
            "vulns": [],
            "os": "UNKNOWN_OS"
        }

    def run_shodan_scan(self):
        """Query Shodan for the target IP."""
        if not self.shodan_api_key or self.shodan_api_key == "your_shodan_api_key_here":
            log("Shodan API key not found in .env. Skipping Shodan OSINT scan.", "WARNING")
            return self.results

        log(f"Running Shodan OSINT scan for {self.target_ip}...", "INFO")
        
        url = f"{self.api_base_url}/shodan/host/{self.target_ip}?key={self.shodan_api_key}"
        try:
            response = requests.get(url, timeout=10)
            if response.status_code == 200:
                data = response.json()
                self.results["ports"] = data.get("ports", [])
                self.results["hostnames"] = data.get("hostnames", [])
                self.results["vulns"] = data.get("vulns", [])
                self.results["os"] = data.get("os", "UNKNOWN_OS")
                
                log(f"Shodan Scan Complete: Found {len(self.results['ports'])} ports, {len(self.results['vulns'])} CVEs.", "SUCCESS")
                if self.results['vulns']:
                    log(f"  CVEs Found via Shodan: {', '.join(self.results['vulns'][:5])}", "WARNING")
            elif response.status_code == 404:
                log("No information found for this IP on Shodan.", "INFO")
            elif response.status_code == 401:
                log("Invalid Shodan API Key.", "ERROR")
            elif response.status_code == 403:
                log(
                    "Shodan host lookup requires paid membership (free/oss plan has no query credits). "
                    "Use nmap locally or upgrade at https://account.shodan.io/",
                    "WARNING",
                )
            else:
                log(f"Shodan API returned status code {response.status_code}", "ERROR")
        except requests.exceptions.RequestException as e:
            log(f"Shodan API request failed: {e}", "ERROR")
            
        return self.results
