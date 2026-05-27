import sys
import os
import json
import subprocess
from engines.utils import log

class ReconAgent:
    """
    Phase 1: Reconnaissance
    Uses Amass, theHarvester, SpiderFoot.
    """
    def __init__(self, target, output_dir):
        self.target = target
        self.output_dir = output_dir
        self.results = {
            "subdomains": [],
            "emails": [],
            "ips": [],
            "open_ports": [],
            "osint_data": {}
        }
        
        # Ensure tools directory exists
        from core.paths import project_root
        self.tools_dir = os.path.join(project_root(), "tools")

    def run_amass(self):
        log(f"[ReconAgent] Running Amass on {self.target}...", "INFO")
        out_file = os.path.join(self.output_dir, "amass_out.txt")
        amass_path = os.path.join(self.tools_dir, "amass", "amass")
        
        # We try to run the locally downloaded amass if it's compiled, otherwise system wide
        cmd = ["amass", "enum", "-passive", "-d", self.target, "-o", out_file]
        
        if os.path.exists(amass_path) and os.access(amass_path, os.X_OK):
            cmd[0] = amass_path
            
        try:
            # We use timeout because recon can take forever
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            if os.path.exists(out_file):
                with open(out_file, "r") as f:
                    subs = [line.strip() for line in f if line.strip()]
                    self.results["subdomains"].extend(subs)
                    log(f"[ReconAgent] Amass found {len(subs)} subdomains.", "SUCCESS")
            else:
                log("[ReconAgent] Amass returned no output file.", "WARNING")
        except subprocess.TimeoutExpired:
            log("[ReconAgent] Amass timed out. Moving on.", "WARNING")
        except Exception as e:
            log(f"[ReconAgent] Amass error: {e}", "ERROR")

    def run_the_harvester(self):
        log(f"[ReconAgent] Running theHarvester on {self.target}...", "INFO")
        harvester_dir = os.path.join(self.tools_dir, "theHarvester")
        out_file = os.path.join(self.output_dir, "harvester_out.json")
        
        if os.path.exists(harvester_dir):
            cmd = ["python", os.path.join(harvester_dir, "theHarvester.py"), "-d", self.target, "-b", "duckduckgo", "-f", out_file]
            try:
                subprocess.run(cmd, capture_output=True, text=True, timeout=60)
                if os.path.exists(out_file):
                    with open(out_file, "r") as f:
                        data = json.load(f)
                        if "emails" in data:
                            self.results["emails"].extend(data["emails"])
                        if "hosts" in data:
                            self.results["subdomains"].extend(data["hosts"])
                    log(f"[ReconAgent] theHarvester finished.", "SUCCESS")
            except Exception as e:
                log(f"[ReconAgent] theHarvester error: {e}", "ERROR")
        else:
            log("[ReconAgent] theHarvester not found in tools directory.", "WARNING")

    def execute(self):
        print("\n" + "="*50)
        print("   [STAGE 1] RECONNAISSANCE AGENT INITIATED")
        print("="*50)

        # Only run DNS-based recon if it looks like a domain, not an IP
        import re
        is_ip = re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", self.target)
        if not is_ip:
            self.run_amass()
            self.run_the_harvester()
            
        # Deduplicate
        self.results["subdomains"] = list(set(self.results["subdomains"]))
        self.results["emails"] = list(set(self.results["emails"]))
        self.results["open_ports"] = list(set(self.results["open_ports"]))
        
        log(f"[ReconAgent] Summary: {len(self.results['subdomains'])} Subdomains, {len(self.results['emails'])} Emails, {len(self.results['open_ports'])} Ports.", "SUCCESS")
        return self.results
