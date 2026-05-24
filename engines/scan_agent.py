import os
import subprocess
from engines.utils import log

class ScanAgent:
    """
    Phase 2: Scanning & Vulnerability Assessment
    Uses Nuclei, Nikto, and WPScan to find vulnerabilities.
    """
    def __init__(self, targets_list, output_dir):
        # targets_list is a list of subdomains/IPs from Recon
        self.targets = targets_list
        self.output_dir = output_dir
        self.results = {
            "nuclei_vulns": [],
            "nikto_vulns": [],
            "wpscan_vulns": []
        }
        from core.paths import project_root
        self.tools_dir = os.path.join(project_root(), "tools")

    def run_nuclei(self):
        if not self.targets:
            return
            
        log("[ScanAgent] Running Nuclei on discovered targets...", "INFO")
        
        # Save targets to a file for nuclei
        targets_file = os.path.join(self.output_dir, "nuclei_targets.txt")
        with open(targets_file, "w") as f:
            for t in self.targets:
                # Nuclei prefers full URLs
                url = t if t.startswith("http") else f"http://{t}"
                f.write(f"{url}\n")
                
        out_file = os.path.join(self.output_dir, "nuclei_out.json")
        
        # Run nuclei with critical/high severity to focus on actionable exploits
        cmd = ["nuclei", "-l", targets_file, "-severity", "critical,high,medium", "-json-export", out_file, "-silent"]
        
        try:
            subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            if os.path.exists(out_file):
                import json
                with open(out_file, "r") as f:
                    for line in f:
                        if line.strip():
                            try:
                                vuln = json.loads(line)
                                self.results["nuclei_vulns"].append(vuln)
                            except:
                                pass
                log(f"[ScanAgent] Nuclei found {len(self.results['nuclei_vulns'])} critical/high vulns.", "SUCCESS")
            else:
                log("[ScanAgent] Nuclei found no severe vulnerabilities.", "INFO")
        except subprocess.TimeoutExpired:
            log("[ScanAgent] Nuclei timed out.", "WARNING")
        except Exception as e:
            log(f"[ScanAgent] Nuclei error: {e}", "ERROR")

    def run_nikto(self):
        # We pick the top target (the main domain) for nikto to save time
        if not self.targets: return
        main_target = self.targets[0]
        
        log(f"[ScanAgent] Running Nikto on {main_target}...", "INFO")
        nikto_dir = os.path.join(self.tools_dir, "nikto", "program")
        out_file = os.path.join(self.output_dir, "nikto_out.txt")
        
        if os.path.exists(nikto_dir):
            cmd = ["perl", os.path.join(nikto_dir, "nikto.pl"), "-h", main_target, "-Tuning", "1234b", "-o", out_file, "-Format", "txt", "-maxtime", "5m"]
            try:
                subprocess.run(cmd, capture_output=True, text=True, timeout=360)
                if os.path.exists(out_file):
                    with open(out_file, "r") as f:
                        self.results["nikto_vulns"] = f.readlines()
                    log("[ScanAgent] Nikto scan completed.", "SUCCESS")
            except Exception as e:
                log(f"[ScanAgent] Nikto error: {e}", "ERROR")
        else:
            log("[ScanAgent] Nikto not found. Skipping.", "WARNING")

    def run_wpscan(self):
        # Quick heuristic to see if any target is wordpress
        # In a real scenario we parse nuclei output, but for now we try the main target
        if not self.targets: return
        main_target = self.targets[0]
        
        log(f"[ScanAgent] Checking {main_target} with WPScan...", "INFO")
        
        cmd = ["wpscan", "--url", main_target if main_target.startswith("http") else f"http://{main_target}", "--no-update", "--no-banner", "-e", "vp,vt,u", "--format", "json"]
        try:
            # We use timeout because wpscan can take a while
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            if res.returncode == 0:
                log("[ScanAgent] WPScan identified WordPress and ran successfully.", "SUCCESS")
                self.results["wpscan_vulns"].append(res.stdout)
            else:
                log("[ScanAgent] Target does not appear to be WordPress or WPScan failed.", "INFO")
        except:
             log("[ScanAgent] WPScan not available or timed out.", "WARNING")

    def execute(self):
        print("\n" + "="*50)
        print("   [STAGE 2] SCAN & VULNERABILITY AGENT INITIATED")
        print("="*50)
        
        self.run_nuclei()
        self.run_nikto()
        self.run_wpscan()
        
        return self.results
