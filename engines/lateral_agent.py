import os
import subprocess
from engines.utils import log

class LateralAgent:
    """
    Phase 4: Lateral Movement Agent
    Uses NetExec (formerly CrackMapExec) to enumerate AD and move laterally.
    """
    def __init__(self, target, output_dir):
        self.target = target
        self.output_dir = output_dir
        self.results = []
        
        from core.paths import project_root
        self.tools_dir = os.path.join(project_root(), "tools")

    def run_netexec_smb(self):
        log(f"[LateralAgent] Running NetExec (SMB) against {self.target}...", "INFO")
        nxc_dir = os.path.join(self.tools_dir, "netexec")
        
        # Determine how to call netexec. If we installed it via pip, it might be in PATH as 'nxc'
        # Or we can run it via python from the cloned dir if we set up poetry, but standard pip install puts nxc in bin
        cmd = ["nxc", "smb", self.target, "--shares", "--users"]
        
        try:
            # Short timeout since it's just checking SMB info anonymously
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            if "SMB" in res.stdout:
                log("[LateralAgent] NetExec successfully enumerated SMB info.", "SUCCESS")
                # In a real scenario we parse this output for open shares or users
                self.results.append({"tool": "netexec_smb", "output_snippet": res.stdout[:500]})
            else:
                log("[LateralAgent] No anonymous SMB access or NetExec failed.", "INFO")
        except FileNotFoundError:
            log("[LateralAgent] 'nxc' command not found in PATH. Ensure NetExec is fully installed.", "WARNING")
        except Exception as e:
            log(f"[LateralAgent] NetExec error: {e}", "ERROR")

    def execute(self):
        print("\n" + "="*50)
        print("   [STAGE 4] LATERAL MOVEMENT AGENT INITIATED")
        print("="*50)
        
        # We only really do this if the target is an IP or subnet
        import re
        is_ip_or_subnet = re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(/\d{1,2})?$", self.target)
        if is_ip_or_subnet:
            self.run_netexec_smb()
        else:
            log("[LateralAgent] Target is a domain. Skipping internal network Lateral Movement (SMB/RDP checks).", "INFO")
            
        return self.results
