import os
from engines.utils import log
from engines.recon_agent import ReconAgent
from engines.scan_agent import ScanAgent
from engines.exploit_agent import ExploitAgent
from engines.lateral_agent import LateralAgent
from core.paths import project_root

class DecepticonCore:
    """
    The Orchestrator for the Decepticon Autonomous Kill-Chain Mode.
    Manages the flow: Recon -> Scan -> Exploit -> Lateral Movement.
    """
    def __init__(self, target):
        self.target = target
        
        # Setup output directory for this run
        self.target_clean = target.replace("http://", "").replace("https://", "").replace("/", "_")
        self.output_dir = os.path.join(project_root(), "targets", "decepticon", self.target_clean)
        os.makedirs(self.output_dir, exist_ok=True)
        
    def run_autonomous_mode(self):
        print("\n" + "*"*60)
        print("   [!] DECEPTICON AUTONOMOUS KILL-CHAIN INITIATED [!]")
        print(f"       Target: {self.target}")
        print("*"*60 + "\n")
        
        log("Initializing Multi-Agent System...", "INFO")
        
        # --- STAGE 1: RECON ---
        recon = ReconAgent(self.target, self.output_dir)
        recon_data = recon.execute()
        
        # Determine targets to pass to Stage 2
        # We start with the main target, plus any discovered subdomains or IPs
        scan_targets = [self.target]
        if recon_data.get("subdomains"):
            scan_targets.extend(recon_data["subdomains"])
        if recon_data.get("ips"):
            scan_targets.extend(recon_data["ips"])
            
        # Deduplicate targets
        scan_targets = list(set(scan_targets))
        
        if len(scan_targets) > 1:
            log(f"Expanding attack surface from 1 to {len(scan_targets)} targets...", "WARNING")
            
        # --- STAGE 2: SCANNING ---
        scanner = ScanAgent(scan_targets, self.output_dir)
        scan_data = scanner.execute()
        
        # --- STAGE 3: EXPLOITATION ---
        exploiter = ExploitAgent(self.target, scan_data, self.output_dir)
        exploit_data = exploiter.execute()
        
        # --- STAGE 4: LATERAL MOVEMENT ---
        lateral = LateralAgent(self.target, self.output_dir)
        lateral_data = lateral.execute()
        
        # --- REPORTING ---
        print("\n" + "*"*60)
        print("   DECEPTICON MISSION ACCOMPLISHED")
        print("*"*60)
        log(f"All agents finished. Detailed logs and outputs saved to: {self.output_dir}", "SUCCESS")
        
        if exploit_data:
            print("\n[!!!] CRITICAL SUCCESSES [!!!]")
            for ex in exploit_data:
                print(f"  -> {ex['type'].upper()} exploited on {ex.get('url', ex.get('target', 'UNKNOWN'))}: {ex['details']}")
        else:
             log("No automatic exploits succeeded. Review scan data for manual exploitation.", "INFO")
             
        input("\nPress Enter to return to the main menu...")
