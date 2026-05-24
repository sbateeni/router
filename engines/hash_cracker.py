import subprocess
import os
import shutil
from engines.utils import log

class HashCracker:
    def __init__(self, target_ip):
        self.target_ip = target_ip
        self.john_path = shutil.which("john")
        self.wordlist_path = "/usr/share/wordlists/rockyou.txt" # Default Kali wordlist
        
    def is_available(self):
        return self.john_path is not None

    def crack_hashes(self, hash_file, format=None):
        """Attempts to crack hashes in a given file using John the Ripper."""
        if not self.is_available():
            log("John the Ripper ('john') not found on system. Skipping auto-decryption.", "WARNING")
            return None

        if not os.path.exists(hash_file):
            log(f"Hash file not found: {hash_file}", "ERROR")
            return None

        if not os.path.exists(self.wordlist_path):
            # Fallback to a smaller wordlist if rockyou isn't unzipped or present
            log(f"Wordlist not found at {self.wordlist_path}. Using john's default rules.", "WARNING")
            cmd = ["john", hash_file]
        else:
            log(f"Starting John the Ripper with wordlist {self.wordlist_path}...", "INFO")
            cmd = ["john", f"--wordlist={self.wordlist_path}", hash_file]
            
        if format:
            cmd.insert(1, f"--format={format}")

        try:
            # Run John the Ripper
            process = subprocess.run(cmd, capture_output=True, text=True)
            
            # Show the results
            show_cmd = ["john", "--show", hash_file]
            if format:
                show_cmd.insert(1, f"--format={format}")
                
            show_process = subprocess.run(show_cmd, capture_output=True, text=True)
            
            output = show_process.stdout
            
            if "0 password hashes cracked" not in output:
                log("Successfully cracked one or more hashes!", "SUCCESS")
                
                # Save cracked passwords to loot
                cracked_passwords = []
                for line in output.splitlines():
                    if ":" in line and not line.startswith("0 password hashes"):
                        cracked_passwords.append(line.split(":")[1])
                return cracked_passwords
            else:
                log("Failed to crack hashes with current wordlist.", "INFO")
                return None
                
        except Exception as e:
            log(f"Error running John the Ripper: {e}", "ERROR")
            return None
