import re
from engines.utils import log

class HikvisionDecryptor:
    XOR_KEYS = (0x73, 0x56, 0x37)

    @staticmethod
    def _looks_like_password(text: str) -> bool:
        if len(text) < 6 or len(text) > 32:
            return False
        if not re.fullmatch(r"[a-zA-Z0-9@#$%^&*!._\-]+", text):
            return False
        if not re.search(r"[a-zA-Z]", text):
            return False
        if not re.search(r"\d", text):
            return False
        noise = ("http", "xml", "version", "hikvision", "admin", "password", "config")
        lower = text.lower()
        return not any(n in lower for n in noise)

    @staticmethod
    def decrypt(config_data):
        """Extract likely password strings from dumped configurationFile."""
        log("Attempting to decrypt Hikvision configurationFile...")
        passwords = []
        try:
            blobs = [config_data]
            for key in HikvisionDecryptor.XOR_KEYS:
                blobs.append(bytes(b ^ key for b in config_data))

            for blob in blobs:
                printable = "".join(chr(b) if 32 <= b <= 126 else " " for b in blob)
                patterns = [
                    r"<password>([^<]{3,64})</password>",
                    r"<passWord>([^<]{3,64})</passWord>",
                    r"<adminPassword>([^<]{3,64})</adminPassword>",
                ]
                for pattern in patterns:
                    for match in re.finditer(pattern, printable, re.IGNORECASE):
                        candidate = match.group(1).strip()
                        if HikvisionDecryptor._looks_like_password(candidate):
                            passwords.append(candidate)

                for match in re.finditer(r"[\x20-\x7e]{6,32}", printable):
                    candidate = match.group().strip()
                    if HikvisionDecryptor._looks_like_password(candidate):
                        passwords.append(candidate)

            passwords = list(dict.fromkeys(passwords))[:20]

            if passwords:
                log(f"Found {len(passwords)} likely password candidate(s) in config.", "SUCCESS")
                for pw in passwords[:5]:
                    log(f"  Config candidate: {pw}", "INFO")
            else:
                log("Config is AES-encrypted — using Router Scan wordlist + Digest auth.", "INFO")
        except Exception as e:
            log(f"Decryption failed: {e}", "ERROR")
        return passwords
