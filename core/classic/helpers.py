import json
import os
import re
import shutil
import sys

from core.classic.context import build_url, normalize_url
from core.context_store import save_scan_context
from core.report import generate_scan_report
from core.scan_config import get_profile_name, get_scan_profile
from core.utils import run_cmd


def is_tool_available(tool_name):
    return shutil.which(tool_name) is not None


def prompt_next_stage():
    while True:
        choice = input(
            "\n[!] Ctrl+C detected. Do you want to skip the current phase and continue to the next stage? [Y/n] "
        ).strip().lower()
        if choice in ("", "y", "yes"):
            return True
        if choice in ("n", "no", "q", "quit", "exit"):
            return False
        print("Please enter 'y' to continue or 'n' to exit.")


def refresh_report(ip, target_dir, selection, exploited, context, phase):
    save_scan_context(target_dir, context, phase, get_profile_name(), exploited)
    report_path = generate_scan_report(
        ip, target_dir, selection, exploited, current_phase=phase, profile=get_profile_name()
    )
    print(f"[*] Report updated after {phase}: {report_path}")
    return report_path


def find_common_wordlist():
    profile = get_scan_profile()
    if profile["ffuf_wordlist"] == "medium":
        candidates = [
            "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
            "/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt",
            "/usr/share/seclists/Discovery/Web-Content/common.txt",
            "/usr/share/wordlists/dirb/common.txt",
        ]
    else:
        candidates = [
            "/usr/share/wordlists/dirb/common.txt",
            "/usr/share/seclists/Discovery/Web-Content/common.txt",
            "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
            "/usr/share/wordlists/rockyou.txt",
        ]
    for path in candidates:
        if os.path.exists(path):
            return path
    return None


def run_metasploit_search(query, target_dir):
    if not shutil.which("msfconsole"):
        print("[!] Metasploit (msfconsole) not found; skipping Metasploit lookup.")
        return False
    generic_queries = {"http", "https", "ssl", "tcp", "nginx", "httpd"}
    if query.lower().strip() in generic_queries:
        print(f"[*] Skipping generic Metasploit search for '{query}'.")
        return False
    log_file = os.path.join(target_dir, "msf_search.txt")
    msf_cmd = f"search {query}; exit"
    command = ["msfconsole", "-q", "-x", msf_cmd]
    success, output = run_cmd(command, capture=True, log_file=log_file)
    if output:
        print(output)
        print(f"[+] Metasploit search results saved to: {log_file}")
        return True
    return False


def run_gau(target_url, target_dir):
    if not is_tool_available("gau"):
        print("[!] gau is not installed; skipping GAU enumeration.")
        return []

    print("[+] Running GAU to gather historical URLs...")
    domain = re.sub(r"^https?://", "", target_url).split("/")[0]
    log_file = os.path.join(target_dir, "gau_urls.txt")
    command = ["gau", domain]
    success, output = run_cmd(command, capture=True, log_file=log_file)
    urls = []
    if output:
        for line in output.splitlines():
            line = line.strip()
            if line.startswith("http://") or line.startswith("https://"):
                urls.append(line)
    urls = list(dict.fromkeys(urls))
    if urls:
        print(f"[+] GAU found {len(urls)} URLs.")
    return urls


def run_ffuf(target_url, target_dir):
    profile = get_scan_profile()
    if not is_tool_available("ffuf"):
        print("[!] ffuf is not installed; skipping FFUF enumeration.")
        return []

    wordlist = find_common_wordlist()
    if not wordlist:
        print("[!] No common wordlist found for ffuf; skipping.")
        return []

    print("[+] Running ffuf for hidden content discovery...")
    port = target_url.split(":")[-1] if ":" in target_url.replace("https://", "").replace("http://", "") else "80"
    json_file = os.path.join(target_dir, f"ffuf_port_{port}.json")
    stdout_log = os.path.join(target_dir, f"ffuf_port_{port}_stdout.txt")
    fuzz_url = normalize_url(target_url) + "/FUZZ"
    command = [
        "ffuf", "-u", fuzz_url, "-w", wordlist,
        "-t", str(profile["ffuf_threads"]), "-s",
        "-o", json_file, "-of", "json",
        "-mc", "200,204,301,302,307,401,403,405,500",
    ]
    success, output = run_cmd(command, capture=True, log_file=stdout_log)
    if not success:
        print(f"[-] ffuf failed for {target_url}. Check {stdout_log}")

    urls = []
    if os.path.exists(json_file):
        try:
            with open(json_file, "r", encoding="utf-8", errors="ignore") as fh:
                content = fh.read().strip()
                if content:
                    data = json.loads(content)
                    for result in data.get("results", []):
                        url = result.get("url")
                        if url:
                            urls.append(url)
                            continue
                        fuzz_value = result.get("input", {}).get("FUZZ")
                        if fuzz_value:
                            urls.append(normalize_url(target_url) + "/" + fuzz_value.lstrip("/"))
        except Exception:
            pass
    urls = list(dict.fromkeys(urls))
    if urls:
        print(f"[+] ffuf discovered {len(urls)} paths.")
    return urls


def handle_keyboard_interrupt():
    if not prompt_next_stage():
        print("\n[-] Exiting as requested.")
        sys.exit(0)
