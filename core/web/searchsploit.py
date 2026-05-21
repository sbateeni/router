import os
import shutil

from core.utils import run_cmd


def run_searchsploit(query, target_dir, append=True):
    if not shutil.which("searchsploit"):
        print("[!] searchsploit is not installed; skipping SearchSploit lookup.")
        return False
    log_file = os.path.join(target_dir, "searchsploit.txt")
    header = f"\n{'=' * 60}\nSEARCH: {query}\n{'=' * 60}\n"
    command = ["searchsploit", query]
    success, output = run_cmd(command, capture=True)
    try:
        mode = "a" if append and os.path.exists(log_file) else "w"
        with open(log_file, mode, encoding="utf-8") as fh:
            if mode == "a":
                fh.write(header)
            fh.write(output or "")
            fh.write("\n")
    except OSError:
        pass
    if output:
        print(output[:1200] + ("..." if len(output) > 1200 else ""))
    print(f"[+] SearchSploit saved: {log_file} (query: {query})")
    return success or bool(output)
