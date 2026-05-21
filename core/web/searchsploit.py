import shutil

from core.utils import run_cmd


def run_searchsploit(query, target_dir):
    if not shutil.which("searchsploit"):
        print("[!] searchsploit is not installed; skipping SearchSploit lookup.")
        return False
    log_file = os.path.join(target_dir, "searchsploit.txt")
    command = ["searchsploit", query]
    success, output = run_cmd(command, capture=True, log_file=log_file)
    if output and "No Results" not in output:
        print(output)
        print(f"[+] searchsploit results saved to: {log_file}")
        return True
    return False
