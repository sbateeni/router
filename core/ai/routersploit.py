from core.ai.planner import analyze_routersploit
from core.exploitation import run_routersploit, run_routersploit_module
from core.utils import sanitize_routersploit_modules


def run_routersploit_with_ai_followup(ip, target_dir, max_modules=3):
    """AI-only: RouterSploit AutoPwn plus AI-suggested follow-up modules."""
    print("\n>>> TOOL: AI RouterSploit + follow-up")
    if run_routersploit(ip, target_dir):
        return True

    plan = analyze_routersploit(ip, target_dir, use_ai=True)
    modules = sanitize_routersploit_modules(plan.get("modules_to_run") or [])
    if not modules:
        print("[*] No valid RouterSploit follow-up modules suggested.")
        return False

    print(f"[*] Trying {min(len(modules), max_modules)} RouterSploit module(s)...")
    for module in modules[:max_modules]:
        if run_routersploit_module(ip, module, target_dir):
            return True
    return False
