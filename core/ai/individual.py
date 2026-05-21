import json
import os

from core.ai.analyst import generate_ai_analysis
from core.ai.planner import plan_scan_tools, recommend_hydra_commands
from core.classic.context import build_context_from_ports
from core.context_store import save_scan_context
from core.scan_config import get_profile_name
from core.scanner import run_nmap


def load_existing_scan_plan(target_dir):
    path = os.path.join(target_dir, "AI_SCAN_PLAN.json")
    if not os.path.exists(path):
        return None
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, json.JSONDecodeError):
        return None


def run_ai_scan_plan_only(ip, target_dir):
    print("\n>>> TOOL: AI scan plan only")
    open_ports = run_nmap(ip, target_dir)
    context = build_context_from_ports(open_ports)
    context.ai_scan_plan = plan_scan_tools(ip, target_dir, context, use_ai=True)
    save_scan_context(target_dir, context, "AI Scan Plan", get_profile_name(), False)
    print(f"[+] Saved: {os.path.join(target_dir, 'AI_SCAN_PLAN.json')}")
    return False


def run_ai_hydra_plan_only(ip, target_dir):
    print("\n>>> TOOL: AI Hydra commands only")
    open_ports = run_nmap(ip, target_dir)
    context = build_context_from_ports(open_ports)
    scan_plan = load_existing_scan_plan(target_dir) or plan_scan_tools(
        ip, target_dir, context, use_ai=True,
    )
    context.ai_scan_plan = scan_plan
    context.ai_hydra_plan = recommend_hydra_commands(
        ip, target_dir, context, scan_plan=scan_plan, use_ai=True,
    )
    save_scan_context(target_dir, context, "AI Hydra Plan", get_profile_name(), False)
    print(f"[+] Saved: {os.path.join(target_dir, 'AI_HYDRA_PLAN.json')}")
    print(f"[+] Saved: {os.path.join(target_dir, 'AI_HYDRA_COMMANDS.txt')}")
    return False


def run_ai_report_only(ip, target_dir):
    print("\n>>> TOOL: AI final report only")
    generate_ai_analysis(ip, target_dir)
    return False
