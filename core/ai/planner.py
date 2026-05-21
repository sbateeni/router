import json
import os
import re

from core.ai.analyst import ai_configured, call_ai_json, _read_optional
from core.utils import normalize_routersploit_module, sanitize_routersploit_modules

SCAN_PLAN_FILE = "AI_SCAN_PLAN.json"
HYDRA_PLAN_FILE = "AI_HYDRA_PLAN.json"
ROUTERSPLOIT_PLAN_FILE = "AI_ROUTERSPLOIT_PLAN.txt"

DEFAULT_SCAN_PLAN = {
    "device_type": "unknown",
    "device_label_ar": "غير معروف",
    "confidence": "low",
    "run_dirsearch": True,
    "run_nuclei": True,
    "run_ffuf": True,
    "run_gau": True,
    "run_sqlmap": True,
    "run_routersploit": True,
    "run_ingram": False,
    "run_hydra": True,
    "notes_ar": "",
    "source": "default",
}

DEFAULT_HYDRA_PLAN = {
    "users": ["admin", "root", "user", "support", "telecomadmin"],
    "http_forms": [
        "/login.html:user=^USER^&pass=^PASS^:F=invalid:F=failed:F=error:F=incorrect",
        "/login.cgi:username=^USER^&password=^PASS^:F=invalid:F=failed:F=error",
        "/goform/login:username=^USER^&password=^PASS^:F=invalid:F=failed:F=error",
        "/cgi-bin/login.cgi:username=^USER^&password=^PASS^:F=invalid:F=failed:F=error",
        "/login:username=^USER^&password=^PASS^:F=invalid:F=failed:F=error",
    ],
    "manual_commands": [],
    "notes_ar": "",
    "source": "default",
}

VENDOR_HYDRA_PRESETS = {
    "fiberhome_router": {
        "users": ["admin", "telecomadmin", "user", "support", "root"],
        "http_forms": [
            "/login.html:user=^USER^&pass=^PASS^:F=invalid:F=failed:F=error",
            "/goform/login:username=^USER^&password=^PASS^:F=invalid:F=failed:F=error",
            "/cgi-bin/login.cgi:username=^USER^&password=^PASS^:F=invalid:F=failed:F=error",
        ],
        "manual_commands": [
            "hydra -l admin -P routers.txt -s 443 -f 192.168.1.1 https-get",
            "hydra -L users.txt -P routers.txt -s 443 -f 192.168.1.1 http-post-form \"/login.html:user=^USER^&pass=^PASS^:F=invalid\"",
        ],
    },
    "hikvision_camera": {
        "users": ["admin", "888888", "666666", "12345", "root"],
        "http_forms": [
            "/doc/page/login.asp:username=^USER^&password=^PASS^:F=invalid:F=failed",
            "/ISAPI/Security/userCheck:username=^USER^&password=^PASS^:F=invalid",
            "/login.cgi:username=^USER^&password=^PASS^:F=invalid:F=failed",
        ],
        "manual_commands": [
            "hydra -l admin -P default-passwords.txt -s 80 -f 192.168.1.1 http-get",
            "hydra -L users.txt -P default-passwords.txt -s 80 -f 192.168.1.1 http-post-form \"/doc/page/login.asp:username=^USER^&password=^PASS^:F=invalid\"",
        ],
    },
}


def _save_json(target_dir, filename, payload):
    path = os.path.join(target_dir, filename)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2, ensure_ascii=False)
    return path


def _save_text(target_dir, filename, text):
    path = os.path.join(target_dir, filename)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)
    return path


def _merge_plan(defaults, overrides):
    plan = dict(defaults)
    if not isinstance(overrides, dict):
        return plan
    for key in plan:
        if key in overrides and overrides[key] is not None:
            plan[key] = overrides[key]
    return plan


def enforce_minimum_scan_plan(plan, context):
    """Keep essential web tools enabled for routers/cameras even if AI disables them."""
    device_type = plan.get("device_type", "unknown")
    if not context.web_ports:
        return plan

    router_types = {"fiberhome_router", "generic_router", "unknown"}
    camera_types = {"hikvision_camera", "dahua_camera", "ip_camera"}

    if device_type in router_types or device_type in camera_types:
        plan["run_dirsearch"] = True
        plan["run_nuclei"] = True
        plan["run_sqlmap"] = True
        if device_type in router_types:
            plan["run_ffuf"] = True
            plan["run_hydra"] = True
            plan["run_routersploit"] = True
            plan["run_ingram"] = False
            plan["run_gau"] = False
        if device_type in camera_types:
            plan["run_ffuf"] = True
            plan["run_hydra"] = True
            plan["run_ingram"] = True

    if context.login_ports or context.web_ports:
        plan["run_hydra"] = True

    if not plan.get("device_label_ar"):
        _, plan["device_label_ar"] = detect_device_from_ports(context.open_ports)

    return plan


def detect_device_from_ports(open_ports):
    vendor = ""
    services_text = ""
    for entry in open_ports:
        if not isinstance(entry, dict):
            continue
        if entry.get("port") == 0:
            vendor = (entry.get("vendor") or entry.get("service") or "").lower()
        if entry.get("service"):
            services_text += " " + entry["service"].lower()

    combined = f"{vendor} {services_text}"
    if "hikvision" in combined:
        return "hikvision_camera", "كاميرا Hikvision"
    if "dahua" in combined:
        return "dahua_camera", "كاميرا Dahua"
    if "fiberhome" in combined:
        return "fiberhome_router", "راوتر Fiberhome"
    if any(entry.get("port") in {554, 37777, 34567, 9000} for entry in open_ports if isinstance(entry, dict)):
        return "ip_camera", "كاميرا IP"
    if any(entry.get("port") in {80, 443, 8080, 8443} for entry in open_ports if isinstance(entry, dict)):
        return "generic_router", "راوتر / واجهة ويب"
    return "unknown", "غير معروف"


def heuristic_scan_plan(context):
    device_type, label_ar = detect_device_from_ports(context.open_ports)
    plan = dict(DEFAULT_SCAN_PLAN)
    plan["device_type"] = device_type
    plan["device_label_ar"] = label_ar
    plan["confidence"] = "medium"
    plan["source"] = "heuristic"

    if device_type in {"fiberhome_router", "generic_router"}:
        plan["run_ingram"] = False
        plan["run_gau"] = False
        plan["notes_ar"] = "راوتر: ركّز على RouterSploit و Hydra و Dirsearch/Nuclei."
    elif device_type in {"hikvision_camera", "dahua_camera", "ip_camera"}:
        plan["run_ingram"] = True
        plan["run_routersploit"] = True
        plan["notes_ar"] = "كاميرا: شغّل Ingram و Nuclei و Hydra على منافذ الويب."

    if not context.web_ports:
        plan["run_dirsearch"] = False
        plan["run_nuclei"] = False
        plan["run_ffuf"] = False
        plan["run_gau"] = False
        plan["run_sqlmap"] = False

    if not context.login_ports and not context.web_ports:
        plan["run_hydra"] = False

    return plan


def plan_scan_tools(ip, target_dir, context, use_ai=True):
    if not use_ai or not ai_configured():
        plan = heuristic_scan_plan(context)
        _save_json(target_dir, SCAN_PLAN_FILE, plan)
        print(f"[*] Scan plan ({plan['source']}): {plan['device_label_ar']}")
        return plan

    recon = _read_optional(os.path.join(target_dir, "recon_summary.json"), 4000)
    prompt = f"""You are a penetration testing planner for routers and IP cameras.
Based on recon for IP {ip}, return ONLY valid JSON (no markdown) with this schema:
{{
  "device_type": "fiberhome_router|hikvision_camera|dahua_camera|generic_router|ip_camera|unknown",
  "device_label_ar": "Arabic short label",
  "confidence": "high|medium|low",
  "run_dirsearch": true,
  "run_nuclei": true,
  "run_ffuf": true,
  "run_gau": true,
  "run_sqlmap": true,
  "run_routersploit": true,
  "run_ingram": true,
  "run_hydra": true,
  "notes_ar": "short Arabic explanation"
}}

Rules:
- Fiberhome / generic router: skip Ingram, prioritize RouterSploit, Hydra, Dirsearch
- Hikvision / Dahua camera: enable Ingram, Nuclei, Hydra on web ports
- Skip web tools if no web ports
- Skip hydra if no login or web ports

Web ports: {context.web_ports}
Login ports: {[entry.get('port') for entry in context.login_ports]}

=== RECON ===
{recon}
"""

    data = call_ai_json(prompt, system="You return only valid JSON for scan planning.")
    if not data:
        plan = heuristic_scan_plan(context)
        plan["notes_ar"] = (plan.get("notes_ar") or "") + " (فشل AI، استُخدمت قواعد محلية)"
    else:
        plan = _merge_plan(DEFAULT_SCAN_PLAN, data)
        plan["source"] = "ai"

    plan = enforce_minimum_scan_plan(plan, context)

    _save_json(target_dir, SCAN_PLAN_FILE, plan)
    print(f"[+] AI scan plan: {plan.get('device_label_ar')} ({plan.get('source')})")
    if plan.get("notes_ar"):
        print(f"    {plan['notes_ar']}")
    return plan


def heuristic_hydra_plan(context, scan_plan=None):
    device_type = (scan_plan or {}).get("device_type")
    if not device_type or device_type == "unknown":
        device_type, _ = detect_device_from_ports(context.open_ports)

    plan = dict(DEFAULT_HYDRA_PLAN)
    preset = VENDOR_HYDRA_PRESETS.get(device_type)
    if preset:
        plan.update(preset)
    plan["device_type"] = device_type
    plan["source"] = "heuristic"
    plan["notes_ar"] = f"اقتراح Hydra لـ {device_type}"
    return plan


def recommend_hydra_commands(ip, target_dir, context, scan_plan=None, use_ai=True):
    base_plan = heuristic_hydra_plan(context, scan_plan)

    if not use_ai or not ai_configured():
        _save_json(target_dir, HYDRA_PLAN_FILE, base_plan)
        _write_hydra_text_plan(target_dir, ip, base_plan)
        print(f"[*] Hydra plan ({base_plan['source']}): {len(base_plan['users'])} users, {len(base_plan['http_forms'])} forms")
        return base_plan

    recon = _read_optional(os.path.join(target_dir, "recon_summary.json"), 3000)
    paths = ", ".join(context.discovered_paths[:20]) if context.discovered_paths else "none"
    device_type = (scan_plan or {}).get("device_type", "unknown")

    prompt = f"""You are a Hydra brute-force expert for routers and cameras.
Target IP: {ip}
Device type: {device_type}
Web ports: {context.web_ports}
Discovered paths: {paths}

Return ONLY valid JSON:
{{
  "users": ["admin", "telecomadmin"],
  "http_forms": [
    "/login.html:user=^USER^&pass=^PASS^:F=invalid:F=failed"
  ],
  "manual_commands": [
    "hydra -l admin -P wordlist.txt -s 443 -f {ip} https-get"
  ],
  "notes_ar": "Arabic tips for this device"
}}

Rules:
- http_forms must use Hydra http-post-form syntax: path:fields:failures
- Fiberhome: telecomadmin, /login.html, /goform/login
- Hikvision: admin, /doc/page/login.asp
- Include 2-4 realistic manual_commands with IP {ip}

=== RECON ===
{recon}
"""

    data = call_ai_json(prompt, system="You return only valid JSON for Hydra planning.")
    if not data:
        plan = base_plan
        plan["notes_ar"] = (plan.get("notes_ar") or "") + " (فشل AI، استُخدمت قواعد محلية)"
    else:
        plan = _merge_plan(base_plan, data)
        plan["source"] = "ai"

    plan["users"] = _normalize_string_list(plan.get("users"), base_plan["users"])
    plan["http_forms"] = _normalize_string_list(plan.get("http_forms"), base_plan["http_forms"])
    plan["manual_commands"] = _normalize_string_list(plan.get("manual_commands"), base_plan.get("manual_commands", []))

    _save_json(target_dir, HYDRA_PLAN_FILE, plan)
    _write_hydra_text_plan(target_dir, ip, plan)
    print(f"[+] AI Hydra plan: {len(plan['users'])} users, {len(plan['http_forms'])} forms")
    return plan


def _normalize_string_list(value, fallback):
    if not isinstance(value, list):
        return list(fallback)
    cleaned = [str(item).strip() for item in value if str(item).strip()]
    return cleaned or list(fallback)


def _write_hydra_text_plan(target_dir, ip, plan):
    lines = [
        f"Target: {ip}",
        f"Source: {plan.get('source', 'unknown')}",
        f"Device: {plan.get('device_type', 'unknown')}",
        "",
        "=== Users ===",
        *plan.get("users", []),
        "",
        "=== HTTP POST forms (http-post-form) ===",
        *plan.get("http_forms", []),
        "",
        "=== Suggested manual commands ===",
    ]
    commands = plan.get("manual_commands") or []
    if commands:
        lines.extend(commands)
    else:
        lines.append("(none)")
    if plan.get("notes_ar"):
        lines.extend(["", "=== Notes ===", plan["notes_ar"]])
    _save_text(target_dir, "AI_HYDRA_COMMANDS.txt", "\n".join(lines))


def _parse_routersploit_modules(text):
    modules = []
    patterns = [
        r"routersploit/modules/((?:exploits|creds)/[\w./-]+)",
        r"((?:exploits|creds)/[\w./-]+)",
    ]
    for pattern in patterns:
        for match in re.findall(pattern, text):
            module = normalize_routersploit_module(match)
            if module and module not in modules:
                modules.append(module)
    return modules


def heuristic_routersploit_plan(target_dir):
    rsf_log = _read_optional(os.path.join(target_dir, "routersploit_scan.txt"), 8000)
    modules = _parse_routersploit_modules(rsf_log)
    promising = []
    for line in rsf_log.splitlines():
        lowered = line.lower()
        if "could not be verified" in lowered or "vulnerable" in lowered:
            found = _parse_routersploit_modules(line)
            for module in found:
                promising.append({
                    "module": module,
                    "reason": line.strip()[:200],
                    "priority": "medium",
                })

    return {
        "promising_modules": promising[:5],
        "modules_to_run": sanitize_routersploit_modules(modules)[:3],
        "summary_ar": "تحليل محلي لملف RouterSploit.",
        "source": "heuristic",
    }


def analyze_routersploit(ip, target_dir, use_ai=True):
    rsf_log = _read_optional(os.path.join(target_dir, "routersploit_scan.txt"), 10000)
    if not rsf_log.strip():
        print("[*] RouterSploit log empty; skipping AI analysis.")
        return heuristic_routersploit_plan(target_dir)

    if not use_ai or not ai_configured():
        plan = heuristic_routersploit_plan(target_dir)
        _write_routersploit_plan(target_dir, ip, plan)
        return plan

    prompt = f"""You are a RouterSploit expert.
Analyze this AutoPwn output for target {ip}.
Return ONLY valid JSON:
{{
  "promising_modules": [
    {{"module": "exploits/routers/vendor/module_name", "reason": "why try it", "priority": "high|medium|low"}}
  ],
  "modules_to_run": ["exploits/routers/...", "..."],
  "summary_ar": "Arabic summary with top 3 recommendations"
}}

Rules:
- Include modules marked 'Could not be verified' — they may still work manually
- modules_to_run: max 3 RouterSploit exploit/creds module paths to try next
- Use paths like exploits/routers/vendor/module_name (NO .py extension)
- NEVER include scanners/autopwn in modules_to_run
- Do not invent modules not suggested by the scan

=== ROUTERSPLOIT LOG ===
{rsf_log[:9000]}
"""

    data = call_ai_json(prompt, system="You return only valid JSON for RouterSploit follow-up.")
    if not data:
        plan = heuristic_routersploit_plan(target_dir)
        plan["summary_ar"] = (plan.get("summary_ar") or "") + " (فشل AI، استُخدم تحليل محلي)"
    else:
        plan = data
        plan["source"] = "ai"

    modules = plan.get("modules_to_run")
    if not isinstance(modules, list) or not modules:
        plan["modules_to_run"] = heuristic_routersploit_plan(target_dir).get("modules_to_run", [])

    plan["modules_to_run"] = sanitize_routersploit_modules(plan.get("modules_to_run"))
    promising = []
    for entry in plan.get("promising_modules", []):
        if isinstance(entry, dict):
            module = normalize_routersploit_module(entry.get("module"))
            if module:
                promising.append({**entry, "module": module})
        else:
            module = normalize_routersploit_module(entry)
            if module:
                promising.append(module)
    plan["promising_modules"] = promising[:5]

    _write_routersploit_plan(target_dir, ip, plan)
    print(f"[+] AI RouterSploit plan saved ({plan.get('source', 'unknown')})")
    return plan


def _write_routersploit_plan(target_dir, ip, plan):
    _save_json(target_dir, "AI_ROUTERSPLOIT_PLAN.json", plan)
    lines = [
        f"Target: {ip}",
        f"Source: {plan.get('source', 'unknown')}",
        "",
        "=== Modules to run next ===",
    ]
    for module in plan.get("modules_to_run", []):
        lines.append(f"- {module}")
    lines.extend(["", "=== Promising modules ==="])
    for entry in plan.get("promising_modules", []):
        if isinstance(entry, dict):
            lines.append(f"- [{entry.get('priority', '?')}] {entry.get('module', '?')}: {entry.get('reason', '')}")
        else:
            lines.append(f"- {entry}")
    if plan.get("summary_ar"):
        lines.extend(["", "=== Summary (AR) ===", plan["summary_ar"]])
    _save_text(target_dir, ROUTERSPLOIT_PLAN_FILE, "\n".join(lines))
