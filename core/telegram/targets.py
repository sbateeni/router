"""Target parsing and scan job building."""

from core.report.parsers import (
    parse_target_input,
    sanitize_target_dir_name,
    target_scan_host,
    target_workspace_name,
)

from core.telegram.sessions import mode_label


def parse_target(text):
    return parse_target_input(text)


def target_prompt_text(target):
    host = target.get("host") or target.get("ip")
    lines = [f"الهدف: {host}"]
    if target.get("resolved_ip") and target.get("is_domain"):
        lines.append(f"DNS → {target['resolved_ip']}")
    if target.get("login_path"):
        lines.append(f"مسار: {target['login_path']}")
    if target.get("query_string"):
        lines.append(f"Query: ?{target['query_string']}")
    if target.get("raw") and target["raw"] != host:
        lines.append(f"URL: {target['raw']}")
    lines.append("\nاختر نوع الهجوم / المسح:")
    return "\n".join(lines)


def job_from_target(target, selection, scan_profile):
    scan_host = target_scan_host(target)
    return {
        "ip": scan_host,
        "scan_host": scan_host,
        "workspace_name": target_workspace_name(target),
        "selection": selection,
        "profile": scan_profile,
        "mode_label": mode_label(selection, scan_profile),
        "hints": {
            "host": target.get("host"),
            "login_path": target.get("login_path"),
            "seed_url": target.get("seed_url"),
            "query_string": target.get("query_string"),
            "port": target.get("port"),
            "scheme": target.get("scheme"),
            "resolved_ip": target.get("resolved_ip"),
            "is_domain": target.get("is_domain"),
            "raw": target.get("raw"),
        },
    }
