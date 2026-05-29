"""
AI-guided scan orchestrator — closed loop:
  workspace state → LLM next action → run tool → refresh → … → comprehensive report.

Falls back to heuristic routing when no API key is configured.
"""

from __future__ import annotations

import json
import os
from typing import Any

from core.ai.analyst import (
    ai_configured,
    ai_llm_available,
    ai_provider_status,
    call_ai_json,
    call_ai_text,
    generate_comprehensive_report,
)
from core.ai.analyst import reset_ai_session
from core.ai.workspace_state import (
    ALLOWED_TOOLS,
    append_orchestrator_log,
    append_step_note,
    build_workspace_state,
    save_workspace_state,
)
from core.notify import load_dotenv
from core.paths import project_root
from core.scan_cancel import ScanCancelled, check_cancelled
from engines.utils import log

ORCHESTRATOR_STATE_FILE = "AI_ORCHESTRATOR_STATE.json"
DEFAULT_MAX_STEPS = 12

SYSTEM_PROMPT = """You are the AUTO-PWN scan orchestrator for authorized router/camera pentests.
Return ONLY valid JSON (no markdown) with this schema:
{
  "reason_ar": "short Arabic explanation",
  "action": "run_tool|router_harvest|test_hikvision|test_router|finish",
  "tool": "nmap|nuclei|dirsearch|sqlmap|routersploit|ingram|hydra|ffuf|whatweb|nikto|nmap_vuln|router_harvest|test_hikvision|test_router|autopwn_engine",
  "inputs": {},
  "stop": false
}

Rules:
- action run_tool requires tool from allowed_next_tools only
- Never invent credentials, CVEs, or LAN clients not in workspace state
- router_harvest only if auth_url or auth_username is set
- ingram only for camera device types (hikvision, camera, dahua)
- routersploit/nuclei/hydra for router types
- Do not repeat tools in executed_tools unless finish
- Set action finish and stop true when enough data for final report or max steps near
- Prefer router_harvest early if user provided http://user:pass@ip/
- test_hikvision if port 8000 or 554 open or device.type suggests camera
- After nmap always run at least nuclei OR test_router for routers
"""


def _save_orch_state(target_dir: str, payload: dict[str, Any]) -> None:
    path = os.path.join(target_dir, ORCHESTRATOR_STATE_FILE)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2, ensure_ascii=False)


def load_orchestrator_progress(target_dir: str) -> dict[str, Any]:
    """Read live progress for GUI (step, tool, phase)."""
    path = os.path.join(target_dir, ORCHESTRATOR_STATE_FILE)
    if not os.path.isfile(path):
        return {}
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
        return data if isinstance(data, dict) else {}
    except (OSError, json.JSONDecodeError):
        return {}


def _looks_like_router_gateway(state: dict[str, Any]) -> bool:
    blob = (state.get("services_summary") or "").lower()
    if state.get("auth_username") or state.get("auth_url"):
        return True
    return any(
        x in blob
        for x in ("zyxel", "netis", "virtual web", "router", "gateway", "tplink", "fiberhome")
    )


def _heuristic_next_action(state: dict[str, Any]) -> dict[str, Any]:
    executed = set(state.get("executed_tools") or [])
    device_type = (state.get("device") or {}).get("type", "unknown")
    ports = state.get("open_ports") or []
    router_primary = _looks_like_router_gateway(state)

    if "nmap" not in executed and not state.get("has_nmap"):
        return {
            "reason_ar": "لا يوجد Nmap — فحص المنافذ أولاً",
            "action": "run_tool",
            "tool": "nmap",
            "inputs": {},
            "stop": False,
            "source": "heuristic",
        }

    if state.get("auth_url") and "router_harvest" not in executed:
        return {
            "reason_ar": "رابط يحتوي حساب دخول — حصاد داخل الراوتر",
            "action": "router_harvest",
            "tool": "router_harvest",
            "inputs": {},
            "stop": False,
            "source": "heuristic",
        }

    if device_type in ("router", "generic_router", "fiberhome_router", "unknown") or router_primary:
        for tool in ("nuclei", "test_router", "routersploit", "hydra", "dirsearch", "router_harvest"):
            if tool == "router_harvest":
                if not state.get("auth_username") or "router_harvest" in executed:
                    continue
                return {
                    "reason_ar": "راوتر — حصاد واجهة الإدارة",
                    "action": "router_harvest",
                    "tool": "router_harvest",
                    "inputs": {},
                    "stop": False,
                    "source": "heuristic",
                }
            if tool not in executed and tool in ALLOWED_TOOLS:
                labels = {
                    "nuclei": "قوالب CVE على الويب",
                    "routersploit": "وحدات استغلال الراوتر",
                    "hydra": "تخمين كلمات المرور",
                    "dirsearch": "مسارات الإدارة",
                    "test_router": "اختبار راوتر Netis/ZyXEL",
                }
                return {
                    "reason_ar": labels.get(tool, tool),
                    "action": "test_router" if tool == "test_router" else "run_tool",
                    "tool": tool,
                    "inputs": {},
                    "stop": False,
                    "source": "heuristic",
                }

    camera_type = device_type in ("camera", "hikvision_camera", "dahua_camera", "ip_camera")
    camera_ports = 8000 in ports or 554 in ports
    if (camera_type or (camera_ports and not router_primary)):
        if "test_hikvision" not in executed and camera_ports:
            return {
                "reason_ar": "منافذ كاميرا — اختبار Hikvision",
                "action": "test_hikvision",
                "tool": "test_hikvision",
                "inputs": {},
                "stop": False,
                "source": "heuristic",
            }
        if "ingram" not in executed and not router_primary:
            return {
                "reason_ar": "كاميرا — Ingram",
                "action": "run_tool",
                "tool": "ingram",
                "inputs": {},
                "stop": False,
                "source": "heuristic",
            }

    if router_primary and camera_ports and "test_hikvision" not in executed:
        return {
            "reason_ar": "راوتر مع منفذ 8000 — فحص Hikvision ثانوي",
            "action": "test_hikvision",
            "tool": "test_hikvision",
            "inputs": {},
            "stop": False,
            "source": "heuristic",
        }

    for rec in state.get("recommended_tools") or []:
        name = (rec.get("name") or "").lower()
        mapping = {
            "nmap": "nmap",
            "nuclei": "nuclei",
            "hydra": "hydra",
            "dirsearch": "dirsearch",
            "routersploit": "routersploit",
            "ingram": "ingram",
            "test hikvision": "test_hikvision",
            "test router": "test_router",
            "router deep harvest": "router_harvest",
        }
        for key, tool in mapping.items():
            if key in name and tool not in executed:
                return {
                    "reason_ar": rec.get("reason", "")[:100],
                    "action": "router_harvest" if tool == "router_harvest" else (
                        "test_hikvision" if tool == "test_hikvision" else (
                            "test_router" if tool == "test_router" else "run_tool"
                        )
                    ),
                    "tool": tool,
                    "inputs": {},
                    "stop": False,
                    "source": "heuristic",
                }

    return {
        "reason_ar": "اكتملت الخطوات المخططة — إنهاء وتوليد التقرير",
        "action": "finish",
        "tool": "",
        "inputs": {},
        "stop": True,
        "source": "heuristic",
    }


def decide_next_action(state: dict[str, Any]) -> dict[str, Any]:
    if not ai_llm_available():
        plan = _heuristic_next_action(state)
        plan["ai_available"] = ai_configured()
        plan["llm_available"] = False
        return plan

    prompt = f"""Workspace state JSON:
{json.dumps(state, ensure_ascii=False, indent=2)[:14000]}

Pick the single best next action. Respect executed_tools — do not repeat.
"""
    data = call_ai_json(prompt, system=SYSTEM_PROMPT)
    if not data or not isinstance(data, dict):
        plan = _heuristic_next_action(state)
        plan["ai_available"] = True
        plan["ai_fallback"] = True
        return plan

    action = str(data.get("action", "finish")).strip().lower()
    tool = str(data.get("tool", "")).strip().lower()
    allowed = state.get("allowed_next_tools") or list(ALLOWED_TOOLS.keys())

    if action == "run_tool" and tool not in allowed:
        if tool in (state.get("executed_tools") or []):
            data = _heuristic_next_action(state)
            data["ai_available"] = True
            data["ai_fallback"] = True
            return data
        tool = allowed[0] if allowed else ""

    if action == "router_harvest" and not state.get("auth_username"):
        data = _heuristic_next_action(state)
        data["ai_available"] = True
        return data

    data["source"] = "ai"
    data["ai_available"] = True
    return data


def _execute_action(
    action: dict[str, Any],
    *,
    ip: str,
    target_dir: str,
    raw_target: str,
    profile: str,
) -> bool:
    """Run one orchestrator action. Returns exploited flag if any."""
    check_cancelled()
    act = action.get("action", "finish")
    tool = action.get("tool", "")
    exploited = False

    if act == "finish":
        return False

    if act == "router_harvest" or tool == "router_harvest":
        from engines.router_harvest import run_router_harvest

        run_router_harvest(target_dir, raw_target or f"http://{ip}/")
        return True

    if act == "test_hikvision" or tool == "test_hikvision":
        from core.device_tests import run_hikvision_test

        run_hikvision_test(ip)
        return False

    if act == "test_router" or tool == "test_router":
        from core.device_tests import run_router_test

        run_router_test(ip)
        return False

    if act == "run_tool" and tool in ALLOWED_TOOLS:
        from core.runner import run_selected_tool

        meta = ALLOWED_TOOLS[tool]
        sel = meta.get("selection")
        if sel:
            exploited = bool(
                run_selected_tool(sel, ip, target_dir, profile=profile)
            )
        return exploited

    log(f"Unknown orchestrator action: {act}/{tool}", "ERROR")
    return False


def run_ai_guided_scan(
    ip: str,
    target_dir: str,
    *,
    raw_target: str = "",
    profile: str = "normal",
    max_steps: int | None = None,
) -> bool:
    """
    Full AI-guided loop. Returns True if any exploitation/creds found.
    """
    load_dotenv(project_root())
    reset_ai_session()
    max_steps = max_steps or int(os.environ.get("AI_ORCHESTRATOR_MAX_STEPS", DEFAULT_MAX_STEPS))
    executed: list[str] = []
    exploited_any = False
    orch_state: dict[str, Any] = {
        "step": 0,
        "max_steps": max_steps,
        "finished": False,
        "phase": "starting",
        "current_tool": "",
        "executed_count": 0,
        "last_reason": "",
    }
    _save_orch_state(target_dir, orch_state)

    log("=" * 60, "INFO")
    log("AI GUIDED SCAN — orchestrator start", "SUCCESS")
    llm = ai_llm_available()
    log(
        f"Target: {ip} | max_steps={max_steps} | LLM={'yes' if llm else 'heuristic'} | "
        f"providers: {ai_provider_status()}",
        "INFO",
    )
    log("=" * 60, "INFO")

    from core.scan_transcript import begin as transcript_begin, end as transcript_end

    transcript_begin(target_dir, header=f"AI Guided Scan | {ip} | profile={profile}")

    try:
        for step in range(1, max_steps + 1):
            check_cancelled()
            state = build_workspace_state(
                target_dir, ip, raw_target=raw_target, executed_tools=executed,
            )
            save_workspace_state(target_dir, state)

            orch_state.update({"phase": "deciding", "step": step, "current_tool": ""})
            _save_orch_state(target_dir, orch_state)

            decision = decide_next_action(state)
            reason = decision.get("reason_ar", "")
            tool = decision.get("tool", "")
            act = decision.get("action", "finish")
            source = decision.get("source", "?")

            log(f"[Step {step}/{max_steps}] {source}: {act} / {tool} — {reason}", "INFO")
            append_orchestrator_log(target_dir, {
                "step": step,
                "decision": decision,
                "state_snapshot": {
                    "ports": state.get("open_ports"),
                    "device": state.get("device"),
                    "credentials_count": len(state.get("credentials") or []),
                },
            })

            if (
                llm
                and decision.get("source") == "ai"
                and reason
                and os.environ.get("AI_ORCHESTRATOR_STEP_NOTES", "0").strip() in ("1", "true", "yes")
            ):
                note, provider = call_ai_text(
                    f"In one Arabic sentence, what do we expect from step {step} "
                    f"({tool or act}) on {ip}? Context: {reason}",
                    system="One short Arabic sentence only.",
                )
                if note:
                    append_step_note(target_dir, step, note, provider=provider or "")

            tool_key = tool if act == "run_tool" else (act or tool)
            orch_state.update({
                "step": step,
                "last_reason": reason,
                "planned_tool": tool_key,
                "decision_source": source,
            })
            _save_orch_state(target_dir, orch_state)

            if decision.get("stop") or act == "finish":
                log("[*] Orchestrator: finish requested", "INFO")
                break

            if tool_key in executed:
                log(f"[!] Duplicate step {tool_key} — ending orchestrator", "WARNING")
                break
            executed.append(tool_key)

            orch_state.update({
                "phase": "running",
                "current_tool": tool_key,
                "executed_count": len(executed),
            })
            _save_orch_state(target_dir, orch_state)

            if _execute_action(
                decision,
                ip=ip,
                target_dir=target_dir,
                raw_target=raw_target,
                profile=profile,
            ):
                exploited_any = True

            try:
                from core.recon.target_profile import build_target_profile, save_target_profile
                from core.classic.context import build_context_from_ports
                from core.workspace_ports import load_open_ports_from_workspace

                ctx = build_context_from_ports(load_open_ports_from_workspace(target_dir))
                prof = build_target_profile(ip, target_dir, context=ctx)
                save_target_profile(target_dir, prof)
            except Exception:
                pass

        orch_state.update({"phase": "report", "current_tool": "comprehensive_report"})
        _save_orch_state(target_dir, orch_state)

        log("[*] Generating comprehensive AI report…", "INFO")
        generate_comprehensive_report(ip, target_dir)

        try:
            from core.report import generate_scan_report

            generate_scan_report(
                ip, target_dir, 0, exploited_any,
                current_phase="AI Guided Complete",
                profile=profile,
            )
        except Exception:
            pass

        orch_state.update({
            "finished": True,
            "phase": "done",
            "step": orch_state.get("step", 0),
            "executed_count": len(executed),
            "current_tool": "",
        })
        _save_orch_state(target_dir, orch_state)

        final = build_workspace_state(
            target_dir, ip, raw_target=raw_target, executed_tools=executed,
        )
        save_workspace_state(target_dir, final)

        log(f"AI Guided Scan complete — steps={len(executed)}, exploited={exploited_any}", "SUCCESS")
        log(f"Report: {os.path.join(target_dir, 'AI_COMPREHENSIVE_REPORT.txt')}", "SUCCESS")

        if not ai_configured():
            log(
                "[!] No valid AI API key — used heuristic routing only. "
                "Set OPENROUTER_API_KEY or GEMINI_API_KEY in .env for full AI.",
                "WARNING",
            )

        try:
            from core.workflow_recommendations import emit_post_tool_recommendations

            emit_post_tool_recommendations(
                target_dir,
                ip,
                finished_tool="ai-guided-scan",
                job_kind="ai_guided",
                exploited=exploited_any,
            )
        except Exception:
            pass

        return exploited_any
    except ScanCancelled:
        raise
    finally:
        transcript_end()
