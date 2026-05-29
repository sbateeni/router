"""
AI-guided scan orchestrator — hybrid loop:
  local tools run on disk → compact workspace state → local rules OR LLM (if ambiguous)
  → … → one AI report at the end (optional).

Modes (AI_ORCHESTRATOR_MODE):
  hybrid      — default: local decisions; LLM only when unclear (saves tokens)
  local_rules — no LLM for step decisions; AI report at end if API available
  full_ai     — LLM chooses every step (highest token use)
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
ORCHESTRATOR_MODES = frozenset({"hybrid", "local_rules", "full_ai"})


def get_orchestrator_mode() -> str:
    mode = os.environ.get("AI_ORCHESTRATOR_MODE", "hybrid").strip().lower()
    return mode if mode in ORCHESTRATOR_MODES else "hybrid"


def ai_report_at_end_enabled() -> bool:
    return os.environ.get("AI_ORCHESTRATOR_AI_REPORT", "1").strip().lower() in (
        "1", "true", "yes", "on",
    )

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
- router_harvest if auth_url, auth_username, or ROUTER_ACCESS / test_router creds in workspace
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
    if state.get("auth_username") or state.get("auth_url") or state.get("has_router_web_creds"):
        return True
    return any(
        x in blob
        for x in ("zyxel", "netis", "virtual web", "router", "gateway", "tplink", "fiberhome")
    )


def _has_router_web_creds(state: dict[str, Any]) -> bool:
    if state.get("auth_username") or state.get("has_router_web_creds"):
        return True
    for c in state.get("credentials") or []:
        if c.get("username") and c.get("password"):
            return True
    return False


def _heuristic_plan(
    reason_ar: str,
    *,
    action: str,
    tool: str,
    stop: bool = False,
) -> dict[str, Any]:
    return {
        "reason_ar": reason_ar,
        "action": action,
        "tool": tool,
        "inputs": {},
        "stop": stop,
        "source": "heuristic",
    }


def _heuristic_next_action(state: dict[str, Any]) -> dict[str, Any]:
    executed = set(state.get("executed_tools") or [])
    device_type = (state.get("device") or {}).get("type", "unknown")
    ports = state.get("open_ports") or []
    router_primary = _looks_like_router_gateway(state)
    camera_ports = 8000 in ports or 554 in ports
    has_creds = _has_router_web_creds(state)

    if "nmap" not in executed and not state.get("has_nmap"):
        return _heuristic_plan(
            "لا يوجد Nmap — فحص المنافذ أولاً",
            action="run_tool",
            tool="nmap",
        )

    if (
        has_creds
        and "router_harvest" not in executed
        and (state.get("auth_url") or "test_router" in executed)
    ):
        return _heuristic_plan(
            "حساب راوتر متاح — حصاد واجهة الإدارة (Wi‑Fi / LAN / WAN)",
            action="router_harvest",
            tool="router_harvest",
        )

    if device_type in ("router", "generic_router", "fiberhome_router", "unknown") or router_primary:
        router_sequence: list[tuple[str, str, str]] = [
            ("test_router", "test_router", "اختبار راوتر Netis/ZyXEL وكلمات افتراضية"),
            ("router_harvest", "router_harvest", "حصاد بعد تأكيد الدخول"),
            ("nuclei", "run_tool", "قوالب CVE على الويب"),
            ("routersploit", "run_tool", "وحدات استغلال الراوتر"),
            ("dirsearch", "run_tool", "مسارات الإدارة"),
        ]
        if not has_creds:
            router_sequence.append(("hydra", "run_tool", "تخمين كلمات المرور (لا يوجد دخول بعد)"))

        for tool, action, label in router_sequence:
            if tool == "router_harvest":
                if tool in executed or not _has_router_web_creds(state):
                    continue
                return _heuristic_plan(label, action=action, tool=tool)
            if tool in executed or tool not in ALLOWED_TOOLS:
                continue
            if tool == "hydra" and has_creds:
                continue
            return _heuristic_plan(label, action=action, tool=tool)

        if router_primary and camera_ports and "test_hikvision" not in executed:
            if "test_router" in executed or "nuclei" in executed:
                return _heuristic_plan(
                    "راوتر مع منفذ كاميرا — فحص Hikvision ثانوي بعد الراوتر",
                    action="test_hikvision",
                    tool="test_hikvision",
                )

        if router_primary:
            router_core = {"test_router", "router_harvest", "nuclei", "routersploit", "dirsearch"}
            camera_done = not camera_ports or "test_hikvision" in executed
            if router_core.issubset(executed) and camera_done:
                return _heuristic_plan(
                    "اكتمل مسار الراوتر — إنهاء (بدون Ingram على بوابة Netis)",
                    action="finish",
                    tool="",
                    stop=True,
                )

    camera_type = device_type in ("camera", "hikvision_camera", "dahua_camera", "ip_camera")
    if (camera_type or (camera_ports and not router_primary)):
        if "test_hikvision" not in executed and camera_ports:
            return _heuristic_plan(
                "منافذ كاميرا — اختبار Hikvision",
                action="test_hikvision",
                tool="test_hikvision",
            )
        if "ingram" not in executed and not router_primary:
            return _heuristic_plan(
                "كاميرا — Ingram",
                action="run_tool",
                tool="ingram",
            )

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
        skip_on_router = frozenset({"ingram", "nmap", "hydra"})
        for key, tool in mapping.items():
            if router_primary and tool in skip_on_router:
                continue
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


def _compact_state_for_llm(state: dict[str, Any]) -> dict[str, Any]:
    """Smaller JSON for LLM calls — full artifacts stay on disk."""
    creds = state.get("credentials") or []
    return {
        "target_ip": state.get("target_ip"),
        "open_ports": state.get("open_ports"),
        "services_summary": (state.get("services_summary") or "")[:400],
        "device": state.get("device"),
        "has_nmap": state.get("has_nmap"),
        "auth_username": state.get("auth_username"),
        "executed_tools": state.get("executed_tools"),
        "allowed_next_tools": state.get("allowed_next_tools"),
        "credentials_count": len(creds),
        "credentials_sample": creds[:5],
        "nuclei": state.get("nuclei"),
        "router_harvest_pages": state.get("router_harvest_pages"),
        "lan_clients_count": len(state.get("lan_clients") or []),
        "recommended_tools": (state.get("recommended_tools") or [])[:4],
    }


def _needs_llm_decision(state: dict[str, Any], heuristic: dict[str, Any]) -> bool:
    """Hybrid: LLM only when heuristic wants finish but recon is still thin."""
    if heuristic.get("action") != "finish":
        return False
    executed = state.get("executed_tools") or []
    if not state.get("has_nmap"):
        return False
    if len(executed) < 2:
        return True
    if not _has_router_web_creds(state) and _looks_like_router_gateway(state):
        if "test_router" not in executed:
            return True
    return False


def _finalize_plan(plan: dict[str, Any], *, mode: str, path: str = "") -> dict[str, Any]:
    plan["mode"] = mode
    plan["decision_path"] = path or plan.get("source", "")
    plan["ai_available"] = ai_configured()
    plan["llm_available"] = ai_llm_available()
    return plan


def _decide_with_llm(state: dict[str, Any]) -> dict[str, Any]:
    compact = _compact_state_for_llm(state)
    prompt = f"""Workspace state JSON:
{json.dumps(compact, ensure_ascii=False, indent=2)}

Pick the single best next action. Respect executed_tools — do not repeat.
"""
    data = call_ai_json(prompt, system=SYSTEM_PROMPT)
    if not data or not isinstance(data, dict):
        plan = _heuristic_next_action(state)
        plan["ai_fallback"] = True
        return _finalize_plan(plan, mode=get_orchestrator_mode(), path="heuristic_fallback")

    action = str(data.get("action", "finish")).strip().lower()
    tool = str(data.get("tool", "")).strip().lower()
    allowed = state.get("allowed_next_tools") or list(ALLOWED_TOOLS.keys())

    if action == "run_tool" and tool not in allowed:
        if tool in (state.get("executed_tools") or []):
            plan = _heuristic_next_action(state)
            plan["ai_fallback"] = True
            return _finalize_plan(plan, mode=get_orchestrator_mode(), path="heuristic_fallback")
        tool = allowed[0] if allowed else ""

    if action == "router_harvest" and not _has_router_web_creds(state):
        plan = _heuristic_next_action(state)
        return _finalize_plan(plan, mode=get_orchestrator_mode(), path="heuristic_fallback")

    data["source"] = "ai"
    data["tool"] = tool
    data["action"] = action
    return _finalize_plan(data, mode=get_orchestrator_mode(), path="llm")


def decide_next_action(state: dict[str, Any]) -> dict[str, Any]:
    mode = get_orchestrator_mode()
    heuristic = _heuristic_next_action(state)

    if mode == "local_rules" or not ai_llm_available():
        return _finalize_plan(heuristic, mode=mode, path="local")

    if mode == "full_ai":
        return _decide_with_llm(state)

    # hybrid: always use local rules while a tool step remains; LLM only at finish if thin
    if heuristic.get("action") != "finish":
        return _finalize_plan(heuristic, mode="hybrid", path="local")

    if _needs_llm_decision(state, heuristic):
        log("[*] Hybrid: recon thin at finish — one LLM decision", "INFO")
        return _decide_with_llm(state)

    return _finalize_plan(heuristic, mode="hybrid", path="local")


def _bootstrap_recon(
    ip: str,
    target_dir: str,
    *,
    raw_target: str,
    profile: str,
    executed: list[str],
) -> bool:
    """Run Nmap locally before the loop if workspace has no scan yet (zero AI tokens)."""
    state = build_workspace_state(
        target_dir, ip, raw_target=raw_target, executed_tools=executed,
    )
    if state.get("has_nmap") or "nmap" in executed:
        return False
    log("[*] Bootstrap: Nmap locally (no AI tokens for this step)", "INFO")
    decision = {
        "action": "run_tool",
        "tool": "nmap",
        "reason_ar": "فحص منافذ أولي محلي",
        "source": "bootstrap",
        "stop": False,
    }
    _execute_action(
        decision,
        ip=ip,
        target_dir=target_dir,
        raw_target=raw_target,
        profile=profile,
    )
    executed.append("nmap")
    return True


def _generate_final_report(ip: str, target_dir: str) -> None:
    if not ai_report_at_end_enabled():
        from core.ai.analyst import generate_offline_comprehensive_report

        log("[*] Final report: offline template (AI_ORCHESTRATOR_AI_REPORT=0)", "INFO")
        generate_offline_comprehensive_report(ip, target_dir)
        return
    if ai_llm_available():
        log("[*] Final report: AI comprehensive (single LLM call)", "INFO")
        generate_comprehensive_report(ip, target_dir)
    else:
        from core.ai.analyst import generate_offline_comprehensive_report

        log("[*] Final report: offline (no LLM available)", "INFO")
        generate_offline_comprehensive_report(ip, target_dir)


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
        from core.target_auth import creds_from_router_access, parse_target_auth
        from engines.router_harvest import run_router_harvest

        harvest_url = raw_target
        if not parse_target_auth(harvest_url or ""):
            access = creds_from_router_access(target_dir)
            if access:
                u, p = access
                harvest_url = f"http://{u}:{p}@{ip}/"
            else:
                state = build_workspace_state(
                    target_dir, ip, raw_target=raw_target, executed_tools=[],
                )
                u = state.get("auth_username")
                p = state.get("auth_password") or ""
                if u:
                    harvest_url = f"http://{u}:{p}@{ip}/"
        run_router_harvest(target_dir, harvest_url or f"http://{ip}/")
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
            prev_nested = os.environ.get("AUTOPWN_NESTED_TOOL")
            os.environ["AUTOPWN_NESTED_TOOL"] = "1"
            try:
                exploited = bool(
                    run_selected_tool(sel, ip, target_dir, profile=profile)
                )
            finally:
                if prev_nested is None:
                    os.environ.pop("AUTOPWN_NESTED_TOOL", None)
                else:
                    os.environ["AUTOPWN_NESTED_TOOL"] = prev_nested
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
    mode = get_orchestrator_mode()
    max_steps = max_steps or int(os.environ.get("AI_ORCHESTRATOR_MAX_STEPS", DEFAULT_MAX_STEPS))
    executed: list[str] = []
    exploited_any = False
    orch_state: dict[str, Any] = {
        "step": 0,
        "max_steps": max_steps,
        "mode": mode,
        "finished": False,
        "phase": "starting",
        "current_tool": "",
        "executed_count": 0,
        "last_reason": "",
        "llm_decisions": 0,
    }
    _save_orch_state(target_dir, orch_state)

    log("=" * 60, "INFO")
    log("AI GUIDED SCAN — orchestrator start", "SUCCESS")
    llm = ai_llm_available()
    log(
        f"Target: {ip} | mode={mode} | max_steps={max_steps} | LLM={'yes' if llm else 'no'} | "
        f"providers: {ai_provider_status()}",
        "INFO",
    )
    if mode == "hybrid":
        log("[*] Hybrid: local tools + rules; LLM only if ambiguous; one AI report at end", "INFO")
    elif mode == "local_rules":
        log("[*] Local rules: no LLM step decisions; AI report at end if configured", "INFO")
    log("=" * 60, "INFO")

    from core.scan_transcript import begin as transcript_begin, end as transcript_end

    transcript_begin(target_dir, header=f"AI Guided Scan | {ip} | profile={profile} | mode={mode}")

    prev_nested = os.environ.get("AUTOPWN_NESTED_TOOL")
    os.environ["AUTOPWN_NESTED_TOOL"] = "1"
    try:
        if profile.strip().lower() == "deep":
            log(
                "[*] Profile=deep: Masscan + deep Nmap enabled (slower). "
                "For faster AI Guided scans set toolbar profile to Normal.",
                "INFO",
            )

        if _bootstrap_recon(
            ip, target_dir, raw_target=raw_target, profile=profile, executed=executed,
        ):
            try:
                from core.recon.target_profile import build_target_profile, save_target_profile
                from core.classic.context import build_context_from_ports
                from core.workspace_ports import load_open_ports_from_workspace

                ctx = build_context_from_ports(load_open_ports_from_workspace(target_dir))
                prof = build_target_profile(ip, target_dir, context=ctx)
                save_target_profile(target_dir, prof)
            except Exception:
                pass

        llm_decisions = 0
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
            path = decision.get("decision_path", source)
            if source == "ai":
                llm_decisions += 1

            tag = "heuristic" if path == "local" or source in ("heuristic", "bootstrap") else source
            if path == "llm":
                tag = "ai"
            log(
                f"[Step {step}/{max_steps}] {tag}: {act} / {tool} — {reason}",
                "INFO",
            )
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

        log(
            f"[*] Orchestrator stats: local_steps={len(executed)}, llm_decisions={llm_decisions}",
            "INFO",
        )
        _generate_final_report(ip, target_dir)

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
            "llm_decisions": llm_decisions,
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
        if prev_nested is None:
            os.environ.pop("AUTOPWN_NESTED_TOOL", None)
        else:
            os.environ["AUTOPWN_NESTED_TOOL"] = prev_nested
        transcript_end()
