import json
import os
import re
import requests

from core.notify import load_dotenv

AI_REPORT_FILE = "AI_ANALYSIS.txt"
AI_COMPREHENSIVE_FILE = "AI_COMPREHENSIVE_REPORT.txt"
MAX_INPUT_CHARS = 12000
PLACEHOLDER_MARKERS = ("your_", "_here", "changeme", "placeholder", "example")


def _looks_like_placeholder(value):
    if not value or not str(value).strip():
        return True
    lowered = str(value).strip().lower()
    return any(marker in lowered for marker in PLACEHOLDER_MARKERS)


def _valid_api_key(env_name):
    value = os.environ.get(env_name, "")
    return bool(value) and not _looks_like_placeholder(value)


def ai_configured():
    return (
        _valid_api_key("OPENROUTER_API_KEY")
        or _valid_api_key("GEMINI_API_KEY")
        or _valid_api_key("NVIDIA_API_KEY")
    )


def ai_placeholder_keys_present():
    keys = ("OPENROUTER_API_KEY", "GEMINI_API_KEY", "NVIDIA_API_KEY")
    return any(os.environ.get(name) and _looks_like_placeholder(os.environ.get(name)) for name in keys)


def _read_optional(path, limit=MAX_INPUT_CHARS):
    if not os.path.exists(path):
        return ""
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            return fh.read(limit)
    except OSError:
        return ""


def _extract_json(text):
    if not text:
        return None
    text = text.strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    fenced = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL | re.IGNORECASE)
    if fenced:
        try:
            return json.loads(fenced.group(1))
        except json.JSONDecodeError:
            pass

    match = re.search(r"\{.*\}", text, re.DOTALL)
    if match:
        try:
            return json.loads(match.group(0))
        except json.JSONDecodeError:
            return None
    return None


def _call_openrouter(prompt, system):
    api_key = os.environ.get("OPENROUTER_API_KEY")
    if not api_key:
        return None
    model = os.environ.get("OPENROUTER_MODEL", "google/gemini-2.5-flash")
    base_url = os.environ.get("OPENROUTER_BASE_URL", "https://openrouter.ai/api/v1").rstrip("/")
    response = requests.post(
        f"{base_url}/chat/completions",
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        },
        json={
            "model": model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": prompt},
            ],
            "temperature": 0.2,
        },
        timeout=90,
    )
    response.raise_for_status()
    data = response.json()
    return data["choices"][0]["message"]["content"].strip()


def _call_gemini(prompt, system):
    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key:
        return None
    model = os.environ.get("GEMINI_MODEL", "gemini-2.0-flash")
    url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"
    combined = f"{system}\n\n{prompt}"
    response = requests.post(
        url,
        params={"key": api_key},
        json={"contents": [{"parts": [{"text": combined}]}]},
        timeout=90,
    )
    response.raise_for_status()
    data = response.json()
    return data["candidates"][0]["content"]["parts"][0]["text"].strip()


def _call_nvidia(prompt, system):
    api_key = os.environ.get("NVIDIA_API_KEY")
    if not api_key:
        return None
    model = os.environ.get("NVIDIA_MODEL", "meta/llama-3.1-70b-instruct")
    base_url = os.environ.get("NVIDIA_BASE_URL", "https://integrate.api.nvidia.com/v1").rstrip("/")
    response = requests.post(
        f"{base_url}/chat/completions",
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        },
        json={
            "model": model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": prompt},
            ],
            "temperature": 0.2,
        },
        timeout=90,
    )
    response.raise_for_status()
    data = response.json()
    return data["choices"][0]["message"]["content"].strip()


def call_ai_text(prompt, system="You analyze security scan reports accurately."):
    providers = [
        ("OpenRouter", _call_openrouter),
        ("Gemini", _call_gemini),
        ("NVIDIA", _call_nvidia),
    ]
    for name, caller in providers:
        try:
            result = caller(prompt, system)
            if result:
                return result, name
        except Exception as exc:
            print(f"[!] {name} AI call failed: {exc}")
    return None, None


def call_ai_json(prompt, system="You return only valid JSON."):
    text, provider = call_ai_text(prompt, system)
    if not text:
        return None
    parsed = _extract_json(text)
    if parsed is None:
        print(f"[!] {provider or 'AI'} returned non-JSON response.")
    return parsed


def _build_comprehensive_context(ip: str, target_dir: str) -> str:
    """Aggregate all major artifacts for final report."""
    chunks: list[str] = []

    try:
        from core.ai.workspace_state import build_workspace_state

        state = build_workspace_state(target_dir, ip)
        chunks.append("=== WORKSPACE STATE (structured) ===\n" + json.dumps(state, ensure_ascii=False, indent=2)[:8000])
    except Exception as exc:
        chunks.append(f"=== WORKSPACE STATE (error: {exc}) ===")

    files = [
        ("RESULTS_SUMMARY.txt", 5000),
        ("ROUTER_HARVEST.txt", 6000),
        ("ROUTER_HARVEST.json", 4000),
        ("ROUTER_LAN_CLIENTS.json", 3000),
        ("ENGINE_LOOT.json", 4000),
        ("hikvision_test_report.json", 4000),
        ("target_profile.json", 3500),
        ("workflow_recommendations.json", 2500),
        ("AI_ORCHESTRATOR_LOG.jsonl", 4000),
        ("AI_STEP_NOTES.jsonl", 2500),
        ("nmap_scan.txt", 3500),
        ("scan_context.json", 2500),
        ("recon_summary.json", 2500),
    ]
    for name, limit in files:
        path = os.path.join(target_dir, name)
        text = _read_optional(path, limit)
        if text.strip():
            chunks.append(f"=== {name} ===\n{text}")

    nuclei = _read_optional(os.path.join(target_dir, "nuclei_port_443_notags.jsonl"), 2500)
    if not nuclei:
        nuclei = _read_optional(os.path.join(target_dir, "nuclei_port_80_notags.jsonl"), 2500)
    if nuclei:
        chunks.append(f"=== NUCLEI SAMPLE ===\n{nuclei}")

    return "\n\n".join(chunks)[:28000]


def _build_prompt(ip, target_dir):
    return _build_comprehensive_context(ip, target_dir)


def _build_comprehensive_prompt(ip, target_dir):
    body = _build_comprehensive_context(ip, target_dir)
    return f"""You are a senior penetration testing analyst writing the FINAL comprehensive report.
Target IP: {ip}
Write in Arabic. Be thorough but only use evidence from the data below.

Required sections (use these exact headings):
## 1. ملخص تنفيذي
## 2. نوع الجهاز والخدمات (منافذ، بانر، stack)
## 3. الحسابات وكلمات المرور المؤكدة (مصدر كل cred)
## 4. الشبكة الداخلية — أجهزة LAN / DHCP / ARP (إن وُجدت)
## 5. Wi‑Fi و PPPoE / WAN
## 6. الثغرات والمخاطر (Nuclei, CVE, RouterSploit — مع تصنيف خطورة)
## 7. ما نُفّذ من أدوات (orchestrator log)
## 8. الفجوات — ما لم يُكتشف ولماذا (مثلاً guest بدون صلاحيات)
## 9. خطة العمل التالية (مرتبة بالأولوية)

Rules:
- NEVER invent usernames, passwords, LAN IPs, or CVEs not in the data
- If a section has no data, say "لا توجد بيانات في workspace" explicitly
- Distinguish confirmed vs attempted vs not tested

{body}
"""


def generate_ai_analysis(ip, target_dir):
    if not ai_configured():
        print("[*] AI analysis skipped (no API keys in .env).")
        return generate_offline_comprehensive_report(ip, target_dir)

    prompt = _build_prompt(ip, target_dir)
    print("[*] Running final AI analysis...")
    analysis, provider = call_ai_text(prompt)
    if analysis:
        output_path = os.path.join(target_dir, AI_REPORT_FILE)
        with open(output_path, "w", encoding="utf-8") as fh:
            fh.write(f"Provider: {provider}\n\n")
            fh.write(analysis)
        print(f"[+] AI analysis saved to: {output_path}")
        return analysis

    print("[!] All AI providers failed.")
    return generate_offline_comprehensive_report(ip, target_dir)


def generate_offline_comprehensive_report(ip: str, target_dir: str) -> str:
    """Template report from workspace_state when AI API unavailable."""
    from core.ai.workspace_state import build_workspace_state

    state = build_workspace_state(target_dir, ip)
    lines = [
        "=" * 60,
        f"تقرير شامل (بدون AI) — {ip}",
        f"تاريخ: {state.get('updated_at', '')}",
        "=" * 60,
        "",
        "## 1. ملخص تنفيذي",
        f"جهاز: {state.get('device', {})}",
        f"منافذ: {', '.join(str(p) for p in (state.get('open_ports') or []))}",
        "",
        "## 3. الحسابات",
    ]
    for c in state.get("credentials") or []:
        lines.append(f"  - {c}")
    if not state.get("credentials"):
        lines.append("  (لا creds مؤكدة)")
    lines.extend(["", "## 4. أجهزة LAN",])
    for c in state.get("lan_clients") or []:
        lines.append(f"  - {c}")
    if not state.get("lan_clients"):
        lines.append("  (لا أجهزة — جرّب admin أو Harvest)")
    lines.extend([
        "",
        "## 6. Nuclei",
        str(state.get("nuclei", {})),
        "",
        "لتقرير AI كامل: ضع OPENROUTER_API_KEY أو GEMINI_API_KEY في .env",
    ])
    text = "\n".join(lines)
    path = os.path.join(target_dir, AI_COMPREHENSIVE_FILE)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)
    also = os.path.join(target_dir, AI_REPORT_FILE)
    with open(also, "w", encoding="utf-8") as fh:
        fh.write(text)
    print(f"[+] Offline comprehensive report: {path}")
    return text


def generate_comprehensive_report(ip: str, target_dir: str) -> str | None:
    """Full Arabic report — used by AI Guided Scan finale."""
    if not ai_configured():
        return generate_offline_comprehensive_report(ip, target_dir)

    prompt = _build_comprehensive_prompt(ip, target_dir)
    print("[*] Generating AI comprehensive report…")
    analysis, provider = call_ai_text(
        prompt,
        system="You write accurate Arabic penetration test reports. Never hallucinate findings.",
    )
    if not analysis:
        return generate_offline_comprehensive_report(ip, target_dir)

    header = (
        f"Provider: {provider}\n"
        f"Target: {ip}\n"
        f"Generated: {__import__('datetime').datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        f"{'=' * 60}\n\n"
    )
    full = header + analysis
    for fname in (AI_COMPREHENSIVE_FILE, AI_REPORT_FILE):
        path = os.path.join(target_dir, fname)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(full)
    print(f"[+] Comprehensive report: {os.path.join(target_dir, AI_COMPREHENSIVE_FILE)}")
    return full
