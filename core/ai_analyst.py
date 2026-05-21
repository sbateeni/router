import json
import os
import re
import requests

from core.notify import load_dotenv

AI_REPORT_FILE = "AI_ANALYSIS.txt"
MAX_INPUT_CHARS = 12000


def ai_configured():
    return bool(
        os.environ.get("OPENROUTER_API_KEY")
        or os.environ.get("GEMINI_API_KEY")
        or os.environ.get("NVIDIA_API_KEY")
    )


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


def _build_prompt(ip, target_dir):
    report = _read_optional(os.path.join(target_dir, "RESULTS_SUMMARY.txt"))
    recon = _read_optional(os.path.join(target_dir, "recon_summary.json"), 4000)
    context = _read_optional(os.path.join(target_dir, "scan_context.json"), 4000)
    scan_plan = _read_optional(os.path.join(target_dir, "AI_SCAN_PLAN.json"), 2000)
    hydra_plan = _read_optional(os.path.join(target_dir, "AI_HYDRA_PLAN.json"), 2000)
    rsf_plan = _read_optional(os.path.join(target_dir, "AI_ROUTERSPLOIT_PLAN.txt"), 2000)
    nuclei = _read_optional(os.path.join(target_dir, "nuclei_port_443_notags.jsonl"), 3000)
    if not nuclei:
        nuclei = _read_optional(os.path.join(target_dir, "nuclei_port_80_notags.jsonl"), 3000)

    return f"""You are a senior penetration testing analyst.
Analyze the following scan data for target IP {ip}.
Write the answer in Arabic.
Be concise, practical, and structured with these sections:
1) ملخص الجهاز
2) ما الذي يعمل بشكل صحيح
3) المشاكل أو الأخطاء في الأدوات
4) أخطر النتائج الأمنية
5) الخطوات التالية المقترحة

Do not invent findings that are not present in the data.

=== RESULTS SUMMARY ===
{report}

=== RECON JSON ===
{recon}

=== SCAN CONTEXT JSON ===
{context}

=== AI SCAN PLAN ===
{scan_plan}

=== AI HYDRA PLAN ===
{hydra_plan}

=== AI ROUTERSPLOIT PLAN ===
{rsf_plan}

=== NUCLEI SAMPLE ===
{nuclei}
"""


def generate_ai_analysis(ip, target_dir):
    if not ai_configured():
        print("[*] AI analysis skipped (no API keys in .env).")
        return None

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
    return None
