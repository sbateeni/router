"""AI provider selection, fallbacks, and session-level disable on hard failures."""

from __future__ import annotations

import os
from typing import Any, Callable

import requests

PLACEHOLDER_MARKERS = ("your_", "_here", "changeme", "placeholder", "example")

# provider name -> reason disabled for this process
_DISABLED: dict[str, str] = {}
# log each provider failure once
_LOGGED: set[str] = set()


def reset_provider_cache() -> None:
    _DISABLED.clear()
    _LOGGED.clear()


def looks_like_placeholder(value: str | None) -> bool:
    if not value or not str(value).strip():
        return True
    lowered = str(value).strip().lower()
    return any(marker in lowered for marker in PLACEHOLDER_MARKERS)


def valid_api_key(env_name: str) -> bool:
    value = os.environ.get(env_name, "")
    return bool(value) and not looks_like_placeholder(value)


def _short_error(exc: BaseException) -> str:
    if isinstance(exc, requests.HTTPError) and exc.response is not None:
        code = exc.response.status_code
        if code == 402:
            return "402 Payment Required (no credits)"
        if code == 401:
            return "401 Unauthorized (invalid key)"
        if code == 503:
            return "503 Service Unavailable"
        return f"HTTP {code}"
    return str(exc)[:120]


def mark_provider_failed(name: str, exc: BaseException) -> None:
    if isinstance(exc, requests.HTTPError) and exc.response is not None:
        if exc.response.status_code == 429:
            if name not in _LOGGED:
                print(f"[!] {name} rate limited (429) — using next provider this call")
                _LOGGED.add(name)
            return
    reason = _short_error(exc)
    _DISABLED[name] = reason
    if name not in _LOGGED:
        print(f"[!] {name} AI disabled for this session: {reason}")
        _LOGGED.add(name)
    if name == "OpenRouter" and "402" in reason:
        model = os.environ.get("OPENROUTER_MODEL", "")
        if ":free" not in model.lower():
            os.environ["AI_SKIP_OPENROUTER"] = "1"
            if name not in _LOGGED:
                print(
                    "[*] Tip: use a free OpenRouter model, e.g. "
                    "OPENROUTER_MODEL=deepseek/deepseek-v4-flash:free"
                )


def provider_order() -> list[str]:
    raw = os.environ.get("AI_PROVIDER_ORDER", "").strip()
    if raw:
        return [p.strip().lower() for p in raw.split(",") if p.strip()]
    if os.environ.get("AI_SKIP_OPENROUTER", "").strip() in ("1", "true", "yes"):
        return ["gemini", "openrouter", "nvidia"]
    or_model = os.environ.get("OPENROUTER_MODEL", "deepseek/deepseek-v4-flash:free")
    or_free = ":free" in or_model.lower()
    if valid_api_key("OPENROUTER_API_KEY") and or_free:
        return ["openrouter", "gemini", "nvidia"]
    if valid_api_key("GEMINI_API_KEY"):
        return ["gemini", "openrouter", "nvidia"]
    return ["openrouter", "gemini", "nvidia"]


def iter_providers(
    *,
    openrouter: Callable[..., Any],
    gemini: Callable[..., Any],
    nvidia: Callable[..., Any],
) -> list[tuple[str, Callable[..., Any]]]:
    registry = {
        "openrouter": ("OpenRouter", openrouter, "OPENROUTER_API_KEY"),
        "gemini": ("Gemini", gemini, "GEMINI_API_KEY"),
        "nvidia": ("NVIDIA", nvidia, "NVIDIA_API_KEY"),
    }
    out: list[tuple[str, Callable[..., Any]]] = []
    for key in provider_order():
        entry = registry.get(key)
        if not entry:
            continue
        label, fn, env_key = entry
        if label in _DISABLED:
            continue
        if not valid_api_key(env_key):
            continue
        out.append((label, fn))
    return out


def any_key_configured() -> bool:
    return any(valid_api_key(k) for k in ("OPENROUTER_API_KEY", "GEMINI_API_KEY", "NVIDIA_API_KEY"))


def llm_available(
    *,
    openrouter: Callable[..., Any],
    gemini: Callable[..., Any],
    nvidia: Callable[..., Any],
) -> bool:
    return bool(iter_providers(openrouter=openrouter, gemini=gemini, nvidia=nvidia))


def provider_summary(
    *,
    openrouter: Callable[..., Any],
    gemini: Callable[..., Any],
    nvidia: Callable[..., Any],
) -> str:
    active = [n for n, _ in iter_providers(openrouter=openrouter, gemini=gemini, nvidia=nvidia)]
    if active:
        return " → ".join(active)
    if not any_key_configured():
        return "none (no API keys)"
    disabled = ", ".join(f"{k}: {v}" for k, v in _DISABLED.items()) if _DISABLED else "all providers failed"
    return f"none ({disabled})"
