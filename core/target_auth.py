"""Parse credentials embedded in target URLs (http://user:pass@host/)."""

from __future__ import annotations

import os
from urllib.parse import unquote, urlparse


def parse_target_auth(raw: str) -> dict | None:
    """
    Return auth + connection info when raw is a URL with embedded credentials.
    """
    text = (raw or "").strip()
    if not text.startswith(("http://", "https://")):
        return None
    parsed = urlparse(text)
    if not parsed.username:
        return None
    host = parsed.hostname
    if not host:
        return None
    scheme = parsed.scheme or "http"
    port = parsed.port or (443 if scheme == "https" else 80)
    user = unquote(parsed.username)
    password = unquote(parsed.password or "")
    if port in (80, 443) and (
        (scheme == "http" and port == 80) or (scheme == "https" and port == 443)
    ):
        netloc = host
    else:
        netloc = f"{host}:{port}"
    path = parsed.path or "/"
    base_url = f"{scheme}://{netloc}{path if path != '/' else ''}"
    if base_url.endswith("/") and path == "/":
        base_url = f"{scheme}://{netloc}"
    return {
        "username": user,
        "password": password,
        "scheme": scheme,
        "host": host,
        "port": port,
        "path": path,
        "base_url": base_url.rstrip("/") or f"{scheme}://{netloc}",
        "authenticated_url": text.split("?", 1)[0],
    }


def auth_from_hints(hints: dict | None) -> tuple[str, str] | None:
    if not hints:
        return None
    user = hints.get("auth_username") or hints.get("username")
    if not user:
        return None
    return str(user), str(hints.get("auth_password") or hints.get("password") or "")


def creds_from_router_access(target_dir: str) -> tuple[str, str] | None:
    """Read user:pass from targets/<ip>/ROUTER_ACCESS.txt (first line)."""
    path = os.path.join(target_dir, "ROUTER_ACCESS.txt")
    if not os.path.isfile(path):
        return None
    try:
        with open(path, encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith(("url=", "method=", "gateway=")):
                    continue
                if ":" in line:
                    user, _, password = line.partition(":")
                    if user and password:
                        return user, password
    except OSError:
        return None
    return None


def save_router_access(
    target_dir: str,
    username: str,
    password: str,
    *,
    host: str,
    port: int = 80,
    scheme: str = "http",
    auth_method: str = "",
) -> str:
    """Persist router login for harvest / orchestrator (guest:guest from test_router, etc.)."""
    os.makedirs(target_dir, exist_ok=True)
    if port in (80, 443):
        netloc = host
    else:
        netloc = f"{host}:{port}"
    auth_url = f"{scheme}://{username}:{password}@{netloc}/"
    path = os.path.join(target_dir, "ROUTER_ACCESS.txt")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(
            f"{username}:{password}\n"
            f"url={auth_url}\n"
            f"method={auth_method}\n"
        )
    return path
