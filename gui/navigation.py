"""Sidebar tree structure — page_id, label, category."""

from __future__ import annotations

NAV_ITEMS: list[tuple[str, str, str | None]] = [
    # (page_id, label, parent_id)
    ("dashboard", "Dashboard", None),
    ("comprehensive", "Comprehensive Scan", None),
    ("classic_nmap", "Nmap", "classic"),
    ("classic_nuclei", "Nuclei", "classic"),
    ("classic_dirsearch", "Dirsearch", "classic"),
    ("classic_sqlmap", "SQLMap", "classic"),
    ("classic_routersploit", "RouterSploit", "classic"),
    ("classic_ingram", "Ingram", "classic"),
    ("classic_hydra", "Hydra", "classic"),
    ("classic_ffuf", "FFUF", "classic"),
    ("classic_gau", "GAU", "classic"),
    ("ai_plan", "AI Scan Plan", "ai"),
    ("ai_hydra", "AI Hydra Plan", "ai"),
    ("ai_rsf", "AI RouterSploit", "ai"),
    ("ai_report", "AI Final Report", "ai"),
    ("recon_lan", "LAN Discovery", "recon"),
    ("recon_nikto", "Nikto", "recon"),
    ("recon_whatweb", "WhatWeb", "recon"),
    ("recon_nmap_vuln", "Nmap Vuln Scripts", "recon"),
    ("engine_autopwn", "AUTO-PWN Target", "engine"),
    ("engine_lan", "LAN Scan", "engine"),
    ("engine_history", "Target History", "engine"),
    ("engine_poc", "PoC Scraper", "engine"),
    ("engine_osint", "Social OSINT", "engine"),
    ("engine_decepticon", "Decepticon", "engine"),
    ("engine_update", "Framework Update", "engine"),
    ("util_direct_cam", "Direct Camera", "utilities"),
    ("util_update", "Update Tools", "utilities"),
    ("util_router_test", "Test Router", "utilities"),
    ("util_hik_test", "Test Hikvision", "utilities"),
    ("util_cve_test", "CVE Report", "utilities"),
    ("settings", "Settings", None),
]

CATEGORIES = {
    "classic": "Master PWN — Classic",
    "ai": "Master PWN — AI",
    "recon": "Master PWN — Recon",
    "engine": "Device Engine",
    "utilities": "Utilities",
}

PAGE_SPECS: dict[str, dict] = {
    "classic_nmap": {"selection": 2, "title": "Nmap", "desc": "Port and service scan only."},
    "classic_nuclei": {"selection": 3, "title": "Nuclei", "desc": "Template-based vulnerability scan."},
    "classic_dirsearch": {"selection": 4, "title": "Dirsearch", "desc": "Web path enumeration."},
    "classic_sqlmap": {"selection": 5, "title": "SQLMap", "desc": "SQL injection testing."},
    "classic_routersploit": {"selection": 6, "title": "RouterSploit", "desc": "Router/IoT exploit modules."},
    "classic_ingram": {"selection": 7, "title": "Ingram", "desc": "IP camera scanner."},
    "classic_hydra": {"selection": 8, "title": "Hydra", "desc": "Brute-force (uses IoT wordlists from workspace if present)."},
    "classic_ffuf": {"selection": 9, "title": "FFUF", "desc": "Web fuzzing."},
    "classic_gau": {"selection": 10, "title": "GAU", "desc": "URL discovery from archives."},
    "ai_plan": {"selection": 11, "title": "AI Scan Plan", "desc": "AI-driven Nmap + tool selection."},
    "ai_hydra": {"selection": 12, "title": "AI Hydra Plan", "desc": "AI-generated Hydra commands."},
    "ai_rsf": {"selection": 13, "title": "AI RouterSploit", "desc": "AI RouterSploit + follow-up modules."},
    "ai_report": {"selection": 14, "title": "AI Final Report", "desc": "Generate report from existing workspace artifacts."},
    "recon_lan": {"selection": 16, "title": "LAN Discovery", "desc": "Find live hosts on subnet (uses Subnet field)."},
    "recon_nikto": {"selection": 17, "title": "Nikto", "desc": "Web vulnerability scan (runs Nmap first if needed)."},
    "recon_whatweb": {"selection": 18, "title": "WhatWeb", "desc": "Web technology fingerprint."},
    "recon_nmap_vuln": {"selection": 19, "title": "Nmap Vuln Scripts", "desc": "Nmap --script vuln."},
    "engine_autopwn": {"kind": "engine", "title": "Device AUTO-PWN", "desc": "Full device engine (cameras, routers, PoCs)."},
}
