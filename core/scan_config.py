"""Scan intensity profiles shared by all tools."""

PROFILES = {
    "normal": {
        "label": "Normal",
        "nmap_quick_args": ["-sV", "-T4", "--open"],
        "nmap_deep_enabled": False,
        "dirsearch_threads": 50,
        "ffuf_threads": 50,
        "ffuf_wordlist": "common",
        "nuclei_all_templates": False,
        "nuclei_url_limit": 20,
        "sqlmap_level": 2,
        "sqlmap_risk": 2,
        "sqlmap_timeout": 30,
        "sqlmap_delay": 1,
        "sqlmap_url_limit": 8,
        "phase_delay_seconds": 5,
        "hydra_threads": 4,
        "hydra_users": 3,
        "hydra_forms": 4,
    },
    "deep": {
        "label": "Deep / Full Power",
        "nmap_quick_args": ["-sS", "-sV", "-T4", "--open", "-F"],
        "nmap_deep_enabled": True,
        "dirsearch_threads": 80,
        "ffuf_threads": 80,
        "ffuf_wordlist": "medium",
        "nuclei_all_templates": True,
        "nuclei_url_limit": 100,
        "sqlmap_level": 3,
        "sqlmap_risk": 3,
        "sqlmap_timeout": 45,
        "sqlmap_delay": 2,
        "sqlmap_url_limit": 12,
        "phase_delay_seconds": 8,
        "hydra_threads": 8,
        "hydra_users": 5,
        "hydra_forms": 6,
    },
}

_active_profile = "normal"


def set_scan_profile(name):
    global _active_profile
    if name not in PROFILES:
        raise ValueError(f"Unknown scan profile: {name}")
    _active_profile = name


def get_scan_profile():
    return PROFILES[_active_profile]


def get_profile_name():
    return _active_profile
