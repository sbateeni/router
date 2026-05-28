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
        "nuclei_cmd_timeout": 480,
        "nuclei_http_timeout": 10,
        "nuclei_rate_limit": 150,
        "sqlmap_level": 2,
        "sqlmap_risk": 2,
        "sqlmap_timeout": 30,
        "sqlmap_delay": 1,
        "sqlmap_url_limit": 8,
        "phase_delay_seconds": 5,
        "hydra_threads": 4,
        "hydra_users": 3,
        "hydra_forms": 4,
        "parallel_workers": 6,
        "parallel_nuclei_workers": 3,
        "job_timeout_default": 600,
        "phase_group_timeout": 3600,
        "phase1_iot_timeout": 900,
        "phase1_group_timeout": 1200,
        "phase2_dirsearch_timeout": 900,
        "phase2_nuclei_timeout": 1800,
        "phase3_iot_timeout": 1500,
        "phase3_classic_timeout": 1200,
        "phase_heartbeat_interval": 15,
        "telegram_heartbeat_interval": 90,
        "preflight_enabled": True,
        "masscan_enabled": False,
        "phase0_main_timeout": 900,
        "phase1_main_timeout": 2400,
        "phase2_main_timeout": 3600,
        "phase3_main_timeout": 3600,
        "phase4_main_timeout": 1800,
    },
    "deep": {
        "label": "Deep / Full Tool Merge",
        "nmap_quick_args": ["-sS", "-sV", "-T4", "--open", "-F"],
        "nmap_deep_enabled": True,
        "dirsearch_threads": 80,
        "ffuf_threads": 80,
        "ffuf_wordlist": "medium",
        "nuclei_all_templates": True,
        "nuclei_url_limit": 100,
        "nuclei_cmd_timeout": 900,
        "nuclei_http_timeout": 12,
        "nuclei_rate_limit": 120,
        "sqlmap_level": 3,
        "sqlmap_risk": 3,
        "sqlmap_timeout": 45,
        "sqlmap_delay": 2,
        "sqlmap_url_limit": 12,
        "phase_delay_seconds": 8,
        "hydra_threads": 8,
        "hydra_users": 5,
        "hydra_forms": 6,
        "parallel_workers": 8,
        "parallel_nuclei_workers": 4,
        "job_timeout_default": 900,
        "phase_group_timeout": 7200,
        "phase1_iot_timeout": 1200,
        "phase1_group_timeout": 1800,
        "phase2_dirsearch_timeout": 1200,
        "phase2_nuclei_timeout": 3600,
        "phase3_iot_timeout": 2400,
        "phase3_classic_timeout": 1800,
        "phase_heartbeat_interval": 15,
        "telegram_heartbeat_interval": 90,
        "preflight_enabled": True,
        "masscan_enabled": True,
        "masscan_ports": "1-1000",
        "masscan_rate": 800,
        "masscan_timeout": 180,
        "masscan_try_sudo": True,
        "masscan_interface": None,
        "local_net_snapshot": True,
        "phase0_main_timeout": 1200,
        "phase1_main_timeout": 3600,
        "phase2_main_timeout": 7200,
        "phase3_main_timeout": 7200,
        "phase4_main_timeout": 3600,
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
