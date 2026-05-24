# Tools Catalog — AUTO-PWN UNIFIED

Complete reference of every tool, module, and external dependency used in this project.

---

## Entry points (how you launch)

| Script | Path | Purpose |
|--------|------|---------|
| Unified menu | `run.sh` / `run.bat` | Main launcher |
| Full orchestrator | `bin/master_pwn.py` | 4-phase scan + Telegram + AI |
| Device engine | `bin/auto_pwn.py` | Cameras, routers, OSINT, PoCs |
| Telegram only | `bin/telegram_pwn.py` | Bot control |
| LAN picker | `bin/lan_pwn.py` | Scan LAN → AUTO-PWN |
| Direct camera | `bin/direct_camera.py` | VLC snapshot mode |
| RouterSploit CLI | `bin/run_rsf_direct.py` | Expert RSF scanner |
| VLC multi-cam | `bin/open_vlc_cameras.py` | Open RTSP in VLC |
| Install tools | `scripts/install_tools.sh` / `.bat` | Clone external repos |
| Update all | `scripts/update_tools.py` | Git pull project + tools |

---

## Telegram bot commands

| Command | Action |
|---------|--------|
| `IP` / `URL` / `domain/path` | Network target → pick scan mode |
| `/engine` or `/autopwn` | Device Engine AUTO-PWN |
| `/osint email` / `phone` / `user` / `full` | Social OSINT |
| Plain email or phone | Auto OSINT |
| `/lan` | LAN device discovery |
| `/lan attack N` | AUTO-PWN on LAN device #N |
| `/history` | Previous pwned targets (`db/`) |
| `/poc` | GitHub Zero-Day PoC scraper |
| `/update` | Framework + tools git pull |
| `/decepticon` | Autonomous kill-chain |
| `/status` / `/queue` / `/clearqueue` / `/cancel` | Queue control |

---

## Core orchestrator (`core/`) — master_pwn scan tools

| # | Tool | Module | External binary |
|---|------|--------|-----------------|
| 1 | Full classic scan | `core/classic/full_scan.py` | All below |
| 2 | Nmap | `core/scanner.py` | `nmap` |
| 3 | Nuclei | `core/web/nuclei.py` | `nuclei` / `nuclei.exe` |
| 4 | Dirsearch | `core/web/dirsearch.py` | Python in `tools/dirsearch/` |
| 5 | SQLMap | `core/web/sqlmap.py` | Python in `tools/sqlmap/` |
| 6 | RouterSploit | `core/exploitation.py` | Python in `tools/routersploit/` |
| 7 | Ingram | `core/exploitation.py` | Python in `tools/ingram/` |
| 8 | Hydra | `core/bruteforce.py` | `hydra` |
| 9 | FFUF | `core/classic/helpers.py` | `ffuf` |
| 10 | GAU | `core/classic/helpers.py` | `gau` |
| 11 | AI scan plan | `core/ai/individual.py` | Gemini / OpenRouter API |
| 12 | AI Hydra plan | `core/ai/individual.py` | AI API |
| 13 | AI RouterSploit | `core/ai/routersploit.py` | AI + RouterSploit |
| 14 | AI final report | `core/ai/analyst.py` | AI API |
| 16 | LAN discovery | `core/network_discovery.py` | `nmap` ping sweep |
| 17 | Nikto | `core/recon_tools.py` | `nikto` |
| 18 | WhatWeb | `core/recon_tools.py` | `whatweb` |
| 19 | Nmap vuln scripts | `core/recon_tools.py` | `nmap --script vuln` |
| 21 | Device Engine | `engines/auto_pwn_main.py` | See engines section |

---

## Device engine (`engines/`)

### Main menu options

| Option | Feature | Module |
|--------|---------|--------|
| [1] | Manual target AUTO-PWN | `auto_pwn_main.py` |
| [2] | LAN scan | `lan_scanner.py` |
| [3] | Target history | `utils.py` → `db/` |
| [4] | GitHub PoC scraper | `zero_day_scraper.py` |
| [5] | Social OSINT | `social_osint.py` |
| [6] | Decepticon kill-chain | `decepticon_core.py` |
| [7] | Framework update | `updater.py` |

### Intelligence

| Tool | Module |
|------|--------|
| Shodan OSINT | `osint_engine.py` |
| Social OSINT (email/phone/user) | `social_osint.py` |
| Fingerprinter | `fingerprinter.py` |
| CVE intelligence | `device_cve_checker.py` |

### Exploitation

| Tool | Module |
|------|--------|
| Hikvision exploit | `hikvision_module.py` |
| Hikvision decrypt/snapshots | `hikvision_decryptor.py`, `hikvision_snapshots.py` |
| Router cred hunt | `credential_hunter.py` |
| ZTE / Laravel / OpenWrt | `zte_module.py`, `laravel_module.py`, `browser_automation.py` |
| RouterSploit / Ingram | `external_tools.py` |
| GitHub PoC runner | `poc_runner.py` |
| Nuclei (engine) | `scanner.py` |
| SSH + persistence | `ssh_engine.py`, `persistence.py` |
| Hash extract/crack | `hash_extractor.py`, `hash_cracker.py` |
| Reverse shell | `reverse_shell_prompt.py` |
| Pivot attack | `pivot_scanner.py` |
| llama.cpp RCE | `llama_cpp_module.py` |

### Decepticon agents

| Stage | Module |
|-------|--------|
| Recon | `recon_agent.py` |
| Scan | `scan_agent.py` |
| Exploit | `exploit_agent.py` |
| Lateral | `lateral_agent.py` |
| Orchestrator | `decepticon_core.py` |

---

## External tools (`tools/`)

| Directory | Purpose |
|-----------|---------|
| `routersploit/` | Router/IoT exploits |
| `ingram/` | IP camera scanner |
| `DefaultCreds-cheat-sheet/` | Default passwords |
| `dirsearch/` | Path enumeration |
| `sqlmap/` | SQL injection |
| `nuclei/` | Vulnerability scanner (optional) |
| `scripts/new_pocs/` | Downloaded GitHub PoCs |

---

## System binaries

| Binary | Kali | Windows | Termux |
|--------|------|---------|--------|
| python3 | yes | yes | yes |
| nmap | yes | install | pkg |
| nuclei | yes | .exe | ARM bin |
| hydra | yes | no | pkg |
| john | yes | no | pkg |
| ffuf / gau | yes | manual | manual |
| nikto / whatweb | yes | no | no |
| msfconsole | yes | no | no |
| vlc | yes | yes | app only |

---

## Environment keys (`.env`)

| Key | Purpose |
|-----|---------|
| `TELEGRAM_BOT_TOKEN` / `TELEGRAM_CHAT_ID` | Bot |
| `GEMINI_API_KEY` | AI tools |
| `SHODAN_API_KEY` | Shodan OSINT |
| `NUMLOOKUP_API_KEY` | Phone OSINT (optional) |

---

## Output paths

| Path | Contents |
|------|----------|
| `targets/{ip}/` | Scan workspace |
| `db/` | Pwned target history |
| `logs/pwn.log` | Global log |
| `data/latest_cves.json` | CVE database |
