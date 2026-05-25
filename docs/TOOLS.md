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
| 1 | Full classic scan (`normal`) | `core/classic/full_scan.py` | Profile-driven tools below |
| 1d | **Deep full merge** (`deep`) | `full_scan.py` + `engines/deep_scan_extras.py` | Everything in #1 **plus** Phase 0 OSINT, full device engine, NetExec lateral |
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
| `routersploit/` | Router/IoT exploits (Python) |
| `rustsploit/` | Router/IoT scanner/exploits (Rust, optional build) |
| `ingram/` | IP camera scanner |
| `DefaultCreds-cheat-sheet/` | Default passwords reference |
| `dirsearch/` | Path enumeration |
| `sqlmap/` | SQL injection |
| `nuclei/` | Vulnerability scanner (optional local clone) |
| `scripts/new_pocs/` | Downloaded GitHub PoCs |
| `changeme/` | Default/backdoor credential scanner |
| `default-hunter/` | SySS modern changeme fork (extended YAML creds) |
| `jeanphorn-wordlist/` | IoT/router/camera/NAS default password wordlists |
| `iotbreaker/` | IoT CVE fingerprint + `--check` framework |
| `iotscan/` | AI-native IoT security assessment CLI |
| `router_analysis/` | Firmware/router analysis reference (manual) |

---

## IoT toolkit — full stack (every IP, normal + deep scan)

**Policy:** كل IP في الفحص الكلاسيكي (`selection=1`) يمر على **جميع** أدوات IoT ذات الأولوية العالية والمتوسطة — بدون استثناء deep-only.

| Priority | Tool | Phase | Module | Output |
|----------|------|-------|--------|--------|
| **High** | Nuclei template refresh | 1 | `iot_toolkit.run_nuclei_template_refresh` | `nuclei_template_update.txt` |
| **High** | UPnP/SSDP (built-in UDP) | 1 | `iot_toolkit.run_upnp_discovery` | `UPNP_DISCOVERY.json`, `upnp_device_descriptions.txt` |
| **High** | upnpfuzz | 1 | `iot_toolkit` (if pip) | `upnpfuzz_discover.txt` |
| **High** | changeme | 1 | `iot_toolkit.run_all_default_cred_scans` | `changeme_scan.txt`, `CHANGEME_HITS.json` |
| **High** | Default-Hunter | 1 | `iot_toolkit` | `default-hunter_scan.txt`, `IOT_DEFAULT_CREDS.json` |
| **High** | jeanphorn wordlists → Hydra | 1 + 4 | `build_iot_hydra_wordlists` | `hydra_iot_passwords.txt`, `hydra_iot_combos.txt` |
| **High** | Genzai | 2 | `run_genzai_scan` | `GENZAI_RESULTS.json`, `genzai_port_*.txt` |
| **High** | CamOver | 3 | `iot_exploit_extras` | `CAMOVER_HITS.json` |
| **High** | CamRaptor | 3 | `iot_exploit_extras` | `CAMRAPTOR_HITS.json` |
| **High** | IoTBreaker (fingerprint/vuln/scan + CVE `--check`) | 3 | `iot_exploit_extras` | `IOTBREAKER_*.txt`, `IOTBREAKER_CHECKS.json` |
| **Medium** | Rustsploit | 3 | `iot_exploit_extras` | `RUSTSPLOIT_SCAN.json` |
| **Medium** | IoTScan | 3 | `iot_exploit_extras` | `IOTSCAN_RESULTS.json` |
| **Medium** | Nuclei (router/IoT tags) | 2 | `core/web/nuclei.py` | `nuclei_*.json` (profile-driven) |
| **Medium** | CVE-2024-9643 (Four-Faith) | 3 | IoTBreaker + `data/latest_cves.json` | in `IOTBREAKER_CHECKS.json` |
| **Medium** | dom-one/router_analysis | — | manual / firmware | `tools/router_analysis/` |

**Merged creds:** `IOT_ALL_CREDS.json` (changeme + Default-Hunter + CamOver + CamRaptor)

### IoTBreaker CVE checks (safe `--check` only)

CVE-2021-36260, CVE-2023-1389, CVE-2017-17215, CVE-2014-8361, CVE-2016-6277, CVE-2022-30525, **CVE-2024-9643**, CVE-2020-25506, CVE-2019-7192

### Install (Kali)

```bash
cd ~/router
bash scripts/install_tools.sh    # clones all IoT repos + pip extras

# Optional Genzai (Go):
go install github.com/umair9747/genzai@latest
# Or: https://github.com/umair9747/genzai/releases

# Optional Rustsploit binary (if cargo installed, install_tools.sh builds release):
export PATH="$PWD/tools/rustsploit/target/release:$PATH"

pkill -f telegram_daemon.py && bash run.sh
```

### Pip packages (via `install_tools.sh`)

| Package | Purpose |
|---------|---------|
| `upnpfuzz` | Extra UPnP/SSDP discovery |
| `camover` (EntySec GitHub) | GoAhead/Netwave/CCTV default creds |
| `camraptor` (EntySec GitHub) | Novo/CeNova/QSee DVR creds |
| `default-hunter` (editable from `tools/default-hunter`) | Extended YAML default cred DB |
| `iotscan` (editable from `tools/iotscan`) | IoT modules: network, web, credentials, attack_paths |

### Phase wiring (`core/classic/full_scan.py`)

```
PHASE 1 → run_phase1_iot_recon()     # Nuclei refresh, UPnP, changeme, Default-Hunter, wordlists
PHASE 2 → run_genzai_scan()          # + existing Nuclei/Dirsearch/SQLMap
PHASE 3 → run_phase3_iot_extras()    # CamOver, CamRaptor, IoTBreaker, Rustsploit, IoTScan
PHASE 4 → build_iot_hydra_wordlists + Hydra (prefers hydra_iot_passwords.txt)
```

Telegram phase summaries: `core/telegram/phase_notify.py` reads all artifacts above.

---

## Parallel job engine (`core/phase_jobs.py`)

**Policy:** أدوات مستقلة تُشغَّل **بالتوازي** مع timeout لكل job — لا تعليق على Nuclei أو Hydra أو changeme.

| Module | Role |
|--------|------|
| `core/phase_jobs.py` | `PhaseRunner` — thread pool, per-job timeout, group timeout, `PHASE_N_JOBS.json` |
| `core/phase_log.py` | `logs/PHASE_N.log` per batch (+ optional terminal via `AUTOPWN_PHASE_WINDOWS=1`) |
| `core/classic/parallel_phases.py` | Phase 1 recon, Phase 2 web, Phase 3 RouterSploit+Ingram |

### Parallel batches

| Batch | Phase ID | Jobs (concurrent) |
|-------|----------|-------------------|
| IoT stack | `1-iot` | nuclei-templates, UPnP, changeme, Default-Hunter, jeanphorn |
| Recon tools | `1-recon` | whatweb×ports, nikto×ports, searchsploit×queries, nmap-vuln (deep) |
| Dirsearch | `2-dirsearch` | dirsearch×ports |
| Path discovery | `2-paths` | gau + ffuf×ports |
| Nuclei | `2-nuclei` | nuclei×URLs (3–4 workers) |
| Genzai | `2-genzai` | genzai×ports |
| Classic exploit | `3-classic` | RouterSploit + Ingram |
| IoT exploit | `3-iot` | CamOver, CamRaptor, IoTBreaker, Rustsploit, IoTScan |
| IoTBreaker CVEs | `3-iotbreaker` | fingerprint, vuln, scan + 9×CVE `--check` |

### Environment tuning (Kali)

```bash
export AUTOPWN_MAX_WORKERS=8          # concurrent jobs (default 6 normal / 8 deep)
export AUTOPWN_JOB_TIMEOUT=600        # per-tool max seconds
export AUTOPWN_PHASE_TIMEOUT=3600       # whole batch max seconds
export NUCLEI_CMD_TIMEOUT=300           # per Nuclei URL
export AUTOPWN_PHASE_WINDOWS=1          # open gnome-terminal per phase log
```

Logs: `logs/LIVE_SCAN.log` (global) + `logs/PHASE_2-nuclei.log` (per batch) + `targets/{ip}/PHASE_*_JOBS.json`

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
| `targets/{ip}/` | Scan workspace (UPnP, creds, IoT tools, Hydra, Nuclei, …) |
| `targets/{ip}/IOT_ALL_CREDS.json` | Merged IoT credentials |
| `targets/{ip}/hydra_iot_passwords.txt` | jeanphorn + IoT defaults for Hydra |
| `db/` | Pwned target history |
| `logs/pwn.log` | Global log |
| `data/latest_cves.json` | CVE database |
