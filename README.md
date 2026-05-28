# AUTO-PWN UNIFIED

Merged project: **router** orchestration + **nuclei-dev** device exploit engine.

One repo for Kali — full scan, camera pwn, router creds, CVE intelligence.

## Quick start (Kali)

```bash
git clone https://github.com/YOUR_USER/router.git
cd router
python3 -m venv .venv
source .venv/bin/activate
pip install -U pip setuptools wheel
pip install -r requirements.txt
chmod +x run.sh scripts/install_tools.sh scripts/fix_venv_kali.sh
bash scripts/install_tools.sh    # clones tools/ + merges tool-specific pins
./run.sh
# If permission denied: bash run.sh
```

## Main entry points

| Command | Purpose |
|---------|---------|
| `./run.sh` | GUI-only launcher |
| `python3 bin/gui_app.py` | Primary entrypoint — PyQt6 desktop GUI (see [`docs/GUI.md`](docs/GUI.md)) |
| `python3 tests/test_router_target.py -H IP` | Netis/router credential test |
| `python3 tests/test_hikvision_target.py -H IP` | Hikvision backdoor + Digest test |
| `python3 tests/test_device_cve.py -H IP` | CVE intelligence report |

## Project layout

```
router/
├── run.sh / run.bat       ← launch menu (stay at root)
├── bin/                   ← Python entry points
│   ├── gui_app.py         ← PyQt6 desktop GUI
│   ├── telegram_daemon.py ← Telegram background listener
│   └── _bootstrap.py
├── scripts/               ← install & maintenance
│   ├── install_tools.sh
│   └── update_tools.py
├── tests/                 ← target tests & unit tests
├── docs/                  ← guides & notes
├── config/                ← editor / deploy config (e.g. sftp.json)
├── logs/                  ← pwn.log (runtime)
├── core/                  ← scan phases, reports, AI, Telegram
├── engines/               ← Hikvision, Netis, CVE, OSINT, loot
├── tools/                 ← RouterSploit, Ingram, Nuclei (gitignored)
└── targets/               ← per-target workspaces (gitignored)
```

## What the merge adds

- **Cameras:** CVE-2017-7921, Digest auth, config decrypt, snapshots
- **Routers:** Netis form login, HTTP Basic, Router Scan wordlists
- **CVE map:** firmware build → skip/try CVE + targeted Nuclei
- **Plus router:** Nmap, Hydra, Dirsearch, SQLMap, AI analyst, Telegram

## Phase 3 flow (--auto)

1. `engines/integration.py` — fingerprint, CVE report, cred hunt, Hikvision/Netis
2. RouterSploit (if profile says router)
3. Ingram (if profile says camera)
4. Hydra (Phase 4)

## Environment

Copy `.env.example` to `.env` for Telegram / AI keys.

See **[docs/TOOLS.md](docs/TOOLS.md)** for the full tools catalog.

## GUI-first policy

- Day-to-day operation should run from `python3 bin/gui_app.py`.
- Launcher scripts (`run.sh`, `run.bat`) run GUI only.
- Attack logic remains intact in `core/` and `engines/`; removed files were CLI wrappers only.

### Kali `.venv` (correct package versions)

Pins match official tool repos ([theHarvester](https://github.com/laramies/theHarvester/blob/master/pyproject.toml), [dirsearch](https://github.com/maurosoria/dirsearch/blob/master/requirements.txt), [RouterSploit](https://github.com/threat9/routersploit/blob/master/requirements.txt)):

| Package | Version | Why |
|---------|---------|-----|
| `paramiko` | **2.12.0** | RouterSploit (`DSSKey`) |
| `beautifulsoup4` | **4.14.3** | theHarvester |
| `dnspython` | **2.8.0** | theHarvester |
| `lxml` | **6.1.1** | theHarvester (avoid SpiderFoot `lxml<5` build) |
| `requests` | **2.32.2** | RouterSploit |

**NetExec (`nxc`)**: never in `.venv` — Kali package: `sudo apt install netexec` ([kali.org/tools/netexec](https://www.kali.org/tools/netexec/))

**SpiderFoot**: never `pip install -r tools/spiderfoot/requirements.txt` — use `requirements.txt` or `sudo apt install spiderfoot`

Repair a broken venv:

```bash
# If git pull fails on install_tools.sh:
git checkout -- scripts/install_tools.sh
git pull

bash scripts/fix_venv_kali.sh
```

If `fix_venv_kali.sh` is missing after pull, run manually:

```bash
source .venv/bin/activate
pip uninstall -y netexec certipy-ad
pip install -r requirements.txt
pip install -c constraints-kali.txt paramiko beautifulsoup4 dnspython lxml requests
sudo apt install -y netexec
```

Clean reinstall:

```bash
rm -rf .venv && python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
bash scripts/install_tools.sh
```

## Legacy repos

`nuclei-dev-main` is merged into `engines/`. You only need this repo on Kali.
