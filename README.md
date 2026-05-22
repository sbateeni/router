# AUTO-PWN UNIFIED

Merged project: **router** orchestration + **nuclei-dev** device exploit engine.

One repo for Kali — full scan, camera pwn, router creds, CVE intelligence.

## Quick start (Kali)

```bash
git clone https://github.com/YOUR_USER/router.git
cd router
chmod +x run.sh install_tools.sh
bash install_tools.sh
pip install -r requirements.txt
./run.sh
```

## Main entry points

| Command | Purpose |
|---------|---------|
| `./run.sh` | Unified menu |
| `python3 master_pwn.py -t IP --auto` | Full 4-phase scan (Nmap → Web → **Engine** → Hydra) |
| `python3 engines/auto_pwn_main.py` | Device engine only (cameras + routers) |
| `python3 test_router_target.py -H IP` | Netis/router credential test |
| `python3 test_hikvision_target.py -H IP` | Hikvision backdoor + Digest test |
| `python3 test_device_cve.py -H IP` | CVE intelligence report |

## Architecture

```
router/                    ← push THIS folder to GitHub
├── master_pwn.py          ← main orchestrator (Nmap, Hydra, Telegram, AI)
├── core/                  ← scan phases, reports, profile routing
├── engines/               ← from nuclei-dev (Hikvision, Netis, CVE, loot)
│   ├── integration.py     ← called from Phase 3 of full scan
│   ├── credential_hunter.py
│   ├── device_cve_checker.py
│   └── auto_pwn_main.py
├── tools/                 ← RouterSploit, Ingram, Nuclei, Dirsearch...
├── targets/               ← per-target scan workspaces
└── run.sh
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

## Legacy repos

`nuclei-dev-main` is merged into `engines/`. You only need this repo on Kali.
