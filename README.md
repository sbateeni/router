# AUTO-PWN UNIFIED

Merged project: **router** orchestration + **nuclei-dev** device exploit engine.

One repo for Kali — full scan, camera pwn, router creds, CVE intelligence.

## Quick start (Kali)

```bash
git clone https://github.com/YOUR_USER/router.git
cd router
chmod +x run.sh scripts/install_tools.sh
bash scripts/install_tools.sh    # creates .venv + clones tools
source .venv/bin/activate
./run.sh
```

## Main entry points

| Command | Purpose |
|---------|---------|
| `./run.sh` | Unified menu (options 1–9) |
| `python3 bin/master_pwn.py -t IP --auto` | Full 4-phase scan (Nmap → Web → **Engine** → Hydra) |
| `python3 bin/auto_pwn.py` | Device engine only (cameras + routers) |
| `python3 tests/test_router_target.py -H IP` | Netis/router credential test |
| `python3 tests/test_hikvision_target.py -H IP` | Hikvision backdoor + Digest test |
| `python3 tests/test_device_cve.py -H IP` | CVE intelligence report |

## Project layout

```
router/
├── run.sh / run.bat       ← launch menu (stay at root)
├── bin/                   ← Python entry points
│   ├── master_pwn.py      ← main orchestrator
│   ├── auto_pwn.py        ← device engine menu
│   ├── lan_pwn.py
│   └── telegram_pwn.py
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

Copy `.env.example` to `.env` for Telegram / AI / Shodan keys.

See **[docs/TOOLS.md](docs/TOOLS.md)** for the full tools catalog.

## Legacy repos

`nuclei-dev-main` is merged into `engines/`. You only need this repo on Kali.
