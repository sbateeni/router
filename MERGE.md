# MERGED — this repo replaces nuclei-dev-main on GitHub

Local copy kept at: `C:\Users\HP\Documents\GitHub\nuclei-dev-main` (experiments only)

## Merge checklist (all phases complete)

- [x] **Phase 1** — `engines/` copied from nuclei-dev (22 modules)
- [x] **Phase 2** — `engines/integration.py` wired into `core/classic/full_scan.py` Phase 3
- [x] **Phase 3** — `ENGINE_LOOT.json` + report tool check in `core/report/generate.py`
- [x] **Phase 4** — Unified `run.sh` / `run.bat` / `auto_pwn.py` / test scripts
- [x] **CVE intelligence** — `device_cve_checker.py` (cameras + routers)
- [x] **Credentials** — Netis form login, Hikvision Digest, Router Scan lists
- [x] **Tools** — RouterSploit, Ingram, Nuclei, Dirsearch, SQLMap (single `tools/`)

## Kali (official repo)

```bash
git clone https://github.com/sbateeni/router.git
cd router
chmod +x run.sh install_tools.sh
bash install_tools.sh && pip install -r requirements.txt
./run.sh
```
