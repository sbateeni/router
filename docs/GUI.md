# PyQt6 Desktop GUI

English LTR desktop interface for AUTO-PWN UNIFIED. Mirrors the CLI tool catalog in [`TOOLS.md`](TOOLS.md).

## Install

```bash
pip install -r requirements-gui.txt
```

On Kali, use the project venv:

```bash
source .venv/bin/activate
pip install -r requirements-gui.txt
```

## Launch

```bash
python bin/gui_app.py
```

Or from the unified launcher:

- **Windows:** `run.bat` → `[G]`
- **Linux/Kali:** `run.sh` → `G`

## Layout

| Area | Purpose |
|------|---------|
| **Target bar** | IP/URL, subnet (LAN discovery), profile (`normal` / `deep`), **Keep artifacts** |
| **Sidebar** | Dashboard, Comprehensive Scan, per-tool pages, Device Engine, Utilities, Settings |
| **Live log** | Tails `logs/LIVE_SCAN.log` (or per-job log) |
| **Artifacts** | Files in `targets/<workspace>/` — shared between tools |

## Comprehensive Scan

- **Run Full Scan** — `selection=1`, profile from target bar (usually `normal`)
- **Run Deep Scan** — same pipeline with `deep` profile (IoT merge + extended timeouts)
- **Run 4-Phase Auto** — full orchestrator equivalent to `bin/master_pwn.py -t TARGET --auto`

## Chaining tools

1. Enter target → **Apply target**
2. Leave **Keep artifacts** checked to reuse Nmap/Nuclei/Hydra outputs
3. Run individual tools (e.g. Nmap, then Hydra) — Hydra prefers `hydra_iot_passwords.txt` from the workspace
4. Use **New workspace** to clear artifacts for a fresh run

## Environment

The GUI sets:

- `AUTOPWN_SCAN_SOURCE=gui`
- `AUTOPWN_LIVE_WINDOW=0` (no extra terminal tail on Windows)
- `AUTOPWN_GUI=1` during scans (non-blocking `input()` defaults)
- `ENGINE_WORKSPACE=<target_dir>` for the device engine

## External binaries

Many tools need binaries on `PATH` (`nmap`, `hydra`, `nuclei`, …). Check **Settings** in the GUI or use Kali with `scripts/install_tools.sh`.

## Cancel

Use **Cancel** on any running tool page; this calls `core.scan_cancel.cancel_job`.
