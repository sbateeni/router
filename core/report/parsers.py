import glob
import json
import os
import re


def read_file(path, max_chars=12000):
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            return fh.read(max_chars)
    except OSError:
        return ""


def strip_ansi(text):
    return re.sub(r"\x1b\[[0-9;]*m", "", text or "")


def find_files(target_dir, pattern):
    return sorted(glob.glob(os.path.join(target_dir, pattern)))


def significant_nuclei_findings(findings):
    significant = {"critical", "high", "medium"}
    return [item for item in findings if str(item.get("severity", "unknown")).lower() in significant]


def count_nuclei_findings(target_dir):
    findings = []
    for path in find_files(target_dir, "nuclei_port_*.jsonl"):
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                line = line.strip()
                if not line.startswith("{"):
                    continue
                try:
                    item = json.loads(line)
                    info = item.get("info", {})
                    findings.append({
                        "template": item.get("template-id", "unknown"),
                        "severity": info.get("severity", "unknown"),
                        "matched_at": item.get("matched-at", ""),
                        "file": os.path.basename(path),
                    })
                except json.JSONDecodeError:
                    continue
    return findings
