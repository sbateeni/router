#!/usr/bin/env python3
"""CVE intelligence test — camera or router (authorized use only)."""

import argparse
import sys

try:
    import bootstrap  # noqa: F401
except ModuleNotFoundError:
    from tests import bootstrap  # noqa: F401
import requests

from engines.device_cve_checker import assess_device, print_cve_report, probe_hikvision_backdoor
from engines.fingerprinter import Fingerprinter

requests.packages.urllib3.disable_warnings()


def main() -> int:
    p = argparse.ArgumentParser(description="Device CVE checker test")
    p.add_argument("-H", "--host", required=True)
    p.add_argument("-p", "--port", type=int, default=80)
    p.add_argument("--user", default="")
    p.add_argument("--password", default="")
    args = p.parse_args()

    host = args.host.strip()
    url = f"http://{host}" if args.port == 80 else f"http://{host}:{args.port}"

    fp = Fingerprinter(url)
    info = fp.identify_details()
    device_type = info["device_type"]
    if device_type == "UNKNOWN" and probe_hikvision_backdoor(host, args.port):
        device_type = "HIKVISION"

    auth = None
    if args.user and args.password:
        auth = (args.user, args.password)

    print(f"\nFingerprint: {device_type} | {info.get('model', '')}\n")
    intel = assess_device(
        host, args.port, device_type, info.get("model", ""),
        info.get("server", ""), auth=auth,
    )
    print_cve_report(intel)
    return 0


if __name__ == "__main__":
    sys.exit(main())
