#!/usr/bin/env python3
"""Radiology-workstation traffic generator.

Simulates a clinical staff workstation doing ordinary, unremarkable
browsing/API activity against the demo range's real clinical systems —
Orthanc (PACS web UI + REST API), Mirth (admin console), and OpenEMR
(patient portal). This exists purely to give the sensors and analytics
pages baseline HTTP/HTTPS traffic beyond the DICOM/HL7 device-to-device
flows, so a demo audience sees a realistic mix rather than only
machine-to-machine clinical protocol traffic.

Intentionally NOT an attack tool: every request here is a normal,
authenticated (where required) read/browse operation a real radiology
technologist or PACS admin would perform. See the red-team-box container
for the deliberately malicious traffic that's a SEPARATE, clearly-labeled
concern.
"""
import argparse
import random
import time

import requests

requests.packages.urllib3.disable_warnings()  # self-signed certs in this range


def hit_orthanc(base):
    """Browse Orthanc's REST API the way the PACS web viewer would."""
    auth = ("orthanc", "orthanc")
    try:
        requests.get(f"{base}/system", auth=auth, timeout=5)
        studies = requests.get(f"{base}/studies", auth=auth, timeout=5).json()
        if studies:
            study_id = random.choice(studies)
            requests.get(f"{base}/studies/{study_id}", auth=auth, timeout=5)
            requests.get(f"{base}/studies/{study_id}/series", auth=auth, timeout=5)
        requests.get(f"{base}/statistics", auth=auth, timeout=5)
    except requests.RequestException as exc:
        print(f"[orthanc] request failed: {exc}", flush=True)


def hit_mirth(base):
    """Poll Mirth's admin/status HTTP endpoint like an ops dashboard."""
    try:
        requests.get(f"{base}/api/server/status", verify=False, timeout=5)
    except requests.RequestException as exc:
        print(f"[mirth] request failed: {exc}", flush=True)


def hit_openemr(base):
    """Load the OpenEMR login/landing page like a clinician's browser."""
    try:
        requests.get(f"{base}/interface/login/login.php", verify=False, timeout=5)
        requests.get(f"{base}/", verify=False, timeout=5)
    except requests.RequestException as exc:
        print(f"[openemr] request failed: {exc}", flush=True)


TARGETS = {
    "orthanc": hit_orthanc,
    "mirth": hit_mirth,
    "openemr": hit_openemr,
}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--orthanc-url", default="http://10.20.70.10:8042")
    parser.add_argument("--mirth-url", default="https://10.20.20.10:8443")
    parser.add_argument("--openemr-url", default="https://10.20.10.10")
    parser.add_argument("--min-interval", type=float, default=15)
    parser.add_argument("--max-interval", type=float, default=45)
    args = parser.parse_args()

    urls = {
        "orthanc": args.orthanc_url,
        "mirth": args.mirth_url,
        "openemr": args.openemr_url,
    }

    print("radiology-workstation traffic generator starting", flush=True)
    while True:
        name = random.choice(list(TARGETS))
        print(f"[gen] hitting {name} ({urls[name]})", flush=True)
        TARGETS[name](urls[name])
        time.sleep(random.uniform(args.min_interval, args.max_interval))


if __name__ == "__main__":
    main()
