#!/usr/bin/env python3
"""Red-team box: deliberately non-conformant DICOM/HL7 traffic generator.

Lives on the imaging_net as a rogue "radiology workstation" that never
should have been provisioned. Everything it sends is designed to trip
MedWatch's correlation rules (see backend/correlation/rules.js):

  - unrecognized_dicom_initiator: issues A-ASSOCIATE-RQ under an AE title
    that isn't in KNOWN_GOOD_DICOM_AE_TITLES (e.g. "ROGUEWS").
  - unrecognized_hl7_sender: sends HL7 MSH segments under a sending
    application that isn't in KNOWN_GOOD_HL7_SENDING_APPS.
  - embedded_device_exposing_remote_admin: N/A here, but the box also
    exposes SSH so an operator can shell in and re-run scripts live
    during a demo.

This is intentionally simplistic (hackathon scope) — it does NOT
implement a real DICOM/HL7 stack, just enough of the wire format to be
classified by the sensor's parsers and to look wrong to the correlation
rules. See ~/.hermes/skills/cyber-range-device-simulation: this box is
kept as its own separate container/codebase specifically so it never
gets bundled into the target simulators' own packages.
"""
import argparse
import random
import socket
import struct
import time


def build_associate_rq(called_ae: str, calling_ae: str) -> bytes:
    """Minimal, mostly-empty A-ASSOCIATE-RQ PDU (PS3.8 9.3.2) — enough
    for the sensor's fixed-header parser to read the AE titles; no
    variable items (app context / presentation context / user info)
    are included since MedWatch's passive parser never reads them."""
    called = called_ae.ljust(16)[:16].encode("ascii")
    calling = calling_ae.ljust(16)[:16].encode("ascii")
    body = struct.pack(">HH", 1, 0) + called + calling + b"\x00" * 32
    pdu_type = 0x01  # A-ASSOCIATE-RQ
    header = struct.pack(">BBI", pdu_type, 0, len(body))
    return header + body


def send_rogue_dicom_associate(host, port, ae_title):
    try:
        with socket.create_connection((host, port), timeout=5) as sock:
            sock.sendall(build_associate_rq("ORTHANC", ae_title))
            sock.settimeout(3)
            try:
                sock.recv(256)
            except socket.timeout:
                pass
        print(f"[dicom] sent rogue A-ASSOCIATE-RQ to {host}:{port} as AE '{ae_title}'", flush=True)
    except OSError as exc:
        print(f"[dicom] connect/send failed: {exc}", flush=True)


def build_hl7_msh(sending_app: str) -> bytes:
    """Minimal MSH-only HL7v2 message wrapped in MLLP framing — enough
    for MedWatch's MSH-only HL7 parser (see agent's HL7 parser: never
    touches PHI segments) to classify it and extract the sending app."""
    ts = time.strftime("%Y%m%d%H%M%S")
    msh = (
        f"MSH|^~\\&|{sending_app}|UNKNOWN_FACILITY|MIRTH|MEDSIM|{ts}||"
        f"ORU^R01|{random.randint(100000,999999)}|P|2.3\r"
    )
    return b"\x0b" + msh.encode("ascii") + b"\x1c\x0d"


def send_rogue_hl7(host, port, sending_app):
    try:
        with socket.create_connection((host, port), timeout=5) as sock:
            sock.sendall(build_hl7_msh(sending_app))
            sock.settimeout(3)
            try:
                sock.recv(256)
            except socket.timeout:
                pass
        print(f"[hl7] sent rogue MSH to {host}:{port} as sending-app '{sending_app}'", flush=True)
    except OSError as exc:
        print(f"[hl7] connect/send failed: {exc}", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dicom-host", default="10.20.70.10")  # orthanc, imaging_net
    parser.add_argument("--dicom-port", type=int, default=4242)
    parser.add_argument("--dicom-ae", default="ROGUEWS")
    parser.add_argument("--hl7-host", default="10.20.80.12")  # mirth, lab_net-side
    parser.add_argument("--hl7-port", type=int, default=6661)
    parser.add_argument("--hl7-sending-app", default="UNKNOWNLIS")
    parser.add_argument("--min-interval", type=float, default=20)
    parser.add_argument("--max-interval", type=float, default=60)
    parser.add_argument("--once", action="store_true", help="fire one round of each and exit (for manual/on-demand runs)")
    args = parser.parse_args()

    def fire_round():
        send_rogue_dicom_associate(args.dicom_host, args.dicom_port, args.dicom_ae)
        send_rogue_hl7(args.hl7_host, args.hl7_port, args.hl7_sending_app)

    if args.once:
        fire_round()
        return

    print("red-team box: rogue DICOM/HL7 generator starting", flush=True)
    while True:
        fire_round()
        time.sleep(random.uniform(args.min_interval, args.max_interval))


if __name__ == "__main__":
    main()
