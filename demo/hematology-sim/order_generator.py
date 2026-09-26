#!/usr/bin/env python3
"""Continuously generates synthetic CBC lab orders (HL7 ORM^O01) and sends
them into Mirth's order-intake channel, so the hematology pipeline produces
traffic on its own instead of waiting for a human to fire test messages.

Draws patients from the same CSV pool used by the DICOM modality simulator,
so patient identities correlate across the imaging and lab-order streams —
useful for asset/data-flow correlation demos.
"""
import argparse
import asyncio
import csv
import random
from datetime import datetime

import hl7
from hl7.mllp import open_hl7_connection

ORDER_CODES = [
    ("CBC", "Complete Blood Count"),
    ("CBCD", "Complete Blood Count with Differential"),
]


def load_patients(csv_path):
    patients = []
    with open(csv_path, newline="") as f:
        for row in csv.DictReader(f):
            patients.append(row)
    if not patients:
        raise SystemExit(f"no patients loaded from {csv_path}")
    return patients


def hl7_ts(dt=None):
    return (dt or datetime.now()).strftime("%Y%m%d%H%M%S")


def build_orm(control_id, placer_no, filler_no, patient, universal_service,
              sending_app, sending_facility, receiving_app, receiving_facility):
    now = hl7_ts()
    code, name = universal_service
    segments = [
        f"MSH|^~\\&|{sending_app}|{sending_facility}|{receiving_app}|{receiving_facility}|{now}||ORM^O01|{control_id}|P|2.5.1",
        f"PID|1||{patient['patient_id']}||{patient['patient_name']}||{patient['birth_date']}|{patient['sex']}",
        f"ORC|NW|{placer_no}|||||||{now}|||{patient['referring_physician']}",
        f"OBR|1|{placer_no}|{filler_no}|{code}^{name}|||{now}",
    ]
    return "\r".join(segments) + "\r"


def log(msg):
    print(f"[{datetime.now().isoformat(timespec='seconds')}] {msg}", flush=True)


async def send_one_order(host, port, control_id, placer_no, filler_no, patient,
                          sending_app, sending_facility, receiving_app, receiving_facility):
    universal_service = random.choice(ORDER_CODES)
    orm_text = build_orm(
        control_id, placer_no, filler_no, patient, universal_service,
        sending_app, sending_facility, receiving_app, receiving_facility,
    )
    reader, writer = await asyncio.wait_for(open_hl7_connection(host, port), timeout=15)
    writer.writemessage(hl7.parse(orm_text))
    await writer.drain()
    ack = await asyncio.wait_for(reader.readmessage(), timeout=25)
    ack_code = ack.segment("MSA")[1] if ack else "??"
    writer.close()
    log(f"order sent: acc={filler_no} patient={patient['patient_name']} ack={ack_code}")


async def main():
    parser = argparse.ArgumentParser(description="Synthetic HL7 lab order generator")
    parser.add_argument("--target-host", default="mirth", help="host that receives ORM orders")
    parser.add_argument("--target-port", type=int, default=6662, help="port that receives ORM orders")
    parser.add_argument("--patients-csv", default="/app/patients.csv")
    parser.add_argument("--min-interval", type=float, default=30.0, help="min seconds between orders")
    parser.add_argument("--max-interval", type=float, default=90.0, help="max seconds between orders")
    parser.add_argument("--sending-app", default="OE-CPOE", help="MSH-3, mimics an EHR order-entry system")
    parser.add_argument("--sending-facility", default="MEDSIM")
    parser.add_argument("--receiving-app", default="LIS")
    parser.add_argument("--receiving-facility", default="HEMATOLOGY")
    args = parser.parse_args()

    patients = load_patients(args.patients_csv)
    log(f"loaded {len(patients)} patients from {args.patients_csv}")
    log(f"sending orders to {args.target_host}:{args.target_port} every "
        f"{args.min_interval:.0f}-{args.max_interval:.0f}s")

    accession_seq = random.randint(1000, 8999)
    while True:
        await asyncio.sleep(random.uniform(args.min_interval, args.max_interval))
        accession_seq += 1
        control_id = f"ORD{accession_seq:05d}"
        placer_no = f"PLC{accession_seq:05d}"
        filler_no = f"FIL{accession_seq:05d}"
        patient = random.choice(patients)
        try:
            await send_one_order(
                args.target_host, args.target_port, control_id, placer_no, filler_no, patient,
                args.sending_app, args.sending_facility, args.receiving_app, args.receiving_facility,
            )
        except Exception as e:
            log(f"failed to send order {control_id}: {e}")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
