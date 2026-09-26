#!/usr/bin/env python3
import argparse
import asyncio
import random
from datetime import datetime

import hl7
from hl7.mllp import open_hl7_connection, start_hl7_server

# ---------------------------------------------------------------------------
# CBC reference ranges: code, display name, unit, low, high, decimal places
# ---------------------------------------------------------------------------
CBC_TESTS = [
    ("WBC",  "White Blood Cell Count",                      "10*3/uL", 4.0, 11.0, 1),
    ("RBC",  "Red Blood Cell Count",                         "10*6/uL", 4.2, 5.9, 2),
    ("HGB",  "Hemoglobin",                                   "g/dL",    13.5, 17.5, 1),
    ("HCT",  "Hematocrit",                                   "%",       38.8, 50.0, 1),
    ("MCV",  "Mean Corpuscular Volume",                      "fL",      80.0, 100.0, 1),
    ("MCH",  "Mean Corpuscular Hemoglobin",                  "pg",      27.0, 33.0, 1),
    ("MCHC", "Mean Corpuscular Hemoglobin Concentration",    "g/dL",    32.0, 36.0, 1),
    ("PLT",  "Platelet Count",                                "10*3/uL", 150.0, 400.0, 0),
    ("RDW",  "Red Cell Distribution Width",                  "%",       11.5, 14.5, 1),
]

DIFF_TESTS = [
    ("NEUTP", "Neutrophils",  40.0, 70.0),
    ("LYMPP", "Lymphocytes",  20.0, 40.0),
    ("MONOP", "Monocytes",     2.0,  8.0),
    ("EOSP",  "Eosinophils",   1.0,  4.0),
    ("BASOP", "Basophils",     0.0,  1.0),
]

ABNORMAL_CHANCE = 0.12  # per-analyte odds of flagging out of range


def gen_value(low, high, decimals):
    span = high - low
    if random.random() < ABNORMAL_CHANCE:
        if random.random() < 0.5:
            val, flag = low - random.uniform(0.1, 0.6) * span, "L"
        else:
            val, flag = high + random.uniform(0.1, 0.6) * span, "H"
    else:
        val, flag = random.uniform(low, high), "N"
    return round(max(val, 0), decimals), flag


def gen_diff():
    raw = {code: random.uniform(lo, hi) for code, _, lo, hi in DIFF_TESTS}
    total = sum(raw.values())
    return {code: round(v / total * 100, 1) for code, v in raw.items()}


def hl7_ts(dt=None):
    return (dt or datetime.now()).strftime("%Y%m%d%H%M%S")


def build_oru(control_id, patient_id, patient_name, dob, sex, placer_no, filler_no, universal_service,
              sending_app, sending_facility, receiving_app, receiving_facility):
    """Build a pipe-delimited ORU^R01 carrying a CBC + diff panel."""
    now = hl7_ts()
    segments = [
        f"MSH|^~\\&|{sending_app}|{sending_facility}|{receiving_app}|{receiving_facility}|{now}||ORU^R01|{control_id}|P|2.5.1",
        f"PID|1||{patient_id}||{patient_name}||{dob}|{sex}",
        f"OBR|1|{placer_no}|{filler_no}|{universal_service}|||{now}||||||||||||||||{now}||||F",
    ]

    seq = 1
    for code, name, unit, low, high, decimals in CBC_TESTS:
        val, flag = gen_value(low, high, decimals)
        ref = f"{low}-{high}"
        segments.append(
            f"OBX|{seq}|NM|{code}^{name}||{val}|{unit}|{ref}|{flag}|||F"
        )
        seq += 1

    diff = gen_diff()
    for code, name, lo, hi in DIFF_TESTS:
        val = diff[code]
        flag = "H" if val > hi else "L" if val < lo else "N"
        segments.append(
            f"OBX|{seq}|NM|{code}^{name}||{val}|%|{lo}-{hi}|{flag}|||F"
        )
        seq += 1

    return "\r".join(segments) + "\r"


def extract_order_fields(message: hl7.Message):
    """Pull the bits we need to echo back into the result message."""
    control_id = str(message.segment("MSH")[10])
    pid = message.segment("PID")
    patient_id = str(pid[3]) if len(pid) > 3 else "UNKNOWN"
    patient_name = str(pid[5]) if len(pid) > 5 else "UNKNOWN^UNKNOWN"
    dob = str(pid[7]) if len(pid) > 7 else ""
    sex = str(pid[8]) if len(pid) > 8 else ""

    try:
        obr = message.segment("OBR")
        placer_no = str(obr[2]) if len(obr) > 2 else "0"
        filler_no = str(obr[3]) if len(obr) > 3 else "0"
        universal_service = str(obr[4]) if len(obr) > 4 else "CBC^Complete Blood Count"
    except KeyError:
        placer_no, filler_no, universal_service = "0", "0", "CBC^Complete Blood Count"

    return control_id, patient_id, patient_name, dob, sex, placer_no, filler_no, universal_service


def build_ack(control_id, ack_code, sending_app, sending_facility, receiving_app, receiving_facility, ack_control_id):
    now = hl7_ts()
    return (
        f"MSH|^~\\&|{sending_app}|{sending_facility}|{receiving_app}|{receiving_facility}|{now}||ACK|{ack_control_id}|P|2.5.1\r"
        f"MSA|{ack_code}|{control_id}\r"
    )


class Analyzer:
    def __init__(self, send_host, send_port, min_delay, max_delay,
                 sending_app, sending_facility, receiving_app, receiving_facility):
        self.send_host = send_host
        self.send_port = send_port
        self.min_delay = min_delay
        self.max_delay = max_delay
        self.sending_app = sending_app
        self.sending_facility = sending_facility
        self.receiving_app = receiving_app
        self.receiving_facility = receiving_facility
        self.busy_lock = asyncio.Lock()  # instrument only runs one sample at a time
        # instrument-style sequential message control numbers, starting at a
        # plausible mid-sequence offset rather than 1
        self.msg_counter = random.randint(40000, 89999)

    def next_control_id(self):
        self.msg_counter += 1
        return str(self.msg_counter)

    def log(self, msg):
        print(f"[{datetime.now().isoformat(timespec='seconds')}] {msg}")

    async def handle_connection(self, reader, writer):
        peer = writer.get_extra_info("peername")
        self.log(f"connection from {peer}")
        try:
            while True:
                try:
                    message = await reader.readmessage()
                except asyncio.IncompleteReadError:
                    break
                if message is None:
                    break

                try:
                    fields = extract_order_fields(message)
                    control_id = fields[0]
                    self.log(f"order received, control_id={control_id}, patient={fields[2]}")
                    ack_text = build_ack(
                        control_id, "AA", self.sending_app, self.sending_facility,
                        self.receiving_app, self.receiving_facility, self.next_control_id(),
                    )
                    writer.writemessage(hl7.parse(ack_text))
                    await writer.drain()
                    asyncio.create_task(self.process_order(fields))
                except Exception as e:
                    self.log(f"failed to parse inbound message: {e}")
                    try:
                        ack_text = build_ack(
                            "0", "AE", self.sending_app, self.sending_facility,
                            self.receiving_app, self.receiving_facility, self.next_control_id(),
                        )
                        writer.writemessage(hl7.parse(ack_text))
                        await writer.drain()
                    except Exception:
                        pass
        finally:
            writer.close()
            self.log(f"connection closed {peer}")

    async def process_order(self, fields):
        control_id, patient_id, patient_name, dob, sex, placer_no, filler_no, universal_service = fields
        delay = random.uniform(self.min_delay, self.max_delay)

        async with self.busy_lock:
            self.log(f"analyzing specimen for {patient_name} (acc {filler_no}) — {delay:.0f}s")
            await asyncio.sleep(delay)

            result_control_id = self.next_control_id()
            oru_text = build_oru(
                result_control_id, patient_id, patient_name, dob, sex,
                placer_no, filler_no, universal_service,
                self.sending_app, self.sending_facility, self.receiving_app, self.receiving_facility,
            )

            try:
                reader, writer = await asyncio.wait_for(
                    open_hl7_connection(self.send_host, self.send_port), timeout=15
                )
                writer.writemessage(hl7.parse(oru_text))
                await writer.drain()
                ack = await asyncio.wait_for(reader.readmessage(), timeout=25)
                self.log(f"results sent for acc {filler_no}, ack={ack.segment('MSA')[1] if ack else '??'}")
                writer.close()
            except Exception as e:
                self.log(f"failed to send results for acc {filler_no}: {e}")


async def main():
    parser = argparse.ArgumentParser(description="Fake HL7 hematology analyzer")
    parser.add_argument("--listen-host", default="0.0.0.0")
    parser.add_argument("--listen-port", type=int, default=6660, help="port Mirth sends orders to")
    parser.add_argument("--send-host", default="localhost", help="Mirth host that receives results")
    parser.add_argument("--send-port", type=int, default=6661, help="Mirth port that receives results")
    parser.add_argument("--min-delay", type=float, default=45.0, help="min analysis time (s)")
    parser.add_argument("--max-delay", type=float, default=120.0, help="max analysis time (s)")
    parser.add_argument("--sending-app", default="HEMA-3000", help="MSH-3 value the instrument identifies as")
    parser.add_argument("--sending-facility", default="HEMATOLOGY", help="MSH-4 value")
    parser.add_argument("--receiving-app", default="LIS", help="MSH-5 value (your Mirth channel/LIS)")
    parser.add_argument("--receiving-facility", default="LAB", help="MSH-6 value")
    args = parser.parse_args()

    analyzer = Analyzer(
        args.send_host, args.send_port, args.min_delay, args.max_delay,
        args.sending_app, args.sending_facility, args.receiving_app, args.receiving_facility,
    )

    server = await start_hl7_server(
        analyzer.handle_connection, args.listen_host, args.listen_port
    )
    analyzer.log(
        f"listening for orders on {args.listen_host}:{args.listen_port}, "
        f"results will be sent to {args.send_host}:{args.send_port}"
    )
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
