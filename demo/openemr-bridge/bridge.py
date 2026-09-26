#!/usr/bin/env python3
"""Receives ORU^R01 hematology results over MLLP and files them directly
into the matching OpenEMR patient's chart (procedure_order /
procedure_report / procedure_result), instead of forwarding them to a
generic SIEM endpoint.

Patient matching is by HL7 PID-3 (the MRN, e.g. "MRN10048") against
OpenEMR's patient_data.pubpid, which is how the demo patient pool in
simulators/patients.csv is seeded into OpenEMR (see openemr/seed/).

This is the destination Mirth's "Hematology Results Ingest" channel talks
to. It does not touch any SIEM/security-monitoring concern — that is a
separate integration point left for the real SIEM/agent codebase.
"""
import argparse
import asyncio
from datetime import datetime, timezone

import hl7
import pymysql
from hl7.mllp import start_hl7_server


def log(msg):
    print(f"[{datetime.now(timezone.utc).isoformat(timespec='seconds')}] {msg}", flush=True)


def db_connect(args):
    return pymysql.connect(
        host=args.db_host,
        port=args.db_port,
        user=args.db_user,
        password=args.db_password,
        database=args.db_name,
        autocommit=True,
        cursorclass=pymysql.cursors.DictCursor,
    )


def hl7_dt_to_mysql(value: str):
    """Convert an HL7 TS value (YYYYMMDDHHMMSS[.SSS]) to a MySQL DATETIME."""
    digits = "".join(ch for ch in (value or "") if ch.isdigit())
    if len(digits) < 8:
        return None
    digits = (digits + "00000000")[:14]
    try:
        return datetime.strptime(digits, "%Y%m%d%H%M%S")
    except ValueError:
        return None


def find_patient(conn, mrn: str):
    with conn.cursor() as cur:
        cur.execute(
            "SELECT pid, providerID FROM patient_data WHERE pubpid = %s LIMIT 1",
            (mrn,),
        )
        return cur.fetchone()


def file_result(conn, message: hl7.Message) -> str:
    """Parse one ORU^R01 message and insert it into the patient's chart.

    Returns a short human-readable outcome string for logging.
    """
    pid_seg = message.segment("PID")
    obr_seg = message.segment("OBR")
    mrn = str(pid_seg[3]) if len(pid_seg) > 3 else ""
    patient_name = str(pid_seg[5]) if len(pid_seg) > 5 else "UNKNOWN"

    patient = find_patient(conn, mrn) if mrn else None
    if not patient:
        return f"no OpenEMR patient found for MRN={mrn!r} ({patient_name}) — skipped"

    patient_id = patient["pid"]
    provider_id = patient["providerID"] or 0

    placer_no = str(obr_seg[2]) if len(obr_seg) > 2 else ""
    filler_no = str(obr_seg[3]) if len(obr_seg) > 3 else ""
    universal_service = str(obr_seg[4]) if len(obr_seg) > 4 else "CBC^Complete Blood Count"
    service_code, _, service_name = universal_service.partition("^")
    date_collected = hl7_dt_to_mysql(str(obr_seg[7])) if len(obr_seg) > 7 else None
    date_report = hl7_dt_to_mysql(str(obr_seg[22])) if len(obr_seg) > 22 else date_collected

    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO procedure_order (
                provider_id, patient_id, encounter_id, date_collected, date_ordered,
                order_priority, order_status, activity, control_id, lab_id,
                specimen_type, specimen_location, specimen_volume, clinical_hx,
                procedure_order_type, order_intent, date_transmitted
            ) VALUES (
                %s, %s, 0, %s, %s,
                'routine', 'complete', 1, %s, 0,
                '', '', '', '',
                'laboratory_test', 'order', NOW()
            )
            """,
            (
                provider_id, patient_id, date_collected, date_collected or date_report,
                filler_no or placer_no,
            ),
        )
        procedure_order_id = cur.lastrowid

        cur.execute(
            """
            INSERT INTO procedure_order_code (
                procedure_order_id, procedure_order_seq, procedure_code,
                procedure_name, procedure_order_title, procedure_type
            ) VALUES (%s, 1, %s, %s, %s, 'laboratory_test')
            """,
            (procedure_order_id, service_code, service_name or service_code, service_name or service_code),
        )

        cur.execute(
            """
            INSERT INTO procedure_report (
                procedure_order_id, procedure_order_seq, date_collected, date_report,
                source, specimen_num, report_status, review_status
            ) VALUES (%s, 1, %s, %s, 0, %s, 'final', 'received')
            """,
            (procedure_order_id, date_collected, date_report, filler_no),
        )
        procedure_report_id = cur.lastrowid

        result_count = 0
        for obx in message.segments("OBX"):
            if len(obx) <= 5:
                continue
            result_code = str(obx[3]).split("^")[0] if len(obx) > 3 else ""
            result_name = str(obx[3]).split("^")[1] if len(obx) > 3 and "^" in str(obx[3]) else result_code
            value = str(obx[5]) if len(obx) > 5 else ""
            units = str(obx[6]) if len(obx) > 6 else ""
            ref_range = str(obx[7]) if len(obx) > 7 else ""
            abnormal = str(obx[8]) if len(obx) > 8 else "N"

            cur.execute(
                """
                INSERT INTO procedure_result (
                    procedure_report_id, result_data_type, result_code, result_text,
                    date, facility, units, result, `range`, abnormal, result_status
                ) VALUES (%s, 'N', %s, %s, %s, %s, %s, %s, %s, %s, 'final')
                """,
                (
                    procedure_report_id, result_code, result_name, date_report,
                    "MedSim Medical Center", units, value, ref_range, abnormal,
                ),
            )
            result_count += 1

    return (
        f"filed {result_count} results for {patient_name} (MRN={mrn}, patient_id={patient_id}) "
        f"order={filler_no} panel={service_code} provider_id={provider_id}"
    )


class Bridge:
    def __init__(self, args):
        self.args = args

    def log(self, msg):
        log(msg)

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
                    control_id = str(message.segment("MSH")[10])
                except Exception:
                    control_id = "0"

                ack_code = "AA"
                try:
                    conn = db_connect(self.args)
                    try:
                        outcome = file_result(conn, message)
                        self.log(outcome)
                    finally:
                        conn.close()
                except Exception as e:
                    ack_code = "AE"
                    self.log(f"failed to file result control_id={control_id}: {e}")

                now = datetime.now().strftime("%Y%m%d%H%M%S")
                ack_text = (
                    f"MSH|^~\\&|OPENEMR-BRIDGE|MEDSIM|MIRTH|MEDSIM|{now}||ACK|{control_id}-ack|P|2.5.1\r"
                    f"MSA|{ack_code}|{control_id}\r"
                )
                writer.writemessage(hl7.parse(ack_text))
                await writer.drain()
        finally:
            writer.close()
            self.log(f"connection closed {peer}")


async def main():
    parser = argparse.ArgumentParser(description="HL7-to-OpenEMR chart bridge")
    parser.add_argument("--listen-host", default="0.0.0.0")
    parser.add_argument("--listen-port", type=int, default=6661, help="port Mirth sends ORU results to")
    parser.add_argument("--db-host", default="openemr-db")
    parser.add_argument("--db-port", type=int, default=3306)
    parser.add_argument("--db-user", default="openemr")
    parser.add_argument("--db-password", default="openemr")
    parser.add_argument("--db-name", default="openemr")
    args = parser.parse_args()

    bridge = Bridge(args)
    server = await start_hl7_server(bridge.handle_connection, args.listen_host, args.listen_port)
    bridge.log(
        f"listening for ORU results on {args.listen_host}:{args.listen_port}, "
        f"filing into OpenEMR at {args.db_host}:{args.db_port}/{args.db_name}"
    )
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
