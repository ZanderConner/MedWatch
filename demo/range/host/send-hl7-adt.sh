#!/usr/bin/env bash
set -euo pipefail

host="${1:-10.20.20.10}"
port="${2:-6661}"

message=$'MSH|^~\\&|MEDSIM|CYBERRANGE|MIRTH|HL7|20260925120000||ADT^A01|MSG00001|P|2.5\rEVN|A01|20260925120000\rPID|1||MRN123456^^^MEDSIM^MR||RANGE^PATIENT||19800101|O|||1 CLINIC WAY^^BALTIMORE^MD^21201||555-0100\rPV1|1|I|ER^01^01||||12345^HOUSE^GREGORY\r'

printf '\x0b%s\x1c\x0d' "$message" | nc -w 3 "$host" "$port"
