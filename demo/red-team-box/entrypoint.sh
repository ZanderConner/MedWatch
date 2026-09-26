#!/bin/bash
# Starts sshd (so an operator can `docker exec`/ssh in during a live demo
# and fire rogue_traffic.py --once on demand) and, in parallel, runs the
# periodic background generator so the box also produces violations
# passively without anyone needing to be at the keyboard.
set -e

mkdir -p /run/sshd
/usr/sbin/sshd

echo "red-team-box: sshd started, launching periodic rogue traffic generator" 
exec python3 -u /app/rogue_traffic.py "$@"
