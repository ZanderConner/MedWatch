#!/usr/bin/env bash
set -euo pipefail

sysctl -w net.ipv4.ip_forward=1 >/dev/null

for setting in /proc/sys/net/ipv4/conf/*/rp_filter; do
  echo 0 > "$setting"
done

iptables -F FORWARD
iptables -P FORWARD DROP

iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

for source in 10.20.10.0/24 10.20.20.0/24 10.20.30.0/24 10.20.40.0/24; do
  for destination in 10.20.10.0/24 10.20.20.0/24 10.20.30.0/24 10.20.40.0/24; do
    if [[ "$source" != "$destination" ]]; then
      iptables -A FORWARD -s "$source" -d "$destination" -j ACCEPT
    fi
  done
done

iptables -A FORWARD -m limit --limit 6/min -j LOG --log-prefix "medsim-drop " --log-level 4

echo "medsim router ready"
ip -brief address
ip route

trap 'exit 0' TERM INT
while true; do
  sleep 3600 &
  wait $!
done
