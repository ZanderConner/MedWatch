# Docker-native SPAN/tap equivalent for MedWatch

## Why this exists

A Docker bridge network is a learning switch, not a hub. Once its
forwarding table learns which port a container's MAC lives behind, unicast
frames between two OTHER containers are switched directly port-to-port and
are never flooded to every port — including a monitoring-agent's own
veth. Confirmed empirically: with a sensor attached normally to a bridge
network and capturing on `any`/promiscuous, it captured 0 events touching
the OT-subnet containers over several real DICOM/HL7 transmission cycles.
It only ever saw its own traffic, broadcast/multicast, and DNS to its own
resolver.

This is the same problem a real switched hospital network has: you cannot
passively see other hosts' unicast traffic just by being plugged into the
same subnet. Production deployments need a SPAN/mirror port or an inline
network tap on the actual switch. This doc is the Docker-native equivalent.

## Distributed deployment: two subnets, two sensors

The range now models two independent clinical/OT subnets, each watched by
its own dedicated sensor — a distributed-agent deployment, not one sensor
trying to see the whole range from a single vantage point:

- **imaging_net** (10.20.70.0/24): `ct-simulator` and `mri-simulator` (two
  independent DICOM modalities) sending studies to `orthanc` (PACS).
  Watched by `monitoring-agent-imaging` (`sensor-agent-imaging.toml`,
  sensor id `sensor-imaging`).
- **lab_net** (10.20.80.0/24): `hl7-simulator` (the hematology analyzer)
  exchanging HL7v2/MLLP orders and results with `mirth`. Watched by
  `monitoring-agent-lab` (`sensor-agent-lab.toml`, sensor id `sensor-lab`).

## The fix: capture on each bridge's own network device

Every Docker bridge network has a `br-<network-id-prefix>` device in the
host's root network namespace. The bridge forwards ALL frames through that
device — capturing there with promiscuous mode on sees everything crossing
the bridge, matching what a real SPAN port would give you.

The original single-subnet version of this range required a human to look
up the bridge ID by hand (`docker network inspect ... --format '{{.Id}}'`)
and hardcode `br-<id>` into the sensor's config file. That doesn't scale to
multiple subnets — each compose project run gets fresh, unpredictable
bridge IDs — so this is now automated: each `monitoring-agent-*`
container's entrypoint (`agents/sensor-agent/resolve-bridge-and-run.sh`)

1. Reads `TARGET_NETWORK` (e.g. `medsim-range_imaging_net` — compose
   prefixes network names with the project name) from its environment.
2. Queries the Docker API over the mounted `/var/run/docker.sock` for that
   network's ID.
3. Derives the host bridge device name: `br-<first 12 hex chars of the
   network ID>` (Docker's own convention).
4. Puts that bridge device into promiscuous mode
   (`ip link set <bridge> promisc on`) — this does NOT persist across a
   host reboot; the wrapper re-applies it every container start, so a
   fresh `docker compose up` after a reboot self-heals without a manual
   step.
5. execs the real `medwatch-sensor` binary with `--interface <bridge>`
   appended — the TOML config's own `interface` value is just a
   documented placeholder.

Requires: `network_mode: host`, `cap_add: [NET_ADMIN, NET_RAW]`, and
`/var/run/docker.sock` mounted read-only — all set on both
`monitoring-agent-imaging` and `monitoring-agent-lab` in
`demo/docker-compose.yml`.

## Validated result

With the tap technique active on the original single-subnet layout: 675 of
682 captured events involved the real OT-subnet hosts (dicom-simulator,
orthanc, hl7-simulator, mirth), versus 0 with a normal bridge-attached
container. Confirmed correct field-level parsing on real traffic:
  - DICOM: `calling_ae_title: "DICOMSIM"`, `called_ae_title: "ORTHANC"`
    from a real A-ASSOCIATE-RQ.
  - HL7: `message_type: "ORM^O01"` order and `"ACK"` reply, with correct
    sending/receiving application+facility fields, no PID/patient data
    touched.

## Verifying it's actually working

```
docker compose logs monitoring-agent-imaging | head -5
docker compose logs monitoring-agent-lab | head -5
curl -s http://localhost:9000/api/v1/analytics/protocol-distribution
```

Expect `resolve-bridge-and-run: TARGET_NETWORK=... -> bridge=br-...` in
each sensor's logs, and non-zero `dicom` and `hl7` counts (not just
`unknown`/`dns`) in the protocol-distribution response once the simulators
have sent a few messages.

## Not for a real production topology

This Docker-bridge-specific technique only exists because Docker doesn't
expose a native port-mirroring feature. A real production OT-subnet
deployment should use an actual SPAN/mirror port or inline network tap on
the physical switch instead.
