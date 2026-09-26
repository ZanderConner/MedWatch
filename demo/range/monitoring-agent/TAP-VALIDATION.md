# Docker-native SPAN/tap equivalent for MedWatch validation

## Why this exists

A Docker bridge network is a learning switch, not a hub. Once its
forwarding table learns which port a container's MAC lives behind, unicast
frames between two OTHER containers are switched directly port-to-port and
are never flooded to every port — including the monitoring-agent's own
veth. Confirmed empirically: with monitoring-agent attached normally to
`orthanc_private_net` and capturing on `any`/promiscuous, it captured 0
events touching dicom-simulator, orthanc, hl7-simulator, or mirth over
several real DICOM/HL7 transmission cycles. It only ever saw its own
traffic, broadcast/multicast, and DNS to its own resolver.

This is the same problem a real switched hospital network has: you cannot
passively see other hosts' unicast traffic just by being plugged into the
same subnet. Production deployments need a SPAN/mirror port or an inline
network tap on the actual switch. This doc is the Docker-native equivalent
for range validation, not a production capture method.

## The fix: capture on the bridge's own network device

Every Docker bridge network has a `br-<network-id-prefix>` device in the
host's root network namespace. The bridge forwards ALL frames through that
device — capturing there with promiscuous mode on sees everything crossing
the bridge, matching what a real SPAN port would give you.

Steps:

1. Find the bridge device name for the target network:
   ```
   docker network inspect medsim-range_orthanc_private_net --format '{{.Id}}'
   # bridge name is br-<first 12 hex chars of that ID>
   ```

2. Put the bridge device into promiscuous mode on the host:
   ```
   sudo ip link set br-<id> promisc on
   ```

3. Run the sensor agent with `--network host` (so it can see the host's
   own network devices, including the bridge) and point `capture.interface`
   at the bridge device name instead of `any` or a container's own veth.
   See `demo/range/monitoring-agent/sensor-agent-tap-validation.toml` for
   a working example config.

## Validated result (this session)

With the tap config active: 675 of 682 captured events involved the real
OT-subnet hosts (dicom-simulator, orthanc, hl7-simulator, mirth), versus 0
with the normal bridge-attached container. Confirmed correct field-level
parsing on real traffic:
  - DICOM: `calling_ae_title: "DICOMSIM"`, `called_ae_title: "ORTHANC"`
    from a real A-ASSOCIATE-RQ on 10.20.50.21 -> 10.20.50.10:4242.
  - HL7: `message_type: "ORM^O01"` order and `"ACK"` reply, with correct
    sending/receiving application+facility fields, no PID/patient data
    touched.

## Not for the actual deployed range topology

This is a validation-only technique — it requires host root-namespace
access (`--network host`, `ip link set promisc`) that a real monitoring
sensor deployment shouldn't need or want. Use the normal
`agents/sensor-agent/Dockerfile` + bridge-attached `monitoring-agent`
service (dry-run, as currently checked in) for anything that isn't a
one-off manual validation pass like this one.
