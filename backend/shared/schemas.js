// Zod schemas mirroring the sensor agent's wire types exactly (source of
// truth: agents/sensor-agent/src/events.rs). Keep these in sync if that
// file ever changes shape.
const { z } = require('zod');

const TRANSPORT_PROTOCOLS = ['tcp', 'udp', 'icmp', 'other'];
const APPLICATION_PROTOCOLS = [
  'dicom',
  'hl7',
  'http',
  'https',
  'dns',
  'dhcp',
  'ssh',
  'rdp',
  'smb',
  'arp',
  'icmp',
  'ntp',
  'snmp',
  'mdns',
  'ldap',
  'syslog',
  'ftp',
  'telnet',
  'smtp',
  'unknown',
];
const OS_GUESSES = [
  'windows',
  'linux',
  'bsd',
  'network-appliance',
  'embedded-or-iot',
  'unknown',
];

const port = z.number().int().min(0).max(65535).nullable().optional();

const NetworkEventSchema = z.object({
  event_id: z.string().uuid(),
  sensor_id: z.string().min(1),
  '@timestamp': z.string().datetime({ offset: true }),
  src_ip: z.string().min(1),
  src_port: port,
  src_mac: z.string().nullable().optional(),
  dst_ip: z.string().min(1),
  dst_port: port,
  dst_mac: z.string().nullable().optional(),
  transport: z.enum(TRANSPORT_PROTOCOLS),
  application: z.enum(APPLICATION_PROTOCOLS),
  length_bytes: z.number().int().min(0),
  protocol_metadata: z.record(z.any()).nullable().optional(),
});

const AssetRecordSchema = z.object({
  asset_id: z.string().min(1),
  sensor_id: z.string().min(1),
  '@timestamp': z.string().datetime({ offset: true }), // last_seen on the wire
  first_seen: z.string().datetime({ offset: true }),
  mac_address: z.string().nullable().optional(),
  ip_addresses: z.array(z.string()),
  vendor_oui: z.string().nullable().optional(),
  os_guess: z.enum(OS_GUESSES),
  observed_ports: z.array(z.number().int().min(0).max(65535)),
  observed_protocols: z.array(z.string()),
  device_identity_hint: z.string().nullable().optional(),
});

module.exports = {
  TRANSPORT_PROTOCOLS,
  APPLICATION_PROTOCOLS,
  OS_GUESSES,
  NetworkEventSchema,
  AssetRecordSchema,
};
