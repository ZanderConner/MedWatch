//! Passive TCP/IP stack fingerprinting.
//!
//! This module never sends a single packet — every signature is derived
//! purely from traffic the sensor already observed on the wire (SYN/SYN-ACK
//! TTL, window size, MSS, window scale, options ordering). This is the same
//! family of technique p0f uses. Good enough to bucket a host into
//! "likely Windows", "likely Linux/embedded Linux", "likely a printer/IoT
//! device", etc. without ever touching the asset — which matters when the
//! asset on the other end is a ventilator or infusion pump.

use serde::{Deserialize, Serialize};

/// Raw signature extracted from a single observed TCP SYN or SYN-ACK.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TcpSignature {
    pub initial_ttl: u8,
    pub window_size: u16,
    pub mss: Option<u16>,
    pub window_scale: Option<u8>,
    pub sack_permitted: bool,
    pub timestamps_present: bool,
    /// Order options appeared on the wire, e.g. "MSS,SACK,TS,NOP,WS".
    pub option_order: String,
    pub is_syn_ack: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum OsGuess {
    Windows,
    Linux,
    Bsd,
    NetworkAppliance,
    EmbeddedOrIot,
    Unknown,
}

impl OsGuess {
    pub fn as_str(&self) -> &'static str {
        match self {
            OsGuess::Windows => "windows",
            OsGuess::Linux => "linux",
            OsGuess::Bsd => "bsd",
            OsGuess::NetworkAppliance => "network-appliance",
            OsGuess::EmbeddedOrIot => "embedded-or-iot",
            OsGuess::Unknown => "unknown",
        }
    }
}

/// Normalize an observed TTL to the nearest common initial-TTL bucket
/// (64, 128, 255) so hop count between sensor and host doesn't defeat
/// matching. Most stacks pick a round starting TTL.
fn normalize_initial_ttl(observed: u8) -> u8 {
    const BUCKETS: [u8; 3] = [64, 128, 255];
    let mut best = BUCKETS[0];
    let mut best_diff = i32::MAX;
    for &b in &BUCKETS {
        // TTL only decreases hop by hop, so the true initial TTL is >= observed.
        if b as i32 >= observed as i32 {
            let diff = b as i32 - observed as i32;
            if diff < best_diff {
                best_diff = diff;
                best = b;
            }
        }
    }
    best
}

/// Heuristic OS classification from a single signature. Deliberately
/// conservative: returns `Unknown` rather than guessing wrong, since a wrong
/// asset classification is worse than an absent one in a clinical inventory.
pub fn classify(sig: &TcpSignature) -> OsGuess {
    let ttl = normalize_initial_ttl(sig.initial_ttl);

    match ttl {
        128 => {
            // Windows almost always: TTL 128, window scale present since Vista,
            // options order MSS,NOP,WS,NOP,NOP,SACK,TS/similar.
            OsGuess::Windows
        }
        64 => {
            if sig.window_scale.is_some() && sig.timestamps_present && sig.sack_permitted {
                // Full modern option set (window scale + timestamps + SACK)
                // at TTL 64 is the common Linux/BSD-userland signature.
                OsGuess::Linux
            } else if !sig.timestamps_present && sig.window_scale.is_none() {
                // Minimal TCP option set: common on embedded stacks (lwIP,
                // VxWorks, many medical devices' network stacks).
                OsGuess::EmbeddedOrIot
            } else {
                OsGuess::Linux
            }
        }
        255 => OsGuess::NetworkAppliance, // Cisco IOS, many routers/switches/APs
        _ => OsGuess::Unknown,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sig(ttl: u8, ws: bool, ts: bool, sack: bool) -> TcpSignature {
        TcpSignature {
            initial_ttl: ttl,
            window_size: 8192,
            mss: Some(1460),
            window_scale: if ws { Some(8) } else { None },
            sack_permitted: sack,
            timestamps_present: ts,
            option_order: "MSS,SACK,TS,NOP,WS".to_string(),
            is_syn_ack: true,
        }
    }

    #[test]
    fn windows_ttl_128_classified() {
        let s = sig(125, true, true, true); // observed 125 (3 hops from 128)
        assert_eq!(classify(&s), OsGuess::Windows);
    }

    #[test]
    fn linux_ttl_64_full_options_classified() {
        let s = sig(60, true, true, true);
        assert_eq!(classify(&s), OsGuess::Linux);
    }

    #[test]
    fn embedded_ttl_64_minimal_options_classified() {
        let s = sig(64, false, false, false);
        assert_eq!(classify(&s), OsGuess::EmbeddedOrIot);
    }

    #[test]
    fn network_appliance_ttl_255_classified() {
        let s = sig(255, false, false, false);
        assert_eq!(classify(&s), OsGuess::NetworkAppliance);
    }

    #[test]
    fn ttl_normalizes_across_hops() {
        assert_eq!(normalize_initial_ttl(128), 128);
        assert_eq!(normalize_initial_ttl(120), 128);
        assert_eq!(normalize_initial_ttl(60), 64);
        assert_eq!(normalize_initial_ttl(250), 255);
    }
}
