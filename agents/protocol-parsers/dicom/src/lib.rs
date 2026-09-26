//! Minimal, read-only DICOM upper-layer protocol (PS3.8) parser.
//!
//! MedWatch never initiates a DICOM association — it only passively parses
//! A-ASSOCIATE-RQ PDUs it observes on the wire (default ports 104/11112) to
//! extract the calling/called AE titles and implementation class/version,
//! which is enough for asset inventory ("this IP is a PACS / modality named
//! CT_SCANNER_3") without touching PHI in the data set itself.

use thiserror::Error;

pub const DICOM_DEFAULT_PORTS: [u16; 2] = [104, 11112];

const PDU_TYPE_ASSOCIATE_RQ: u8 = 0x01;
const PDU_TYPE_ASSOCIATE_AC: u8 = 0x02;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum DicomParseError {
    #[error("buffer too short: need at least {need} bytes, have {have}")]
    TooShort { need: usize, have: usize },
    #[error("not an A-ASSOCIATE PDU (type byte 0x{0:02x})")]
    NotAssociatePdu(u8),
    #[error("malformed AE title field")]
    MalformedAeTitle,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssociateRq {
    pub called_ae_title: String,
    pub calling_ae_title: String,
    pub protocol_version: u16,
}

/// Which of the two DICOM upper-layer PDUs a parsed header came from.
/// A-ASSOCIATE-RQ is sent BY the initiator (SCU) — its `calling_ae_title`
/// identifies the sender. A-ASSOCIATE-AC is sent BY the acceptor (SCP,
/// e.g. a PACS/archive like Orthanc) — critically, its `called_ae_title`
/// field echoes back the RQ's addressee, which in practice is the
/// acceptor's own real AE title (an SCP only accepts associations
/// addressed to itself), so it doubles as reliable self-identification
/// for a device that never initiates an association and therefore would
/// otherwise never appear in a captured RQ.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PduKind {
    AssociateRq,
    AssociateAc,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssociateHeader {
    pub kind: PduKind,
    pub called_ae_title: String,
    pub calling_ae_title: String,
    pub protocol_version: u16,
}

/// Parse a DICOM A-ASSOCIATE-RQ PDU (PS3.8 §9.3.2) from a raw TCP payload.
/// Only the fixed-length header fields are read; variable items
/// (Application Context, Presentation Context, User Info) are ignored since
/// asset inventory only needs the AE titles.
pub fn parse_associate_rq(buf: &[u8]) -> Result<AssociateRq, DicomParseError> {
    let header = parse_associate_header(buf)?;
    if header.kind != PduKind::AssociateRq {
        return Err(DicomParseError::NotAssociatePdu(buf[0]));
    }
    Ok(AssociateRq {
        called_ae_title: header.called_ae_title,
        calling_ae_title: header.calling_ae_title,
        protocol_version: header.protocol_version,
    })
}

/// Parse either an A-ASSOCIATE-RQ or A-ASSOCIATE-AC PDU (both PS3.8
/// §9.3.2/§9.3.3 share the same fixed 74-byte header layout: PDU type,
/// reserved, length, protocol version, reserved, called AE, calling AE,
/// reserved). Prefer this over `parse_associate_rq` when the caller cares
/// about identifying BOTH sides of a DICOM association, not just the
/// initiator — see `PduKind` for why the AC side matters for passively
/// fingerprinting an SCP that never initiates traffic.
pub fn parse_associate_header(buf: &[u8]) -> Result<AssociateHeader, DicomParseError> {
    const HEADER_LEN: usize = 74;
    if buf.len() < HEADER_LEN {
        return Err(DicomParseError::TooShort {
            need: HEADER_LEN,
            have: buf.len(),
        });
    }
    let kind = match buf[0] {
        PDU_TYPE_ASSOCIATE_RQ => PduKind::AssociateRq,
        PDU_TYPE_ASSOCIATE_AC => PduKind::AssociateAc,
        other => return Err(DicomParseError::NotAssociatePdu(other)),
    };

    let protocol_version = u16::from_be_bytes([buf[6], buf[7]]);
    let called_ae_title = extract_ae_title(&buf[10..26])?;
    let calling_ae_title = extract_ae_title(&buf[26..42])?;

    Ok(AssociateHeader {
        kind,
        called_ae_title,
        calling_ae_title,
        protocol_version,
    })
}

/// Returns true if `buf` looks like the start of an A-ASSOCIATE-RQ or -AC
/// PDU, used by the sensor's protocol dispatcher for fast content sniffing
/// on non-standard ports. Checks more than just the first byte: PDU type
/// is one byte in a space of 256 values, so a bare `buf[0] == 0x01` check
/// alone produces frequent false positives on arbitrary non-DICOM traffic
/// (confirmed in range validation — ICMPv6/NDP payloads that happen to
/// start with 0x01 were being tagged as DICOM). Also validates the
/// reserved byte, the two reserved bytes at the protocol-version offset,
/// and that the declared PDU length is internally plausible.
pub fn looks_like_dicom(buf: &[u8]) -> bool {
    // Fixed header layout (PS3.8 §9.3.2/9.3.3): byte 0 PDU type, byte 1
    // reserved (must be 0x00), bytes 2..6 PDU length (u32 BE, describes
    // bytes following the 6-byte header), bytes 8..10 reserved (0x0000)
    // for both A-ASSOCIATE-RQ and -AC.
    const MIN_SNIFF_LEN: usize = 10;
    if buf.len() < MIN_SNIFF_LEN {
        return false;
    }
    let is_associate_type = matches!(buf[0], PDU_TYPE_ASSOCIATE_RQ | PDU_TYPE_ASSOCIATE_AC);
    if !is_associate_type {
        return false;
    }
    let reserved_byte_1 = buf[1] == 0x00;
    let reserved_bytes_8_9 = buf[8] == 0x00 && buf[9] == 0x00;
    let declared_len = u32::from_be_bytes([buf[2], buf[3], buf[4], buf[5]]);
    // A real A-ASSOCIATE PDU body is at least ~68 bytes (protocol version +
    // both AE titles + reserved) and DICOM PDUs are capped well under 1MB
    // in practice; this range rules out both all-zero and wildly-implausible
    // "length" fields that random payload bytes tend to produce.
    let plausible_length = (2..1_000_000).contains(&declared_len);

    reserved_byte_1 && reserved_bytes_8_9 && plausible_length
}

fn extract_ae_title(field: &[u8]) -> Result<String, DicomParseError> {
    if field.len() != 16 {
        return Err(DicomParseError::MalformedAeTitle);
    }
    // AE titles are space-padded ASCII, fixed 16 bytes, restricted to the
    // DICOM default character repertoire (PS3.5 §6.1.2.3: uppercase/
    // lowercase letters, digits, and a handful of punctuation — no
    // control characters). Reject anything outside printable ASCII
    // rather than using from_utf8_lossy's replacement-character
    // fallback: `looks_like_dicom`'s cheap 10-byte header sniff only
    // validates PDU type/reserved-bytes/length, NOT these title bytes,
    // so a false-positive match on arbitrary non-DICOM payload can
    // reach here with raw binary garbage in this field — that garbage
    // must never be accepted as a device's identity, since it silently
    // clobbers a previously-good name (see the MRISIM regression this
    // caught: an intermittent non-DICOM TCP chunk momentarily matched
    // the loose sniff and overwrote a device's correct AE title with
    // control-character noise for a few seconds).
    let trimmed: Vec<u8> = field.iter().copied().take_while(|&b| b != 0).collect();
    if !trimmed.iter().all(|&b| (0x20..=0x7e).contains(&b)) {
        return Err(DicomParseError::MalformedAeTitle);
    }
    let s = String::from_utf8_lossy(&trimmed).trim().to_string();
    if s.is_empty() {
        Err(DicomParseError::MalformedAeTitle)
    } else {
        Ok(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_associate_rq(pdu_type: u8, called: &str, calling: &str) -> Vec<u8> {
        let mut buf = vec![0u8; 74];
        buf[0] = pdu_type;
        buf[1] = 0x00; // reserved
        buf[2..6].copy_from_slice(&66u32.to_be_bytes()); // pdu length (arbitrary, unread)
        buf[6..8].copy_from_slice(&1u16.to_be_bytes()); // protocol version 1
                                                        // buf[8..10] reserved
        let mut called_field = [0x20u8; 16]; // space padded
        called_field[..called.len()].copy_from_slice(called.as_bytes());
        buf[10..26].copy_from_slice(&called_field);

        let mut calling_field = [0x20u8; 16];
        calling_field[..calling.len()].copy_from_slice(calling.as_bytes());
        buf[26..42].copy_from_slice(&calling_field);
        buf
    }

    #[test]
    fn parses_ae_titles_from_associate_rq() {
        let buf = build_associate_rq(PDU_TYPE_ASSOCIATE_RQ, "PACS_MAIN", "CT_SCANNER_3");
        let rq = parse_associate_rq(&buf).unwrap();
        assert_eq!(rq.called_ae_title, "PACS_MAIN");
        assert_eq!(rq.calling_ae_title, "CT_SCANNER_3");
        assert_eq!(rq.protocol_version, 1);
    }

    #[test]
    fn parses_associate_ac_header_for_responder_self_identification() {
        // An A-ASSOCIATE-AC sent BY Orthanc echoes back the RQ's called
        // AE title ("ORTHANC", the responder's own real name) in the
        // same field position — this is how a passive sensor identifies
        // an SCP/archive that never itself sends an RQ.
        let buf = build_associate_rq(PDU_TYPE_ASSOCIATE_AC, "ORTHANC", "CTSIM");
        let header = parse_associate_header(&buf).unwrap();
        assert_eq!(header.kind, PduKind::AssociateAc);
        assert_eq!(header.called_ae_title, "ORTHANC");
        assert_eq!(header.calling_ae_title, "CTSIM");

        // parse_associate_rq stays RQ-only (existing callers expect that).
        assert_eq!(
            parse_associate_rq(&buf).unwrap_err(),
            DicomParseError::NotAssociatePdu(PDU_TYPE_ASSOCIATE_AC)
        );
    }

    #[test]
    fn rejects_ae_title_with_non_printable_bytes() {
        // The exact class of bug this guards against: a false-positive
        // `looks_like_dicom` match on non-DICOM payload can put raw
        // binary garbage (control bytes, high-bit bytes) into the AE
        // title field position. from_utf8_lossy alone would happily
        // turn that into a string full of U+FFFD replacement
        // characters and a stray control char — accepted here instead
        // means a device's real, previously-learned identity gets
        // silently clobbered by noise. Must be rejected as malformed.
        let mut buf = build_associate_rq(PDU_TYPE_ASSOCIATE_RQ, "MRISIM", "ORTHANC");
        buf[10] = 0x02;
        buf[11] = 0xff; // invalid UTF-8 continuation byte
        buf[12] = 0x01;
        buf[13] = 0xfe;
        assert_eq!(
            parse_associate_rq(&buf).unwrap_err(),
            DicomParseError::MalformedAeTitle
        );
    }

    #[test]
    fn rejects_too_short_buffer() {
        let err = parse_associate_rq(&[0x01, 0x00, 0x00]).unwrap_err();
        assert_eq!(err, DicomParseError::TooShort { need: 74, have: 3 });
    }

    #[test]
    fn rejects_wrong_pdu_type() {
        let mut buf = build_associate_rq(PDU_TYPE_ASSOCIATE_RQ, "A", "B");
        buf[0] = 0x07; // A-ABORT
        assert_eq!(
            parse_associate_rq(&buf).unwrap_err(),
            DicomParseError::NotAssociatePdu(0x07)
        );
    }

    #[test]
    fn looks_like_dicom_matches_real_associate_headers() {
        let rq = build_associate_rq(PDU_TYPE_ASSOCIATE_RQ, "A", "B");
        assert!(looks_like_dicom(&rq));
        let mut ac = rq.clone();
        ac[0] = PDU_TYPE_ASSOCIATE_AC;
        assert!(looks_like_dicom(&ac));
    }

    #[test]
    fn looks_like_dicom_rejects_wrong_type_or_short_buffer() {
        assert!(!looks_like_dicom(&[0x50, 0, 0, 0, 0, 0, 0, 0, 0, 0]));
        assert!(!looks_like_dicom(&[0x01, 0, 0, 0]));
        assert!(!looks_like_dicom(&[]));
    }

    #[test]
    fn looks_like_dicom_rejects_non_dicom_byte_that_starts_with_pdu_type() {
        // Real-world false positive found via range validation: an
        // ICMPv6/NDP payload whose first byte happens to be 0x01 but
        // whose "reserved" bytes and length field don't match any real
        // DICOM PDU.
        let icmpv6_like = [0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0x99, 0x00];
        assert!(!looks_like_dicom(&icmpv6_like));
    }
}
