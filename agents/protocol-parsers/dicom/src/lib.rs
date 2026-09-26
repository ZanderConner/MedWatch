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

/// Parse a DICOM A-ASSOCIATE-RQ PDU (PS3.8 §9.3.2) from a raw TCP payload.
/// Only the fixed-length header fields are read; variable items
/// (Application Context, Presentation Context, User Info) are ignored since
/// asset inventory only needs the AE titles.
pub fn parse_associate_rq(buf: &[u8]) -> Result<AssociateRq, DicomParseError> {
    // Fixed header: 1 byte PDU type, 1 reserved, 4 byte length,
    // 2 byte protocol version, 2 reserved, 16 byte called AE, 16 byte calling AE,
    // 32 reserved bytes = 74 bytes minimum before variable items.
    const HEADER_LEN: usize = 74;
    if buf.len() < HEADER_LEN {
        return Err(DicomParseError::TooShort {
            need: HEADER_LEN,
            have: buf.len(),
        });
    }
    if buf[0] != PDU_TYPE_ASSOCIATE_RQ {
        return Err(DicomParseError::NotAssociatePdu(buf[0]));
    }

    let protocol_version = u16::from_be_bytes([buf[6], buf[7]]);
    let called_ae_title = extract_ae_title(&buf[10..26])?;
    let calling_ae_title = extract_ae_title(&buf[26..42])?;

    Ok(AssociateRq {
        called_ae_title,
        calling_ae_title,
        protocol_version,
    })
}

/// Returns true if `buf` opens with an A-ASSOCIATE-RQ or -AC PDU type byte,
/// used by the sensor's protocol dispatcher for fast port+content sniffing.
pub fn looks_like_dicom(buf: &[u8]) -> bool {
    matches!(
        buf.first(),
        Some(&PDU_TYPE_ASSOCIATE_RQ) | Some(&PDU_TYPE_ASSOCIATE_AC)
    )
}

fn extract_ae_title(field: &[u8]) -> Result<String, DicomParseError> {
    if field.len() != 16 {
        return Err(DicomParseError::MalformedAeTitle);
    }
    // AE titles are space-padded ASCII, fixed 16 bytes.
    let trimmed: Vec<u8> = field.iter().copied().take_while(|&b| b != 0).collect();
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

    fn build_associate_rq(called: &str, calling: &str) -> Vec<u8> {
        let mut buf = vec![0u8; 74];
        buf[0] = PDU_TYPE_ASSOCIATE_RQ;
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
        let buf = build_associate_rq("PACS_MAIN", "CT_SCANNER_3");
        let rq = parse_associate_rq(&buf).unwrap();
        assert_eq!(rq.called_ae_title, "PACS_MAIN");
        assert_eq!(rq.calling_ae_title, "CT_SCANNER_3");
        assert_eq!(rq.protocol_version, 1);
    }

    #[test]
    fn rejects_too_short_buffer() {
        let err = parse_associate_rq(&[0x01, 0x00, 0x00]).unwrap_err();
        assert_eq!(err, DicomParseError::TooShort { need: 74, have: 3 });
    }

    #[test]
    fn rejects_wrong_pdu_type() {
        let mut buf = build_associate_rq("A", "B");
        buf[0] = 0x07; // A-ABORT
        assert_eq!(
            parse_associate_rq(&buf).unwrap_err(),
            DicomParseError::NotAssociatePdu(0x07)
        );
    }

    #[test]
    fn looks_like_dicom_matches_rq_and_ac() {
        assert!(looks_like_dicom(&[0x01, 0, 0, 0]));
        assert!(looks_like_dicom(&[0x02, 0, 0, 0]));
        assert!(!looks_like_dicom(&[0x50, 0, 0, 0]));
        assert!(!looks_like_dicom(&[]));
    }
}
