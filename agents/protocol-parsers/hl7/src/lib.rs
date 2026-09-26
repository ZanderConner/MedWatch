//! Minimal passive HL7v2 / MLLP parser.
//!
//! Only reads the MSH (Message Header) segment out of MLLP-framed HL7v2
//! traffic (default port 2575) — sending application/facility, receiving
//! application/facility, and message type. That's sufficient to fingerprint
//! an interface engine or EHR endpoint for asset inventory without parsing
//! (or storing) any patient-identifying segments (PID, etc).

use thiserror::Error;

pub const HL7_DEFAULT_PORT: u16 = 2575;

const MLLP_START: u8 = 0x0B;
const MLLP_END_1: u8 = 0x1C;
const MLLP_END_2: u8 = 0x0D;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum Hl7ParseError {
    #[error("missing MLLP start block byte (0x0B)")]
    MissingStartBlock,
    #[error("missing MLLP end block bytes (0x1C 0x0D)")]
    MissingEndBlock,
    #[error("message does not begin with an MSH segment")]
    NoMshSegment,
    #[error("MSH segment has too few fields (need sending/receiving app+facility and type)")]
    TruncatedMsh,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MshHeader {
    pub field_separator: char,
    pub sending_application: String,
    pub sending_facility: String,
    pub receiving_application: String,
    pub receiving_facility: String,
    pub message_type: String,
}

// Field index reference (0-based split on the field separator):
// 0=MSH, 1=encoding chars, 2=sending app, 3=sending facility,
// 4=receiving app, 5=receiving facility, 6=timestamp, 7=security,
// 8=message type.

/// Strip MLLP framing (start-of-block / end-of-block) from a raw TCP
/// payload, returning the inner HL7 message bytes.
pub fn unwrap_mllp(buf: &[u8]) -> Result<&[u8], Hl7ParseError> {
    if buf.first() != Some(&MLLP_START) {
        return Err(Hl7ParseError::MissingStartBlock);
    }
    let inner = &buf[1..];
    if inner.len() < 2
        || inner[inner.len() - 2] != MLLP_END_1
        || inner[inner.len() - 1] != MLLP_END_2
    {
        return Err(Hl7ParseError::MissingEndBlock);
    }
    Ok(&inner[..inner.len() - 2])
}

/// Parse the MSH segment out of an (already MLLP-unwrapped) HL7v2 message.
pub fn parse_msh(message: &[u8]) -> Result<MshHeader, Hl7ParseError> {
    let text = String::from_utf8_lossy(message);
    let first_segment = text
        .split(['\r', '\n'])
        .find(|l| !l.is_empty())
        .ok_or(Hl7ParseError::NoMshSegment)?;

    if !first_segment.starts_with("MSH") || first_segment.len() < 4 {
        return Err(Hl7ParseError::NoMshSegment);
    }

    // MSH-1 is the field separator itself (the character right after "MSH").
    let field_separator = first_segment.chars().nth(3).unwrap_or('|');
    let fields: Vec<&str> = first_segment.split(field_separator).collect();

    // fields[0] == "MSH", fields[1] == encoding chars, fields[2] == sending app, ...
    // MSH-3 sending app, MSH-4 sending facility, MSH-5 receiving app,
    // MSH-6 receiving facility, MSH-9 message type.
    if fields.len() <= 6 {
        return Err(Hl7ParseError::TruncatedMsh);
    }

    let message_type = fields.get(8).copied().unwrap_or("").to_string();

    Ok(MshHeader {
        field_separator,
        sending_application: fields[2].to_string(),
        sending_facility: fields[3].to_string(),
        receiving_application: fields[4].to_string(),
        receiving_facility: fields[5].to_string(),
        message_type,
    })
}

/// Fast content sniff for the sensor's protocol dispatcher: true if the
/// payload is MLLP-framed and its inner content starts with "MSH".
pub fn looks_like_hl7(buf: &[u8]) -> bool {
    match unwrap_mllp(buf) {
        Ok(inner) => inner.starts_with(b"MSH"),
        Err(_) => buf.starts_with(b"MSH"), // tolerate non-MLLP-framed captures
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_message() -> Vec<u8> {
        let msh = "MSH|^~\\&|ADT_APP|GENERAL_HOSPITAL|INTERFACE_ENGINE|LAB_FACILITY|20240101120000||ADT^A01|MSG00001|P|2.3\r";
        let mut buf = vec![MLLP_START];
        buf.extend_from_slice(msh.as_bytes());
        buf.push(MLLP_END_1);
        buf.push(MLLP_END_2);
        buf
    }

    #[test]
    fn unwraps_mllp_framing() {
        let framed = sample_message();
        let inner = unwrap_mllp(&framed).unwrap();
        assert!(inner.starts_with(b"MSH"));
    }

    #[test]
    fn rejects_missing_start_block() {
        let framed = sample_message();
        assert_eq!(
            unwrap_mllp(&framed[1..]).unwrap_err(),
            Hl7ParseError::MissingStartBlock
        );
    }

    #[test]
    fn parses_msh_fields() {
        let framed = sample_message();
        let inner = unwrap_mllp(&framed).unwrap();
        let msh = parse_msh(inner).unwrap();
        assert_eq!(msh.sending_application, "ADT_APP");
        assert_eq!(msh.sending_facility, "GENERAL_HOSPITAL");
        assert_eq!(msh.receiving_application, "INTERFACE_ENGINE");
        assert_eq!(msh.receiving_facility, "LAB_FACILITY");
        assert_eq!(msh.message_type, "ADT^A01");
    }

    #[test]
    fn looks_like_hl7_detects_framed_and_unframed() {
        assert!(looks_like_hl7(&sample_message()));
        assert!(looks_like_hl7(b"MSH|^~\\&|X"));
        assert!(!looks_like_hl7(b"GET / HTTP/1.1"));
    }
}
