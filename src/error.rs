//! ROHC (Robust Header Compression) error types and utilities.
//!
//! This module defines the error types used throughout the Rohcstar library.
//! It distinguishes between parsing errors, packet building errors, and general
//! operational errors. The `thiserror` crate is used for ergonomic error definitions.

use thiserror::Error;

/// Errors that can occur during ROHC packet parsing.
///
/// These errors typically indicate issues with the format or content of an
/// incoming ROHC packet or an uncompressed packet being prepared for compression.
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum RohcParsingError {
    /// Insufficient data was provided to parse a complete field or structure.
    #[error("Incomplete packet data: needed {needed} bytes, got {got} for {context}")]
    NotEnoughData {
        needed: usize,
        got: usize,
        context: String, // e.g., "IPv4 header", "ROHC IR packet static chain"
    },

    /// An invalid or unsupported ROHC profile identifier was encountered.
    #[error("Invalid or unsupported ROHC profile ID: 0x{0:02X}")]
    InvalidProfileId(u8),

    /// The packet type discriminator (e.g., the first byte of a ROHC packet)
    /// is invalid or not recognized by the specific profile handler.
    #[error(
        "Invalid ROHC packet type discriminator: 0x{discriminator:02X} for profile {profile_id:?}"
    )]
    InvalidPacketType {
        discriminator: u8,
        profile_id: Option<u8>, // Optionally provide profile ID for context
    },

    /// An IP version other than the expected one (e.g., IPv4) was found.
    #[error("Invalid IP version: expected {expected}, got {got}")]
    InvalidIpVersion { expected: u8, got: u8 },

    /// An unsupported protocol was specified in a header (e.g., a non-UDP protocol
    /// in an IP header when expecting UDP for ROHC Profile 1).
    #[error("Unsupported protocol: {protocol_id} in {layer} header")]
    UnsupportedProtocol {
        protocol_id: u8,
        layer: String, // e.g., "IP", "UDP"
    },

    /// A CRC (Cyclic Redundancy Check) validation failed, indicating potential
    /// data corruption or a mismatch in context.
    #[error("CRC mismatch: expected 0x{expected:X}, got 0x{calculated:X} for {crc_type} CRC")]
    CrcMismatch {
        expected: u8,
        calculated: u8,
        crc_type: String, // e.g., "ROHC-CRC8", "ROHC-CRC3"
    },

    /// An error occurred during LSB (Least Significant Bits) encoding or decoding.
    /// This typically means a value could not be unambiguously resolved.
    #[error("Invalid LSB operation for field '{field_name}': {description}")]
    InvalidLsbOperation {
        field_name: String,
        description: String,
    },

    /// A mandatory field was missing from a packet or header.
    #[error("Missing required field: {field_name} in {structure_name}")]
    MandatoryFieldMissing {
        field_name: String,
        structure_name: String,
    },

    /// A field contained an invalid or unexpected value according to protocol rules.
    #[error("Invalid value for field '{field_name}' in {structure_name}: {description}")]
    InvalidFieldValue {
        field_name: String,
        structure_name: String,
        description: String,
    },

    /// A general, profile-specific parsing error occurred.
    #[error("Profile-specific parsing error for profile 0x{profile_id:02X}: {description}")]
    ProfileSpecificParsingError { profile_id: u8, description: String },
}

/// Errors that can occur during ROHC packet building (construction).
///
/// These errors indicate issues that prevent the successful creation of a
/// ROHC packet from uncompressed headers or context information.
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum RohcBuildingError {
    /// The provided buffer was too small to hold the packet being built.
    /// (Note: Most builders in Rohcstar will return `Vec<u8>`, making this less common
    /// unless a fixed-size buffer is explicitly used by a specific function).
    #[error("Buffer too small: needed {needed} bytes, have {available} for {context}")]
    BufferTooSmall {
        needed: usize,
        available: usize,
        context: String,
    },

    /// Necessary context information was missing or insufficient to build the packet.
    #[error("Context insufficient for building packet: {reason}")]
    ContextInsufficient { reason: String },

    /// An invalid value was provided for a field during packet construction.
    #[error("Invalid value for field '{field_name}' during packet building: {description}")]
    InvalidFieldValueForBuild {
        field_name: String,
        description: String,
    },

    /// A general, profile-specific building error occurred.
    #[error("Profile-specific building error for profile 0x{profile_id:02X}: {description}")]
    ProfileSpecificBuildingError { profile_id: u8, description: String },
}

/// The main error type for ROHC operations within the Rohcstar library.
///
/// This enum consolidates various error kinds that can occur during
/// compression, decompression, context management, or other ROHC operations.
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum RohcError {
    /// An error occurred during packet parsing.
    #[error("Parsing error: {0}")]
    Parsing(#[from] RohcParsingError),

    /// An error occurred during packet building.
    #[error("Building error: {0}")]
    Building(#[from] RohcBuildingError),

    /// No ROHC context was found for the given Context Identifier (CID).
    #[error("Context not found for CID: {0}")]
    ContextNotFound(u16),

    /// An error occurred related to ROHC context state or management.
    #[error("Context error: {0}")]
    ContextError(String),

    /// An operation was attempted that is invalid for the current ROHC state
    /// (e.g., compressor or decompressor mode).
    #[error("Invalid state for operation: {0}")]
    InvalidState(String),

    /// The specified ROHC profile is not supported by this instance of Rohcstar
    /// or by the current configuration.
    #[error("Unsupported ROHC profile: 0x{0:02X}")]
    UnsupportedProfile(u8),

    /// The requested operation is not supported in the current ROHC operational mode
    /// (e.g., Unidirectional, Bidirectional-Optimistic, Bidirectional-Reliable).
    #[error("Operation not supported in current ROHC mode: {0}")]
    ModeNotSupported(String), // e.g. U-mode, O-mode, R-mode

    /// An unexpected internal logic error occurred. This typically indicates a bug
    /// within the Rohcstar library itself.
    #[error("Internal logic error: {0}")]
    Internal(String),

    /// An I/O error occurred (e.g., when reading from or writing to a stream,
    /// though Rohcstar primarily deals with byte slices).
    #[error("I/O error: {0}")]
    Io(String), // Simplified; for real I/O, use std::io::Error or a wrapper

    /// A profile-specific error that doesn't fit into parsing or building categories.
    #[error("Profile-specific error for profile 0x{profile_id:02X}: {description}")]
    ProfileSpecific { profile_id: u8, description: String },
}

// Optional: Implement From for easier error conversion if needed elsewhere
// impl From<std::io::Error> for RohcError {
//     fn from(err: std::io::Error) -> Self {
//         RohcError::Io(err.to_string())
//     }
// }

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn not_enough_data_error_display() {
        let err = RohcParsingError::NotEnoughData {
            needed: 10,
            got: 5,
            context: "ROHC IR Header".to_string(),
        };
        assert_eq!(
            format!("{}", err),
            "Incomplete packet data: needed 10 bytes, got 5 for ROHC IR Header"
        );
    }

    #[test]
    fn invalid_profile_id_error_display() {
        let err = RohcParsingError::InvalidProfileId(0xAB);
        assert_eq!(
            format!("{}", err),
            "Invalid or unsupported ROHC profile ID: 0xAB"
        );
    }

    #[test]
    fn invalid_packet_type_error_display() {
        let err = RohcParsingError::InvalidPacketType {
            discriminator: 0xF0,
            profile_id: Some(0x01),
        };
        assert_eq!(
            format!("{}", err),
            "Invalid ROHC packet type discriminator: 0xF0 for profile Some(1)"
        );
    }

    #[test]
    fn crc_mismatch_error_display() {
        let err = RohcParsingError::CrcMismatch {
            expected: 0x12,
            calculated: 0x34,
            crc_type: "TestCRC".to_string(),
        };
        assert_eq!(
            format!("{}", err),
            "CRC mismatch: expected 0x12, got 0x34 for TestCRC CRC"
        );
    }

    #[test]
    fn rohc_error_from_parsing_error() {
        let parsing_err = RohcParsingError::NotEnoughData {
            needed: 8,
            got: 4,
            context: "Field X".to_string(),
        };
        let rohc_err = RohcError::from(parsing_err.clone());
        match rohc_err {
            RohcError::Parsing(inner_err) => assert_eq!(inner_err, parsing_err),
            _ => panic!("Incorrect RohcError variant"),
        }
    }

    #[test]
    fn rohc_error_from_building_error() {
        let building_err = RohcBuildingError::ContextInsufficient {
            reason: "SSRC not set".to_string(),
        };
        let rohc_err = RohcError::from(building_err.clone());
        match rohc_err {
            RohcError::Building(inner_err) => assert_eq!(inner_err, building_err),
            _ => panic!("Incorrect RohcError variant"),
        }
    }

    #[test]
    fn context_not_found_error_display() {
        let err = RohcError::ContextNotFound(123);
        assert_eq!(format!("{}", err), "Context not found for CID: 123");
    }

    #[test]
    fn profile_specific_parsing_error_display() {
        let err = RohcParsingError::ProfileSpecificParsingError {
            profile_id: 0x01,
            description: "Invalid SN encoding for UO-0".to_string(),
        };
        assert_eq!(
            format!("{}", err),
            "Profile-specific parsing error for profile 0x01: Invalid SN encoding for UO-0"
        );
    }
}
