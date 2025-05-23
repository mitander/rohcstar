//! ROHC error types and utilities.
//!
//! Defines the error types used throughout the ROHC implementation,
//! including parsing errors, validation failures, and protocol violations.
//! Uses the `thiserror` crate for convenient error type definitions.

use thiserror::Error;

/// ROHC packet parsing errors.
///
/// This enum represents all possible errors that can occur during ROHC packet parsing.
/// Each variant includes contextual information to help diagnose the issue.
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum RohcParsingError {
    /// Insufficient data to parse field/structure.
    ///
    /// This typically occurs when the packet is truncated or malformed.
    #[error("Incomplete packet data: needed {needed} bytes, got {got}")]
    NotEnoughData {
        /// Minimum number of bytes required to parse the field/structure
        needed: usize,
        /// Number of bytes actually available in the input
        got: usize,
    },

    /// Unsupported or invalid ROHC profile ID.
    ///
    /// The provided profile ID doesn't match any supported ROHC profile.
    #[error("Invalid ROHC profile ID: 0x{0:02X}")]
    InvalidProfileId(u8),

    /// Invalid packet type discriminator.
    ///
    /// The packet type byte doesn't match any known packet format.
    #[error("Invalid packet type: 0x{0:02X}")]
    InvalidPacketType(u8),

    /// Unexpected IP version.
    ///
    /// The IP version in the packet is not supported (only IPv4 is currently supported).
    #[error("Invalid IP version: expected 4, got {0}")]
    InvalidIpVersion(u8),

    /// Unsupported protocol in the IP header.
    ///
    /// The protocol specified in the IP header is not supported.
    #[error("Unsupported protocol: {0}")]
    UnsupportedProtocol(u8),

    /// CRC check failed during packet validation.
    ///
    /// The calculated CRC doesn't match the expected value, indicating data corruption.
    #[error("CRC mismatch: expected 0x{expected:02X}, got 0x{calculated:02X}")]
    CrcMismatch {
        /// Expected CRC value from the packet
        expected: u8,
        /// CRC value calculated from the received data
        calculated: u8,
    },

    /// Error in LSB (Least Significant Bits) encoding/decoding.
    ///
    /// This occurs when the encoded value cannot be properly decoded using the
    /// reference value and number of LSBs.
    #[error("Invalid LSB encoding for {field_name}: {description}")]
    InvalidLsbEncoding {
        /// Name of the field that failed LSB encoding/decoding
        field_name: String,
        /// Detailed description of the error
        description: String,
    },

    /// A required field is missing from the packet.
    ///
    /// This typically indicates a malformed packet or unsupported packet format.
    #[error("Missing required field: {field_name}")]
    MandatoryFieldMissing {
        /// Name of the missing field
        field_name: String,
    },

    /// A field contains an invalid or unexpected value.
    ///
    /// The field's value is outside the expected range or violates protocol rules.
    #[error("Invalid value for '{field_name}': {description}")]
    InvalidFieldValue {
        /// Name of the field with the invalid value
        field_name: String,
        /// Description of why the value is invalid
        description: String,
    },
}

/// ROHC packet building errors.
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum RohcBuildingError {
    /// Insufficient buffer space.
    #[error("Buffer too small: need {needed} bytes, have {available}")]
    BufferTooSmall {
        /// Required buffer size
        needed: usize,
        /// Available buffer size
        available: usize,
    },
    /// Missing context information.
    #[error("Insufficient context: {0}")]
    ContextInsufficient(String),
    /// Invalid build value.
    #[error("Invalid build value for '{field_name}': {description}")]
    InvalidFieldValueForBuild {
        /// Problematic field name
        field_name: String,
        /// Error details
        description: String,
    },
}

/// Main ROHC operation errors.
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum RohcError {
    /// Packet parsing failed.
    #[error("Parsing error: {0}")]
    Parsing(#[from] RohcParsingError),
    /// Packet building failed.
    #[error("Building error: {0}")]
    Building(#[from] RohcBuildingError),
    /// Context not found for CID.
    #[error("Context not found for CID: {0}")]
    ContextNotFound(u16),
    /// Context operation error.
    #[error("Context error: {0}")]
    ContextError(String),
    /// Invalid state transition.
    #[error("Invalid state transition or operation for current state: {0}")]
    InvalidState(String),
    /// The specified ROHC profile is not supported by this implementation.
    #[error("Unsupported ROHC profile: 0x{0:02X}")]
    UnsupportedProfile(u8),
    /// The requested operation is not supported in the current ROHC operational mode (e.g., U-mode, O-mode, R-mode).
    #[error("Operation not supported in current mode: {0}")]
    ModeNotSupported(String),
    /// An unexpected internal logic error occurred. This typically indicates a bug in Rohcstar.
    #[error("Internal logic error: {0}")]
    Internal(String),
}
