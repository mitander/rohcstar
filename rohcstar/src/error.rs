//! ROHC (Robust Header Compression) error types and utilities.
//!
//! This module defines the error types used throughout the Rohcstar library.
//! It distinguishes between parsing errors, packet building errors, and general
//! operational errors. The `thiserror` crate is used for ergonomic error definitions.

use thiserror::Error;

use crate::packet_defs::RohcProfile;
use crate::types::ContextId;

/// Context types for parsing operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseContext {
    RohcPacketInput,
    CorePacketAfterCid,
    CidParsing,
    ProfileIdPeek,
    Ipv4HeaderMin,
    Ipv4HeaderCalculated,
    UdpHeader,
    RtpHeaderMin,
    IrPacketTypeOctet,
    IrPacketRtpFlags,
    IrPacketCrcAndPayload,
    IrPacketTsStrideExtension,
    Uo0PacketCore,
    Uo1SnPacketCore,
    Uo1TsPacketCore,
    Uo1IdPacketCore,
    Uo1RtpPacketCore,
    UoPacketTypeDiscriminator,
}

impl std::fmt::Display for ParseContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::RohcPacketInput => "ROHC packet input",
            Self::CorePacketAfterCid => "Core ROHC packet after CID processing",
            Self::CidParsing => "CID parsing",
            Self::ProfileIdPeek => "Peeking profile ID from core packet",
            Self::Ipv4HeaderMin => "IPv4 header (minimum)",
            Self::Ipv4HeaderCalculated => "IPv4 header (calculated IHL)",
            Self::UdpHeader => "UDP header",
            Self::RtpHeaderMin => "RTP header (minimum)",
            Self::IrPacketTypeOctet => "IR Packet Type Octet",
            Self::IrPacketRtpFlags => "IR Packet (RTP_Flags for CRC check)",
            Self::IrPacketCrcAndPayload => "IR Packet (CRC field and defined payload)",
            Self::IrPacketTsStrideExtension => "IR Packet TS_STRIDE Extension",
            Self::Uo0PacketCore => "UO-0 Packet Core",
            Self::Uo1SnPacketCore => "UO-1-SN Packet Core",
            Self::Uo1TsPacketCore => "UO-1-TS Packet Core",
            Self::Uo1IdPacketCore => "UO-1-ID Packet Core",
            Self::Uo1RtpPacketCore => "UO-1-RTP Packet Core",
            Self::UoPacketTypeDiscriminator => "UO packet type discriminator",
        };
        write!(f, "{}", s)
    }
}

/// Field types for structured error reporting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Field {
    // Generic fields
    Cid,
    ProfileId,
    NumLsbBits,
    ReceivedLsbs,

    // IP fields
    IpVersion,
    IpIhl,
    IpProtocol,

    // RTP fields
    RtpVersion,
    RtpCsrcCount,

    // UO packet fields
    SnLsb,
    TsLsb,
    IpIdLsb,
    TsScaled,
    Crc3,
    NumSnLsbBits,
    NumTsLsbBits,
    NumIpIdLsbBits,

    // Packet structure fields
    Uo0CorePacketLength,
    BufferSize,
}

impl std::fmt::Display for Field {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::Cid => "CID",
            Self::ProfileId => "Profile ID",
            Self::NumLsbBits => "num_lsb_bits",
            Self::ReceivedLsbs => "received_lsbs",
            Self::IpVersion => "IPv4 Version",
            Self::IpIhl => "IPv4 IHL",
            Self::IpProtocol => "IP Protocol",
            Self::RtpVersion => "RTP Version",
            Self::RtpCsrcCount => "RTP CSRC Count",
            Self::SnLsb => "sn_lsb",
            Self::TsLsb => "ts_lsb",
            Self::IpIdLsb => "ip_id_lsb",
            Self::TsScaled => "ts_scaled",
            Self::Crc3 => "crc3",
            Self::NumSnLsbBits => "num_sn_lsb_bits",
            Self::NumTsLsbBits => "num_ts_lsb_bits",
            Self::NumIpIdLsbBits => "num_ip_id_lsb_bits",
            Self::Uo0CorePacketLength => "UO-0 Core Packet Length",
            Self::BufferSize => "Buffer Size",
        };
        write!(f, "{}", s)
    }
}

/// Header structure types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StructureType {
    Ipv4Header,
    RtpHeader,
    Uo0Packet,
    Uo1SnPacket,
    Uo1TsPacket,
    Uo1IdPacket,
    Uo1RtpPacket,
}

impl std::fmt::Display for StructureType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::Ipv4Header => "IPv4 Header",
            Self::RtpHeader => "RTP Header",
            Self::Uo0Packet => "UO-0 Packet",
            Self::Uo1SnPacket => "UO-1-SN Packet",
            Self::Uo1TsPacket => "UO-1-TS Packet",
            Self::Uo1IdPacket => "UO-1-ID Packet",
            Self::Uo1RtpPacket => "UO-1-RTP Packet",
        };
        write!(f, "{}", s)
    }
}

/// Network layer types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkLayer {
    Ip,
    Udp,
    Rtp,
}

impl std::fmt::Display for NetworkLayer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::Ip => "IP",
            Self::Udp => "UDP",
            Self::Rtp => "RTP",
        };
        write!(f, "{}", s)
    }
}

/// CRC types used in ROHC.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CrcType {
    Rohc3,
    Rohc8,
    Crc3Uo0,
    Crc8Uo1Sn,
    TestCrc,
}

impl std::fmt::Display for CrcType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::Rohc3 => "ROHC-CRC3",
            Self::Rohc8 => "ROHC-CRC8",
            Self::Crc3Uo0 => "CRC3-UO0",
            Self::Crc8Uo1Sn => "CRC8-UO1SN",
            Self::TestCrc => "TestCRC",
        };
        write!(f, "{}", s)
    }
}

/// Errors that can occur during ROHC packet parsing.
///
/// These errors typically indicate issues with the format or content of an
/// incoming ROHC packet or an uncompressed packet being prepared for compression.
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum RohcParsingError {
    /// Insufficient data to parse a complete field or structure.
    #[error("Incomplete packet data: needed {needed} bytes, got {got} for {context}")]
    NotEnoughData {
        needed: usize,
        got: usize,
        context: ParseContext,
    },

    /// Invalid or unsupported ROHC profile identifier encountered.
    #[error("Invalid or unsupported ROHC profile ID: 0x{0:02X}")]
    InvalidProfileId(u8),

    /// Unrecognized ROHC packet type discriminator for the current profile.
    #[error(
        "Invalid ROHC packet type discriminator: 0x{discriminator:02X} for profile {profile_id:?}"
    )]
    InvalidPacketType {
        discriminator: u8,
        profile_id: Option<u8>,
    },

    /// Invalid IP version found; expected a specific version.
    #[error("Invalid IP version: expected {expected}, got {got}")]
    InvalidIpVersion { expected: u8, got: u8 },

    /// Unsupported protocol specified in a header (e.g., non-UDP in IP for Profile 1).
    #[error("Unsupported protocol: {protocol_id} in {layer} header")]
    UnsupportedProtocol {
        protocol_id: u8,
        layer: NetworkLayer,
    },

    /// CRC validation failed, indicating data corruption or context mismatch.
    #[error("CRC mismatch: expected 0x{expected:X}, got 0x{calculated:X} for {crc_type} CRC")]
    CrcMismatch {
        expected: u8,
        calculated: u8,
        crc_type: CrcType,
    },

    /// LSB encoding or decoding operation failed with specific values.
    #[error("Invalid LSB operation for field '{field}': {description}")]
    InvalidLsbOperation {
        field: Field,
        description: String, // Keep String for complex dynamic descriptions
    },

    /// A mandatory field was missing from a packet or header.
    #[error("Missing required field: {field} in {structure}")]
    MandatoryFieldMissing {
        field: Field,
        structure: StructureType,
    },

    /// A field contained an invalid or unexpected value.
    #[error("Invalid value for field '{field}' in {structure}: expected {expected}, got {got}")]
    InvalidFieldValue {
        field: Field,
        structure: StructureType,
        expected: u32, // Keep numeric values for debugging
        got: u32,
    },

    /// General, profile-specific parsing error.
    #[error("Profile-specific parsing error for profile 0x{profile_id:02X}: {description}")]
    ProfileSpecificParsingError {
        profile_id: u8,
        description: &'static str,
    },
}

/// Errors that can occur during ROHC packet building (construction).
///
/// These errors indicate issues that prevent the successful creation of a
/// ROHC packet from uncompressed headers or context information.
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum RohcBuildingError {
    /// Provided buffer was too small for the packet being built.
    /// (Less common in Rohcstar as builders typically return `Vec<u8>`).
    #[error("Buffer too small: needed {needed} bytes, have {available} for {context}")]
    BufferTooSmall {
        needed: usize,
        available: usize,
        context: ParseContext,
    },

    /// Context information insufficient to build the packet.
    #[error("Context insufficient for building packet: missing {field}")]
    ContextInsufficient { field: Field },

    /// Invalid value provided for a field during packet construction.
    #[error(
        "Invalid value for field '{field}' during packet building: {value} exceeds {max_bits}-bit limit"
    )]
    InvalidFieldValueForBuild {
        field: Field,
        value: u32,   // Keep actual problematic value
        max_bits: u8, // Keep bit limit for debugging
    },

    /// General, profile-specific building error.
    #[error("Profile-specific building error for profile 0x{profile_id:02X}: {description}")]
    ProfileSpecificBuildingError {
        profile_id: u8,
        description: &'static str,
    },
}

/// Errors that can occur during ROHC compression operations.
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum CompressionError {
    /// Context not found for the given CID.
    #[error("Context {cid} not found")]
    ContextNotFound { cid: ContextId },

    /// Context state insufficient for operation.
    #[error("Context {cid} insufficient: missing {field}")]
    ContextInsufficient { cid: ContextId, field: Field },

    /// Packet building failed during compression.
    #[error("Packet building failed: {0}")]
    BuildingFailed(#[from] RohcBuildingError),
}

/// Errors that can occur during ROHC decompression operations.
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum DecompressionError {
    /// Context not found for the given CID.
    #[error("Context {cid} not found")]
    ContextNotFound { cid: ContextId },

    /// CRC mismatch during decompression.
    #[error("CRC mismatch in context {cid}: expected {expected:#04x}, got {actual:#04x}")]
    CrcMismatch {
        cid: ContextId,
        expected: u8,
        actual: u8,
    },

    /// LSB decoding error during decompression.
    #[error("LSB decoding failed for {field} in context {cid}")]
    LsbDecodingFailed { cid: ContextId, field: Field },

    /// Packet type invalid for current state.
    #[error("Packet type {packet_type:#04x} invalid for context {cid}")]
    InvalidPacketType { cid: ContextId, packet_type: u8 },

    /// Packet parsing failed during decompression.
    #[error("Packet parsing failed: {0}")]
    ParsingFailed(#[from] RohcParsingError),

    /// CRC recovery failed because sequence number distance exceeded safe limits.
    #[error(
        "CRC recovery limit exceeded in context {cid}: expected SN{expected_sn}, recovered SN{recovered_sn} (distance {distance} > limit {limit})"
    )]
    CrcRecoveryLimitExceeded {
        cid: ContextId,
        expected_sn: u16,
        recovered_sn: u16,
        distance: u16,
        limit: u16,
    },
}

/// Errors that can occur during engine operations.
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum EngineError {
    /// Profile handler not registered.
    #[error("Profile handler for {profile:?} not registered")]
    ProfileHandlerNotRegistered { profile: RohcProfile },

    /// Profile handler already registered.
    #[error("Profile handler for {profile:?} already registered")]
    ProfileHandlerAlreadyRegistered { profile: RohcProfile },

    /// Compression operation failed.
    #[error("Compression failed: {0}")]
    CompressionFailed(#[from] CompressionError),

    /// Decompression operation failed.
    #[error("Decompression failed: {0}")]
    DecompressionFailed(#[from] DecompressionError),

    /// Packet loss detected - decompression failed due to expected network conditions.
    #[error("Packet lost - decompression failed due to expected network conditions")]
    PacketLoss { underlying_error: Box<RohcError> },

    /// Internal engine error.
    #[error("Internal engine error: {reason}")]
    Internal { reason: &'static str },
}

/// Main error type for ROHC operations in Rohcstar.
///
/// Top-level error type that consolidates all specific error categories.
/// Provides pattern matching capabilities and rich context information.
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum RohcError {
    /// Error during compression operations.
    #[error("Compression error: {0}")]
    Compression(#[from] CompressionError),

    /// Error during decompression operations.
    #[error("Decompression error: {0}")]
    Decompression(#[from] DecompressionError),

    /// Error during packet parsing.
    #[error("Parsing error: {0}")]
    Parsing(#[from] RohcParsingError),

    /// Error during packet building.
    #[error("Building error: {0}")]
    Building(#[from] RohcBuildingError),

    /// Error during engine operations.
    #[error("Engine error: {0}")]
    Engine(#[from] EngineError),

    /// Legacy support for existing code (temporary).
    // TODO: Refactor callsites to use EngineError::ContextNotFound and remove this variant.
    #[error("Context not found for CID: {0}")]
    ContextNotFound(u16),

    /// Legacy support for existing code (temporary).
    // TODO: Refactor callsites to use EngineError::ProfileHandlerNotRegistered and remove this variant.
    #[error("Unsupported ROHC profile: 0x{0:02X}")]
    UnsupportedProfile(u8),

    /// Legacy support for existing code (temporary).
    // TODO: Refactor callsites to use structured errors and remove this variant.
    #[error("Invalid state for operation: {0}")]
    InvalidState(String),

    /// Legacy support for existing code (temporary).
    // TODO: Refactor callsites to use structured errors and remove this variant.
    #[error("Internal logic error: {0}")]
    Internal(String),
}

impl RohcError {
    /// Returns true if this error is expected under packet loss conditions.
    ///
    /// These errors represent normal ROHC protocol behavior when packets are lost
    /// and should typically be handled gracefully by applications rather than
    /// treated as critical failures.
    pub fn is_expected_with_packet_loss(&self) -> bool {
        match self {
            // CRC mismatches are expected when packets are corrupted or lost
            RohcError::Parsing(RohcParsingError::CrcMismatch { .. }) => true,

            // LSB decoding failures occur when context is damaged by packet loss
            RohcError::Decompression(DecompressionError::LsbDecodingFailed { .. }) => true,

            // Engine internal errors for missing contexts with non-IR packets
            RohcError::Engine(EngineError::Internal { reason })
                if reason.contains("Cannot determine ROHC profile from non-IR packet") =>
            {
                true
            }

            // Context not found is expected when IR packets are lost
            RohcError::Decompression(DecompressionError::ContextNotFound { .. }) => true,

            // Invalid packet types are expected when packets are corrupted by packet loss
            RohcError::Decompression(DecompressionError::InvalidPacketType { .. }) => true,

            // Internal "packet discarded" messages from engine graceful degradation
            RohcError::Internal(reason)
                if reason.contains("Packet discarded due to expected packet loss") =>
            {
                true
            }

            // Internal "waiting for IR" messages when no fallback headers exist
            RohcError::Internal(reason)
                if reason.contains("No headers available yet - waiting for IR packet") =>
            {
                true
            }

            // All other errors are implementation issues or malformed packets
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn not_enough_data_error_display() {
        let err = RohcParsingError::NotEnoughData {
            needed: 10,
            got: 5,
            context: ParseContext::IrPacketCrcAndPayload,
        };
        assert_eq!(
            format!("{}", err),
            "Incomplete packet data: needed 10 bytes, got 5 for IR Packet (CRC field and defined payload)"
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
            crc_type: CrcType::TestCrc,
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
            context: ParseContext::RtpHeaderMin,
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
            field: Field::TsScaled,
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
            description: "Invalid SN encoding for UO-0",
        };
        assert_eq!(
            format!("{}", err),
            "Profile-specific parsing error for profile 0x01: Invalid SN encoding for UO-0"
        );
    }

    #[test]
    fn field_value_error_with_numbers() {
        let err = RohcParsingError::InvalidFieldValue {
            field: Field::RtpVersion,
            structure: StructureType::RtpHeader,
            expected: 2,
            got: 1,
        };
        assert_eq!(
            format!("{}", err),
            "Invalid value for field 'RTP Version' in RTP Header: expected 2, got 1"
        );
    }

    #[test]
    fn enum_display_implementations() {
        assert_eq!(
            format!("{}", ParseContext::RohcPacketInput),
            "ROHC packet input"
        );
        assert_eq!(format!("{}", Field::RtpVersion), "RTP Version");
        assert_eq!(format!("{}", StructureType::RtpHeader), "RTP Header");
        assert_eq!(format!("{}", NetworkLayer::Ip), "IP");
        assert_eq!(format!("{}", CrcType::Rohc8), "ROHC-CRC8");
    }
}
