use thiserror::Error;

/// Errors that can occur during the parsing of ROHC packets or uncompressed headers.
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum RohcParsingError {
    /// Indicates that the provided data buffer is too short to parse an expected field or structure.
    #[error("Incomplete packet data: needed at least {needed} bytes, but only got {got}")]
    NotEnoughData {
        /// The minimum number of bytes required for the operation.
        needed: usize,
        /// The actual number of bytes available.
        got: usize,
    },
    /// An invalid or unsupported ROHC profile identifier was encountered.
    #[error("Invalid ROHC profile ID: 0x{0:02X}")]
    InvalidProfileId(u8),
    /// An unrecognized or malformed ROHC packet type discriminator was found.
    #[error("Invalid ROHC packet type discriminator: 0x{0:02X}")]
    InvalidPacketType(u8),
    /// An IP version other than 4 was encountered when IPv4 was expected.
    #[error("Invalid IP version: expected 4, got {0}")]
    InvalidIpVersion(u8),
    /// A protocol was encountered (e.g., in an IP header) that is not supported by the current parser.
    #[error("Unsupported protocol for parsing: {0}")]
    UnsupportedProtocol(u8),
    /// A CRC check failed, indicating potential data corruption or misinterpretation.
    #[error("CRC mismatch: expected 0x{expected:02X}, calculated 0x{calculated:02X}")]
    CrcMismatch {
        /// The CRC value read from the packet.
        expected: u8,
        /// The CRC value calculated from the packet data.
        calculated: u8,
    },
    /// An error occurred during LSB (Least Significant Bits) decoding or encoding.
    #[error("Invalid LSB encoding for {field_name}: {description}")]
    InvalidLsbEncoding {
        /// Name of the field being processed.
        field_name: String,
        /// Specific reason for the LSB encoding failure.
        description: String,
    },
    /// A field that is mandatory for the current packet type or operation was missing.
    #[error("Mandatory field missing: {field_name}")]
    MandatoryFieldMissing {
        /// Name of the missing field.
        field_name: String,
    },
    /// A field contained an invalid or unexpected value.
    #[error("Invalid value for field '{field_name}': {description}")]
    InvalidFieldValue {
        /// Name of the field with the invalid value.
        field_name: String,
        /// Description of why the value is invalid.
        description: String,
    },
}

/// Errors that can occur during the construction (building) of ROHC packets.
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum RohcBuildingError {
    /// The provided buffer is too small to hold the ROHC packet being built.
    #[error(
        "Buffer too small to build packet: needed {needed} bytes, but only {available} available"
    )]
    BufferTooSmall {
        /// The minimum number of bytes required for the packet.
        needed: usize,
        /// The number of bytes available in the buffer.
        available: usize,
    },
    /// The ROHC context lacks sufficient information to build the requested packet type.
    /// For example, trying to build a UO packet without a fully established context.
    #[error("Context insufficient to build packet: {0}")]
    ContextInsufficient(String),
    /// A field value provided for building the packet is invalid or out of range.
    #[error("Invalid value for building field '{field_name}': {description}")]
    InvalidFieldValueForBuild {
        /// Name of the field with the invalid value.
        field_name: String,
        /// Description of why the value is invalid for building.
        description: String,
    },
}

/// General ROHC operational errors, encompassing parsing, building, context, and state issues.
/// This is the primary error type returned by most public Rohcstar functions.
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum RohcError {
    /// An error occurred during packet parsing.
    #[error("Parsing error: {0}")]
    Parsing(#[from] RohcParsingError),
    /// An error occurred during packet building.
    #[error("Building error: {0}")]
    Building(#[from] RohcBuildingError),
    /// The ROHC context for the specified Context ID (CID) was not found.
    #[error("Context not found for CID: {0}")]
    ContextNotFound(u16),
    /// An error occurred during a context management operation.
    #[error("Context operation failed: {0}")]
    ContextError(String),
    /// An operation was attempted that is not valid for the current ROHC state machine state.
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
