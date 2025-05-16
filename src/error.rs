use thiserror::Error;

#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum RohcParsingError {
    #[error("Incomplete packet data: needed {needed}, got {got}")]
    NotEnoughData { needed: usize, got: usize },
    #[error("Invalid ROHC profile ID: {0}")]
    InvalidProfileId(u8),
    #[error("Invalid ROHC packet type discriminator: {0}")]
    InvalidPacketType(u8),
    #[error("Invalid IP version: {0}")]
    InvalidIpVersion(u8),
    #[error("Unsupported protocol for parsing: {0}")]
    UnsupportedProtocol(u8),
    #[error("CRC mismatch: expected {expected:x}, calculated {calculated:x}")]
    CrcMismatch { expected: u8, calculated: u8 },
    #[error("Invalid LSB encoding for field {field_name}")]
    InvalidLsbEncoding { field_name: String },
    #[error("Mandatory field missing: {field_name}")]
    MandatoryFieldMissing { field_name: String },
    #[error("Invalid field value for {field_name}: {description}")]
    InvalidFieldValue {
        field_name: String,
        description: String,
    },
}

#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum RohcBuildingError {
    #[error("Buffer too small to build packet: needed {needed}, got {available}")]
    BufferTooSmall { needed: usize, available: usize },
    #[error("Context insufficient to build packet: {0}")]
    ContextInsufficient(String),
    #[error("Invalid field value for building {field_name}: {description}")]
    InvalidFieldValueForBuild {
        field_name: String,
        description: String,
    },
}

#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum RohcError {
    #[error("Parsing error: {0}")]
    Parsing(#[from] RohcParsingError),
    #[error("Building error: {0}")]
    Building(#[from] RohcBuildingError),
    #[error("Context not found for CID: {0}")]
    ContextNotFound(u16),
    #[error("Context operation failed: {0}")]
    ContextError(String),
    #[error("Invalid state transition: {0}")]
    InvalidState(String),
    #[error("Unsupported ROHC profile: {0}")]
    UnsupportedProfile(u8),
    #[error("Operation not supported in current mode: {0}")]
    ModeNotSupported(String),
    #[error("Internal logic error: {0}")]
    Internal(String),
}
