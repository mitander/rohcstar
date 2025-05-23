//! `rohcstar`: A modern and memory-safe ROHC (Robust Header Compression) implementation in Rust.
//!
//! Implements ROHC Profile 1 (RTP/UDP/IP) in Unidirectional mode with an extensible
//! architecture for future profile support. This implementation focuses on:
//! - Memory safety without compromising performance
//! - Clear separation of concerns between compression profiles
//! - Extensibility for additional ROHC profiles
//!
//! ## Core Components
//! - `traits`: Core interfaces for ROHC operations
//! - `context`: Compressor/decompressor state management
//! - `profiles`: Profile-specific implementations (currently Profile 1)
//! - `packet_processor`: Low-level packet parsing and building

// Core modules
pub mod constants;
pub mod context;
pub mod context_manager;
pub mod crc;
pub mod encodings;
pub mod error;
pub mod packet_defs;
pub mod packet_processor;
pub mod profiles;
pub mod protocol_types;
pub mod traits;

// Fuzzing related
pub mod fuzz_harnesses;

// Traits
pub use traits::{ProfileHandler, RohcCompressorContext, RohcDecompressorContext};

// Contexts and Manager
pub use context::{
    CompressorMode, DecompressorMode, RtpUdpIpP1CompressorContext, RtpUdpIpP1DecompressorContext,
};
pub use context_manager::SimpleContextManager;

// Enums and Definitions
pub use packet_defs::{GenericUncompressedHeaders, RohcPacketDiscriminator, RohcProfile};
// Re-export specific ROHC packet data structs if they are part of public API for certain profiles
pub use packet_defs::{RohcIrProfile1Packet, RohcUo0PacketProfile1, RohcUo1PacketProfile1};

// Uncompressed Header Types
pub use protocol_types::RtpUdpIpv4Headers;

// Top-level Error
pub use error::RohcError;

// Specific Profile Handlers
pub use profiles::p1_handler::Profile1Handler;
