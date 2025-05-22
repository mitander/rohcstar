//! `rohcstar`: A modern, memory-safe, and performant Rust implementation of the Robust Header Compression (ROHC) framework.
//!
//! This crate provides implementations for ROHC profiles, context management,
//! packet processing (parsing and building), and core ROHC logic like LSB encoding
//! and CRC calculation.
//!
//! The primary focus of the MVP is ROHC Profile 1 (RTP/UDP/IP) in Unidirectional mode.
//! It is currently being refactored towards an extensible, trait-based architecture
//! to support multiple ROHC profiles in the future.
//!
//! ## Key Modules:
//! - `traits`: Core behavioral traits for contexts and profile handlers.
//! - `packet_defs`: ROHC-specific packet type definitions, profile IDs, etc.
//! - `protocol_types`: Structs representing uncompressed network headers.
//! - `context`: Concrete context implementations (e.g., for Profile 1).
//! - `context_manager`: Management of ROHC contexts.
//! - `profiles`: Profile-specific logic handlers (e.g., `p1_handler`).
//! - `constants`: Core protocol constants.
//! - `crc`: ROHC-specific CRC calculation functions.
//! - `encodings`: LSB encoding and decoding utilities.
//! - `error`: Custom error types for ROHC operations.
//! - `packet_processor`: Low-level ROHC packet parsing/building utilities.
//! - `fuzz_harnesses`: Harness functions for fuzz testing.
//!
//! ## Example: Basic Profile 1 U-mode Compression and Decompression
//!
//! ```rust
//! use rohcstar::{
//!     // Uncompressed header type
//!     protocol_types::RtpUdpIpv4Headers,
//!     // Context traits and Profile 1 handler
//!     traits::{ProfileHandler, RohcCompressorContext, RohcDecompressorContext},
//!     profiles::p1_handler::Profile1Handler,
//!     // Generic wrapper for headers
//!     packet_defs::GenericUncompressedHeaders,
//!     // Top-level error
//!     error::RohcError,
//! };
//! use std::net::Ipv4Addr;
//!
//! fn main() -> Result<(), RohcError> {
//!     // 0. Create a handler for Profile 1
//!     let p1_handler = Profile1Handler::new();
//!
//!     // 1. Create initial uncompressed headers
//!     let original_headers = RtpUdpIpv4Headers {
//!         ip_src: "192.168.1.10".parse().unwrap(),
//!         ip_dst: "192.168.1.20".parse().unwrap(),
//!         udp_src_port: 12345,
//!         udp_dst_port: 54321,
//!         rtp_ssrc: 0x11223344,
//!         rtp_sequence_number: 100,
//!         rtp_timestamp: 1000,
//!         rtp_marker: false,
//!         ..Default::default()
//!     };
//!     let generic_original_headers = GenericUncompressedHeaders::RtpUdpIpv4(original_headers.clone());
//!
//!     // 2. Initialize compressor and decompressor contexts (CID 0) via the handler
//!     let cid = 0u16;
//!     let ir_refresh_interval = 20;
//!     let mut compressor_context_dyn = p1_handler.create_compressor_context(cid, ir_refresh_interval);
//!     let mut decompressor_context_dyn = p1_handler.create_decompressor_context(cid);
//!     // The handler's create methods should set the CID within the concrete context.
//!     // If a central engine were managing CIDs from Add-CID octets, it would call:
//!     // decompressor_context_dyn.set_cid(cid_from_packet_or_flow);
//!
//!     // 3. Compress the headers (first packet will be an IR packet)
//!     let compressed_packet_ir = p1_handler.compress(
//!         compressor_context_dyn.as_mut(), // Get &mut dyn RohcCompressorContext
//!         &generic_original_headers
//!     )?;
//!     println!("Sent IR packet ({} bytes)", compressed_packet_ir.len());
//!
//!     // 4. Decompress the IR packet
//!     // For CID 0, the IR packet bytes are the core bytes.
//!     // If CID > 0, build_ir_profile1_packet would prepend Add-CID. The engine would strip it.
//!     // Here, we assume CID 0 for simplicity for the decompress call.
//!     let decompressed_generic_ir = p1_handler.decompress(
//!         decompressor_context_dyn.as_mut(), // Get &mut dyn RohcDecompressorContext
//!         &compressed_packet_ir
//!     )?;
//!     let decompressed_headers_ir = match decompressed_generic_ir {
//!         GenericUncompressedHeaders::RtpUdpIpv4(h) => h,
//!         // _ => return Err(RohcError::Internal("Unexpected header type from IR decompression".into())),
//!     };
//!
//!     assert_eq!(decompressed_headers_ir.rtp_sequence_number, original_headers.rtp_sequence_number);
//!     assert_eq!(decompressed_headers_ir.rtp_ssrc, original_headers.rtp_ssrc);
//!     println!("Decompressed IR packet successfully.");
//!
//!     // 5. Create a subsequent packet (e.g., SN increment)
//!     let mut next_headers_uncomp = original_headers.clone();
//!     next_headers_uncomp.rtp_sequence_number += 1;
//!     next_headers_uncomp.rtp_timestamp += 160;
//!     let generic_next_headers = GenericUncompressedHeaders::RtpUdpIpv4(next_headers_uncomp.clone());
//!
//!     // 6. Compress the subsequent packet (should be a UO packet)
//!     let compressed_packet_uo = p1_handler.compress(
//!         compressor_context_dyn.as_mut(),
//!         &generic_next_headers
//!     )?;
//!     println!("Sent UO packet ({} bytes)", compressed_packet_uo.len());
//!
//!     // 7. Decompress the UO packet
//!     let decompressed_generic_uo = p1_handler.decompress(
//!         decompressor_context_dyn.as_mut(),
//!         &compressed_packet_uo
//!     )?;
//!     let decompressed_headers_uo = match decompressed_generic_uo {
//!         GenericUncompressedHeaders::RtpUdpIpv4(h) => h,
//!         // _ => return Err(RohcError::Internal("Unexpected header type from UO decompression".into())),
//!     };
//!
//!     assert_eq!(decompressed_headers_uo.rtp_sequence_number, next_headers_uncomp.rtp_sequence_number);
//!     println!("Decompressed UO packet successfully.");
//!
//!     Ok(())
//! }
//! ```

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

// Fuzzing related, potentially feature-gated in the future
pub mod fuzz_harnesses;

// --- Commonly used public types and functions re-exported for convenience ---

// Traits
pub use traits::{ProfileHandler, RohcCompressorContext, RohcDecompressorContext};

// Contexts and Manager
pub use context::{
    CompressorMode,
    DecompressorMode,
    // Re-export concrete P1 contexts if users might need to downcast or create them directly
    RtpUdpIpP1CompressorContext,
    RtpUdpIpP1DecompressorContext,
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

// Specific Profile Handlers (if users are expected to instantiate them)
pub use profiles::p1_handler::Profile1Handler;

// Note: The direct compress/decompress functions for P1 are no longer top-level re-exports
// as they are now methods of Profile1Handler.
// Users would instantiate a handler and call methods on it.
