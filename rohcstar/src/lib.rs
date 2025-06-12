//! `rohcstar`: A modern and memory-safe ROHC (Robust Header Compression) implementation in Rust.
//!
//! This library provides a framework for ROHC compression and decompression,
//! with an extensible architecture allowing for the addition of various ROHC profiles.
//! The primary entry point for using the library is the [`RohcEngine`].
//!
//! ## Core Concepts
//!
//! - **[`RohcEngine`]**: The central orchestrator for compression and decompression.
//!   You register profile handlers with the engine and then use it to process packets.
//! - **Profiles**: Implementations for specific ROHC standards (e.g., Profile 1 for RTP/UDP/IP).
//!   Each profile is managed by a [`ProfileHandler`].
//! - **Contexts**: State maintained for each compression or decompression flow (CID).
//!   Managed internally by the [`RohcEngine`] and [`ContextManager`].
//!
//! ## Quick Start
//!
//! ```rust
//! use rohcstar::packet_defs::GenericUncompressedHeaders;
//! use rohcstar::profiles::profile1::{Profile1Handler, RtpUdpIpv4Headers};
//! use rohcstar::time::SystemClock;
//! use rohcstar::{EngineError, RohcEngine, RohcProfile};
//! use std::sync::Arc;
//! use std::time::Duration;
//!
//! fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Create a ROHC engine
//!     let mut engine = RohcEngine::new(
//!         20,                       // IR refresh interval
//!         Duration::from_secs(300), // Context timeout
//!         Arc::new(SystemClock),    // Clock implementation
//!     );
//!
//!     // Register Profile 1 handler for RTP/UDP/IP compression
//!     engine.register_profile_handler(Box::new(Profile1Handler::new()))?;
//!
//!     // Create headers to compress
//!     let headers = RtpUdpIpv4Headers {
//!         ip_src: "192.168.1.10".parse().unwrap(),
//!         ip_dst: "192.168.1.20".parse().unwrap(),
//!         udp_src_port: 10010,
//!         udp_dst_port: 20020,
//!         rtp_ssrc: 0x12345678.into(),
//!         rtp_sequence_number: 100.into(),
//!         rtp_timestamp: 1000.into(),
//!         ..Default::default()
//!     };
//!     let generic_headers = GenericUncompressedHeaders::RtpUdpIpv4(headers);
//!
//!     // Compress packet
//!     let mut compressed_buf = [0u8; 128];
//!     let compressed_len = engine.compress(
//!         0.into(),                    // Context ID
//!         Some(RohcProfile::RtpUdpIp), // Profile hint
//!         &generic_headers,
//!         &mut compressed_buf,
//!     )?;
//!     let compressed_packet = &compressed_buf[..compressed_len];
//!     println!("Compressed packet: {} bytes", compressed_len);
//!
//!     // Decompress packet - graceful packet loss handling
//!     match engine.decompress(compressed_packet) {
//!         Ok(decompressed_headers) => {
//!             println!("Decompressed headers: {:#?}", decompressed_headers);
//!         }
//!         Err(rohcstar::RohcError::Engine(EngineError::PacketLoss { .. })) => {
//!             todo!("handle packet loss")
//!         }
//!         Err(e) => {
//!             panic!("failed to decompress: {e} ");
//!         }
//!     }
//!
//!     Ok(())
//! }
//! ```
//!
//! ## Supported Profiles
//!
//! - **Profile 1 (RTP/UDP/IP)**: Complete implementation supporting IR, UO-0, UO-1, and UOR-2 packets
//! - Additional profiles can be implemented by creating custom [`ProfileHandler`]s
//!
//! [`ContextManager`]: crate::context_manager::ContextManager

pub mod constants;
pub mod context_manager;
pub mod crc;
pub mod encodings;
pub mod engine;
pub mod error;
pub mod packet_defs;
pub mod profiles;
pub mod serialization;
pub mod time;
pub mod traits;
pub mod types;

pub use engine::RohcEngine;
pub use error::{
    CompressionError, CrcType, DecompressionError, EngineError, Field, NetworkLayer, ParseContext,
    RohcBuildingError, RohcError, RohcParsingError, StructureType,
};
pub use packet_defs::{GenericUncompressedHeaders, RohcProfile};
pub use traits::{ProfileHandler, RohcCompressorContext, RohcDecompressorContext};
pub mod fuzz_harnesses;
pub use time::mock_clock::MockClock;
