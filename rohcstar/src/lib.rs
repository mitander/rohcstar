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
//! use rohcstar::{RohcEngine, RohcProfile};
//! use rohcstar::profiles::profile1::handler::Profile1Handler;
//! use rohcstar::time::SystemClock;
//! use rohcstar::packet_defs::GenericUncompressedHeaders;
//! use std::sync::Arc;
//! use std::time::Duration;
//!
//! // Create a ROHC engine
//! let mut engine = RohcEngine::new(
//!     20,                              // IR refresh interval
//!     Duration::from_secs(300),        // Context timeout
//!     Arc::new(SystemClock),           // Clock implementation
//! );
//!
//! // Register Profile 1 handler for RTP/UDP/IP compression
//! let profile1_handler = Box::new(Profile1Handler::new());
//! engine.register_profile_handler(profile1_handler).unwrap();
//!
//! // Compress packets (example with actual headers)
//! # /*
//! let headers = GenericUncompressedHeaders::RtpUdpIpv4(rtp_udp_ip_headers);
//! let compressed_packet = engine.compress(
//!     0,                                    // Context ID
//!     Some(RohcProfile::RtpUdpIp),         // Profile hint for new contexts
//!     &headers,
//! )?;
//!
//! // Decompress packets
//! let decompressed_headers = engine.decompress(&compressed_packet)?;
//! # */
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
