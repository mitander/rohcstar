//! Production-ready ROHC implementation with comprehensive Profile 1 support.
//!
//! **Philosophy:** Correctness, performance, and simplicity. RFC-compliant implementation
//! with zero-allocation packet processing and deterministic behavior.
//!
//! **Core Components:**
//! - [`RohcEngine`]: Main API for compression and decompression
//! - Profile handlers: Extensible implementations for ROHC profiles
//! - Context management: Automatic state tracking per CID
//!
//! ## Usage
//!
//! ```rust
//! use std::sync::Arc;
//! use std::time::Duration;
//!
//! use rohcstar::packet_defs::GenericUncompressedHeaders;
//! use rohcstar::profiles::profile1::Profile1Handler;
//! use rohcstar::protocol_types::RtpUdpIpv4Headers;
//! use rohcstar::time::SystemClock;
//! use rohcstar::{RohcEngine, RohcProfile};
//!
//! fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let mut engine = RohcEngine::new(20, Duration::from_secs(300), Arc::new(SystemClock));
//!     engine.register_profile_handler(Box::new(Profile1Handler::new()))?;
//!
//!     let headers = RtpUdpIpv4Headers {
//!         ip_src: "192.168.1.10".parse()?,
//!         ip_dst: "192.168.1.20".parse()?,
//!         udp_src_port: 5004,
//!         udp_dst_port: 5006,
//!         rtp_ssrc: 0x12345678.into(),
//!         rtp_sequence_number: 100.into(),
//!         rtp_timestamp: 8000.into(),
//!         ..Default::default()
//!     };
//!
//!     let mut buf = [0u8; 128];
//!     let len = engine.compress(
//!         0.into(),
//!         Some(RohcProfile::RtpUdpIp),
//!         &GenericUncompressedHeaders::RtpUdpIpv4(headers),
//!         &mut buf,
//!     )?;
//!
//!     let decompressed = engine.decompress(&buf[..len])?;
//!     println!("Roundtrip successful: {} -> {} bytes", 28, len);
//!     Ok(())
//! }
//! ```
//!
//! ## Profiles
//!
//! - **Profile 1 (RTP/UDP/IP)**: Complete U-mode implementation
//! - Additional profiles: Implement [`ProfileHandler`]

pub mod constants;
pub mod context_manager;
pub mod crc;
pub mod encodings;
pub mod engine;
pub mod error;
pub mod packet_defs;
pub mod profiles;
pub mod protocol_types;
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

#[cfg(test)]
mod tidy;
