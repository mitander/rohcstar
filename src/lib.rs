//! `rohcstar`: A modern and memory-safe ROHC (Robust Header Compression) implementation in Rust.
//!
//! This library provides a framework for ROHC compression and decompression,
//! with an extensible architecture allowing for the addition of various ROHC profiles.
//! The primary entry point for using the library is the `RohcEngine`.
//!
//! ## Core Concepts
//!
//! - **`RohcEngine`**: The central orchestrator for compression and decompression.
//!   You register profile handlers with the engine and then use it to process packets.
//! - **Profiles**: Implementations for specific ROHC standards (e.g., Profile 1 for RTP/UDP/IP).
//!   Each profile is managed by a `ProfileHandler`.
//! - **Contexts**: State maintained for each compression or decompression flow (CID).
//!   Managed internally by the `RohcEngine` and `ContextManager`.

pub mod constants;
pub mod context_manager;
pub mod crc;
pub mod encodings;
pub mod engine;
pub mod error;
pub mod packet_defs;
pub mod profiles;
pub mod traits;

pub use engine::RohcEngine;
pub use error::{RohcBuildingError, RohcError, RohcParsingError};
pub use packet_defs::{GenericUncompressedHeaders, RohcProfile};
pub use traits::{ProfileHandler, RohcCompressorContext, RohcDecompressorContext};
pub mod fuzz_harnesses;
