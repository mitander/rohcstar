//! ROHC (Robust Header Compression) Profile 1 (RTP/UDP/IP) implementation.
//!
//! This module and its submodules contain all the specific logic, data structures,
//! and constants required to implement ROHC Profile 1 as defined in RFC 3095
//! for compressing RTP/UDP/IPv4 headers.
//!
//! Key components:
//! - `handler`: Implements the `ProfileHandler` trait for Profile 1.
//! - `context`: Defines `Profile1CompressorContext` and `Profile1DecompressorContext`.
//! - `protocol_types`: Defines `RtpUdpIpv4Headers`.
//! - `packet_types`: Defines Profile 1 specific ROHC packet representations (IR, UO-0, UO-1).
//! - `packet_processor`: Contains functions for parsing and building Profile 1 ROHC packets.
//! - `constants`: Holds constants specific to Profile 1 operations.

pub mod constants;
pub mod context;
pub mod handler;
pub mod packet_processor;
pub mod packet_types;
pub mod protocol_types;

pub use self::constants::*;
pub use self::context::{Profile1CompressorContext, Profile1DecompressorContext};
pub use self::handler::Profile1Handler;
pub use self::packet_types::{IrPacket, Uo0Packet, Uo1Packet};
pub use self::protocol_types::RtpUdpIpv4Headers;
