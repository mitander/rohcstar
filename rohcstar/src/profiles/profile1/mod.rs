//! ROHC (Robust Header Compression) Profile 1 (RTP/UDP/IP) implementation.
//!
//! This module and its submodules contain all the specific logic, data structures,
//! and constants required to implement ROHC Profile 1 as defined in RFC 3095
//! for compressing RTP/UDP/IPv4 headers.
//!
//! Key components:
//! - `handler`: Implements the `ProfileHandler` trait for Profile 1.
//! - `compression`: Contains focused compression modules for Profile 1 packet building and
//!   compression decisions.
//! - `decompression`: Contains focused decompression modules for Profile 1 packet parsing and
//!   header reconstruction.
//! - `state_machine`: Handles decompressor state transitions for Profile 1.
//! - `context`: Defines `Profile1CompressorContext` and `Profile1DecompressorContext`.
//! - `discriminator`: Defines `Profile1PacketType` for structured packet type identification.
//! - `serialization`: Focused packet serialization modules (IR, UO-0, UO-1 variants).
//! - `packet_types`: Defines Profile 1 specific ROHC packet representations (IR, UO-0, UO-1).
//! - Re-exports `RtpUdpIpv4Headers` from `protocol_types` for convenience.
//! - `constants`: Holds constants specific to Profile 1 operations.

mod compression;
pub mod constants;
pub mod context;
pub mod decompression;

pub mod discriminator;
pub mod handler;
pub mod packet_types;

pub mod serialization;
mod state_machine;
mod state_transitions;
mod state_types;

pub use self::constants::*;
pub use self::context::{Profile1CompressorContext, Profile1DecompressorContext};
pub use self::discriminator::Profile1PacketType;
pub use self::handler::Profile1Handler;
pub use self::packet_types::{IrPacket, Uo0Packet, Uo1Packet};
pub use self::serialization::ir_packets::serialize_ir;
pub use crate::protocol_types::RtpUdpIpv4Headers;
