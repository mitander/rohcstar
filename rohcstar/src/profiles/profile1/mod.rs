//! ROHC (Robust Header Compression) Profile 1 (RTP/UDP/IP) implementation.
//!
//! This module and its submodules contain all the specific logic, data structures,
//! and constants required to implement ROHC Profile 1 as defined in RFC 3095
//! for compressing RTP/UDP/IPv4 headers.
//!
//! Key components:
//! - `handler`: Implements the `ProfileHandler` trait for Profile 1.
//! - `compressor`: Contains functions for Profile 1 compression decisions and packet building.
//! - `decompressor`: Contains functions for Profile 1 ROHC packet parsing and header reconstruction.
//! - `state_machine`: Handles decompressor state transitions for Profile 1.
//! - `context`: Defines `Profile1CompressorContext` and `Profile1DecompressorContext`.
//! - `discriminator`: Defines `Profile1PacketType` for structured packet type identification.
//! - `serialization`: Focused packet serialization modules (IR, UO-0, UO-1 variants).
//! - `packet_types`: Defines Profile 1 specific ROHC packet representations (IR, UO-0, UO-1).
//! - `protocol_types`: Defines `RtpUdpIpv4Headers`.
//! - `constants`: Holds constants specific to Profile 1 operations.

mod compressor;
pub mod constants;
pub mod context;
mod decompressor;
pub mod discriminator;
pub mod handler;
mod packet_builder;
pub mod packet_types;
pub mod protocol_types;
mod serialization;
mod state_machine;
mod state_transitions;
mod state_types;

pub use self::constants::*;
pub use self::context::{Profile1CompressorContext, Profile1DecompressorContext};
pub use self::discriminator::Profile1PacketType;
pub use self::handler::Profile1Handler;
pub use self::packet_types::{IrPacket, Uo0Packet, Uo1Packet};
pub use self::protocol_types::RtpUdpIpv4Headers;
pub use self::serialization::ir_packets::serialize_ir;
