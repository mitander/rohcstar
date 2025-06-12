//! Profile 1 packet serialization modules.
//!
//! Contains specialized serialization and deserialization functions for each Profile 1 packet type.

pub mod headers;
pub mod ir_packets;
pub mod uo0_packets;
pub mod uo1_packets;

pub use self::ir_packets::serialize_ir;
