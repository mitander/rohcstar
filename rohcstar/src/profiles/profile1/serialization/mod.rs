//! Profile 1 packet serialization modules.
//!
//! Contains specialized serialization functions for each Profile 1 packet type.

pub mod ir_packets;
pub mod uo0_packets;
pub mod uo1_packets;

pub use ir_packets::{deserialize_ir, serialize_ir};
pub use uo0_packets::{deserialize_uo0, serialize_uo0};
pub use uo1_packets::{
    deserialize_uo1_id, deserialize_uo1_rtp, deserialize_uo1_sn, deserialize_uo1_ts,
    serialize_uo1_id, serialize_uo1_rtp, serialize_uo1_sn, serialize_uo1_ts,
};
