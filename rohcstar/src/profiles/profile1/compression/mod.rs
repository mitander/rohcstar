//! Profile 1 compression logic.
//!
//! This module contains functions for making compression decisions and building
//! ROHC Profile 1 packets. It implements the core compression algorithms for
//! RTP/UDP/IPv4 header compression as defined in RFC 3095.

use crate::types::Timestamp;

use super::context::Profile1CompressorContext;

mod ir_compression;
mod uo_compression;

pub(super) use ir_compression::{compress_as_ir, should_force_ir};
pub(super) use uo_compression::compress_as_uo;

/// Calculates minimum wrapping distance between two 16-bit values.
///
/// Computes the minimum distance considering both forward and backward
/// wrapping for 16-bit values. This is used for LSB window calculations.
pub(super) fn min_wrapping_distance_u16<T, U>(a: T, b: U) -> u16
where
    T: Into<u16>,
    U: Into<u16>,
{
    let a_val = a.into();
    let b_val = b.into();
    let forward = a_val.wrapping_sub(b_val);
    let backward = b_val.wrapping_sub(a_val);
    forward.min(backward)
}

/// Calculates minimum wrapping distance between two 32-bit values.
///
/// Computes the minimum distance considering both forward and backward
/// wrapping for 32-bit values. This is used for LSB window calculations.
pub(super) fn min_wrapping_distance_u32<T, U>(a: T, b: U) -> u32
where
    T: Into<u32>,
    U: Into<u32>,
{
    let a_val = a.into();
    let b_val = b.into();
    let forward = a_val.wrapping_sub(b_val);
    let backward = b_val.wrapping_sub(a_val);
    forward.min(backward)
}

/// Computes implicit timestamp based on sequence number delta and stride.
///
/// Calculates the expected timestamp value based on the sequence number
/// change and the established or potential timestamp stride. This is used
/// for UO-1-SN packets where the timestamp follows a predictable pattern.
pub(super) fn compute_implicit_ts(
    context: &Profile1CompressorContext,
    sn_delta: u16,
) -> Option<Timestamp> {
    // Use established stride first, then potential stride for early UO-1-SN usage
    // This allows UO-1-SN during stride detection while maintaining sync
    let stride = context.ts_stride.or(context.potential_ts_stride)?;

    if sn_delta > 0 {
        Some(
            context
                .last_sent_rtp_ts_full
                .value()
                .wrapping_add(sn_delta as u32 * stride)
                .into(),
        )
    } else {
        None
    }
}
