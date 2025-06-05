//! ROHC Profile 1 compression logic for RTP/UDP/IP packets.
//!
//! This module implements the compression-side packet processing for ROHC Profile 1,
//! determining optimal packet types (IR, UO-0, UO-1 variants) based on header field
//! changes and context state. The compressor aims to minimize packet size while
//! maintaining decompressor synchronization through strategic IR packet transmission
//! and careful LSB encoding window management.
//!
//! Key responsibilities:
//! - Packet type selection based on field changes and encoding constraints.
//! - IR packet generation for initialization and resynchronization.
//! - UO packet generation with appropriate field encodings.
//! - Context state updates after successful compression.

use super::constants::*;
use super::context::{Profile1CompressorContext, Profile1CompressorMode};
use super::packet_processor::{
    prepare_generic_uo_crc_input_payload, prepare_uo1_id_specific_crc_input_payload, serialize_ir,
    serialize_uo0, serialize_uo1_id, serialize_uo1_rtp, serialize_uo1_sn, serialize_uo1_ts,
};
use super::packet_types::{IrPacket, Uo0Packet, Uo1Packet};
use super::protocol_types::RtpUdpIpv4Headers;

use crate::crc::CrcCalculators;
use crate::encodings::encode_lsb;
use crate::error::RohcError;
use crate::packet_defs::RohcProfile;
use crate::types::{IpId, SequenceNumber, Timestamp};

/// Determines if an IR packet must be sent by the compressor.
///
/// IR packets are forced when the compressor needs to reset state, for periodic
/// refresh, or when field changes would exceed LSB encoding capabilities,
/// risking decompressor desynchronization.
///
/// # Parameters
/// - `context`: Current compressor context containing state and configuration.
/// - `headers`: Headers from the packet being compressed.
///
/// # Returns
/// `true` if an IR packet must be sent, `false` if other UO packet types can be considered.
pub(super) fn should_force_ir(
    context: &Profile1CompressorContext,
    headers: &RtpUdpIpv4Headers,
) -> bool {
    debug_assert_ne!(
        context.rtp_ssrc, 0,
        "SSRC must be initialized before checking IR conditions"
    );

    if context.mode == Profile1CompressorMode::InitializationAndRefresh {
        return true;
    }

    // Periodic refresh prevents long-term desynchronization due to undetected errors.
    if context.ir_refresh_interval > 0
        && context.fo_packets_sent_since_ir >= context.ir_refresh_interval.saturating_sub(1)
    {
        return true;
    }

    // SSRC change requires new context
    if context.rtp_ssrc != headers.rtp_ssrc {
        return true;
    }

    if context.ts_scaled_mode {
        if context.ts_stride.is_none() {
            // TS_SCALED requires known stride
            return true;
        }
        if context.calculate_ts_scaled(headers.rtp_timestamp).is_none() {
            // TS not aligned with stride or would overflow
            return true;
        }
    }

    // Check if field deltas exceed LSB encoding windows
    is_lsb_window_exceeded(context, headers)
}

/// Prepares and builds an IR (Initialization/Refresh) packet.
///
/// Handles TS stride signaling for TS_SCALED mode and updates compressor
/// state after successful IR packet generation. Assumes SSRC validation
/// has been performed by the caller.
///
/// # Parameters
/// - `context`: Mutable compressor context to update after IR generation.
/// - `headers`: Headers from the current packet to include in the IR packet.
/// - `crc_calculators`: CRC calculator instances for packet integrity checks.
///
/// # Returns
/// The compressed IR packet data as a byte vector.
///
/// # Errors
/// - [`RohcError::Building`] - IR packet construction failed
/// - [`RohcError::Internal`] - Internal logic error
pub(super) fn compress_as_ir(
    context: &mut Profile1CompressorContext,
    headers: &RtpUdpIpv4Headers,
    crc_calculators: &CrcCalculators,
) -> Result<Vec<u8>, RohcError> {
    debug_assert_eq!(
        context.rtp_ssrc, headers.rtp_ssrc,
        "SSRC mismatch in compress_as_ir; context should have been initialized or SSRC change handled."
    );

    let previous_ts_before_ir = context.last_sent_rtp_ts_full;

    // Reset scaled mode if calculation failures or missing stride
    let scaled_mode_failed = context.ts_scaled_mode
        && (context.ts_stride.is_none()
            || context.calculate_ts_scaled(headers.rtp_timestamp).is_none());

    let stride_to_signal = if scaled_mode_failed {
        context.ts_scaled_mode = false;
        context.ts_stride = None;
        context.ts_offset = Timestamp::default();
        context.ts_stride_packets = 0;
        None
    } else if context.ts_scaled_mode {
        context.ts_stride
    } else if context.ts_stride.is_some()
        && context.ts_stride_packets >= P1_TS_STRIDE_ESTABLISHMENT_THRESHOLD
    {
        // Stride established, signal for future use
        context.ts_stride
    } else {
        None
    };

    let ir_data = IrPacket {
        cid: context.cid,
        profile_id: RohcProfile::RtpUdpIp,
        crc8: 0, // Calculated by build_profile1_ir_packet
        static_ip_src: context.ip_source,
        static_ip_dst: context.ip_destination,
        static_udp_src_port: context.udp_source_port,
        static_udp_dst_port: context.udp_destination_port,
        static_rtp_ssrc: context.rtp_ssrc,
        dyn_rtp_sn: headers.rtp_sequence_number,
        dyn_rtp_timestamp: headers.rtp_timestamp,
        dyn_rtp_marker: headers.rtp_marker,
        ts_stride: stride_to_signal,
    };

    let packet = serialize_ir(&ir_data, crc_calculators).map_err(RohcError::Building)?;

    // Perform stride detection BEFORE updating context state to avoid race condition
    if scaled_mode_failed {
        // Resume stride detection using TS before IR, as IR TS may not be part of regular sequence
        let old_ts = context.last_sent_rtp_ts_full;
        context.last_sent_rtp_ts_full = previous_ts_before_ir;
        context.detect_ts_stride(headers.rtp_timestamp);
        context.last_sent_rtp_ts_full = old_ts;
    } else if context.last_sent_rtp_ts_full.value() != 0 || context.ts_stride_packets > 0 {
        // Normal stride detection for any packet with a previous timestamp reference
        // This ensures stride detection works for the second packet and beyond
        context.detect_ts_stride(headers.rtp_timestamp);
    }

    context.last_sent_rtp_sn_full = headers.rtp_sequence_number;
    context.last_sent_rtp_ts_full = headers.rtp_timestamp;
    context.last_sent_rtp_marker = headers.rtp_marker;
    context.last_sent_ip_id_full = headers.ip_identification;
    context.mode = Profile1CompressorMode::FirstOrder;
    context.fo_packets_sent_since_ir = 0;
    context.consecutive_fo_packets_sent = 0;

    if stride_to_signal.is_some() {
        // IR packet TS becomes new ts_offset for scaled calculations
        context.ts_offset = headers.rtp_timestamp;
        context.ts_scaled_mode = true;
    }

    Ok(packet)
}

/// Compresses headers as a UO (Unidirectional Optimistic) packet.
///
/// Selects the optimal UO packet type based on field changes between the current packet
/// and the compressor's context state. Prioritizes smaller packet types when possible.
/// Updates the compressor mode and packet counters after successful compression.
///
/// # Parameters
/// - `context`: Mutable compressor context containing state and configuration.
/// - `headers`: Uncompressed headers of the current packet to compress.
/// - `crc_calculators`: CRC calculator instances for packet integrity checks.
///
/// # Returns
/// The compressed UO packet data as a byte vector.
///
/// # Errors
/// - [`RohcError::Building`] - No suitable UO packet type available or construction failed
/// - [`RohcError::Internal`] - Internal logic error
pub(super) fn compress_as_uo(
    context: &mut Profile1CompressorContext,
    headers: &RtpUdpIpv4Headers,
    crc_calculators: &CrcCalculators,
) -> Result<Vec<u8>, RohcError> {
    debug_assert_eq!(
        context.rtp_ssrc, headers.rtp_ssrc,
        "SSRC mismatch in compress_as_uo; context should align with packet SSRC."
    );

    let current_sn = headers.rtp_sequence_number;
    let current_ts = headers.rtp_timestamp;
    let current_marker = headers.rtp_marker;
    let current_ip_id = headers.ip_identification;

    let sn_delta = current_sn.wrapping_sub(context.last_sent_rtp_sn_full);
    let marker_changed = current_marker != context.last_sent_rtp_marker;
    let ts_changed = current_ts != context.last_sent_rtp_ts_full;
    let ip_id_changed = current_ip_id != context.last_sent_ip_id_full;

    let implicit_ts = compute_implicit_ts(context, sn_delta);

    let (packet_bytes, actual_ts_for_context_update) = select_and_build_uo_packet(
        context,
        current_sn,
        current_ts,
        current_marker,
        current_ip_id,
        sn_delta,
        marker_changed,
        ts_changed,
        ip_id_changed,
        implicit_ts,
        crc_calculators,
    )?;

    context.last_sent_rtp_sn_full = current_sn;
    context.last_sent_rtp_ts_full = actual_ts_for_context_update;
    context.last_sent_rtp_marker = current_marker;
    context.last_sent_ip_id_full = current_ip_id;

    advance_compressor_mode(context);
    context.fo_packets_sent_since_ir = context.fo_packets_sent_since_ir.saturating_add(1);

    Ok(packet_bytes)
}

// Check if field deltas exceed LSB decoding windows, requiring IR refresh
fn is_lsb_window_exceeded(
    context: &Profile1CompressorContext,
    headers: &RtpUdpIpv4Headers,
) -> bool {
    let sn_k = P1_UO1_SN_LSB_WIDTH_DEFAULT;
    if sn_k > 0 && sn_k < 16 {
        // Unambiguous window is 2^(k-1)
        let max_safe_delta: u16 = (1u16 << (sn_k - 1)).saturating_sub(1);
        let sn_delta_abs =
            min_wrapping_distance_u16(headers.rtp_sequence_number, context.last_sent_rtp_sn_full);
        if sn_delta_abs > max_safe_delta {
            return true;
        }
    }

    // Check TS window only if not in TS_SCALED mode
    let ts_k = P1_UO1_TS_LSB_WIDTH_DEFAULT;
    if !context.ts_scaled_mode && ts_k > 0 && ts_k < 32 {
        let max_safe_delta: u32 = (1u32 << (ts_k - 1)).saturating_sub(1);
        let ts_delta_abs = min_wrapping_distance_u32(
            headers.rtp_timestamp.value(),
            context.last_sent_rtp_ts_full.value(),
        );
        if ts_delta_abs > max_safe_delta {
            return true;
        }
    }

    if headers.ip_identification != context.last_sent_ip_id_full {
        let ipid_k = P1_UO1_IPID_LSB_WIDTH_DEFAULT;
        if ipid_k > 0 && ipid_k < 16 {
            let max_safe_delta: u16 = (1u16 << (ipid_k - 1)).saturating_sub(1);
            let ipid_delta_abs =
                min_wrapping_distance_u16(headers.ip_identification, context.last_sent_ip_id_full);
            if ipid_delta_abs > max_safe_delta {
                return true;
            }
        }
    }

    false
}

fn min_wrapping_distance_u16<T, U>(a: T, b: U) -> u16
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

fn min_wrapping_distance_u32<T, U>(a: T, b: U) -> u32
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

// Calculate implicit RTP timestamp based on SN delta and TS stride
fn compute_implicit_ts(context: &Profile1CompressorContext, sn_delta: u16) -> Option<Timestamp> {
    if let Some(stride) = context.ts_stride {
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
    } else {
        None
    }
}

// Select optimal UO packet type based on field changes
#[allow(clippy::too_many_arguments)]
fn select_and_build_uo_packet(
    context: &mut Profile1CompressorContext,
    current_sn: SequenceNumber,
    current_ts: Timestamp,
    current_marker: bool,
    current_ip_id: IpId,
    sn_delta: u16,
    marker_changed: bool,
    ts_changed: bool,
    ip_id_changed: bool,
    implicit_ts: Option<Timestamp>,
    crc_calculators: &CrcCalculators,
) -> Result<(Vec<u8>, Timestamp), RohcError> {
    // Try UO-1-RTP for TS_SCALED mode
    if context.ts_scaled_mode && sn_delta == 1 && !ip_id_changed {
        if let Some(ts_scaled_val) = context.calculate_ts_scaled(current_ts) {
            let packet = build_uo1_rtp_packet(
                context,
                current_sn,
                ts_scaled_val,
                current_marker,
                crc_calculators,
            )?;
            return Ok((packet, current_ts));
        } else if context.ts_stride.is_some() {
            // TS_SCALED failed, fallback to UO-1-SN with implicit TS
            let implicit_ts_for_fallback = implicit_ts
                .expect("Stride exists with positive sn_delta, implicit_ts should be Some.");
            let packet = build_uo1_sn_packet(context, current_sn, current_marker, crc_calculators)?;
            return Ok((packet, implicit_ts_for_fallback));
        } else {
            return Err(RohcError::InvalidState(
                "TS_SCALED failed and no stride for fallback".to_string(),
            ));
        }
    }

    // Try UO-0 for minimal changes
    if !marker_changed && sn_delta > 0 && sn_delta < 16 && !ip_id_changed {
        let ts_matches_stride_pattern = implicit_ts == Some(current_ts);
        let ts_is_unchanged_from_context = current_ts == context.last_sent_rtp_ts_full;

        if ts_matches_stride_pattern || ts_is_unchanged_from_context {
            if ts_matches_stride_pattern && context.ts_stride.is_some() && !context.ts_scaled_mode {
                let _ = context.detect_ts_stride(current_ts);
            }
            let ts_to_use_for_uo0_crc = if ts_matches_stride_pattern {
                current_ts
            } else {
                context.last_sent_rtp_ts_full
            };
            let packet =
                build_uo0_packet(context, current_sn, ts_to_use_for_uo0_crc, crc_calculators)?;
            return Ok((packet, ts_to_use_for_uo0_crc));
        }
    }

    // Try UO-1-TS - Allow IP ID changes when stride detection is needed
    if !marker_changed
        && ts_changed
        && sn_delta == 1
        && (!ip_id_changed || context.ts_stride.is_none())
    {
        let _ = context.detect_ts_stride(current_ts);
        let packet = build_uo1_ts_packet(context, current_sn, current_ts, crc_calculators)?;
        return Ok((packet, current_ts));
    }

    // Try UO-1-ID
    let ts_for_uo1_id_check = implicit_ts.unwrap_or(context.last_sent_rtp_ts_full);
    if !marker_changed && ip_id_changed && sn_delta == 1 && (current_ts == ts_for_uo1_id_check) {
        if context.ts_stride.is_some()
            && current_ts == implicit_ts.unwrap_or(current_ts.value().wrapping_add(1).into())
            && !context.ts_scaled_mode
        {
            let _ = context.detect_ts_stride(current_ts);
        }
        let packet = build_uo1_id_packet(context, current_sn, current_ip_id, crc_calculators)?;
        return Ok((packet, ts_for_uo1_id_check));
    }

    // Use UO-1-SN as fallback
    if context.ts_stride.is_some() {
        let implicit_ts_for_sn_fallback = match implicit_ts {
            Some(ts) => ts,
            None => {
                let current_sn_delta_for_fallback =
                    current_sn.wrapping_sub(context.last_sent_rtp_sn_full);
                context
                    .last_sent_rtp_ts_full
                    .value()
                    .wrapping_add(
                        current_sn_delta_for_fallback as u32 * context.ts_stride.unwrap_or(0),
                    )
                    .into()
            }
        };
        let packet = build_uo1_sn_packet(context, current_sn, current_marker, crc_calculators)?;
        return Ok((packet, implicit_ts_for_sn_fallback));
    }

    // If no suitable UO packet type is found and no stride is established for UO-1-SN fallback.
    Err(RohcError::InvalidState(
        "No suitable UO packet type and no stride for UO-1-SN".to_string(),
    ))
}

fn advance_compressor_mode(context: &mut Profile1CompressorContext) {
    if context.mode == Profile1CompressorMode::FirstOrder {
        context.consecutive_fo_packets_sent = context.consecutive_fo_packets_sent.saturating_add(1);
        if context.consecutive_fo_packets_sent >= P1_COMPRESSOR_FO_TO_SO_THRESHOLD {
            context.mode = Profile1CompressorMode::SecondOrder;
            context.consecutive_fo_packets_sent = 0;
        }
    }
}

fn build_uo0_packet(
    context: &Profile1CompressorContext,
    current_sn: SequenceNumber,
    ts_for_crc: Timestamp, // This is the TS value used in CRC calculation.
    crc_calculators: &CrcCalculators,
) -> Result<Vec<u8>, RohcError> {
    let sn_lsb = encode_lsb(current_sn.as_u64(), P1_UO0_SN_LSB_WIDTH_DEFAULT)? as u8;
    let crc_input_bytes = prepare_generic_uo_crc_input_payload(
        context.rtp_ssrc,
        current_sn,
        ts_for_crc,
        context.last_sent_rtp_marker,
    );
    let crc3 = crc_calculators.crc3(&crc_input_bytes);

    let uo0_data = Uo0Packet {
        cid: context.get_small_cid_for_packet(),
        sn_lsb,
        crc3,
    };
    serialize_uo0(&uo0_data).map_err(RohcError::Building)
}

fn build_uo1_ts_packet(
    context: &mut Profile1CompressorContext,
    current_sn: SequenceNumber,
    current_ts: Timestamp,
    crc_calculators: &CrcCalculators,
) -> Result<Vec<u8>, RohcError> {
    let ts_lsb = encode_lsb(current_ts.as_u64(), P1_UO1_TS_LSB_WIDTH_DEFAULT)? as u16;
    let crc_input_bytes = prepare_generic_uo_crc_input_payload(
        context.rtp_ssrc,
        current_sn, // UO-1-TS implies SN+1, so current_sn should be context.last_sn + 1.
        current_ts,
        context.last_sent_rtp_marker, // UO-1-TS implies marker is unchanged from context.
    );
    let crc8 = crc_calculators.crc8(&crc_input_bytes);

    let uo1_packet_data = Uo1Packet {
        cid: context.get_small_cid_for_packet(),
        marker: false, // UO-1-TS specific: M bit in type is 0. Actual marker is from context.
        ts_lsb: Some(ts_lsb),
        num_ts_lsb_bits: Some(P1_UO1_TS_LSB_WIDTH_DEFAULT),
        crc8,
        ..Default::default()
    };
    serialize_uo1_ts(&uo1_packet_data).map_err(RohcError::Building)
}

fn build_uo1_sn_packet(
    context: &Profile1CompressorContext,
    current_sn: SequenceNumber,
    current_marker: bool,
    crc_calculators: &CrcCalculators,
) -> Result<Vec<u8>, RohcError> {
    debug_assert!(
        context.ts_stride.is_some(),
        "UO-1-SN build logic called without established TS_STRIDE in context."
    );

    let sn_lsb_val = encode_lsb(current_sn.as_u64(), P1_UO1_SN_LSB_WIDTH_DEFAULT)? as u16;

    // Calculate implicit timestamp based on stride for CRC
    let sn_delta_for_ts = current_sn.wrapping_sub(context.last_sent_rtp_sn_full);
    let implicit_ts_for_crc = if let Some(stride_val) = context.ts_stride {
        context
            .last_sent_rtp_ts_full
            .value()
            .wrapping_add(sn_delta_for_ts as u32 * stride_val)
            .into()
    } else {
        // Should not happen due to debug_assert, but fallback.
        context.last_sent_rtp_ts_full
    };

    let crc_input_bytes = prepare_generic_uo_crc_input_payload(
        context.rtp_ssrc,
        current_sn,
        implicit_ts_for_crc,
        current_marker, // UO-1-SN carries the current marker.
    );
    let calculated_crc8 = crc_calculators.crc8(&crc_input_bytes);

    let uo1_sn_data = Uo1Packet {
        cid: context.get_small_cid_for_packet(),
        sn_lsb: sn_lsb_val,
        num_sn_lsb_bits: P1_UO1_SN_LSB_WIDTH_DEFAULT,
        marker: current_marker, // This is the marker bit set in the UO-1-SN type octet.
        crc8: calculated_crc8,
        ..Default::default()
    };
    serialize_uo1_sn(&uo1_sn_data).map_err(RohcError::Building)
}

// Builds a UO-1-ID packet when IP identification changes but SN increments by 1.
fn build_uo1_id_packet(
    context: &Profile1CompressorContext,
    current_sn: SequenceNumber,
    current_ip_id: IpId,
    crc_calculators: &CrcCalculators,
) -> Result<Vec<u8>, RohcError> {
    let ip_id_lsb_for_packet =
        encode_lsb(current_ip_id.as_u64(), P1_UO1_IPID_LSB_WIDTH_DEFAULT)? as u8;

    // UO-1-ID implies SN+1 and unchanged TS (or TS follows stride for implicit update if stride known).
    // For CRC, it specifically uses the *last sent TS* from context if no stride,
    // or implicit TS if stride is present.
    // This function's caller (`select_and_build_uo_packet`) already filters for `!ts_changed`
    // or ensures `implicit_ts_if_stride_set` is compatible before choosing UO-1-ID.
    // For CRC, we need the effective TS based on these rules.
    let ts_for_crc = if let Some(stride_val) = context.ts_stride {
        // SN delta is implicitly 1 for UO-1-ID
        context
            .last_sent_rtp_ts_full
            .value()
            .wrapping_add(stride_val)
            .into()
    } else {
        context.last_sent_rtp_ts_full // If no stride, TS must be unchanged from context.
    };

    let crc_input_bytes = prepare_uo1_id_specific_crc_input_payload(
        context.rtp_ssrc,
        current_sn, // UO-1-ID implies SN+1, so current_sn is context.last_sn + 1.
        ts_for_crc,
        context.last_sent_rtp_marker, // UO-1-ID implies marker is unchanged from context.
        ip_id_lsb_for_packet,
    );
    let calculated_crc8 = crc_calculators.crc8(&crc_input_bytes);

    let uo1_id_packet_data = Uo1Packet {
        cid: context.get_small_cid_for_packet(),
        ip_id_lsb: Some(ip_id_lsb_for_packet as u16),
        num_ip_id_lsb_bits: Some(P1_UO1_IPID_LSB_WIDTH_DEFAULT),
        crc8: calculated_crc8,
        ..Default::default() // Marker is false in type byte, other LSBs None
    };
    serialize_uo1_id(&uo1_id_packet_data).map_err(RohcError::Building)
}

// Builds a UO-1-RTP packet using TS_SCALED mode when TS follows the established stride.
fn build_uo1_rtp_packet(
    context: &Profile1CompressorContext,
    current_sn: SequenceNumber,
    ts_scaled_val: u8, // The calculated TS_SCALED value.
    current_marker: bool,
    crc_calculators: &CrcCalculators,
) -> Result<Vec<u8>, RohcError> {
    let stride = context.ts_stride.ok_or_else(|| {
        RohcError::Internal("TS stride missing in scaled mode during UO-1-RTP build.".to_string())
    })?;
    debug_assert!(stride > 0, "TS Stride must be positive to build UO-1-RTP.");

    // Reconstruct the full TS value from TS_Offset and TS_SCALED for CRC calculation.
    // current_sn for CRC is the SN of the packet (context.last_sn + 1).
    let full_ts_for_crc = context
        .ts_offset
        .wrapping_add(ts_scaled_val as u32 * stride);

    let crc_input_bytes = prepare_generic_uo_crc_input_payload(
        context.rtp_ssrc,
        current_sn, // UO-1-RTP implies SN+1.
        full_ts_for_crc,
        current_marker, // UO-1-RTP carries the current marker bit.
    );
    let calculated_crc8 = crc_calculators.crc8(&crc_input_bytes);

    let uo1_rtp_data = Uo1Packet {
        cid: context.get_small_cid_for_packet(),
        marker: current_marker, // This is the marker bit set in the UO-1-RTP type octet.
        ts_scaled: Some(ts_scaled_val),
        crc8: calculated_crc8,
        ..Default::default() // Other LSB fields are not used by UO-1-RTP.
    };
    serialize_uo1_rtp(&uo1_rtp_data).map_err(RohcError::Building)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crc::CrcCalculators;
    use crate::profiles::profile1::context::Profile1CompressorContext;
    use crate::profiles::profile1::protocol_types::RtpUdpIpv4Headers;
    use std::time::Instant;

    fn create_test_context(
        ssrc: u32,
        last_sn: u16,
        last_ts: u32,
        last_marker: bool,
        last_ip_id: u16,
    ) -> Profile1CompressorContext {
        let mut context = Profile1CompressorContext::new(0.into(), 20, Instant::now());
        context.rtp_ssrc = ssrc.into();
        context.last_sent_rtp_sn_full = last_sn.into();
        context.last_sent_rtp_ts_full = last_ts.into();
        context.last_sent_rtp_marker = last_marker;
        context.last_sent_ip_id_full = last_ip_id.into();
        context.mode = Profile1CompressorMode::FirstOrder;
        context
    }

    fn create_test_headers(
        ssrc: u32,
        sn: u16,
        ts: u32,
        marker: bool,
        ip_id: u16,
    ) -> RtpUdpIpv4Headers {
        RtpUdpIpv4Headers {
            rtp_ssrc: ssrc.into(),
            rtp_sequence_number: sn.into(),
            rtp_timestamp: ts.into(),
            rtp_marker: marker,
            ip_identification: ip_id.into(),
            ip_src: "192.168.0.1".parse().unwrap(),
            ip_dst: "192.168.0.2".parse().unwrap(),
            udp_src_port: 1000,
            udp_dst_port: 2000,
            ..Default::default()
        }
    }

    #[test]
    fn p1_should_force_ir_initialization_mode() {
        let mut context = create_test_context(1, 100, 1000, false, 10);
        let headers = create_test_headers(1, 101, 1000, false, 10);

        context.mode = Profile1CompressorMode::InitializationAndRefresh;
        assert!(should_force_ir(&context, &headers));
    }

    #[test]
    fn p1_should_force_ir_refresh_interval() {
        let mut context = create_test_context(1, 100, 1000, false, 10);
        let headers = create_test_headers(1, 101, 1000, false, 10);

        context.ir_refresh_interval = 5;
        context.fo_packets_sent_since_ir = 4;
        assert!(should_force_ir(&context, &headers));

        context.fo_packets_sent_since_ir = 3;
        assert!(!should_force_ir(&context, &headers));
    }

    #[test]
    fn p1_should_force_ir_ssrc_change() {
        let context = create_test_context(1, 100, 1000, false, 10);
        let headers = create_test_headers(2, 101, 1000, false, 10);
        assert!(should_force_ir(&context, &headers));
    }

    #[test]
    fn p1_should_force_ir_scaled_mode_misaligned() {
        let mut context = create_test_context(1, 100, 1000, false, 10);
        context.ts_scaled_mode = true;
        context.ts_stride = Some(160);
        context.ts_offset = 1000.into();

        let headers = create_test_headers(1, 101, 1080, false, 10); // Not stride-aligned
        assert!(should_force_ir(&context, &headers));
    }

    #[test]
    fn p1_should_force_ir_large_sn_jump() {
        let context = create_test_context(1, 100, 1000, false, 10);
        let headers = create_test_headers(1, 228, 1000, false, 10); // Delta = 128
        assert!(should_force_ir(&context, &headers));
    }

    #[test]
    fn p1_should_force_ir_large_ts_jump() {
        let mut context = create_test_context(1, 100, 1000, false, 10);
        context.ts_scaled_mode = false;
        let headers = create_test_headers(1, 101, 33768, false, 10); // Delta = 32768
        assert!(should_force_ir(&context, &headers));
    }

    #[test]
    fn p1_should_force_ir_large_ip_id_jump() {
        let context = create_test_context(1, 100, 1000, false, 10);
        let headers = create_test_headers(1, 101, 1000, false, 138); // Delta = 128
        assert!(should_force_ir(&context, &headers));
    }

    #[test]
    fn p1_should_force_ir_scaled_mode_no_stride() {
        let mut context = create_test_context(1, 100, 1000, false, 10);
        context.ts_scaled_mode = true;
        context.ts_stride = None;

        let headers = create_test_headers(1, 101, 1160, false, 10);
        assert!(should_force_ir(&context, &headers));
    }

    #[test]
    fn p1_compress_as_ir_updates_context() {
        let crc_calculators = CrcCalculators::new();
        let mut context = create_test_context(0, 0, 0, false, 0);
        let headers = create_test_headers(1, 100, 1000, true, 50);

        context.rtp_ssrc = 0.into(); // Simulate initial state before SSRC is known
        context.initialize_context_from_uncompressed_headers(&headers); // SSRC becomes 1, mode -> InitAndRefresh

        let _ = compress_as_ir(&mut context, &headers, &crc_calculators).unwrap();

        assert_eq!(context.mode, Profile1CompressorMode::FirstOrder);
        assert_eq!(context.last_sent_rtp_sn_full, headers.rtp_sequence_number);
        assert_eq!(context.last_sent_rtp_ts_full, headers.rtp_timestamp);
        assert_eq!(context.last_sent_rtp_marker, headers.rtp_marker);
        assert_eq!(context.last_sent_ip_id_full, headers.ip_identification);
        assert_eq!(context.fo_packets_sent_since_ir, 0);
    }

    #[test]
    fn p1_compress_as_uo_selects_uo0() {
        let crc_calculators = CrcCalculators::new();
        let mut context = create_test_context(1, 100, 1000, false, 10);
        let headers = create_test_headers(1, 101, 1000, false, 10);

        let packet = compress_as_uo(&mut context, &headers, &crc_calculators).unwrap();
        assert_eq!(packet.len(), 1, "UO-0 packet should be 1 byte");
        assert_eq!(packet[0] & 0x80, 0, "UO-0 discriminator check");
    }

    #[test]
    fn p1_compress_as_uo_uo0_implicit_ts() {
        let crc_calculators = CrcCalculators::new();
        let mut context = create_test_context(1, 100, 1000, false, 10);
        context.ts_stride = Some(160); // Establish stride

        let headers = create_test_headers(1, 101, 1160, false, 10); // TS = 1000 + 1*160

        let packet = compress_as_uo(&mut context, &headers, &crc_calculators).unwrap();
        assert_eq!(packet.len(), 1);
        assert_eq!(context.last_sent_rtp_ts_full, 1160); // Context TS updated based on packet's actual TS
    }

    #[test]
    fn p1_compress_as_uo_selects_uo1_sn_marker_change() {
        let crc_calculators = CrcCalculators::new();
        let mut context = create_test_context(1, 100, 1000, false, 10); // last_marker = false
        context.ts_stride = Some(160); // UO-1-SN requires stride established
        let headers = create_test_headers(1, 101, 1000, true, 10); // current_marker = true (changed)

        let packet = compress_as_uo(&mut context, &headers, &crc_calculators).unwrap();
        assert_eq!(packet.len(), 3, "UO-1-SN packet should be 3 bytes");
        assert_eq!(
            packet[0] & P1_UO_1_SN_PACKET_TYPE_PREFIX, // Check base prefix for UO-1-SN
            P1_UO_1_SN_PACKET_TYPE_PREFIX
        );
        assert_ne!(
            packet[0] & P1_UO_1_SN_MARKER_BIT_MASK,
            0,
            "Marker bit should be set in UO-1-SN type octet"
        );
    }

    #[test]
    fn p1_compress_as_uo_selects_uo1_ts() {
        let crc_calculators = CrcCalculators::new();
        let mut context = create_test_context(1, 100, 1000, false, 10);
        let headers = create_test_headers(1, 101, 2000, false, 10); // SN+1, TS changed significantly

        let packet = compress_as_uo(&mut context, &headers, &crc_calculators).unwrap();
        assert_eq!(packet.len(), 4, "UO-1-TS packet should be 4 bytes");
        assert_eq!(packet[0], P1_UO_1_TS_DISCRIMINATOR);
    }

    #[test]
    fn p1_compress_as_uo_selects_uo1_id() {
        let crc_calculators = CrcCalculators::new();
        let mut context = create_test_context(1, 100, 1000, false, 10);
        let headers = create_test_headers(1, 101, 1000, false, 11); // IP-ID changes, SN+1, TS same

        let packet = compress_as_uo(&mut context, &headers, &crc_calculators).unwrap();
        assert_eq!(packet.len(), 3, "UO-1-ID packet should be 3 bytes");
        assert_eq!(packet[0], P1_UO_1_ID_DISCRIMINATOR);
    }

    #[test]
    fn p1_compress_as_uo_selects_uo1_rtp_scaled_mode() {
        let crc_calculators = CrcCalculators::new();
        let mut context = create_test_context(1, 100, 1000, false, 10);
        context.ts_scaled_mode = true;
        context.ts_stride = Some(160);
        context.ts_offset = 1000.into(); // TS_Offset aligned with last_sent_ts_full for this test

        let headers = create_test_headers(1, 101, 1160, false, 10); // current_ts = offset + 1 * stride

        let packet = compress_as_uo(&mut context, &headers, &crc_calculators).unwrap();
        assert_eq!(packet.len(), 3, "UO-1-RTP packet should be 3 bytes");
        assert_eq!(
            packet[0] & !P1_UO_1_RTP_MARKER_BIT_MASK, // Check base without marker bit
            P1_UO_1_RTP_DISCRIMINATOR_BASE
        );
        assert_eq!(packet[1], 1, "TS_SCALED should be 1"); // (1160 - 1000) / 160 = 1
    }

    #[test]
    fn p1_compress_as_uo_error_no_stride_for_fallback() {
        let crc_calculators = CrcCalculators::new();
        let mut context = create_test_context(1, 100, 1000, false, 10);
        context.ts_stride = None; // Ensure no stride for UO-1-SN fallback

        // Conditions that would typically lead to UO-1-SN if stride existed (e.g., marker change, SN jump > 15)
        let headers = create_test_headers(1, 120, 1000, true, 10); // SN delta 20, marker true

        let result = compress_as_uo(&mut context, &headers, &crc_calculators);
        assert!(
            result.is_err(),
            "Should return error when no stride for UO-1-SN fallback"
        );

        if let Err(RohcError::InvalidState(msg)) = result {
            assert!(
                msg.contains("No suitable UO packet type and no stride for UO-1-SN"),
                "Error message mismatch. Got: {}",
                msg
            );
        } else {
            panic!("Expected InvalidState error, got {:?}", result);
        }
    }

    #[test]
    fn p1_compress_as_uo_uo1_sn_with_stride_selected() {
        let crc_calculators = CrcCalculators::new();
        let mut context = create_test_context(1, 100, 1000, false, 10);
        context.ts_stride = Some(160); // Stride established

        // Packet conditions: SN jump, marker changes (forces UO-1-SN)
        let headers = create_test_headers(1, 102, 1000, true, 10);

        let result = compress_as_uo(&mut context, &headers, &crc_calculators);
        assert!(
            result.is_ok(),
            "Expected Ok for UO-1-SN with stride, got Err: {:?}",
            result.err()
        );
        let packet = result.unwrap();
        assert_eq!(packet.len(), 3);
        assert_eq!(
            packet[0] & P1_UO_1_SN_PACKET_TYPE_PREFIX,
            P1_UO_1_SN_PACKET_TYPE_PREFIX
        );
    }

    #[test]
    fn p1_compress_as_uo_scaled_mode_fallback_to_uo1sn() {
        let crc_calculators = CrcCalculators::new();
        let mut context = create_test_context(1, 100, 1000, false, 10);
        context.ts_stride = Some(160); // Stride known for UO-1-SN fallback
        context.ts_scaled_mode = true;
        context.ts_offset = 1000.into();

        // Header will fail TS_SCALED calc (misaligned: 1000 + 160/2), SN_delta > 1.
        // This combination means UO-1-RTP fails, UO-0/UO-1-TS/UO-1-ID conditions not met, should use UO-1-SN.
        let headers = create_test_headers(1, 120, 1080, false, 10);

        let result = compress_as_uo(&mut context, &headers, &crc_calculators);
        assert!(
            result.is_ok(),
            "Should fall back to UO-1-SN, got: {:?}",
            result.err()
        );
        let packet = result.unwrap();
        assert!(packet.len() >= 3);
        assert_eq!(
            packet[0] & P1_UO_1_SN_PACKET_TYPE_PREFIX,
            P1_UO_1_SN_PACKET_TYPE_PREFIX,
            "Should use UO-1-SN as fallback."
        );
    }

    #[test]
    fn p1_mode_transition_to_second_order() {
        let crc_calculators = CrcCalculators::new();
        let mut context = create_test_context(1, 100, 1000, false, 10);
        context.mode = Profile1CompressorMode::FirstOrder;
        context.consecutive_fo_packets_sent = P1_COMPRESSOR_FO_TO_SO_THRESHOLD - 1; // One short of threshold

        let headers = create_test_headers(1, 101, 1000, false, 10); // UO-0 conditions
        let _ = compress_as_uo(&mut context, &headers, &crc_calculators).unwrap();

        assert_eq!(context.mode, Profile1CompressorMode::SecondOrder);
        assert_eq!(context.consecutive_fo_packets_sent, 0); // Reset after transition
    }

    #[test]
    fn p1_helper_build_functions_produce_correct_format() {
        let context_no_stride = create_test_context(1, 100, 1000, false, 10);
        let crc_calculators = CrcCalculators::new();

        // UO-0
        let uo0 = build_uo0_packet(
            &context_no_stride,
            101.into(),
            1000.into(),
            &crc_calculators,
        )
        .unwrap();
        assert_eq!(uo0.len(), 1);

        // UO-1-SN requires stride in context
        let mut context_with_stride = context_no_stride.clone();
        context_with_stride.ts_stride = Some(160);
        let uo1_sn =
            build_uo1_sn_packet(&context_with_stride, 101.into(), true, &crc_calculators).unwrap();
        assert_eq!(uo1_sn.len(), 3);

        // UO-1-TS
        let mut context_mut_for_ts = context_no_stride.clone();
        let uo1_ts = build_uo1_ts_packet(
            &mut context_mut_for_ts,
            101.into(),
            1160.into(),
            &crc_calculators,
        )
        .unwrap();
        assert_eq!(uo1_ts.len(), 4);

        // UO-1-ID
        let uo1_id = build_uo1_id_packet(
            &context_no_stride,
            101.into(),
            12345.into(),
            &crc_calculators,
        )
        .unwrap();
        assert_eq!(uo1_id.len(), 3);

        // UO-1-RTP
        let mut context_scaled = context_no_stride.clone();
        context_scaled.ts_offset = 1000.into(); // Assume offset aligns for simplicity
        context_scaled.ts_stride = Some(160);
        let uo1_rtp =
            build_uo1_rtp_packet(&context_scaled, 101.into(), 1, false, &crc_calculators).unwrap();
        assert_eq!(uo1_rtp.len(), 3);
    }

    #[test]
    fn p1_min_wrapping_distance_works() {
        assert_eq!(min_wrapping_distance_u16(10u16, 5u16), 5);
        assert_eq!(min_wrapping_distance_u16(5u16, 10u16), 5);
        assert_eq!(min_wrapping_distance_u16(u16::MAX, 1u16), 2); // 65535 vs 1
        assert_eq!(min_wrapping_distance_u16(1u16, u16::MAX), 2);

        assert_eq!(min_wrapping_distance_u32(1000u32, 500u32), 500);
        assert_eq!(min_wrapping_distance_u32(500u32, 1000u32), 500);
        assert_eq!(min_wrapping_distance_u32(u32::MAX, 1u32), 2);
        assert_eq!(min_wrapping_distance_u32(1u32, u32::MAX), 2);
    }
}
