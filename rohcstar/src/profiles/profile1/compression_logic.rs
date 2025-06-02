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
    build_profile1_ir_packet, build_profile1_uo0_packet, build_profile1_uo1_id_packet,
    build_profile1_uo1_rtp_packet, build_profile1_uo1_sn_packet, build_profile1_uo1_ts_packet,
    prepare_generic_uo_crc_input_payload, prepare_uo1_id_specific_crc_input_payload,
};
use super::packet_types::{IrPacket, Uo0Packet, Uo1Packet};
use super::protocol_types::{RtpUdpIpv4Headers, Timestamp};

use crate::crc::CrcCalculators;
use crate::encodings::encode_lsb;
use crate::error::RohcError;
use crate::packet_defs::RohcProfile;

/// Determines if an IR packet must be sent by the compressor.
///
/// IR packets are forced when the compressor needs to reset state, for periodic
/// refresh, or when field changes would exceed LSB encoding capabilities,
/// risking decompressor desynchronization.
///
/// # Parameters
/// - `context`: Current compressor context containing state and configuration.
/// - `uncompressed_headers`: Headers from the packet being compressed.
///
/// # Returns
/// - `true`: An IR packet must be sent.
/// - `false`: Other, more optimal UO packet types can be considered.
pub(super) fn should_force_ir(
    context: &Profile1CompressorContext,
    uncompressed_headers: &RtpUdpIpv4Headers,
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

    // Change in SSRC signifies a new RTP stream, requiring full context establishment.
    if context.rtp_ssrc != uncompressed_headers.rtp_ssrc {
        return true;
    }

    // Check conditions related to TS_SCALED mode.
    if context.ts_scaled_mode {
        if context.ts_stride.is_none() {
            // Scaled mode requires a known TS stride; this is an inconsistent state.
            return true;
        }
        if context
            .calculate_ts_scaled(uncompressed_headers.rtp_timestamp)
            .is_none()
        {
            // Current RTP timestamp is not aligned with the established stride for TS_SCALED,
            // or the scaled value would overflow. An IR is needed to resynchronize or signal a change.
            return true;
        }
    }

    // Check if field deltas exceed LSB encoding windows, risking misinterpretation by decompressor.
    check_lsb_window_exceeded(context, uncompressed_headers)
}

/// Prepares and builds an IR (Initialization/Refresh) packet.
///
/// Handles TS stride signaling for TS_SCALED mode and updates compressor
/// state after successful IR packet generation. Assumes SSRC validation
/// has been performed by the caller.
///
/// # Parameters
/// - `context`: Mutable compressor context to update after IR generation.
/// - `uncompressed_headers`: Headers from the current packet to include in the IR packet.
/// - `crc_calculators`: CRC calculator instances for packet integrity checks.
///
/// # Returns
/// - `Ok(Vec<u8>)`: Compressed IR packet data.
/// - `Err(RohcError)`: If IR packet building fails (e.g., internal error).
pub(super) fn compress_as_ir(
    context: &mut Profile1CompressorContext,
    uncompressed_headers: &RtpUdpIpv4Headers,
    crc_calculators: &CrcCalculators,
) -> Result<Vec<u8>, RohcError> {
    debug_assert_eq!(
        context.rtp_ssrc, uncompressed_headers.rtp_ssrc,
        "SSRC mismatch in compress_as_ir; context should have been initialized or SSRC change handled."
    );

    let previous_ts_before_ir = context.last_sent_rtp_ts_full;

    // Determine if scaled mode needs to be reset due to calculation failures or missing stride.
    let scaled_mode_had_issues = context.ts_scaled_mode
        && (context.ts_stride.is_none()
            || context
                .calculate_ts_scaled(uncompressed_headers.rtp_timestamp)
                .is_none());

    // Determine the TS_STRIDE value to signal in the IR packet, if any.
    let ir_packet_stride_to_signal = if scaled_mode_had_issues {
        // Reset scaled mode state due to issues.
        context.ts_scaled_mode = false;
        context.ts_stride = None;
        context.ts_offset = Timestamp::new(0);
        context.ts_stride_packets = 0;
        None // Don't signal a stride if scaled mode just failed.
    } else if context.ts_scaled_mode {
        // Already in scaled mode and no issues, signal the current active stride.
        context.ts_stride
    } else if context.ts_stride.is_some()
        && context.ts_stride_packets >= P1_TS_STRIDE_ESTABLISHMENT_THRESHOLD
    {
        // Not in scaled mode, but stride is established enough to signal for future use.
        context.ts_stride
    } else {
        None // No stride to signal.
    };

    let ir_data = IrPacket {
        cid: context.cid,
        profile_id: RohcProfile::RtpUdpIp,
        crc8: 0, // Placeholder, calculated by build_profile1_ir_packet
        static_ip_src: context.ip_source,
        static_ip_dst: context.ip_destination,
        static_udp_src_port: context.udp_source_port,
        static_udp_dst_port: context.udp_destination_port,
        static_rtp_ssrc: context.rtp_ssrc,
        dyn_rtp_sn: uncompressed_headers.rtp_sequence_number,
        dyn_rtp_timestamp: uncompressed_headers.rtp_timestamp,
        dyn_rtp_marker: uncompressed_headers.rtp_marker,
        ts_stride: ir_packet_stride_to_signal,
    };

    let rohc_packet_bytes =
        build_profile1_ir_packet(&ir_data, crc_calculators).map_err(RohcError::Building)?;

    // Update context state common to all IR packets.
    context.last_sent_rtp_sn_full = uncompressed_headers.rtp_sequence_number;
    context.last_sent_rtp_ts_full = uncompressed_headers.rtp_timestamp;
    context.last_sent_rtp_marker = uncompressed_headers.rtp_marker;
    context.last_sent_ip_id_full = uncompressed_headers.ip_identification;
    context.mode = Profile1CompressorMode::FirstOrder;
    context.fo_packets_sent_since_ir = 0;
    context.consecutive_fo_packets_sent = 0;

    if ir_packet_stride_to_signal.is_some() {
        // Activate scaled mode if a stride was signaled in this IR.
        // The TS of the IR packet itself becomes the new TS_Offset for scaled calculations.
        context.ts_offset = uncompressed_headers.rtp_timestamp;
        context.ts_scaled_mode = true;
    } else if scaled_mode_had_issues {
        // Scaled mode was just turned off. Resume stride detection using the TS
        // *before* this IR packet, as the IR's TS might not be part of the regular sequence.
        let ts_of_this_ir = context.last_sent_rtp_ts_full; // Currently holds uncompressed_headers.rtp_timestamp
        context.last_sent_rtp_ts_full = previous_ts_before_ir;
        context.update_ts_stride_detection(uncompressed_headers.rtp_timestamp);
        context.last_sent_rtp_ts_full = ts_of_this_ir; // Restore for next packet's reference
    }

    Ok(rohc_packet_bytes)
}

/// Compresses headers as a UO (Unidirectional Optimistic) packet.
///
/// Selects the optimal UO packet type based on field changes between the current packet
/// and the compressor's context state. Prioritizes smaller packet types when possible.
/// Updates the compressor mode and packet counters after successful compression.
///
/// # Parameters
/// - `context`: Mutable compressor context containing state and configuration.
/// - `uncompressed_headers`: Uncompressed headers of the current packet to compress.
/// - `crc_calculators`: CRC calculator instances for packet integrity checks.
///
/// # Returns
/// - `Ok(Vec<u8>)`: Compressed UO packet data.
/// - `Err(RohcError)`: If no suitable UO packet type is available or building fails.
pub(super) fn compress_as_uo(
    context: &mut Profile1CompressorContext,
    uncompressed_headers: &RtpUdpIpv4Headers,
    crc_calculators: &CrcCalculators,
) -> Result<Vec<u8>, RohcError> {
    debug_assert_eq!(
        context.rtp_ssrc, uncompressed_headers.rtp_ssrc,
        "SSRC mismatch in compress_as_uo; context should align with packet SSRC."
    );

    let current_sn = uncompressed_headers.rtp_sequence_number;
    let current_ts = uncompressed_headers.rtp_timestamp;
    let current_marker = uncompressed_headers.rtp_marker;
    let current_ip_id = uncompressed_headers.ip_identification;

    let sn_delta = current_sn.wrapping_sub(context.last_sent_rtp_sn_full);
    let marker_changed = current_marker != context.last_sent_rtp_marker;
    let ts_changed = current_ts != context.last_sent_rtp_ts_full;
    let ip_id_changed = current_ip_id != context.last_sent_ip_id_full;

    let implicit_ts_if_stride_is_set = calculate_implicit_ts(context, sn_delta);

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
        implicit_ts_if_stride_is_set,
        crc_calculators,
    )?;

    // Update context with the values that were effectively transmitted or implied.
    context.last_sent_rtp_sn_full = current_sn;
    context.last_sent_rtp_ts_full = actual_ts_for_context_update;
    context.last_sent_rtp_marker = current_marker;
    context.last_sent_ip_id_full = current_ip_id;

    update_compressor_mode(context);
    context.fo_packets_sent_since_ir = context.fo_packets_sent_since_ir.saturating_add(1);

    Ok(packet_bytes)
}

/// Checks if any field delta (SN, TS, IP-ID) exceeds its LSB encoding window.
/// This indicates that an IR packet might be needed to prevent decompressor ambiguity.
fn check_lsb_window_exceeded(
    context: &Profile1CompressorContext,
    headers: &RtpUdpIpv4Headers,
) -> bool {
    // Check sequence number window.
    let sn_k = P1_UO1_SN_LSB_WIDTH_DEFAULT; // Using UO-1-SN as a common case.
    if sn_k > 0 && sn_k < 16 {
        // LSB widths for SN are typically small (e.g., 4-8 bits).
        // The unambiguous window is 2^(k-1). Delta must be within this.
        let max_safe_delta: u16 = (1u16 << (sn_k - 1)).saturating_sub(1);
        let sn_delta_abs =
            min_wrapping_distance_u16(headers.rtp_sequence_number, context.last_sent_rtp_sn_full);
        if sn_delta_abs > max_safe_delta {
            return true;
        }
    }

    // Check timestamp window, but only if not in TS_SCALED mode (where TS is handled differently).
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

    // Check IP-ID window only if IP-ID has changed from the last sent packet.
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

/// Calculates the minimum wrapping distance between two u16 values.
/// E.g., distance(65535, 1) is 2, not 65534.
fn min_wrapping_distance_u16(a: u16, b: u16) -> u16 {
    let forward = a.wrapping_sub(b);
    let backward = b.wrapping_sub(a);
    forward.min(backward)
}

/// Calculates the minimum wrapping distance between two u32 values.
fn min_wrapping_distance_u32(a: u32, b: u32) -> u32 {
    let forward = a.wrapping_sub(b);
    let backward = b.wrapping_sub(a);
    forward.min(backward)
}

/// Calculates the implicit RTP timestamp if a TS stride is active in the context.
/// Based on the sequence number delta from the last sent packet.
fn calculate_implicit_ts(context: &Profile1CompressorContext, sn_delta: u16) -> Option<Timestamp> {
    if let Some(stride) = context.ts_stride {
        if sn_delta > 0 {
            // Only calculate if SN has advanced.
            Some(Timestamp::new(
                context
                    .last_sent_rtp_ts_full
                    .value()
                    .wrapping_add(sn_delta as u32 * stride),
            ))
        } else {
            None // SN did not advance or regressed; implicit TS is not straightforward.
        }
    } else {
        None // No stride active.
    }
}

/// Selects the most appropriate UO packet type and builds it.
/// Returns the packet bytes and the RTP timestamp value that was effectively transmitted or implied.
#[allow(clippy::too_many_arguments)]
fn select_and_build_uo_packet(
    context: &mut Profile1CompressorContext,
    current_sn: u16,
    current_ts: Timestamp,
    current_marker: bool,
    current_ip_id: u16,
    sn_delta: u16,
    marker_changed: bool,
    ts_changed: bool,
    ip_id_changed: bool,
    implicit_ts_if_stride_set: Option<Timestamp>,
    crc_calculators: &CrcCalculators,
) -> Result<(Vec<u8>, Timestamp), RohcError> {
    // Try UO-1-RTP for scaled mode if SN increments by 1 and IP-ID is unchanged.
    if context.ts_scaled_mode && sn_delta == 1 && !ip_id_changed {
        if let Some(ts_scaled_val) = context.calculate_ts_scaled(current_ts) {
            let packet = build_uo1_rtp(
                context,
                current_sn,
                ts_scaled_val,
                current_marker,
                crc_calculators,
            )?;
            return Ok((packet, current_ts)); // Actual current_ts used for UO-1-RTP
        } else if context.ts_stride.is_some() {
            // TS_SCALED calculation failed (e.g., misaligned, overflow), but stride exists.
            // Fallback to UO-1-SN, which uses implicit TS update via stride.
            let implicit_ts_for_fallback = implicit_ts_if_stride_set
                .expect("Stride exists with positive sn_delta, implicit_ts should be Some.");
            let packet = build_uo1_sn(context, current_sn, current_marker, crc_calculators)?;
            return Ok((packet, implicit_ts_for_fallback));
        } else {
            // Should have been caught by should_force_ir if TS_SCALED failed without stride.
            return Err(RohcError::InvalidState(
                "TS_SCALED failed and no stride for fallback".to_string(),
            ));
        }
    }

    // Try UO-0 for minimal changes: Marker unchanged, SN increments within UO-0 window, IP-ID unchanged.
    if !marker_changed && sn_delta > 0 && sn_delta < 16 && !ip_id_changed {
        let ts_matches_stride_pattern = implicit_ts_if_stride_set == Some(current_ts);
        let ts_is_unchanged_from_context = current_ts == context.last_sent_rtp_ts_full;

        if ts_matches_stride_pattern || ts_is_unchanged_from_context {
            if ts_matches_stride_pattern && context.ts_stride.is_some() && !context.ts_scaled_mode {
                // If UO-0 chosen because TS matches stride, update detection state.
                // This aids transition to scaled_mode.
                let _ = context.update_ts_stride_detection(current_ts);
            }
            let ts_to_use_for_uo0_crc = if ts_matches_stride_pattern {
                current_ts
            } else {
                context.last_sent_rtp_ts_full
            };
            let packet = build_uo0(context, current_sn, ts_to_use_for_uo0_crc, crc_calculators)?;
            return Ok((packet, ts_to_use_for_uo0_crc));
        }
    }

    // Try UO-1-TS: Marker unchanged, TS changed, SN increments by 1, IP-ID unchanged.
    if !marker_changed && ts_changed && sn_delta == 1 && !ip_id_changed {
        // This packet helps in TS stride detection.
        let _ = context.update_ts_stride_detection(current_ts);
        let packet = build_uo1_ts(context, current_sn, current_ts, crc_calculators)?;
        return Ok((packet, current_ts));
    }

    // Try UO-1-ID: Effective TS for UO-1-ID is based on context's last TS, potentially advanced by stride.
    let ts_for_uo1_id_check = implicit_ts_if_stride_set.unwrap_or(context.last_sent_rtp_ts_full);
    if !marker_changed && ip_id_changed && sn_delta == 1 && (current_ts == ts_for_uo1_id_check) {
        if context.ts_stride.is_some()
            && current_ts
                == implicit_ts_if_stride_set
                    .unwrap_or(Timestamp::new(current_ts.value().wrapping_add(1)))
            && !context.ts_scaled_mode
        {
            // TS matches stride, ensure stride detection state is updated.
            let _ = context.update_ts_stride_detection(current_ts);
        }
        let packet = build_uo1_id(context, current_sn, current_ip_id, crc_calculators)?;
        return Ok((packet, ts_for_uo1_id_check));
    }

    // Use UO-1-SN as fallback
    if context.ts_stride.is_some() {
        let implicit_ts_for_sn_fallback = match implicit_ts_if_stride_set {
            Some(ts) => ts,
            None => {
                // This implies sn_delta might not have been positive when implicit_ts_if_stride_set was calculated,
                // or stride got broken. If stride is still Some now, recalculate with current_sn_delta.
                let current_sn_delta_for_fallback =
                    current_sn.wrapping_sub(context.last_sent_rtp_sn_full);
                Timestamp::new(context.last_sent_rtp_ts_full.value().wrapping_add(
                    current_sn_delta_for_fallback as u32 * context.ts_stride.unwrap_or(0),
                ))
            }
        };
        let packet = build_uo1_sn(context, current_sn, current_marker, crc_calculators)?;
        return Ok((packet, implicit_ts_for_sn_fallback));
    }

    // If no suitable UO packet type is found and no stride is established for UO-1-SN fallback.
    Err(RohcError::InvalidState(
        "No suitable UO packet type and no stride for UO-1-SN".to_string(),
    ))
}

/// Updates compressor mode from FirstOrder to SecondOrder if threshold is met.
fn update_compressor_mode(context: &mut Profile1CompressorContext) {
    if context.mode == Profile1CompressorMode::FirstOrder {
        context.consecutive_fo_packets_sent = context.consecutive_fo_packets_sent.saturating_add(1);
        if context.consecutive_fo_packets_sent >= P1_COMPRESSOR_FO_TO_SO_THRESHOLD {
            context.mode = Profile1CompressorMode::SecondOrder;
            context.consecutive_fo_packets_sent = 0;
        }
    }
}

/// Builds a ROHC Profile 1 UO-0 packet.
fn build_uo0(
    context: &Profile1CompressorContext,
    current_sn: u16,
    ts_for_crc: Timestamp, // This is the TS value used in CRC calculation.
    crc_calculators: &CrcCalculators,
) -> Result<Vec<u8>, RohcError> {
    let sn_lsb = encode_lsb(current_sn as u64, P1_UO0_SN_LSB_WIDTH_DEFAULT)? as u8;
    let crc_input_bytes = prepare_generic_uo_crc_input_payload(
        context.rtp_ssrc,
        current_sn,
        ts_for_crc,
        context.last_sent_rtp_marker, // UO-0 implies marker is unchanged from context.
    );
    let crc3 = crc_calculators.calculate_rohc_crc3(&crc_input_bytes);

    let uo0_data = Uo0Packet {
        cid: context.get_small_cid_for_packet(),
        sn_lsb,
        crc3,
    };
    build_profile1_uo0_packet(&uo0_data).map_err(RohcError::Building)
}

/// Builds a ROHC Profile 1 UO-1-TS packet.
fn build_uo1_ts(
    context: &mut Profile1CompressorContext, // Mutable for update_ts_stride_detection.
    current_sn: u16,
    current_ts: Timestamp,
    crc_calculators: &CrcCalculators,
) -> Result<Vec<u8>, RohcError> {
    let ts_lsb = encode_lsb(current_ts.value() as u64, P1_UO1_TS_LSB_WIDTH_DEFAULT)? as u16;
    let crc_input_bytes = prepare_generic_uo_crc_input_payload(
        context.rtp_ssrc,
        current_sn, // UO-1-TS implies SN+1, so current_sn should be context.last_sn + 1.
        current_ts,
        context.last_sent_rtp_marker, // UO-1-TS implies marker is unchanged from context.
    );
    let crc8 = crc_calculators.calculate_rohc_crc8(&crc_input_bytes);

    let uo1_packet_data = Uo1Packet {
        cid: context.get_small_cid_for_packet(),
        marker: false, // UO-1-TS specific: M bit in type is 0. Actual marker is from context.
        ts_lsb: Some(ts_lsb),
        num_ts_lsb_bits: Some(P1_UO1_TS_LSB_WIDTH_DEFAULT),
        crc8,
        ..Default::default()
    };
    build_profile1_uo1_ts_packet(&uo1_packet_data).map_err(RohcError::Building)
}

/// Builds a ROHC Profile 1 UO-1-SN packet.
fn build_uo1_sn(
    context: &Profile1CompressorContext,
    current_sn: u16,
    current_marker: bool,
    crc_calculators: &CrcCalculators,
) -> Result<Vec<u8>, RohcError> {
    debug_assert!(
        context.ts_stride.is_some(),
        "UO-1-SN build logic called without established TS_STRIDE in context."
    );

    let sn_lsb_val = encode_lsb(current_sn as u64, P1_UO1_SN_LSB_WIDTH_DEFAULT)? as u16;

    // Calculate implicit timestamp based on stride for CRC.
    let sn_delta_for_ts = current_sn.wrapping_sub(context.last_sent_rtp_sn_full);
    let implicit_ts_for_crc = if let Some(stride_val) = context.ts_stride {
        Timestamp::new(
            context
                .last_sent_rtp_ts_full
                .value()
                .wrapping_add(sn_delta_for_ts as u32 * stride_val),
        )
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
    let calculated_crc8 = crc_calculators.calculate_rohc_crc8(&crc_input_bytes);

    let uo1_sn_data = Uo1Packet {
        cid: context.get_small_cid_for_packet(),
        sn_lsb: sn_lsb_val,
        num_sn_lsb_bits: P1_UO1_SN_LSB_WIDTH_DEFAULT,
        marker: current_marker, // This is the marker bit set in the UO-1-SN type octet.
        crc8: calculated_crc8,
        ..Default::default()
    };
    build_profile1_uo1_sn_packet(&uo1_sn_data).map_err(RohcError::Building)
}

/// Builds a ROHC Profile 1 UO-1-ID packet.
fn build_uo1_id(
    context: &Profile1CompressorContext,
    current_sn: u16,
    current_ip_id: u16,
    crc_calculators: &CrcCalculators,
) -> Result<Vec<u8>, RohcError> {
    let ip_id_lsb_for_packet =
        encode_lsb(current_ip_id as u64, P1_UO1_IPID_LSB_WIDTH_DEFAULT)? as u8;

    // UO-1-ID implies SN+1 and unchanged TS (or TS follows stride for implicit update if stride known).
    // For CRC, it specifically uses the *last sent TS* from context if no stride,
    // or implicit TS if stride is present.
    // This function's caller (`select_and_build_uo_packet`) already filters for `!ts_changed`
    // or ensures `implicit_ts_if_stride_set` is compatible before choosing UO-1-ID.
    // For CRC, we need the effective TS based on these rules.
    let ts_for_crc = if let Some(stride_val) = context.ts_stride {
        // SN delta is implicitly 1 for UO-1-ID selection.
        Timestamp::new(
            context
                .last_sent_rtp_ts_full
                .value()
                .wrapping_add(stride_val),
        )
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
    let calculated_crc8 = crc_calculators.calculate_rohc_crc8(&crc_input_bytes);

    let uo1_id_packet_data = Uo1Packet {
        cid: context.get_small_cid_for_packet(),
        ip_id_lsb: Some(ip_id_lsb_for_packet as u16),
        num_ip_id_lsb_bits: Some(P1_UO1_IPID_LSB_WIDTH_DEFAULT),
        crc8: calculated_crc8,
        ..Default::default() // Marker is false in type byte, other LSBs None
    };
    build_profile1_uo1_id_packet(&uo1_id_packet_data).map_err(RohcError::Building)
}

/// Builds a ROHC Profile 1 UO-1-RTP packet.
fn build_uo1_rtp(
    context: &Profile1CompressorContext,
    current_sn: u16,
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
    let calculated_crc8 = crc_calculators.calculate_rohc_crc8(&crc_input_bytes);

    let uo1_rtp_data = Uo1Packet {
        cid: context.get_small_cid_for_packet(),
        marker: current_marker, // This is the marker bit set in the UO-1-RTP type octet.
        ts_scaled: Some(ts_scaled_val),
        crc8: calculated_crc8,
        ..Default::default() // Other LSB fields are not used by UO-1-RTP.
    };
    build_profile1_uo1_rtp_packet(&uo1_rtp_data).map_err(RohcError::Building)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crc::CrcCalculators;
    use crate::profiles::profile1::context::Profile1CompressorContext;
    use crate::profiles::profile1::protocol_types::{RtpUdpIpv4Headers, Timestamp};
    use std::time::Instant;

    fn create_test_context(
        ssrc: u32,
        last_sn: u16,
        last_ts: u32,
        last_marker: bool,
        last_ip_id: u16,
    ) -> Profile1CompressorContext {
        let mut context = Profile1CompressorContext::new(0, 20, Instant::now());
        context.rtp_ssrc = ssrc;
        context.last_sent_rtp_sn_full = last_sn;
        context.last_sent_rtp_ts_full = Timestamp::new(last_ts);
        context.last_sent_rtp_marker = last_marker;
        context.last_sent_ip_id_full = last_ip_id;
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
            rtp_ssrc: ssrc,
            rtp_sequence_number: sn,
            rtp_timestamp: Timestamp::new(ts),
            rtp_marker: marker,
            ip_identification: ip_id,
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
        context.ts_offset = Timestamp::new(1000);

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

        context.rtp_ssrc = 0; // Simulate initial state before SSRC is known
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
        assert_eq!(context.last_sent_rtp_ts_full, Timestamp::new(1160)); // Context TS updated based on packet's actual TS
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
        context.ts_offset = Timestamp::new(1000); // TS_Offset aligned with last_sent_ts_full for this test

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
        context.ts_offset = Timestamp::new(1000);

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
        let uo0 = build_uo0(
            &context_no_stride,
            101,
            Timestamp::new(1000),
            &crc_calculators,
        )
        .unwrap();
        assert_eq!(uo0.len(), 1);

        // UO-1-SN requires stride in context
        let mut context_with_stride = context_no_stride.clone();
        context_with_stride.ts_stride = Some(160);
        let uo1_sn = build_uo1_sn(&context_with_stride, 101, true, &crc_calculators).unwrap();
        assert_eq!(uo1_sn.len(), 3);

        // UO-1-TS
        let mut context_mut_for_ts = context_no_stride.clone();
        let uo1_ts = build_uo1_ts(
            &mut context_mut_for_ts,
            101,
            Timestamp::new(1160),
            &crc_calculators,
        )
        .unwrap();
        assert_eq!(uo1_ts.len(), 4);

        // UO-1-ID
        let uo1_id = build_uo1_id(&context_no_stride, 101, 11, &crc_calculators).unwrap();
        assert_eq!(uo1_id.len(), 3);

        // UO-1-RTP
        let mut context_scaled = context_no_stride.clone();
        context_scaled.ts_offset = Timestamp::new(1000); // Assume offset aligns for simplicity
        context_scaled.ts_stride = Some(160);
        let uo1_rtp = build_uo1_rtp(&context_scaled, 101, 1, false, &crc_calculators).unwrap();
        assert_eq!(uo1_rtp.len(), 3);
    }

    #[test]
    fn p1_min_wrapping_distance_works() {
        assert_eq!(min_wrapping_distance_u16(10, 5), 5);
        assert_eq!(min_wrapping_distance_u16(5, 10), 5);
        assert_eq!(min_wrapping_distance_u16(u16::MAX, 1), 2); // 65535 vs 1
        assert_eq!(min_wrapping_distance_u16(1, u16::MAX), 2);

        assert_eq!(min_wrapping_distance_u32(1000, 500), 500);
        assert_eq!(min_wrapping_distance_u32(500, 1000), 500);
        assert_eq!(min_wrapping_distance_u32(u32::MAX, 1), 2);
        assert_eq!(min_wrapping_distance_u32(1, u32::MAX), 2);
    }
}
