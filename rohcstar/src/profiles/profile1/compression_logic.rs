//! ROHC (Robust Header Compression) Profile 1 (RTP/UDP/IP) compression logic.
//!
//! This module handles the compression-side processing of packets according to ROHC Profile 1.
//! It determines which ROHC packet type to generate (IR, UO-0, UO-1-* variants) and builds
//! those packets based on packet changes and context state.

use super::constants::*;
use super::context::{Profile1CompressorContext, Profile1CompressorMode};
use super::packet_processor::{
    build_profile1_ir_packet, build_profile1_uo0_packet, build_profile1_uo1_id_packet,
    build_profile1_uo1_rtp_packet, build_profile1_uo1_sn_packet, build_profile1_uo1_ts_packet,
    prepare_generic_uo_crc_input_payload,
};
use super::packet_types::{IrPacket, Uo0Packet, Uo1Packet};
use super::protocol_types::{RtpUdpIpv4Headers, Timestamp};

use crate::crc::CrcCalculators;
use crate::encodings::encode_lsb;
use crate::error::RohcError;
use crate::packet_defs::RohcProfile;

/// Determines if an IR (Initialization/Refresh) packet must be sent by the compressor.
///
/// An IR packet is forced when the compressor needs to reset state or when field changes
/// would exceed the LSB encoding capabilities of UO packets, potentially causing
/// decompressor ambiguity.
///
/// # Parameters
/// - `context`: Reference to the current `Profile1CompressorContext`.
/// - `uncompressed_headers`: Reference to the current uncompressed headers.
///
/// # Returns
/// `true` if an IR packet should be sent, `false` otherwise.
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

    // Periodic IR refresh for reliability
    if context.ir_refresh_interval > 0
        && context.fo_packets_sent_since_ir >= context.ir_refresh_interval.saturating_sub(1)
    {
        return true;
    }

    // SSRC change forces new stream initialization
    if context.rtp_ssrc != uncompressed_headers.rtp_ssrc {
        return true;
    }

    // TS_SCALED mode failure indicates stride misalignment
    if context.ts_scaled_mode
        && context
            .calculate_ts_scaled(uncompressed_headers.rtp_timestamp)
            .is_none()
    {
        return true;
    }

    // Check for large field jumps that exceed LSB encoding windows
    // The k-bit LSB window is 2^k, unambiguous window is roughly 2^(k-1)
    let sn_k = P1_UO1_SN_LSB_WIDTH_DEFAULT;
    if sn_k > 0 && sn_k < 16 {
        let max_safe_sn_delta: u16 = (1u16 << (sn_k - 1)).saturating_sub(1);
        let current_sn = uncompressed_headers.rtp_sequence_number;
        let diff_sn_abs = current_sn.wrapping_sub(context.last_sent_rtp_sn_full);
        let diff_sn_abs_alt = context.last_sent_rtp_sn_full.wrapping_sub(current_sn);
        if core::cmp::min(diff_sn_abs, diff_sn_abs_alt) > max_safe_sn_delta {
            return true;
        }
    }

    // Only check TS jumps when not in scaled mode (scaled mode handles TS differently)
    let ts_k = P1_UO1_TS_LSB_WIDTH_DEFAULT;
    if !context.ts_scaled_mode && ts_k > 0 && ts_k < 32 {
        let max_safe_ts_delta: u32 = (1u32 << (ts_k - 1)).saturating_sub(1);
        let current_ts_val = uncompressed_headers.rtp_timestamp.value();
        let last_ts_val = context.last_sent_rtp_ts_full.value();
        let diff_ts_abs = current_ts_val.wrapping_sub(last_ts_val);
        let diff_ts_abs_alt = last_ts_val.wrapping_sub(current_ts_val);
        if core::cmp::min(diff_ts_abs, diff_ts_abs_alt) > max_safe_ts_delta {
            return true;
        }
    }

    // Check IP-ID jumps when it has changed
    if uncompressed_headers.ip_identification != context.last_sent_ip_id_full {
        let ipid_k = P1_UO1_IPID_LSB_WIDTH_DEFAULT;
        if ipid_k > 0 && ipid_k < 16 {
            let max_safe_ipid_delta: u16 = (1u16 << (ipid_k - 1)).saturating_sub(1);
            let current_ip_id = uncompressed_headers.ip_identification;
            let diff_ipid_abs = current_ip_id.wrapping_sub(context.last_sent_ip_id_full);
            let diff_ipid_abs_alt = context.last_sent_ip_id_full.wrapping_sub(current_ip_id);
            if core::cmp::min(diff_ipid_abs, diff_ipid_abs_alt) > max_safe_ipid_delta {
                return true;
            }
        }
    }
    false
}

/// Prepares and builds an IR or IR-DYN packet.
///
/// This function handles TS stride detection and updates compressor state after successful
/// IR transmission. It assumes SSRC change detection has already been handled by the caller.
///
/// # Parameters
/// - `context`: The mutable compressor context.
/// - `uncompressed_headers`: The headers of the packet to compress as IR.
/// - `crc_calculators`: Reference to `CrcCalculators` for CRC computation.
///
/// # Returns
/// - `Ok(Vec<u8>)` containing the compressed IR packet.
/// - `Err(RohcError)` if building the IR packet fails.
pub(super) fn compress_as_ir(
    context: &mut Profile1CompressorContext,
    uncompressed_headers: &RtpUdpIpv4Headers,
    crc_calculators: &CrcCalculators,
) -> Result<Vec<u8>, RohcError> {
    debug_assert_eq!(
        context.rtp_ssrc, uncompressed_headers.rtp_ssrc,
        "SSRC mismatch in compress_as_ir; context should have been initialized."
    );
    debug_assert_ne!(context.rtp_ssrc, 0, "Context SSRC must be non-zero.");

    // Only establish stride for IR if it was forced by stride misalignment
    let newly_activated_scaled_mode = if context.ts_scaled_mode {
        // Reset scaled mode and start detecting new stride
        context.ts_scaled_mode = false;
        context.update_ts_stride_detection(uncompressed_headers.rtp_timestamp)
    } else {
        false
    };

    let ir_packet_signals_ts_stride: Option<u32> = if context.ts_scaled_mode {
        context.ts_stride
    } else {
        None
    };

    let ir_data = IrPacket {
        cid: context.cid,
        profile_id: RohcProfile::RtpUdpIp,
        crc8: 0,
        static_ip_src: context.ip_source,
        static_ip_dst: context.ip_destination,
        static_udp_src_port: context.udp_source_port,
        static_udp_dst_port: context.udp_destination_port,
        static_rtp_ssrc: context.rtp_ssrc,
        dyn_rtp_sn: uncompressed_headers.rtp_sequence_number,
        dyn_rtp_timestamp: uncompressed_headers.rtp_timestamp,
        dyn_rtp_marker: uncompressed_headers.rtp_marker,
        ts_stride: ir_packet_signals_ts_stride,
    };

    let rohc_packet_bytes =
        build_profile1_ir_packet(&ir_data, crc_calculators).map_err(RohcError::Building)?;

    // Update context state after successful IR transmission
    context.last_sent_rtp_sn_full = uncompressed_headers.rtp_sequence_number;
    context.last_sent_rtp_ts_full = uncompressed_headers.rtp_timestamp;
    context.last_sent_rtp_marker = uncompressed_headers.rtp_marker;
    context.last_sent_ip_id_full = uncompressed_headers.ip_identification;

    context.mode = Profile1CompressorMode::FirstOrder;
    context.fo_packets_sent_since_ir = 0;
    context.consecutive_fo_packets_sent = 0;

    // Update ts_offset when establishing new stride
    if ir_packet_signals_ts_stride.is_some() || newly_activated_scaled_mode {
        context.ts_offset = uncompressed_headers.rtp_timestamp;
    }

    Ok(rohc_packet_bytes)
}

/// Handles compressor logic for sending UO (Unidirectional Optimistic) packets.
///
/// Selects the most appropriate UO packet type based on changes between current headers
/// and compressor state. Priority order: UO-1-RTP > UO-0 > UO-1-TS > UO-1-ID > UO-1-SN.
///
/// # Parameters
/// - `context`: The mutable compressor context.
/// - `uncompressed_headers`: The headers of the packet to compress as UO.
/// - `crc_calculators`: Reference to `CrcCalculators` for CRC computation.
///
/// # Returns
/// - `Ok(Vec<u8>)` containing the compressed UO packet.
/// - `Err(RohcError)` if LSB encoding or building the selected UO packet fails.
pub(super) fn compress_as_uo(
    context: &mut Profile1CompressorContext,
    uncompressed_headers: &RtpUdpIpv4Headers,
    crc_calculators: &CrcCalculators,
) -> Result<Vec<u8>, RohcError> {
    debug_assert_eq!(
        context.rtp_ssrc, uncompressed_headers.rtp_ssrc,
        "SSRC mismatch in compress_as_uo"
    );
    debug_assert_ne!(context.rtp_ssrc, 0, "Context SSRC must be non-zero.");

    let current_sn = uncompressed_headers.rtp_sequence_number;
    let current_ts = uncompressed_headers.rtp_timestamp;
    let current_marker = uncompressed_headers.rtp_marker;
    let current_ip_id = uncompressed_headers.ip_identification;

    let sn_diff = current_sn.wrapping_sub(context.last_sent_rtp_sn_full);
    let marker_changed = current_marker != context.last_sent_rtp_marker;
    let ts_changed = current_ts != context.last_sent_rtp_ts_full;
    let ip_id_changed = current_ip_id != context.last_sent_ip_id_full;
    let sn_incremented_by_one = sn_diff == 1;

    // Validate existing stride for packets that will use input TS explicitly
    if let Some(existing_stride) = context.ts_stride {
        let ts_diff = current_ts.wrapping_diff(context.last_sent_rtp_ts_full);
        let will_use_input_ts =
            !marker_changed && ts_changed && sn_incremented_by_one && !ip_id_changed;

        if will_use_input_ts && ts_diff > 0 && sn_diff > 0 && ts_diff % existing_stride != 0 {
            // Stride broken - reset to normal mode
            context.ts_stride = None;
            context.ts_scaled_mode = false;
            context.ts_stride_packets = 0;
        }
    }

    // Pre-calculate implicit timestamp for UO-1-SN packets
    let implicit_ts_for_uo1_sn = if let Some(ts_stride) = context.ts_stride {
        let ts_delta = sn_diff as u32 * ts_stride;
        Timestamp::new(context.last_sent_rtp_ts_full.value().wrapping_add(ts_delta))
    } else {
        context.last_sent_rtp_ts_full
    };

    // Packet selection logic based on RFC 3095 rules
    let (final_rohc_packet_bytes, actual_ts_for_context) =
        if context.ts_scaled_mode && sn_incremented_by_one && !ip_id_changed {
            // UO-1-RTP: TS_Scaled mode active, SN increments by 1, IP-ID unchanged
            if let Some(ts_scaled_val) = context.calculate_ts_scaled(current_ts) {
                let packet = build_uo1_rtp(
                    context,
                    current_sn,
                    ts_scaled_val,
                    current_marker,
                    crc_calculators,
                )?;
                (packet, current_ts)
            } else {
                // TS_SCALED calculation failed - fallback to UO-1-SN
                let packet = build_uo1_sn(context, current_sn, current_marker, crc_calculators)?;
                (packet, implicit_ts_for_uo1_sn)
            }
        } else if !marker_changed && sn_diff > 0 && sn_diff < 16 && !ts_changed && !ip_id_changed {
            // UO-0: Marker same, SN encodable in 4 bits, TS same, IP-ID same
            let packet = build_uo0(context, current_sn, crc_calculators)?;
            (packet, context.last_sent_rtp_ts_full)
        } else if !marker_changed && ts_changed && sn_incremented_by_one && !ip_id_changed {
            // UO-1-TS: Marker same, TS changed, SN increments by 1, IP-ID same
            let _ = context.update_ts_stride_detection(current_ts);
            let packet = build_uo1_ts(context, current_sn, current_ts, crc_calculators)?;
            (packet, current_ts)
        } else if !marker_changed && ip_id_changed && sn_incremented_by_one && !ts_changed {
            // UO-1-ID: Marker same, IP-ID changed, SN increments by 1, TS same
            let packet = build_uo1_id(context, current_sn, current_ip_id, crc_calculators)?;
            (packet, context.last_sent_rtp_ts_full)
        } else {
            // UO-1-SN: Fallback for SN jumps, marker changes, etc.
            let packet = build_uo1_sn(context, current_sn, current_marker, crc_calculators)?;
            (packet, implicit_ts_for_uo1_sn)
        };

    // Update context with packet-specific timestamps
    context.last_sent_rtp_sn_full = current_sn;
    context.last_sent_rtp_ts_full = actual_ts_for_context;
    context.last_sent_rtp_marker = current_marker;
    context.last_sent_ip_id_full = current_ip_id;

    // Transition from First Order to Second Order mode
    if context.mode == Profile1CompressorMode::FirstOrder {
        context.consecutive_fo_packets_sent = context.consecutive_fo_packets_sent.saturating_add(1);
        if context.consecutive_fo_packets_sent >= P1_COMPRESSOR_FO_TO_SO_THRESHOLD {
            context.mode = Profile1CompressorMode::SecondOrder;
            context.consecutive_fo_packets_sent = 0;
        }
    }
    context.fo_packets_sent_since_ir = context.fo_packets_sent_since_ir.saturating_add(1);

    Ok(final_rohc_packet_bytes)
}

/// Builds a ROHC Profile 1 UO-0 packet.
fn build_uo0(
    context: &mut Profile1CompressorContext,
    current_sn: u16,
    crc_calculators: &CrcCalculators,
) -> Result<Vec<u8>, RohcError> {
    let sn_lsb_val = encode_lsb(current_sn as u64, P1_UO0_SN_LSB_WIDTH_DEFAULT)? as u8;
    let crc_input_bytes = prepare_generic_uo_crc_input_payload(
        context.rtp_ssrc,
        current_sn,
        context.last_sent_rtp_ts_full,
        context.last_sent_rtp_marker,
    );
    let crc3_val = crc_calculators.calculate_rohc_crc3(&crc_input_bytes);
    let uo0_data = Uo0Packet {
        cid: context.get_small_cid_for_packet(),
        sn_lsb: sn_lsb_val,
        crc3: crc3_val,
    };
    build_profile1_uo0_packet(&uo0_data).map_err(RohcError::Building)
}

/// Builds a ROHC Profile 1 UO-1-TS packet.
fn build_uo1_ts(
    context: &mut Profile1CompressorContext,
    current_sn: u16,
    current_ts: Timestamp,
    crc_calculators: &CrcCalculators,
) -> Result<Vec<u8>, RohcError> {
    let ts_lsb_val = encode_lsb(current_ts.value() as u64, P1_UO1_TS_LSB_WIDTH_DEFAULT)? as u16;
    let crc_input_bytes = prepare_generic_uo_crc_input_payload(
        context.rtp_ssrc,
        current_sn,
        current_ts,
        context.last_sent_rtp_marker,
    );
    let calculated_crc8 = crc_calculators.calculate_rohc_crc8(&crc_input_bytes);
    let uo1_ts_packet_data = Uo1Packet {
        cid: context.get_small_cid_for_packet(),
        marker: false,
        ts_lsb: Some(ts_lsb_val),
        num_ts_lsb_bits: Some(P1_UO1_TS_LSB_WIDTH_DEFAULT),
        crc8: calculated_crc8,
        ..Default::default()
    };
    build_profile1_uo1_ts_packet(&uo1_ts_packet_data).map_err(RohcError::Building)
}

/// Builds a ROHC Profile 1 UO-1-SN packet.
fn build_uo1_sn(
    context: &mut Profile1CompressorContext,
    current_sn: u16,
    current_marker: bool,
    crc_calculators: &CrcCalculators,
) -> Result<Vec<u8>, RohcError> {
    let sn_lsb_val = encode_lsb(current_sn as u64, P1_UO1_SN_LSB_WIDTH_DEFAULT)? as u16;

    let sn_delta = current_sn.wrapping_sub(context.last_sent_rtp_sn_full);
    let implicit_ts = if let Some(ts_stride) = context.ts_stride {
        let ts_delta = sn_delta as u32 * ts_stride;
        Timestamp::new(context.last_sent_rtp_ts_full.value().wrapping_add(ts_delta))
    } else {
        context.last_sent_rtp_ts_full
    };

    let crc_input_bytes = prepare_generic_uo_crc_input_payload(
        context.rtp_ssrc,
        current_sn,
        implicit_ts,
        current_marker,
    );
    let calculated_crc8 = crc_calculators.calculate_rohc_crc8(&crc_input_bytes);
    let uo1_sn_data = Uo1Packet {
        cid: context.get_small_cid_for_packet(),
        sn_lsb: sn_lsb_val,
        num_sn_lsb_bits: P1_UO1_SN_LSB_WIDTH_DEFAULT,
        marker: current_marker,
        crc8: calculated_crc8,
        ..Default::default()
    };
    build_profile1_uo1_sn_packet(&uo1_sn_data).map_err(RohcError::Building)
}

/// Builds a ROHC Profile 1 UO-1-ID packet.
fn build_uo1_id(
    context: &mut Profile1CompressorContext,
    current_sn: u16,
    current_ip_id: u16,
    crc_calculators: &CrcCalculators,
) -> Result<Vec<u8>, RohcError> {
    let ip_id_lsb_for_packet_field =
        encode_lsb(current_ip_id as u64, P1_UO1_IPID_LSB_WIDTH_DEFAULT)? as u8;
    let crc_input_bytes = build_uo1_id_specific_crc_input(
        context.rtp_ssrc,
        current_sn,
        context.last_sent_rtp_ts_full,
        context.last_sent_rtp_marker,
        ip_id_lsb_for_packet_field,
    );
    let calculated_crc8 = crc_calculators.calculate_rohc_crc8(&crc_input_bytes);
    let uo1_id_packet_data = Uo1Packet {
        cid: context.get_small_cid_for_packet(),
        ip_id_lsb: Some(ip_id_lsb_for_packet_field as u16),
        num_ip_id_lsb_bits: Some(P1_UO1_IPID_LSB_WIDTH_DEFAULT),
        crc8: calculated_crc8,
        ..Default::default()
    };
    build_profile1_uo1_id_packet(&uo1_id_packet_data).map_err(RohcError::Building)
}

/// Builds a ROHC Profile 1 UO-1-RTP packet.
fn build_uo1_rtp(
    context: &Profile1CompressorContext,
    current_sn: u16,
    ts_scaled_val: u8,
    current_marker: bool,
    crc_calculators: &CrcCalculators,
) -> Result<Vec<u8>, RohcError> {
    let stride = context.ts_stride.ok_or_else(|| {
        RohcError::Internal("TS stride missing in scaled mode during UO-1-RTP build.".to_string())
    })?;
    debug_assert!(stride > 0, "TS Stride must be positive to build UO-1-RTP");

    // Reconstruct full TS value for CRC calculation
    let full_ts_for_crc = context
        .ts_offset
        .wrapping_add(ts_scaled_val as u32 * stride);

    let crc_input_bytes = prepare_generic_uo_crc_input_payload(
        context.rtp_ssrc,
        current_sn,
        full_ts_for_crc,
        current_marker,
    );
    let calculated_crc8 = crc_calculators.calculate_rohc_crc8(&crc_input_bytes);

    let uo1_rtp_data = Uo1Packet {
        cid: context.get_small_cid_for_packet(),
        marker: current_marker,
        ts_scaled: Some(ts_scaled_val),
        crc8: calculated_crc8,
        ..Default::default()
    };
    build_profile1_uo1_rtp_packet(&uo1_rtp_data).map_err(RohcError::Building)
}

/// Creates byte slice input specifically for UO-1-ID packet CRC calculation.
///
/// Input format: SSRC (4B), SN (2B), TS (4B), Marker (1B), IP-ID_LSB (1B) = 12 bytes total.
fn build_uo1_id_specific_crc_input(
    context_ssrc: u32,
    sn_for_crc: u16,
    ts_for_crc: Timestamp,
    marker_for_crc: bool,
    ip_id_lsb_for_crc: u8,
) -> Vec<u8> {
    let mut crc_input = Vec::with_capacity(P1_UO_CRC_INPUT_LENGTH_BYTES + 1);
    crc_input.extend_from_slice(&context_ssrc.to_be_bytes());
    crc_input.extend_from_slice(&sn_for_crc.to_be_bytes());
    crc_input.extend_from_slice(&ts_for_crc.to_be_bytes());
    crc_input.push(if marker_for_crc { 0x01 } else { 0x00 });
    crc_input.push(ip_id_lsb_for_crc);
    debug_assert_eq!(crc_input.len(), P1_UO_CRC_INPUT_LENGTH_BYTES + 1);
    crc_input
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crc::CrcCalculators;
    use crate::profiles::profile1::context::Profile1CompressorContext;
    use crate::profiles::profile1::protocol_types::{RtpUdpIpv4Headers, Timestamp};
    use std::time::Instant;

    fn create_comp_context(
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
        context.mode = Profile1CompressorMode::FirstOrder; // Default to FO for UO tests
        context
    }

    fn create_rtp_headers(
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
            ..Default::default()
        }
    }

    #[test]
    fn should_force_ir_basic_conditions() {
        let mut context = create_comp_context(1, 100, 1000, false, 10);
        let headers = create_rtp_headers(1, 101, 1000, false, 10); // Same SSRC

        context.mode = Profile1CompressorMode::InitializationAndRefresh;
        assert!(should_force_ir(&context, &headers), "IR due to mode");
        context.mode = Profile1CompressorMode::FirstOrder;

        context.ir_refresh_interval = 5;
        context.fo_packets_sent_since_ir = 4;
        assert!(
            should_force_ir(&context, &headers),
            "IR due to refresh interval"
        );
        context.fo_packets_sent_since_ir = 3;

        let headers_ssrc_change = create_rtp_headers(2, 101, 1000, false, 10); // Different SSRC
        assert!(
            should_force_ir(&context, &headers_ssrc_change),
            "IR due to SSRC change"
        );
    }

    #[test]
    fn should_force_ir_scaled_mode_ts_misaligned() {
        let mut context = create_comp_context(1, 100, 1000, false, 10);
        context.ts_scaled_mode = true;
        context.ts_stride = Some(160);
        context.ts_offset = Timestamp::new(1000);
        let headers_misaligned_ts = create_rtp_headers(1, 101, 1000 + 80, false, 10); // TS not multiple of stride from offset
        assert!(
            should_force_ir(&context, &headers_misaligned_ts),
            "IR due to TS misaligned in scaled mode"
        );
    }

    #[test]
    fn should_force_ir_large_sn_jump() {
        let context = create_comp_context(1, 100, 1000, false, 10);
        let headers_large_sn_jump = create_rtp_headers(
            1,
            100 + (1 << (P1_UO1_SN_LSB_WIDTH_DEFAULT - 1)),
            1000,
            false,
            10,
        );
        assert!(
            should_force_ir(&context, &headers_large_sn_jump),
            "IR due to large SN jump"
        );
    }

    #[test]
    fn should_force_ir_large_ts_jump_non_scaled() {
        let mut context = create_comp_context(1, 100, 1000, false, 10);
        context.ts_scaled_mode = false;
        let headers_large_ts_jump = create_rtp_headers(
            1,
            101,
            1000 + (1 << (P1_UO1_TS_LSB_WIDTH_DEFAULT - 1)),
            false,
            10,
        );
        assert!(
            should_force_ir(&context, &headers_large_ts_jump),
            "IR due to large TS jump"
        );
    }

    #[test]
    fn should_force_ir_large_ip_id_jump() {
        let context = create_comp_context(1, 100, 1000, false, 10);
        let headers_large_ip_id_jump = create_rtp_headers(
            1,
            101,
            1000,
            false,
            10 + (1 << (P1_UO1_IPID_LSB_WIDTH_DEFAULT - 1)),
        );
        assert!(
            should_force_ir(&context, &headers_large_ip_id_jump),
            "IR due to large IP_ID jump"
        );
    }

    #[test]
    fn compress_as_ir_updates_context() {
        let crc_calculators = CrcCalculators::new();
        let mut context = create_comp_context(0, 0, 0, false, 0); // SSRC 0 forces init
        let headers = create_rtp_headers(1, 100, 1000, true, 50);
        context.initialize_context_from_uncompressed_headers(&headers); // Simulate SSRC change init

        let _ = compress_as_ir(&mut context, &headers, &crc_calculators).unwrap();

        assert_eq!(context.mode, Profile1CompressorMode::FirstOrder);
        assert_eq!(context.last_sent_rtp_sn_full, headers.rtp_sequence_number);
        assert_eq!(context.last_sent_rtp_ts_full, headers.rtp_timestamp);
        assert_eq!(context.last_sent_rtp_marker, headers.rtp_marker);
        assert_eq!(context.last_sent_ip_id_full, headers.ip_identification);
        assert_eq!(context.fo_packets_sent_since_ir, 0);
    }

    #[test]
    fn compress_as_uo_selects_uo0() {
        let crc_calculators = CrcCalculators::new();
        let mut context = create_comp_context(1, 100, 1000, false, 10);
        let headers = create_rtp_headers(1, 101, 1000, false, 10); // UO-0 conditions

        let packet = compress_as_uo(&mut context, &headers, &crc_calculators).unwrap();
        assert_eq!(packet.len(), 1, "Packet length for UO-0"); // CID 0 implies no Add-CID
        assert!((packet[0] & 0x80) == 0, "UO-0 discriminator");
    }

    #[test]
    fn compress_as_uo_selects_uo1_sn_on_marker_change() {
        let crc_calculators = CrcCalculators::new();
        let mut context = create_comp_context(1, 100, 1000, false, 10);
        let headers = create_rtp_headers(1, 101, 1000, true, 10); // Marker changes

        let packet = compress_as_uo(&mut context, &headers, &crc_calculators).unwrap();
        assert_eq!(packet.len(), 3, "Packet length for UO-1-SN");
        assert_eq!(
            packet[0] & P1_UO_1_SN_PACKET_TYPE_PREFIX,
            P1_UO_1_SN_PACKET_TYPE_PREFIX
        );
        assert_ne!(packet[0] & P1_UO_1_SN_MARKER_BIT_MASK, 0); // Marker should be set
    }

    #[test]
    fn compress_as_uo_selects_uo1_ts_on_ts_change() {
        let crc_calculators = CrcCalculators::new();
        let mut context = create_comp_context(1, 100, 1000, false, 10);
        let headers = create_rtp_headers(
            1,
            101,
            1000 + P1_TS_STRIDE_ESTABLISHMENT_THRESHOLD * 10,
            false,
            10,
        ); // TS changes, SN+1

        let packet = compress_as_uo(&mut context, &headers, &crc_calculators).unwrap();
        assert_eq!(packet.len(), 4, "Packet length for UO-1-TS");
        assert_eq!(packet[0], P1_UO_1_TS_DISCRIMINATOR);
    }

    #[test]
    fn compress_as_uo_selects_uo1_id_on_ip_id_change() {
        let crc_calculators = CrcCalculators::new();
        let mut context = create_comp_context(1, 100, 1000, false, 10);
        let headers = create_rtp_headers(1, 101, 1000, false, 10 + 1); // IP-ID changes, SN+1

        let packet = compress_as_uo(&mut context, &headers, &crc_calculators).unwrap();
        assert_eq!(packet.len(), 3, "Packet length for UO-1-ID");
        assert_eq!(packet[0], P1_UO_1_ID_DISCRIMINATOR);
    }

    #[test]
    fn compress_as_uo_selects_uo1_rtp_in_scaled_mode() {
        let crc_calculators = CrcCalculators::new();
        let mut context = create_comp_context(1, 100, 1000, false, 10);
        context.ts_scaled_mode = true;
        context.ts_stride = Some(160);
        context.ts_offset = Timestamp::new(1000);
        // current_ts = offset + 1 * stride
        let headers = create_rtp_headers(1, 101, 1000 + 160, false, 10); // SN+1, conditions for TS_SCALED=1

        let packet = compress_as_uo(&mut context, &headers, &crc_calculators).unwrap();
        assert_eq!(packet.len(), 3, "Packet length for UO-1-RTP");
        assert_eq!(
            packet[0] & !P1_UO_1_RTP_MARKER_BIT_MASK,
            P1_UO_1_RTP_DISCRIMINATOR_BASE
        );
        assert_eq!(packet[1], 1, "TS_SCALED should be 1");
    }

    #[test]
    fn helper_build_uo0_correct_format() {
        let mut context = create_comp_context(1, 100, 1000, false, 10);
        let crc_calculators = CrcCalculators::new();
        let result = build_uo0(&mut context, 101, &crc_calculators).unwrap();
        assert_eq!(result.len(), 1);
        // Further checks on byte values can be added if needed based on known CRC/SN_LSB
    }

    #[test]
    fn helper_build_uo1_sn_correct_format() {
        let mut context = create_comp_context(1, 100, 1000, false, 10);
        let crc_calculators = CrcCalculators::new();
        let result = build_uo1_sn(&mut context, 101, true, &crc_calculators).unwrap();
        assert_eq!(result.len(), 3);
        assert_eq!(
            result[0] & P1_UO_1_SN_PACKET_TYPE_PREFIX,
            P1_UO_1_SN_PACKET_TYPE_PREFIX
        );
        assert_ne!(result[0] & P1_UO_1_SN_MARKER_BIT_MASK, 0);
    }

    #[test]
    fn helper_build_uo1_ts_correct_format() {
        let mut context = create_comp_context(1, 100, 1000, false, 10);
        let crc_calculators = CrcCalculators::new();
        let result =
            build_uo1_ts(&mut context, 101, Timestamp::new(1160), &crc_calculators).unwrap();
        assert_eq!(result.len(), 4);
        assert_eq!(result[0], P1_UO_1_TS_DISCRIMINATOR);
    }

    #[test]
    fn helper_build_uo1_id_correct_format() {
        let mut context = create_comp_context(1, 100, 1000, false, 10);
        let crc_calculators = CrcCalculators::new();
        let result = build_uo1_id(&mut context, 101, 11, &crc_calculators).unwrap();
        assert_eq!(result.len(), 3);
        assert_eq!(result[0], P1_UO_1_ID_DISCRIMINATOR);
    }

    #[test]
    fn helper_build_uo1_rtp_correct_format() {
        let mut context = create_comp_context(1, 100, 1000, false, 10);
        context.ts_offset = Timestamp::new(1000); // Assume offset is last_ts for simplicity here
        context.ts_stride = Some(160);
        let crc_calculators = CrcCalculators::new();
        let result = build_uo1_rtp(&context, 101, 1, false, &crc_calculators).unwrap();
        assert_eq!(result.len(), 3);
        assert_eq!(
            result[0] & !P1_UO_1_RTP_MARKER_BIT_MASK,
            P1_UO_1_RTP_DISCRIMINATOR_BASE
        );
        assert_eq!(result[1], 1);
    }
}
