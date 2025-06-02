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
    prepare_generic_uo_crc_input_payload, prepare_uo1_id_specific_crc_input_payload,
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

    if context.ts_scaled_mode {
        if context.ts_stride.is_none() {
            // Inconsistent state: scaled mode active but no stride known.
            return true;
        }
        if context
            .calculate_ts_scaled(uncompressed_headers.rtp_timestamp)
            .is_none()
        {
            // TS_SCALED calculation failed (e.g. misaligned, overflow), needs IR to resync/signal.
            return true;
        }
    }

    // Check for large field jumps that exceed LSB encoding windows
    // The k-bit LSB window is 2^k, unambiguous window is roughly 2^(k-1)
    let sn_k = P1_UO1_SN_LSB_WIDTH_DEFAULT;
    if sn_k > 0 && sn_k < 16 {
        // Valid LSB width range for this check
        let max_safe_sn_delta: u16 = (1u16 << (sn_k - 1)).saturating_sub(1);
        let current_sn = uncompressed_headers.rtp_sequence_number;
        let diff_sn_abs = current_sn.wrapping_sub(context.last_sent_rtp_sn_full);
        let diff_sn_abs_alt = context.last_sent_rtp_sn_full.wrapping_sub(current_sn);
        if core::cmp::min(diff_sn_abs, diff_sn_abs_alt) > max_safe_sn_delta {
            return true;
        }
    }

    let ts_k = P1_UO1_TS_LSB_WIDTH_DEFAULT;
    if !context.ts_scaled_mode && ts_k > 0 && ts_k < 32 {
        // Check only if not in scaled mode
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

    let previous_ts_before_ir = context.last_sent_rtp_ts_full;

    let ts_stride_active = context.ts_stride.is_none();
    let was_scaled_mode_problem = context.ts_scaled_mode
        && (ts_stride_active
            || context
                .calculate_ts_scaled(uncompressed_headers.rtp_timestamp)
                .is_none());

    let ir_packet_signals_ts_stride = if was_scaled_mode_problem {
        context.ts_scaled_mode = false;
        context.ts_stride = None;
        context.ts_offset = Timestamp::new(0);
        context.ts_stride_packets = 0;
        None
    } else {
        let stride_confirmed = context.ts_scaled_mode
            || context.ts_stride_packets >= P1_TS_STRIDE_ESTABLISHMENT_THRESHOLD;
        context.ts_stride.filter(|_| stride_confirmed)
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

    // Standard context updates for any IR
    context.last_sent_rtp_sn_full = uncompressed_headers.rtp_sequence_number;
    context.last_sent_rtp_ts_full = uncompressed_headers.rtp_timestamp;
    context.last_sent_rtp_marker = uncompressed_headers.rtp_marker;
    context.last_sent_ip_id_full = uncompressed_headers.ip_identification;

    context.mode = Profile1CompressorMode::FirstOrder;
    context.fo_packets_sent_since_ir = 0;
    context.consecutive_fo_packets_sent = 0;

    // Update ts_offset when establishing new stride
    if ir_packet_signals_ts_stride.is_some() {
        context.ts_offset = uncompressed_headers.rtp_timestamp;
        context.ts_scaled_mode = true;
    } else if was_scaled_mode_problem {
        // Scaled mode was turned off, stride info was reset.
        let original_last_ts = context.last_sent_rtp_ts_full;
        context.last_sent_rtp_ts_full = previous_ts_before_ir;
        context.update_ts_stride_detection(uncompressed_headers.rtp_timestamp);
        context.last_sent_rtp_ts_full = original_last_ts;
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

    let sn_delta = current_sn.wrapping_sub(context.last_sent_rtp_sn_full);
    let marker_changed = current_marker != context.last_sent_rtp_marker;
    let ts_changed_explicitly = current_ts != context.last_sent_rtp_ts_full;
    let ip_id_changed = current_ip_id != context.last_sent_ip_id_full;
    let sn_incremented_by_one = sn_delta == 1;

    let implicit_ts_if_stride = if let Some(stride) = context.ts_stride {
        if sn_delta > 0 {
            Some(Timestamp::new(
                context
                    .last_sent_rtp_ts_full
                    .value()
                    .wrapping_add(sn_delta as u32 * stride),
            ))
        } else {
            None
        }
    } else {
        None
    };

    let (final_rohc_packet_bytes, actual_ts_for_context_update) = if context.ts_scaled_mode
        && sn_incremented_by_one
        && !ip_id_changed
    {
        if let Some(ts_scaled_val) = context.calculate_ts_scaled(current_ts) {
            let packet = build_uo1_rtp(
                context,
                current_sn,
                ts_scaled_val,
                current_marker,
                crc_calculators,
            )?;
            (packet, current_ts)
        } else if context.ts_stride.is_some() {
            let implicit_ts = implicit_ts_if_stride
                .expect("Stride exists, so implicit_ts must be Some for positive sn_delta");
            let packet = build_uo1_sn(context, current_sn, current_marker, crc_calculators)?;
            (packet, implicit_ts)
        } else {
            return Err(RohcError::InvalidState(
                "TS_SCALED mode failed, no TS_STRIDE for UO-1-SN fallback, and IR not forced."
                    .to_string(),
            ));
        }
    } else if !marker_changed
        && sn_delta > 0
        && sn_delta < 16
        && !ip_id_changed
        && context.ts_stride.is_some()
        && implicit_ts_if_stride == Some(current_ts)
    {
        let packet = build_uo0(context, current_sn, current_ts, crc_calculators)?;
        (packet, current_ts)
    } else if !marker_changed
        && sn_delta > 0
        && sn_delta < 16
        && !ts_changed_explicitly
        && !ip_id_changed
    {
        let packet = build_uo0(
            context,
            current_sn,
            context.last_sent_rtp_ts_full,
            crc_calculators,
        )?;
        (packet, context.last_sent_rtp_ts_full)
    } else if !marker_changed && ts_changed_explicitly && sn_incremented_by_one && !ip_id_changed {
        let _ = context.update_ts_stride_detection(current_ts);
        let packet = build_uo1_ts(context, current_sn, current_ts, crc_calculators)?;
        (packet, current_ts)
    } else if !marker_changed && ip_id_changed && sn_incremented_by_one && !ts_changed_explicitly {
        let packet = build_uo1_id(context, current_sn, current_ip_id, crc_calculators)?;
        (packet, context.last_sent_rtp_ts_full)
    } else if context.ts_stride.is_some() {
        let implicit_ts = implicit_ts_if_stride.unwrap_or(context.last_sent_rtp_ts_full);
        match build_uo1_sn(context, current_sn, current_marker, crc_calculators) {
            Ok(packet) => (packet, implicit_ts),
            Err(e) => {
                return Err(e);
            }
        }
    } else {
        return Err(RohcError::InvalidState(
        "No suitable UO packet type available and TS_STRIDE not established for UO-1-SN fallback.".to_string(),
    ));
    };

    // Update context with packet-specific timestamps
    context.last_sent_rtp_sn_full = current_sn;
    context.last_sent_rtp_ts_full = actual_ts_for_context_update;
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
    context: &Profile1CompressorContext,
    current_sn: u16,
    ts_for_crc: Timestamp,
    crc_calculators: &CrcCalculators,
) -> Result<Vec<u8>, RohcError> {
    let sn_lsb_val = encode_lsb(current_sn as u64, P1_UO0_SN_LSB_WIDTH_DEFAULT)? as u8;
    let crc_input_bytes = prepare_generic_uo_crc_input_payload(
        context.rtp_ssrc,
        current_sn,
        ts_for_crc,
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
    // UO-1-TS uses CRC-8
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
    context: &Profile1CompressorContext,
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
    context: &Profile1CompressorContext,
    current_sn: u16,
    current_ip_id: u16,
    crc_calculators: &CrcCalculators,
) -> Result<Vec<u8>, RohcError> {
    let ip_id_lsb_for_packet_field =
        encode_lsb(current_ip_id as u64, P1_UO1_IPID_LSB_WIDTH_DEFAULT)? as u8;

    let crc_input_bytes = prepare_uo1_id_specific_crc_input_payload(
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crc::CrcCalculators;
    use crate::profiles::profile1::context::Profile1CompressorContext;
    use crate::profiles::profile1::protocol_types::{RtpUdpIpv4Headers, Timestamp};
    use std::time::Instant;

    // Helper to create a compressor context pre-filled for tests.
    fn create_comp_context(
        ssrc: u32,
        last_sn: u16,
        last_ts: u32,
        last_marker: bool,
        last_ip_id: u16,
    ) -> Profile1CompressorContext {
        let mut context = Profile1CompressorContext::new(0, 20, Instant::now()); // Default CID 0, IR refresh 20
        context.rtp_ssrc = ssrc;
        context.last_sent_rtp_sn_full = last_sn;
        context.last_sent_rtp_ts_full = Timestamp::new(last_ts);
        context.last_sent_rtp_marker = last_marker;
        context.last_sent_ip_id_full = last_ip_id;
        context.mode = Profile1CompressorMode::FirstOrder; // Default to FirstOrder for most UO tests
        context
    }

    // Helper to create RTP/UDP/IPv4 headers for tests.
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
            // Assuming default IP/UDP source/dest for simplicity in these unit tests
            ip_src: "192.168.0.1".parse().unwrap(),
            ip_dst: "192.168.0.2".parse().unwrap(),
            udp_src_port: 1000,
            udp_dst_port: 2000,
            ..Default::default()
        }
    }

    #[test]
    fn should_force_ir_basic_conditions() {
        let mut context = create_comp_context(1, 100, 1000, false, 10);
        let headers = create_rtp_headers(1, 101, 1000, false, 10); // SSRC is 1, same as context

        // Test 1: Mode is InitializationAndRefresh
        context.mode = Profile1CompressorMode::InitializationAndRefresh;
        assert!(
            should_force_ir(&context, &headers),
            "IR should be forced if mode is InitializationAndRefresh."
        );

        // Reset mode for subsequent checks
        context.mode = Profile1CompressorMode::FirstOrder;

        // Test 2: IR Refresh Interval met
        context.ir_refresh_interval = 5;
        context.fo_packets_sent_since_ir = 4; // Next packet (5th FO) should trigger IR
        assert!(
            should_force_ir(&context, &headers),
            "IR should be forced when refresh interval is met."
        );

        context.fo_packets_sent_since_ir = 3; // Not yet met
        assert!(
            !should_force_ir(&context, &headers),
            "IR should not be forced if refresh interval is not met."
        );

        // Test 3: SSRC change
        let headers_ssrc_change = create_rtp_headers(2, 101, 1000, false, 10); // SSRC is 2, different from context (1)
        assert!(
            should_force_ir(&context, &headers_ssrc_change),
            "IR should be forced on SSRC change."
        );
    }

    #[test]
    fn should_force_ir_scaled_mode_ts_misaligned() {
        let mut context = create_comp_context(1, 100, 1000, false, 10);
        context.ts_scaled_mode = true; // Scaled mode is active
        context.ts_stride = Some(160); // Stride is known
        context.ts_offset = Timestamp::new(1000); // Offset is known

        // Packet TS is 1000 (offset) + 80 (half stride) = 1080, which is not a multiple of stride from offset
        let headers_misaligned_ts = create_rtp_headers(1, 101, 1000 + 80, false, 10);
        assert!(
            should_force_ir(&context, &headers_misaligned_ts),
            "IR should be forced if TS is misaligned in scaled mode (calculate_ts_scaled returns None)."
        );
    }

    #[test]
    fn should_force_ir_large_sn_jump() {
        let context = create_comp_context(1, 100, 1000, false, 10);
        // SN jump greater than max_safe_sn_delta for 8 LSBs (127)
        let headers_large_sn_jump = create_rtp_headers(
            1,                                              // SSRC
            100 + (1 << (P1_UO1_SN_LSB_WIDTH_DEFAULT - 1)), // current_sn = 100 + 128 = 228. Delta = 128.
            1000,                                           // TS
            false,                                          // Marker
            10,                                             // IP-ID
        );
        assert!(
            should_force_ir(&context, &headers_large_sn_jump),
            "IR should be forced for a large SN jump exceeding LSB unambiguous window."
        );
    }

    #[test]
    fn should_force_ir_large_ts_jump_non_scaled() {
        let mut context = create_comp_context(1, 100, 1000, false, 10);
        context.ts_scaled_mode = false; // Not in scaled mode

        // TS jump greater than max_safe_ts_delta for 16 LSBs (32767)
        let headers_large_ts_jump = create_rtp_headers(
            1,                                               // SSRC
            101,                                             // SN
            1000 + (1 << (P1_UO1_TS_LSB_WIDTH_DEFAULT - 1)), // current_ts = 1000 + 32768 = 33768. Delta = 32768.
            false,                                           // Marker
            10,                                              // IP-ID
        );
        assert!(
            should_force_ir(&context, &headers_large_ts_jump),
            "IR should be forced for a large TS jump in non-scaled mode."
        );
    }

    #[test]
    fn should_force_ir_large_ip_id_jump() {
        let context = create_comp_context(1, 100, 1000, false, 10); // last_ip_id = 10
        // IP-ID jump greater than max_safe_ipid_delta for 8 LSBs (127)
        let headers_large_ip_id_jump = create_rtp_headers(
            1,                                               // SSRC
            101,                                             // SN
            1000,                                            // TS
            false,                                           // Marker
            10 + (1 << (P1_UO1_IPID_LSB_WIDTH_DEFAULT - 1)), // current_ip_id = 10 + 128 = 138. Delta = 128.
        );
        assert!(
            should_force_ir(&context, &headers_large_ip_id_jump),
            "IR should be forced for a large IP-ID jump."
        );
    }

    #[test]
    fn should_force_ir_when_ts_scaled_mode_but_no_stride() {
        let mut context = create_comp_context(1, 100, 1000, false, 10);
        context.ts_scaled_mode = true; // Scaled mode is active
        context.ts_stride = None; // But stride is NOT known (inconsistent state)

        let headers = create_rtp_headers(1, 101, 1160, false, 10);
        assert!(
            should_force_ir(&context, &headers),
            "IR should be forced if in scaled mode but stride is None."
        );
    }

    #[test]
    fn compress_as_ir_updates_context() {
        let crc_calculators = CrcCalculators::new();
        let mut context = create_comp_context(0, 0, 0, false, 0);
        let headers = create_rtp_headers(1, 100, 1000, true, 50);
        // Manually set SSRC to 0 to trigger initialization path, then initialize
        context.rtp_ssrc = 0;
        context.initialize_context_from_uncompressed_headers(&headers);
        // After init, mode is InitializationAndRefresh, so compress_as_ir will be called.

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
        let mut context = create_comp_context(1, 100, 1000, false, 10); // SSRC=1
        let headers = create_rtp_headers(1, 101, 1000, false, 10); // SSRC=1, UO-0 conditions

        let packet = compress_as_uo(&mut context, &headers, &crc_calculators).unwrap();
        assert_eq!(packet.len(), 1, "Packet length for UO-0");
        assert!((packet[0] & 0x80) == 0, "UO-0 discriminator");
    }

    #[test]
    fn compress_as_uo_selects_uo0_with_implicit_ts_update() {
        let crc_calculators = CrcCalculators::new();
        let mut context = create_comp_context(1, 100, 1000, false, 10);
        context.ts_stride = Some(160);

        let headers = create_rtp_headers(1, 101, 1160, false, 10); // TS = 1000 + 1*160

        let packet = compress_as_uo(&mut context, &headers, &crc_calculators).unwrap();
        assert_eq!(packet.len(), 1, "Packet length for UO-0 with implicit TS");
        assert!((packet[0] & 0x80) == 0, "UO-0 discriminator");
        assert_eq!(context.last_sent_rtp_ts_full, Timestamp::new(1160)); // Context TS updated implicitly
    }

    #[test]
    fn compress_as_uo_selects_uo1_sn_on_marker_change() {
        let crc_calculators = CrcCalculators::new();
        let mut context = create_comp_context(1, 100, 1000, false, 10); // last_marker = false
        context.ts_stride = Some(160); // Needed for UO-1-SN fallback path
        let headers = create_rtp_headers(1, 101, 1000, true, 10); // current_marker = true (changed)

        let packet = compress_as_uo(&mut context, &headers, &crc_calculators).unwrap();
        assert_eq!(packet.len(), 3, "Packet length for UO-1-SN");
        assert_eq!(
            packet[0] & P1_UO_1_SN_PACKET_TYPE_PREFIX, // Checks base bits 10100000
            P1_UO_1_SN_PACKET_TYPE_PREFIX
        );
        assert_ne!(
            packet[0] & P1_UO_1_SN_MARKER_BIT_MASK,
            0,
            "Marker bit should be set in UO-1-SN type"
        );
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
        let context = create_comp_context(1, 100, 1000, false, 10);
        let crc_calculators = CrcCalculators::new();
        let result = build_uo0(&context, 101, Timestamp::new(1000), &crc_calculators).unwrap();
        assert_eq!(result.len(), 1);
        // Further checks on byte values can be added if needed based on known CRC/SN_LSB
    }

    #[test]
    fn helper_build_uo1_sn_correct_format() {
        let mut context = create_comp_context(1, 100, 1000, false, 10);
        context.ts_stride = Some(160); // UO-1-SN build requires stride
        let crc_calculators = CrcCalculators::new();
        let result = build_uo1_sn(&context, 101, true, &crc_calculators).unwrap();
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
        let context = create_comp_context(1, 100, 1000, false, 10);
        let crc_calculators = CrcCalculators::new();
        let result = build_uo1_id(&context, 101, 11, &crc_calculators).unwrap();
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

    #[test]
    fn compress_as_uo_forces_ir_when_no_stride_and_uo1_sn_needed() {
        let crc_calculators = CrcCalculators::new();
        let mut context = create_comp_context(1, 100, 1000, false, 10);
        context.ts_stride = None;

        let headers = create_rtp_headers(1, 105, 1000, true, 10);

        let result = compress_as_uo(&mut context, &headers, &crc_calculators);
        assert!(
            result.is_err(),
            "Compress_as_uo should return Err when no stride for UO-1-SN."
        );

        if let Err(RohcError::InvalidState(msg)) = result {
            assert!(
                msg.contains("TS_STRIDE not established for UO-1-SN fallback"),
                "Error message mismatch. Got: {}",
                msg
            );
        } else {
            panic!(
                "Expected InvalidState error for UO-1-SN without stride, got {:?}",
                result
            );
        }
    }

    #[test]
    fn compress_as_uo_allows_uo1_sn_with_stride() {
        let crc_calculators = CrcCalculators::new();
        let mut context = create_comp_context(1, 100, 1000, false, 10);
        context.ts_stride = Some(160);

        let headers = create_rtp_headers(1, 102, 1000, true, 10);

        let result = compress_as_uo(&mut context, &headers, &crc_calculators);
        assert!(
            result.is_ok(),
            "UO-1-SN should be generated with established stride: {:?}",
            result.err()
        );

        let packet = result.unwrap();
        assert_eq!(packet.len(), 3, "Should be UO-1-SN packet");
        assert_eq!(
            packet[0] & P1_UO_1_SN_PACKET_TYPE_PREFIX,
            P1_UO_1_SN_PACKET_TYPE_PREFIX,
            "Should be UO-1-SN discriminator"
        );
    }

    #[test]
    fn compress_as_uo_ts_scaled_fallback_behavior() {
        let crc_calculators = CrcCalculators::new();
        let mut context = create_comp_context(1, 100, 1000, false, 10);

        context.ts_stride = Some(160); // Stride known
        context.ts_scaled_mode = true; // Scaled mode active
        context.ts_offset = Timestamp::new(1000);

        // Create headers that will fail TS_SCALED calculation (e.g. misaligned or overflow)
        // AND will not fit UO-0, UO-1-TS, UO-1-ID.
        let headers = create_rtp_headers(1, 120, 1500, false, 10); // SN delta=20, TS changed, IP-ID same

        let result = compress_as_uo(&mut context, &headers, &crc_calculators);
        assert!(
            result.is_ok(),
            "Should fall back to UO-1-SN when UO-1-RTP fails and other UO types not applicable."
        );

        let packet = result.unwrap();
        let (core_packet_start, expected_min_length) =
            if context.cid == 0 { (0, 3) } else { (1, 4) }; // Assuming CID 0 for these tests
        assert!(
            packet.len() >= expected_min_length,
            "Packet should be at least {} bytes for UO-1-SN",
            expected_min_length
        );
        let core_byte = packet[core_packet_start];
        assert_eq!(
            core_byte & P1_UO_1_SN_PACKET_TYPE_PREFIX,
            P1_UO_1_SN_PACKET_TYPE_PREFIX,
            "Should use UO-1-SN as fallback from failed UO-1-RTP. Got core byte: 0x{:02X}",
            core_byte
        );
    }
}
