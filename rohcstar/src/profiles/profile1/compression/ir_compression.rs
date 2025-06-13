//! IR (Initialization/Refresh) packet compression logic.
//!
//! This module handles the compression logic for IR packets, including determining
//! when IR packets are required and building them according to RFC 3095.

use crate::crc::CrcCalculators;
use crate::error::RohcError;
use crate::packet_defs::RohcProfile;
use crate::types::Timestamp;

use super::super::constants::*;
use super::super::context::{Profile1CompressorContext, Profile1CompressorMode};
use super::super::packet_types::IrPacket;
use super::super::protocol_types::RtpUdpIpv4Headers;
use super::super::serialization::ir_packets::serialize_ir;
use super::{min_wrapping_distance_u16, min_wrapping_distance_u32};

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
pub fn should_force_ir(context: &Profile1CompressorContext, headers: &RtpUdpIpv4Headers) -> bool {
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

    // IR required due to context state changes
    if context.ir_required {
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

    is_lsb_window_exceeded(context, headers)
}

/// Prepares and builds an IR (Initialization/Refresh) packet into provided buffer.
///
/// Constructs an IR packet containing static and dynamic header information for context
/// initialization or refresh. Updates the compressor context state and optionally signals
/// timestamp stride for scaled mode operation.
///
/// # Parameters
/// - `context`: Mutable compressor context to update after IR generation.
/// - `headers`: Headers from the current packet to include in the IR packet.
/// - `crc_calculators`: CRC calculator instances for packet integrity checks.
/// - `out`: Output buffer to write the compressed packet into.
///
/// # Returns
/// The number of bytes written to the output buffer.
///
/// # Errors
/// - [`RohcError::Building`] - IR packet construction failed
/// - [`RohcError::Internal`] - Internal logic error
pub fn compress_as_ir(
    context: &mut Profile1CompressorContext,
    headers: &RtpUdpIpv4Headers,
    crc_calculators: &CrcCalculators,
    out: &mut [u8],
) -> Result<usize, RohcError> {
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
        context.ts_stride
    } else {
        None
    };

    let ir_data = IrPacket {
        cid: context.cid,
        profile_id: RohcProfile::RtpUdpIp,
        crc8: 0, // Calculated by serialize_ir
        static_ip_src: context.ip_source,
        static_ip_dst: context.ip_destination,
        static_udp_src_port: context.udp_source_port,
        static_udp_dst_port: context.udp_destination_port,
        static_rtp_ssrc: context.rtp_ssrc,
        static_rtp_payload_type: headers.rtp_payload_type,
        static_rtp_extension: headers.rtp_extension,
        static_rtp_padding: headers.rtp_padding,
        dyn_rtp_sn: headers.rtp_sequence_number,
        dyn_rtp_timestamp: headers.rtp_timestamp,
        dyn_rtp_marker: headers.rtp_marker,
        dyn_ip_ttl: context.ip_ttl,
        dyn_ip_id: headers.ip_identification,
        ts_stride: stride_to_signal,
    };

    let len = serialize_ir(&ir_data, crc_calculators, out).map_err(RohcError::Building)?;

    // Perform stride detection BEFORE updating context state to avoid race condition
    if scaled_mode_failed {
        // Resume stride detection using TS before IR, as IR TS may not be part of regular sequence
        let old_ts = context.last_sent_rtp_ts_full;
        context.last_sent_rtp_ts_full = previous_ts_before_ir;
        context.detect_ts_stride(headers.rtp_timestamp, headers.rtp_sequence_number);
        context.last_sent_rtp_ts_full = old_ts;
    } else if context.last_sent_rtp_ts_full.value() != 0 || context.ts_stride_packets > 0 {
        // Normal stride detection for any packet with a previous timestamp reference
        context.detect_ts_stride(headers.rtp_timestamp, headers.rtp_sequence_number);
    }

    context.rtp_ssrc = headers.rtp_ssrc;
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

    // Clear the IR required flag after successful IR packet
    context.ir_required = false;

    Ok(len)
}

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
        let ip_id_k = P1_UO1_IP_ID_LSB_WIDTH_DEFAULT;
        if ip_id_k > 0 && ip_id_k < 16 {
            let max_safe_delta: u16 = (1u16 << (ip_id_k - 1)).saturating_sub(1);
            let ip_id_delta_abs =
                min_wrapping_distance_u16(headers.ip_identification, context.last_sent_ip_id_full);
            if ip_id_delta_abs > max_safe_delta {
                return true;
            }
        }
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crc::CrcCalculators;
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
    fn should_force_ir_initialization_mode() {
        let mut context = create_test_context(1, 100, 1000, false, 10);
        let headers = create_test_headers(1, 101, 1000, false, 10);

        context.mode = Profile1CompressorMode::InitializationAndRefresh;
        assert!(should_force_ir(&context, &headers));
    }

    #[test]
    fn should_force_ir_refresh_interval() {
        let mut context = create_test_context(1, 100, 1000, false, 10);
        let headers = create_test_headers(1, 101, 1000, false, 10);

        context.ir_refresh_interval = 5;
        context.fo_packets_sent_since_ir = 4;
        assert!(should_force_ir(&context, &headers));

        context.fo_packets_sent_since_ir = 3;
        assert!(!should_force_ir(&context, &headers));
    }

    #[test]
    fn should_force_ir_ssrc_change() {
        let context = create_test_context(1, 100, 1000, false, 10);
        let headers = create_test_headers(2, 101, 1000, false, 10);
        assert!(should_force_ir(&context, &headers));
    }

    #[test]
    fn should_force_ir_scaled_mode_misaligned() {
        let mut context = create_test_context(1, 100, 1000, false, 10);
        context.ts_scaled_mode = true;
        context.ts_stride = Some(160);
        context.ts_offset = 1000.into();

        let headers = create_test_headers(1, 101, 1080, false, 10); // Not stride-aligned
        assert!(should_force_ir(&context, &headers));
    }

    #[test]
    fn should_force_ir_large_sn_jump() {
        let context = create_test_context(1, 100, 1000, false, 10);
        let headers = create_test_headers(1, 228, 1000, false, 10); // Delta = 128
        assert!(should_force_ir(&context, &headers));
    }

    #[test]
    fn should_force_ir_large_ts_jump() {
        let mut context = create_test_context(1, 100, 1000, false, 10);
        context.ts_scaled_mode = false;
        let headers = create_test_headers(1, 101, 33768, false, 10); // Delta = 32768
        assert!(should_force_ir(&context, &headers));
    }

    #[test]
    fn should_force_ir_large_ip_id_jump() {
        let context = create_test_context(1, 100, 1000, false, 10);
        let headers = create_test_headers(1, 101, 1000, false, 138); // Delta = 128
        assert!(should_force_ir(&context, &headers));
    }

    #[test]
    fn should_force_ir_scaled_mode_no_stride() {
        let mut context = create_test_context(1, 100, 1000, false, 10);
        context.ts_scaled_mode = true;
        context.ts_stride = None;

        let headers = create_test_headers(1, 101, 1160, false, 10);
        assert!(should_force_ir(&context, &headers));
    }

    #[test]
    fn compress_as_ir_updates_context() {
        let crc_calculators = CrcCalculators::new();
        let mut context = create_test_context(0, 0, 0, false, 0);
        let headers = create_test_headers(1, 100, 1000, true, 50);

        context.rtp_ssrc = 0.into(); // Simulate initial state before SSRC is known
        context.initialize_context_from_uncompressed_headers(&headers); // SSRC becomes 1, mode -> InitAndRefresh

        let mut ir_buf = [0u8; 64];
        let _ = compress_as_ir(&mut context, &headers, &crc_calculators, &mut ir_buf).unwrap();

        assert_eq!(context.mode, Profile1CompressorMode::FirstOrder);
        assert_eq!(context.last_sent_rtp_sn_full, headers.rtp_sequence_number);
        assert_eq!(context.last_sent_rtp_ts_full, headers.rtp_timestamp);
        assert_eq!(context.last_sent_rtp_marker, headers.rtp_marker);
        assert_eq!(context.last_sent_ip_id_full, headers.ip_identification);
        assert_eq!(context.fo_packets_sent_since_ir, 0);
    }
}
