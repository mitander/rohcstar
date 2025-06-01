//! Integration tests for ROHC Profile 1 UO-1-RTP packet handling.
//!
//! This module tests the UO-1-RTP packet format, which is used when the compressor
//! has established a timestamp stride and can send a scaled timestamp (TS_SCALED).
//! Tests cover TS_SCALED calculation, TS stride detection & updates, marker bit,
//! CRC validation, and integration with IR-DYN TS_STRIDE signaling.

mod common;
use common::{
    create_rtp_headers, create_test_engine_with_system_clock, establish_ts_stride_context,
    get_compressor_context, get_decompressor_context,
};

use rohcstar::packet_defs::{GenericUncompressedHeaders, RohcProfile};
use rohcstar::profiles::profile1::protocol_types::Timestamp;
use rohcstar::profiles::profile1::{
    P1_ROHC_IR_PACKET_TYPE_WITH_DYN, P1_TS_SCALED_MAX_VALUE, P1_TS_STRIDE_ESTABLISHMENT_THRESHOLD,
    P1_UO_1_RTP_DISCRIMINATOR_BASE, P1_UO_1_RTP_MARKER_BIT_MASK, Profile1Handler,
};

const TEST_SSRC_UO1_RTP: u32 = 0x7788AADD;
const TEST_CID_UO1_RTP: u16 = 0;

/// Tests basic UO-1-RTP compression and decompression with TS_SCALED. Marker bit is false.
#[test]
fn p1_uo1_rtp_basic_compression_decompression_marker_false_succeeds() {
    let mut engine = create_test_engine_with_system_clock(50);
    engine
        .register_profile_handler(Box::new(Profile1Handler::new()))
        .unwrap();

    let initial_sn_for_ir = 100;
    let initial_ts_for_first_ir = 1000;
    let stride = 160;

    establish_ts_stride_context(
        &mut engine,
        TEST_CID_UO1_RTP,
        TEST_SSRC_UO1_RTP,
        initial_sn_for_ir,
        initial_ts_for_first_ir,
        stride,
    );

    let (last_sn, last_ts_from_ctx, last_ip_id, _) = {
        let comp_ctx = get_compressor_context(&engine, TEST_CID_UO1_RTP);
        (
            comp_ctx.last_sent_rtp_sn_full,
            comp_ctx.last_sent_rtp_ts_full,
            comp_ctx.last_sent_ip_id_full,
            comp_ctx.ts_offset,
        )
    };

    let next_sn = last_sn.wrapping_add(1);
    let next_ts_val = last_ts_from_ctx.value().wrapping_add(stride);

    let headers =
        create_rtp_headers(next_sn, next_ts_val, false, TEST_SSRC_UO1_RTP).with_ip_id(last_ip_id);
    let generic_headers = GenericUncompressedHeaders::RtpUdpIpv4(headers.clone());

    let compressed_packet = engine
        .compress(
            TEST_CID_UO1_RTP,
            Some(RohcProfile::RtpUdpIp),
            &generic_headers,
        )
        .unwrap();

    assert_eq!(
        compressed_packet.len(),
        3,
        "UO-1-RTP packet length incorrect"
    );
    assert_eq!(
        compressed_packet[0] & !P1_UO_1_RTP_MARKER_BIT_MASK,
        P1_UO_1_RTP_DISCRIMINATOR_BASE
    );
    assert_eq!(
        compressed_packet[0] & P1_UO_1_RTP_MARKER_BIT_MASK,
        0,
        "Marker bit should be 0"
    );

    // After establish_ts_stride_context, C and D ts_offset are TS of the final IR.
    // last_ts_from_ctx is also TS of final IR.
    // So, next_ts_val = (TS of final IR) + stride.
    // TS_SCALED = (next_ts_val - comp_ts_offset) / stride = ( (TS_final_IR + stride) - TS_final_IR ) / stride = 1
    assert_eq!(
        compressed_packet[1], 1,
        "TS_SCALED value mismatch, expected 1"
    );

    let decompressed_generic = engine.decompress(&compressed_packet).unwrap();
    let decomp_headers = decompressed_generic.as_rtp_udp_ipv4().unwrap();

    assert_eq!(decomp_headers.rtp_sequence_number, next_sn);
    assert_eq!(decomp_headers.rtp_timestamp, Timestamp::new(next_ts_val));
    assert!(!decomp_headers.rtp_marker);
}

/// Tests basic UO-1-RTP compression and decompression with TS_SCALED. Marker bit is true.
#[test]
fn p1_uo1_rtp_basic_compression_decompression_marker_true_succeeds() {
    let mut engine = create_test_engine_with_system_clock(50);
    engine
        .register_profile_handler(Box::new(Profile1Handler::new()))
        .unwrap();

    let initial_sn_for_ir = 200;
    let initial_ts_for_ir = 20000;
    let stride = 80;
    establish_ts_stride_context(
        &mut engine,
        TEST_CID_UO1_RTP,
        TEST_SSRC_UO1_RTP,
        initial_sn_for_ir,
        initial_ts_for_ir,
        stride,
    );

    let (last_sn, last_ts, last_ip_id, comp_ts_offset) = {
        let comp_ctx = get_compressor_context(&engine, TEST_CID_UO1_RTP);
        (
            comp_ctx.last_sent_rtp_sn_full,
            comp_ctx.last_sent_rtp_ts_full,
            comp_ctx.last_sent_ip_id_full,
            comp_ctx.ts_offset,
        )
    };
    let next_sn = last_sn.wrapping_add(1);
    let next_ts_val = last_ts.value().wrapping_add(stride);

    let headers =
        create_rtp_headers(next_sn, next_ts_val, true, TEST_SSRC_UO1_RTP).with_ip_id(last_ip_id);
    let generic_headers = GenericUncompressedHeaders::RtpUdpIpv4(headers.clone());

    let compressed_packet = engine
        .compress(
            TEST_CID_UO1_RTP,
            Some(RohcProfile::RtpUdpIp),
            &generic_headers,
        )
        .unwrap();

    assert_eq!(compressed_packet.len(), 3);
    assert_eq!(
        compressed_packet[0] & P1_UO_1_RTP_MARKER_BIT_MASK,
        P1_UO_1_RTP_MARKER_BIT_MASK,
        "Marker bit should be 1"
    );

    let expected_ts_scaled = Timestamp::new(next_ts_val)
        .wrapping_diff(comp_ts_offset)
        .wrapping_div(stride);
    assert_eq!(
        expected_ts_scaled, 1,
        "Logic error in test: expected ts_scaled for this packet should be 1"
    );
    assert_eq!(
        compressed_packet[1], 1,
        "TS_SCALED value mismatch, expected 1"
    );

    let decompressed_generic = engine.decompress(&compressed_packet).unwrap();
    let decomp_headers = decompressed_generic.as_rtp_udp_ipv4().unwrap();
    assert_eq!(decomp_headers.rtp_sequence_number, next_sn);
    assert_eq!(decomp_headers.rtp_timestamp, Timestamp::new(next_ts_val));
    assert!(decomp_headers.rtp_marker);
}

/// Tests TS_SCALED for the packet immediately after stride context is established via common helper.
/// The first UO-1-RTP sent after this helper should have TS_SCALED = 1.
#[test]
fn p1_uo1_rtp_ts_scaled_at_establishment_threshold_succeeds() {
    let mut engine = create_test_engine_with_system_clock(50);
    engine
        .register_profile_handler(Box::new(Profile1Handler::new()))
        .unwrap();

    let initial_sn_for_ir = 10;
    let initial_ts_for_ir = 1000;
    let stride = 160;

    establish_ts_stride_context(
        &mut engine,
        TEST_CID_UO1_RTP,
        TEST_SSRC_UO1_RTP,
        initial_sn_for_ir,
        initial_ts_for_ir,
        stride,
    );

    let (last_sn, last_ts_from_final_ir, last_ip_id, comp_ts_offset_after_final_ir) = {
        let comp_ctx = get_compressor_context(&engine, TEST_CID_UO1_RTP);
        (
            comp_ctx.last_sent_rtp_sn_full,
            comp_ctx.last_sent_rtp_ts_full,
            comp_ctx.last_sent_ip_id_full,
            comp_ctx.ts_offset,
        )
    };
    assert_eq!(
        comp_ts_offset_after_final_ir, last_ts_from_final_ir,
        "Compressor ts_offset should be TS of final IR from helper"
    );

    let next_sn = last_sn.wrapping_add(1);
    let next_ts_val = last_ts_from_final_ir.value().wrapping_add(stride);

    let headers =
        create_rtp_headers(next_sn, next_ts_val, false, TEST_SSRC_UO1_RTP).with_ip_id(last_ip_id);
    let generic_headers = GenericUncompressedHeaders::RtpUdpIpv4(headers.clone());
    let compressed_packet = engine
        .compress(
            TEST_CID_UO1_RTP,
            Some(RohcProfile::RtpUdpIp),
            &generic_headers,
        )
        .unwrap();

    assert_eq!(
        compressed_packet[1], 1,
        "TS_SCALED value mismatch, expected 1"
    );

    let decompressed_generic = engine.decompress(&compressed_packet).unwrap();
    let decomp_headers = decompressed_generic.as_rtp_udp_ipv4().unwrap();
    assert_eq!(decomp_headers.rtp_timestamp, Timestamp::new(next_ts_val));
}

/// Tests TS_SCALED calculation at boundary value 255.
#[test]
fn p1_uo1_rtp_ts_scaled_boundary_max_succeeds() {
    let mut engine = create_test_engine_with_system_clock(5000); // Very high IR refresh
    engine
        .register_profile_handler(Box::new(Profile1Handler::new()))
        .unwrap();

    let initial_sn_for_ir = 10;
    let initial_ts_for_ir = 1000;
    let stride = 10;

    establish_ts_stride_context(
        // This helper syncs Ctx C and D ts_offset & ts_stride
        &mut engine,
        TEST_CID_UO1_RTP,
        TEST_SSRC_UO1_RTP,
        initial_sn_for_ir,
        initial_ts_for_ir,
        stride,
    );

    // After establish_ts_stride_context, both C and D contexts are aligned.
    // C.ts_offset is the TS of the final IR from the helper.
    // C.last_sent_rtp_ts_full is also the TS of that final IR.
    let (sn_from_ctx, ts_offset_from_ctx, ip_id_from_ctx, marker_from_ctx) = {
        let comp_ctx = get_compressor_context(&engine, TEST_CID_UO1_RTP);
        assert!(comp_ctx.ts_scaled_mode);
        assert_eq!(comp_ctx.ts_stride, Some(stride));
        (
            comp_ctx.last_sent_rtp_sn_full,
            comp_ctx.ts_offset.value(), // This is TS_final_IR
            comp_ctx.last_sent_ip_id_full,
            comp_ctx.last_sent_rtp_marker,
        )
    };

    // Packet to achieve TS_SCALED = 255:
    // SN must be +1 for UO-1-RTP
    let sn_for_target_packet = sn_from_ctx.wrapping_add(1);
    // TS = context_ts_offset + (255 * stride)
    let ts_for_target_packet = ts_offset_from_ctx.wrapping_add(P1_TS_SCALED_MAX_VALUE * stride);
    // IP-ID should be same as context's last sent to prefer UO-1-RTP
    // Marker can be anything, choose same as context for consistency
    let headers_for_assertion = create_rtp_headers(
        sn_for_target_packet,
        ts_for_target_packet,
        marker_from_ctx,
        TEST_SSRC_UO1_RTP,
    )
    .with_ip_id(ip_id_from_ctx);
    let generic_headers_for_assertion =
        GenericUncompressedHeaders::RtpUdpIpv4(headers_for_assertion.clone());

    // Compress this single packet
    let compressed_packet_for_max = engine
        .compress(
            TEST_CID_UO1_RTP,
            Some(RohcProfile::RtpUdpIp),
            &generic_headers_for_assertion,
        )
        .unwrap();

    assert_eq!(
        compressed_packet_for_max.len(),
        3,
        "Packet for TS_SCALED_MAX should be UO-1-RTP (length 3)"
    );
    assert_eq!(
        compressed_packet_for_max[0] & !P1_UO_1_RTP_MARKER_BIT_MASK,
        P1_UO_1_RTP_DISCRIMINATOR_BASE,
        "Packet type should be UO-1-RTP base. Got type {:#04X}",
        compressed_packet_for_max[0]
    );
    assert_eq!(
        compressed_packet_for_max[1],
        P1_TS_SCALED_MAX_VALUE as u8,
        "TS_SCALED should be 255. Compressor ts_offset={}, packet_ts={}, comp_stride={:?}",
        get_compressor_context(&engine, TEST_CID_UO1_RTP)
            .ts_offset
            .value(),
        ts_for_target_packet,
        get_compressor_context(&engine, TEST_CID_UO1_RTP).ts_stride
    );

    // Decompress to ensure CRC matches, now that C and D contexts should be aligned
    let decompressed_generic = engine.decompress(&compressed_packet_for_max).unwrap();
    let decomp_headers = decompressed_generic.as_rtp_udp_ipv4().unwrap();
    assert_eq!(
        decomp_headers.rtp_timestamp,
        Timestamp::new(ts_for_target_packet)
    );
    assert_eq!(decomp_headers.rtp_sequence_number, sn_for_target_packet);
    assert_eq!(decomp_headers.rtp_marker, marker_from_ctx);
}

/// Tests that if TS_SCALED would overflow (be > 255), the compressor sends an IR packet.
#[test]
fn p1_uo1_rtp_ts_scaled_overflow_triggers_ir() {
    let mut engine = create_test_engine_with_system_clock(500);
    engine
        .register_profile_handler(Box::new(Profile1Handler::new()))
        .unwrap();

    let initial_sn_for_ir = 10;
    let initial_ts_for_ir = 1000;
    let stride = 10;
    establish_ts_stride_context(
        &mut engine,
        TEST_CID_UO1_RTP,
        TEST_SSRC_UO1_RTP,
        initial_sn_for_ir,
        initial_ts_for_ir,
        stride,
    );

    let (mut current_sn, mut current_ts_val, current_ip_id, comp_ts_offset_after_final_ir) = {
        let comp_ctx = get_compressor_context(&engine, TEST_CID_UO1_RTP);
        (
            comp_ctx.last_sent_rtp_sn_full,
            comp_ctx.last_sent_rtp_ts_full.value(),
            comp_ctx.last_sent_ip_id_full,
            comp_ctx.ts_offset.value(),
        )
    };

    let ts_for_scale_255 = comp_ts_offset_after_final_ir + (P1_TS_SCALED_MAX_VALUE * stride);
    while current_ts_val < ts_for_scale_255 {
        current_sn = current_sn.wrapping_add(1);
        current_ts_val = current_ts_val.wrapping_add(stride);
        let headers = create_rtp_headers(current_sn, current_ts_val, false, TEST_SSRC_UO1_RTP)
            .with_ip_id(current_ip_id);
        let _ = engine
            .compress(
                TEST_CID_UO1_RTP,
                Some(RohcProfile::RtpUdpIp),
                &GenericUncompressedHeaders::RtpUdpIpv4(headers),
            )
            .unwrap();
    }

    let sn_for_overflow = current_sn.wrapping_add(1);
    let ts_for_overflow = current_ts_val.wrapping_add(stride);

    let headers = create_rtp_headers(sn_for_overflow, ts_for_overflow, false, TEST_SSRC_UO1_RTP)
        .with_ip_id(current_ip_id);
    let generic_headers = GenericUncompressedHeaders::RtpUdpIpv4(headers.clone());
    let compressed_packet = engine
        .compress(
            TEST_CID_UO1_RTP,
            Some(RohcProfile::RtpUdpIp),
            &generic_headers,
        )
        .unwrap();

    assert!(
        compressed_packet.len() > 4,
        "Packet should be IR (len > 4) due to TS_SCALED overflow, got len {}",
        compressed_packet.len()
    );
    assert_eq!(compressed_packet[0], P1_ROHC_IR_PACKET_TYPE_WITH_DYN);
}

/// Tests that if the timestamp does not align with the established stride, an IR is sent
/// because `calculate_ts_scaled` returns None and `should_force_ir` detects this.
#[test]
fn p1_uo1_rtp_ts_misaligned_forces_ir() {
    let mut engine = create_test_engine_with_system_clock(50);
    engine
        .register_profile_handler(Box::new(Profile1Handler::new()))
        .unwrap();

    let initial_sn_for_ir = 10;
    let initial_ts_for_ir = 1000;
    let stride = 160;
    establish_ts_stride_context(
        &mut engine,
        TEST_CID_UO1_RTP,
        TEST_SSRC_UO1_RTP,
        initial_sn_for_ir,
        initial_ts_for_ir,
        stride,
    );

    let (last_sn, last_ts_ctx, last_ip_id) = {
        let comp_ctx_before = get_compressor_context(&engine, TEST_CID_UO1_RTP);
        (
            comp_ctx_before.last_sent_rtp_sn_full,
            comp_ctx_before.last_sent_rtp_ts_full,
            comp_ctx_before.last_sent_ip_id_full,
        )
    };
    let next_sn = last_sn.wrapping_add(1);
    let misaligned_ts_val = last_ts_ctx.value().wrapping_add(stride / 2);

    let headers = create_rtp_headers(next_sn, misaligned_ts_val, false, TEST_SSRC_UO1_RTP)
        .with_ip_id(last_ip_id);
    let generic_headers = GenericUncompressedHeaders::RtpUdpIpv4(headers.clone());

    let compressed_packet = engine
        .compress(
            TEST_CID_UO1_RTP,
            Some(RohcProfile::RtpUdpIp),
            &generic_headers,
        )
        .unwrap();

    assert!(
        compressed_packet.len() > 4,
        "Packet should be IR due to TS misalignment in scaled mode, got len {}",
        compressed_packet.len()
    );
    assert_eq!(compressed_packet[0], P1_ROHC_IR_PACKET_TYPE_WITH_DYN);

    let decompressed_generic = engine.decompress(&compressed_packet).unwrap();
    let decomp_headers = decompressed_generic.as_rtp_udp_ipv4().unwrap();
    assert_eq!(decomp_headers.rtp_sequence_number, next_sn);
    assert_eq!(
        decomp_headers.rtp_timestamp,
        Timestamp::new(misaligned_ts_val)
    );
}

/// Tests integration of IR-DYN TS_STRIDE signaling with subsequent UO-1-RTP packets.
/// Verifies correct TS_SCALED calculation based on aligned C/D ts_offset.
#[test]
fn p1_uo1_rtp_after_ir_with_ts_stride_succeeds() {
    let mut engine = create_test_engine_with_system_clock(50);
    engine
        .register_profile_handler(Box::new(Profile1Handler::new()))
        .unwrap();

    let ir_sn_base = 300; // SN of the packet *before* the one that establishes stride for compressor
    let ir_ts_base = 28000; // TS of the packet *before* the one that establishes stride for compressor
    let stride_val = 200;

    // Setup compressor to be in scaled mode.
    // Its ts_offset will be ir_ts_base.
    // Its last_sent_rtp_ts will be ir_ts_base + P1_TS_STRIDE_ESTABLISHMENT_THRESHOLD * stride_val
    establish_ts_stride_context(
        &mut engine,
        TEST_CID_UO1_RTP,
        TEST_SSRC_UO1_RTP,
        ir_sn_base,
        ir_ts_base,
        stride_val,
    );

    // The `establish_ts_stride_context` sends a final IR. Let's find its TS.
    // It sends initial_ir, then THRESHOLD UOs, then final IR.
    // TS of final IR = ir_ts_base + (P1_TS_STRIDE_ESTABLISHMENT_THRESHOLD + 1) * stride_val
    let final_ir_ts_val = ir_ts_base + (P1_TS_STRIDE_ESTABLISHMENT_THRESHOLD + 1) * stride_val;

    // After establish_ts_stride_context:
    // Both Compressor and Decompressor ts_offset should be final_ir_ts_val.
    // Compressor's last_sent_rtp_ts_full should also be final_ir_ts_val.
    let comp_ctx = get_compressor_context(&engine, TEST_CID_UO1_RTP);
    assert_eq!(
        comp_ctx.ts_offset,
        Timestamp::new(final_ir_ts_val),
        "Compressor ts_offset incorrect"
    );
    assert_eq!(
        comp_ctx.last_sent_rtp_ts_full,
        Timestamp::new(final_ir_ts_val),
        "Compressor last_sent_ts incorrect"
    );

    let decomp_ctx = get_decompressor_context(&engine, TEST_CID_UO1_RTP);
    assert!(
        decomp_ctx.ts_scaled_mode,
        "Decompressor should be in scaled mode"
    );
    assert_eq!(decomp_ctx.ts_stride, Some(stride_val));
    assert_eq!(decomp_ctx.ts_offset, Timestamp::new(final_ir_ts_val));

    // Send a subsequent UO-1-RTP packet
    let next_sn = comp_ctx.last_sent_rtp_sn_full.wrapping_add(1);
    let next_ts_val = final_ir_ts_val.wrapping_add(stride_val); // TS = current_offset + 1 * stride_val
    let last_ip_id_from_comp = comp_ctx.last_sent_ip_id_full;

    let headers_uo1_rtp = create_rtp_headers(next_sn, next_ts_val, false, TEST_SSRC_UO1_RTP)
        .with_ip_id(last_ip_id_from_comp);
    let generic_uo1_rtp = GenericUncompressedHeaders::RtpUdpIpv4(headers_uo1_rtp.clone());

    let compressed_uo1_rtp = engine
        .compress(
            TEST_CID_UO1_RTP,
            Some(RohcProfile::RtpUdpIp),
            &generic_uo1_rtp,
        )
        .unwrap();
    assert_eq!(
        compressed_uo1_rtp.len(),
        3,
        "UO-1-RTP packet length incorrect"
    );
    assert_eq!(
        compressed_uo1_rtp[0] & !P1_UO_1_RTP_MARKER_BIT_MASK,
        P1_UO_1_RTP_DISCRIMINATOR_BASE,
        "Should be UO-1-RTP type"
    );

    // Expected TS_SCALED = (next_ts_val - comp_ctx.ts_offset) / stride_val
    //                     = ( (final_ir_ts_val + stride_val) - final_ir_ts_val ) / stride_val = 1
    assert_eq!(
        compressed_uo1_rtp[1], 1,
        "TS_SCALED value incorrect, expected 1"
    );

    let decompressed_generic_uo1_rtp = engine.decompress(&compressed_uo1_rtp).unwrap();
    let decomp_headers_uo1_rtp = decompressed_generic_uo1_rtp.as_rtp_udp_ipv4().unwrap();

    assert_eq!(decomp_headers_uo1_rtp.rtp_sequence_number, next_sn);
    assert_eq!(
        decomp_headers_uo1_rtp.rtp_timestamp,
        Timestamp::new(next_ts_val)
    );
}

/// Tests scenario where TS stride changes, forcing an IR because new TS is misaligned with old stride.
#[test]
fn p1_uo1_rtp_ts_stride_change_forces_ir() {
    let mut engine = create_test_engine_with_system_clock(50);
    engine
        .register_profile_handler(Box::new(Profile1Handler::new()))
        .unwrap();

    let initial_sn_for_ir = 400;
    let initial_ts_for_ir = 40000;
    let stride1 = 100;
    establish_ts_stride_context(
        &mut engine,
        TEST_CID_UO1_RTP,
        TEST_SSRC_UO1_RTP,
        initial_sn_for_ir,
        initial_ts_for_ir,
        stride1,
    );

    let (sn1, ts1_val, ip_id1) = {
        // Values after context establishment
        let comp_ctx1 = get_compressor_context(&engine, TEST_CID_UO1_RTP);
        (
            comp_ctx1.last_sent_rtp_sn_full.wrapping_add(1),
            comp_ctx1
                .last_sent_rtp_ts_full
                .value()
                .wrapping_add(stride1),
            comp_ctx1.last_sent_ip_id_full,
        )
    };
    let headers1 = create_rtp_headers(sn1, ts1_val, false, TEST_SSRC_UO1_RTP).with_ip_id(ip_id1);
    let generic1 = GenericUncompressedHeaders::RtpUdpIpv4(headers1);
    let compressed1 = engine
        .compress(TEST_CID_UO1_RTP, Some(RohcProfile::RtpUdpIp), &generic1)
        .unwrap();
    assert_eq!(
        compressed1[0] & !P1_UO_1_RTP_MARKER_BIT_MASK,
        P1_UO_1_RTP_DISCRIMINATOR_BASE,
        "First UO should be UO-1-RTP"
    );
    let _ = engine.decompress(&compressed1).unwrap();

    let sn2 = sn1.wrapping_add(1);
    let stride2 = 50;
    let ts2_val = ts1_val.wrapping_add(stride2);
    let headers2 = create_rtp_headers(sn2, ts2_val, false, TEST_SSRC_UO1_RTP).with_ip_id(ip_id1);
    let generic2 = GenericUncompressedHeaders::RtpUdpIpv4(headers2.clone());

    let compressed2 = engine
        .compress(TEST_CID_UO1_RTP, Some(RohcProfile::RtpUdpIp), &generic2)
        .unwrap();

    // Expect IR because ts_scaled_mode is true (from stride1), but new TS (ts2_val) will be misaligned with old stride1,
    // causing calculate_ts_scaled to return None, and should_force_ir to return true.
    assert!(
        compressed2.len() > 4,
        "Packet should be IR due to TS stride change/misalignment, got len {}",
        compressed2.len()
    );
    assert_eq!(compressed2[0], P1_ROHC_IR_PACKET_TYPE_WITH_DYN);

    let decompressed_generic2 = engine.decompress(&compressed2).unwrap();
    let decomp_headers2 = decompressed_generic2.as_rtp_udp_ipv4().unwrap();
    assert_eq!(decomp_headers2.rtp_sequence_number, sn2);
    assert_eq!(decomp_headers2.rtp_timestamp, Timestamp::new(ts2_val));

    let comp_ctx2 = get_compressor_context(&engine, TEST_CID_UO1_RTP);
    assert!(
        !comp_ctx2.ts_scaled_mode,
        "Compressor should exit scaled mode when IR is forced by stride change/misalignment"
    );
    assert_eq!(
        comp_ctx2.ts_stride,
        Some(stride2),
        "Compressor should begin detecting the new stride"
    );
    // The ts_offset for the compressor's new stride detection should be ts1_val (the packet before the change)
    assert_eq!(
        comp_ctx2.ts_offset,
        Timestamp::new(ts1_val),
        "Compressor ts_offset should be the base of the new stride detection"
    );
    assert_eq!(
        comp_ctx2.ts_stride_packets, 1,
        "Compressor should have 1 packet counted for the new stride (the IR itself)"
    );

    let decomp_ctx_after_ir2 = get_decompressor_context(&engine, TEST_CID_UO1_RTP);

    // Since the IR did not signal TS_STRIDE (because new stride2 was not yet confirmed by compressor)
    assert!(
        !decomp_ctx_after_ir2.ts_scaled_mode,
        "Decompressor should not be in scaled mode as IR did not signal stride"
    );
    assert_eq!(
        decomp_ctx_after_ir2.ts_stride, None,
        "Decompressor ts_stride should be None as IR did not signal it"
    );
    // Decompressor's ts_offset is updated to the TS of the received IR packet
    assert_eq!(
        decomp_ctx_after_ir2.ts_offset,
        Timestamp::new(ts2_val),
        "Decompressor ts_offset is the TS of the IR packet"
    );
}
