//! Integration tests for ROHC Profile 1 UO-1-RTP packet handling.
//!
//! Tests UO-1-RTP packet format with TS_SCALED when stride is established.
//! Covers TS_SCALED calculation, stride detection, marker bit, and IR-DYN TS_STRIDE signaling.

mod common;
use common::{
    create_rtp_headers, create_test_engine_with_system_clock, establish_ir_context,
    establish_ts_stride_context_for_uo1_rtp, get_compressor_context, get_decompressor_context,
    get_ip_id_established_by_ir,
};

use rohcstar::packet_defs::{GenericUncompressedHeaders, RohcProfile};
use rohcstar::profiles::profile1::{
    P1_ROHC_IR_PACKET_TYPE_WITH_DYN, P1_TS_SCALED_MAX_VALUE, P1_TS_STRIDE_ESTABLISHMENT_THRESHOLD,
    P1_UO_1_RTP_DISCRIMINATOR_BASE, P1_UO_1_RTP_MARKER_BIT_MASK, P1_UO_1_TS_DISCRIMINATOR,
    Profile1Handler,
};

const TEST_SSRC_UO1_RTP: u32 = 0x7788AADD;
const TEST_CID_UO1_RTP: u16 = 0;

/// Tests UO-1-RTP with TS_SCALED and marker bit false.
#[test]
fn p1_uo1_rtp_basic_compression_decompression_marker_false_succeeds() {
    let mut engine = create_test_engine_with_system_clock(50);
    engine
        .register_profile_handler(Box::new(Profile1Handler::new()))
        .unwrap();

    let final_ir_sn_val = 104;
    let final_ir_ts_val = 1640;
    let stride = 160;

    establish_ts_stride_context_for_uo1_rtp(
        &mut engine,
        TEST_CID_UO1_RTP,
        TEST_SSRC_UO1_RTP,
        final_ir_sn_val,
        final_ir_ts_val,
        stride,
    );

    let comp_ctx_after_setup = get_compressor_context(&engine, TEST_CID_UO1_RTP);
    let decomp_ctx_after_setup = get_decompressor_context(&engine, TEST_CID_UO1_RTP);

    assert!(
        comp_ctx_after_setup.ts_scaled_mode,
        "C: ts_scaled_mode mismatch"
    );
    assert_eq!(
        comp_ctx_after_setup.ts_stride,
        Some(stride),
        "C: ts_stride mismatch"
    );
    assert_eq!(
        comp_ctx_after_setup.ts_offset, final_ir_ts_val,
        "C: ts_offset mismatch"
    );

    assert!(
        decomp_ctx_after_setup.ts_scaled_mode,
        "D: ts_scaled_mode mismatch"
    );
    assert_eq!(
        decomp_ctx_after_setup.ts_stride,
        Some(stride),
        "D: ts_stride mismatch"
    );
    assert_eq!(
        decomp_ctx_after_setup.ts_offset, final_ir_ts_val,
        "D: ts_offset mismatch"
    );

    let last_ip_id_from_setup = comp_ctx_after_setup.last_sent_ip_id_full;
    let comp_offset_val_for_assert = comp_ctx_after_setup.ts_offset.value();

    let next_sn = final_ir_sn_val.wrapping_add(1);
    let next_ts_val = final_ir_ts_val.wrapping_add(stride);

    let headers = create_rtp_headers(next_sn, next_ts_val, false, TEST_SSRC_UO1_RTP)
        .with_ip_id(last_ip_id_from_setup);
    let generic_headers = GenericUncompressedHeaders::RtpUdpIpv4(headers.clone());

    let compressed_packet = engine
        .compress(
            TEST_CID_UO1_RTP.into(),
            Some(RohcProfile::RtpUdpIp),
            &generic_headers,
        )
        .unwrap();

    assert_eq!(
        compressed_packet.len(),
        3,
        "UO-1-RTP packet length incorrect. Packet: {:02X?}",
        compressed_packet
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
        "TS_SCALED value mismatch, expected 1. Comp offset: {}, Packet TS: {}",
        comp_offset_val_for_assert, next_ts_val
    );

    let decompressed_generic = engine.decompress(&compressed_packet).unwrap();
    let decomp_headers = decompressed_generic.as_rtp_udp_ipv4().unwrap();

    assert_eq!(decomp_headers.rtp_sequence_number, next_sn);
    assert_eq!(decomp_headers.rtp_timestamp, next_ts_val);
    assert!(!decomp_headers.rtp_marker);
}

/// Tests basic UO-1-RTP compression and decompression with TS_SCALED. Marker bit is true.
#[test]
fn p1_uo1_rtp_basic_compression_decompression_marker_true_succeeds() {
    let mut engine = create_test_engine_with_system_clock(50);
    engine
        .register_profile_handler(Box::new(Profile1Handler::new()))
        .unwrap();

    let final_ir_sn_val = 204;
    let stride = 80;
    let final_ir_ts_val = 20000 + (P1_TS_STRIDE_ESTABLISHMENT_THRESHOLD + 2) * stride;

    establish_ts_stride_context_for_uo1_rtp(
        &mut engine,
        TEST_CID_UO1_RTP,
        TEST_SSRC_UO1_RTP,
        final_ir_sn_val,
        final_ir_ts_val,
        stride,
    );

    let comp_ctx_after_setup = get_compressor_context(&engine, TEST_CID_UO1_RTP);
    let last_ip_id_from_setup = comp_ctx_after_setup.last_sent_ip_id_full;
    let comp_offset_val_for_assert = comp_ctx_after_setup.ts_offset.value();

    let next_sn_val = final_ir_sn_val.wrapping_add(1);
    let next_ts_val = final_ir_ts_val.wrapping_add(stride);

    let headers_uo1rtp = create_rtp_headers(next_sn_val, next_ts_val, true, TEST_SSRC_UO1_RTP) // Marker true
        .with_ip_id(last_ip_id_from_setup);
    let generic_headers_uo1rtp = GenericUncompressedHeaders::RtpUdpIpv4(headers_uo1rtp.clone());

    let compressed_packet = engine
        .compress(
            TEST_CID_UO1_RTP.into(),
            Some(RohcProfile::RtpUdpIp),
            &generic_headers_uo1rtp,
        )
        .unwrap();

    assert_eq!(
        compressed_packet.len(),
        3,
        "UO-1-RTP packet length incorrect. Packet: {:02X?}",
        compressed_packet
    );
    assert_eq!(
        compressed_packet[0] & P1_UO_1_RTP_MARKER_BIT_MASK,
        P1_UO_1_RTP_MARKER_BIT_MASK,
        "Marker bit should be 1"
    );
    assert_eq!(
        compressed_packet[1], 1,
        "TS_SCALED value mismatch, expected 1. Comp offset: {}, Packet TS: {}",
        comp_offset_val_for_assert, next_ts_val
    );

    let decompressed_generic = engine.decompress(&compressed_packet).unwrap();
    let decomp_headers = decompressed_generic.as_rtp_udp_ipv4().unwrap();
    assert_eq!(decomp_headers.rtp_sequence_number, next_sn_val);
    assert_eq!(decomp_headers.rtp_timestamp, next_ts_val);
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

    let stride = 160;
    let final_ir_sn_val = 10 + P1_TS_STRIDE_ESTABLISHMENT_THRESHOLD + 1 + 1;
    let final_ir_ts_val = 1000 + (P1_TS_STRIDE_ESTABLISHMENT_THRESHOLD + 2) * stride;

    establish_ts_stride_context_for_uo1_rtp(
        &mut engine,
        TEST_CID_UO1_RTP,
        TEST_SSRC_UO1_RTP,
        final_ir_sn_val as u16,
        final_ir_ts_val,
        stride,
    );

    let comp_ctx = get_compressor_context(&engine, TEST_CID_UO1_RTP);
    assert_eq!(
        comp_ctx.ts_offset,
        final_ir_ts_val,
        "Compressor ts_offset (left) should be TS of final IR (right). Actual comp_offset: {}, expected final_ir_ts: {}",
        comp_ctx.ts_offset.value(),
        final_ir_ts_val
    );

    let last_ip_id_from_setup = comp_ctx.last_sent_ip_id_full;
    let comp_offset_val_for_assert = comp_ctx.ts_offset.value();

    let next_sn = final_ir_sn_val.wrapping_add(1);
    let next_ts_val = final_ir_ts_val.wrapping_add(stride);

    let headers = create_rtp_headers(next_sn as u16, next_ts_val, false, TEST_SSRC_UO1_RTP)
        .with_ip_id(last_ip_id_from_setup);
    let generic_headers = GenericUncompressedHeaders::RtpUdpIpv4(headers.clone());
    let compressed_packet = engine
        .compress(
            TEST_CID_UO1_RTP.into(),
            Some(RohcProfile::RtpUdpIp),
            &generic_headers,
        )
        .unwrap();

    assert_eq!(
        compressed_packet.len(),
        3,
        "Packet length should be 3 for UO-1-RTP"
    );
    assert_eq!(
        compressed_packet[1], 1,
        "TS_SCALED value mismatch, expected 1. Comp offset: {}, Packet TS: {}",
        comp_offset_val_for_assert, next_ts_val
    );

    let decompressed_generic = engine.decompress(&compressed_packet).unwrap();
    let decomp_headers = decompressed_generic.as_rtp_udp_ipv4().unwrap();
    assert_eq!(decomp_headers.rtp_timestamp, next_ts_val);
}

#[test]
fn p1_uo1_rtp_ts_scaled_boundary_max_succeeds() {
    let mut engine = create_test_engine_with_system_clock(5000);
    engine
        .register_profile_handler(Box::new(Profile1Handler::new()))
        .unwrap();

    let stride = 10;
    let final_ir_sn_val = 10 + P1_TS_STRIDE_ESTABLISHMENT_THRESHOLD + 1 + 1;
    let final_ir_ts_val = 1000 + (P1_TS_STRIDE_ESTABLISHMENT_THRESHOLD + 2) * stride;

    establish_ts_stride_context_for_uo1_rtp(
        &mut engine,
        TEST_CID_UO1_RTP,
        TEST_SSRC_UO1_RTP,
        final_ir_sn_val as u16,
        final_ir_ts_val,
        stride,
    );

    let comp_ctx = get_compressor_context(&engine, TEST_CID_UO1_RTP);
    assert!(
        comp_ctx.ts_scaled_mode,
        "Compressor should be in scaled mode"
    );
    assert_eq!(comp_ctx.ts_stride, Some(stride));
    assert_eq!(comp_ctx.ts_offset, final_ir_ts_val);
    let comp_ctx_ts_stride_val_for_assert = comp_ctx.ts_stride; // Capture before mutable borrow

    let last_ip_id_from_setup = comp_ctx.last_sent_ip_id_full;
    let marker_from_setup = comp_ctx.last_sent_rtp_marker;
    let comp_offset_val_for_assert = comp_ctx.ts_offset.value();

    let sn_for_target_packet = final_ir_sn_val.wrapping_add(1);
    let ts_for_target_packet = final_ir_ts_val.wrapping_add(P1_TS_SCALED_MAX_VALUE * stride);

    let headers_for_assertion = create_rtp_headers(
        sn_for_target_packet as u16,
        ts_for_target_packet,
        marker_from_setup,
        TEST_SSRC_UO1_RTP,
    )
    .with_ip_id(last_ip_id_from_setup);
    let generic_headers_for_assertion =
        GenericUncompressedHeaders::RtpUdpIpv4(headers_for_assertion.clone());

    let compressed_packet_for_max = engine
        .compress(
            TEST_CID_UO1_RTP.into(),
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
        compressed_packet_for_max[1], P1_TS_SCALED_MAX_VALUE as u8,
        "TS_SCALED should be 255. Comp offset={}, packet_ts={}, comp_stride={:?}",
        comp_offset_val_for_assert, ts_for_target_packet, comp_ctx_ts_stride_val_for_assert
    );

    let decompressed_generic = engine.decompress(&compressed_packet_for_max).unwrap();
    let decomp_headers = decompressed_generic.as_rtp_udp_ipv4().unwrap();
    assert_eq!(decomp_headers.rtp_timestamp, ts_for_target_packet);
    assert_eq!(
        decomp_headers.rtp_sequence_number,
        sn_for_target_packet as u16
    );
}

#[test]
fn p1_uo1_rtp_ts_scaled_overflow_triggers_ir() {
    let mut engine = create_test_engine_with_system_clock(500);
    engine
        .register_profile_handler(Box::new(Profile1Handler::new()))
        .unwrap();

    let stride = 10;
    let final_ir_sn_val = 10 + P1_TS_STRIDE_ESTABLISHMENT_THRESHOLD + 1 + 1;
    let final_ir_ts_val = 1000 + (P1_TS_STRIDE_ESTABLISHMENT_THRESHOLD + 2) * stride;

    establish_ts_stride_context_for_uo1_rtp(
        &mut engine,
        TEST_CID_UO1_RTP,
        TEST_SSRC_UO1_RTP,
        final_ir_sn_val as u16,
        final_ir_ts_val,
        stride,
    );

    let comp_ctx = get_compressor_context(&engine, TEST_CID_UO1_RTP);
    let last_ip_id_from_setup = comp_ctx.last_sent_ip_id_full;

    let sn_for_overflow = final_ir_sn_val.wrapping_add(1);
    let ts_for_overflow = final_ir_ts_val.wrapping_add((P1_TS_SCALED_MAX_VALUE + 1) * stride);

    let headers = create_rtp_headers(
        sn_for_overflow as u16,
        ts_for_overflow,
        false,
        TEST_SSRC_UO1_RTP,
    )
    .with_ip_id(last_ip_id_from_setup);
    let generic_headers = GenericUncompressedHeaders::RtpUdpIpv4(headers.clone());

    let compressed_packet = engine
        .compress(
            TEST_CID_UO1_RTP.into(),
            Some(RohcProfile::RtpUdpIp),
            &generic_headers,
        )
        .unwrap();

    assert!(
        compressed_packet.len() > 4,
        "Packet should be IR (len > 4) due to TS_SCALED overflow, got len {}. Packet: {:02X?}",
        compressed_packet.len(),
        compressed_packet
    );
    assert_eq!(compressed_packet[0], P1_ROHC_IR_PACKET_TYPE_WITH_DYN);
}

#[test]
fn p1_uo1_rtp_ts_misaligned_forces_ir() {
    let mut engine = create_test_engine_with_system_clock(50);
    engine
        .register_profile_handler(Box::new(Profile1Handler::new()))
        .unwrap();

    let stride = 160;
    let final_ir_sn_val = 10 + P1_TS_STRIDE_ESTABLISHMENT_THRESHOLD + 1 + 1;
    let final_ir_ts_val = 1000 + (P1_TS_STRIDE_ESTABLISHMENT_THRESHOLD + 2) * stride;

    establish_ts_stride_context_for_uo1_rtp(
        &mut engine,
        TEST_CID_UO1_RTP,
        TEST_SSRC_UO1_RTP,
        final_ir_sn_val as u16,
        final_ir_ts_val,
        stride,
    );

    let comp_ctx = get_compressor_context(&engine, TEST_CID_UO1_RTP);
    let last_ip_id_from_setup = comp_ctx.last_sent_ip_id_full;

    let next_sn = final_ir_sn_val.wrapping_add(1);
    let misaligned_ts_val = final_ir_ts_val.wrapping_add(stride / 2); // Misaligned

    let headers = create_rtp_headers(next_sn as u16, misaligned_ts_val, false, TEST_SSRC_UO1_RTP)
        .with_ip_id(last_ip_id_from_setup);
    let generic_headers = GenericUncompressedHeaders::RtpUdpIpv4(headers.clone());

    let compressed_packet = engine
        .compress(
            TEST_CID_UO1_RTP.into(),
            Some(RohcProfile::RtpUdpIp),
            &generic_headers,
        )
        .unwrap();

    assert!(
        compressed_packet.len() > 4,
        "Packet should be IR due to TS misalignment in scaled mode, got len {}. Packet: {:02X?}",
        compressed_packet.len(),
        compressed_packet
    );
    assert_eq!(compressed_packet[0], P1_ROHC_IR_PACKET_TYPE_WITH_DYN);

    let decompressed_generic = engine.decompress(&compressed_packet).unwrap();
    let decomp_headers = decompressed_generic.as_rtp_udp_ipv4().unwrap();
    assert_eq!(decomp_headers.rtp_sequence_number, next_sn as u16);
    assert_eq!(decomp_headers.rtp_timestamp, misaligned_ts_val);
}

#[test]
fn p1_uo1_rtp_ts_stride_change_forces_ir() {
    let mut engine = create_test_engine_with_system_clock(50);
    engine
        .register_profile_handler(Box::new(Profile1Handler::new()))
        .unwrap();

    let stride1 = 100;
    let final_ir_sn1 = 400 + P1_TS_STRIDE_ESTABLISHMENT_THRESHOLD + 1 + 1;
    let final_ir_ts1 = 40000 + (P1_TS_STRIDE_ESTABLISHMENT_THRESHOLD + 2) * stride1;

    establish_ts_stride_context_for_uo1_rtp(
        &mut engine,
        TEST_CID_UO1_RTP,
        TEST_SSRC_UO1_RTP,
        final_ir_sn1 as u16,
        final_ir_ts1,
        stride1,
    );

    // Send one UO-1-RTP successfully with stride1
    let comp_ctx1 = get_compressor_context(&engine, TEST_CID_UO1_RTP);
    let sn1_uo1rtp = final_ir_sn1.wrapping_add(1);
    let ts1_val_uo1rtp = final_ir_ts1.wrapping_add(stride1);
    let ip_id1 = comp_ctx1.last_sent_ip_id_full;

    let headers1 = create_rtp_headers(sn1_uo1rtp as u16, ts1_val_uo1rtp, false, TEST_SSRC_UO1_RTP)
        .with_ip_id(ip_id1);
    let generic1 = GenericUncompressedHeaders::RtpUdpIpv4(headers1);
    let compressed1 = engine
        .compress(
            TEST_CID_UO1_RTP.into(),
            Some(RohcProfile::RtpUdpIp),
            &generic1,
        )
        .unwrap();
    assert_eq!(
        compressed1.len(),
        3,
        "First UO-1-RTP packet length error. Pkt: {:02X?}",
        compressed1
    );
    assert_eq!(
        compressed1[0] & !P1_UO_1_RTP_MARKER_BIT_MASK,
        P1_UO_1_RTP_DISCRIMINATOR_BASE,
        "First UO should be UO-1-RTP. Got {:02X?}",
        compressed1[0]
    );
    let _ = engine.decompress(&compressed1).unwrap();

    let sn2 = sn1_uo1rtp.wrapping_add(1);
    let stride2 = 50; // New, different stride
    let ts2_val = ts1_val_uo1rtp.wrapping_add(stride2); // TS change implies new stride (misaligned with stride1)
    let headers2 =
        create_rtp_headers(sn2 as u16, ts2_val, false, TEST_SSRC_UO1_RTP).with_ip_id(ip_id1);
    let generic2 = GenericUncompressedHeaders::RtpUdpIpv4(headers2.clone());

    let compressed2 = engine
        .compress(
            TEST_CID_UO1_RTP.into(),
            Some(RohcProfile::RtpUdpIp),
            &generic2,
        )
        .unwrap();

    assert!(
        compressed2.len() > 4,
        "Packet should be IR due to TS stride change/misalignment, got len {}. Packet: {:02X?}",
        compressed2.len(),
        compressed2
    );
    assert_eq!(compressed2[0], P1_ROHC_IR_PACKET_TYPE_WITH_DYN);

    let decompressed_generic2 = engine.decompress(&compressed2).unwrap();
    let decomp_headers2 = decompressed_generic2.as_rtp_udp_ipv4().unwrap();
    assert_eq!(decomp_headers2.rtp_sequence_number, sn2 as u16);
    assert_eq!(decomp_headers2.rtp_timestamp, ts2_val);

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
    assert_eq!(
        comp_ctx2.ts_offset, ts1_val_uo1rtp,
        "Compressor ts_offset should be the base of the new stride detection (TS of previous packet)"
    );
    assert_eq!(
        comp_ctx2.ts_stride_packets, 1,
        "Compressor should have 1 packet counted for the new stride (the IR itself)"
    );
}

#[test]
fn p1_uo1_rtp_after_ir_with_ts_stride_succeeds() {
    let mut engine = create_test_engine_with_system_clock(50);
    engine
        .register_profile_handler(Box::new(Profile1Handler::new()))
        .unwrap();

    let stride_val = 200;
    let ir_sn_for_offset_sync = 300 + P1_TS_STRIDE_ESTABLISHMENT_THRESHOLD + 1 + 1;
    let ir_ts_for_offset_sync = 28000 + (P1_TS_STRIDE_ESTABLISHMENT_THRESHOLD + 2) * stride_val;

    establish_ts_stride_context_for_uo1_rtp(
        &mut engine,
        TEST_CID_UO1_RTP,
        TEST_SSRC_UO1_RTP,
        ir_sn_for_offset_sync as u16,
        ir_ts_for_offset_sync,
        stride_val,
    );

    let comp_ctx = get_compressor_context(&engine, TEST_CID_UO1_RTP);
    assert_eq!(
        comp_ctx.ts_offset, ir_ts_for_offset_sync,
        "Compressor ts_offset incorrect after aligned setup. Expected TS of final IR."
    );

    let last_ip_id_from_comp = comp_ctx.last_sent_ip_id_full;
    let comp_offset_val_for_assert = comp_ctx.ts_offset.value();

    let next_sn = ir_sn_for_offset_sync.wrapping_add(1);
    let next_ts_val = ir_ts_for_offset_sync.wrapping_add(stride_val);

    let headers_uo1_rtp = create_rtp_headers(next_sn as u16, next_ts_val, false, TEST_SSRC_UO1_RTP)
        .with_ip_id(last_ip_id_from_comp);
    let generic_uo1_rtp = GenericUncompressedHeaders::RtpUdpIpv4(headers_uo1_rtp.clone());

    let compressed_uo1_rtp = engine
        .compress(
            TEST_CID_UO1_RTP.into(),
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
        compressed_uo1_rtp[1], 1,
        "TS_SCALED value incorrect, expected 1. Comp offset: {}, Packet TS: {}",
        comp_offset_val_for_assert, next_ts_val
    );

    let decompressed_generic_uo1_rtp = engine.decompress(&compressed_uo1_rtp).unwrap();
    let decomp_headers_uo1_rtp = decompressed_generic_uo1_rtp.as_rtp_udp_ipv4().unwrap();

    assert_eq!(decomp_headers_uo1_rtp.rtp_sequence_number, next_sn as u16);
    assert_eq!(decomp_headers_uo1_rtp.rtp_timestamp, next_ts_val);
}

#[test]
fn p1_umode_uo1ts_selection_after_ir() {
    let mut engine = create_test_engine_with_system_clock(50);
    engine
        .register_profile_handler(Box::new(Profile1Handler::new()))
        .unwrap();
    let cid = TEST_CID_UO1_RTP;
    let ssrc = TEST_SSRC_UO1_RTP;
    let stride = 160;

    // 1. Initial IR
    let initial_sn: u16 = 10;
    let initial_ts = 1000;
    establish_ir_context(&mut engine, cid, initial_sn, initial_ts, false, ssrc);
    let ip_id_for_setup = get_ip_id_established_by_ir(initial_sn, ssrc);

    // 2. Prepare headers for the *first* UO packet
    let uo_packet_sn = initial_sn.wrapping_add(1); // SN = 11
    let uo_packet_ts = initial_ts.wrapping_add(stride); // TS = 1160 (TS changed)
    let uo_packet_marker = false; // Marker same
    let uo_packet_ip_id = ip_id_for_setup; // IP-ID same

    let headers_for_uo = create_rtp_headers(uo_packet_sn, uo_packet_ts, uo_packet_marker, ssrc)
        .with_ip_id(uo_packet_ip_id.into());

    let compressed_packet = engine
        .compress(
            cid.into(),
            Some(RohcProfile::RtpUdpIp),
            &GenericUncompressedHeaders::RtpUdpIpv4(headers_for_uo),
        )
        .unwrap();

    assert_eq!(
        compressed_packet.len(),
        4,
        "Packet should be UO-1-TS (len 4)."
    );
    if !compressed_packet.is_empty() {
        assert_eq!(
            compressed_packet[0], P1_UO_1_TS_DISCRIMINATOR,
            "Packet type should be UO-1-TS."
        );
    }
}
