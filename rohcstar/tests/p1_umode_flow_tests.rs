//! Integration tests for ROHC Profile 1 unidirectional mode packet flows.
//!
//! This module verifies correct packet type selection and state transitions during
//! typical compression sequences. Tests cover the progression from IR packets through
//! various UO (Uncompressed/Optimized) packet types under different conditions.

mod common;
use common::{
    create_rtp_headers, create_rtp_headers_fixed_ssrc, create_test_engine_with_system_clock,
    establish_ir_context, get_compressor_context, get_decompressor_context,
    get_ip_id_established_by_ir,
};
use rohcstar::profiles::profile1::RtpUdpIpv4Headers;

use rohcstar::constants::{ROHC_ADD_CID_FEEDBACK_PREFIX_VALUE, ROHC_SMALL_CID_MASK};
use rohcstar::packet_defs::{GenericUncompressedHeaders, RohcProfile};
use rohcstar::profiles::profile1::context::Profile1DecompressorMode;
use rohcstar::profiles::profile1::{
    P1_ROHC_IR_PACKET_TYPE_WITH_DYN, P1_UO_1_SN_MARKER_BIT_MASK, P1_UO_1_SN_PACKET_TYPE_PREFIX,
    P1_UO_1_TS_DISCRIMINATOR, Profile1Handler,
};

/// SSRC used for flow tests in this module.
const SSRC_FOR_FLOW_TESTS: u32 = 0x12345678;

/// Tests a sequence of packets for CID 0, transitioning from IR to UO-0 and UO-1-SN,
/// and finally forcing an IR due to TS change.
#[test]
fn p1_umode_ir_to_fo_sequence_cid0() {
    let cid: u16 = 0;
    let mut engine = create_test_engine_with_system_clock(6);
    engine
        .register_profile_handler(Box::new(Profile1Handler::new()))
        .unwrap();

    let initial_sn_p1: u16 = 100;
    let initial_ts_p1_val: u32 = 1000;
    let initial_marker_p1 = false;
    let ssrc_p1 = SSRC_FOR_FLOW_TESTS;
    let initial_ip_id_p1 = initial_sn_p1.wrapping_add(ssrc_p1 as u16);
    let headers_for_ir = RtpUdpIpv4Headers {
        ip_src: "192.168.0.1".parse().unwrap(), // Match common::create_rtp_headers
        ip_dst: "192.168.0.2".parse().unwrap(),
        udp_src_port: 1000,
        udp_dst_port: 2000,
        rtp_ssrc: ssrc_p1.into(),
        rtp_sequence_number: initial_sn_p1.into(),
        rtp_timestamp: initial_ts_p1_val.into(),
        rtp_marker: initial_marker_p1,
        ip_identification: initial_ip_id_p1.into(),
        ..Default::default()
    };
    let generic_headers_for_ir = GenericUncompressedHeaders::RtpUdpIpv4(headers_for_ir.clone());

    let mut compress_buf_p1 = [0u8; 1500];
    let rohc_packet_p1_len = engine
        .compress(
            cid.into(),
            Some(RohcProfile::RtpUdpIp),
            &generic_headers_for_ir,
            &mut compress_buf_p1,
        )
        .expect("P1 IR Compression failed");
    let rohc_packet_p1 = &compress_buf_p1[..rohc_packet_p1_len];
    engine
        .decompress(rohc_packet_p1)
        .expect("P1 IR Decompression failed");

    let comp_ctx_after_p1 = get_compressor_context(&engine, cid);

    let sn_p2 = initial_sn_p1.wrapping_add(1);
    let headers_p2 = RtpUdpIpv4Headers {
        ip_src: headers_for_ir.ip_src,
        ip_dst: headers_for_ir.ip_dst,
        udp_src_port: headers_for_ir.udp_src_port,
        udp_dst_port: headers_for_ir.udp_dst_port,
        rtp_ssrc: comp_ctx_after_p1.rtp_ssrc,
        rtp_sequence_number: sn_p2.into(),
        rtp_timestamp: comp_ctx_after_p1.last_sent_rtp_ts_full,
        rtp_marker: comp_ctx_after_p1.last_sent_rtp_marker,
        ip_identification: comp_ctx_after_p1.last_sent_ip_id_full,
        ..Default::default()
    };

    let generic_headers_p2 = GenericUncompressedHeaders::RtpUdpIpv4(headers_p2.clone());
    let mut compress_buf_p2 = [0u8; 1500];
    let rohc_packet_p2_len = engine
        .compress(
            cid.into(),
            Some(RohcProfile::RtpUdpIp),
            &generic_headers_p2,
            &mut compress_buf_p2,
        )
        .expect("P2 UO-0 Compression failed");
    let rohc_packet_p2 = &compress_buf_p2[..rohc_packet_p2_len];

    assert_eq!(
        rohc_packet_p2.len(),
        1,
        "Packet 2 (SN {}) should be UO-0",
        sn_p2
    );

    let _ = engine.decompress(rohc_packet_p2).unwrap();

    let comp_ctx_after_p2 = get_compressor_context(&engine, cid);
    let sn_p3 = sn_p2.wrapping_add(1);
    let ts_p3_val: u32 = 1160;
    let headers_p3 = RtpUdpIpv4Headers {
        ip_src: headers_for_ir.ip_src,
        ip_dst: headers_for_ir.ip_dst,
        udp_src_port: headers_for_ir.udp_src_port,
        udp_dst_port: headers_for_ir.udp_dst_port,
        rtp_ssrc: comp_ctx_after_p2.rtp_ssrc,
        rtp_sequence_number: sn_p3.into(),
        rtp_timestamp: ts_p3_val.into(),
        rtp_marker: comp_ctx_after_p2.last_sent_rtp_marker,
        ip_identification: comp_ctx_after_p2.last_sent_ip_id_full,
        ..Default::default()
    };

    let generic_headers_p3 = GenericUncompressedHeaders::RtpUdpIpv4(headers_p3.clone());
    let mut compress_buf_p3 = [0u8; 1500];
    let rohc_packet_p3_len = engine
        .compress(
            cid.into(),
            Some(RohcProfile::RtpUdpIp),
            &generic_headers_p3,
            &mut compress_buf_p3,
        )
        .unwrap();
    let rohc_packet_p3 = &compress_buf_p3[..rohc_packet_p3_len];
    assert_eq!(
        rohc_packet_p3.len(),
        4,
        "Packet 3 (SN {}) should be UO-1-TS",
        sn_p3
    );
    assert_eq!(rohc_packet_p3[0], P1_UO_1_TS_DISCRIMINATOR);
    let decompressed_generic_p3 = engine.decompress(rohc_packet_p3).unwrap();
    let decomp_headers_p3 = decompressed_generic_p3.as_rtp_udp_ipv4().unwrap();
    assert_eq!(decomp_headers_p3.rtp_timestamp, ts_p3_val);

    let comp_ctx_after_p3 = get_compressor_context(&engine, cid);
    let sn_p4 = sn_p3.wrapping_add(1);
    let marker_p4 = true;
    let ts_p4_val = 1320; // Implicit TS update via stride
    let headers_p4 = RtpUdpIpv4Headers {
        ip_src: headers_for_ir.ip_src,
        ip_dst: headers_for_ir.ip_dst,
        udp_src_port: headers_for_ir.udp_src_port,
        udp_dst_port: headers_for_ir.udp_dst_port,
        rtp_ssrc: comp_ctx_after_p3.rtp_ssrc,
        rtp_sequence_number: sn_p4.into(),
        rtp_timestamp: ts_p4_val.into(),
        rtp_marker: marker_p4,
        ip_identification: comp_ctx_after_p3.last_sent_ip_id_full,
        ..Default::default()
    };

    let generic_headers_p4 = GenericUncompressedHeaders::RtpUdpIpv4(headers_p4.clone());
    let mut compress_buf_p4 = [0u8; 1500];
    let rohc_packet_p4_len = engine
        .compress(
            cid.into(),
            Some(RohcProfile::RtpUdpIp),
            &generic_headers_p4,
            &mut compress_buf_p4,
        )
        .unwrap();
    let rohc_packet_p4 = &compress_buf_p4[..rohc_packet_p4_len];
    assert_eq!(
        rohc_packet_p4.len(),
        3,
        "Packet 4 (SN {}) should be UO-1-SN",
        sn_p4
    );
    let decompressed_generic_p4 = engine.decompress(rohc_packet_p4).unwrap();
    let decomp_headers_p4 = decompressed_generic_p4.as_rtp_udp_ipv4().unwrap();
    assert_eq!(decomp_headers_p4.rtp_timestamp, ts_p4_val);

    let comp_ctx_after_p4 = get_compressor_context(&engine, cid);
    let sn_p5 = sn_p4.wrapping_add(1);
    let marker_p5 = false;
    let ts_p5_val = 1480;
    let headers_p5 = RtpUdpIpv4Headers {
        ip_src: headers_for_ir.ip_src,
        ip_dst: headers_for_ir.ip_dst,
        udp_src_port: headers_for_ir.udp_src_port,
        udp_dst_port: headers_for_ir.udp_dst_port,
        rtp_ssrc: comp_ctx_after_p4.rtp_ssrc,
        rtp_sequence_number: sn_p5.into(),
        rtp_timestamp: ts_p5_val.into(),
        rtp_marker: marker_p5,
        ip_identification: comp_ctx_after_p4.last_sent_ip_id_full,
        ..Default::default()
    };

    let generic_headers_p5 = GenericUncompressedHeaders::RtpUdpIpv4(headers_p5.clone());
    let mut compress_buf_p5 = [0u8; 1500];
    let rohc_packet_p5_len = engine
        .compress(
            cid.into(),
            Some(RohcProfile::RtpUdpIp),
            &generic_headers_p5,
            &mut compress_buf_p5,
        )
        .unwrap();
    let rohc_packet_p5 = &compress_buf_p5[..rohc_packet_p5_len];
    assert_eq!(
        rohc_packet_p5.len(),
        3,
        "Packet 5 (SN {}) should be UO-1-SN",
        sn_p5
    );
    let decompressed_generic_p5 = engine.decompress(rohc_packet_p5).unwrap();
    let decomp_headers_p5 = decompressed_generic_p5.as_rtp_udp_ipv4().unwrap();
    assert_eq!(decomp_headers_p5.rtp_timestamp, ts_p5_val);

    let comp_ctx_after_p5 = get_compressor_context(&engine, cid);
    let sn_p6 = sn_p5.wrapping_add(1);
    let ts_p6_val = 1640;
    let headers_p6 = RtpUdpIpv4Headers {
        ip_src: headers_for_ir.ip_src,
        ip_dst: headers_for_ir.ip_dst,
        udp_src_port: headers_for_ir.udp_src_port,
        udp_dst_port: headers_for_ir.udp_dst_port,
        rtp_ssrc: comp_ctx_after_p5.rtp_ssrc,
        rtp_sequence_number: sn_p6.into(),
        rtp_timestamp: ts_p6_val.into(), // Use the calculated TS
        rtp_marker: comp_ctx_after_p5.last_sent_rtp_marker,
        ip_identification: comp_ctx_after_p5.last_sent_ip_id_full,
        ..Default::default()
    };

    let generic_headers_p6 = GenericUncompressedHeaders::RtpUdpIpv4(headers_p6.clone());
    let mut compress_buf_p6 = [0u8; 1500];
    let rohc_packet_p6_len = engine
        .compress(
            cid.into(),
            Some(RohcProfile::RtpUdpIp),
            &generic_headers_p6,
            &mut compress_buf_p6,
        )
        .unwrap();
    let rohc_packet_p6 = &compress_buf_p6[..rohc_packet_p6_len];
    assert_eq!(
        rohc_packet_p6.len(),
        4,
        "Packet 6 (SN {}) should be UO-1-TS (timestamp changes)",
        sn_p6
    );
    let _ = engine.decompress(rohc_packet_p6).unwrap();

    // P7: IR (TS changes significantly, refresh interval also met: 6 packets sent, interval 6)
    let sn_p7 = sn_p6.wrapping_add(1);
    let headers_p7 = RtpUdpIpv4Headers {
        ip_src: headers_for_ir.ip_src,
        ip_dst: headers_for_ir.ip_dst,
        udp_src_port: headers_for_ir.udp_src_port,
        udp_dst_port: headers_for_ir.udp_dst_port,
        rtp_ssrc: SSRC_FOR_FLOW_TESTS.into(),
        rtp_sequence_number: sn_p7.into(),
        rtp_timestamp: 2000.into(), // Significant TS change
        rtp_marker: true,
        ip_identification: initial_ip_id_p1
            .wrapping_add(sn_p7.wrapping_sub(initial_sn_p1))
            .into(),
        ..Default::default()
    };

    let generic_headers_p7 = GenericUncompressedHeaders::RtpUdpIpv4(headers_p7.clone());
    let mut compress_buf_p7 = [0u8; 1500];
    let rohc_packet_p7_len = engine
        .compress(
            cid.into(),
            Some(RohcProfile::RtpUdpIp),
            &generic_headers_p7,
            &mut compress_buf_p7,
        )
        .unwrap();
    let rohc_packet_p7 = &compress_buf_p7[..rohc_packet_p7_len];
    assert_eq!(
        rohc_packet_p7[0], P1_ROHC_IR_PACKET_TYPE_WITH_DYN,
        "Packet 7 (SN {}) should be IR",
        sn_p7
    );
    let decompressed_generic_p7 = engine.decompress(rohc_packet_p7).unwrap();
    let decomp_headers_p7 = decompressed_generic_p7.as_rtp_udp_ipv4().unwrap();
    assert_eq!(decomp_headers_p7.rtp_timestamp, 2000);

    let comp_ctx_after_p7 = get_compressor_context(&engine, cid);
    assert_eq!(comp_ctx_after_p7.fo_packets_sent_since_ir, 0);
}

/// Tests packet sequence for small CID with Add-CID handling through IR→UO-1-TS→UO-1-SN→IR transitions.
#[test]
fn p1_umode_ir_to_fo_sequence_small_cid() {
    let small_cid: u16 = 5;
    let mut engine = create_test_engine_with_system_clock(4);
    engine
        .register_profile_handler(Box::new(Profile1Handler::new()))
        .unwrap();

    establish_ir_context(&mut engine, small_cid, 200, 2000, true, SSRC_FOR_FLOW_TESTS);
    let ip_id_in_context = get_ip_id_established_by_ir(200, SSRC_FOR_FLOW_TESTS);

    let decomp_ctx_p1 = get_decompressor_context(&engine, small_cid);
    assert_eq!(decomp_ctx_p1.cid, small_cid);
    assert_eq!(decomp_ctx_p1.mode, Profile1DecompressorMode::FullContext);
    assert!(decomp_ctx_p1.last_reconstructed_rtp_marker);
    assert_eq!(decomp_ctx_p1.last_reconstructed_rtp_ts_full, 2000);
    let comp_ctx_p1 = get_compressor_context(&engine, small_cid);
    assert_eq!(comp_ctx_p1.last_sent_rtp_ts_full, 2000);
    assert_eq!(comp_ctx_p1.last_sent_ip_id_full, ip_id_in_context);

    let mut original_headers2 = create_rtp_headers_fixed_ssrc(201, 2160, true);
    original_headers2.ip_identification = ip_id_in_context.into();
    let generic_headers2 = GenericUncompressedHeaders::RtpUdpIpv4(original_headers2.clone());
    let mut compress_buf2_framed = [0u8; 1500];
    let rohc_packet2_framed_len = engine
        .compress(
            small_cid.into(),
            Some(RohcProfile::RtpUdpIp),
            &generic_headers2,
            &mut compress_buf2_framed,
        )
        .unwrap();
    let rohc_packet2_framed = &compress_buf2_framed[..rohc_packet2_framed_len];
    assert_eq!(
        rohc_packet2_framed.len(),
        5,
        "Packet 2 should be UO-1-TS with Add-CID"
    );
    assert_eq!(
        rohc_packet2_framed[0],
        ROHC_ADD_CID_FEEDBACK_PREFIX_VALUE | (small_cid as u8 & ROHC_SMALL_CID_MASK)
    );
    assert_eq!(rohc_packet2_framed[1], P1_UO_1_TS_DISCRIMINATOR);

    let comp_ctx_after_p2 = get_compressor_context(&engine, small_cid);
    assert_eq!(comp_ctx_after_p2.fo_packets_sent_since_ir, 1);
    assert_eq!(comp_ctx_after_p2.last_sent_rtp_ts_full, 2160);

    let decompressed_generic2 = engine.decompress(rohc_packet2_framed).unwrap();
    let decomp_headers2 = decompressed_generic2.as_rtp_udp_ipv4().unwrap();
    assert_eq!(decomp_headers2.rtp_marker, original_headers2.rtp_marker);
    assert_eq!(decomp_headers2.rtp_sequence_number, 201);
    assert_eq!(decomp_headers2.rtp_timestamp, 2160);

    let mut original_headers3 = create_rtp_headers_fixed_ssrc(202, 2160, false);
    original_headers3.ip_identification = ip_id_in_context.into();
    let generic_headers3 = GenericUncompressedHeaders::RtpUdpIpv4(original_headers3.clone());
    let mut compress_buf3_framed = [0u8; 1500];
    let rohc_packet3_framed_len = engine
        .compress(
            small_cid.into(),
            Some(RohcProfile::RtpUdpIp),
            &generic_headers3,
            &mut compress_buf3_framed,
        )
        .unwrap();
    let rohc_packet3_framed = &compress_buf3_framed[..rohc_packet3_framed_len];
    assert_eq!(
        rohc_packet3_framed.len(),
        4,
        "Packet 3 should be UO-1-SN with Add-CID"
    );
    assert_eq!(rohc_packet3_framed[1] & P1_UO_1_SN_MARKER_BIT_MASK, 0);

    let comp_ctx_after_p3 = get_compressor_context(&engine, small_cid);
    assert_eq!(comp_ctx_after_p3.fo_packets_sent_since_ir, 2);

    let decompressed_generic3 = engine.decompress(rohc_packet3_framed).unwrap();
    let decomp_headers3 = decompressed_generic3.as_rtp_udp_ipv4().unwrap();
    assert_eq!(
        decomp_headers3.rtp_sequence_number,
        original_headers3.rtp_sequence_number
    );
    assert_eq!(decomp_headers3.rtp_marker, original_headers3.rtp_marker);

    assert_eq!(decomp_headers3.rtp_timestamp, 2320);

    let mut original_headers4 = create_rtp_headers_fixed_ssrc(203, 2320, true);
    original_headers4.ip_identification = ip_id_in_context.into();
    let generic_headers4 = GenericUncompressedHeaders::RtpUdpIpv4(original_headers4.clone());
    let mut compress_buf4_framed = [0u8; 1500];
    let rohc_packet4_framed_len = engine
        .compress(
            small_cid.into(),
            Some(RohcProfile::RtpUdpIp),
            &generic_headers4,
            &mut compress_buf4_framed,
        )
        .unwrap();
    let rohc_packet4_framed = &compress_buf4_framed[..rohc_packet4_framed_len];
    assert_eq!(
        rohc_packet4_framed.len(),
        4,
        "Packet 4 should be UO-1-SN with Add-CID"
    );
    assert_ne!(rohc_packet4_framed[1] & P1_UO_1_SN_MARKER_BIT_MASK, 0);

    let comp_ctx_after_p4 = get_compressor_context(&engine, small_cid);
    assert_eq!(comp_ctx_after_p4.fo_packets_sent_since_ir, 3);

    let decompressed_generic4 = engine.decompress(rohc_packet4_framed).unwrap();
    let decomp_headers4 = decompressed_generic4.as_rtp_udp_ipv4().unwrap();
    assert_eq!(decomp_headers4.rtp_marker, original_headers4.rtp_marker);
    // Implicit TS update: 2320 + 160 = 2480
    assert_eq!(decomp_headers4.rtp_timestamp, 2480);

    // P5: IR (SN+1 from P4, TS changes significantly, refresh interval met: 4 packets sent, interval 4)
    let original_headers5 = create_rtp_headers_fixed_ssrc(204, 3000, false);
    let generic_headers5 = GenericUncompressedHeaders::RtpUdpIpv4(original_headers5.clone());
    let mut compress_buf5_framed = [0u8; 1500];
    let rohc_packet5_framed_len = engine
        .compress(
            small_cid.into(),
            Some(RohcProfile::RtpUdpIp),
            &generic_headers5,
            &mut compress_buf5_framed,
        )
        .unwrap();
    let rohc_packet5_framed = &compress_buf5_framed[..rohc_packet5_framed_len];
    assert_eq!(
        rohc_packet5_framed[0],
        ROHC_ADD_CID_FEEDBACK_PREFIX_VALUE | (small_cid as u8 & ROHC_SMALL_CID_MASK)
    );
    assert_eq!(
        rohc_packet5_framed[1], P1_ROHC_IR_PACKET_TYPE_WITH_DYN,
        "Packet 5 should be IR"
    );

    let comp_ctx_after_p5 = get_compressor_context(&engine, small_cid);
    assert_eq!(comp_ctx_after_p5.fo_packets_sent_since_ir, 0); // Reset after IR
    assert_eq!(comp_ctx_after_p5.last_sent_rtp_ts_full, 3000);

    let decompressed_generic5 = engine.decompress(rohc_packet5_framed).unwrap();
    let decomp_headers5 = decompressed_generic5.as_rtp_udp_ipv4().unwrap();
    assert_eq!(
        decomp_headers5.rtp_sequence_number,
        original_headers5.rtp_sequence_number
    );
    assert_eq!(
        decomp_headers5.rtp_timestamp,
        original_headers5.rtp_timestamp
    );
    assert_eq!(decomp_headers5.rtp_marker, original_headers5.rtp_marker);
}

/// Tests that a jump in SN beyond UO-0 capability, along with TS changes,
/// results in UO-1-TS first (to establish stride), then UO-1-SN packets.
#[test]
fn p1_umode_sn_jump_triggers_uo1() {
    let cid: u16 = 0;
    let mut engine = create_test_engine_with_system_clock(10);
    engine
        .register_profile_handler(Box::new(Profile1Handler::new()))
        .unwrap();

    // P1: Initial IR
    establish_ir_context(&mut engine, cid, 500, 5000, false, SSRC_FOR_FLOW_TESTS);
    let ip_id_from_context_p1 = get_ip_id_established_by_ir(500, SSRC_FOR_FLOW_TESTS);

    let comp_ctx_p1 = get_compressor_context(&engine, cid);
    assert_eq!(comp_ctx_p1.last_sent_rtp_ts_full, 5000);
    assert_eq!(comp_ctx_p1.last_sent_ip_id_full, ip_id_from_context_p1);

    // P2: UO-0 (SN+1)
    let mut headers2 = create_rtp_headers_fixed_ssrc(501, 5000, false);
    headers2.ip_identification = ip_id_from_context_p1.into();
    let generic2 = GenericUncompressedHeaders::RtpUdpIpv4(headers2.clone());
    let mut compress_buf_2 = [0u8; 1500];
    let rohc_packet2_len = engine
        .compress(
            cid.into(),
            Some(RohcProfile::RtpUdpIp),
            &generic2,
            &mut compress_buf_2,
        )
        .unwrap();
    let rohc_packet2 = &compress_buf_2[..rohc_packet2_len];
    assert_eq!(rohc_packet2.len(), 1, "Packet 2 should be UO-0");

    let decomp_generic2 = engine.decompress(rohc_packet2).unwrap();
    let decomp_headers2 = decomp_generic2.as_rtp_udp_ipv4().unwrap();
    assert_eq!(decomp_headers2.rtp_sequence_number, 501);
    assert!(!decomp_headers2.rtp_marker);
    assert_eq!(decomp_headers2.rtp_timestamp, 5000);

    // P3: UO-1-TS (SN+1, TS changes to establish stride)
    let mut headers3 = create_rtp_headers_fixed_ssrc(502, 5160, false); // TS changed by 160
    headers3.ip_identification = ip_id_from_context_p1.into();
    let generic3 = GenericUncompressedHeaders::RtpUdpIpv4(headers3.clone());
    let mut compress_buf_3 = [0u8; 1500];
    let rohc_packet3_len = engine
        .compress(
            cid.into(),
            Some(RohcProfile::RtpUdpIp),
            &generic3,
            &mut compress_buf_3,
        )
        .unwrap();
    let rohc_packet3 = &compress_buf_3[..rohc_packet3_len];
    assert_eq!(rohc_packet3.len(), 4, "Packet 3 should be UO-1-TS");
    assert_eq!(rohc_packet3[0], P1_UO_1_TS_DISCRIMINATOR);

    let decomp_generic3 = engine.decompress(rohc_packet3).unwrap();
    let decomp_headers3 = decomp_generic3.as_rtp_udp_ipv4().unwrap();
    assert_eq!(decomp_headers3.rtp_sequence_number, 502);
    assert_eq!(decomp_headers3.rtp_timestamp, 5160);

    // P4: UO-1-SN (SN jumps by +15 from last SN, stride now established)
    let mut headers4 = create_rtp_headers_fixed_ssrc(517, 5160, false); // SN 502 -> 517 (jump of 15)
    headers4.ip_identification = ip_id_from_context_p1.wrapping_add(1).into(); // IP-ID also changes
    let generic4 = GenericUncompressedHeaders::RtpUdpIpv4(headers4.clone());
    let mut compress_buf_4 = [0u8; 1500];
    let rohc_packet4_len = engine
        .compress(
            cid.into(),
            Some(RohcProfile::RtpUdpIp),
            &generic4,
            &mut compress_buf_4,
        )
        .unwrap();
    let rohc_packet4 = &compress_buf_4[..rohc_packet4_len];
    assert_eq!(rohc_packet4.len(), 3, "Packet 4 should be UO-1-SN");
    assert_eq!(
        rohc_packet4[0] & P1_UO_1_SN_PACKET_TYPE_PREFIX,
        P1_UO_1_SN_PACKET_TYPE_PREFIX
    );
    assert_eq!((rohc_packet4[0] & P1_UO_1_SN_MARKER_BIT_MASK), 0); // Marker is false

    let decomp_generic4 = engine.decompress(rohc_packet4).unwrap();
    let decomp_headers4 = decomp_generic4.as_rtp_udp_ipv4().unwrap();
    assert_eq!(decomp_headers4.rtp_sequence_number, 517);
    assert!(!decomp_headers4.rtp_marker);

    // Implicit timestamp calculation: 5160 + (15 * 160) = 5160 + 2400 = 7560
    assert_eq!(decomp_headers4.rtp_timestamp, 7560);

    let decomp_ctx = get_decompressor_context(&engine, cid);
    assert_eq!(decomp_ctx.last_reconstructed_rtp_sn_full, 517);
    assert_eq!(decomp_ctx.last_reconstructed_rtp_ts_full, 7560);
    let comp_ctx_p4 = get_compressor_context(&engine, cid);
    assert_eq!(comp_ctx_p4.last_sent_rtp_ts_full, 7560); // Implicit TS from UO-1-SN
    assert_eq!(comp_ctx_p4.last_sent_ip_id_full, headers4.ip_identification);
}

/// Tests UO-0 SN decoding robustness in the presence of simulated packet loss.
/// Ensures the decompressor can correctly interpret LSBs after missing some packets.
#[test]
fn p1_umode_uo0_sn_decoding_with_simulated_packet_loss() {
    let cid: u16 = 0;
    let mut engine = create_test_engine_with_system_clock(20);
    engine
        .register_profile_handler(Box::new(Profile1Handler::new()))
        .unwrap();

    // Establish context with SN 100
    establish_ir_context(&mut engine, cid, 100, 1000, false, SSRC_FOR_FLOW_TESTS);
    let ip_id_in_comp_ctx = get_ip_id_established_by_ir(100, SSRC_FOR_FLOW_TESTS);

    let decomp_ctx_initial = get_decompressor_context(&engine, cid);
    assert_eq!(decomp_ctx_initial.last_reconstructed_rtp_sn_full, 100);
    assert_eq!(
        decomp_ctx_initial.mode,
        Profile1DecompressorMode::FullContext
    );
    assert_eq!(decomp_ctx_initial.last_reconstructed_rtp_ts_full, 1000);

    // Simulate packet for SN 101 being compressed but "lost" (not sent to decompressor)
    let mut headers_sn101 = create_rtp_headers_fixed_ssrc(101, 1000, false);
    headers_sn101.ip_identification = ip_id_in_comp_ctx.into();
    let mut _compress_buf_lost1 = [0u8; 1500];
    let _rohc_lost_packet1_len = engine
        .compress(
            cid.into(),
            Some(RohcProfile::RtpUdpIp),
            &GenericUncompressedHeaders::RtpUdpIpv4(headers_sn101.clone()),
            &mut _compress_buf_lost1,
        )
        .unwrap();

    // Simulate packet for SN 102 being compressed but "lost"
    let mut headers_sn102 = create_rtp_headers_fixed_ssrc(102, 1000, false);
    headers_sn102.ip_identification = ip_id_in_comp_ctx.into();
    let mut _compress_buf_lost2 = [0u8; 1500];
    let _rohc_lost_packet2_len = engine
        .compress(
            cid.into(),
            Some(RohcProfile::RtpUdpIp),
            &GenericUncompressedHeaders::RtpUdpIpv4(headers_sn102.clone()),
            &mut _compress_buf_lost2,
        )
        .unwrap();

    // Compressor context should be at SN 102
    let comp_ctx_after_loss_sim = get_compressor_context(&engine, cid);
    assert_eq!(comp_ctx_after_loss_sim.last_sent_rtp_sn_full, 102);
    assert_eq!(comp_ctx_after_loss_sim.last_sent_rtp_ts_full, 1000);
    assert_eq!(
        comp_ctx_after_loss_sim.last_sent_ip_id_full,
        ip_id_in_comp_ctx
    );

    // Decompressor context is still at SN 100.
    // Now send packet for SN 103.
    let mut headers_sn103 = create_rtp_headers_fixed_ssrc(103, 1000, false);
    headers_sn103.ip_identification = ip_id_in_comp_ctx.into();
    let generic_h103 = GenericUncompressedHeaders::RtpUdpIpv4(headers_sn103.clone());
    let mut compress_buf_103 = [0u8; 1500];
    let rohc_packet_sn103_len = engine
        .compress(
            cid.into(),
            Some(RohcProfile::RtpUdpIp),
            &generic_h103,
            &mut compress_buf_103,
        )
        .unwrap();
    let rohc_packet_sn103 = &compress_buf_103[..rohc_packet_sn103_len];
    assert_eq!(rohc_packet_sn103.len(), 1); // Should be UO-0

    // Decompressor should decode SN 103 correctly using its window around 100.
    let decomp_gen_103 = engine.decompress(rohc_packet_sn103).unwrap();
    let decomp_headers_103 = decomp_gen_103.as_rtp_udp_ipv4().unwrap();
    assert_eq!(decomp_headers_103.rtp_sequence_number, 103);
    assert_eq!(decomp_headers_103.rtp_timestamp, 1000);

    let decomp_ctx_after_103 = get_decompressor_context(&engine, cid);
    assert_eq!(decomp_ctx_after_103.last_reconstructed_rtp_sn_full, 103);
    assert_eq!(decomp_ctx_after_103.last_reconstructed_rtp_ts_full, 1000);

    // Send packet for SN 104
    let mut headers_sn104 = create_rtp_headers_fixed_ssrc(104, 1000, false);
    headers_sn104.ip_identification = ip_id_in_comp_ctx.into();
    let generic_h104 = GenericUncompressedHeaders::RtpUdpIpv4(headers_sn104.clone());
    let mut compress_buf_104 = [0u8; 1500];
    let rohc_packet_sn104_len = engine
        .compress(
            cid.into(),
            Some(RohcProfile::RtpUdpIp),
            &generic_h104,
            &mut compress_buf_104,
        )
        .unwrap();
    let rohc_packet_sn104 = &compress_buf_104[..rohc_packet_sn104_len];
    assert_eq!(rohc_packet_sn104.len(), 1); // UO-0

    let decomp_gen_104 = engine.decompress(rohc_packet_sn104).unwrap();
    let decomp_headers_104 = decomp_gen_104.as_rtp_udp_ipv4().unwrap();
    assert_eq!(decomp_headers_104.rtp_sequence_number, 104);
    assert_eq!(decomp_headers_104.rtp_timestamp, 1000);

    let decomp_ctx_after_104 = get_decompressor_context(&engine, cid);
    assert_eq!(decomp_ctx_after_104.last_reconstructed_rtp_sn_full, 104);
    assert_eq!(decomp_ctx_after_104.last_reconstructed_rtp_ts_full, 1000);
}

#[test]
fn p1_umode_uo0_sequence_preserved() {
    let cid: u16 = 0;
    let mut engine = create_test_engine_with_system_clock(20);
    engine
        .register_profile_handler(Box::new(Profile1Handler::new()))
        .unwrap();

    // Establish context with SN 100
    establish_ir_context(&mut engine, cid, 100, 1000, false, SSRC_FOR_FLOW_TESTS);
    let ip_id_in_comp_ctx = get_ip_id_established_by_ir(100, SSRC_FOR_FLOW_TESTS);

    // Test sequence of UO-0 packets (all conditions same except SN)
    for sn in 101..106 {
        let headers = create_rtp_headers(sn, 1000, false, SSRC_FOR_FLOW_TESTS)
            .with_ip_id(ip_id_in_comp_ctx.into());
        let generic = GenericUncompressedHeaders::RtpUdpIpv4(headers.clone());

        let mut compress_buf_generic = [0u8; 1500];
        let rohc_packet_len = engine
            .compress(
                cid.into(),
                Some(RohcProfile::RtpUdpIp),
                &generic,
                &mut compress_buf_generic,
            )
            .unwrap();
        let rohc_packet = &compress_buf_generic[..rohc_packet_len];

        assert_eq!(rohc_packet.len(), 1, "Packet SN {} should be UO-0", sn);
        assert_eq!(rohc_packet[0] & 0x80, 0, "Should be UO-0 discriminator");

        let decompressed = engine.decompress(rohc_packet).unwrap();
        let decomp_headers = decompressed.as_rtp_udp_ipv4().unwrap();
        assert_eq!(decomp_headers.rtp_sequence_number, sn);
        assert_eq!(decomp_headers.rtp_timestamp, 1000);
        assert!(!decomp_headers.rtp_marker);
    }
}

#[test]
fn p1_umode_ir_to_fo_sequence_cid0_fixed() {
    let cid: u16 = 0;
    let mut engine = create_test_engine_with_system_clock(6);
    engine
        .register_profile_handler(Box::new(Profile1Handler::new()))
        .unwrap();

    // P1: Initial IR
    establish_ir_context(&mut engine, cid, 100, 1000, false, SSRC_FOR_FLOW_TESTS);
    let comp_ctx_after_ir = get_compressor_context(&engine, cid);
    let actual_ip_id_in_context = comp_ctx_after_ir.last_sent_ip_id_full;

    // P2: UO-0 (SN+1, TS/Marker/IP-ID same as context)
    let mut original_headers2 = create_rtp_headers_fixed_ssrc(101, 1000, false);
    original_headers2.ip_identification = actual_ip_id_in_context; // Use actual context value
    original_headers2.rtp_ssrc = comp_ctx_after_ir.rtp_ssrc;
    original_headers2.rtp_timestamp = comp_ctx_after_ir.last_sent_rtp_ts_full;
    original_headers2.rtp_marker = comp_ctx_after_ir.last_sent_rtp_marker;

    let generic_headers2 = GenericUncompressedHeaders::RtpUdpIpv4(original_headers2.clone());
    let mut compress_buf_h2 = [0u8; 1500];
    let rohc_packet2_len = engine
        .compress(
            cid.into(),
            Some(RohcProfile::RtpUdpIp),
            &generic_headers2,
            &mut compress_buf_h2,
        )
        .unwrap();
    let rohc_packet2 = &compress_buf_h2[..rohc_packet2_len];
    assert_eq!(rohc_packet2.len(), 1, "Packet 2 should be UO-0");
    let _ = engine.decompress(rohc_packet2).unwrap();

    // P3: UO-1-TS (SN+1 from P2, TS changes to establish stride, marker same)
    let comp_ctx_after_p2 = get_compressor_context(&engine, cid);
    let mut original_headers3 = create_rtp_headers_fixed_ssrc(102, 1160, false);
    original_headers3.ip_identification = comp_ctx_after_p2.last_sent_ip_id_full;
    original_headers3.rtp_ssrc = comp_ctx_after_p2.rtp_ssrc;
    original_headers3.rtp_marker = comp_ctx_after_p2.last_sent_rtp_marker;

    let generic_headers3 = GenericUncompressedHeaders::RtpUdpIpv4(original_headers3.clone());
    let mut compress_buf_h3 = [0u8; 1500];
    let rohc_packet3_len = engine
        .compress(
            cid.into(),
            Some(RohcProfile::RtpUdpIp),
            &generic_headers3,
            &mut compress_buf_h3,
        )
        .unwrap();
    let rohc_packet3 = &compress_buf_h3[..rohc_packet3_len];
    assert_eq!(rohc_packet3.len(), 4, "Packet 3 should be UO-1-TS");
    assert_eq!(rohc_packet3[0], P1_UO_1_TS_DISCRIMINATOR);
    let decompressed_generic3 = engine.decompress(rohc_packet3).unwrap();
    let decomp_headers3 = decompressed_generic3.as_rtp_udp_ipv4().unwrap();
    assert_eq!(decomp_headers3.rtp_timestamp, 1160);
}

#[test]
fn p1_umode_ir_to_fo_sequence_cid0_context_consistent() {
    let cid: u16 = 0;
    let mut engine = create_test_engine_with_system_clock(6);
    engine
        .register_profile_handler(Box::new(Profile1Handler::new()))
        .unwrap();

    // P1: Initial IR with known values
    let ir_headers = create_rtp_headers_fixed_ssrc(100, 1000, false);
    let generic_ir = GenericUncompressedHeaders::RtpUdpIpv4(ir_headers.clone());
    let mut compress_buf_ir = [0u8; 1500];
    let ir_packet_len = engine
        .compress(
            cid.into(),
            Some(RohcProfile::RtpUdpIp),
            &generic_ir,
            &mut compress_buf_ir,
        )
        .unwrap();
    let ir_packet = &compress_buf_ir[..ir_packet_len];
    let _decomp_ir = engine.decompress(ir_packet).unwrap();

    // Get the established context values
    let comp_ctx = get_compressor_context(&engine, cid);
    let decomp_ctx = get_decompressor_context(&engine, cid);

    // Verify contexts are synchronized
    assert_eq!(comp_ctx.rtp_ssrc, decomp_ctx.rtp_ssrc);
    assert_eq!(
        comp_ctx.last_sent_rtp_sn_full,
        decomp_ctx.last_reconstructed_rtp_sn_full
    );
    assert_eq!(
        comp_ctx.last_sent_rtp_ts_full,
        decomp_ctx.last_reconstructed_rtp_ts_full
    );
    assert_eq!(
        comp_ctx.last_sent_rtp_marker,
        decomp_ctx.last_reconstructed_rtp_marker
    );
    // For Profile 1, IP-ID is not sent in IR, so decompressor initializes it to 0.
    // The compressor knows the IP-ID of the packet it used for IR.
    // This assertion specifically checks the decompressor's state.
    assert_eq!(decomp_ctx.last_reconstructed_ip_id_full, 0);

    // P2: UO-0 - create headers that exactly match compressor context expectations
    let mut uo0_headers = create_rtp_headers_fixed_ssrc(
        101,                                    // SN changes
        comp_ctx.last_sent_rtp_ts_full.value(), // TS same as context
        comp_ctx.last_sent_rtp_marker,          // Marker same as context
    );
    uo0_headers.rtp_ssrc = comp_ctx.rtp_ssrc; // SSRC same as context
    uo0_headers.ip_identification = comp_ctx.last_sent_ip_id_full; // IP-ID same as context

    let generic_uo0 = GenericUncompressedHeaders::RtpUdpIpv4(uo0_headers);
    let mut compress_buf_uo0 = [0u8; 1500];
    let uo0_packet_len = engine
        .compress(
            cid.into(),
            Some(RohcProfile::RtpUdpIp),
            &generic_uo0,
            &mut compress_buf_uo0,
        )
        .unwrap();
    let uo0_packet = &compress_buf_uo0[..uo0_packet_len];
    assert_eq!(uo0_packet.len(), 1, "Should be UO-0");
    let _decomp_uo0 = engine.decompress(uo0_packet).unwrap();
}
