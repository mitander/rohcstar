//! Integration tests for ROHC Profile 1 unidirectional mode packet flows.
//!
//! This module verifies correct packet type selection and state transitions during
//! typical compression sequences. Tests cover the progression from IR packets through
//! various UO (Uncompressed/Optimized) packet types under different conditions.

mod common;
use common::{
    create_rtp_headers_fixed_ssrc, create_test_engine_with_system_clock, establish_ir_context,
    get_compressor_context, get_decompressor_context, get_ip_id_established_by_ir,
};

use rohcstar::constants::{ROHC_ADD_CID_FEEDBACK_PREFIX_VALUE, ROHC_SMALL_CID_MASK};
use rohcstar::packet_defs::{GenericUncompressedHeaders, RohcProfile};
use rohcstar::profiles::profile1::context::Profile1DecompressorMode;
use rohcstar::profiles::profile1::protocol_types::Timestamp;
use rohcstar::profiles::profile1::{
    P1_ROHC_IR_PACKET_TYPE_WITH_DYN, P1_UO_1_SN_MARKER_BIT_MASK, P1_UO_1_SN_PACKET_TYPE_PREFIX,
    Profile1Handler,
};

const SSRC_FOR_FLOW_TESTS: u32 = 0x12345678;

#[test]
fn p1_umode_ir_to_fo_sequence_cid0() {
    let cid: u16 = 0;
    let mut engine = create_test_engine_with_system_clock(5);
    engine
        .register_profile_handler(Box::new(Profile1Handler::new()))
        .unwrap();

    establish_ir_context(&mut engine, cid, 100, 1000, false, SSRC_FOR_FLOW_TESTS);
    let ip_id_in_context = get_ip_id_established_by_ir(100, SSRC_FOR_FLOW_TESTS);

    let mut original_headers2 = create_rtp_headers_fixed_ssrc(101, 1000, false);
    original_headers2.ip_identification = ip_id_in_context;
    let generic_headers2 = GenericUncompressedHeaders::RtpUdpIpv4(original_headers2.clone());
    let rohc_packet2 = engine
        .compress(cid, Some(RohcProfile::RtpUdpIp), &generic_headers2)
        .unwrap();
    assert_eq!(rohc_packet2.len(), 1);
    let _ = engine.decompress(&rohc_packet2).unwrap();

    let mut original_headers3 = create_rtp_headers_fixed_ssrc(102, 1000, true);
    original_headers3.ip_identification = ip_id_in_context;
    let generic_headers3 = GenericUncompressedHeaders::RtpUdpIpv4(original_headers3.clone());
    let rohc_packet3 = engine
        .compress(cid, Some(RohcProfile::RtpUdpIp), &generic_headers3)
        .unwrap();
    assert_eq!(rohc_packet3.len(), 3);
    let decompressed_generic3 = engine.decompress(&rohc_packet3).unwrap();
    let decomp_headers3 = decompressed_generic3.as_rtp_udp_ipv4().unwrap();
    assert_eq!(decomp_headers3.rtp_timestamp, Timestamp::new(1000));

    let mut original_headers4 = create_rtp_headers_fixed_ssrc(103, 1000, false);
    original_headers4.ip_identification = ip_id_in_context;
    let generic_headers4 = GenericUncompressedHeaders::RtpUdpIpv4(original_headers4.clone());
    let rohc_packet4 = engine
        .compress(cid, Some(RohcProfile::RtpUdpIp), &generic_headers4)
        .unwrap();
    assert_eq!(rohc_packet4.len(), 3);
    let decompressed_generic4 = engine.decompress(&rohc_packet4).unwrap();
    let decomp_headers4 = decompressed_generic4.as_rtp_udp_ipv4().unwrap();
    assert_eq!(decomp_headers4.rtp_timestamp, Timestamp::new(1000));

    let mut original_headers5 = create_rtp_headers_fixed_ssrc(104, 1000, false);
    original_headers5.ip_identification = ip_id_in_context;
    let generic_headers5 = GenericUncompressedHeaders::RtpUdpIpv4(original_headers5.clone());
    let rohc_packet5 = engine
        .compress(cid, Some(RohcProfile::RtpUdpIp), &generic_headers5)
        .unwrap();
    assert_eq!(rohc_packet5.len(), 1);
    let _ = engine.decompress(&rohc_packet5).unwrap();

    let original_headers6 = create_rtp_headers_fixed_ssrc(105, 1800, true);
    let generic_headers6 = GenericUncompressedHeaders::RtpUdpIpv4(original_headers6.clone());
    let rohc_packet6 = engine
        .compress(cid, Some(RohcProfile::RtpUdpIp), &generic_headers6)
        .unwrap();
    assert_eq!(rohc_packet6[0], P1_ROHC_IR_PACKET_TYPE_WITH_DYN);
    let decompressed_generic6 = engine.decompress(&rohc_packet6).unwrap();
    let decomp_headers6 = decompressed_generic6.as_rtp_udp_ipv4().unwrap();
    assert_eq!(decomp_headers6.rtp_timestamp, Timestamp::new(1800));

    let comp_ctx = get_compressor_context(&engine, cid);
    assert_eq!(comp_ctx.fo_packets_sent_since_ir, 0);
}

#[test]
fn p1_umode_ir_to_fo_sequence_small_cid() {
    let small_cid: u16 = 5;
    let mut engine = create_test_engine_with_system_clock(3);
    engine
        .register_profile_handler(Box::new(Profile1Handler::new()))
        .unwrap();

    establish_ir_context(&mut engine, small_cid, 200, 2000, true, SSRC_FOR_FLOW_TESTS);
    let ip_id_in_context = get_ip_id_established_by_ir(200, SSRC_FOR_FLOW_TESTS);

    let decomp_ctx_p1 = get_decompressor_context(&engine, small_cid);
    assert_eq!(decomp_ctx_p1.cid, small_cid);
    assert_eq!(decomp_ctx_p1.mode, Profile1DecompressorMode::FullContext);
    assert!(decomp_ctx_p1.last_reconstructed_rtp_marker);
    assert_eq!(
        decomp_ctx_p1.last_reconstructed_rtp_ts_full,
        Timestamp::new(2000)
    );
    let comp_ctx_p1 = get_compressor_context(&engine, small_cid);
    assert_eq!(comp_ctx_p1.last_sent_rtp_ts_full, Timestamp::new(2000));
    assert_eq!(comp_ctx_p1.last_sent_ip_id_full, ip_id_in_context);

    let mut original_headers2 = create_rtp_headers_fixed_ssrc(201, 2000, false);
    original_headers2.ip_identification = ip_id_in_context;
    let generic_headers2 = GenericUncompressedHeaders::RtpUdpIpv4(original_headers2.clone());
    let rohc_packet2_framed = engine
        .compress(small_cid, Some(RohcProfile::RtpUdpIp), &generic_headers2)
        .unwrap();
    assert_eq!(
        rohc_packet2_framed[0],
        ROHC_ADD_CID_FEEDBACK_PREFIX_VALUE | (small_cid as u8 & ROHC_SMALL_CID_MASK)
    );
    assert_eq!(rohc_packet2_framed.len(), 4);
    assert_eq!(
        rohc_packet2_framed[1] & P1_UO_1_SN_PACKET_TYPE_PREFIX,
        P1_UO_1_SN_PACKET_TYPE_PREFIX
    );
    assert_eq!(rohc_packet2_framed[1] & P1_UO_1_SN_MARKER_BIT_MASK, 0);

    let comp_ctx_after_p2 = get_compressor_context(&engine, small_cid);
    assert_eq!(comp_ctx_after_p2.fo_packets_sent_since_ir, 1);
    assert_eq!(
        comp_ctx_after_p2.last_sent_rtp_ts_full,
        Timestamp::new(2000)
    );
    assert_eq!(comp_ctx_after_p2.last_sent_ip_id_full, ip_id_in_context);

    let decompressed_generic2 = engine.decompress(&rohc_packet2_framed).unwrap();
    let decomp_headers2 = decompressed_generic2.as_rtp_udp_ipv4().unwrap();
    assert_eq!(decomp_headers2.rtp_marker, original_headers2.rtp_marker);
    assert_eq!(decomp_headers2.rtp_sequence_number, 201);
    assert_eq!(decomp_headers2.rtp_timestamp, Timestamp::new(2000));
    let decomp_ctx_p2 = get_decompressor_context(&engine, small_cid);
    assert_eq!(
        decomp_ctx_p2.last_reconstructed_rtp_ts_full,
        Timestamp::new(2000)
    );

    let mut original_headers3 = create_rtp_headers_fixed_ssrc(202, 2000, true);
    original_headers3.ip_identification = ip_id_in_context;
    let generic_headers3 = GenericUncompressedHeaders::RtpUdpIpv4(original_headers3.clone());
    let rohc_packet3_framed = engine
        .compress(small_cid, Some(RohcProfile::RtpUdpIp), &generic_headers3)
        .unwrap();
    assert_eq!(rohc_packet3_framed.len(), 4);
    assert_ne!(rohc_packet3_framed[1] & P1_UO_1_SN_MARKER_BIT_MASK, 0);

    let comp_ctx_after_p3 = get_compressor_context(&engine, small_cid);
    assert_eq!(comp_ctx_after_p3.fo_packets_sent_since_ir, 2);
    assert_eq!(
        comp_ctx_after_p3.last_sent_rtp_ts_full,
        Timestamp::new(2000)
    );
    assert_eq!(comp_ctx_after_p3.last_sent_ip_id_full, ip_id_in_context);

    let decompressed_generic3 = engine.decompress(&rohc_packet3_framed).unwrap();
    let decomp_headers3 = decompressed_generic3.as_rtp_udp_ipv4().unwrap();
    assert_eq!(
        decomp_headers3.rtp_sequence_number,
        original_headers3.rtp_sequence_number
    );
    assert_eq!(decomp_headers3.rtp_marker, original_headers3.rtp_marker);
    assert_eq!(decomp_headers3.rtp_timestamp, Timestamp::new(2000));
    let decomp_ctx_p3 = get_decompressor_context(&engine, small_cid);
    assert_eq!(
        decomp_ctx_p3.last_reconstructed_rtp_ts_full,
        Timestamp::new(2000)
    );

    let original_headers4 = create_rtp_headers_fixed_ssrc(203, 2480, false);
    let generic_headers4 = GenericUncompressedHeaders::RtpUdpIpv4(original_headers4.clone());
    let rohc_packet4_framed = engine
        .compress(small_cid, Some(RohcProfile::RtpUdpIp), &generic_headers4)
        .unwrap();
    assert_eq!(
        rohc_packet4_framed[0],
        ROHC_ADD_CID_FEEDBACK_PREFIX_VALUE | (small_cid as u8 & ROHC_SMALL_CID_MASK)
    );
    assert_eq!(rohc_packet4_framed[1], P1_ROHC_IR_PACKET_TYPE_WITH_DYN);

    let comp_ctx_after_p4 = get_compressor_context(&engine, small_cid);
    assert_eq!(comp_ctx_after_p4.fo_packets_sent_since_ir, 0);
    assert_eq!(
        comp_ctx_after_p4.last_sent_rtp_ts_full,
        Timestamp::new(2480)
    );

    let decompressed_generic4 = engine.decompress(&rohc_packet4_framed).unwrap();
    let decomp_headers4 = decompressed_generic4.as_rtp_udp_ipv4().unwrap();
    assert_eq!(
        decomp_headers4.rtp_sequence_number,
        original_headers4.rtp_sequence_number
    );
    assert_eq!(
        decomp_headers4.rtp_timestamp,
        original_headers4.rtp_timestamp
    );
    assert_eq!(decomp_headers4.rtp_marker, original_headers4.rtp_marker);
    let decomp_ctx_p4 = get_decompressor_context(&engine, small_cid);
    assert_eq!(
        decomp_ctx_p4.last_reconstructed_rtp_ts_full,
        Timestamp::new(2480)
    );
}

#[test]
fn p1_umode_sn_jump_triggers_uo1() {
    let cid: u16 = 0;
    let mut engine = create_test_engine_with_system_clock(10);
    engine
        .register_profile_handler(Box::new(Profile1Handler::new()))
        .unwrap();

    establish_ir_context(&mut engine, cid, 500, 5000, false, SSRC_FOR_FLOW_TESTS);
    let ip_id_from_context_p1 = get_ip_id_established_by_ir(500, SSRC_FOR_FLOW_TESTS);

    let comp_ctx_p1 = get_compressor_context(&engine, cid);
    assert_eq!(comp_ctx_p1.last_sent_rtp_ts_full, Timestamp::new(5000));
    assert_eq!(comp_ctx_p1.last_sent_ip_id_full, ip_id_from_context_p1);

    let mut headers2 = create_rtp_headers_fixed_ssrc(501, 5000, false);
    headers2.ip_identification = ip_id_from_context_p1;
    let generic2 = GenericUncompressedHeaders::RtpUdpIpv4(headers2.clone());
    let rohc_packet2 = engine
        .compress(cid, Some(RohcProfile::RtpUdpIp), &generic2)
        .unwrap();
    assert_eq!(rohc_packet2.len(), 1);

    let decomp_generic2 = engine.decompress(&rohc_packet2).unwrap();
    let decomp_headers2 = decomp_generic2.as_rtp_udp_ipv4().unwrap();
    assert_eq!(decomp_headers2.rtp_sequence_number, 501);
    assert!(!decomp_headers2.rtp_marker);
    assert_eq!(decomp_headers2.rtp_timestamp, Timestamp::new(5000));
    let comp_ctx_p2 = get_compressor_context(&engine, cid);
    assert_eq!(comp_ctx_p2.last_sent_rtp_ts_full, Timestamp::new(5000));
    assert_eq!(comp_ctx_p2.last_sent_ip_id_full, ip_id_from_context_p1);

    let mut headers3 = create_rtp_headers_fixed_ssrc(517, 5320, false);
    headers3.ip_identification = ip_id_from_context_p1.wrapping_add(1);
    let generic3 = GenericUncompressedHeaders::RtpUdpIpv4(headers3.clone());
    let rohc_packet3 = engine
        .compress(cid, Some(RohcProfile::RtpUdpIp), &generic3)
        .unwrap();
    assert_eq!(rohc_packet3.len(), 3);
    assert_eq!(
        rohc_packet3[0] & P1_UO_1_SN_PACKET_TYPE_PREFIX,
        P1_UO_1_SN_PACKET_TYPE_PREFIX
    );
    assert_eq!((rohc_packet3[0] & P1_UO_1_SN_MARKER_BIT_MASK), 0);

    let decomp_generic3 = engine.decompress(&rohc_packet3).unwrap();
    let decomp_headers3 = decomp_generic3.as_rtp_udp_ipv4().unwrap();
    assert_eq!(decomp_headers3.rtp_sequence_number, 517);
    assert!(!decomp_headers3.rtp_marker);
    assert_eq!(decomp_headers3.rtp_timestamp, Timestamp::new(5000)); // TS from context

    let decomp_ctx = get_decompressor_context(&engine, cid);
    assert_eq!(decomp_ctx.last_reconstructed_rtp_sn_full, 517);
    assert_eq!(
        decomp_ctx.last_reconstructed_rtp_ts_full,
        Timestamp::new(5000)
    );
    let comp_ctx_p3 = get_compressor_context(&engine, cid);
    assert_eq!(comp_ctx_p3.last_sent_rtp_ts_full, Timestamp::new(5320));
    assert_eq!(comp_ctx_p3.last_sent_ip_id_full, headers3.ip_identification);
}

#[test]
fn p1_umode_uo0_sn_decoding_with_simulated_packet_loss() {
    let cid: u16 = 0;
    let mut engine = create_test_engine_with_system_clock(20);
    engine
        .register_profile_handler(Box::new(Profile1Handler::new()))
        .unwrap();

    establish_ir_context(&mut engine, cid, 100, 1000, false, SSRC_FOR_FLOW_TESTS);
    let ip_id_in_comp_ctx = get_ip_id_established_by_ir(100, SSRC_FOR_FLOW_TESTS);

    let decomp_ctx_initial = get_decompressor_context(&engine, cid);
    assert_eq!(decomp_ctx_initial.last_reconstructed_rtp_sn_full, 100);
    assert_eq!(
        decomp_ctx_initial.mode,
        Profile1DecompressorMode::FullContext
    );
    assert_eq!(
        decomp_ctx_initial.last_reconstructed_rtp_ts_full,
        Timestamp::new(1000)
    );

    let mut headers_sn101 = create_rtp_headers_fixed_ssrc(101, 1000, false);
    headers_sn101.ip_identification = ip_id_in_comp_ctx;
    let _rohc_lost_packet1 = engine
        .compress(
            cid,
            Some(RohcProfile::RtpUdpIp),
            &GenericUncompressedHeaders::RtpUdpIpv4(headers_sn101.clone()),
        )
        .unwrap();

    let mut headers_sn102 = create_rtp_headers_fixed_ssrc(102, 1000, false);
    headers_sn102.ip_identification = ip_id_in_comp_ctx;
    let _rohc_lost_packet2 = engine
        .compress(
            cid,
            Some(RohcProfile::RtpUdpIp),
            &GenericUncompressedHeaders::RtpUdpIpv4(headers_sn102.clone()),
        )
        .unwrap();

    let comp_ctx_after_loss_sim = get_compressor_context(&engine, cid);
    assert_eq!(comp_ctx_after_loss_sim.last_sent_rtp_sn_full, 102);
    assert_eq!(
        comp_ctx_after_loss_sim.last_sent_rtp_ts_full,
        Timestamp::new(1000)
    );
    assert_eq!(
        comp_ctx_after_loss_sim.last_sent_ip_id_full,
        ip_id_in_comp_ctx
    );

    let mut headers_sn103 = create_rtp_headers_fixed_ssrc(103, 1000, false);
    headers_sn103.ip_identification = ip_id_in_comp_ctx;
    let generic_h103 = GenericUncompressedHeaders::RtpUdpIpv4(headers_sn103.clone());
    let rohc_packet_sn103 = engine
        .compress(cid, Some(RohcProfile::RtpUdpIp), &generic_h103)
        .unwrap();
    assert_eq!(rohc_packet_sn103.len(), 1);

    let decomp_gen_103 = engine.decompress(&rohc_packet_sn103).unwrap();
    let decomp_headers_103 = decomp_gen_103.as_rtp_udp_ipv4().unwrap();
    assert_eq!(decomp_headers_103.rtp_sequence_number, 103);
    assert_eq!(decomp_headers_103.rtp_timestamp, Timestamp::new(1000));

    let decomp_ctx_after_103 = get_decompressor_context(&engine, cid);
    assert_eq!(decomp_ctx_after_103.last_reconstructed_rtp_sn_full, 103);
    assert_eq!(
        decomp_ctx_after_103.last_reconstructed_rtp_ts_full,
        Timestamp::new(1000)
    );

    let mut headers_sn104 = create_rtp_headers_fixed_ssrc(104, 1000, false);
    headers_sn104.ip_identification = ip_id_in_comp_ctx;
    let generic_h104 = GenericUncompressedHeaders::RtpUdpIpv4(headers_sn104.clone());
    let rohc_packet_sn104 = engine
        .compress(cid, Some(RohcProfile::RtpUdpIp), &generic_h104)
        .unwrap();
    assert_eq!(rohc_packet_sn104.len(), 1);

    let decomp_gen_104 = engine.decompress(&rohc_packet_sn104).unwrap();
    let decomp_headers_104 = decomp_gen_104.as_rtp_udp_ipv4().unwrap();
    assert_eq!(decomp_headers_104.rtp_sequence_number, 104);
    assert_eq!(decomp_headers_104.rtp_timestamp, Timestamp::new(1000));

    let decomp_ctx_after_104 = get_decompressor_context(&engine, cid);
    assert_eq!(decomp_ctx_after_104.last_reconstructed_rtp_sn_full, 104);
    assert_eq!(
        decomp_ctx_after_104.last_reconstructed_rtp_ts_full,
        Timestamp::new(1000)
    );
}
