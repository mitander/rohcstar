//! Integration tests for ROHC Profile 1 unidirectional mode packet flows.
//!
//! This module verifies correct packet type selection and state transitions during
//! typical compression sequences. Tests cover the progression from IR packets through
//! various UO (Uncompressed/Optimized) packet types under different conditions.

mod common;
use common::{
    create_rtp_headers_fixed_ssrc, establish_ir_context, get_compressor_context,
    get_decompressor_context,
};

use rohcstar::engine::RohcEngine;
use rohcstar::packet_defs::{GenericUncompressedHeaders, RohcProfile};
use rohcstar::profiles::profile1::Profile1Handler;
use rohcstar::profiles::profile1::context::Profile1DecompressorMode;

use rohcstar::constants::{
    DEFAULT_WLSB_P_OFFSET, ROHC_ADD_CID_FEEDBACK_PREFIX_VALUE, ROHC_SMALL_CID_MASK,
};
use rohcstar::profiles::profile1::constants::{
    P1_ROHC_IR_PACKET_TYPE_WITH_DYN, P1_UO_1_SN_MARKER_BIT_MASK, P1_UO_1_SN_PACKET_TYPE_PREFIX,
};

#[test]
fn p1_umode_ir_to_fo_sequence_cid0() {
    let cid: u16 = 0;
    let ir_refresh_interval: u32 = 5;
    let mut engine = RohcEngine::new(ir_refresh_interval);
    engine
        .register_profile_handler(Box::new(Profile1Handler::new()))
        .unwrap();

    // --- Packet 1: IR (SN=100, M=false, TS=1000) ---
    establish_ir_context(&mut engine, cid, 100, 1000, false, 0x12345678);
    // Comp context: last_ts=1000. Decomp context: last_reconstructed_ts=1000.

    // --- Packet 2: UO-0 (SN=101, M=false, TS=1000) ---
    let original_headers2 = create_rtp_headers_fixed_ssrc(101, 1000, false);
    let generic_headers2 = GenericUncompressedHeaders::RtpUdpIpv4(original_headers2.clone());
    let rohc_packet2 = engine
        .compress(cid, Some(RohcProfile::RtpUdpIp), &generic_headers2)
        .unwrap();
    assert_eq!(
        rohc_packet2.len(),
        1,
        "P2_UO0: Length check. Got: {:?}",
        rohc_packet2
    );
    let _ = engine.decompress(&rohc_packet2).unwrap();
    // Comp context: last_ts=1000. Decomp context: last_reconstructed_ts=1000.

    // --- Packet 3: UO-1-SN (SN=102, M=true, Uncompressed TS=1000 to keep context same for CRC) ---
    // Marker changed. UO-1-SN will use TS=1000 from context for CRC.
    // Compressor will update its last_sent_ts to 1000. Decompressor's last_reconstructed_ts is 1000.
    let original_headers3 = create_rtp_headers_fixed_ssrc(102, 1000, true);
    let generic_headers3 = GenericUncompressedHeaders::RtpUdpIpv4(original_headers3.clone());
    let rohc_packet3 = engine
        .compress(cid, Some(RohcProfile::RtpUdpIp), &generic_headers3)
        .unwrap();
    assert_eq!(rohc_packet3.len(), 3, "P3_UO1SN: Length");
    let decompressed_generic3 = engine.decompress(&rohc_packet3).unwrap();
    let decomp_headers3 = decompressed_generic3.as_rtp_udp_ipv4().unwrap();
    assert_eq!(decomp_headers3.rtp_timestamp, 1000); // Decompressed using context TS=1000
    // Comp context: last_ts=1000. Decomp context: last_reconstructed_ts=1000.

    // --- Packet 4: UO-1-SN (SN=103, M=false, Uncompressed TS=1000 to keep context same for CRC) ---
    // Marker changed. UO-1-SN will use TS=1000 from context for CRC.
    let original_headers4 = create_rtp_headers_fixed_ssrc(103, 1000, false);
    let generic_headers4 = GenericUncompressedHeaders::RtpUdpIpv4(original_headers4.clone());
    let rohc_packet4 = engine
        .compress(cid, Some(RohcProfile::RtpUdpIp), &generic_headers4)
        .unwrap();
    assert_eq!(rohc_packet4.len(), 3, "P4_UO1SN: Length");
    let decompressed_generic4 = engine.decompress(&rohc_packet4).unwrap();
    let decomp_headers4 = decompressed_generic4.as_rtp_udp_ipv4().unwrap();
    assert_eq!(decomp_headers4.rtp_timestamp, 1000);
    // Comp context: last_ts=1000. Decomp context: last_reconstructed_ts=1000.

    // --- Packet 5: UO-0 (SN=104, M=false, TS=1000) ---
    let original_headers5 = create_rtp_headers_fixed_ssrc(104, 1000, false);
    let generic_headers5 = GenericUncompressedHeaders::RtpUdpIpv4(original_headers5.clone());
    let rohc_packet5 = engine
        .compress(cid, Some(RohcProfile::RtpUdpIp), &generic_headers5)
        .unwrap();
    assert_eq!(
        rohc_packet5.len(),
        1,
        "P5_UO0: Length. Got: {:?}",
        rohc_packet5
    );
    let _ = engine.decompress(&rohc_packet5).unwrap();
    // Comp context: last_ts=1000. Decomp context: last_reconstructed_ts=1000.

    // --- Packet 6: IR (Refresh: SN=105, M=true, TS=1800) ---
    // IR will carry and update TS to 1800.
    let original_headers6 = create_rtp_headers_fixed_ssrc(105, 1800, true);
    let generic_headers6 = GenericUncompressedHeaders::RtpUdpIpv4(original_headers6.clone());
    let rohc_packet6 = engine
        .compress(cid, Some(RohcProfile::RtpUdpIp), &generic_headers6)
        .unwrap();
    assert_eq!(rohc_packet6[0], P1_ROHC_IR_PACKET_TYPE_WITH_DYN);
    let decompressed_generic6 = engine.decompress(&rohc_packet6).unwrap();
    let decomp_headers6 = decompressed_generic6.as_rtp_udp_ipv4().unwrap();
    assert_eq!(decomp_headers6.rtp_timestamp, 1800);
    // Comp context: last_ts=1800. Decomp context: last_reconstructed_ts=1800.

    let comp_ctx = get_compressor_context(&engine, cid);
    assert_eq!(comp_ctx.fo_packets_sent_since_ir, 0);
}

#[test]
fn p1_umode_ir_to_fo_sequence_small_cid() {
    let small_cid: u16 = 5;
    let ir_refresh_interval: u32 = 3;
    let mut engine = RohcEngine::new(ir_refresh_interval);
    engine
        .register_profile_handler(Box::new(Profile1Handler::new()))
        .unwrap();

    // --- Packet 1 (IR for small_cid, SN=200, M=true, TS=2000) ---
    establish_ir_context(&mut engine, small_cid, 200, 2000, true, 0x12345678);

    let decomp_ctx_p1 = get_decompressor_context(&engine, small_cid);
    assert_eq!(decomp_ctx_p1.cid, small_cid);
    assert_eq!(decomp_ctx_p1.mode, Profile1DecompressorMode::FullContext);
    assert!(decomp_ctx_p1.last_reconstructed_rtp_marker);
    assert_eq!(decomp_ctx_p1.last_reconstructed_rtp_ts_full, 2000);
    let comp_ctx_p1 = get_compressor_context(&engine, small_cid);
    assert_eq!(comp_ctx_p1.last_sent_rtp_ts_full, 2000);

    // --- Packet 2 (UO-1-SN for small_cid, SN=201, M=false, TS from context = 2000) ---
    // Marker changed (true->false). Uncompressed header has TS=2000.
    let original_headers2 = create_rtp_headers_fixed_ssrc(201, 2000, false);
    let generic_headers2 = GenericUncompressedHeaders::RtpUdpIpv4(original_headers2.clone());
    let rohc_packet2_framed = engine
        .compress(small_cid, Some(RohcProfile::RtpUdpIp), &generic_headers2)
        .unwrap();
    assert_eq!(
        rohc_packet2_framed[0],
        ROHC_ADD_CID_FEEDBACK_PREFIX_VALUE | (small_cid as u8 & ROHC_SMALL_CID_MASK)
    );
    // UO-1-SN due to marker change. Length: AddCID(1) + Core(3) = 4
    assert_eq!(
        rohc_packet2_framed.len(),
        4,
        "P2_SCID_UO1: Length check. Got: {:?}",
        rohc_packet2_framed
    );
    assert_eq!(
        rohc_packet2_framed[1] & P1_UO_1_SN_PACKET_TYPE_PREFIX,
        P1_UO_1_SN_PACKET_TYPE_PREFIX
    );
    assert_eq!(rohc_packet2_framed[1] & P1_UO_1_SN_MARKER_BIT_MASK, 0); // M=false

    let comp_ctx_after_p2 = get_compressor_context(&engine, small_cid);
    assert_eq!(
        comp_ctx_after_p2.fo_packets_sent_since_ir, 1,
        "P2_SCID_UO1: Compressor FO count after first UO"
    );
    assert_eq!(comp_ctx_after_p2.last_sent_rtp_ts_full, 2000);

    let decompressed_generic2 = engine.decompress(&rohc_packet2_framed).unwrap();
    let decomp_headers2 = match decompressed_generic2 {
        GenericUncompressedHeaders::RtpUdpIpv4(h) => h,
        other => panic!("P2_SCID_UO1_DECOMP: Expected RtpUdpIpv4, got {:?}", other),
    };
    assert_eq!(decomp_headers2.rtp_marker, original_headers2.rtp_marker);
    assert_eq!(decomp_headers2.rtp_sequence_number, 201);
    assert_eq!(decomp_headers2.rtp_timestamp, 2000); // TS from context
    let decomp_ctx_p2 = get_decompressor_context(&engine, small_cid);
    assert_eq!(decomp_ctx_p2.last_reconstructed_rtp_ts_full, 2000);

    // --- Packet 3 (UO-1-SN for small_cid, SN=202, M=true, TS from context=2000) ---
    // Marker changed again (false -> true). Uncompressed header has TS=2000.
    let original_headers3 = create_rtp_headers_fixed_ssrc(202, 2000, true);
    let generic_headers3 = GenericUncompressedHeaders::RtpUdpIpv4(original_headers3.clone());
    let rohc_packet3_framed = engine
        .compress(small_cid, Some(RohcProfile::RtpUdpIp), &generic_headers3)
        .unwrap();
    assert_eq!(
        rohc_packet3_framed.len(),
        4,
        "P3_SCID_UO1: Length check. Got: {:?}",
        rohc_packet3_framed
    );
    assert_ne!(rohc_packet3_framed[1] & P1_UO_1_SN_MARKER_BIT_MASK, 0); // M=true

    let comp_ctx_after_p3 = get_compressor_context(&engine, small_cid);
    assert_eq!(
        comp_ctx_after_p3.fo_packets_sent_since_ir, 2,
        "P3_SCID_UO1: Compressor FO count after second UO"
    );
    assert_eq!(comp_ctx_after_p3.last_sent_rtp_ts_full, 2000);

    let decompressed_generic3 = engine.decompress(&rohc_packet3_framed).unwrap();
    let decomp_headers3 = match decompressed_generic3 {
        GenericUncompressedHeaders::RtpUdpIpv4(h) => h,
        other => panic!("P3_SCID_UO1_DECOMP: Expected RtpUdpIpv4, got {:?}", other),
    };
    assert_eq!(
        decomp_headers3.rtp_sequence_number,
        original_headers3.rtp_sequence_number
    );
    assert_eq!(decomp_headers3.rtp_marker, original_headers3.rtp_marker);
    assert_eq!(decomp_headers3.rtp_timestamp, 2000);
    let decomp_ctx_p3 = get_decompressor_context(&engine, small_cid);
    assert_eq!(decomp_ctx_p3.last_reconstructed_rtp_ts_full, 2000);

    // --- Packet 4 (IR refresh for small_cid, SN=203, M=false, TS=2480) ---
    // Uncompressed header TS changes to 2480. This is an IR.
    let original_headers4 = create_rtp_headers_fixed_ssrc(203, 2480, false);
    let generic_headers4 = GenericUncompressedHeaders::RtpUdpIpv4(original_headers4.clone());
    let rohc_packet4_framed = engine
        .compress(small_cid, Some(RohcProfile::RtpUdpIp), &generic_headers4)
        .unwrap();
    assert_eq!(
        rohc_packet4_framed[0],
        ROHC_ADD_CID_FEEDBACK_PREFIX_VALUE | (small_cid as u8 & ROHC_SMALL_CID_MASK)
    );
    assert_eq!(
        rohc_packet4_framed[1], P1_ROHC_IR_PACKET_TYPE_WITH_DYN,
        "P4_SCID_IR_REFRESH: Core IR type"
    );

    let comp_ctx_after_p4 = get_compressor_context(&engine, small_cid);
    assert_eq!(
        comp_ctx_after_p4.fo_packets_sent_since_ir, 0,
        "P4_SCID_IR_REFRESH: Compressor FO count reset"
    );
    assert_eq!(comp_ctx_after_p4.last_sent_rtp_ts_full, 2480);

    let decompressed_generic4 = engine.decompress(&rohc_packet4_framed).unwrap();
    let decomp_headers4 = match decompressed_generic4 {
        GenericUncompressedHeaders::RtpUdpIpv4(h) => h,
        other => panic!(
            "P4_SCID_IR_REFRESH_DECOMP: Expected RtpUdpIpv4, got {:?}",
            other
        ),
    };
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
    assert_eq!(decomp_ctx_p4.last_reconstructed_rtp_ts_full, 2480);
}

#[test]
fn p1_umode_sn_jump_triggers_uo1() {
    let cid: u16 = 0;
    let ir_refresh_interval: u32 = 10;
    let mut engine = RohcEngine::new(ir_refresh_interval);
    engine
        .register_profile_handler(Box::new(Profile1Handler::new()))
        .unwrap();

    // Packet 1: IR (SN=500, TS=5000)
    establish_ir_context(&mut engine, cid, 500, 5000, false, 0x12345678);
    let comp_ctx_p1 = get_compressor_context(&engine, cid);
    assert_eq!(comp_ctx_p1.last_sent_rtp_ts_full, 5000);

    // Packet 2: UO-0 (SN=501, TS=5000)
    // For UO-0, TS must be same as context (5000).
    let headers2 = create_rtp_headers_fixed_ssrc(501, 5000, false);
    let generic2 = GenericUncompressedHeaders::RtpUdpIpv4(headers2.clone());
    let rohc_packet2 = engine
        .compress(cid, Some(RohcProfile::RtpUdpIp), &generic2)
        .unwrap();
    assert_eq!(
        rohc_packet2.len(),
        1,
        "P2_SNJUMP_UO0: Length. Got: {:?}",
        rohc_packet2
    );

    let decomp_generic2 = engine.decompress(&rohc_packet2).unwrap();
    let decomp_headers2 = match decomp_generic2 {
        GenericUncompressedHeaders::RtpUdpIpv4(h) => h,
        other => panic!("P2_SNJUMP_UO0_DECOMP: Expected RtpUdpIpv4, got {:?}", other),
    };
    assert_eq!(decomp_headers2.rtp_sequence_number, 501);
    assert!(!decomp_headers2.rtp_marker);
    assert_eq!(decomp_headers2.rtp_timestamp, 5000);
    let comp_ctx_p2 = get_compressor_context(&engine, cid);
    assert_eq!(comp_ctx_p2.last_sent_rtp_ts_full, 5000);

    // Packet 3: SN jumps to 517 (from 501), TS changes, should force UO-1-SN
    // Not UO-0 because sn_diff (16) not < 16.
    // Not UO-1-TS because sn_diff is not 1.
    let headers3 = create_rtp_headers_fixed_ssrc(517, 5320, false);
    let generic3 = GenericUncompressedHeaders::RtpUdpIpv4(headers3.clone());
    let rohc_packet3 = engine
        .compress(cid, Some(RohcProfile::RtpUdpIp), &generic3)
        .unwrap();
    assert_eq!(
        rohc_packet3.len(),
        3,
        "P3_SNJUMP_UO1: Length due to SN jump. Got: {:?}",
        rohc_packet3
    );
    assert_eq!(
        rohc_packet3[0] & P1_UO_1_SN_PACKET_TYPE_PREFIX,
        P1_UO_1_SN_PACKET_TYPE_PREFIX
    );
    assert_eq!((rohc_packet3[0] & P1_UO_1_SN_MARKER_BIT_MASK), 0);

    let decomp_generic3 = engine.decompress(&rohc_packet3).unwrap();
    let decomp_headers3 = match decomp_generic3 {
        GenericUncompressedHeaders::RtpUdpIpv4(h) => h,
        other => panic!("P3_SNJUMP_UO1_DECOMP: Expected RtpUdpIpv4, got {:?}", other),
    };
    assert_eq!(decomp_headers3.rtp_sequence_number, 517);
    assert!(!decomp_headers3.rtp_marker);
    // UO-1-SN uses context TS for reconstruction. Compressor context TS was 5000.
    assert_eq!(decomp_headers3.rtp_timestamp, 5000);

    let decomp_ctx = get_decompressor_context(&engine, cid);
    assert_eq!(decomp_ctx.last_reconstructed_rtp_sn_full, 517);
    // Decompressor context TS should remain 5000 because UO-1-SN doesn't update it from packet.
    assert_eq!(decomp_ctx.last_reconstructed_rtp_ts_full, 5000);
    let comp_ctx_p3 = get_compressor_context(&engine, cid);
    assert_eq!(comp_ctx_p3.last_sent_rtp_ts_full, 5320); // Compressor TS is updated to actual header
}

#[test]
fn p1_umode_uo0_sn_decoding_with_simulated_packet_loss() {
    let cid: u16 = 0;
    let ir_refresh_interval: u32 = 20;
    let mut engine = RohcEngine::new(ir_refresh_interval);
    engine
        .register_profile_handler(Box::new(Profile1Handler::new()))
        .unwrap();

    // Packet 1: IR (SN=100, TS=1000)
    establish_ir_context(&mut engine, cid, 100, 1000, false, 0x12345678);

    let decomp_ctx_initial = get_decompressor_context(&engine, cid);
    assert_eq!(decomp_ctx_initial.last_reconstructed_rtp_sn_full, 100);
    assert_eq!(
        decomp_ctx_initial.mode,
        Profile1DecompressorMode::FullContext
    );
    assert_eq!(decomp_ctx_initial.p_sn, DEFAULT_WLSB_P_OFFSET);
    assert_eq!(decomp_ctx_initial.last_reconstructed_rtp_ts_full, 1000);

    // Simulate loss of SN=101 and SN=102 by compressing but not decompressing
    // These UO-0 packets will use TS=1000 from context.
    let headers_sn101 = create_rtp_headers_fixed_ssrc(101, 1000, false);
    let _rohc_lost_packet1 = engine
        .compress(
            cid,
            Some(RohcProfile::RtpUdpIp),
            &GenericUncompressedHeaders::RtpUdpIpv4(headers_sn101.clone()),
        )
        .unwrap();
    let headers_sn102 = create_rtp_headers_fixed_ssrc(102, 1000, false);
    let _rohc_lost_packet2 = engine
        .compress(
            cid,
            Some(RohcProfile::RtpUdpIp),
            &GenericUncompressedHeaders::RtpUdpIpv4(headers_sn102.clone()),
        )
        .unwrap();

    // Compressor context now: SN=102, TS=1000, M=false
    let comp_ctx_after_loss_sim = get_compressor_context(&engine, cid);
    assert_eq!(comp_ctx_after_loss_sim.last_sent_rtp_sn_full, 102);
    assert_eq!(comp_ctx_after_loss_sim.last_sent_rtp_ts_full, 1000);

    // Packet SN=103 - Received by decompressor.
    // To be UO-0, TS must match compressor context's last_sent_ts (1000).
    let headers_sn103 = create_rtp_headers_fixed_ssrc(103, 1000, false);
    let generic_h103 = GenericUncompressedHeaders::RtpUdpIpv4(headers_sn103.clone());
    let rohc_packet_sn103 = engine
        .compress(cid, Some(RohcProfile::RtpUdpIp), &generic_h103)
        .unwrap();
    assert_eq!(
        rohc_packet_sn103.len(),
        1,
        "PLOSS_SN103: UO-0 expected. Got: {:?}",
        rohc_packet_sn103
    );

    let decomp_gen_103 = engine.decompress(&rohc_packet_sn103).unwrap();
    let decomp_headers_103 = match decomp_gen_103 {
        GenericUncompressedHeaders::RtpUdpIpv4(h) => h,
        other => panic!("PLOSS_SN103_DECOMP: Expected RtpUdpIpv4, got {:?}", other),
    };
    assert_eq!(
        decomp_headers_103.rtp_sequence_number, 103,
        "PLOSS_SN103: SN check after loss"
    );
    assert_eq!(decomp_headers_103.rtp_timestamp, 1000); // Decompressor context still has TS=1000

    let decomp_ctx_after_103 = get_decompressor_context(&engine, cid);
    assert_eq!(decomp_ctx_after_103.last_reconstructed_rtp_sn_full, 103);
    assert_eq!(decomp_ctx_after_103.last_reconstructed_rtp_ts_full, 1000);

    // Packet SN=104 - Received by decompressor
    // To be UO-0, TS must match compressor context's TS (1000).
    let headers_sn104 = create_rtp_headers_fixed_ssrc(104, 1000, false);
    let generic_h104 = GenericUncompressedHeaders::RtpUdpIpv4(headers_sn104.clone());
    let rohc_packet_sn104 = engine
        .compress(cid, Some(RohcProfile::RtpUdpIp), &generic_h104)
        .unwrap();
    assert_eq!(
        rohc_packet_sn104.len(),
        1,
        "PLOSS_SN104: UO-0 expected. Got: {:?}",
        rohc_packet_sn104
    );

    let decomp_gen_104 = engine.decompress(&rohc_packet_sn104).unwrap();
    let decomp_headers_104 = match decomp_gen_104 {
        GenericUncompressedHeaders::RtpUdpIpv4(h) => h,
        other => panic!("PLOSS_SN104_DECOMP: Expected RtpUdpIpv4, got {:?}", other),
    };
    assert_eq!(
        decomp_headers_104.rtp_sequence_number, 104,
        "PLOSS_SN104: SN check"
    );
    assert_eq!(decomp_headers_104.rtp_timestamp, 1000);

    let decomp_ctx_after_104 = get_decompressor_context(&engine, cid);
    assert_eq!(decomp_ctx_after_104.last_reconstructed_rtp_sn_full, 104);
    assert_eq!(decomp_ctx_after_104.last_reconstructed_rtp_ts_full, 1000);
}
