//! Integration tests for ROHC Profile 1 Unidirectional mode operations,
//! using the RohcEngine and Profile1Handler.

use rohcstar::engine::RohcEngine;
use rohcstar::packet_defs::{GenericUncompressedHeaders, RohcProfile};
use rohcstar::profiles::profile1::Profile1Handler;
use rohcstar::profiles::profile1::RtpUdpIpv4Headers;
use rohcstar::profiles::profile1::context::{
    Profile1CompressorContext, Profile1DecompressorContext, Profile1DecompressorMode,
};

use rohcstar::constants::{
    DEFAULT_WLSB_P_OFFSET, ROHC_ADD_CID_FEEDBACK_PREFIX_VALUE, ROHC_SMALL_CID_MASK,
};
use rohcstar::profiles::profile1::constants::{
    P1_ROHC_IR_PACKET_TYPE_WITH_DYN, P1_UO_1_SN_MARKER_BIT_MASK, P1_UO_1_SN_PACKET_TYPE_PREFIX,
};

/// Helper function to create sample RTP/UDP/IPv4 headers for testing.
fn create_sample_rtp_packet(seq_num: u16, timestamp: u32, marker: bool) -> RtpUdpIpv4Headers {
    RtpUdpIpv4Headers {
        ip_src: "192.168.0.1".parse().unwrap(),
        ip_dst: "192.168.0.2".parse().unwrap(),
        udp_src_port: 10000,
        udp_dst_port: 20000,
        rtp_ssrc: 0x12345678,
        rtp_sequence_number: seq_num,
        rtp_timestamp: timestamp,
        rtp_marker: marker,
        ..Default::default()
    }
}

#[test]
fn p1_umode_ir_to_fo_sequence_cid0() {
    let cid: u16 = 0;
    let ir_refresh_interval: u32 = 5;
    let mut engine = RohcEngine::new(ir_refresh_interval);
    engine
        .register_profile_handler(Box::new(Profile1Handler::new()))
        .unwrap();

    // --- Packet 1: IR (SN=100, M=false) ---
    let original_headers1 = create_sample_rtp_packet(100, 1000, false);
    let generic_headers1 = GenericUncompressedHeaders::RtpUdpIpv4(original_headers1.clone());

    let rohc_packet1 = engine
        .compress(cid, Some(RohcProfile::RtpUdpIp), &generic_headers1)
        .unwrap();
    assert_eq!(
        rohc_packet1[0], P1_ROHC_IR_PACKET_TYPE_WITH_DYN,
        "P1_IR: Type check"
    );

    let decompressed_generic1 = engine.decompress(&rohc_packet1).unwrap();
    let decomp_headers1 = match decompressed_generic1 {
        GenericUncompressedHeaders::RtpUdpIpv4(h) => h,
        other => panic!("P1_IR_DECOMP: Expected RtpUdpIpv4, got {:?}", other),
    };
    assert_eq!(decomp_headers1.rtp_marker, original_headers1.rtp_marker);
    assert_eq!(
        decomp_headers1.rtp_sequence_number,
        original_headers1.rtp_sequence_number
    );

    let decomp_ctx_box = engine
        .context_manager_mut()
        .get_decompressor_context_mut(cid)
        .unwrap();
    let p1_decomp_ctx = decomp_ctx_box
        .as_any()
        .downcast_ref::<Profile1DecompressorContext>()
        .unwrap();
    assert_eq!(
        p1_decomp_ctx.mode,
        Profile1DecompressorMode::FullContext,
        "P1_IR_DECOMP: Decomp ctx mode"
    );

    // --- Packet 2: UO-0 (SN=101, M=false) ---
    let original_headers2 = create_sample_rtp_packet(101, 1160, false);
    let generic_headers2 = GenericUncompressedHeaders::RtpUdpIpv4(original_headers2.clone());
    let rohc_packet2 = engine
        .compress(cid, Some(RohcProfile::RtpUdpIp), &generic_headers2)
        .unwrap();
    assert_eq!(rohc_packet2.len(), 1, "P2_UO0: Length check");

    let decompressed_generic2 = engine.decompress(&rohc_packet2).unwrap();
    let decomp_headers2 = match decompressed_generic2 {
        GenericUncompressedHeaders::RtpUdpIpv4(h) => h,
        other => panic!("P2_UO0_DECOMP: Expected RtpUdpIpv4, got {:?}", other),
    };
    assert_eq!(
        decomp_headers2.rtp_marker, original_headers1.rtp_marker,
        "P2_UO0: Context marker"
    );
    assert_eq!(
        decomp_headers2.rtp_sequence_number,
        original_headers2.rtp_sequence_number
    );

    // --- Packet 3: UO-1-SN (SN=102, M=true) ---
    let original_headers3 = create_sample_rtp_packet(102, 1320, true);
    let generic_headers3 = GenericUncompressedHeaders::RtpUdpIpv4(original_headers3.clone());
    let rohc_packet3 = engine
        .compress(cid, Some(RohcProfile::RtpUdpIp), &generic_headers3)
        .unwrap();
    assert_eq!(rohc_packet3.len(), 3, "P3_UO1SN: Length");
    assert_eq!(
        rohc_packet3[0] & P1_UO_1_SN_PACKET_TYPE_PREFIX,
        P1_UO_1_SN_PACKET_TYPE_PREFIX
    );
    assert_ne!(rohc_packet3[0] & P1_UO_1_SN_MARKER_BIT_MASK, 0);

    let decompressed_generic3 = engine.decompress(&rohc_packet3).unwrap();
    let decomp_headers3 = match decompressed_generic3 {
        GenericUncompressedHeaders::RtpUdpIpv4(h) => h,
        other => panic!("P3_UO1SN_DECOMP: Expected RtpUdpIpv4, got {:?}", other),
    };
    assert_eq!(
        decomp_headers3.rtp_sequence_number,
        original_headers3.rtp_sequence_number
    );
    assert_eq!(decomp_headers3.rtp_marker, original_headers3.rtp_marker);
    assert_eq!(
        decomp_headers3.rtp_timestamp,
        original_headers1.rtp_timestamp
    );

    // --- Packet 4: UO-1-SN (SN=103, M=false) ---
    let original_headers4 = create_sample_rtp_packet(103, 1480, false);
    let generic_headers4 = GenericUncompressedHeaders::RtpUdpIpv4(original_headers4.clone());
    let rohc_packet4 = engine
        .compress(cid, Some(RohcProfile::RtpUdpIp), &generic_headers4)
        .unwrap();
    assert_eq!(rohc_packet4.len(), 3, "P4_UO1SN: Length");
    assert_eq!((rohc_packet4[0] & P1_UO_1_SN_MARKER_BIT_MASK), 0);

    let decompressed_generic4 = engine.decompress(&rohc_packet4).unwrap();
    let decomp_headers4 = match decompressed_generic4 {
        GenericUncompressedHeaders::RtpUdpIpv4(h) => h,
        other => panic!("P4_UO1SN_DECOMP: Expected RtpUdpIpv4, got {:?}", other),
    };
    assert_eq!(decomp_headers4.rtp_marker, original_headers4.rtp_marker);

    // --- Packet 5: UO-0 (SN=104, M=false) ---
    let original_headers5 = create_sample_rtp_packet(104, 1640, false);
    let generic_headers5 = GenericUncompressedHeaders::RtpUdpIpv4(original_headers5.clone());
    let rohc_packet5 = engine
        .compress(cid, Some(RohcProfile::RtpUdpIp), &generic_headers5)
        .unwrap();
    assert_eq!(rohc_packet5.len(), 1, "P5_UO0: Length");

    let decompressed_generic5 = engine.decompress(&rohc_packet5).unwrap();
    let decomp_headers5 = match decompressed_generic5 {
        GenericUncompressedHeaders::RtpUdpIpv4(h) => h,
        other => panic!("P5_UO0_DECOMP: Expected RtpUdpIpv4, got {:?}", other),
    };
    assert_eq!(
        decomp_headers5.rtp_marker, original_headers4.rtp_marker,
        "P5_UO0: Context marker from P4"
    );

    // --- Packet 6: IR (Refresh: SN=105, M=true) ---
    let original_headers6 = create_sample_rtp_packet(105, 1800, true);
    let generic_headers6 = GenericUncompressedHeaders::RtpUdpIpv4(original_headers6.clone());
    let rohc_packet6 = engine
        .compress(cid, Some(RohcProfile::RtpUdpIp), &generic_headers6)
        .unwrap();
    assert_eq!(
        rohc_packet6[0], P1_ROHC_IR_PACKET_TYPE_WITH_DYN,
        "P6_IR_REFRESH: Type check"
    );

    let decompressed_generic6 = engine.decompress(&rohc_packet6).unwrap();
    let decomp_headers6 = match decompressed_generic6 {
        GenericUncompressedHeaders::RtpUdpIpv4(h) => h,
        other => panic!("P6_IR_REFRESH_DECOMP: Expected RtpUdpIpv4, got {:?}", other),
    };
    assert_eq!(decomp_headers6.rtp_marker, original_headers6.rtp_marker);

    let comp_ctx_box = engine
        .context_manager_mut()
        .get_compressor_context_mut(cid)
        .unwrap();
    let p1_comp_ctx = comp_ctx_box
        .as_any()
        .downcast_ref::<Profile1CompressorContext>()
        .unwrap();
    assert_eq!(
        p1_comp_ctx.fo_packets_sent_since_ir, 0,
        "P6_IR_REFRESH: Compressor FO count reset"
    );
}

#[test]
fn p1_umode_ir_to_fo_sequence_small_cid() {
    let small_cid: u16 = 5;
    let ir_refresh_interval: u32 = 3;
    let mut engine = RohcEngine::new(ir_refresh_interval);
    engine
        .register_profile_handler(Box::new(Profile1Handler::new()))
        .unwrap();

    // --- Packet 1 (IR for small_cid, SN=200, M=true) ---
    let original_headers1 = create_sample_rtp_packet(200, 2000, true);
    let generic_headers1 = GenericUncompressedHeaders::RtpUdpIpv4(original_headers1.clone());
    let rohc_packet1_framed = engine
        .compress(small_cid, Some(RohcProfile::RtpUdpIp), &generic_headers1)
        .unwrap();

    assert_eq!(
        rohc_packet1_framed[0],
        ROHC_ADD_CID_FEEDBACK_PREFIX_VALUE | (small_cid as u8 & ROHC_SMALL_CID_MASK)
    );
    assert_eq!(rohc_packet1_framed[1], P1_ROHC_IR_PACKET_TYPE_WITH_DYN);

    let decompressed_generic1 = engine.decompress(&rohc_packet1_framed).unwrap();
    let decomp_headers1 = match decompressed_generic1 {
        GenericUncompressedHeaders::RtpUdpIpv4(h) => h,
        other => panic!("P1_SCID_IR_DECOMP: Expected RtpUdpIpv4, got {:?}", other),
    };
    assert_eq!(decomp_headers1.rtp_marker, original_headers1.rtp_marker);

    let decomp_ctx_box = engine
        .context_manager_mut()
        .get_decompressor_context_mut(small_cid)
        .unwrap();
    let p1_decomp_ctx = decomp_ctx_box
        .as_any()
        .downcast_ref::<Profile1DecompressorContext>()
        .unwrap();
    assert_eq!(p1_decomp_ctx.cid, small_cid);
    assert_eq!(p1_decomp_ctx.mode, Profile1DecompressorMode::FullContext);
    assert!(p1_decomp_ctx.last_reconstructed_rtp_marker);

    // --- Packet 2 (UO-1 for small_cid, SN=201, M=false) ---
    // After P1 (IR), compressor's fo_packets_sent_since_ir = 0.
    let original_headers2 = create_sample_rtp_packet(201, 2160, false); // Marker changed
    let generic_headers2 = GenericUncompressedHeaders::RtpUdpIpv4(original_headers2.clone());
    let rohc_packet2_framed = engine
        .compress(small_cid, Some(RohcProfile::RtpUdpIp), &generic_headers2)
        .unwrap();
    assert_eq!(
        rohc_packet2_framed[0],
        ROHC_ADD_CID_FEEDBACK_PREFIX_VALUE | (small_cid as u8 & ROHC_SMALL_CID_MASK)
    );

    // Check compressor state *after* P2 (first UO) has been compressed
    let fo_count_after_p2: u32;
    {
        let comp_ctx_box = engine
            .context_manager_mut()
            .get_compressor_context_mut(small_cid)
            .unwrap();
        let p1_comp_ctx = comp_ctx_box
            .as_any()
            .downcast_ref::<Profile1CompressorContext>()
            .unwrap();
        fo_count_after_p2 = p1_comp_ctx.fo_packets_sent_since_ir;
    }
    assert_eq!(
        fo_count_after_p2, 1,
        "P2_SCID_UO1: Compressor FO count after first UO"
    );

    let decompressed_generic2 = engine.decompress(&rohc_packet2_framed).unwrap();
    let decomp_headers2 = match decompressed_generic2 {
        GenericUncompressedHeaders::RtpUdpIpv4(h) => h,
        other => panic!("P2_SCID_UO1_DECOMP: Expected RtpUdpIpv4, got {:?}", other),
    };
    assert_eq!(decomp_headers2.rtp_marker, original_headers2.rtp_marker);

    // --- Packet 3 (UO-1 for small_cid, SN=202, M=true) ---
    // After P2 (UO), compressor's fo_packets_sent_since_ir = 1. ir_refresh_interval = 3.
    // Condition for IR: 1 >= (3-1) is false. So P3 is UO.
    let original_headers3 = create_sample_rtp_packet(202, 2320, true); // Marker changed
    let generic_headers3 = GenericUncompressedHeaders::RtpUdpIpv4(original_headers3.clone());
    let rohc_packet3_framed = engine
        .compress(small_cid, Some(RohcProfile::RtpUdpIp), &generic_headers3)
        .unwrap();

    // Check compressor state *after* P3 (second UO) has been compressed
    let fo_count_after_p3: u32;
    {
        let comp_ctx_box = engine
            .context_manager_mut()
            .get_compressor_context_mut(small_cid)
            .unwrap();
        let p1_comp_ctx = comp_ctx_box
            .as_any()
            .downcast_ref::<Profile1CompressorContext>()
            .unwrap();
        fo_count_after_p3 = p1_comp_ctx.fo_packets_sent_since_ir;
    }
    assert_eq!(
        fo_count_after_p3, 2,
        "P3_SCID_UO1: Compressor FO count after second UO"
    ); // This was the failing line, now expecting 2

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

    // --- Packet 4 (IR refresh for small_cid, SN=203, M=false) ---
    // After P3 (UO), compressor's fo_packets_sent_since_ir = 2. ir_refresh_interval = 3.
    // Condition for IR: 2 >= (3-1) is true. So P4 is IR.
    let original_headers4 = create_sample_rtp_packet(203, 2480, false);
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

    let comp_ctx_box_after_p4 = engine
        .context_manager_mut()
        .get_compressor_context_mut(small_cid)
        .unwrap();
    let p1_comp_ctx_after_p4 = comp_ctx_box_after_p4
        .as_any()
        .downcast_ref::<Profile1CompressorContext>()
        .unwrap();
    assert_eq!(
        p1_comp_ctx_after_p4.fo_packets_sent_since_ir, 0,
        "P4_SCID_IR_REFRESH: Compressor FO count reset"
    );

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
}

#[test]
fn p1_umode_sn_jump_triggers_uo1() {
    let cid: u16 = 0;
    let ir_refresh_interval: u32 = 10;
    let mut engine = RohcEngine::new(ir_refresh_interval);
    engine
        .register_profile_handler(Box::new(Profile1Handler::new()))
        .unwrap();

    // Packet 1: IR (SN=500)
    let headers1 = create_sample_rtp_packet(500, 5000, false);
    let generic1 = GenericUncompressedHeaders::RtpUdpIpv4(headers1);
    let compressed_ir = engine
        .compress(cid, Some(RohcProfile::RtpUdpIp), &generic1)
        .unwrap();
    let _ = engine.decompress(&compressed_ir).unwrap();

    // Packet 2: UO-0 (SN=501)
    let headers2 = create_sample_rtp_packet(501, 5160, false);
    let generic2 = GenericUncompressedHeaders::RtpUdpIpv4(headers2.clone());
    let rohc_packet2 = engine
        .compress(cid, Some(RohcProfile::RtpUdpIp), &generic2)
        .unwrap();
    assert_eq!(rohc_packet2.len(), 1, "P2_SNJUMP_UO0: Length");

    let decomp_generic2 = engine.decompress(&rohc_packet2).unwrap();
    let decomp_headers2 = match decomp_generic2 {
        GenericUncompressedHeaders::RtpUdpIpv4(h) => h,
        other => panic!("P2_SNJUMP_UO0_DECOMP: Expected RtpUdpIpv4, got {:?}", other),
    };
    assert_eq!(decomp_headers2.rtp_sequence_number, 501);
    assert!(!decomp_headers2.rtp_marker);

    // Packet 3: SN jumps to 517 (from 501), should force UO-1
    let headers3 = create_sample_rtp_packet(517, 5320, false);
    let generic3 = GenericUncompressedHeaders::RtpUdpIpv4(headers3.clone());
    let rohc_packet3 = engine
        .compress(cid, Some(RohcProfile::RtpUdpIp), &generic3)
        .unwrap();
    assert_eq!(
        rohc_packet3.len(),
        3,
        "P3_SNJUMP_UO1: Length due to SN jump"
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

    let decomp_ctx_box = engine
        .context_manager_mut()
        .get_decompressor_context_mut(cid)
        .unwrap();
    let p1_decomp_ctx = decomp_ctx_box
        .as_any()
        .downcast_ref::<Profile1DecompressorContext>()
        .unwrap();
    assert_eq!(p1_decomp_ctx.last_reconstructed_rtp_sn_full, 517);
}

#[test]
fn p1_umode_uo0_sn_decoding_with_simulated_packet_loss() {
    let cid: u16 = 0;
    let ir_refresh_interval: u32 = 20;
    let mut engine = RohcEngine::new(ir_refresh_interval);
    engine
        .register_profile_handler(Box::new(Profile1Handler::new()))
        .unwrap();

    // Packet 1: IR (SN=100)
    let headers_sn100 = create_sample_rtp_packet(100, 1000, false);
    let generic_h100 = GenericUncompressedHeaders::RtpUdpIpv4(headers_sn100);
    let rohc_ir_packet = engine
        .compress(cid, Some(RohcProfile::RtpUdpIp), &generic_h100)
        .unwrap();
    let decomp_gen_ir = engine.decompress(&rohc_ir_packet).unwrap();
    let decomp_headers_ir = match decomp_gen_ir {
        GenericUncompressedHeaders::RtpUdpIpv4(h) => h,
        other => panic!("PLOSS_IR_DECOMP: Expected RtpUdpIpv4, got {:?}", other),
    };
    assert_eq!(decomp_headers_ir.rtp_sequence_number, 100);

    let decomp_ctx_box = engine
        .context_manager_mut()
        .get_decompressor_context_mut(cid)
        .unwrap();
    let p1_decomp_ctx = decomp_ctx_box
        .as_any()
        .downcast_ref::<Profile1DecompressorContext>()
        .unwrap();
    assert_eq!(p1_decomp_ctx.last_reconstructed_rtp_sn_full, 100);
    assert_eq!(p1_decomp_ctx.mode, Profile1DecompressorMode::FullContext);
    assert_eq!(p1_decomp_ctx.p_sn, DEFAULT_WLSB_P_OFFSET);

    // Simulate loss of SN=101 and SN=102 by compressing but not decompressing
    let headers_sn101 = create_sample_rtp_packet(101, 1160, false);
    let _rohc_lost_packet1 = engine
        .compress(
            cid,
            Some(RohcProfile::RtpUdpIp),
            &GenericUncompressedHeaders::RtpUdpIpv4(headers_sn101),
        )
        .unwrap();
    let headers_sn102 = create_sample_rtp_packet(102, 1320, false);
    let _rohc_lost_packet2 = engine
        .compress(
            cid,
            Some(RohcProfile::RtpUdpIp),
            &GenericUncompressedHeaders::RtpUdpIpv4(headers_sn102),
        )
        .unwrap();

    // Packet SN=103 - Received by decompressor
    let headers_sn103 = create_sample_rtp_packet(103, 1480, false);
    let generic_h103 = GenericUncompressedHeaders::RtpUdpIpv4(headers_sn103);
    let rohc_packet_sn103 = engine
        .compress(cid, Some(RohcProfile::RtpUdpIp), &generic_h103)
        .unwrap();
    assert_eq!(rohc_packet_sn103.len(), 1, "PLOSS_SN103: UO-0 expected");

    let decomp_gen_103 = engine.decompress(&rohc_packet_sn103).unwrap();
    let decomp_headers_103 = match decomp_gen_103 {
        GenericUncompressedHeaders::RtpUdpIpv4(h) => h,
        other => panic!("PLOSS_SN103_DECOMP: Expected RtpUdpIpv4, got {:?}", other),
    };
    assert_eq!(
        decomp_headers_103.rtp_sequence_number, 103,
        "PLOSS_SN103: SN check after loss"
    );

    let decomp_ctx_box_after_103 = engine
        .context_manager_mut()
        .get_decompressor_context_mut(cid)
        .unwrap();
    let p1_decomp_ctx_after_103 = decomp_ctx_box_after_103
        .as_any()
        .downcast_ref::<Profile1DecompressorContext>()
        .unwrap();
    assert_eq!(p1_decomp_ctx_after_103.last_reconstructed_rtp_sn_full, 103);

    // Packet SN=104 - Received by decompressor
    let headers_sn104 = create_sample_rtp_packet(104, 1640, false);
    let generic_h104 = GenericUncompressedHeaders::RtpUdpIpv4(headers_sn104);
    let rohc_packet_sn104 = engine
        .compress(cid, Some(RohcProfile::RtpUdpIp), &generic_h104)
        .unwrap();
    assert_eq!(rohc_packet_sn104.len(), 1, "PLOSS_SN104: UO-0 expected");

    let decomp_gen_104 = engine.decompress(&rohc_packet_sn104).unwrap();
    let decomp_headers_104 = match decomp_gen_104 {
        GenericUncompressedHeaders::RtpUdpIpv4(h) => h,
        other => panic!("PLOSS_SN104_DECOMP: Expected RtpUdpIpv4, got {:?}", other),
    };
    assert_eq!(
        decomp_headers_104.rtp_sequence_number, 104,
        "PLOSS_SN104: SN check"
    );

    let decomp_ctx_box_after_104 = engine
        .context_manager_mut()
        .get_decompressor_context_mut(cid)
        .unwrap();
    let p1_decomp_ctx_after_104 = decomp_ctx_box_after_104
        .as_any()
        .downcast_ref::<Profile1DecompressorContext>()
        .unwrap();
    assert_eq!(p1_decomp_ctx_after_104.last_reconstructed_rtp_sn_full, 104);
}
