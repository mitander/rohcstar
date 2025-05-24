// Integration tests for ROHC Profile 1 Unidirectional mode operations,
// using the Profile1Handler.

use rohcstar::constants::{
    ADD_CID_OCTET_PREFIX_VALUE, DEFAULT_P_SN_OFFSET, ROHC_IR_PACKET_TYPE_WITH_DYN,
    UO_1_SN_P1_MARKER_BIT_MASK, UO_1_SN_P1_PACKET_TYPE_BASE,
};
use rohcstar::context::{DecompressorMode as P1DecompressorMode, RtpUdpIpP1DecompressorContext};
use rohcstar::packet_defs::GenericUncompressedHeaders;
use rohcstar::profiles::p1_handler::Profile1Handler;
use rohcstar::protocol_types::RtpUdpIpv4Headers;
use rohcstar::traits::ProfileHandler;
use rohcstar::traits::RohcDecompressorContext;

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
        ip_protocol: 17, // UDP
        rtp_version: 2,
        ip_ihl: 5,
        ip_ttl: 64,
        ..Default::default()
    }
}

#[test]
fn p1_umode_ir_to_fo_sequence_cid0() {
    let handler = Profile1Handler::new();
    let cid: u16 = 0;
    let ir_refresh_interval = 5;

    let mut compressor_context_dyn = handler.create_compressor_context(cid, ir_refresh_interval);
    let mut decompressor_context_dyn = handler.create_decompressor_context(cid);
    // CID is set within create_decompressor_context by P1Handler calling RtpUdpIpP1DecompressorContext::new

    // Packet 1: IR (SN=100, M=false)
    let original_headers1 = create_sample_rtp_packet(100, 1000, false);
    let generic_headers1 = GenericUncompressedHeaders::RtpUdpIpv4(original_headers1.clone());

    let rohc_packet1 = handler
        .compress(compressor_context_dyn.as_mut(), &generic_headers1)
        .unwrap();
    assert_eq!(rohc_packet1[0], ROHC_IR_PACKET_TYPE_WITH_DYN);

    let decompressed_generic1 = handler
        .decompress(decompressor_context_dyn.as_mut(), &rohc_packet1)
        .unwrap();
    let GenericUncompressedHeaders::RtpUdpIpv4(decompressed_headers1) = decompressed_generic1;
    assert_eq!(
        decompressed_headers1.rtp_marker,
        original_headers1.rtp_marker
    );

    let p1_decomp_ctx = decompressor_context_dyn
        .as_any()
        .downcast_ref::<RtpUdpIpP1DecompressorContext>()
        .unwrap();
    assert_eq!(p1_decomp_ctx.mode, P1DecompressorMode::FullContext);

    // Packet 2: UO-0 (SN=101, M=false)
    let original_headers2 = create_sample_rtp_packet(101, 1160, false);
    let generic_headers2 = GenericUncompressedHeaders::RtpUdpIpv4(original_headers2.clone());
    let rohc_packet2 = handler
        .compress(compressor_context_dyn.as_mut(), &generic_headers2)
        .unwrap();
    assert_eq!(rohc_packet2.len(), 1);

    let decompressed_generic2 = handler
        .decompress(decompressor_context_dyn.as_mut(), &rohc_packet2)
        .unwrap();
    let GenericUncompressedHeaders::RtpUdpIpv4(decompressed_headers2) = decompressed_generic2;
    assert_eq!(
        decompressed_headers2.rtp_marker,
        original_headers1.rtp_marker
    ); // UO-0 uses context marker
    assert_eq!(
        decompressed_headers2.rtp_sequence_number,
        original_headers2.rtp_sequence_number
    );

    // Packet 3: UO-1-SN (SN=102, M=true)
    let original_headers3 = create_sample_rtp_packet(102, 1320, true);
    let generic_headers3 = GenericUncompressedHeaders::RtpUdpIpv4(original_headers3.clone());
    let rohc_packet3 = handler
        .compress(compressor_context_dyn.as_mut(), &generic_headers3)
        .unwrap();
    assert_eq!(rohc_packet3.len(), 3);
    assert_eq!((rohc_packet3[0] & 0xF0), UO_1_SN_P1_PACKET_TYPE_BASE);
    assert_ne!((rohc_packet3[0] & UO_1_SN_P1_MARKER_BIT_MASK), 0);

    let decompressed_generic3 = handler
        .decompress(decompressor_context_dyn.as_mut(), &rohc_packet3)
        .unwrap();
    let GenericUncompressedHeaders::RtpUdpIpv4(decompressed_headers3) = decompressed_generic3;
    assert_eq!(
        decompressed_headers3.rtp_sequence_number,
        original_headers3.rtp_sequence_number
    );
    // For UO-1-SN (MVP), TS is from context (i.e., from original_headers1 as UO-0 didn't update it)
    assert_eq!(
        decompressed_headers3.rtp_timestamp,
        original_headers1.rtp_timestamp
    );
    assert_eq!(
        decompressed_headers3.rtp_marker,
        original_headers3.rtp_marker
    );

    // Packet 4: UO-1-SN (SN=103, M=false)
    let original_headers4 = create_sample_rtp_packet(103, 1480, false);
    let generic_headers4 = GenericUncompressedHeaders::RtpUdpIpv4(original_headers4.clone());
    let rohc_packet4 = handler
        .compress(compressor_context_dyn.as_mut(), &generic_headers4)
        .unwrap();
    assert_eq!(rohc_packet4.len(), 3);
    assert_eq!((rohc_packet4[0] & UO_1_SN_P1_MARKER_BIT_MASK), 0);

    let decompressed_generic4 = handler
        .decompress(decompressor_context_dyn.as_mut(), &rohc_packet4)
        .unwrap();
    let GenericUncompressedHeaders::RtpUdpIpv4(decompressed_headers4) = decompressed_generic4;
    assert_eq!(
        decompressed_headers4.rtp_marker,
        original_headers4.rtp_marker
    );

    // Packet 5: UO-0 (SN=104, M=false)
    let original_headers5 = create_sample_rtp_packet(104, 1640, false);
    let generic_headers5 = GenericUncompressedHeaders::RtpUdpIpv4(original_headers5.clone());
    let rohc_packet5 = handler
        .compress(compressor_context_dyn.as_mut(), &generic_headers5)
        .unwrap();
    assert_eq!(rohc_packet5.len(), 1);

    let decompressed_generic5 = handler
        .decompress(decompressor_context_dyn.as_mut(), &rohc_packet5)
        .unwrap();
    let GenericUncompressedHeaders::RtpUdpIpv4(decompressed_headers5) = decompressed_generic5;
    assert_eq!(
        decompressed_headers5.rtp_marker,
        original_headers4.rtp_marker
    ); // UO-0 uses context marker (from P4)

    // Packet 6: IR (Refresh: SN=105, M=true)
    let original_headers6 = create_sample_rtp_packet(105, 1800, true);
    let generic_headers6 = GenericUncompressedHeaders::RtpUdpIpv4(original_headers6.clone());
    let rohc_packet6 = handler
        .compress(compressor_context_dyn.as_mut(), &generic_headers6)
        .unwrap();
    assert_eq!(rohc_packet6[0], ROHC_IR_PACKET_TYPE_WITH_DYN);

    let decompressed_generic6 = handler
        .decompress(decompressor_context_dyn.as_mut(), &rohc_packet6)
        .unwrap();
    let GenericUncompressedHeaders::RtpUdpIpv4(decompressed_headers6) = decompressed_generic6;
    assert_eq!(
        decompressed_headers6.rtp_marker,
        original_headers6.rtp_marker
    );
}

#[test]
fn p1_umode_ir_to_fo_sequence_small_cid() {
    let handler = Profile1Handler::new();
    let cid: u16 = 5;
    let ir_refresh_interval = 3;

    let mut compressor_context_dyn = handler.create_compressor_context(cid, ir_refresh_interval);
    // Decompressor context starts unassociated with CID 5
    let mut decompressor_context_dyn = handler.create_decompressor_context(0);
    // Downcast to set NoContext mode for testing IR reception for new CID
    decompressor_context_dyn
        .as_any_mut()
        .downcast_mut::<RtpUdpIpP1DecompressorContext>()
        .unwrap()
        .mode = P1DecompressorMode::NoContext;

    // Packet 1 (IR with Add-CID for CID 5)
    let original_headers1 = create_sample_rtp_packet(200, 2000, true);
    let generic_headers1 = GenericUncompressedHeaders::RtpUdpIpv4(original_headers1.clone());
    let rohc_packet1_framed = handler
        .compress(compressor_context_dyn.as_mut(), &generic_headers1)
        .unwrap();
    assert_eq!(
        rohc_packet1_framed[0],
        ADD_CID_OCTET_PREFIX_VALUE | (cid as u8)
    );
    assert_eq!(rohc_packet1_framed[1], ROHC_IR_PACKET_TYPE_WITH_DYN);

    // Engine/Dispatcher would parse Add-CID, get/create context for CID 5, and set its CID.
    // Simulate this by setting the CID on our decompressor_context before calling decompress.
    decompressor_context_dyn
        .as_any_mut()
        .downcast_mut::<RtpUdpIpP1DecompressorContext>()
        .unwrap()
        .set_cid(cid);
    let core_rohc_packet1 = &rohc_packet1_framed[1..]; // Pass core packet to handler
    let decompressed_generic1 = handler
        .decompress(decompressor_context_dyn.as_mut(), core_rohc_packet1)
        .unwrap();
    let GenericUncompressedHeaders::RtpUdpIpv4(decompressed_headers1) = decompressed_generic1;

    let p1_decomp_ctx = decompressor_context_dyn
        .as_any()
        .downcast_ref::<RtpUdpIpP1DecompressorContext>()
        .unwrap();
    assert_eq!(p1_decomp_ctx.cid, cid);
    assert_eq!(p1_decomp_ctx.mode, P1DecompressorMode::FullContext);
    assert_eq!(
        decompressed_headers1.rtp_marker,
        original_headers1.rtp_marker
    );
    assert!(p1_decomp_ctx.last_reconstructed_rtp_marker);

    // Packet 2 (UO-1 with Add-CID for CID 5)
    let original_headers2 = create_sample_rtp_packet(201, 2160, false);
    let generic_headers2 = GenericUncompressedHeaders::RtpUdpIpv4(original_headers2.clone());
    let rohc_packet2_framed = handler
        .compress(compressor_context_dyn.as_mut(), &generic_headers2)
        .unwrap();
    assert_eq!(
        rohc_packet2_framed[0],
        ADD_CID_OCTET_PREFIX_VALUE | (cid as u8)
    );

    // Decompressor context already knows CID 5.
    let core_rohc_packet2 = &rohc_packet2_framed[1..];
    let decompressed_generic2 = handler
        .decompress(decompressor_context_dyn.as_mut(), core_rohc_packet2)
        .unwrap();
    let GenericUncompressedHeaders::RtpUdpIpv4(decompressed_headers2) = decompressed_generic2;
    assert_eq!(
        decompressed_headers2.rtp_marker,
        original_headers2.rtp_marker
    );
    let p1_decomp_ctx_after_p2 = decompressor_context_dyn
        .as_any()
        .downcast_ref::<RtpUdpIpP1DecompressorContext>()
        .unwrap();
    assert!(!p1_decomp_ctx_after_p2.last_reconstructed_rtp_marker);

    // Packet 3 (UO-1 with Add-CID for CID 5)
    let original_headers3 = create_sample_rtp_packet(202, 2320, true);
    let generic_headers3 = GenericUncompressedHeaders::RtpUdpIpv4(original_headers3.clone());
    let rohc_packet3_framed = handler
        .compress(compressor_context_dyn.as_mut(), &generic_headers3)
        .unwrap();
    let p1_comp_ctx = compressor_context_dyn
        .as_any()
        .downcast_ref::<rohcstar::context::RtpUdpIpP1CompressorContext>()
        .unwrap();
    assert_eq!(p1_comp_ctx.fo_packets_sent_since_ir, 2); // Before this P3 packet was sent

    let core_rohc_packet3 = &rohc_packet3_framed[1..];
    let decompressed_generic3 = handler
        .decompress(decompressor_context_dyn.as_mut(), core_rohc_packet3)
        .unwrap();
    let GenericUncompressedHeaders::RtpUdpIpv4(decompressed_headers3) = decompressed_generic3;
    assert_eq!(
        decompressed_headers3.rtp_sequence_number,
        original_headers3.rtp_sequence_number
    );
    assert_eq!(
        decompressed_headers3.rtp_marker,
        original_headers3.rtp_marker
    );
    let p1_decomp_ctx_after_p3 = decompressor_context_dyn
        .as_any()
        .downcast_ref::<RtpUdpIpP1DecompressorContext>()
        .unwrap();
    assert!(p1_decomp_ctx_after_p3.last_reconstructed_rtp_marker);

    // Packet 4 (IR with Add-CID for CID 5 - Refresh)
    let original_headers4 = create_sample_rtp_packet(203, 2480, false);
    let generic_headers4 = GenericUncompressedHeaders::RtpUdpIpv4(original_headers4.clone());
    let rohc_packet4_framed = handler
        .compress(compressor_context_dyn.as_mut(), &generic_headers4)
        .unwrap();
    assert_eq!(
        rohc_packet4_framed[0],
        ADD_CID_OCTET_PREFIX_VALUE | (cid as u8)
    );
    assert_eq!(rohc_packet4_framed[1], ROHC_IR_PACKET_TYPE_WITH_DYN);
    let p1_comp_ctx_after_p4 = compressor_context_dyn
        .as_any()
        .downcast_ref::<rohcstar::context::RtpUdpIpP1CompressorContext>()
        .unwrap();
    assert_eq!(p1_comp_ctx_after_p4.fo_packets_sent_since_ir, 0);

    let core_rohc_packet4 = &rohc_packet4_framed[1..];
    let decompressed_generic4 = handler
        .decompress(decompressor_context_dyn.as_mut(), core_rohc_packet4)
        .unwrap();
    let GenericUncompressedHeaders::RtpUdpIpv4(decompressed_headers4) = decompressed_generic4;
    let p1_decomp_ctx_after_p4 = decompressor_context_dyn
        .as_any()
        .downcast_ref::<RtpUdpIpP1DecompressorContext>()
        .unwrap();
    assert_eq!(p1_decomp_ctx_after_p4.cid, cid);
    assert_eq!(
        decompressed_headers4.rtp_sequence_number,
        original_headers4.rtp_sequence_number
    );
    assert_eq!(
        decompressed_headers4.rtp_timestamp,
        original_headers4.rtp_timestamp
    );
    assert_eq!(
        decompressed_headers4.rtp_marker,
        original_headers4.rtp_marker
    );
    assert!(!p1_decomp_ctx_after_p4.last_reconstructed_rtp_marker);
}

#[test]
fn p1_umode_sn_jump_triggers_uo1() {
    let handler = Profile1Handler::new();
    let cid: u16 = 0;
    let ir_refresh_interval = 10;

    let mut compressor_context_dyn = handler.create_compressor_context(cid, ir_refresh_interval);
    let mut decompressor_context_dyn = handler.create_decompressor_context(cid);

    let original_headers1 = create_sample_rtp_packet(500, 5000, false);
    let generic_headers1 = GenericUncompressedHeaders::RtpUdpIpv4(original_headers1);
    let rohc_packet1 = handler
        .compress(compressor_context_dyn.as_mut(), &generic_headers1)
        .unwrap();
    let _ = handler
        .decompress(decompressor_context_dyn.as_mut(), &rohc_packet1)
        .unwrap();

    let original_headers2 = create_sample_rtp_packet(501, 5160, false);
    let generic_headers2 = GenericUncompressedHeaders::RtpUdpIpv4(original_headers2.clone());
    let rohc_packet2 = handler
        .compress(compressor_context_dyn.as_mut(), &generic_headers2)
        .unwrap();
    assert_eq!(rohc_packet2.len(), 1);
    let decomp_generic2 = handler
        .decompress(decompressor_context_dyn.as_mut(), &rohc_packet2)
        .unwrap();

    let GenericUncompressedHeaders::RtpUdpIpv4(h) = decomp_generic2;
    assert_eq!(h.rtp_sequence_number, 501);
    assert!(!h.rtp_marker);

    let original_headers3 = create_sample_rtp_packet(517, 5320, false);
    let generic_headers3 = GenericUncompressedHeaders::RtpUdpIpv4(original_headers3.clone());
    let rohc_packet3 = handler
        .compress(compressor_context_dyn.as_mut(), &generic_headers3)
        .unwrap();
    assert_eq!(rohc_packet3.len(), 3);
    assert_eq!((rohc_packet3[0] & 0xF0), UO_1_SN_P1_PACKET_TYPE_BASE);
    assert_eq!((rohc_packet3[0] & UO_1_SN_P1_MARKER_BIT_MASK), 0);

    let decomp_generic3 = handler
        .decompress(decompressor_context_dyn.as_mut(), &rohc_packet3)
        .unwrap();
    let p1_decomp_ctx = decompressor_context_dyn
        .as_any()
        .downcast_ref::<RtpUdpIpP1DecompressorContext>()
        .unwrap();

    let GenericUncompressedHeaders::RtpUdpIpv4(h) = decomp_generic3;
    assert_eq!(h.rtp_sequence_number, 517);
    assert!(!h.rtp_marker);
    assert_eq!(p1_decomp_ctx.last_reconstructed_rtp_sn_full, 517);
}

#[test]
fn p1_umode_uo0_sn_decoding_with_simulated_packet_loss() {
    let handler = Profile1Handler::new();
    let cid: u16 = 0;
    let ir_refresh_interval = 20;

    let mut compressor_context_dyn = handler.create_compressor_context(cid, ir_refresh_interval);
    let mut decompressor_context_dyn = handler.create_decompressor_context(cid);

    let headers_sn100 = create_sample_rtp_packet(100, 1000, false);
    let generic_h100 = GenericUncompressedHeaders::RtpUdpIpv4(headers_sn100);
    let rohc_ir_packet = handler
        .compress(compressor_context_dyn.as_mut(), &generic_h100)
        .unwrap();
    let decomp_gen_ir = handler
        .decompress(decompressor_context_dyn.as_mut(), &rohc_ir_packet)
        .unwrap();

    let GenericUncompressedHeaders::RtpUdpIpv4(h) = decomp_gen_ir;
    assert_eq!(h.rtp_sequence_number, 100);

    let p1_decomp_ctx = decompressor_context_dyn
        .as_any()
        .downcast_ref::<RtpUdpIpP1DecompressorContext>()
        .unwrap();
    assert_eq!(p1_decomp_ctx.last_reconstructed_rtp_sn_full, 100);
    assert_eq!(p1_decomp_ctx.mode, P1DecompressorMode::FullContext);
    assert_eq!(p1_decomp_ctx.p_sn, DEFAULT_P_SN_OFFSET);

    let headers_sn101 = create_sample_rtp_packet(101, 1160, false);
    let generic_h101 = GenericUncompressedHeaders::RtpUdpIpv4(headers_sn101);
    let _rohc_lost_packet1 = handler
        .compress(compressor_context_dyn.as_mut(), &generic_h101)
        .unwrap();

    let headers_sn102 = create_sample_rtp_packet(102, 1320, false);
    let generic_h102 = GenericUncompressedHeaders::RtpUdpIpv4(headers_sn102);
    let _rohc_lost_packet2 = handler
        .compress(compressor_context_dyn.as_mut(), &generic_h102)
        .unwrap();

    let headers_sn103 = create_sample_rtp_packet(103, 1480, false);
    let generic_h103 = GenericUncompressedHeaders::RtpUdpIpv4(headers_sn103);
    let rohc_packet_sn103 = handler
        .compress(compressor_context_dyn.as_mut(), &generic_h103)
        .unwrap();
    assert_eq!(rohc_packet_sn103.len(), 1);

    let decomp_gen_103 = handler
        .decompress(decompressor_context_dyn.as_mut(), &rohc_packet_sn103)
        .unwrap();
    let p1_decomp_ctx_after_103 = decompressor_context_dyn
        .as_any()
        .downcast_ref::<RtpUdpIpP1DecompressorContext>()
        .unwrap();

    let GenericUncompressedHeaders::RtpUdpIpv4(h) = decomp_gen_103;
    assert_eq!(h.rtp_sequence_number, 103);
    assert_eq!(p1_decomp_ctx_after_103.last_reconstructed_rtp_sn_full, 103);

    let headers_sn104 = create_sample_rtp_packet(104, 1640, false);
    let generic_h104 = GenericUncompressedHeaders::RtpUdpIpv4(headers_sn104);
    let rohc_packet_sn104 = handler
        .compress(compressor_context_dyn.as_mut(), &generic_h104)
        .unwrap();
    assert_eq!(rohc_packet_sn104.len(), 1);

    let decomp_gen_104 = handler
        .decompress(decompressor_context_dyn.as_mut(), &rohc_packet_sn104)
        .unwrap();
    let p1_decomp_ctx_after_104 = decompressor_context_dyn
        .as_any()
        .downcast_ref::<RtpUdpIpP1DecompressorContext>()
        .unwrap();

    let GenericUncompressedHeaders::RtpUdpIpv4(h) = decomp_gen_104;
    assert_eq!(h.rtp_sequence_number, 104);
    assert_eq!(p1_decomp_ctx_after_104.last_reconstructed_rtp_sn_full, 104);
}
