use rohcstar::context::{
    DecompressorMode, RtpUdpIpP1CompressorContext, RtpUdpIpP1DecompressorContext,
};
use rohcstar::packet_processor::{ADD_CID_OCTET_PREFIX_VALUE, PROFILE_ID_RTP_UDP_IP};
use rohcstar::profiles::profile1_compressor::compress_rtp_udp_ip_umode;
use rohcstar::profiles::profile1_decompressor::decompress_rtp_udp_ip_umode;
use rohcstar::protocol_types::RtpUdpIpv4Headers;

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
        ip_protocol: 17,
        rtp_version: 2,
        ip_ihl: 5,
        ip_ttl: 64,
        ..Default::default()
    }
}

#[test]
fn test_p1_umode_ir_then_uo0_flow_cid0() {
    let cid: u16 = 0;
    let ir_refresh_interval = 5;

    let mut compressor_context =
        RtpUdpIpP1CompressorContext::new(cid, PROFILE_ID_RTP_UDP_IP, ir_refresh_interval);
    let mut decompressor_context = RtpUdpIpP1DecompressorContext::new(cid, PROFILE_ID_RTP_UDP_IP);

    let original_headers1 = create_sample_rtp_packet(100, 1000, false);
    compressor_context.initialize_static_part_with_uncompressed_headers(&original_headers1);
    let rohc_packet1 =
        compress_rtp_udp_ip_umode(&mut compressor_context, &original_headers1).unwrap();
    assert_eq!(
        rohc_packet1[0],
        rohcstar::packet_processor::ROHC_IR_PACKET_TYPE_WITH_DYN
    );
    let decompressed_headers1 =
        decompress_rtp_udp_ip_umode(&mut decompressor_context, &rohc_packet1).unwrap();
    assert_eq!(
        decompressed_headers1.rtp_marker,
        original_headers1.rtp_marker
    ); // false == false

    let original_headers2 = create_sample_rtp_packet(101, 1160, false);
    let rohc_packet2 =
        compress_rtp_udp_ip_umode(&mut compressor_context, &original_headers2).unwrap();
    let decompressed_headers2 =
        decompress_rtp_udp_ip_umode(&mut decompressor_context, &rohc_packet2).unwrap();
    assert_eq!(
        decompressed_headers2.rtp_marker,
        original_headers1.rtp_marker // UO-0 keeps marker from context (orig1)
    ); // false == false

    // --- Packet 3: Should be UO-1 because Marker changed ---
    let original_headers3 = create_sample_rtp_packet(102, 1320, true); // Marker changes to true
    let rohc_packet3 =
        compress_rtp_udp_ip_umode(&mut compressor_context, &original_headers3).unwrap();
    assert_eq!(rohc_packet3.len(), 3);
    assert_eq!(
        (rohc_packet3[0] & 0xF0),
        rohcstar::packet_processor::UO_1_SN_PACKET_TYPE_BASE
    );
    assert_ne!(
        (rohc_packet3[0] & rohcstar::packet_processor::UO_1_SN_MARKER_BIT_MASK),
        0
    );

    let decompressed_headers3 =
        decompress_rtp_udp_ip_umode(&mut decompressor_context, &rohc_packet3).unwrap();
    assert_eq!(
        decompressed_headers3.rtp_marker,
        original_headers3.rtp_marker // UO-1 updates marker to true. THIS IS THE FIX.
    ); // true == true. This was failing.

    // --- Packet 4: Marker changed back to false
    let original_headers4 = create_sample_rtp_packet(103, 1480, false);
    let rohc_packet4 =
        compress_rtp_udp_ip_umode(&mut compressor_context, &original_headers4).unwrap();
    assert_eq!(rohc_packet4.len(), 3); // UO-1 due to marker change
    let decompressed_headers4 =
        decompress_rtp_udp_ip_umode(&mut decompressor_context, &rohc_packet4).unwrap();
    assert_eq!(
        decompressed_headers4.rtp_marker,
        original_headers4.rtp_marker
    ); // false == false

    // --- Packet 5: Marker same (false), SN small delta. Should be UO-0.
    let original_headers5 = create_sample_rtp_packet(104, 1640, false);
    let rohc_packet5 =
        compress_rtp_udp_ip_umode(&mut compressor_context, &original_headers5).unwrap();
    assert_eq!(rohc_packet5.len(), 1); // UO-0
    let decompressed_headers5 =
        decompress_rtp_udp_ip_umode(&mut decompressor_context, &rohc_packet5).unwrap();
    assert_eq!(
        decompressed_headers5.rtp_marker,
        original_headers4.rtp_marker // UO-0 takes marker from context (which is P4's marker)
    ); // false == false

    // --- Packet 6: IR refresh
    let original_headers6 = create_sample_rtp_packet(105, 1800, true);
    let rohc_packet6 =
        compress_rtp_udp_ip_umode(&mut compressor_context, &original_headers6).unwrap();
    assert_eq!(
        rohc_packet6[0],
        rohcstar::packet_processor::ROHC_IR_PACKET_TYPE_WITH_DYN
    );
    let decompressed_headers6 =
        decompress_rtp_udp_ip_umode(&mut decompressor_context, &rohc_packet6).unwrap();
    assert_eq!(
        decompressed_headers6.rtp_marker,
        original_headers6.rtp_marker
    ); // true == true
}

#[test]
fn test_p1_umode_ir_then_uo0_flow_cid5() {
    let cid: u16 = 5;
    let ir_refresh_interval = 3;

    let mut compressor_context =
        RtpUdpIpP1CompressorContext::new(cid, PROFILE_ID_RTP_UDP_IP, ir_refresh_interval);
    let mut decompressor_context = RtpUdpIpP1DecompressorContext::new(0, PROFILE_ID_RTP_UDP_IP);
    decompressor_context.mode = DecompressorMode::NoContext;

    // Packet 1 (IR): SN=200, M=true
    let original_headers1 = create_sample_rtp_packet(200, 2000, true);
    compressor_context.initialize_static_part_with_uncompressed_headers(&original_headers1);
    let rohc_packet1 =
        compress_rtp_udp_ip_umode(&mut compressor_context, &original_headers1).unwrap();
    assert_eq!(rohc_packet1[0], ADD_CID_OCTET_PREFIX_VALUE | (cid as u8));
    let _ = decompress_rtp_udp_ip_umode(&mut decompressor_context, &rohc_packet1).unwrap();
    assert_eq!(decompressor_context.cid, cid);
    assert!(decompressor_context.last_reconstructed_rtp_marker);

    // Packet 2 (UO-1): SN=201, M=false (marker changed)
    let original_headers2 = create_sample_rtp_packet(201, 2160, false);
    let uo1_core_packet =
        compress_rtp_udp_ip_umode(&mut compressor_context, &original_headers2).unwrap();
    assert_eq!(uo1_core_packet.len(), 3); // UO-1
    let mut rohc_packet2_framed = vec![ADD_CID_OCTET_PREFIX_VALUE | (cid as u8)];
    rohc_packet2_framed.extend_from_slice(&uo1_core_packet);
    let decompressed_headers2 =
        decompress_rtp_udp_ip_umode(&mut decompressor_context, &rohc_packet2_framed).unwrap();
    assert!(!decompressed_headers2.rtp_marker);
    assert!(!decompressor_context.last_reconstructed_rtp_marker);

    // Packet 3 (UO-1): SN=202, M=true (marker changed again)
    // This is where the CRC mismatch was occurring. The SN is a small increment.
    let original_headers3 = create_sample_rtp_packet(202, 2320, true); // SN +1 from 201, M changes from false to true
    let uo1_core_packet3 =
        compress_rtp_udp_ip_umode(&mut compressor_context, &original_headers3).unwrap();
    assert_eq!(compressor_context.fo_packets_sent_since_ir, 2);
    assert_eq!(uo1_core_packet3.len(), 3, "Packet 3 core should be UO-1");
    assert_eq!(
        (uo1_core_packet3[0] & 0xF0),
        rohcstar::packet_processor::UO_1_SN_PACKET_TYPE_BASE
    );
    assert_ne!(
        (uo1_core_packet3[0] & rohcstar::packet_processor::UO_1_SN_MARKER_BIT_MASK),
        0
    );

    let mut rohc_packet3_framed = vec![ADD_CID_OCTET_PREFIX_VALUE | (cid as u8)];
    rohc_packet3_framed.extend_from_slice(&uo1_core_packet3);
    let decompressed_headers3 =
        decompress_rtp_udp_ip_umode(&mut decompressor_context, &rohc_packet3_framed).unwrap(); // This was failing CRC

    assert_eq!(
        decompressed_headers3.rtp_sequence_number,
        original_headers3.rtp_sequence_number
    );
    assert_eq!(
        decompressed_headers3.rtp_marker,
        original_headers3.rtp_marker
    ); // M true
    assert!(decompressor_context.last_reconstructed_rtp_marker);

    // Packet 4 (IR): This is the 3rd FO packet attempt. refresh_interval = 3.
    // fo_packets_sent_since_ir was 2. (2 >= 3-1) is true. So, IR.
    let original_headers4 = create_sample_rtp_packet(203, 2480, false); // M changes to false
    let rohc_packet4 =
        compress_rtp_udp_ip_umode(&mut compressor_context, &original_headers4).unwrap();

    assert_eq!(rohc_packet4[0], ADD_CID_OCTET_PREFIX_VALUE | (cid as u8));
    assert_eq!(
        rohc_packet4[1],
        rohcstar::packet_processor::ROHC_IR_PACKET_TYPE_WITH_DYN
    );
    assert_eq!(compressor_context.fo_packets_sent_since_ir, 0);

    let decompressed_headers4 =
        decompress_rtp_udp_ip_umode(&mut decompressor_context, &rohc_packet4).unwrap();
    assert_eq!(decompressor_context.cid, cid);
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
    assert!(!decompressor_context.last_reconstructed_rtp_marker);
}
