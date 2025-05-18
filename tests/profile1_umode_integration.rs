use rohcstar::context::{
    CompressorMode, DecompressorMode, RtpUdpIpP1CompressorContext, RtpUdpIpP1DecompressorContext,
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
        ip_protocol: 17, // UDP
        rtp_version: 2,
        ip_ihl: 5,
        ip_ttl: 64,
        ..Default::default()
    }
}

#[test]
fn test_p1_umode_ir_then_uo0_flow_cid0() {
    let cid: u16 = 0;
    let ir_refresh_interval = 5; // Refresh IR after 5 FO packets (means after 4 FOs, 5th will be IR)

    let mut compressor_context =
        RtpUdpIpP1CompressorContext::new(cid, PROFILE_ID_RTP_UDP_IP, ir_refresh_interval);
    let mut decompressor_context = RtpUdpIpP1DecompressorContext::new(cid, PROFILE_ID_RTP_UDP_IP);

    // --- Packet 1: Should be IR ---
    let original_headers1 = create_sample_rtp_packet(100, 1000, false);

    // Initialize compressor context with the first packet (as a real system would)
    compressor_context.initialize_static_part_with_uncompressed_headers(&original_headers1);

    let rohc_packet1 =
        compress_rtp_udp_ip_umode(&mut compressor_context, &original_headers1).unwrap();

    // Check if it looks like an IR packet (basic check for MVP)
    // For CID 0, IR type is the first byte
    assert_eq!(
        rohc_packet1[0],
        rohcstar::packet_processor::ROHC_IR_PACKET_TYPE_WITH_DYN
    );
    assert_eq!(compressor_context.mode, CompressorMode::FirstOrder);

    let decompressed_headers1 =
        decompress_rtp_udp_ip_umode(&mut decompressor_context, &rohc_packet1).unwrap();

    assert_eq!(decompressor_context.mode, DecompressorMode::FullContext);
    assert_eq!(decompressor_context.cid, cid);
    assert_eq!(decompressed_headers1.rtp_ssrc, original_headers1.rtp_ssrc);
    assert_eq!(
        decompressed_headers1.rtp_sequence_number,
        original_headers1.rtp_sequence_number
    );
    assert_eq!(
        decompressed_headers1.rtp_timestamp,
        original_headers1.rtp_timestamp
    );
    assert_eq!(
        decompressed_headers1.rtp_marker,
        original_headers1.rtp_marker
    );
    assert_eq!(decompressed_headers1.ip_src, original_headers1.ip_src);
    assert_eq!(decompressed_headers1.ip_dst, original_headers1.ip_dst);
    assert_eq!(
        decompressed_headers1.udp_src_port,
        original_headers1.udp_src_port
    );
    assert_eq!(
        decompressed_headers1.udp_dst_port,
        original_headers1.udp_dst_port
    );

    // --- Packet 2: Should be UO-0 ---
    let original_headers2 = create_sample_rtp_packet(101, 1160, false); // SN +1, TS +160
    let rohc_packet2 =
        compress_rtp_udp_ip_umode(&mut compressor_context, &original_headers2).unwrap();

    // Check if it looks like a UO-0 packet (basic check)
    assert_eq!(rohc_packet2.len(), 1); // Simplest UO-0
    assert_eq!((rohc_packet2[0] & 0x80), 0x00); // MSB is 0
    assert_eq!(compressor_context.mode, CompressorMode::FirstOrder);
    assert_eq!(compressor_context.fo_packets_sent_since_ir, 1);

    let decompressed_headers2 =
        decompress_rtp_udp_ip_umode(&mut decompressor_context, &rohc_packet2).unwrap();

    assert_eq!(decompressor_context.mode, DecompressorMode::FullContext);
    assert_eq!(
        decompressed_headers2.rtp_sequence_number,
        original_headers2.rtp_sequence_number
    );
    // For MVP UO-0 decompressor, TS and Marker are taken from context (last IR/Update)
    assert_eq!(
        decompressed_headers2.rtp_timestamp,
        original_headers1.rtp_timestamp
    );
    assert_eq!(
        decompressed_headers2.rtp_marker,
        original_headers1.rtp_marker
    );
    // Static fields should still match
    assert_eq!(decompressed_headers2.rtp_ssrc, original_headers1.rtp_ssrc);

    // --- Packet 3: Another UO-0 ---
    let original_headers3 = create_sample_rtp_packet(102, 1320, true); // SN +1, TS +160, Marker changed
    let rohc_packet3 =
        compress_rtp_udp_ip_umode(&mut compressor_context, &original_headers3).unwrap();
    assert_eq!(compressor_context.fo_packets_sent_since_ir, 2);

    let decompressed_headers3 =
        decompress_rtp_udp_ip_umode(&mut decompressor_context, &rohc_packet3).unwrap();

    assert_eq!(
        decompressed_headers3.rtp_sequence_number,
        original_headers3.rtp_sequence_number
    );
    // For MVP UO-0 decompressor, TS and Marker are taken from context
    assert_eq!(
        decompressed_headers3.rtp_timestamp,
        original_headers1.rtp_timestamp
    ); // Still from original_headers1 as UO-0 doesn't update TS
    assert_eq!(
        decompressed_headers3.rtp_marker,
        original_headers1.rtp_marker
    ); // Still from original_headers1 as UO-0 doesn't update M

    // --- Packet 4: Would be 3rd FO packet. ir_refresh_interval = 5. Should still be UO-0.
    // (ir_refresh_interval - 1) = 4. Current fo_packets_sent_since_ir = 2. 2 < 4.
    let original_headers4 = create_sample_rtp_packet(103, 1480, false);
    let rohc_packet4 =
        compress_rtp_udp_ip_umode(&mut compressor_context, &original_headers4).unwrap();
    assert_eq!(compressor_context.fo_packets_sent_since_ir, 3);
    assert_eq!((rohc_packet4[0] & 0x80), 0x00, "Packet 4 should be UO-0");

    // --- Packet 5: Would be 4th FO packet. fo_packets_sent_since_ir = 3. 3 < 4. Should be UO-0.
    let original_headers5 = create_sample_rtp_packet(104, 1640, false);
    let rohc_packet5 =
        compress_rtp_udp_ip_umode(&mut compressor_context, &original_headers5).unwrap();
    assert_eq!(compressor_context.fo_packets_sent_since_ir, 4);
    assert_eq!((rohc_packet5[0] & 0x80), 0x00, "Packet 5 should be UO-0");

    // --- Packet 6: Would be 5th FO packet. fo_packets_sent_since_ir = 4.
    // Now, 4 >= (ir_refresh_interval - 1) which is 4 >= 4. Should be IR.
    let original_headers6 = create_sample_rtp_packet(105, 1800, true);
    let rohc_packet6 =
        compress_rtp_udp_ip_umode(&mut compressor_context, &original_headers6).unwrap();

    assert_eq!(
        rohc_packet6[0],
        rohcstar::packet_processor::ROHC_IR_PACKET_TYPE_WITH_DYN,
        "Packet 6 should be IR due to refresh"
    );
    assert_eq!(compressor_context.fo_packets_sent_since_ir, 0); // Reset after IR

    let decompressed_headers6 =
        decompress_rtp_udp_ip_umode(&mut decompressor_context, &rohc_packet6).unwrap();
    assert_eq!(
        decompressed_headers6.rtp_sequence_number,
        original_headers6.rtp_sequence_number
    );
    assert_eq!(
        decompressed_headers6.rtp_timestamp,
        original_headers6.rtp_timestamp
    ); // IR updates TS
    assert_eq!(
        decompressed_headers6.rtp_marker,
        original_headers6.rtp_marker
    ); // IR updates Marker
}

#[test]
fn test_p1_umode_ir_then_uo0_flow_cid5() {
    let cid: u16 = 5; // Non-zero small CID
    let ir_refresh_interval = 3;

    let mut compressor_context =
        RtpUdpIpP1CompressorContext::new(cid, PROFILE_ID_RTP_UDP_IP, ir_refresh_interval);
    // For a specific CID, decompressor context might be initialized for that CID from the start,
    // or it learns it from the first IR packet.
    let mut decompressor_context = RtpUdpIpP1DecompressorContext::new(0, PROFILE_ID_RTP_UDP_IP); // Start as if unknown CID
    decompressor_context.mode = DecompressorMode::NoContext;

    // --- Packet 1: Should be IR with Add-CID for 5 ---
    let original_headers1 = create_sample_rtp_packet(200, 2000, true);
    compressor_context.initialize_static_part_with_uncompressed_headers(&original_headers1);

    let rohc_packet1 =
        compress_rtp_udp_ip_umode(&mut compressor_context, &original_headers1).unwrap();

    // Check IR packet structure for CID 5
    assert!(rohc_packet1.len() > 1);
    assert_eq!(rohc_packet1[0], ADD_CID_OCTET_PREFIX_VALUE | (cid as u8)); // Add-CID octet
    assert_eq!(
        rohc_packet1[1],
        rohcstar::packet_processor::ROHC_IR_PACKET_TYPE_WITH_DYN
    ); // IR Type
    assert_eq!(compressor_context.mode, CompressorMode::FirstOrder);

    let decompressed_headers1 =
        decompress_rtp_udp_ip_umode(&mut decompressor_context, &rohc_packet1).unwrap();

    assert_eq!(decompressor_context.mode, DecompressorMode::FullContext);
    assert_eq!(decompressor_context.cid, cid); // Decompressor context should now know CID 5
    assert_eq!(decompressed_headers1.rtp_ssrc, original_headers1.rtp_ssrc);
    assert_eq!(
        decompressed_headers1.rtp_sequence_number,
        original_headers1.rtp_sequence_number
    );

    // --- Packet 2: Should be UO-0, framed with Add-CID for 5 by the test harness ---
    let original_headers2 = create_sample_rtp_packet(201, 2160, false);
    let uo0_core_packet =
        compress_rtp_udp_ip_umode(&mut compressor_context, &original_headers2).unwrap();

    // Check that compressor produced a 1-byte UO-0 (it doesn't add Add-CID for UO-0)
    assert_eq!(uo0_core_packet.len(), 1);
    assert_eq!((uo0_core_packet[0] & 0x80), 0x00);
    assert_eq!(compressor_context.fo_packets_sent_since_ir, 1);

    // Test harness frames the UO-0 with Add-CID
    let mut rohc_packet2_framed = vec![ADD_CID_OCTET_PREFIX_VALUE | (cid as u8)];
    rohc_packet2_framed.extend_from_slice(&uo0_core_packet);

    let decompressed_headers2 =
        decompress_rtp_udp_ip_umode(&mut decompressor_context, &rohc_packet2_framed).unwrap();

    assert_eq!(decompressor_context.mode, DecompressorMode::FullContext);
    assert_eq!(decompressor_context.cid, cid); // Still CID 5
    assert_eq!(
        decompressed_headers2.rtp_sequence_number,
        original_headers2.rtp_sequence_number
    );
    assert_eq!(decompressed_headers2.rtp_ssrc, original_headers1.rtp_ssrc);

    // --- Packet 3: Would be 2nd FO. ir_refresh_interval = 3.
    // fo_packets_sent_since_ir = 1. 1 >= (3-1) is 1 >= 2 which is false. Send UO-0.
    let original_headers3 = create_sample_rtp_packet(202, 2320, true);
    let uo0_core_packet3 =
        compress_rtp_udp_ip_umode(&mut compressor_context, &original_headers3).unwrap();
    assert_eq!(compressor_context.fo_packets_sent_since_ir, 2);
    assert_eq!((uo0_core_packet3[0] & 0x80), 0x00);

    // --- Packet 4: Would be 3rd FO packet. fo_packets_sent_since_ir = 2.
    // 2 >= (3-1) which is 2 >= 2. Should be IR.
    let original_headers4 = create_sample_rtp_packet(203, 2480, false);
    let rohc_packet4 =
        compress_rtp_udp_ip_umode(&mut compressor_context, &original_headers4).unwrap();

    assert_eq!(rohc_packet4[0], ADD_CID_OCTET_PREFIX_VALUE | (cid as u8)); // IR for CID 5
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
}
