use rohcstar::constants::{
    ADD_CID_OCTET_PREFIX_VALUE, PROFILE_ID_RTP_UDP_IP, ROHC_IR_PACKET_TYPE_WITH_DYN,
    UO_1_SN_MARKER_BIT_MASK, UO_1_SN_PACKET_TYPE_BASE,
};
use rohcstar::context::{
    DecompressorMode, RtpUdpIpP1CompressorContext, RtpUdpIpP1DecompressorContext,
};
use rohcstar::profiles::profile1_compressor::compress_rtp_udp_ip_umode;
use rohcstar::profiles::profile1_decompressor::decompress_rtp_udp_ip_umode;
use rohcstar::protocol_types::RtpUdpIpv4Headers;

/// Helper function to create sample RTP/UDP/IPv4 headers for testing.
fn create_sample_rtp_packet(seq_num: u16, timestamp: u32, marker: bool) -> RtpUdpIpv4Headers {
    RtpUdpIpv4Headers {
        ip_src: "192.168.0.1".parse().unwrap(),
        ip_dst: "192.168.0.2".parse().unwrap(),
        udp_src_port: 10000,
        udp_dst_port: 20000,
        rtp_ssrc: 0x12345678, // Consistent SSRC for a flow
        rtp_sequence_number: seq_num,
        rtp_timestamp: timestamp,
        rtp_marker: marker,
        ip_protocol: 17, // UDP
        rtp_version: 2,
        ip_ihl: 5, // No IP options
        ip_ttl: 64,
        ..Default::default()
    }
}

/// Tests a basic flow for Profile 1 U-mode with CID 0:
/// IR -> UO-0 (SN increment) -> UO-1 (Marker change) -> UO-1 (Marker change back) -> UO-0 -> IR (refresh).
#[test]
fn p1_umode_ir_to_fo_sequence_cid0() {
    let cid: u16 = 0;
    let ir_refresh_interval = 5; // Refresh after 4 FO packets

    let mut compressor_context =
        RtpUdpIpP1CompressorContext::new(cid, PROFILE_ID_RTP_UDP_IP, ir_refresh_interval);
    let mut decompressor_context = RtpUdpIpP1DecompressorContext::new(cid, PROFILE_ID_RTP_UDP_IP);

    // Packet 1: IR
    // SN=100, M=false
    let original_headers1 = create_sample_rtp_packet(100, 1000, false);
    // Compressor context is initialized with these headers implicitly by the first compress call
    // when in InitializationAndRefresh mode.
    let rohc_packet1 =
        compress_rtp_udp_ip_umode(&mut compressor_context, &original_headers1).unwrap();
    assert_eq!(
        rohc_packet1[0], ROHC_IR_PACKET_TYPE_WITH_DYN,
        "P1: IR packet type check"
    );

    let decompressed_headers1 =
        decompress_rtp_udp_ip_umode(&mut decompressor_context, &rohc_packet1).unwrap();
    assert_eq!(
        decompressed_headers1.rtp_marker, original_headers1.rtp_marker,
        "P1: Marker mismatch"
    );
    assert_eq!(
        decompressor_context.mode,
        DecompressorMode::FullContext,
        "P1: Decompressor should be in FC mode"
    );

    // Packet 2: UO-0
    // SN=101 (small increment), M=false (no change)
    let original_headers2 = create_sample_rtp_packet(101, 1160, false);
    let rohc_packet2 =
        compress_rtp_udp_ip_umode(&mut compressor_context, &original_headers2).unwrap();
    assert_eq!(rohc_packet2.len(), 1, "P2: Expected UO-0 (1 byte)");

    let decompressed_headers2 =
        decompress_rtp_udp_ip_umode(&mut decompressor_context, &rohc_packet2).unwrap();
    // UO-0 takes marker from decompressor context (which was from original_headers1)
    assert_eq!(
        decompressed_headers2.rtp_marker, original_headers1.rtp_marker,
        "P2: Marker should be from context (original_headers1)"
    );
    assert_eq!(
        decompressed_headers2.rtp_sequence_number, original_headers2.rtp_sequence_number,
        "P2: SN mismatch"
    );

    // Packet 3: UO-1 (Marker changes)
    // SN=102, M=true
    let original_headers3 = create_sample_rtp_packet(102, 1320, true);
    let rohc_packet3 =
        compress_rtp_udp_ip_umode(&mut compressor_context, &original_headers3).unwrap();
    assert_eq!(rohc_packet3.len(), 3, "P3: Expected UO-1-SN (3 bytes)");
    assert_eq!(
        (rohc_packet3[0] & 0xF0),
        UO_1_SN_PACKET_TYPE_BASE,
        "P3: UO-1 type prefix check"
    );
    assert_ne!(
        (rohc_packet3[0] & UO_1_SN_MARKER_BIT_MASK),
        0,
        "P3: UO-1 marker bit should be set"
    );

    let decompressed_headers3 =
        decompress_rtp_udp_ip_umode(&mut decompressor_context, &rohc_packet3).unwrap();
    assert_eq!(
        decompressed_headers3.rtp_sequence_number, original_headers3.rtp_sequence_number,
        "P3: SN mismatch"
    );
    // UO-1-SN for MVP doesn't carry TS, so decompressor uses last known TS from context
    assert_eq!(
        decompressed_headers3.rtp_timestamp,
        original_headers1.rtp_timestamp, // TS from P1 context
        "P3: TS should be from context (original_headers1)"
    );
    assert_eq!(
        decompressed_headers3.rtp_marker, original_headers3.rtp_marker,
        "P3: Marker should match current packet"
    );

    // Packet 4: UO-1 (Marker changes again)
    // SN=103, M=false
    let original_headers4 = create_sample_rtp_packet(103, 1480, false);
    let rohc_packet4 =
        compress_rtp_udp_ip_umode(&mut compressor_context, &original_headers4).unwrap();
    assert_eq!(rohc_packet4.len(), 3, "P4: Expected UO-1-SN (3 bytes)");
    assert_eq!(
        (rohc_packet4[0] & UO_1_SN_MARKER_BIT_MASK),
        0,
        "P4: UO-1 marker bit should be clear"
    );

    let decompressed_headers4 =
        decompress_rtp_udp_ip_umode(&mut decompressor_context, &rohc_packet4).unwrap();
    assert_eq!(
        decompressed_headers4.rtp_marker, original_headers4.rtp_marker,
        "P4: Marker mismatch"
    );

    // Packet 5: UO-0 (Marker same, SN small delta)
    // SN=104, M=false
    // This is the 4th FO packet. IR refresh interval is 5. Next FO packet will trigger IR.
    let original_headers5 = create_sample_rtp_packet(104, 1640, false);
    let rohc_packet5 =
        compress_rtp_udp_ip_umode(&mut compressor_context, &original_headers5).unwrap();
    assert_eq!(rohc_packet5.len(), 1, "P5: Expected UO-0 (1 byte)");

    let decompressed_headers5 =
        decompress_rtp_udp_ip_umode(&mut decompressor_context, &rohc_packet5).unwrap();
    // UO-0 takes marker from decompressor context (which was P4's marker: false)
    assert_eq!(
        decompressed_headers5.rtp_marker, original_headers4.rtp_marker,
        "P5: Marker should be from context (original_headers4)"
    );

    // Packet 6: IR (Refresh interval triggered)
    // SN=105, M=true
    let original_headers6 = create_sample_rtp_packet(105, 1800, true);
    let rohc_packet6 =
        compress_rtp_udp_ip_umode(&mut compressor_context, &original_headers6).unwrap();
    assert_eq!(
        rohc_packet6[0], ROHC_IR_PACKET_TYPE_WITH_DYN,
        "P6: IR packet type check (refresh)"
    );

    let decompressed_headers6 =
        decompress_rtp_udp_ip_umode(&mut decompressor_context, &rohc_packet6).unwrap();
    assert_eq!(
        decompressed_headers6.rtp_marker, original_headers6.rtp_marker,
        "P6: Marker mismatch"
    );
}

/// Tests Profile 1 U-mode sequence with a small non-zero CID, requiring Add-CID octets.
/// Verifies IR -> UO-1 (marker change) -> UO-1 (marker change + SN LSBs) -> IR (refresh)
#[test]
fn p1_umode_ir_to_fo_sequence_small_cid() {
    let cid: u16 = 5;
    let ir_refresh_interval = 3; // Refresh after 2 FO packets

    let mut compressor_context =
        RtpUdpIpP1CompressorContext::new(cid, PROFILE_ID_RTP_UDP_IP, ir_refresh_interval);
    // Decompressor context starts with CID 0 or an irrelevant CID to simulate NoContext for CID `cid`.
    let mut decompressor_context = RtpUdpIpP1DecompressorContext::new(0, PROFILE_ID_RTP_UDP_IP);
    decompressor_context.mode = DecompressorMode::NoContext; // Ensure it needs IR to establish context for `cid`

    // Packet 1 (IR): SN=200, M=true
    let original_headers1 = create_sample_rtp_packet(200, 2000, true);
    // Compressor context implicitly initialized for this flow by first compress call
    let rohc_packet1 =
        compress_rtp_udp_ip_umode(&mut compressor_context, &original_headers1).unwrap();
    assert_eq!(
        rohc_packet1[0],
        ADD_CID_OCTET_PREFIX_VALUE | (cid as u8),
        "P1: Add-CID octet check"
    );
    assert_eq!(
        rohc_packet1[1], ROHC_IR_PACKET_TYPE_WITH_DYN,
        "P1: IR type check after Add-CID"
    );

    let decompressed_headers1 =
        decompress_rtp_udp_ip_umode(&mut decompressor_context, &rohc_packet1).unwrap();
    assert_eq!(
        decompressor_context.cid, cid,
        "P1: Decompressor CID should be updated from Add-CID"
    );
    assert_eq!(decompressor_context.mode, DecompressorMode::FullContext);
    assert_eq!(
        decompressed_headers1.rtp_marker,
        original_headers1.rtp_marker
    );
    assert!(
        decompressor_context.last_reconstructed_rtp_marker,
        "P1: Context marker should be true"
    );

    // Packet 2 (UO-1): SN=201, M=false (marker changed)
    let original_headers2 = create_sample_rtp_packet(201, 2160, false);
    let uo1_core_packet = // Compressor generates core packet without Add-CID
        compress_rtp_udp_ip_umode(&mut compressor_context, &original_headers2).unwrap();
    assert_eq!(uo1_core_packet.len(), 3, "P2: UO-1 core packet length");

    // Simulate framing with Add-CID for decompressor
    let mut rohc_packet2_framed = vec![ADD_CID_OCTET_PREFIX_VALUE | (cid as u8)];
    rohc_packet2_framed.extend_from_slice(&uo1_core_packet);

    let decompressed_headers2 =
        decompress_rtp_udp_ip_umode(&mut decompressor_context, &rohc_packet2_framed).unwrap();
    assert_eq!(
        decompressed_headers2.rtp_marker,
        original_headers2.rtp_marker
    );
    assert!(
        !decompressor_context.last_reconstructed_rtp_marker,
        "P2: Context marker should be false"
    );

    // Packet 3 (UO-1): SN=202, M=true (marker changed again)
    // This is the 2nd FO packet. IR refresh interval is 3. (2 >= 3-1) -> Next should be IR.
    let original_headers3 = create_sample_rtp_packet(202, 2320, true);
    let uo1_core_packet3 =
        compress_rtp_udp_ip_umode(&mut compressor_context, &original_headers3).unwrap();
    assert_eq!(
        compressor_context.fo_packets_sent_since_ir, 2,
        "P3: FO packets count before this one"
    );
    assert_eq!(uo1_core_packet3.len(), 3, "P3: UO-1 core packet length");
    assert_eq!(
        (uo1_core_packet3[0] & 0xF0),
        UO_1_SN_PACKET_TYPE_BASE,
        "P3: UO-1 type prefix"
    );
    assert_ne!(
        (uo1_core_packet3[0] & UO_1_SN_MARKER_BIT_MASK),
        0,
        "P3: UO-1 marker bit set"
    );

    let mut rohc_packet3_framed = vec![ADD_CID_OCTET_PREFIX_VALUE | (cid as u8)];
    rohc_packet3_framed.extend_from_slice(&uo1_core_packet3);
    let decompressed_headers3 =
        decompress_rtp_udp_ip_umode(&mut decompressor_context, &rohc_packet3_framed).unwrap();

    assert_eq!(
        decompressed_headers3.rtp_sequence_number,
        original_headers3.rtp_sequence_number
    );
    assert_eq!(
        decompressed_headers3.rtp_marker,
        original_headers3.rtp_marker
    );
    assert!(
        decompressor_context.last_reconstructed_rtp_marker,
        "P3: Context marker should be true"
    );

    // Packet 4 (IR): Refresh interval triggered
    // SN=203, M=false (marker changes)
    let original_headers4 = create_sample_rtp_packet(203, 2480, false);
    let rohc_packet4_framed = // Compressor directly includes Add-CID for IR
        compress_rtp_udp_ip_umode(&mut compressor_context, &original_headers4).unwrap();

    assert_eq!(
        rohc_packet4_framed[0],
        ADD_CID_OCTET_PREFIX_VALUE | (cid as u8),
        "P4: Add-CID for IR refresh"
    );
    assert_eq!(
        rohc_packet4_framed[1], ROHC_IR_PACKET_TYPE_WITH_DYN,
        "P4: IR type after Add-CID"
    );
    assert_eq!(
        compressor_context.fo_packets_sent_since_ir, 0,
        "P4: FO counter reset after IR"
    );

    let decompressed_headers4 =
        decompress_rtp_udp_ip_umode(&mut decompressor_context, &rohc_packet4_framed).unwrap();
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
    assert!(
        !decompressor_context.last_reconstructed_rtp_marker,
        "P4: Context marker should be false"
    );
}

/// Tests that a significant jump in RTP Sequence Number (that cannot be encoded by UO-0)
/// correctly triggers the sending of a UO-1 packet.
#[test]
fn p1_umode_sn_jump_triggers_uo1() {
    let cid: u16 = 0;
    let ir_refresh_interval = 10; // High enough not to interfere with this specific test

    let mut compressor_context =
        RtpUdpIpP1CompressorContext::new(cid, PROFILE_ID_RTP_UDP_IP, ir_refresh_interval);
    let mut decompressor_context = RtpUdpIpP1DecompressorContext::new(cid, PROFILE_ID_RTP_UDP_IP);

    // Packet 1: IR to establish context
    // SN=500, M=false
    let original_headers1 = create_sample_rtp_packet(500, 5000, false);
    let rohc_packet1 =
        compress_rtp_udp_ip_umode(&mut compressor_context, &original_headers1).unwrap();
    let _decompressed_headers1 =
        decompress_rtp_udp_ip_umode(&mut decompressor_context, &rohc_packet1).unwrap();
    // Contexts are now established:
    // Compressor in FO, Decompressor in FC.
    // last_sent_rtp_sn_full = 500, last_reconstructed_rtp_sn_full = 500
    // last_sent_rtp_marker = false, last_reconstructed_rtp_marker = false

    // Packet 2: Small SN jump, Marker same -> UO-0
    // SN=501 (increment by 1), M=false
    let original_headers2 = create_sample_rtp_packet(501, 5160, false);
    let rohc_packet2 =
        compress_rtp_udp_ip_umode(&mut compressor_context, &original_headers2).unwrap();
    assert_eq!(
        rohc_packet2.len(),
        1,
        "P2: Expected UO-0 for small SN increment"
    );

    let decompressed_headers2 =
        decompress_rtp_udp_ip_umode(&mut decompressor_context, &rohc_packet2).unwrap();
    assert_eq!(
        decompressed_headers2.rtp_sequence_number, 501,
        "P2: SN mismatch"
    );
    assert!(
        !decompressed_headers2.rtp_marker,
        "P2: Marker should be false"
    );

    // Packet 3: Large SN jump, Marker same -> UO-1
    // UO-0 with 4 LSBs (p=0) for SN_ref=501 has window [501, 501+15=516].
    // Next SN is 517 (501 + 16), which is outside this UO-0 window.
    // SN=517 (increment by 16 from P2), M=false
    let original_headers3 = create_sample_rtp_packet(517, 5320, false);
    let rohc_packet3 =
        compress_rtp_udp_ip_umode(&mut compressor_context, &original_headers3).unwrap();

    assert_eq!(
        rohc_packet3.len(),
        3,
        "P3: Expected UO-1 due to large SN jump"
    );
    assert_eq!(
        (rohc_packet3[0] & 0xF0),
        UO_1_SN_PACKET_TYPE_BASE,
        "P3: UO-1 type prefix check"
    );
    assert_eq!(
        (rohc_packet3[0] & UO_1_SN_MARKER_BIT_MASK),
        0,
        "P3: UO-1 marker bit should be clear (false)"
    );

    let decompressed_headers3 =
        decompress_rtp_udp_ip_umode(&mut decompressor_context, &rohc_packet3).unwrap();
    assert_eq!(
        decompressed_headers3.rtp_sequence_number, 517,
        "P3: SN mismatch"
    );
    assert!(
        !decompressed_headers3.rtp_marker,
        "P3: Marker should be false"
    );
    assert_eq!(
        decompressor_context.last_reconstructed_rtp_sn_full, 517,
        "P3: Decompressor context SN update check"
    );
}
