//! Integration tests for ROHC Profile 1 UO-1-TS packet handling.
//!
//! This module focuses on testing the UO-1-TS packet format, which is used
//! when the RTP Timestamp changes, the RTP Sequence Number increments by one,
//! and the RTP Marker bit remains unchanged from the context.

mod common;
use common::{
    create_rtp_headers, create_test_engine_with_system_clock, establish_ir_context,
    get_decompressor_context,
};

use rohcstar::constants::ROHC_ADD_CID_FEEDBACK_PREFIX_VALUE;
use rohcstar::packet_defs::{GenericUncompressedHeaders, RohcProfile};
use rohcstar::profiles::profile1::{
    P1_UO_1_SN_MARKER_BIT_MASK, P1_UO_1_SN_PACKET_TYPE_PREFIX, P1_UO_1_TS_DISCRIMINATOR,
    Profile1Handler,
};

/// Tests UO-1-TS packet when TS changes with SN+1 and stable marker.
#[test]
fn p1_uo1_ts_basic_timestamp_change_sn_updates() {
    let mut engine = create_test_engine_with_system_clock(100);
    engine
        .register_profile_handler(Box::new(Profile1Handler::new()))
        .unwrap();
    let cid = 0u16;
    let ssrc = 0x12345678;

    let ir_headers = create_rtp_headers(100, 1000, false, ssrc);
    establish_ir_context(
        &mut engine,
        cid,
        ir_headers.rtp_sequence_number.into(),
        ir_headers.rtp_timestamp.into(),
        ir_headers.rtp_marker,
        ssrc,
    );
    let ip_id_from_ir_context = ir_headers.ip_identification;

    let headers = create_rtp_headers(101, 2000, false, ssrc).with_ip_id(ip_id_from_ir_context);
    let generic = GenericUncompressedHeaders::RtpUdpIpv4(headers.clone());
    let mut compress_buf = [0u8; 128];
    let compressed_len = engine
        .compress(
            cid.into(),
            Some(RohcProfile::RtpUdpIp),
            &generic,
            &mut compress_buf,
        )
        .unwrap();
    let compressed = &compress_buf[..compressed_len];

    assert_eq!(compressed.len(), 4);
    assert_eq!(compressed[0], P1_UO_1_TS_DISCRIMINATOR);

    let decompressed = engine
        .decompress(compressed)
        .unwrap()
        .as_rtp_udp_ipv4()
        .unwrap()
        .clone();
    assert_eq!(decompressed.rtp_sequence_number, 101);
    assert_eq!(decompressed.rtp_timestamp, 2000);
    assert!(!decompressed.rtp_marker);

    let decomp_ctx = get_decompressor_context(&engine, cid);
    assert_eq!(decomp_ctx.last_reconstructed_rtp_sn_full, 101);
    assert_eq!(decomp_ctx.last_reconstructed_rtp_ts_full, 2000);
    assert!(!decomp_ctx.last_reconstructed_rtp_marker);
}

/// Tests UO-1-TS with large timestamp jump.
#[test]
fn p1_uo1_ts_large_timestamp_jump_sn_updates() {
    let mut engine = create_test_engine_with_system_clock(100);
    engine
        .register_profile_handler(Box::new(Profile1Handler::new()))
        .unwrap();
    let cid = 0u16;
    let ssrc = 0xAABBCCDD;

    let ir_headers = create_rtp_headers(200, 10000, false, ssrc);
    establish_ir_context(
        &mut engine,
        cid,
        ir_headers.rtp_sequence_number.into(),
        ir_headers.rtp_timestamp.into(),
        ir_headers.rtp_marker,
        ssrc,
    );
    let ip_id_from_ir_context = ir_headers.ip_identification;

    let new_ts_val: u32 = 10000 + 15000;
    let headers =
        create_rtp_headers(201, new_ts_val, false, ssrc).with_ip_id(ip_id_from_ir_context);
    let generic = GenericUncompressedHeaders::RtpUdpIpv4(headers.clone());
    let mut compress_buf = [0u8; 128];
    let compressed_len = engine
        .compress(
            cid.into(),
            Some(RohcProfile::RtpUdpIp),
            &generic,
            &mut compress_buf,
        )
        .unwrap();
    let compressed = &compress_buf[..compressed_len];

    assert_eq!(compressed.len(), 4);
    assert_eq!(compressed[0], P1_UO_1_TS_DISCRIMINATOR);

    let decompressed = engine
        .decompress(compressed)
        .unwrap()
        .as_rtp_udp_ipv4()
        .unwrap()
        .clone();
    assert_eq!(decompressed.rtp_sequence_number, 201);
    assert_eq!(decompressed.rtp_timestamp, new_ts_val);

    let decomp_ctx = get_decompressor_context(&engine, cid);
    assert_eq!(decomp_ctx.last_reconstructed_rtp_sn_full, 201);
    assert_eq!(decomp_ctx.last_reconstructed_rtp_ts_full, new_ts_val);
}

/// Tests packet type selection priority between UO-1-TS and UO-1-SN under various conditions.
#[test]
fn p1_uo1_ts_vs_uo1_sn_selection_priority() {
    let mut engine = create_test_engine_with_system_clock(100);
    engine
        .register_profile_handler(Box::new(Profile1Handler::new()))
        .unwrap();
    let cid = 0u16;
    let ssrc = 0x11223344;

    // Initial IR: SN=300, TS=3000, Marker=false
    let ir_headers = create_rtp_headers(300, 3000, false, ssrc);
    establish_ir_context(
        &mut engine,
        cid,
        ir_headers.rtp_sequence_number.into(),
        ir_headers.rtp_timestamp.into(),
        ir_headers.rtp_marker,
        ssrc,
    );
    let ip_id_in_context = ir_headers.ip_identification;

    // Packet 1: SN=301 (ctx_sn+1), TS=4000 (changed), Marker=false (same), IP-ID=same
    // Expected: UO-1-TS
    let headers1 = create_rtp_headers(301, 4000, false, ssrc).with_ip_id(ip_id_in_context);
    let mut compress_buf1 = [0u8; 1500];
    let compressed1_len = engine
        .compress(
            cid.into(),
            Some(RohcProfile::RtpUdpIp),
            &GenericUncompressedHeaders::RtpUdpIpv4(headers1.clone()),
            &mut compress_buf1,
        )
        .unwrap_or_else(|e| panic!("Compression failed: {:?}", e));
    let compressed1 = &compress_buf1[..compressed1_len];

    assert_eq!(compressed1.len(), 4, "Packet 1 should be UO-1-TS");
    assert_eq!(
        compressed1[0], P1_UO_1_TS_DISCRIMINATOR,
        "Packet 1 should be UO-1-TS type. Got: {:#04X}",
        compressed1[0]
    );

    let decomp1_result = engine.decompress(compressed1);
    assert!(
        decomp1_result.is_ok(),
        "Decompression failed: {:?}",
        decomp1_result.err()
    );
    let decomp1 = decomp1_result.unwrap().as_rtp_udp_ipv4().unwrap().clone();
    assert_eq!(decomp1.rtp_sequence_number, 301);
    assert_eq!(decomp1.rtp_timestamp, 4000);

    // Packet 2: SN=302 (ctx_sn+1), TS=4000 (same as P1 context), Marker=true (changed), IP-ID=same
    // Expected: UO-1-SN (Marker change takes precedence over UO-1-TS conditions)
    let headers2 = create_rtp_headers(302, 4000, true, ssrc).with_ip_id(ip_id_in_context);
    let mut compress_buf2 = [0u8; 1500];
    let compressed2_len = engine
        .compress(
            cid.into(),
            Some(RohcProfile::RtpUdpIp),
            &GenericUncompressedHeaders::RtpUdpIpv4(headers2.clone()),
            &mut compress_buf2,
        )
        .unwrap();
    let compressed2 = &compress_buf2[..compressed2_len];
    assert_eq!(compressed2.len(), 3, "Packet 2 should be UO-1-SN");
    assert_eq!(
        compressed2[0] & P1_UO_1_SN_PACKET_TYPE_PREFIX,
        P1_UO_1_SN_PACKET_TYPE_PREFIX
    );
    assert_ne!(compressed2[0], P1_UO_1_TS_DISCRIMINATOR);
    let decomp2_result = engine.decompress(compressed2);
    assert!(
        decomp2_result.is_ok(),
        "Decompression failed: {:?}",
        decomp2_result.err()
    );
    let decomp2 = decomp2_result.unwrap().as_rtp_udp_ipv4().unwrap().clone();
    assert_eq!(decomp2.rtp_sequence_number, 302);
    assert!(decomp2.rtp_marker);
    assert_eq!(decomp2.rtp_timestamp, 5000);

    // Packet 3: SN=303 (ctx_sn+1), TS=4000 (same as P2 context), Marker=false (changed from P2 context), IP-ID=same
    // Expected: UO-1-SN (Marker change)
    let headers3 = create_rtp_headers(303, 4000, false, ssrc).with_ip_id(ip_id_in_context);
    // Packet 3: SN=303 (ctx_sn+1), TS=6000 (changed), Marker=false (same as P2 context), IP-ID same
    // Expected: UO-1-SN (SN+1, TS changed, but SN takes priority for packet type selection)
    let mut compress_buf3 = [0u8; 1500];
    let compressed3_len = engine
        .compress(
            cid.into(),
            Some(RohcProfile::RtpUdpIp),
            &GenericUncompressedHeaders::RtpUdpIpv4(headers3.clone()),
            &mut compress_buf3,
        )
        .unwrap();
    let compressed3 = &compress_buf3[..compressed3_len];

    assert_eq!(compressed3.len(), 3, "Packet 3 should be UO-1-SN");
    assert_eq!(
        compressed3[0] & P1_UO_1_SN_PACKET_TYPE_PREFIX,
        P1_UO_1_SN_PACKET_TYPE_PREFIX,
        "Packet 3 should be UO-1-SN type. Got: {:#04X}",
        compressed3[0]
    );
    assert_ne!(
        compressed3[0] & !P1_UO_1_SN_MARKER_BIT_MASK,
        P1_UO_1_TS_DISCRIMINATOR,
        "Packet 3 should not be UO-1-TS type"
    );

    let decomp3_result = engine.decompress(compressed3);
    assert!(
        decomp3_result.is_ok(),
        "Decompression failed: {:?}",
        decomp3_result.err()
    );
    let decomp3 = decomp3_result.unwrap().as_rtp_udp_ipv4().unwrap().clone();
    assert_eq!(decomp3.rtp_sequence_number, 303);
    assert_eq!(decomp3.rtp_timestamp, 6000);
    assert!(!decomp3.rtp_marker);

    // Packet 4: SN=305 (ctx_sn+2), TS=6000 (changed), Marker=false (same as P3 context), IP-ID changes
    // Expected: UO-1-SN (SN jump > 1, overrides UO-1-TS/ID consideration)
    let headers4 =
        create_rtp_headers(305, 6000, false, ssrc).with_ip_id(ip_id_in_context.wrapping_add(1));

    let mut compress_buf4 = [0u8; 1500];
    let compressed4_len = engine
        .compress(
            cid.into(),
            Some(RohcProfile::RtpUdpIp),
            &GenericUncompressedHeaders::RtpUdpIpv4(headers4.clone()),
            &mut compress_buf4,
        )
        .unwrap();
    let compressed4 = &compress_buf4[..compressed4_len];

    assert_eq!(compressed4.len(), 3, "Packet 4 should be UO-1-SN");
    assert_eq!(
        compressed4[0] & P1_UO_1_SN_PACKET_TYPE_PREFIX,
        P1_UO_1_SN_PACKET_TYPE_PREFIX,
        "Packet 4 should be UO-1-SN type. Got: {:#04X}",
        compressed4[0]
    );
    assert_ne!(
        compressed4[0] & !P1_UO_1_SN_MARKER_BIT_MASK,
        P1_UO_1_TS_DISCRIMINATOR,
        "Packet 4 should not be UO-1-TS type"
    );

    let decomp4_result = engine.decompress(compressed4);
    assert!(
        decomp4_result.is_ok(),
        "Decompression failed: {:?}",
        decomp4_result.err()
    );
    let decomp4 = decomp4_result.unwrap().as_rtp_udp_ipv4().unwrap().clone();
    assert_eq!(decomp4.rtp_sequence_number, 305);
    assert_eq!(decomp4.rtp_timestamp, 8000); // TS from P3 context
}

/// Tests UO-1-TS where the Marker bit is TRUE in the context and remains TRUE for the packet,
/// ensuring CRC calculation correctly uses the context marker.
#[test]
fn p1_uo1_ts_marker_from_context_for_crc() {
    let mut engine = create_test_engine_with_system_clock(100);
    engine
        .register_profile_handler(Box::new(Profile1Handler::new()))
        .unwrap();
    let cid = 0u16;
    let ssrc = 0xBADF00D;

    // IR establishes context with Marker=true
    let ir_headers = create_rtp_headers(50, 500, true, ssrc);
    establish_ir_context(
        &mut engine,
        cid,
        ir_headers.rtp_sequence_number.into(),
        ir_headers.rtp_timestamp.into(),
        ir_headers.rtp_marker,
        ssrc,
    );
    let ip_id_from_ir_context = ir_headers.ip_identification;

    // Packet: SN+1, TS change, Marker still true (same as context), IP-ID stable
    let headers = create_rtp_headers(51, 600, true, ssrc).with_ip_id(ip_id_from_ir_context);
    let generic = GenericUncompressedHeaders::RtpUdpIpv4(headers.clone());
    let mut compress_buf = [0u8; 128];
    let compressed_len = engine
        .compress(
            cid.into(),
            Some(RohcProfile::RtpUdpIp),
            &generic,
            &mut compress_buf,
        )
        .unwrap();
    let compressed = &compress_buf[..compressed_len];

    assert_eq!(compressed.len(), 4);
    assert_eq!(compressed[0], P1_UO_1_TS_DISCRIMINATOR); // UO-1-TS selected

    let decompressed = engine
        .decompress(compressed)
        .unwrap()
        .as_rtp_udp_ipv4()
        .unwrap()
        .clone();
    assert_eq!(decompressed.rtp_sequence_number, 51);
    assert_eq!(decompressed.rtp_timestamp, 600);
    assert!(decompressed.rtp_marker); // Marker correctly true

    let decomp_ctx = get_decompressor_context(&engine, cid);
    assert!(decomp_ctx.last_reconstructed_rtp_marker);
    assert_eq!(decomp_ctx.last_reconstructed_rtp_ts_full, 600);
    assert_eq!(decomp_ctx.last_reconstructed_rtp_sn_full, 51);
}

/// Tests UO-1-TS packet compression and decompression when a small CID is used,
/// ensuring the Add-CID octet is correctly prepended.
#[test]
fn p1_uo1_ts_with_add_cid() {
    let mut engine = create_test_engine_with_system_clock(100);
    engine
        .register_profile_handler(Box::new(Profile1Handler::new()))
        .unwrap();
    let cid = 3u16; // Small CID
    let ssrc = 0xFEEDF00D;

    let ir_headers = create_rtp_headers(70, 7000, false, ssrc);
    establish_ir_context(
        &mut engine,
        cid,
        ir_headers.rtp_sequence_number.into(),
        ir_headers.rtp_timestamp.into(),
        ir_headers.rtp_marker,
        ssrc,
    );
    let ip_id_from_ir_context = ir_headers.ip_identification;

    // Packet: SN+1, TS change, Marker stable, IP-ID stable
    let headers = create_rtp_headers(71, 7500, false, ssrc).with_ip_id(ip_id_from_ir_context);
    let generic = GenericUncompressedHeaders::RtpUdpIpv4(headers.clone());
    let mut compress_buf = [0u8; 128];
    let compressed_len = engine
        .compress(
            cid.into(),
            Some(RohcProfile::RtpUdpIp),
            &generic,
            &mut compress_buf,
        )
        .unwrap();
    let compressed = &compress_buf[..compressed_len];

    assert_eq!(compressed.len(), 5); // Add-CID + Type + TS_LSB(2) + CRC8
    assert_eq!(
        compressed[0],
        ROHC_ADD_CID_FEEDBACK_PREFIX_VALUE | (cid as u8)
    );
    assert_eq!(compressed[1], P1_UO_1_TS_DISCRIMINATOR);

    let decompressed = engine
        .decompress(compressed)
        .unwrap()
        .as_rtp_udp_ipv4()
        .unwrap()
        .clone();
    assert_eq!(decompressed.rtp_sequence_number, 71);
    assert_eq!(decompressed.rtp_timestamp, 7500);
    assert!(!decompressed.rtp_marker);
}

/// Tests that UO-1-TS is selected when RTP Timestamp changes significantly, SN increments by one,
/// and Marker remains unchanged from the context.
#[test]
fn p1_uo1_ts_is_used_when_ts_changes_marker_sn_ok_for_uo1ts() {
    let mut engine = create_test_engine_with_system_clock(100);
    engine
        .register_profile_handler(Box::new(Profile1Handler::new()))
        .unwrap();
    let cid = 0u16;
    let ssrc = 0x4B5C6D;

    let initial_sn = 400;
    let initial_ts_val: u32 = 5000;
    let initial_marker = false;
    let ir_headers_for_context =
        create_rtp_headers(initial_sn, initial_ts_val, initial_marker, ssrc);
    establish_ir_context(
        &mut engine,
        cid,
        ir_headers_for_context.rtp_sequence_number.into(),
        ir_headers_for_context.rtp_timestamp.into(),
        ir_headers_for_context.rtp_marker,
        ssrc,
    );

    let next_sn = initial_sn + 1; // SN increments by one
    let next_ts_val: u32 = initial_ts_val + 500; // TS changes significantly
    let mut headers_ts_change = create_rtp_headers(next_sn, next_ts_val, initial_marker, ssrc); // Marker same
    headers_ts_change.ip_identification = ir_headers_for_context.ip_identification; // IP-ID same
    let generic_ts_change = GenericUncompressedHeaders::RtpUdpIpv4(headers_ts_change.clone());

    let mut compress_buf = [0u8; 1500];
    let compressed_len = engine
        .compress(
            cid.into(),
            Some(RohcProfile::RtpUdpIp),
            &generic_ts_change,
            &mut compress_buf,
        )
        .unwrap();
    let compressed_packet = &compress_buf[..compressed_len];

    // Expect UO-1-TS (4 bytes for CID 0: Type + TS_LSB(2) + CRC8)
    assert_eq!(compressed_packet.len(), 4);
    assert_eq!(compressed_packet[0], P1_UO_1_TS_DISCRIMINATOR);

    let decomp_headers = engine
        .decompress(compressed_packet)
        .unwrap()
        .as_rtp_udp_ipv4()
        .unwrap()
        .clone();
    assert_eq!(decomp_headers.rtp_sequence_number, next_sn);
    assert_eq!(decomp_headers.rtp_marker, initial_marker);
    assert_eq!(decomp_headers.rtp_timestamp, next_ts_val); // TS reconstructed
}
