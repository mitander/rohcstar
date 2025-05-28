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
use rohcstar::profiles::profile1::protocol_types::Timestamp;
use rohcstar::profiles::profile1::{
    P1_UO_1_SN_PACKET_TYPE_PREFIX, P1_UO_1_TS_DISCRIMINATOR, Profile1Handler,
};

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
        ir_headers.rtp_sequence_number,
        ir_headers.rtp_timestamp.value(),
        ir_headers.rtp_marker,
        ssrc,
    );
    let ip_id_from_ir_context = ir_headers.ip_identification;

    let headers = create_rtp_headers(101, 2000, false, ssrc).with_ip_id(ip_id_from_ir_context);
    let generic = GenericUncompressedHeaders::RtpUdpIpv4(headers.clone());
    let compressed = engine
        .compress(cid, Some(RohcProfile::RtpUdpIp), &generic)
        .unwrap();

    assert_eq!(compressed.len(), 4);
    assert_eq!(compressed[0], P1_UO_1_TS_DISCRIMINATOR);

    let decompressed = engine
        .decompress(&compressed)
        .unwrap()
        .as_rtp_udp_ipv4()
        .unwrap()
        .clone();
    assert_eq!(decompressed.rtp_sequence_number, 101);
    assert_eq!(decompressed.rtp_timestamp, Timestamp::new(2000));
    assert!(!decompressed.rtp_marker);

    let decomp_ctx = get_decompressor_context(&engine, cid);
    assert_eq!(decomp_ctx.last_reconstructed_rtp_sn_full, 101);
    assert_eq!(
        decomp_ctx.last_reconstructed_rtp_ts_full,
        Timestamp::new(2000)
    );
    assert!(!decomp_ctx.last_reconstructed_rtp_marker);
}

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
        ir_headers.rtp_sequence_number,
        ir_headers.rtp_timestamp.value(),
        ir_headers.rtp_marker,
        ssrc,
    );
    let ip_id_from_ir_context = ir_headers.ip_identification;

    let new_ts_val: u32 = 10000 + 15000;
    let headers =
        create_rtp_headers(201, new_ts_val, false, ssrc).with_ip_id(ip_id_from_ir_context);
    let generic = GenericUncompressedHeaders::RtpUdpIpv4(headers.clone());
    let compressed = engine
        .compress(cid, Some(RohcProfile::RtpUdpIp), &generic)
        .unwrap();

    assert_eq!(compressed.len(), 4);
    assert_eq!(compressed[0], P1_UO_1_TS_DISCRIMINATOR);

    let decompressed = engine
        .decompress(&compressed)
        .unwrap()
        .as_rtp_udp_ipv4()
        .unwrap()
        .clone();
    assert_eq!(decompressed.rtp_sequence_number, 201);
    assert_eq!(decompressed.rtp_timestamp, Timestamp::new(new_ts_val));

    let decomp_ctx = get_decompressor_context(&engine, cid);
    assert_eq!(decomp_ctx.last_reconstructed_rtp_sn_full, 201);
    assert_eq!(
        decomp_ctx.last_reconstructed_rtp_ts_full,
        Timestamp::new(new_ts_val)
    );
}
#[test]
fn p1_uo1_ts_vs_uo1_sn_selection_priority() {
    let mut engine = create_test_engine_with_system_clock(100);
    engine
        .register_profile_handler(Box::new(Profile1Handler::new()))
        .unwrap();
    let cid = 0u16;
    let ssrc = 0x11223344;

    let ir_headers = create_rtp_headers(300, 3000, false, ssrc);
    establish_ir_context(
        &mut engine,
        cid,
        ir_headers.rtp_sequence_number,
        ir_headers.rtp_timestamp.value(),
        ir_headers.rtp_marker,
        ssrc,
    );
    let ip_id_in_context = ir_headers.ip_identification;

    let headers1 = create_rtp_headers(301, 4000, false, ssrc).with_ip_id(ip_id_in_context);
    let compressed1 = engine
        .compress(
            cid,
            Some(RohcProfile::RtpUdpIp),
            &GenericUncompressedHeaders::RtpUdpIpv4(headers1.clone()),
        )
        .unwrap();
    assert_eq!(compressed1.len(), 4);
    assert_eq!(compressed1[0], P1_UO_1_TS_DISCRIMINATOR);
    let decomp1_result = engine.decompress(&compressed1);
    assert!(decomp1_result.is_ok());
    let decomp1 = decomp1_result.unwrap().as_rtp_udp_ipv4().unwrap().clone();
    assert_eq!(decomp1.rtp_sequence_number, 301);
    assert_eq!(decomp1.rtp_timestamp, Timestamp::new(4000));

    let headers2 = create_rtp_headers(302, 4000, true, ssrc).with_ip_id(ip_id_in_context);
    let compressed2 = engine
        .compress(
            cid,
            Some(RohcProfile::RtpUdpIp),
            &GenericUncompressedHeaders::RtpUdpIpv4(headers2.clone()),
        )
        .unwrap();
    assert_eq!(compressed2.len(), 3);
    assert_eq!(
        compressed2[0] & P1_UO_1_SN_PACKET_TYPE_PREFIX,
        P1_UO_1_SN_PACKET_TYPE_PREFIX
    );
    assert_ne!(compressed2[0], P1_UO_1_TS_DISCRIMINATOR);
    let decomp2_result = engine.decompress(&compressed2);
    assert!(decomp2_result.is_ok());
    let decomp2 = decomp2_result.unwrap().as_rtp_udp_ipv4().unwrap().clone();
    assert_eq!(decomp2.rtp_sequence_number, 302);
    assert!(decomp2.rtp_marker);
    assert_eq!(decomp2.rtp_timestamp, Timestamp::new(4000));

    let headers3 = create_rtp_headers(303, 4000, false, ssrc).with_ip_id(ip_id_in_context);
    let compressed3 = engine
        .compress(
            cid,
            Some(RohcProfile::RtpUdpIp),
            &GenericUncompressedHeaders::RtpUdpIpv4(headers3.clone()),
        )
        .unwrap();
    assert_eq!(compressed3.len(), 3);
    assert_eq!(
        compressed3[0] & P1_UO_1_SN_PACKET_TYPE_PREFIX,
        P1_UO_1_SN_PACKET_TYPE_PREFIX
    );
    assert_ne!(compressed3[0], P1_UO_1_TS_DISCRIMINATOR);
    let decomp3_result = engine.decompress(&compressed3);
    assert!(decomp3_result.is_ok());
    let decomp3 = decomp3_result.unwrap().as_rtp_udp_ipv4().unwrap().clone();
    assert_eq!(decomp3.rtp_sequence_number, 303);
    assert_eq!(decomp3.rtp_timestamp, Timestamp::new(4000));
    assert!(!decomp3.rtp_marker);

    let headers4 =
        create_rtp_headers(305, 6000, false, ssrc).with_ip_id(ip_id_in_context.wrapping_add(1));
    let compressed4 = engine
        .compress(
            cid,
            Some(RohcProfile::RtpUdpIp),
            &GenericUncompressedHeaders::RtpUdpIpv4(headers4.clone()),
        )
        .unwrap();
    assert_eq!(compressed4.len(), 3);
    assert_eq!(
        compressed4[0] & P1_UO_1_SN_PACKET_TYPE_PREFIX,
        P1_UO_1_SN_PACKET_TYPE_PREFIX
    );
    assert_ne!(compressed4[0], P1_UO_1_TS_DISCRIMINATOR);
    let decomp4_result = engine.decompress(&compressed4);
    assert!(decomp4_result.is_ok());
    let decomp4 = decomp4_result.unwrap().as_rtp_udp_ipv4().unwrap().clone();
    assert_eq!(decomp4.rtp_sequence_number, 305);
    assert_eq!(decomp4.rtp_timestamp, Timestamp::new(4000));
}

#[test]
fn p1_uo1_ts_marker_from_context_for_crc() {
    let mut engine = create_test_engine_with_system_clock(100);
    engine
        .register_profile_handler(Box::new(Profile1Handler::new()))
        .unwrap();
    let cid = 0u16;
    let ssrc = 0xBADF00D;

    let ir_headers = create_rtp_headers(50, 500, true, ssrc);
    establish_ir_context(
        &mut engine,
        cid,
        ir_headers.rtp_sequence_number,
        ir_headers.rtp_timestamp.value(),
        ir_headers.rtp_marker,
        ssrc,
    );
    let ip_id_from_ir_context = ir_headers.ip_identification;

    let headers = create_rtp_headers(51, 600, true, ssrc).with_ip_id(ip_id_from_ir_context);
    let generic = GenericUncompressedHeaders::RtpUdpIpv4(headers.clone());
    let compressed = engine
        .compress(cid, Some(RohcProfile::RtpUdpIp), &generic)
        .unwrap();

    assert_eq!(compressed.len(), 4);
    assert_eq!(compressed[0], P1_UO_1_TS_DISCRIMINATOR);

    let decompressed = engine
        .decompress(&compressed)
        .unwrap()
        .as_rtp_udp_ipv4()
        .unwrap()
        .clone();
    assert_eq!(decompressed.rtp_sequence_number, 51);
    assert_eq!(decompressed.rtp_timestamp, Timestamp::new(600));
    assert!(decompressed.rtp_marker);

    let decomp_ctx = get_decompressor_context(&engine, cid);
    assert!(decomp_ctx.last_reconstructed_rtp_marker);
    assert_eq!(
        decomp_ctx.last_reconstructed_rtp_ts_full,
        Timestamp::new(600)
    );
    assert_eq!(decomp_ctx.last_reconstructed_rtp_sn_full, 51);
}

#[test]
fn p1_uo1_ts_with_add_cid() {
    let mut engine = create_test_engine_with_system_clock(100);
    engine
        .register_profile_handler(Box::new(Profile1Handler::new()))
        .unwrap();
    let cid = 3u16;
    let ssrc = 0xFEEDF00D;

    let ir_headers = create_rtp_headers(70, 7000, false, ssrc);
    establish_ir_context(
        &mut engine,
        cid,
        ir_headers.rtp_sequence_number,
        ir_headers.rtp_timestamp.value(),
        ir_headers.rtp_marker,
        ssrc,
    );
    let ip_id_from_ir_context = ir_headers.ip_identification;

    let headers = create_rtp_headers(71, 7500, false, ssrc).with_ip_id(ip_id_from_ir_context);
    let generic = GenericUncompressedHeaders::RtpUdpIpv4(headers.clone());
    let compressed = engine
        .compress(cid, Some(RohcProfile::RtpUdpIp), &generic)
        .unwrap();

    assert_eq!(compressed.len(), 5);
    assert_eq!(
        compressed[0],
        ROHC_ADD_CID_FEEDBACK_PREFIX_VALUE | (cid as u8)
    );
    assert_eq!(compressed[1], P1_UO_1_TS_DISCRIMINATOR);

    let decompressed = engine
        .decompress(&compressed)
        .unwrap()
        .as_rtp_udp_ipv4()
        .unwrap()
        .clone();
    assert_eq!(decompressed.rtp_sequence_number, 71);
    assert_eq!(decompressed.rtp_timestamp, Timestamp::new(7500));
    assert!(!decompressed.rtp_marker);
}
