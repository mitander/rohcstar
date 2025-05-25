//! Integration tests for ROHC Profile 1 UO-1-TS packet handling.
//!
//! This module focuses on testing the UO-1-TS packet format, which is used
//! when the RTP Timestamp changes, the RTP Sequence Number increments by one,
//! and the RTP Marker bit remains unchanged from the context.

mod common;
use common::{create_rtp_headers, establish_ir_context, get_decompressor_context};

use rohcstar::constants::ROHC_ADD_CID_FEEDBACK_PREFIX_VALUE;
use rohcstar::engine::RohcEngine;
use rohcstar::packet_defs::{GenericUncompressedHeaders, RohcProfile};
use rohcstar::profiles::profile1::{
    P1_UO_1_SN_PACKET_TYPE_PREFIX, P1_UO_1_TS_DISCRIMINATOR, Profile1Handler,
};

#[test]
fn p1_uo1_ts_basic_timestamp_change_sn_updates() {
    let mut engine = RohcEngine::new(100);
    engine
        .register_profile_handler(Box::new(Profile1Handler::new()))
        .unwrap();
    let cid = 0u16;
    let ssrc = 0x12345678;

    // Establish context: SN=100, TS=1000, M=false
    establish_ir_context(&mut engine, cid, 100, 1000, false, ssrc);

    // Packet with TS change (TS=2000), SN increments (SN=101), marker same (false)
    // This combination should select UO-1-TS.
    let headers = create_rtp_headers(101, 2000, false, ssrc);
    let generic = GenericUncompressedHeaders::RtpUdpIpv4(headers.clone());
    let compressed = engine
        .compress(cid, Some(RohcProfile::RtpUdpIp), &generic)
        .unwrap();

    // UO-1-TS for CID 0 is 4 bytes.
    assert_eq!(
        compressed.len(),
        4,
        "UO-1-TS packet length check. Expected 4, Got: {:?}",
        compressed
    );
    assert_eq!(
        compressed[0], P1_UO_1_TS_DISCRIMINATOR,
        "UO-1-TS discriminator check"
    );

    // Decompress and verify
    let decompressed = engine
        .decompress(&compressed)
        .unwrap()
        .as_rtp_udp_ipv4()
        .unwrap()
        .clone();
    assert_eq!(decompressed.rtp_sequence_number, 101, "SN after UO-1-TS");
    assert_eq!(decompressed.rtp_timestamp, 2000, "TS after UO-1-TS");
    assert!(!decompressed.rtp_marker, "Marker after UO-1-TS");

    // Verify decompressor context update
    let decomp_ctx = get_decompressor_context(&engine, cid);
    assert_eq!(
        decomp_ctx.last_reconstructed_rtp_sn_full, 101,
        "Decomp context SN"
    );
    assert_eq!(
        decomp_ctx.last_reconstructed_rtp_ts_full, 2000,
        "Decomp context TS"
    );
    assert!(
        !decomp_ctx.last_reconstructed_rtp_marker,
        "Decomp context Marker"
    );
}

#[test]
fn p1_uo1_ts_large_timestamp_jump_sn_updates() {
    let mut engine = RohcEngine::new(100);
    engine
        .register_profile_handler(Box::new(Profile1Handler::new()))
        .unwrap();
    let cid = 0u16;
    let ssrc = 0xAABBCCDD;

    // Establish context: SN=200, TS=10000, M=false
    establish_ir_context(&mut engine, cid, 200, 10000, false, ssrc);

    // Large TS jump, SN increments, marker same. Should be UO-1-TS.
    let headers = create_rtp_headers(201, 50000, false, ssrc);
    let generic = GenericUncompressedHeaders::RtpUdpIpv4(headers.clone());
    let compressed = engine
        .compress(cid, Some(RohcProfile::RtpUdpIp), &generic)
        .unwrap();

    assert_eq!(
        compressed.len(),
        4,
        "UO-1-TS for large TS jump. Expected 4, Got: {:?}",
        compressed
    );
    assert_eq!(
        compressed[0], P1_UO_1_TS_DISCRIMINATOR,
        "UO-1-TS discriminator check"
    );

    let decompressed = engine
        .decompress(&compressed)
        .unwrap()
        .as_rtp_udp_ipv4()
        .unwrap()
        .clone();
    assert_eq!(
        decompressed.rtp_sequence_number, 201,
        "SN after large TS jump"
    );
    assert_eq!(decompressed.rtp_timestamp, 50000, "TS after large TS jump");

    let decomp_ctx = get_decompressor_context(&engine, cid);
    assert_eq!(
        decomp_ctx.last_reconstructed_rtp_sn_full, 201,
        "Decomp context SN after large TS jump"
    );
}

#[test]
fn p1_uo1_ts_vs_uo1_sn_selection_priority() {
    let mut engine = RohcEngine::new(100);
    engine
        .register_profile_handler(Box::new(Profile1Handler::new()))
        .unwrap();
    let cid = 0u16;
    let ssrc = 0x11223344;

    // Establish context: SN=300, TS=3000, M=false
    establish_ir_context(&mut engine, cid, 300, 3000, false, ssrc);

    // Case 1: TS change, SN+1, Marker same -> UO-1-TS
    // Uncompressed: SN=301, TS=4000, M=false
    let headers1 = create_rtp_headers(301, 4000, false, ssrc);
    let compressed1 = engine
        .compress(
            cid,
            Some(RohcProfile::RtpUdpIp),
            &GenericUncompressedHeaders::RtpUdpIpv4(headers1.clone()),
        )
        .unwrap();
    assert_eq!(
        compressed1.len(),
        4,
        "C1: UO-1-TS length. Got: {:?}",
        compressed1
    );
    assert_eq!(compressed1[0], P1_UO_1_TS_DISCRIMINATOR, "C1: UO-1-TS type");
    let decomp1_result = engine.decompress(&compressed1);
    assert!(
        decomp1_result.is_ok(),
        "C1: Decompression failed: {:?}",
        decomp1_result.err()
    );
    let decomp1 = decomp1_result.unwrap().as_rtp_udp_ipv4().unwrap().clone();
    assert_eq!(decomp1.rtp_sequence_number, 301);
    assert_eq!(decomp1.rtp_timestamp, 4000);
    // Compressor context after P1: SN=301, TS=4000, M=false
    // Decompressor context after P1: SN=301, TS=4000, M=false

    // Case 2: Marker change, SN+1 (from 301), TS same (as 4000 from context after P1) -> UO-1-SN
    // Uncompressed: SN=302, TS=4000, M=true
    let headers2 = create_rtp_headers(302, 4000, true, ssrc);
    let compressed2 = engine
        .compress(
            cid,
            Some(RohcProfile::RtpUdpIp),
            &GenericUncompressedHeaders::RtpUdpIpv4(headers2.clone()),
        )
        .unwrap();
    assert_eq!(
        compressed2.len(),
        3,
        "C2: UO-1-SN length. Got: {:?}",
        compressed2
    );
    assert_eq!(
        compressed2[0] & P1_UO_1_SN_PACKET_TYPE_PREFIX,
        P1_UO_1_SN_PACKET_TYPE_PREFIX,
        "C2: UO-1-SN prefix"
    );
    assert_ne!(
        compressed2[0], P1_UO_1_TS_DISCRIMINATOR,
        "C2: Should not be UO-1-TS"
    );
    let decomp2_result = engine.decompress(&compressed2);
    assert!(
        decomp2_result.is_ok(),
        "C2: Decompression failed: {:?}",
        decomp2_result.err()
    );
    let decomp2 = decomp2_result.unwrap().as_rtp_udp_ipv4().unwrap().clone();
    assert_eq!(decomp2.rtp_sequence_number, 302);
    assert!(decomp2.rtp_marker);
    assert_eq!(decomp2.rtp_timestamp, 4000); // TS from context (established by P1 UO-1-TS)
    // Compressor context after P2: SN=302, TS=4000, M=true
    // Decompressor context after P2: SN=302, TS=4000, M=true

    // Case 3: Both TS and marker change, SN+1 (from 302) -> UO-1-SN (marker change takes precedence)
    // Uncompressed: SN=303, TS=4000 (to keep TS context for CRC aligned for this UO-1-SN), M=false
    let headers3 = create_rtp_headers(303, 4000, false, ssrc);
    let compressed3 = engine
        .compress(
            cid,
            Some(RohcProfile::RtpUdpIp),
            &GenericUncompressedHeaders::RtpUdpIpv4(headers3.clone()),
        )
        .unwrap();
    assert_eq!(
        compressed3.len(),
        3,
        "C3: UO-1-SN length. Got: {:?}",
        compressed3
    );
    assert_eq!(
        compressed3[0] & P1_UO_1_SN_PACKET_TYPE_PREFIX,
        P1_UO_1_SN_PACKET_TYPE_PREFIX,
        "C3: UO-1-SN prefix"
    );
    assert_ne!(
        compressed3[0], P1_UO_1_TS_DISCRIMINATOR,
        "C3: Should not be UO-1-TS"
    );
    let decomp3_result = engine.decompress(&compressed3);
    assert!(
        decomp3_result.is_ok(),
        "C3: Decompression failed: {:?}",
        decomp3_result.err()
    );
    let decomp3 = decomp3_result.unwrap().as_rtp_udp_ipv4().unwrap().clone();
    assert_eq!(decomp3.rtp_sequence_number, 303);
    assert_eq!(decomp3.rtp_timestamp, 4000); // TS from context
    assert!(!decomp3.rtp_marker);
    // Compressor context after P3: SN=303, TS=4000, M=false
    // Decompressor context after P3: SN=303, TS=4000, M=false

    // Case 4: TS change (in uncompressed header), Marker same, SN not +1 (e.g. +2) -> UO-1-SN
    // Uncompressed: SN=305, TS=6000 (TS changes from 4000), M=false
    // Compressor context before P4: last_sn=303, last_ts=4000, last_marker=false
    // Decompressor context before P4: last_sn=303, last_ts=4000, last_marker=false
    let headers4 = create_rtp_headers(305, 6000, false, ssrc);
    let compressed4 = engine
        .compress(
            cid,
            Some(RohcProfile::RtpUdpIp),
            &GenericUncompressedHeaders::RtpUdpIpv4(headers4.clone()),
        )
        .unwrap();
    // Packet selection for P4:
    // M_unchanged=true. sn_diff=2 (encodable_for_uo0=true). ts_changed=true (6000!=4000). sn_incr_by_1=false.
    // UO-0: false because ts_changed.
    // UO-1-TS: false because sn_incr_by_1=false.
    // Fallback: UO-1-SN.
    assert_eq!(
        compressed4.len(),
        3,
        "C4: UO-1-SN length for SN jump. Got: {:?}",
        compressed4
    );
    assert_eq!(
        compressed4[0] & P1_UO_1_SN_PACKET_TYPE_PREFIX,
        P1_UO_1_SN_PACKET_TYPE_PREFIX,
        "C4: UO-1-SN prefix"
    );
    assert_ne!(
        compressed4[0], P1_UO_1_TS_DISCRIMINATOR,
        "C4: Should not be UO-1-TS"
    );
    // For CRC of P4 (UO-1-SN):
    // Compressor uses its context last_ts = 4000. Updates its last_ts to 6000 after.
    // Decompressor uses its context last_ts = 4000.
    // CRCs should match.
    let decomp4_result = engine.decompress(&compressed4);
    assert!(
        decomp4_result.is_ok(),
        "C4: Decompression failed: {:?}",
        decomp4_result.err()
    );
    let decomp4 = decomp4_result.unwrap().as_rtp_udp_ipv4().unwrap().clone();
    assert_eq!(decomp4.rtp_sequence_number, 305);
    assert_eq!(decomp4.rtp_timestamp, 4000); // TS from decompressor's context, as UO-1-SN does not carry TS
}

#[test]
fn p1_uo1_ts_marker_from_context_for_crc() {
    let mut engine = RohcEngine::new(100);
    engine
        .register_profile_handler(Box::new(Profile1Handler::new()))
        .unwrap();
    let cid = 0u16;
    let ssrc = 0xBADF00D;

    // Establish context with Marker = true, SN=50, TS=500
    establish_ir_context(&mut engine, cid, 50, 500, true, ssrc);

    // Packet with TS change, SN increments. Uncompressed marker is true (same as context).
    // UO-1-TS should be sent. UO-1-TS packet type field implies M=0,
    // but CRC calculation must use M=true from the context.
    let headers = create_rtp_headers(51, 600, true, ssrc);
    let generic = GenericUncompressedHeaders::RtpUdpIpv4(headers.clone());
    let compressed = engine
        .compress(cid, Some(RohcProfile::RtpUdpIp), &generic)
        .unwrap();

    assert_eq!(
        compressed.len(),
        4,
        "UO-1-TS length with context M=true. Got: {:?}",
        compressed
    );
    assert_eq!(
        compressed[0], P1_UO_1_TS_DISCRIMINATOR,
        "UO-1-TS type discriminator (M=0 in type field)"
    );

    let decompressed = engine
        .decompress(&compressed)
        .unwrap()
        .as_rtp_udp_ipv4()
        .unwrap()
        .clone();
    assert_eq!(decompressed.rtp_sequence_number, 51, "Reconstructed SN");
    assert_eq!(decompressed.rtp_timestamp, 600, "Reconstructed TS");
    assert!(decompressed.rtp_marker, "Reconstructed marker from context");

    let decomp_ctx = get_decompressor_context(&engine, cid);
    assert!(decomp_ctx.last_reconstructed_rtp_marker, "Decomp context M");
    assert_eq!(
        decomp_ctx.last_reconstructed_rtp_ts_full, 600,
        "Decomp context TS"
    );
    assert_eq!(
        decomp_ctx.last_reconstructed_rtp_sn_full, 51,
        "Decomp context SN"
    );
}

#[test]
fn p1_uo1_ts_with_add_cid() {
    let mut engine = RohcEngine::new(100);
    engine
        .register_profile_handler(Box::new(Profile1Handler::new()))
        .unwrap();
    let cid = 3u16; // Small CID
    let ssrc = 0xFEEDF00D;

    // Establish context: SN=70, TS=7000, M=false
    establish_ir_context(&mut engine, cid, 70, 7000, false, ssrc);

    // Packet conditions for UO-1-TS: TS changes, SN+1, M same as context.
    let headers = create_rtp_headers(71, 7500, false, ssrc);
    let generic = GenericUncompressedHeaders::RtpUdpIpv4(headers.clone());
    let compressed = engine
        .compress(cid, Some(RohcProfile::RtpUdpIp), &generic)
        .unwrap();

    assert_eq!(
        compressed.len(),
        5,
        "UO-1-TS with Add-CID length check. Got: {:?}",
        compressed
    ); // Add-CID (1) + UO-1-TS (4)
    assert_eq!(
        compressed[0],
        ROHC_ADD_CID_FEEDBACK_PREFIX_VALUE | (cid as u8),
        "Add-CID octet check"
    );
    assert_eq!(
        compressed[1], P1_UO_1_TS_DISCRIMINATOR,
        "Core UO-1-TS discriminator check"
    );

    let decompressed = engine
        .decompress(&compressed)
        .unwrap()
        .as_rtp_udp_ipv4()
        .unwrap()
        .clone();
    assert_eq!(
        decompressed.rtp_sequence_number, 71,
        "Reconstructed SN with Add-CID"
    );
    assert_eq!(
        decompressed.rtp_timestamp, 7500,
        "Reconstructed TS with Add-CID"
    );
    assert!(
        !decompressed.rtp_marker,
        "Reconstructed Marker with Add-CID"
    );
}
