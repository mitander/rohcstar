//! Integration tests for ROHC Profile 1 UO-1-SN packet handling.
//!
//! This module tests the UO-1-SN packet format, which provides extended sequence
//! number encoding and marker bit transmission. Tests cover sequence number jumps,
//! marker bit changes, wraparound scenarios, and packet type selection logic.

mod common;
use common::{create_rtp_headers, establish_ir_context, get_decompressor_context};

use rohcstar::engine::RohcEngine;
use rohcstar::error::RohcError;
use rohcstar::error::RohcParsingError;
use rohcstar::packet_defs::{GenericUncompressedHeaders, RohcProfile};
use rohcstar::profiles::profile1::{
    P1_UO_1_SN_MARKER_BIT_MASK, P1_UO_1_SN_PACKET_TYPE_PREFIX, Profile1Handler,
};

#[test]
fn p1_uo1_sn_with_sn_wraparound() {
    let mut engine = RohcEngine::new(200);
    engine
        .register_profile_handler(Box::new(Profile1Handler::new()))
        .unwrap();
    let cid = 0u16;
    let ssrc = 0xABCDEF01;

    let ir_sn = 65530;
    let ir_ts = 1000; // This timestamp will be the context for subsequent UO-1-SNs
    let ir_marker = false;
    establish_ir_context(&mut engine, cid, ir_sn, ir_ts, ir_marker, ssrc);

    let sn1 = 65532;
    let marker1 = true;
    // For UO-1-SN, the uncompressed header's TS should align with the context TS for consistent CRC.
    let headers1 = create_rtp_headers(sn1, ir_ts, marker1, ssrc); // Use ir_ts
    let generic1 = GenericUncompressedHeaders::RtpUdpIpv4(headers1.clone());
    let compressed1 = engine
        .compress(cid, Some(RohcProfile::RtpUdpIp), &generic1)
        .unwrap();
    assert_eq!(
        compressed1.len(),
        3,
        "SN 65532, M=true should be UO-1. Got: {:?}",
        compressed1
    );
    assert_eq!(
        compressed1[0] & P1_UO_1_SN_PACKET_TYPE_PREFIX,
        P1_UO_1_SN_PACKET_TYPE_PREFIX
    );
    assert_ne!(compressed1[0] & P1_UO_1_SN_MARKER_BIT_MASK, 0);

    let decomp1 = engine
        .decompress(&compressed1)
        .unwrap()
        .as_rtp_udp_ipv4()
        .unwrap()
        .clone();
    assert_eq!(decomp1.rtp_sequence_number, sn1);
    assert_eq!(decomp1.rtp_marker, marker1);
    assert_eq!(decomp1.rtp_timestamp, ir_ts); // TS from context

    let sn2 = 2; // SN wraps around
    let marker2 = false;
    // Maintain consistent TS for UO-1-SN CRC context.
    // Compressor's context last_sent_ts will be ir_ts from processing headers1.
    // Decompressor's context last_reconstructed_ts is ir_ts.
    let headers2 = create_rtp_headers(sn2, ir_ts, marker2, ssrc); // Use ir_ts
    let generic2 = GenericUncompressedHeaders::RtpUdpIpv4(headers2.clone());
    let compressed2 = engine
        .compress(cid, Some(RohcProfile::RtpUdpIp), &generic2)
        .unwrap();
    assert_eq!(
        compressed2.len(),
        3,
        "SN 2 (wrap), M=false should be UO-1. Got: {:?}",
        compressed2
    );
    assert_eq!(
        compressed2[0] & P1_UO_1_SN_PACKET_TYPE_PREFIX,
        P1_UO_1_SN_PACKET_TYPE_PREFIX
    );
    assert_eq!(compressed2[0] & P1_UO_1_SN_MARKER_BIT_MASK, 0);

    let decomp2 = engine
        .decompress(&compressed2)
        .unwrap()
        .as_rtp_udp_ipv4()
        .unwrap()
        .clone();
    assert_eq!(decomp2.rtp_sequence_number, sn2);
    assert_eq!(decomp2.rtp_marker, marker2);
    assert_eq!(decomp2.rtp_timestamp, ir_ts); // TS from context
}

#[test]
fn p1_rapid_marker_toggling_forces_uo1() {
    let mut engine = RohcEngine::new(200);
    engine
        .register_profile_handler(Box::new(Profile1Handler::new()))
        .unwrap();
    let cid = 0u16;
    let ssrc = 0x1234FEDC;

    let initial_sn = 100;
    let initial_ts = 5000; // This TS will be the stable context for UO-1-SN packets in the loop
    let mut current_marker = false;

    establish_ir_context(
        &mut engine,
        cid,
        initial_sn,
        initial_ts,
        current_marker,
        ssrc,
    );

    for i in 1..=5 {
        let current_sn = initial_sn + i;
        current_marker = !current_marker; // Marker toggles, this is the primary driver for UO-1-SN

        // For UO-1-SN packets, the timestamp used in uncompressed headers should be
        // consistent with the established context if we expect CRC to match,
        // as UO-1-SN itself doesn't update the decompressor's TS context from the packet.
        let headers = create_rtp_headers(
            current_sn,
            initial_ts, // Use the established initial_ts for these UO-1-SNs
            current_marker,
            ssrc,
        );
        let generic = GenericUncompressedHeaders::RtpUdpIpv4(headers.clone());
        let compressed = engine
            .compress(cid, Some(RohcProfile::RtpUdpIp), &generic)
            .unwrap();

        assert_eq!(
            compressed.len(),
            3,
            "Packet {} with toggled marker should be UO-1. Got: {:?}",
            i,
            compressed
        );
        assert_eq!(
            compressed[0] & P1_UO_1_SN_PACKET_TYPE_PREFIX,
            P1_UO_1_SN_PACKET_TYPE_PREFIX
        );
        if current_marker {
            assert_ne!(compressed[0] & P1_UO_1_SN_MARKER_BIT_MASK, 0);
        } else {
            assert_eq!(compressed[0] & P1_UO_1_SN_MARKER_BIT_MASK, 0);
        }

        let decomp = engine
            .decompress(&compressed)
            .unwrap()
            .as_rtp_udp_ipv4()
            .unwrap()
            .clone();
        assert_eq!(decomp.rtp_sequence_number, current_sn);
        assert_eq!(decomp.rtp_marker, current_marker);
        assert_eq!(decomp.rtp_timestamp, initial_ts); // TS from context

        let decomp_ctx = get_decompressor_context(&engine, cid);
        assert_eq!(decomp_ctx.last_reconstructed_rtp_marker, current_marker);
        assert_eq!(decomp_ctx.last_reconstructed_rtp_ts_full, initial_ts);
    }
}

#[test]
fn p1_uo1_sn_max_sn_jump_encodable() {
    let mut engine = RohcEngine::new(500);
    engine
        .register_profile_handler(Box::new(Profile1Handler::new()))
        .unwrap();
    let cid = 0u16;
    let ssrc = 0x778899AA;

    let initial_sn = 1000;
    let initial_ts = 10000; // Context TS for UO-1-SN CRCs
    let initial_marker = false;
    establish_ir_context(
        &mut engine,
        cid,
        initial_sn,
        initial_ts,
        initial_marker,
        ssrc,
    );

    let sn_jump_pos = initial_sn + 100; // SN diff = 100
    // Uncompressed TS is initial_ts + 100. Marker same.
    // This will be UO-1-SN as SN_diff > 16 and TS change without SN_diff=1.
    let headers_jump_pos = create_rtp_headers(sn_jump_pos, initial_ts + 100, initial_marker, ssrc);
    let generic_jump_pos = GenericUncompressedHeaders::RtpUdpIpv4(headers_jump_pos.clone());
    let compressed_jump_pos = engine
        .compress(cid, Some(RohcProfile::RtpUdpIp), &generic_jump_pos)
        .unwrap();
    assert_eq!(
        compressed_jump_pos.len(),
        3,
        "SN jump +100 should be UO-1. Got: {:?}",
        compressed_jump_pos
    );
    let decomp_jump_pos_result = engine.decompress(&compressed_jump_pos);
    assert!(
        decomp_jump_pos_result.is_ok(),
        "Decompression of positive jump failed: {:?}",
        decomp_jump_pos_result.err()
    );
    let decomp_jump_pos = decomp_jump_pos_result
        .unwrap()
        .as_rtp_udp_ipv4()
        .unwrap()
        .clone();
    assert_eq!(decomp_jump_pos.rtp_sequence_number, sn_jump_pos);
    assert_eq!(decomp_jump_pos.rtp_timestamp, initial_ts); // TS from context

    // Compressor context after previous packet: SN=1100, TS=10100 (from uncompressed headers_jump_pos)
    // Next packet SN is 1000 (original initial_sn). SN diff is 1000 - 1100 = -100 (or large positive after wrap)
    // Uncompressed TS is initial_ts + 200 = 10200.
    // This will be UO-1-SN. Compressor uses its TS context (10100) for CRC.
    let sn_jump_neg = initial_sn; // This is 1000. Last sent was 1100.
    let headers_jump_neg = create_rtp_headers(sn_jump_neg, initial_ts + 200, initial_marker, ssrc);
    let generic_jump_neg = GenericUncompressedHeaders::RtpUdpIpv4(headers_jump_neg.clone());
    let compressed_jump_neg = engine
        .compress(cid, Some(RohcProfile::RtpUdpIp), &generic_jump_neg)
        .unwrap();
    // Decompressor's context SN=1100, TS=10000.
    // The W-LSB for SN with p=0 might struggle with such a large negative jump without more bits or IR.
    // CRC is calculated by decompressor using its context TS = 10000.
    // Compressor used its context TS = 10100 for CRC. This *will* lead to a CRC mismatch.
    assert_eq!(
        compressed_jump_neg.len(),
        3,
        "SN jump -100 (wrap) should still be UO-1 based on SN diff. Got: {:?}",
        compressed_jump_neg
    );

    let decompress_result_neg_jump = engine.decompress(&compressed_jump_neg);
    match decompress_result_neg_jump {
        Err(RohcError::Parsing(RohcParsingError::CrcMismatch { .. })) => { /* Expected due to TS context divergence for CRC */
        }
        Ok(h) => panic!(
            "Expected CrcMismatch for large negative SN jump with diverging TS context for CRC, but got Ok({:?})",
            h
        ),
        Err(e) => panic!(
            "Expected CrcMismatch, but got other error: {:?}. Decomp CTX TS was 10000, Comp CTX TS for CRC was 10100.",
            e
        ),
    }
}

#[test]
fn p1_uo1_sn_prefered_over_uo0_for_larger_sn_diff() {
    let mut engine = RohcEngine::new(100);
    engine
        .register_profile_handler(Box::new(Profile1Handler::new()))
        .unwrap();
    let cid = 0u16;
    let ssrc = 0xBBCCDDFF;

    let initial_sn = 500;
    let initial_ts = 6000; // Base TS for context
    let initial_marker = false;
    establish_ir_context(
        &mut engine,
        cid,
        initial_sn,
        initial_ts,
        initial_marker,
        ssrc,
    );

    let sn_uo0_max = initial_sn + 15; // 515
    // To be UO-0, TS must match context (initial_ts)
    let headers_uo0 = create_rtp_headers(sn_uo0_max, initial_ts, initial_marker, ssrc);
    let compressed_uo0 = engine
        .compress(
            cid,
            Some(RohcProfile::RtpUdpIp),
            &GenericUncompressedHeaders::RtpUdpIpv4(headers_uo0),
        )
        .unwrap();
    assert_eq!(
        compressed_uo0.len(),
        1,
        "SN diff 15 should be UO-0. Got: {:?}",
        compressed_uo0
    );
    let _ = engine.decompress(&compressed_uo0).unwrap();

    // Compressor context now: SN=515, TS=initial_ts (6000)
    // Packet: SN=515+16=531. SN diff is 16. Uncompressed TS is initial_ts + 20 = 6020.
    // This will be UO-1-SN as SN diff >= 16. TS change also means not UO-0. SN diff != 1 means not UO-1-TS.
    let sn_force_uo1 = initial_sn + 15 + 16;
    let headers_uo1 = create_rtp_headers(sn_force_uo1, initial_ts + 20, initial_marker, ssrc);
    let compressed_uo1 = engine
        .compress(
            cid,
            Some(RohcProfile::RtpUdpIp),
            &GenericUncompressedHeaders::RtpUdpIpv4(headers_uo1),
        )
        .unwrap();
    assert_eq!(
        compressed_uo1.len(),
        3,
        "SN diff 16 (from 515) should be UO-1. Got: {:?}",
        compressed_uo1
    );
    assert_eq!(
        compressed_uo1[0] & P1_UO_1_SN_PACKET_TYPE_PREFIX,
        P1_UO_1_SN_PACKET_TYPE_PREFIX
    );

    let decomp_uo1 = engine
        .decompress(&compressed_uo1)
        .unwrap()
        .as_rtp_udp_ipv4()
        .unwrap()
        .clone();
    assert_eq!(decomp_uo1.rtp_sequence_number, sn_force_uo1);
    assert_eq!(decomp_uo1.rtp_timestamp, initial_ts); // TS from context
}
