//! Integration tests for ROHC Profile 1 UO-0 packet handling.
//!
//! This module focuses on the smallest compressed packet format (UO-0), testing
//! sequence number encoding/decoding, CRC validation, context state transitions,
//! and edge cases around the limited encoding space of UO-0 packets.

mod common;
use common::{create_rtp_headers, establish_ir_context, get_decompressor_context};

use rohcstar::engine::RohcEngine;
use rohcstar::error::{RohcError, RohcParsingError};
use rohcstar::packet_defs::{GenericUncompressedHeaders, RohcProfile};
use rohcstar::profiles::profile1::context::Profile1DecompressorMode;
use rohcstar::profiles::profile1::{
    P1_DECOMPRESSOR_FC_TO_SC_CRC_FAILURE_THRESHOLD, P1_UO_1_SN_PACKET_TYPE_PREFIX, Profile1Handler,
};

// --- Phase 2: UO-0 Packet Implementation Edge Case Tests ---

#[test]
fn p1_uo0_sn_wraparound_65535_to_0() {
    let mut engine = RohcEngine::new(100); // High refresh interval
    engine
        .register_profile_handler(Box::new(Profile1Handler::new()))
        .unwrap();
    let cid = 0u16;
    let ssrc = 0xABC123;

    let initial_sn = 65534;
    let initial_ts = 1000;
    let initial_marker = false;
    establish_ir_context(
        &mut engine,
        cid,
        initial_sn,
        initial_ts,
        initial_marker,
        ssrc,
    );

    // Packet: SN = 65535 (should be UO-0)
    let headers_65535 = create_rtp_headers(65535, initial_ts + 10, initial_marker, ssrc);
    let generic_65535 = GenericUncompressedHeaders::RtpUdpIpv4(headers_65535.clone());
    let compressed_65535 = engine
        .compress(cid, Some(RohcProfile::RtpUdpIp), &generic_65535)
        .unwrap();
    assert_eq!(compressed_65535.len(), 1, "SN 65535 should be UO-0");
    let decomp_65535 = engine
        .decompress(&compressed_65535)
        .unwrap()
        .as_rtp_udp_ipv4()
        .unwrap()
        .clone();
    assert_eq!(decomp_65535.rtp_sequence_number, 65535);

    // Packet: SN = 0 (wraparound, should be UO-0)
    let headers_0 = create_rtp_headers(0, initial_ts + 20, initial_marker, ssrc);
    let generic_0 = GenericUncompressedHeaders::RtpUdpIpv4(headers_0.clone());
    let compressed_0 = engine
        .compress(cid, Some(RohcProfile::RtpUdpIp), &generic_0)
        .unwrap();
    assert_eq!(compressed_0.len(), 1, "SN 0 (after 65535) should be UO-0");
    let decomp_0 = engine
        .decompress(&compressed_0)
        .unwrap()
        .as_rtp_udp_ipv4()
        .unwrap()
        .clone();
    assert_eq!(decomp_0.rtp_sequence_number, 0);

    // Packet: SN = 1 (should be UO-0)
    let headers_1 = create_rtp_headers(1, initial_ts + 30, initial_marker, ssrc);
    let generic_1 = GenericUncompressedHeaders::RtpUdpIpv4(headers_1.clone());
    let compressed_1 = engine
        .compress(cid, Some(RohcProfile::RtpUdpIp), &generic_1)
        .unwrap();
    assert_eq!(compressed_1.len(), 1, "SN 1 (after 0) should be UO-0");
    let decomp_1 = engine
        .decompress(&compressed_1)
        .unwrap()
        .as_rtp_udp_ipv4()
        .unwrap()
        .clone();
    assert_eq!(decomp_1.rtp_sequence_number, 1);
}

#[test]
fn p1_uo0_sn_at_lsb_window_edge() {
    let mut engine = RohcEngine::new(100);
    engine
        .register_profile_handler(Box::new(Profile1Handler::new()))
        .unwrap();
    let cid = 0u16;
    let ssrc = 0xDEF456;

    let initial_sn_ir = 100;
    let initial_ts = 2000;
    let initial_marker = false;
    establish_ir_context(
        &mut engine,
        cid,
        initial_sn_ir,
        initial_ts,
        initial_marker,
        ssrc,
    );

    let sn_at_edge = initial_sn_ir + 15; // 115
    let headers_at_edge = create_rtp_headers(sn_at_edge, initial_ts + 10, initial_marker, ssrc);
    let generic_at_edge = GenericUncompressedHeaders::RtpUdpIpv4(headers_at_edge.clone());
    let compressed_at_edge = engine
        .compress(cid, Some(RohcProfile::RtpUdpIp), &generic_at_edge)
        .unwrap();
    assert_eq!(
        compressed_at_edge.len(),
        1,
        "SN 115 (from 100) should be UO-0"
    );
    let decomp_at_edge = engine
        .decompress(&compressed_at_edge)
        .unwrap()
        .as_rtp_udp_ipv4()
        .unwrap()
        .clone();
    assert_eq!(decomp_at_edge.rtp_sequence_number, sn_at_edge);

    let sn_next_to_edge = sn_at_edge + 1; // 116
    let headers_next_to_edge =
        create_rtp_headers(sn_next_to_edge, initial_ts + 20, initial_marker, ssrc);
    let generic_next_to_edge = GenericUncompressedHeaders::RtpUdpIpv4(headers_next_to_edge.clone());
    let compressed_next_to_edge = engine
        .compress(cid, Some(RohcProfile::RtpUdpIp), &generic_next_to_edge)
        .unwrap();
    assert_eq!(
        compressed_next_to_edge.len(),
        1,
        "SN 116 (from 115) should be UO-0"
    );
    let decomp_next_to_edge = engine
        .decompress(&compressed_next_to_edge)
        .unwrap()
        .as_rtp_udp_ipv4()
        .unwrap()
        .clone();
    assert_eq!(decomp_next_to_edge.rtp_sequence_number, sn_next_to_edge);

    establish_ir_context(
        &mut engine,
        cid,
        115,             // Re-establish context with SN 115
        initial_ts + 20, // New TS for this IR
        initial_marker,
        ssrc, // Use same SSRC for same CID flow
    );

    let sn_outside_window = 115 + 16; // 131
    let headers_outside_window =
        create_rtp_headers(sn_outside_window, initial_ts + 30, initial_marker, ssrc);
    let generic_outside_window =
        GenericUncompressedHeaders::RtpUdpIpv4(headers_outside_window.clone());
    let compressed_outside_window = engine
        .compress(cid, Some(RohcProfile::RtpUdpIp), &generic_outside_window)
        .unwrap();
    assert_eq!(
        compressed_outside_window.len(),
        3,
        "SN 131 (from 115) should be UO-1 as diff is 16"
    );
    let decomp_outside_window = engine
        .decompress(&compressed_outside_window)
        .unwrap()
        .as_rtp_udp_ipv4()
        .unwrap()
        .clone();
    assert_eq!(decomp_outside_window.rtp_sequence_number, sn_outside_window);
}

#[test]
fn p1_uo0_crc_failures_trigger_context_downgrade() {
    let mut engine = RohcEngine::new(100);
    engine
        .register_profile_handler(Box::new(Profile1Handler::new()))
        .unwrap();
    let cid = 0u16;
    let ssrc = 0xFAFBFCD;

    establish_ir_context(&mut engine, cid, 200, 3000, false, ssrc);

    for i in 1..=P1_DECOMPRESSOR_FC_TO_SC_CRC_FAILURE_THRESHOLD {
        let headers_good_uo0 =
            create_rtp_headers(200 + i as u16, 3000 + (i as u32 * 10), false, ssrc);
        let generic_good_uo0 = GenericUncompressedHeaders::RtpUdpIpv4(headers_good_uo0);

        let mut compressed_uo0 = engine
            .compress(cid, Some(RohcProfile::RtpUdpIp), &generic_good_uo0)
            .unwrap();
        assert_eq!(compressed_uo0.len(), 1, "Should be a UO-0 packet");

        compressed_uo0[0] = compressed_uo0[0].wrapping_add(1);
        if compressed_uo0[0] & 0x80 != 0 {
            compressed_uo0[0] &= 0x7F;
        }

        let result = engine.decompress(&compressed_uo0);
        assert!(
            matches!(
                result,
                Err(RohcError::Parsing(RohcParsingError::CrcMismatch { .. }))
            ),
            "Attempt {} should result in CRC mismatch",
            i
        );

        let decomp_ctx = get_decompressor_context(&engine, cid);

        if i < P1_DECOMPRESSOR_FC_TO_SC_CRC_FAILURE_THRESHOLD {
            assert_eq!(
                decomp_ctx.mode,
                Profile1DecompressorMode::FullContext,
                "Mode should be FC before threshold"
            );
            assert_eq!(decomp_ctx.consecutive_crc_failures_in_fc, i);
        } else {
            assert_eq!(
                decomp_ctx.mode,
                Profile1DecompressorMode::StaticContext,
                "Mode should downgrade to SC after threshold"
            );
        }
    }
}

#[test]
fn p1_uo0_not_used_when_marker_changes() {
    let mut engine = RohcEngine::new(100);
    engine
        .register_profile_handler(Box::new(Profile1Handler::new()))
        .unwrap();
    let cid = 0u16;
    let ssrc = 0x1A2B3C;

    establish_ir_context(&mut engine, cid, 300, 4000, false, ssrc);

    let headers_marker_change = create_rtp_headers(301, 4010, true, ssrc);
    let generic_marker_change =
        GenericUncompressedHeaders::RtpUdpIpv4(headers_marker_change.clone());

    let compressed_packet = engine
        .compress(cid, Some(RohcProfile::RtpUdpIp), &generic_marker_change)
        .unwrap();

    assert_eq!(
        compressed_packet.len(),
        3,
        "Packet should be UO-1 due to marker change, not UO-0"
    );
    assert_eq!(
        compressed_packet[0] & P1_UO_1_SN_PACKET_TYPE_PREFIX,
        P1_UO_1_SN_PACKET_TYPE_PREFIX,
        "Should be UO-1 type"
    );

    let decomp_headers = engine
        .decompress(&compressed_packet)
        .unwrap()
        .as_rtp_udp_ipv4()
        .unwrap()
        .clone();
    assert_eq!(decomp_headers.rtp_sequence_number, 301);
    assert!(decomp_headers.rtp_marker);
}

#[test]
fn p1_uo0_is_used_despite_ts_change_if_marker_sn_ok() {
    let mut engine = RohcEngine::new(100);
    engine
        .register_profile_handler(Box::new(Profile1Handler::new()))
        .unwrap();
    let cid = 0u16;
    let ssrc = 0x4B5C6D;

    let initial_sn = 400;
    let initial_ts = 5000;
    let initial_marker = false;
    establish_ir_context(
        &mut engine,
        cid,
        initial_sn,
        initial_ts,
        initial_marker,
        ssrc,
    );

    let next_sn = initial_sn + 1;
    let next_ts = initial_ts + 500;
    let headers_ts_change = create_rtp_headers(next_sn, next_ts, initial_marker, ssrc);
    let generic_ts_change = GenericUncompressedHeaders::RtpUdpIpv4(headers_ts_change.clone());

    let compressed_packet = engine
        .compress(cid, Some(RohcProfile::RtpUdpIp), &generic_ts_change)
        .unwrap();

    assert_eq!(
        compressed_packet.len(),
        1,
        "Packet should be UO-0 even with TS change, given other criteria match"
    );
    assert_eq!(
        compressed_packet[0] & 0x80,
        0x00,
        "Should be UO-0 type (MSB=0)"
    );

    let decomp_headers = engine
        .decompress(&compressed_packet)
        .unwrap()
        .as_rtp_udp_ipv4()
        .unwrap()
        .clone();
    assert_eq!(decomp_headers.rtp_sequence_number, next_sn);
    assert_eq!(decomp_headers.rtp_marker, initial_marker);
    assert_eq!(decomp_headers.rtp_timestamp, initial_ts);
}
