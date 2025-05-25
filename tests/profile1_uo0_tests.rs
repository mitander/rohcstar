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
    P1_DECOMPRESSOR_FC_TO_SC_CRC_FAILURE_THRESHOLD, P1_UO_1_SN_PACKET_TYPE_PREFIX,
    P1_UO_1_TS_DISCRIMINATOR, Profile1Handler,
};

#[test]
fn p1_uo0_sn_wraparound_65535_to_0() {
    let mut engine = RohcEngine::new(100); // High refresh interval
    engine
        .register_profile_handler(Box::new(Profile1Handler::new()))
        .unwrap();
    let cid = 0u16;
    let ssrc = 0xABC123;

    let initial_sn = 65534;
    let initial_ts = 1000; // Establish a base timestamp for UO-0 packets
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
    // To be UO-0, TS must match context (initial_ts)
    let headers_65535 = create_rtp_headers(65535, initial_ts, initial_marker, ssrc);
    let generic_65535 = GenericUncompressedHeaders::RtpUdpIpv4(headers_65535.clone());
    let compressed_65535 = engine
        .compress(cid, Some(RohcProfile::RtpUdpIp), &generic_65535)
        .unwrap();
    assert_eq!(
        compressed_65535.len(),
        1,
        "SN 65535 should be UO-0. Got: {:?}",
        compressed_65535
    );
    let decomp_65535 = engine
        .decompress(&compressed_65535)
        .unwrap()
        .as_rtp_udp_ipv4()
        .unwrap()
        .clone();
    assert_eq!(decomp_65535.rtp_sequence_number, 65535);
    assert_eq!(decomp_65535.rtp_timestamp, initial_ts); // TS from context

    // Packet: SN = 0 (wraparound, should be UO-0)
    // To be UO-0, TS must match context (initial_ts)
    let headers_0 = create_rtp_headers(0, initial_ts, initial_marker, ssrc);
    let generic_0 = GenericUncompressedHeaders::RtpUdpIpv4(headers_0.clone());
    let compressed_0 = engine
        .compress(cid, Some(RohcProfile::RtpUdpIp), &generic_0)
        .unwrap();
    assert_eq!(
        compressed_0.len(),
        1,
        "SN 0 (after 65535) should be UO-0. Got: {:?}",
        compressed_0
    );
    let decomp_0 = engine
        .decompress(&compressed_0)
        .unwrap()
        .as_rtp_udp_ipv4()
        .unwrap()
        .clone();
    assert_eq!(decomp_0.rtp_sequence_number, 0);
    assert_eq!(decomp_0.rtp_timestamp, initial_ts); // TS from context

    // Packet: SN = 1 (should be UO-0)
    // To be UO-0, TS must match context (initial_ts)
    let headers_1 = create_rtp_headers(1, initial_ts, initial_marker, ssrc);
    let generic_1 = GenericUncompressedHeaders::RtpUdpIpv4(headers_1.clone());
    let compressed_1 = engine
        .compress(cid, Some(RohcProfile::RtpUdpIp), &generic_1)
        .unwrap();
    assert_eq!(
        compressed_1.len(),
        1,
        "SN 1 (after 0) should be UO-0. Got: {:?}",
        compressed_1
    );
    let decomp_1 = engine
        .decompress(&compressed_1)
        .unwrap()
        .as_rtp_udp_ipv4()
        .unwrap()
        .clone();
    assert_eq!(decomp_1.rtp_sequence_number, 1);
    assert_eq!(decomp_1.rtp_timestamp, initial_ts); // TS from context
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
    let initial_ts = 2000; // Establish a base timestamp
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
    // To be UO-0, TS must match context (initial_ts)
    let headers_at_edge = create_rtp_headers(sn_at_edge, initial_ts, initial_marker, ssrc);
    let generic_at_edge = GenericUncompressedHeaders::RtpUdpIpv4(headers_at_edge.clone());
    let compressed_at_edge = engine
        .compress(cid, Some(RohcProfile::RtpUdpIp), &generic_at_edge)
        .unwrap();
    assert_eq!(
        compressed_at_edge.len(),
        1,
        "SN 115 (from 100) should be UO-0. Got: {:?}",
        compressed_at_edge
    );
    let decomp_at_edge = engine
        .decompress(&compressed_at_edge)
        .unwrap()
        .as_rtp_udp_ipv4()
        .unwrap()
        .clone();
    assert_eq!(decomp_at_edge.rtp_sequence_number, sn_at_edge);
    assert_eq!(decomp_at_edge.rtp_timestamp, initial_ts); // TS from context

    let sn_next_to_edge = sn_at_edge + 1; // 116
    // Compressor context SN is now 115, TS is initial_ts (2000)
    // To be UO-0, TS must match context (initial_ts)
    let headers_next_to_edge =
        create_rtp_headers(sn_next_to_edge, initial_ts, initial_marker, ssrc);
    let generic_next_to_edge = GenericUncompressedHeaders::RtpUdpIpv4(headers_next_to_edge.clone());
    let compressed_next_to_edge = engine
        .compress(cid, Some(RohcProfile::RtpUdpIp), &generic_next_to_edge)
        .unwrap();
    assert_eq!(
        compressed_next_to_edge.len(),
        1,
        "SN 116 (from 115) should be UO-0. Got: {:?}",
        compressed_next_to_edge
    );
    let decomp_next_to_edge = engine
        .decompress(&compressed_next_to_edge)
        .unwrap()
        .as_rtp_udp_ipv4()
        .unwrap()
        .clone();
    assert_eq!(decomp_next_to_edge.rtp_sequence_number, sn_next_to_edge);
    assert_eq!(decomp_next_to_edge.rtp_timestamp, initial_ts); // TS from context

    // Re-establish context with SN 115. Use a new distinct TS for this IR context.
    let new_ir_base_ts = initial_ts + 100;
    establish_ir_context(&mut engine, cid, 115, new_ir_base_ts, initial_marker, ssrc);

    let sn_outside_window = 115 + 16; // 131
    // Uncompressed TS can be different here as this will be UO-1-SN due to SN diff.
    let headers_outside_window =
        create_rtp_headers(sn_outside_window, new_ir_base_ts + 30, initial_marker, ssrc);
    let generic_outside_window =
        GenericUncompressedHeaders::RtpUdpIpv4(headers_outside_window.clone());
    let compressed_outside_window = engine
        .compress(cid, Some(RohcProfile::RtpUdpIp), &generic_outside_window)
        .unwrap();
    assert_eq!(
        compressed_outside_window.len(),
        3,
        "SN 131 (from 115) should be UO-1 as diff is 16. Got: {:?}",
        compressed_outside_window
    );
    let decomp_outside_window = engine
        .decompress(&compressed_outside_window)
        .unwrap()
        .as_rtp_udp_ipv4()
        .unwrap()
        .clone();
    assert_eq!(decomp_outside_window.rtp_sequence_number, sn_outside_window);
    assert_eq!(decomp_outside_window.rtp_timestamp, new_ir_base_ts); // UO-1-SN uses context TS
}

#[test]
fn p1_uo0_crc_failures_trigger_context_downgrade() {
    let mut engine = RohcEngine::new(100);
    engine
        .register_profile_handler(Box::new(Profile1Handler::new()))
        .unwrap();
    let cid = 0u16;
    let ssrc = 0xFAFBFCD;

    let base_ts_for_uo0_series = 3000;
    establish_ir_context(&mut engine, cid, 200, base_ts_for_uo0_series, false, ssrc);

    for i in 1..=P1_DECOMPRESSOR_FC_TO_SC_CRC_FAILURE_THRESHOLD {
        // To generate UO-0 packets, their TS must match the context TS (base_ts_for_uo0_series)
        let headers_good_uo0 =
            create_rtp_headers(200 + i as u16, base_ts_for_uo0_series, false, ssrc);
        let generic_good_uo0 = GenericUncompressedHeaders::RtpUdpIpv4(headers_good_uo0);

        let mut compressed_uo0 = engine
            .compress(cid, Some(RohcProfile::RtpUdpIp), &generic_good_uo0)
            .unwrap();
        assert_eq!(
            compressed_uo0.len(),
            1,
            "Should be a UO-0 packet. Got: {:?}",
            compressed_uo0
        );

        // Corrupt the UO-0 packet to cause CRC failure
        compressed_uo0[0] = compressed_uo0[0].wrapping_add(1);
        // Ensure the MSB (packet type bit for UO-0) remains 0 after corruption
        if (compressed_uo0[0] & 0x80) != 0 {
            // If corruption made it look like UO-1 or IR, force it back to UO-0-like prefix
            compressed_uo0[0] &= 0x7F;
        }

        let result = engine.decompress(&compressed_uo0);
        assert!(
            matches!(
                result,
                Err(RohcError::Parsing(RohcParsingError::CrcMismatch { .. }))
            ),
            "Attempt {} should result in CRC mismatch. Got: {:?}",
            i,
            result
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

    // Uncompressed header TS is different, but marker change takes precedence for UO-1-SN.
    let headers_marker_change = create_rtp_headers(301, 4010, true, ssrc);
    let generic_marker_change =
        GenericUncompressedHeaders::RtpUdpIpv4(headers_marker_change.clone());

    let compressed_packet = engine
        .compress(cid, Some(RohcProfile::RtpUdpIp), &generic_marker_change)
        .unwrap();

    assert_eq!(
        compressed_packet.len(),
        3,
        "Packet should be UO-1 due to marker change, not UO-0. Got: {:?}",
        compressed_packet
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
    assert_eq!(decomp_headers.rtp_timestamp, 4000); // TS from context for UO-1-SN
}

#[test]
fn p1_uo1_ts_is_used_when_ts_changes_marker_sn_ok_for_uo1ts() {
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
        // Context: SN=400, TS=5000, M=false
        &mut engine,
        cid,
        initial_sn,
        initial_ts,
        initial_marker,
        ssrc,
    );

    let next_sn = initial_sn + 1; // SN increments by 1
    let next_ts = initial_ts + 500; // TS changes significantly
    // Marker is same as context (false)
    let headers_ts_change = create_rtp_headers(next_sn, next_ts, initial_marker, ssrc);
    let generic_ts_change = GenericUncompressedHeaders::RtpUdpIpv4(headers_ts_change.clone());

    let compressed_packet = engine
        .compress(cid, Some(RohcProfile::RtpUdpIp), &generic_ts_change)
        .unwrap();

    // Expect UO-1-TS because: Marker unchanged, TS changed, SN incremented by 1
    assert_eq!(
        compressed_packet.len(),
        4, // UO-1-TS for CID 0 is 4 bytes
        "Packet should be UO-1-TS due to TS change and SN+1, marker same. Got: {:?}",
        compressed_packet
    );
    assert_eq!(
        compressed_packet[0], P1_UO_1_TS_DISCRIMINATOR,
        "Should be UO-1-TS type"
    );

    let decomp_headers = engine
        .decompress(&compressed_packet)
        .unwrap()
        .as_rtp_udp_ipv4()
        .unwrap()
        .clone();
    assert_eq!(decomp_headers.rtp_sequence_number, next_sn);
    assert_eq!(decomp_headers.rtp_marker, initial_marker);
    assert_eq!(decomp_headers.rtp_timestamp, next_ts); // TS should be updated by UO-1-TS
}
