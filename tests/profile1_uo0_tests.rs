//! Integration tests for ROHC Profile 1 UO-0 packet handling.
//!
//! This module focuses on the smallest compressed packet format (UO-0), testing
//! sequence number encoding/decoding, CRC validation, context state transitions,
//! and edge cases around the limited encoding space of UO-0 packets.

mod common;
use common::{
    create_rtp_headers, create_test_engine_with_system_clock, establish_ir_context,
    get_decompressor_context,
};

use rohcstar::error::{RohcError, RohcParsingError};
use rohcstar::packet_defs::{GenericUncompressedHeaders, RohcProfile};
use rohcstar::profiles::profile1::context::Profile1DecompressorMode;
use rohcstar::profiles::profile1::protocol_types::Timestamp;
use rohcstar::profiles::profile1::{
    P1_DECOMPRESSOR_FC_TO_SC_CRC_FAILURE_THRESHOLD, P1_UO_1_SN_PACKET_TYPE_PREFIX,
    P1_UO_1_TS_DISCRIMINATOR, Profile1Handler,
};

/// Tests UO-0 SN compression and decompression across the 65535 -> 0 sequence number wraparound,
/// ensuring RTP TS remains constant.
#[test]
fn p1_uo0_sn_wraparound_65535_to_0() {
    let mut engine = create_test_engine_with_system_clock(100);
    engine
        .register_profile_handler(Box::new(Profile1Handler::new()))
        .unwrap();
    let cid = 0u16;
    let ssrc = 0xABC123;

    let initial_sn = 65534;
    let initial_ts_val: u32 = 1000;
    let initial_marker = false;

    let mut current_packet_headers =
        create_rtp_headers(initial_sn, initial_ts_val, initial_marker, ssrc);
    establish_ir_context(
        &mut engine,
        cid,
        current_packet_headers.rtp_sequence_number,
        current_packet_headers.rtp_timestamp.value(), // Pass u32
        current_packet_headers.rtp_marker,
        ssrc,
    );

    let mut headers_65535 = create_rtp_headers(65535, initial_ts_val, initial_marker, ssrc);
    headers_65535.ip_identification = current_packet_headers.ip_identification;
    let generic_65535 = GenericUncompressedHeaders::RtpUdpIpv4(headers_65535.clone());
    let compressed_65535 = engine
        .compress(cid, Some(RohcProfile::RtpUdpIp), &generic_65535)
        .unwrap();
    assert_eq!(compressed_65535.len(), 1);
    let decomp_65535 = engine
        .decompress(&compressed_65535)
        .unwrap()
        .as_rtp_udp_ipv4()
        .unwrap()
        .clone();
    assert_eq!(decomp_65535.rtp_sequence_number, 65535);
    assert_eq!(decomp_65535.rtp_timestamp, Timestamp::new(initial_ts_val));
    current_packet_headers = headers_65535;

    let mut headers_0 = create_rtp_headers(0, initial_ts_val, initial_marker, ssrc);
    headers_0.ip_identification = current_packet_headers.ip_identification;
    let generic_0 = GenericUncompressedHeaders::RtpUdpIpv4(headers_0.clone());
    let compressed_0 = engine
        .compress(cid, Some(RohcProfile::RtpUdpIp), &generic_0)
        .unwrap();
    assert_eq!(compressed_0.len(), 1);
    let decomp_0 = engine
        .decompress(&compressed_0)
        .unwrap()
        .as_rtp_udp_ipv4()
        .unwrap()
        .clone();
    assert_eq!(decomp_0.rtp_sequence_number, 0);
    assert_eq!(decomp_0.rtp_timestamp, Timestamp::new(initial_ts_val));
    current_packet_headers = headers_0;

    let mut headers_1 = create_rtp_headers(1, initial_ts_val, initial_marker, ssrc);
    headers_1.ip_identification = current_packet_headers.ip_identification;
    let generic_1 = GenericUncompressedHeaders::RtpUdpIpv4(headers_1.clone());
    let compressed_1 = engine
        .compress(cid, Some(RohcProfile::RtpUdpIp), &generic_1)
        .unwrap();
    assert_eq!(compressed_1.len(), 1);
    let decomp_1 = engine
        .decompress(&compressed_1)
        .unwrap()
        .as_rtp_udp_ipv4()
        .unwrap()
        .clone();
    assert_eq!(decomp_1.rtp_sequence_number, 1);
    assert_eq!(decomp_1.rtp_timestamp, Timestamp::new(initial_ts_val));
}

/// Verifies UO-0 SN LSB encoding at the interpretation window edges.
/// Tests SN values just within the UO-0 window (ref_sn + 15), just outside (ref_sn + 16, which
/// can still be UO-0 if other fields like TS are stable), and then a larger jump forcing UO-1.
#[test]
fn p1_uo0_sn_at_lsb_window_edge() {
    let mut engine = create_test_engine_with_system_clock(100);
    engine
        .register_profile_handler(Box::new(Profile1Handler::new()))
        .unwrap();
    let cid = 0u16;
    let ssrc = 0xDEF456;

    let initial_sn_ir = 100;
    let initial_ts_val: u32 = 2000;
    let initial_marker = false;
    let ir_headers_for_context =
        create_rtp_headers(initial_sn_ir, initial_ts_val, initial_marker, ssrc);
    establish_ir_context(
        &mut engine,
        cid,
        ir_headers_for_context.rtp_sequence_number,
        ir_headers_for_context.rtp_timestamp.value(),
        ir_headers_for_context.rtp_marker,
        ssrc,
    );
    let ip_id_from_ir_context = ir_headers_for_context.ip_identification;

    // Test SN at the edge of UO-0 encodable range (ref_sn + 15)
    let sn_at_edge = initial_sn_ir + 15;
    let headers_at_edge_uncompressed =
        create_rtp_headers(sn_at_edge, initial_ts_val, initial_marker, ssrc)
            .with_ip_id(ip_id_from_ir_context);
    let generic_at_edge =
        GenericUncompressedHeaders::RtpUdpIpv4(headers_at_edge_uncompressed.clone());
    let compressed_at_edge = engine
        .compress(cid, Some(RohcProfile::RtpUdpIp), &generic_at_edge)
        .unwrap();
    assert_eq!(compressed_at_edge.len(), 1); // Expect UO-0
    let decomp_at_edge = engine
        .decompress(&compressed_at_edge)
        .unwrap()
        .as_rtp_udp_ipv4()
        .unwrap()
        .clone();
    assert_eq!(decomp_at_edge.rtp_sequence_number, sn_at_edge);
    assert_eq!(decomp_at_edge.rtp_timestamp, Timestamp::new(initial_ts_val));
    assert_eq!(decomp_at_edge.ip_identification, 0); // IP-ID not in UO-0

    // Test SN just beyond the simple +15 UO-0 window, but still potentially UO-0 if TS is stable
    let sn_next_to_edge = sn_at_edge + 1; // initial_sn_ir + 16
    let headers_next_to_edge_uncompressed =
        create_rtp_headers(sn_next_to_edge, initial_ts_val, initial_marker, ssrc)
            .with_ip_id(ip_id_from_ir_context);
    let generic_next_to_edge =
        GenericUncompressedHeaders::RtpUdpIpv4(headers_next_to_edge_uncompressed.clone());
    let compressed_next_to_edge = engine
        .compress(cid, Some(RohcProfile::RtpUdpIp), &generic_next_to_edge)
        .unwrap();
    assert_eq!(compressed_next_to_edge.len(), 1); // Still expect UO-0 due to stable TS/Marker
    let decomp_next_to_edge = engine
        .decompress(&compressed_next_to_edge)
        .unwrap()
        .as_rtp_udp_ipv4()
        .unwrap()
        .clone();
    assert_eq!(decomp_next_to_edge.rtp_sequence_number, sn_next_to_edge);
    assert_eq!(
        decomp_next_to_edge.rtp_timestamp,
        Timestamp::new(initial_ts_val)
    );
    assert_eq!(decomp_next_to_edge.ip_identification, 0);

    // Re-establish context and test a larger jump that should force UO-1 (or IR if too large)
    let new_ir_base_ts_val: u32 = initial_ts_val + 100; // Change TS to differentiate context
    let new_ir_sn = 115;
    let new_ir_headers_for_context =
        create_rtp_headers(new_ir_sn, new_ir_base_ts_val, initial_marker, ssrc);
    establish_ir_context(
        &mut engine,
        cid,
        new_ir_headers_for_context.rtp_sequence_number,
        new_ir_headers_for_context.rtp_timestamp.value(),
        new_ir_headers_for_context.rtp_marker,
        ssrc,
    );
    let ip_id_from_new_ir_context = new_ir_headers_for_context.ip_identification;

    // SN jump that should not be UO-0 (115 + 16 = 131)
    let sn_outside_window = new_ir_sn + 16;
    let headers_outside_window_uncompressed = create_rtp_headers(
        sn_outside_window,
        new_ir_base_ts_val + 30, // Also change TS to make it clearly not UO-0
        initial_marker,
        ssrc,
    )
    .with_ip_id(ip_id_from_new_ir_context.wrapping_add(1)); // And IP-ID
    let generic_outside_window =
        GenericUncompressedHeaders::RtpUdpIpv4(headers_outside_window_uncompressed.clone());
    let compressed_outside_window = engine
        .compress(cid, Some(RohcProfile::RtpUdpIp), &generic_outside_window)
        .unwrap();
    assert_eq!(compressed_outside_window.len(), 3); // Expect UO-1-SN
    let decomp_outside_window = engine
        .decompress(&compressed_outside_window)
        .unwrap()
        .as_rtp_udp_ipv4()
        .unwrap()
        .clone();
    assert_eq!(decomp_outside_window.rtp_sequence_number, sn_outside_window);
    assert_eq!(
        // UO-1-SN uses TS from context
        decomp_outside_window.rtp_timestamp,
        Timestamp::new(new_ir_base_ts_val)
    );
    assert_eq!(decomp_outside_window.ip_identification, 0); // IP-ID not in UO-1-SN
}

/// Tests that consecutive CRC failures on UO-0 packets in Full Context (FC) mode
/// trigger a downgrade to Static Context (SC) mode in the decompressor.
#[test]
fn p1_uo0_crc_failures_trigger_context_downgrade() {
    let mut engine = create_test_engine_with_system_clock(100);
    engine
        .register_profile_handler(Box::new(Profile1Handler::new()))
        .unwrap();
    let cid = 0u16;
    let ssrc = 0xFAFBFCD;

    let base_ts_for_uo0_series_val: u32 = 3000;
    let initial_ir_sn = 200u16;
    let ir_headers_for_context =
        create_rtp_headers(initial_ir_sn, base_ts_for_uo0_series_val, false, ssrc);
    establish_ir_context(
        &mut engine,
        cid,
        ir_headers_for_context.rtp_sequence_number,
        ir_headers_for_context.rtp_timestamp.value(),
        ir_headers_for_context.rtp_marker,
        ssrc,
    );

    for i in 1..=P1_DECOMPRESSOR_FC_TO_SC_CRC_FAILURE_THRESHOLD {
        let current_sn_for_uo0 = initial_ir_sn.wrapping_add(i as u16);
        let mut headers_good_uo0 =
            create_rtp_headers(current_sn_for_uo0, base_ts_for_uo0_series_val, false, ssrc);
        headers_good_uo0.ip_identification = ir_headers_for_context.ip_identification;
        let generic_good_uo0 = GenericUncompressedHeaders::RtpUdpIpv4(headers_good_uo0.clone());

        let mut compressed_uo0 = engine
            .compress(cid, Some(RohcProfile::RtpUdpIp), &generic_good_uo0)
            .unwrap();
        assert_eq!(compressed_uo0.len(), 1);

        // Corrupt CRC (last 3 bits of the UO-0 byte)
        compressed_uo0[0] = compressed_uo0[0].wrapping_add(1);
        // Ensure it's still a UO-0 type (MSB is 0) if corruption made it non-UO-0
        if (compressed_uo0[0] & 0x80) != 0 {
            compressed_uo0[0] &= 0x7F;
        }

        let result = engine.decompress(&compressed_uo0);
        assert!(matches!(
            result,
            Err(RohcError::Parsing(RohcParsingError::CrcMismatch { .. }))
        ));

        let decomp_ctx = get_decompressor_context(&engine, cid);
        if i < P1_DECOMPRESSOR_FC_TO_SC_CRC_FAILURE_THRESHOLD {
            assert_eq!(decomp_ctx.mode, Profile1DecompressorMode::FullContext);
            assert_eq!(decomp_ctx.consecutive_crc_failures_in_fc, i);
        } else {
            assert_eq!(decomp_ctx.mode, Profile1DecompressorMode::StaticContext);
        }
    }
}

/// Verifies that UO-0 is not used when the RTP Marker bit changes,
/// and a UO-1-SN packet is chosen instead.
#[test]
fn p1_uo0_not_used_when_marker_changes() {
    let mut engine = create_test_engine_with_system_clock(100);
    engine
        .register_profile_handler(Box::new(Profile1Handler::new()))
        .unwrap();
    let cid = 0u16;
    let ssrc = 0x1A2B3C;

    let ir_headers = create_rtp_headers(300, 4000, false, ssrc); // Initial marker is false
    establish_ir_context(
        &mut engine,
        cid,
        ir_headers.rtp_sequence_number,
        ir_headers.rtp_timestamp.value(),
        ir_headers.rtp_marker,
        ssrc,
    );

    // Next packet: SN+1, TS changes slightly, Marker changes to true
    let mut headers_marker_change = create_rtp_headers(301, 4010, true, ssrc);
    headers_marker_change.ip_identification = ir_headers.ip_identification; // Keep IP-ID same
    let generic_marker_change =
        GenericUncompressedHeaders::RtpUdpIpv4(headers_marker_change.clone());

    let compressed_packet = engine
        .compress(cid, Some(RohcProfile::RtpUdpIp), &generic_marker_change)
        .unwrap();

    // Expect UO-1-SN (3 bytes for CID 0) because marker changed
    assert_eq!(compressed_packet.len(), 3);
    assert_eq!(
        compressed_packet[0] & P1_UO_1_SN_PACKET_TYPE_PREFIX,
        P1_UO_1_SN_PACKET_TYPE_PREFIX
    );

    let decomp_headers = engine
        .decompress(&compressed_packet)
        .unwrap()
        .as_rtp_udp_ipv4()
        .unwrap()
        .clone();
    assert_eq!(decomp_headers.rtp_sequence_number, 301);
    assert!(decomp_headers.rtp_marker); // Marker bit correctly reconstructed
    assert_eq!(decomp_headers.rtp_timestamp, Timestamp::new(4000)); // TS from context for UO-1-SN
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
        ir_headers_for_context.rtp_sequence_number,
        ir_headers_for_context.rtp_timestamp.value(),
        ir_headers_for_context.rtp_marker,
        ssrc,
    );

    let next_sn = initial_sn + 1; // SN increments by one
    let next_ts_val: u32 = initial_ts_val + 500; // TS changes significantly
    let mut headers_ts_change = create_rtp_headers(next_sn, next_ts_val, initial_marker, ssrc); // Marker same
    headers_ts_change.ip_identification = ir_headers_for_context.ip_identification; // IP-ID same
    let generic_ts_change = GenericUncompressedHeaders::RtpUdpIpv4(headers_ts_change.clone());

    let compressed_packet = engine
        .compress(cid, Some(RohcProfile::RtpUdpIp), &generic_ts_change)
        .unwrap();

    // Expect UO-1-TS (4 bytes for CID 0: Type + TS_LSB(2) + CRC8)
    assert_eq!(compressed_packet.len(), 4);
    assert_eq!(compressed_packet[0], P1_UO_1_TS_DISCRIMINATOR);

    let decomp_headers = engine
        .decompress(&compressed_packet)
        .unwrap()
        .as_rtp_udp_ipv4()
        .unwrap()
        .clone();
    assert_eq!(decomp_headers.rtp_sequence_number, next_sn);
    assert_eq!(decomp_headers.rtp_marker, initial_marker);
    assert_eq!(decomp_headers.rtp_timestamp, Timestamp::new(next_ts_val)); // TS reconstructed
}
