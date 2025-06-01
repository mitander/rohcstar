//! Integration tests for ROHC Profile 1 UO-1-SN packet handling.
//!
//! This module tests the UO-1-SN packet format, which provides extended sequence
//! number encoding and marker bit transmission. Tests cover sequence number jumps,
//! marker bit changes, wraparound scenarios, and packet type selection logic.

mod common;
use common::{
    create_rtp_headers, create_test_engine_with_system_clock, establish_ir_context,
    get_compressor_context, get_decompressor_context, get_ip_id_established_by_ir,
};

use rohcstar::error::RohcError;
use rohcstar::error::RohcParsingError;
use rohcstar::packet_defs::{GenericUncompressedHeaders, RohcProfile};
use rohcstar::profiles::profile1::protocol_types::Timestamp;
use rohcstar::profiles::profile1::{
    P1_UO_1_SN_MARKER_BIT_MASK, P1_UO_1_SN_PACKET_TYPE_PREFIX, Profile1Handler,
};

/// Tests UO-1-SN compression and decompression with SN wrapping around from high values to low values,
/// ensuring marker bit and TS are handled correctly.
#[test]
fn p1_uo1_sn_with_sn_wraparound() {
    let mut engine = create_test_engine_with_system_clock(200);
    engine
        .register_profile_handler(Box::new(Profile1Handler::new()))
        .unwrap();
    let cid = 0u16;
    let ssrc = 0xABCDEF01;

    let ir_sn = 65530;
    let ir_ts_val: u32 = 1000;
    let ir_marker = false;
    establish_ir_context(&mut engine, cid, ir_sn, ir_ts_val, ir_marker, ssrc);
    let ip_id_from_ir = get_ip_id_established_by_ir(ir_sn, ssrc);

    // Packet with SN near wraparound, marker true
    let sn1 = 65532;
    let marker1 = true;
    let headers1 = create_rtp_headers(sn1, ir_ts_val, marker1, ssrc).with_ip_id(ip_id_from_ir);
    let generic1 = GenericUncompressedHeaders::RtpUdpIpv4(headers1.clone());
    let compressed1 = engine
        .compress(cid, Some(RohcProfile::RtpUdpIp), &generic1)
        .unwrap();

    assert_eq!(compressed1.len(), 3);
    assert_eq!(
        compressed1[0] & P1_UO_1_SN_PACKET_TYPE_PREFIX,
        P1_UO_1_SN_PACKET_TYPE_PREFIX
    );
    assert_ne!(compressed1[0] & P1_UO_1_SN_MARKER_BIT_MASK, 0); // Marker should be set

    let decomp1 = engine
        .decompress(&compressed1)
        .unwrap()
        .as_rtp_udp_ipv4()
        .unwrap()
        .clone();
    assert_eq!(decomp1.rtp_sequence_number, sn1);
    assert_eq!(decomp1.rtp_marker, marker1);
    assert_eq!(decomp1.rtp_timestamp, Timestamp::new(ir_ts_val));

    // Packet with SN wrapped around, marker false
    let sn2 = 2;
    let marker2 = false;
    let headers2 = create_rtp_headers(sn2, ir_ts_val, marker2, ssrc).with_ip_id(ip_id_from_ir);
    let generic2 = GenericUncompressedHeaders::RtpUdpIpv4(headers2.clone());
    let compressed2 = engine
        .compress(cid, Some(RohcProfile::RtpUdpIp), &generic2)
        .unwrap();

    assert_eq!(compressed2.len(), 3);
    assert_eq!(
        compressed2[0] & P1_UO_1_SN_PACKET_TYPE_PREFIX,
        P1_UO_1_SN_PACKET_TYPE_PREFIX
    );
    assert_eq!(compressed2[0] & P1_UO_1_SN_MARKER_BIT_MASK, 0); // Marker should be clear

    let decomp2 = engine
        .decompress(&compressed2)
        .unwrap()
        .as_rtp_udp_ipv4()
        .unwrap()
        .clone();
    assert_eq!(decomp2.rtp_sequence_number, sn2);
    assert_eq!(decomp2.rtp_marker, marker2);
    assert_eq!(decomp2.rtp_timestamp, Timestamp::new(ir_ts_val));
}

/// Verifies that UO-1-SN packets are used when the RTP Marker bit changes rapidly,
/// even if SN increments by one and TS is stable.
#[test]
fn p1_rapid_marker_toggling_forces_uo1() {
    let mut engine = create_test_engine_with_system_clock(200);
    engine
        .register_profile_handler(Box::new(Profile1Handler::new()))
        .unwrap();
    let cid = 0u16;
    let ssrc = 0x1234FEDC;

    let initial_sn = 100;
    let initial_ts_val: u32 = 5000;
    let mut current_marker = false;

    establish_ir_context(
        &mut engine,
        cid,
        initial_sn,
        initial_ts_val,
        current_marker,
        ssrc,
    );
    let ip_id_from_ir = get_ip_id_established_by_ir(initial_sn, ssrc);

    for i in 1..=5 {
        let current_sn = initial_sn + i;
        current_marker = !current_marker; // Toggle marker bit

        let headers = create_rtp_headers(current_sn, initial_ts_val, current_marker, ssrc)
            .with_ip_id(ip_id_from_ir);
        let generic = GenericUncompressedHeaders::RtpUdpIpv4(headers.clone());
        let compressed = engine
            .compress(cid, Some(RohcProfile::RtpUdpIp), &generic)
            .unwrap();

        assert_eq!(compressed.len(), 3); // UO-1-SN
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
        assert_eq!(decomp.rtp_timestamp, Timestamp::new(initial_ts_val));

        let decomp_ctx = get_decompressor_context(&engine, cid);
        assert_eq!(decomp_ctx.last_reconstructed_rtp_marker, current_marker);
        assert_eq!(
            decomp_ctx.last_reconstructed_rtp_ts_full,
            Timestamp::new(initial_ts_val)
        );
    }
}

/// Tests UO-1-SN encoding for a significant positive SN jump and robustness to a
/// subsequent SN that appears "out of order" (lower than the previous SN).
#[test]
fn p1_uo1_sn_max_sn_jump_encodable() {
    let mut engine = create_test_engine_with_system_clock(500);
    engine
        .register_profile_handler(Box::new(Profile1Handler::new()))
        .unwrap();
    let cid = 0u16;
    let ssrc = 0x778899AA;

    let initial_sn = 1000;
    let initial_ts_val: u32 = 10000;
    let initial_marker = false;
    establish_ir_context(
        &mut engine,
        cid,
        initial_sn,
        initial_ts_val,
        initial_marker,
        ssrc,
    );
    let ip_id_from_ir = get_ip_id_established_by_ir(initial_sn, ssrc);

    // Positive SN jump, encodable by UO-1-SN (8 LSBs)
    let sn_jump_pos = initial_sn + 100;
    let headers_jump_pos =
        create_rtp_headers(sn_jump_pos, initial_ts_val + 100, initial_marker, ssrc) // TS also changes
            .with_ip_id(ip_id_from_ir.wrapping_add(1)); // IP-ID also changes
    let generic_jump_pos = GenericUncompressedHeaders::RtpUdpIpv4(headers_jump_pos.clone());
    let compressed_jump_pos = engine
        .compress(cid, Some(RohcProfile::RtpUdpIp), &generic_jump_pos)
        .unwrap();
    assert_eq!(compressed_jump_pos.len(), 3); // UO-1-SN

    let decomp_jump_pos_result = engine.decompress(&compressed_jump_pos);
    assert!(
        decomp_jump_pos_result.is_ok(),
        "Decompression of positive jump failed: {:?}",
        decomp_jump_pos_result.err()
    );
    let decomp_jump_pos_generic = decomp_jump_pos_result.unwrap();
    let decomp_jump_pos = decomp_jump_pos_generic.as_rtp_udp_ipv4().unwrap().clone();
    assert_eq!(decomp_jump_pos.rtp_sequence_number, sn_jump_pos);
    assert_eq!(
        // UO-1-SN uses TS from context
        decomp_jump_pos.rtp_timestamp,
        Timestamp::new(initial_ts_val)
    );

    // Simulate an "out of order" packet or SN reset by jumping back.
    // The decompressor's reference SN is now `sn_jump_pos`.
    // Sending LSBs for `initial_sn` might be misinterpreted, leading to CRC failure.
    let comp_ctx_before_neg_jump = get_compressor_context(&engine, cid);
    let ip_id_in_comp_ctx = comp_ctx_before_neg_jump.last_sent_ip_id_full;

    let sn_jump_neg = initial_sn; // Jump back to original SN
    let headers_jump_neg =
        create_rtp_headers(sn_jump_neg, initial_ts_val + 200, initial_marker, ssrc)
            .with_ip_id(ip_id_in_comp_ctx.wrapping_add(1));
    let generic_jump_neg = GenericUncompressedHeaders::RtpUdpIpv4(headers_jump_neg.clone());
    let compressed_jump_neg = engine
        .compress(cid, Some(RohcProfile::RtpUdpIp), &generic_jump_neg)
        .unwrap();
    assert_eq!(compressed_jump_neg.len(), 3); // Still UO-1-SN from compressor perspective

    let decompress_result_neg_jump = engine.decompress(&compressed_jump_neg);
    // Expect CRC mismatch because decompressor's v_ref_sn is sn_jump_pos (e.g., 1100).
    // LSBs for initial_sn (1000) will likely be decoded far from 1000 by the decompressor,
    // causing the reconstructed values for CRC check to differ from compressor's.
    match decompress_result_neg_jump {
        Err(RohcError::Parsing(RohcParsingError::CrcMismatch { .. })) => {} // Expected
        Ok(h) => panic!("Expected CrcMismatch for SN jump-back, but got Ok({:?})", h),
        Err(e) => panic!(
            "Expected CrcMismatch for SN jump-back, but got other error: {:?}",
            e
        ),
    }
}

/// Tests that UO-1-SN is preferred over UO-0 when the SN difference is too large
/// for UO-0's limited LSB encoding (typically > 15).
#[test]
fn p1_uo1_sn_prefered_over_uo0_for_larger_sn_diff() {
    let mut engine = create_test_engine_with_system_clock(100);
    engine
        .register_profile_handler(Box::new(Profile1Handler::new()))
        .unwrap();
    let cid = 0u16;
    let ssrc = 0xBBCCDDFF;

    let initial_sn = 500;
    let initial_ts_val: u32 = 6000;
    let initial_marker = false;

    establish_ir_context(
        &mut engine,
        cid,
        initial_sn,
        initial_ts_val,
        initial_marker,
        ssrc,
    );
    let ip_id_from_ir = get_ip_id_established_by_ir(initial_sn, ssrc);

    // Packet within UO-0 SN range (max delta for UO-0's 4 LSBs is 15)
    let sn_uo0_max = initial_sn + 15;
    let headers_uo0 = create_rtp_headers(sn_uo0_max, initial_ts_val, initial_marker, ssrc)
        .with_ip_id(ip_id_from_ir); // Keep IP-ID same for UO-0

    let compressed_uo0 = engine
        .compress(
            cid,
            Some(RohcProfile::RtpUdpIp),
            &GenericUncompressedHeaders::RtpUdpIpv4(headers_uo0.clone()),
        )
        .unwrap();
    assert_eq!(compressed_uo0.len(), 1, "Should be UO-0 for SN delta 15");
    let _ = engine.decompress(&compressed_uo0).unwrap();

    // Packet outside UO-0 SN range (e.g., delta 31)
    let sn_force_uo1 = initial_sn + 31; // Example: initial_sn + 15 + 16
    let headers_uo1 = create_rtp_headers(sn_force_uo1, initial_ts_val + 20, initial_marker, ssrc); // TS also changes

    let compressed_uo1 = engine
        .compress(
            cid,
            Some(RohcProfile::RtpUdpIp),
            &GenericUncompressedHeaders::RtpUdpIpv4(headers_uo1.clone()),
        )
        .unwrap();
    assert_eq!(
        compressed_uo1.len(),
        3,
        "Should be UO-1-SN for larger SN delta"
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
    assert_eq!(decomp_uo1.rtp_timestamp, Timestamp::new(initial_ts_val)); // TS from context
}
