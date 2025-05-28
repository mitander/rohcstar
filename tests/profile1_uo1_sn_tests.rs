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
use rohcstar::profiles::profile1::{
    P1_UO_1_SN_MARKER_BIT_MASK, P1_UO_1_SN_PACKET_TYPE_PREFIX, Profile1Handler,
};

#[test]
fn p1_uo1_sn_with_sn_wraparound() {
    let mut engine = create_test_engine_with_system_clock(200);
    engine
        .register_profile_handler(Box::new(Profile1Handler::new()))
        .unwrap();
    let cid = 0u16;
    let ssrc = 0xABCDEF01;

    let ir_sn = 65530;
    let ir_ts = 1000;
    let ir_marker = false;
    establish_ir_context(&mut engine, cid, ir_sn, ir_ts, ir_marker, ssrc);
    let ip_id_from_ir = get_ip_id_established_by_ir(ir_sn, ssrc);

    let sn1 = 65532;
    let marker1 = true;
    // For UO-1-SN, TS for CRC is from context. IP-ID kept stable to avoid unrelated IR.
    let headers1 = create_rtp_headers(sn1, ir_ts, marker1, ssrc).with_ip_id(ip_id_from_ir);
    let generic1 = GenericUncompressedHeaders::RtpUdpIpv4(headers1.clone());
    let compressed1 = engine
        .compress(cid, Some(RohcProfile::RtpUdpIp), &generic1)
        .unwrap();

    assert_eq!(compressed1.len(), 3, "SN 65532, M=true should be UO-1-SN.");
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
    assert_eq!(decomp1.rtp_timestamp, ir_ts); // TS reconstructed from context

    let sn2 = 2; // SN wraps around
    let marker2 = false;
    let headers2 = create_rtp_headers(sn2, ir_ts, marker2, ssrc).with_ip_id(ip_id_from_ir); // Keep IP-ID stable
    let generic2 = GenericUncompressedHeaders::RtpUdpIpv4(headers2.clone());
    let compressed2 = engine
        .compress(cid, Some(RohcProfile::RtpUdpIp), &generic2)
        .unwrap();

    assert_eq!(
        compressed2.len(),
        3,
        "SN 2 (wrap), M=false should be UO-1-SN."
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
    assert_eq!(decomp2.rtp_timestamp, ir_ts); // TS reconstructed from context
}

#[test]
fn p1_rapid_marker_toggling_forces_uo1() {
    let mut engine = create_test_engine_with_system_clock(200);
    engine
        .register_profile_handler(Box::new(Profile1Handler::new()))
        .unwrap();
    let cid = 0u16;
    let ssrc = 0x1234FEDC;

    let initial_sn = 100;
    let initial_ts = 5000;
    let mut current_marker = false;

    establish_ir_context(
        &mut engine,
        cid,
        initial_sn,
        initial_ts,
        current_marker,
        ssrc,
    );
    let ip_id_from_ir = get_ip_id_established_by_ir(initial_sn, ssrc);

    for i in 1..=5 {
        let current_sn = initial_sn + i;
        current_marker = !current_marker; // Marker toggles, primary driver for UO-1-SN

        // TS for CRC is from context. IP-ID kept stable.
        let headers = create_rtp_headers(current_sn, initial_ts, current_marker, ssrc)
            .with_ip_id(ip_id_from_ir);
        let generic = GenericUncompressedHeaders::RtpUdpIpv4(headers.clone());
        let compressed = engine
            .compress(cid, Some(RohcProfile::RtpUdpIp), &generic)
            .unwrap();

        assert_eq!(
            compressed.len(),
            3,
            "Packet {} with toggled marker should be UO-1-SN.",
            i
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
    let mut engine = create_test_engine_with_system_clock(500);
    engine
        .register_profile_handler(Box::new(Profile1Handler::new()))
        .unwrap();
    let cid = 0u16;
    let ssrc = 0x778899AA;

    let initial_sn = 1000;
    let initial_ts = 10000;
    let initial_marker = false;
    establish_ir_context(
        &mut engine,
        cid,
        initial_sn,
        initial_ts,
        initial_marker,
        ssrc,
    );
    let ip_id_from_ir = get_ip_id_established_by_ir(initial_sn, ssrc);

    // Positive SN jump
    let sn_jump_pos = initial_sn + 100;
    // UO-1-SN due to SN_diff > LSB range for UO-0 and TS change.
    // Keep IP-ID change minimal to avoid IR due to IP-ID.
    let headers_jump_pos = create_rtp_headers(sn_jump_pos, initial_ts + 100, initial_marker, ssrc)
        .with_ip_id(ip_id_from_ir.wrapping_add(1));
    let generic_jump_pos = GenericUncompressedHeaders::RtpUdpIpv4(headers_jump_pos.clone());
    let compressed_jump_pos = engine
        .compress(cid, Some(RohcProfile::RtpUdpIp), &generic_jump_pos)
        .unwrap();
    assert_eq!(
        compressed_jump_pos.len(),
        3,
        "SN jump +100 should be UO-1-SN."
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

    // Negative SN jump (wraparound)
    // Compressor context after previous packet: SN=1100, TS=10100, IP-ID updated
    let comp_ctx_before_neg_jump = get_compressor_context(&engine, cid);
    let ip_id_in_comp_ctx = comp_ctx_before_neg_jump.last_sent_ip_id_full;

    let sn_jump_neg = initial_sn; // Target SN is 1000. Last sent was 1100.
    let headers_jump_neg = create_rtp_headers(sn_jump_neg, initial_ts + 200, initial_marker, ssrc)
        .with_ip_id(ip_id_in_comp_ctx.wrapping_add(1)); // Small change from current context IP-ID
    let generic_jump_neg = GenericUncompressedHeaders::RtpUdpIpv4(headers_jump_neg.clone());
    let compressed_jump_neg = engine
        .compress(cid, Some(RohcProfile::RtpUdpIp), &generic_jump_neg)
        .unwrap();
    // Expected UO-1-SN. CRC might mismatch due to TS divergence for CRC calculation.
    assert_eq!(
        compressed_jump_neg.len(),
        3,
        "SN jump -100 (wrap) should be UO-1-SN."
    );

    let decompress_result_neg_jump = engine.decompress(&compressed_jump_neg);
    match decompress_result_neg_jump {
        Err(RohcError::Parsing(RohcParsingError::CrcMismatch { .. })) => {
            // Expected: Compressor used its TS context (10100) for CRC,
            // decompressor used its context (10000).
        }
        Ok(h) => panic!(
            "Expected CrcMismatch for SN jump with diverging TS context for CRC, but got Ok({:?})",
            h
        ),
        Err(e) => panic!(
            "Expected CrcMismatch, but got other error: {:?}. Decomp TS context was 10000.",
            e
        ),
    }
}

#[test]
fn p1_uo1_sn_prefered_over_uo0_for_larger_sn_diff() {
    let mut engine = create_test_engine_with_system_clock(100);
    engine
        .register_profile_handler(Box::new(Profile1Handler::new()))
        .unwrap();
    let cid = 0u16;
    let ssrc = 0xBBCCDDFF;

    let initial_sn = 500;
    let initial_ts = 6000;
    let initial_marker = false;

    establish_ir_context(
        &mut engine,
        cid,
        initial_sn,
        initial_ts,
        initial_marker,
        ssrc,
    );
    let ip_id_from_ir = get_ip_id_established_by_ir(initial_sn, ssrc);

    // First UO packet: UO-0 (SN diff 15)
    let sn_uo0_max = initial_sn + 15;
    let headers_uo0 =
        create_rtp_headers(sn_uo0_max, initial_ts, initial_marker, ssrc).with_ip_id(ip_id_from_ir); // Match IR context for UO-0

    let compressed_uo0 = engine
        .compress(
            cid,
            Some(RohcProfile::RtpUdpIp),
            &GenericUncompressedHeaders::RtpUdpIpv4(headers_uo0.clone()),
        )
        .unwrap();
    assert_eq!(compressed_uo0.len(), 1, "SN diff 15 should be UO-0.");
    let _ = engine.decompress(&compressed_uo0).unwrap();
    // Compressor context now: SN=sn_uo0_max, TS=initial_ts, IP-ID=ip_id_from_ir

    // Second UO packet: UO-1-SN (SN diff 16 from previous UO-0's SN)
    let sn_force_uo1 = sn_uo0_max + 16; // SN = 500 + 15 + 16 = 531
    // Uncompressed TS changes. IP-ID will naturally change due to SN change in create_rtp_headers.
    // The jump in IP-ID from ip_id_from_ir to the new IP-ID must not be > max_safe_delta.
    // IP-ID(IR) = 500 + (ssrc LSB)
    // IP-ID(UO-1) = 531 + (ssrc LSB)
    // Diff = 31, which is < 128. So UO-1-SN is expected, not IR.
    let headers_uo1 = create_rtp_headers(sn_force_uo1, initial_ts + 20, initial_marker, ssrc);

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
        "SN diff 16 (from {}) should be UO-1-SN. Got: {:?}",
        sn_uo0_max,
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
    // UO-1-SN uses context TS from the previous packet (UO-0), which was initial_ts.
    assert_eq!(decomp_uo1.rtp_timestamp, initial_ts);
}
