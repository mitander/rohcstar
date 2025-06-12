//! Integration tests for ROHC Profile 1 IR (Initialization and Refresh) packet handling.
//!
//! This module tests the generation, parsing, and processing of IR packets, which are
//! used to establish and refresh compression contexts. Tests cover error conditions,
//! context state management, CID handling, and robustness scenarios.

use std::sync::Arc;
use std::time::Instant;

use super::common::{
    DEFAULT_ENGINE_TEST_TIMEOUT, create_ir_packet_data, create_rtp_headers,
    create_test_engine_with_system_clock, establish_ir_context, get_compressor_context,
    get_decompressor_context, get_ip_id_established_by_ir,
};

use rohcstar::ProfileHandler;
use rohcstar::crc::CrcCalculators;
use rohcstar::engine::RohcEngine;
use rohcstar::error::{DecompressionError, RohcBuildingError, RohcError, RohcParsingError};
use rohcstar::packet_defs::{GenericUncompressedHeaders, RohcProfile};
use rohcstar::profiles::profile1::context::{
    Profile1CompressorContext, Profile1CompressorMode, Profile1DecompressorContext,
    Profile1DecompressorMode,
};
use rohcstar::profiles::profile1::serialize_ir;
use rohcstar::profiles::profile1::{
    P1_ROHC_IR_PACKET_TYPE_STATIC_ONLY, P1_ROHC_IR_PACKET_TYPE_WITH_DYN,
    P1_STATIC_CHAIN_LENGTH_BYTES, Profile1Handler,
};
use rohcstar::time::SystemClock;

/// Verifies that an IR packet with a modified CRC fails parsing with a CrcMismatch error.
#[test]
fn p1_ir_packet_with_corrupted_crc_fails() {
    let handler = Profile1Handler::new();
    let test_crc_calculators = CrcCalculators::new();
    let mut decomp_ctx_dyn = handler.create_decompressor_context(0.into(), Instant::now());

    let ir_data = create_ir_packet_data(0, 0x12345678, 100, 1000);
    let mut ir_packet_buf = [0u8; 64];
    let ir_packet_len = serialize_ir(&ir_data, &test_crc_calculators, &mut ir_packet_buf).unwrap();
    let ir_packet_bytes = &mut ir_packet_buf[..ir_packet_len];

    let crc_index = ir_packet_bytes.len() - 1;
    ir_packet_bytes[crc_index] = ir_packet_bytes[crc_index].wrapping_add(1);

    let result = handler.decompress(decomp_ctx_dyn.as_mut(), ir_packet_bytes);

    match result {
        Err(RohcError::Parsing(RohcParsingError::CrcMismatch { .. })) => {}
        _ => panic!("Expected CRC mismatch error, got: {:?}", result),
    }
}

/// Tests that an IR packet with an incorrect Profile ID (but correct CRC for that modified payload)
/// fails parsing with an InvalidProfileId error.
#[test]
fn p1_ir_packet_with_wrong_profile_id_fails() {
    let handler = Profile1Handler::new();
    let test_crc_calculators = CrcCalculators::new();
    let mut decomp_ctx_dyn = handler.create_decompressor_context(0.into(), Instant::now());

    let ir_data = create_ir_packet_data(0, 0x12345678, 100, 1000);
    let mut ir_packet_buf = [0u8; 64];
    let ir_packet_len = serialize_ir(&ir_data, &test_crc_calculators, &mut ir_packet_buf).unwrap();
    let ir_packet_bytes = &mut ir_packet_buf[..ir_packet_len];

    if ir_packet_bytes.len() > 1 {
        ir_packet_bytes[1] = RohcProfile::UdpIp.into();

        // Recalculate CRC for modified payload
        let crc_payload_slice = &ir_packet_bytes[1..ir_packet_bytes.len() - 1];
        let new_crc = test_crc_calculators.crc8(crc_payload_slice);
        *ir_packet_bytes.last_mut().unwrap() = new_crc;
    } else {
        panic!("Generated IR packet is too short to modify profile ID.");
    }

    let result = handler.decompress(decomp_ctx_dyn.as_mut(), ir_packet_bytes);
    match result {
        Err(RohcError::Parsing(RohcParsingError::InvalidProfileId(id))) => {
            assert_eq!(id, u8::from(RohcProfile::UdpIp));
        }
        _ => panic!("Expected InvalidProfileId error, got: {:?}", result),
    }
}

/// Checks that attempting to parse IR packets that are too short (truncated) results
/// in a NotEnoughData error. Also tests with an empty byte slice.
#[test]
fn p1_ir_packet_too_short_fails() {
    let handler = Profile1Handler::new();
    let test_crc_calculators = CrcCalculators::new();
    let mut decomp_ctx_dyn = handler.create_decompressor_context(0.into(), Instant::now());

    let ir_data = create_ir_packet_data(0, 0x12345678, 100, 1000);
    let mut ir_packet_buf_full = [0u8; 64];
    let ir_packet_full_len =
        serialize_ir(&ir_data, &test_crc_calculators, &mut ir_packet_buf_full).unwrap();
    let ir_packet_bytes_full = &ir_packet_buf_full[..ir_packet_full_len];
    // Minimum IR-STATIC length: Type + Profile + Static Chain + CRC
    let min_valid_ir_len = 1 + 1 + P1_STATIC_CHAIN_LENGTH_BYTES + 1;

    for len in 0..ir_packet_bytes_full.len() {
        if len < min_valid_ir_len {
            let truncated_packet = &ir_packet_bytes_full[0..len];
            let result = handler.decompress(decomp_ctx_dyn.as_mut(), truncated_packet);
            match result {
                Err(RohcError::Parsing(RohcParsingError::NotEnoughData { .. })) => {}
                _ => panic!(
                    "Expected NotEnoughData for truncated packet of len {}, got: {:?}. Packet: {:?}",
                    len, result, truncated_packet
                ),
            }
        }
    }

    let result_empty = handler.decompress(decomp_ctx_dyn.as_mut(), &[]);
    match result_empty {
        Err(RohcError::Parsing(RohcParsingError::NotEnoughData { .. })) => {}
        _ => panic!(
            "Expected NotEnoughData for empty packet, got: {:?}. Packet: []",
            result_empty
        ),
    }
}

/// Ensures that static fields in the compressor context remain unchanged after processing
/// subsequent packets with the same SSRC, while dynamic fields are updated.
#[test]
fn p1_compressor_context_static_fields_remain_constant() {
    let handler = Profile1Handler::new();
    let mut comp_ctx_dyn = handler.create_compressor_context(0.into(), 5, Instant::now());

    let ssrc1 = 0x11111111;
    let headers1 = create_rtp_headers(100, 1000, false, ssrc1);
    let generic_headers1 = GenericUncompressedHeaders::RtpUdpIpv4(headers1.clone());

    let mut compress_buf = [0u8; 128];
    let _ = handler
        .compress(comp_ctx_dyn.as_mut(), &generic_headers1, &mut compress_buf)
        .unwrap();

    let comp_ctx_snapshot1 = comp_ctx_dyn
        .as_any()
        .downcast_ref::<Profile1CompressorContext>()
        .unwrap()
        .clone();
    assert_eq!(comp_ctx_snapshot1.rtp_ssrc, ssrc1);
    assert_eq!(comp_ctx_snapshot1.ip_source, headers1.ip_src);
    assert_eq!(comp_ctx_snapshot1.udp_source_port, headers1.udp_src_port);

    for i in 1..=3 {
        let mut headers_next = create_rtp_headers(100 + i, 1000, false, ssrc1);
        headers_next.ip_identification = headers1.ip_identification; // Keep IP ID same for UO-0
        let generic_headers_next = GenericUncompressedHeaders::RtpUdpIpv4(headers_next);
        let _ = handler
            .compress(
                comp_ctx_dyn.as_mut(),
                &generic_headers_next,
                &mut compress_buf,
            )
            .unwrap();

        let comp_ctx_current = comp_ctx_dyn
            .as_any()
            .downcast_ref::<Profile1CompressorContext>()
            .unwrap();

        assert_eq!(comp_ctx_current.rtp_ssrc, ssrc1);
        assert_eq!(comp_ctx_current.ip_source, headers1.ip_src);
        assert_eq!(comp_ctx_current.udp_source_port, headers1.udp_src_port);

        assert_eq!(comp_ctx_current.last_sent_rtp_sn_full, 100 + i);
    }
}

/// Validates that the decompressor remains in NoContext mode and returns an InvalidState error
/// if it receives a non-IR packet (e.g., UO-0) before a context is established.
#[test]
fn p1_decompressor_stays_in_no_context_without_ir() {
    let handler = Profile1Handler::new();
    let mut decomp_ctx_dyn = handler.create_decompressor_context(0.into(), Instant::now());
    let uo0_packet_bytes = vec![0x09]; // A valid UO-0 packet for SN LSB 1, CRC3 1
    let result = handler.decompress(decomp_ctx_dyn.as_mut(), &uo0_packet_bytes);

    match result {
        Err(RohcError::Decompression(DecompressionError::InvalidPacketType {
            cid,
            packet_type,
        })) => {
            assert_eq!(cid, 0);
            assert_eq!(packet_type, 0x09);
        }
        _ => panic!(
            "Expected InvalidPacketType error for UO packet in NoContext, got: {:?}",
            result
        ),
    }

    let decomp_ctx = decomp_ctx_dyn
        .as_any()
        .downcast_ref::<Profile1DecompressorContext>()
        .unwrap();
    assert_eq!(
        decomp_ctx.mode,
        Profile1DecompressorMode::NoContext,
        "Decompressor mode should remain NoContext"
    );
}

/// Tests that the IR packet builder rejects CIDs larger than 15, as it currently
/// only supports Add-CID encoding for small CIDs (1-15) or implicit CID 0.
#[test]
fn p1_ir_packet_large_cid_not_supported_by_builder() {
    let test_crc_calculators = CrcCalculators::new();
    let large_cid = 16u16; // CID > 15
    let ir_data = create_ir_packet_data(large_cid, 0x12345678, 100, 1000);

    let mut ir_buf = [0u8; 64];
    let result = serialize_ir(&ir_data, &test_crc_calculators, &mut ir_buf);
    match result {
        Err(RohcBuildingError::InvalidFieldValueForBuild {
            field,
            value,
            max_bits,
        }) => {
            assert_eq!(field, rohcstar::error::Field::Cid);
            assert_eq!(value, large_cid as u32);
            assert_eq!(max_bits, 4);
        }
        _ => panic!(
            "Expected InvalidFieldValueForBuild for large CID, got {:?}.",
            result
        ),
    }
}

/// Verifies that the ROHC engine can manage multiple Profile 1 flows with different CIDs,
/// maintaining separate contexts and ensuring correct compression/decompression for each.
#[test]
fn p1_multiple_flows_different_cids() {
    let mut engine = create_test_engine_with_system_clock(5);
    engine
        .register_profile_handler(Box::new(Profile1Handler::new()))
        .unwrap();

    let cid1: u16 = 1;
    let ssrc1: u32 = 0xAAAA1111;
    let headers1_flow1 = create_rtp_headers(10, 100, false, ssrc1);
    let generic1_flow1 = GenericUncompressedHeaders::RtpUdpIpv4(headers1_flow1.clone());

    let mut compress_buf1_flow1 = [0u8; 128];
    let compress_len1_flow1 = engine
        .compress(
            cid1.into(),
            Some(RohcProfile::RtpUdpIp),
            &generic1_flow1,
            &mut compress_buf1_flow1,
        )
        .unwrap();
    let compressed1_flow1 = &compress_buf1_flow1[..compress_len1_flow1];
    assert_eq!(
        compressed1_flow1[0],
        rohcstar::constants::ROHC_ADD_CID_FEEDBACK_PREFIX_VALUE | cid1 as u8
    );
    assert_eq!(compressed1_flow1[1], P1_ROHC_IR_PACKET_TYPE_WITH_DYN);
    let _ = engine.decompress(compressed1_flow1).unwrap();

    let cid2: u16 = 2;
    let ssrc2: u32 = 0xBBBB2222;
    let headers1_flow2 = create_rtp_headers(50, 500, true, ssrc2);
    let generic1_flow2 = GenericUncompressedHeaders::RtpUdpIpv4(headers1_flow2.clone());

    let mut compress_buf1_flow2 = [0u8; 128];
    let compress_len1_flow2 = engine
        .compress(
            cid2.into(),
            Some(RohcProfile::RtpUdpIp),
            &generic1_flow2,
            &mut compress_buf1_flow2,
        )
        .unwrap();
    let compressed1_flow2 = &compress_buf1_flow2[..compress_len1_flow2];
    assert_eq!(
        compressed1_flow2[0],
        rohcstar::constants::ROHC_ADD_CID_FEEDBACK_PREFIX_VALUE | cid2 as u8
    );
    assert_eq!(compressed1_flow2[1], P1_ROHC_IR_PACKET_TYPE_WITH_DYN);
    let _ = engine.decompress(compressed1_flow2).unwrap();

    assert_eq!(engine.context_manager().compressor_context_count(), 2);
    assert_eq!(engine.context_manager().decompressor_context_count(), 2);

    let comp_ctx_cid1 = get_compressor_context(&engine, cid1);
    let ip_id_in_cid1_context = get_ip_id_established_by_ir(
        headers1_flow1.rtp_sequence_number.into(),
        *headers1_flow1.rtp_ssrc,
    );
    assert_eq!(comp_ctx_cid1.last_sent_ip_id_full, ip_id_in_cid1_context);

    let sn2_flow1 = headers1_flow1.rtp_sequence_number.wrapping_add(1);
    let ts2_flow1_val = headers1_flow1.rtp_timestamp.value();
    let marker2_flow1 = headers1_flow1.rtp_marker;

    let headers2_flow1 = create_rtp_headers(*sn2_flow1, ts2_flow1_val, marker2_flow1, ssrc1)
        .with_ip_id(ip_id_in_cid1_context.into()); // IP-ID same for UO-0

    let generic2_flow1 = GenericUncompressedHeaders::RtpUdpIpv4(headers2_flow1.clone());
    let mut compress_buf2_flow1 = [0u8; 128];
    let compress_len2_flow1 = engine
        .compress(
            cid1.into(),
            Some(RohcProfile::RtpUdpIp),
            &generic2_flow1,
            &mut compress_buf2_flow1,
        )
        .unwrap();
    let compressed2_flow1 = &compress_buf2_flow1[..compress_len2_flow1];

    assert_eq!(compressed2_flow1.len(), 2); // Add-CID + UO-0 byte
    assert_eq!(
        compressed2_flow1[0],
        rohcstar::constants::ROHC_ADD_CID_FEEDBACK_PREFIX_VALUE | cid1 as u8
    );
    assert_eq!(compressed2_flow1[1] & 0x80, 0x00); // UO-0 discriminator check

    let decompressed2_flow1_generic = engine.decompress(compressed2_flow1).unwrap();
    let decompressed2_flow1 = decompressed2_flow1_generic.as_rtp_udp_ipv4().unwrap();

    assert_eq!(decompressed2_flow1.rtp_ssrc, ssrc1);
    assert_eq!(decompressed2_flow1.rtp_sequence_number, sn2_flow1);
    assert_eq!(decompressed2_flow1.rtp_marker, marker2_flow1);
    assert_eq!(decompressed2_flow1.rtp_timestamp, ts2_flow1_val);
    assert_eq!(
        decompressed2_flow1.ip_identification,
        headers2_flow1.ip_identification
    ); // IP-ID reconstructed from context
}

/// Tests that a change in SSRC forces the compressor to reinitialize context and send an IR packet.
#[test]
fn p1_ssrc_change_forces_context_reinitialization_and_ir() {
    let handler = Profile1Handler::new();
    let mut comp_ctx_dyn = handler.create_compressor_context(0.into(), 5, Instant::now());

    let ssrc1 = 0xAAAA0001;
    let headers1 = create_rtp_headers(200, 2000, false, ssrc1);
    let generic1 = GenericUncompressedHeaders::RtpUdpIpv4(headers1.clone());

    let mut compress_buf = [0u8; 128];
    let compress_len = handler
        .compress(comp_ctx_dyn.as_mut(), &generic1, &mut compress_buf)
        .unwrap();
    let compressed1 = &compress_buf[..compress_len];
    assert_eq!(compressed1[0], P1_ROHC_IR_PACKET_TYPE_WITH_DYN);
    let comp_ctx1 = comp_ctx_dyn
        .as_any()
        .downcast_ref::<Profile1CompressorContext>()
        .unwrap();
    assert_eq!(comp_ctx1.rtp_ssrc, ssrc1);
    assert_eq!(comp_ctx1.mode, Profile1CompressorMode::FirstOrder);

    let mut headers2 = create_rtp_headers(201, 2000, false, ssrc1);
    headers2.ip_identification = headers1.ip_identification;
    let generic2 = GenericUncompressedHeaders::RtpUdpIpv4(headers2);
    let mut compress_buf2 = [0u8; 128];
    let compress_len2 = handler
        .compress(comp_ctx_dyn.as_mut(), &generic2, &mut compress_buf2)
        .unwrap();
    let compressed2 = &compress_buf2[..compress_len2];
    assert_ne!(compressed2[0], P1_ROHC_IR_PACKET_TYPE_WITH_DYN);
    let ssrc2 = 0xBBBB0002;
    let headers3 = create_rtp_headers(10, 100, true, ssrc2);
    let generic3 = GenericUncompressedHeaders::RtpUdpIpv4(headers3.clone());
    let mut compress_buf3 = [0u8; 128];
    let compress_len3 = handler
        .compress(comp_ctx_dyn.as_mut(), &generic3, &mut compress_buf3)
        .unwrap();
    let compressed3 = &compress_buf3[..compress_len3];

    assert_eq!(compressed3[0], P1_ROHC_IR_PACKET_TYPE_WITH_DYN); // IR due to SSRC change
    let comp_ctx3 = comp_ctx_dyn
        .as_any()
        .downcast_ref::<Profile1CompressorContext>()
        .unwrap();
    assert_eq!(comp_ctx3.rtp_ssrc, ssrc2);
    assert_eq!(comp_ctx3.last_sent_rtp_sn_full, 10);
    assert_eq!(comp_ctx3.mode, Profile1CompressorMode::FirstOrder);
    assert_eq!(comp_ctx3.fo_packets_sent_since_ir, 0);
}

/// Tests IR refresh behavior with different `ir_refresh_interval` settings.
#[test]
fn p1_ir_refresh_interval_edge_cases() {
    let handler = Profile1Handler::new();
    let ssrc = 0xCCCC0001;

    let mut comp_ctx_dyn_0 = handler.create_compressor_context(0.into(), 0, Instant::now());
    let headers_ir0 = create_rtp_headers(1, 10, false, ssrc);
    let generic_ir0 = GenericUncompressedHeaders::RtpUdpIpv4(headers_ir0.clone());
    let mut compress_buf = [0u8; 128];
    let _ = handler
        .compress(comp_ctx_dyn_0.as_mut(), &generic_ir0, &mut compress_buf)
        .unwrap();
    let mut last_ip_id = headers_ir0.ip_identification;

    for i in 2..=10 {
        // Send 9 UO packets
        let mut headers_uo = create_rtp_headers(i, 10, false, ssrc);
        headers_uo.ip_identification = last_ip_id;
        let mut compress_buf_uo = [0u8; 128];
        let compress_len_uo = handler
            .compress(
                comp_ctx_dyn_0.as_mut(),
                &GenericUncompressedHeaders::RtpUdpIpv4(headers_uo.clone()),
                &mut compress_buf_uo,
            )
            .unwrap();
        let compressed = &compress_buf_uo[..compress_len_uo];
        assert_ne!(compressed[0], P1_ROHC_IR_PACKET_TYPE_WITH_DYN); // Should all be UO
        last_ip_id = headers_uo.ip_identification;
    }
    let comp_ctx_0 = comp_ctx_dyn_0
        .as_any()
        .downcast_ref::<Profile1CompressorContext>()
        .unwrap();
    assert_eq!(comp_ctx_0.fo_packets_sent_since_ir, 9); // Counter still increments

    // Test with ir_refresh_interval = 1 (every packet is IR after initial)
    let mut comp_ctx_dyn_1 = handler.create_compressor_context(0.into(), 1, Instant::now());
    let headers_ir1_1 = create_rtp_headers(101, 1010, false, ssrc);
    let mut compress_buf_ir1_1 = [0u8; 128];
    let compress_len_ir1_1 = handler
        .compress(
            comp_ctx_dyn_1.as_mut(),
            &GenericUncompressedHeaders::RtpUdpIpv4(headers_ir1_1),
            &mut compress_buf_ir1_1,
        )
        .unwrap();
    let compressed_ir1_1 = &compress_buf_ir1_1[..compress_len_ir1_1];
    assert_eq!(compressed_ir1_1[0], P1_ROHC_IR_PACKET_TYPE_WITH_DYN); // Initial IR
    let comp_ctx_1_after_p1 = comp_ctx_dyn_1
        .as_any()
        .downcast_ref::<Profile1CompressorContext>()
        .unwrap();
    assert_eq!(comp_ctx_1_after_p1.fo_packets_sent_since_ir, 0);

    let headers_ir1_2 = create_rtp_headers(102, 1020, false, ssrc); // Next packet
    let mut compress_buf_ir1_2 = [0u8; 128];
    let compress_len_ir1_2 = handler
        .compress(
            comp_ctx_dyn_1.as_mut(),
            &GenericUncompressedHeaders::RtpUdpIpv4(headers_ir1_2),
            &mut compress_buf_ir1_2,
        )
        .unwrap();
    let compressed_ir1_2 = &compress_buf_ir1_2[..compress_len_ir1_2];
    assert_eq!(compressed_ir1_2[0], P1_ROHC_IR_PACKET_TYPE_WITH_DYN); // Should be IR due to interval=1
    let comp_ctx_1_after_p2 = comp_ctx_dyn_1
        .as_any()
        .downcast_ref::<Profile1CompressorContext>()
        .unwrap();
    assert_eq!(comp_ctx_1_after_p2.fo_packets_sent_since_ir, 0);

    // Test with a larger interval
    let large_interval = 3u32;
    let mut comp_ctx_dyn_large =
        handler.create_compressor_context(0.into(), large_interval, Instant::now());
    let headers_ir_large_init = create_rtp_headers(201, 2010, false, ssrc);
    let mut compress_buf_large_init = [0u8; 128];
    let _ = handler
        .compress(
            comp_ctx_dyn_large.as_mut(),
            &GenericUncompressedHeaders::RtpUdpIpv4(headers_ir_large_init.clone()),
            &mut compress_buf_large_init,
        )
        .unwrap(); // Initial IR
    last_ip_id = headers_ir_large_init.ip_identification;

    for i in 1..=(large_interval - 1) {
        // Send `large_interval - 1` UO packets
        let current_sn = 201 + i as u16;
        let mut headers_uo = create_rtp_headers(current_sn, 2010, false, ssrc);
        headers_uo.ip_identification = last_ip_id;
        let mut compress_buf_large_uo = [0u8; 128];
        let compress_len_large_uo = handler
            .compress(
                comp_ctx_dyn_large.as_mut(),
                &GenericUncompressedHeaders::RtpUdpIpv4(headers_uo.clone()),
                &mut compress_buf_large_uo,
            )
            .unwrap();
        let compressed = &compress_buf_large_uo[..compress_len_large_uo];
        assert_ne!(compressed[0], P1_ROHC_IR_PACKET_TYPE_WITH_DYN); // Should be UO
        last_ip_id = headers_uo.ip_identification;
    }
    let comp_ctx_large_before_refresh = comp_ctx_dyn_large
        .as_any()
        .downcast_ref::<Profile1CompressorContext>()
        .unwrap();
    assert_eq!(
        comp_ctx_large_before_refresh.fo_packets_sent_since_ir,
        large_interval - 1
    );

    // Next packet should trigger IR refresh
    let headers_refresh_ir = create_rtp_headers(
        201 + large_interval as u16,  // SN = 201 + 3 = 204
        2010 + (large_interval * 10), // Different TS to ensure it's not other IR trigger
        false,
        ssrc,
    );
    let mut compress_buf_refresh_ir = [0u8; 128];
    let compress_len_refresh_ir = handler
        .compress(
            comp_ctx_dyn_large.as_mut(),
            &GenericUncompressedHeaders::RtpUdpIpv4(headers_refresh_ir),
            &mut compress_buf_refresh_ir,
        )
        .unwrap();
    let compressed_refresh_ir = &compress_buf_refresh_ir[..compress_len_refresh_ir];
    assert_eq!(compressed_refresh_ir[0], P1_ROHC_IR_PACKET_TYPE_WITH_DYN); // IR refresh
    let comp_ctx_large_after_refresh = comp_ctx_dyn_large
        .as_any()
        .downcast_ref::<Profile1CompressorContext>()
        .unwrap();
    assert_eq!(comp_ctx_large_after_refresh.fo_packets_sent_since_ir, 0);
}

/// Tests parsing of an IR-STATIC packet (D-bit = 0), ensuring dynamic fields are zeroed.
#[test]
fn p1_ir_packet_with_static_only_d_bit_0_parse_successfully() {
    let handler = Profile1Handler::new();
    let test_crc_calculators = CrcCalculators::new();
    let mut decomp_ctx_dyn = handler.create_decompressor_context(0.into(), Instant::now());

    // Manually construct IR-STATIC packet bytes
    let ir_data_for_static_part = create_ir_packet_data(0, 0xFEEDF00D, 10, 100); // Dyn values are placeholders
    let mut ir_packet_bytes = Vec::new();

    ir_packet_bytes.push(P1_ROHC_IR_PACKET_TYPE_STATIC_ONLY); // D-bit = 0
    ir_packet_bytes.push(RohcProfile::RtpUdpIp.into());
    ir_packet_bytes.extend_from_slice(&ir_data_for_static_part.static_ip_src.octets());
    ir_packet_bytes.extend_from_slice(&ir_data_for_static_part.static_ip_dst.octets());
    ir_packet_bytes.extend_from_slice(&ir_data_for_static_part.static_udp_src_port.to_be_bytes());
    ir_packet_bytes.extend_from_slice(&ir_data_for_static_part.static_udp_dst_port.to_be_bytes());
    ir_packet_bytes.extend_from_slice(&ir_data_for_static_part.static_rtp_ssrc.to_be_bytes());
    ir_packet_bytes.extend_from_slice(
        &ir_data_for_static_part
            .static_rtp_payload_type
            .to_be_bytes(),
    );
    ir_packet_bytes.push(ir_data_for_static_part.static_rtp_extension.into());
    ir_packet_bytes.push(ir_data_for_static_part.static_rtp_padding.into());

    // CRC for IR-STATIC is over Profile ID + Static Chain
    let crc_payload_slice = &ir_packet_bytes[1..]; // Skip Type, include Profile + Static
    assert_eq!(crc_payload_slice.len(), 1 + P1_STATIC_CHAIN_LENGTH_BYTES);
    let crc = test_crc_calculators.crc8(crc_payload_slice);
    ir_packet_bytes.push(crc);

    assert_eq!(
        ir_packet_bytes.len(),
        1 + 1 + P1_STATIC_CHAIN_LENGTH_BYTES + 1 // Type + Profile + Static + CRC
    );

    let result = handler.decompress(decomp_ctx_dyn.as_mut(), &ir_packet_bytes);
    match result {
        Ok(GenericUncompressedHeaders::RtpUdpIpv4(h)) => {
            assert_eq!(h.rtp_ssrc, ir_data_for_static_part.static_rtp_ssrc);
            // Dynamic fields should be zeroed/default for IR-STATIC
            assert_eq!(h.rtp_sequence_number, 0);
            assert_eq!(h.rtp_timestamp, 0);
            assert!(!h.rtp_marker);
        }
        Ok(other) => panic!(
            "Expected RtpUdpIpv4, but got unexpected Ok variant: {:?}",
            other
        ),
        Err(e) => panic!("Expected successful parse for static-only IR. Got: {:?}", e),
    }
}

/// Verifies that the decompressor context correctly updates and persists across multiple IR packets,
/// reflecting the latest received static and dynamic information.
#[test]
fn p1_decompressor_context_persistence_across_ir_packets() {
    let mut engine = create_test_engine_with_system_clock(10);
    engine
        .register_profile_handler(Box::new(Profile1Handler::new()))
        .unwrap();
    let cid = 0u16;

    // First IR packet
    let ssrc1 = 0xABCDE001;
    establish_ir_context(&mut engine, cid, 10, 100, false, ssrc1);
    let ip_id_from_ir1 = get_ip_id_established_by_ir(10, ssrc1);

    let decomp_ctx1 = get_decompressor_context(&engine, cid);
    assert_eq!(decomp_ctx1.mode, Profile1DecompressorMode::FullContext);
    assert_eq!(decomp_ctx1.rtp_ssrc, ssrc1);
    assert_eq!(decomp_ctx1.last_reconstructed_rtp_sn_full, 10);
    assert_eq!(decomp_ctx1.last_reconstructed_rtp_ts_full, 100,);
    assert!(!decomp_ctx1.last_reconstructed_rtp_marker);

    // Send a UO packet to confirm FC state
    let headers_uo = create_rtp_headers(11, 100, false, ssrc1).with_ip_id(ip_id_from_ir1.into());
    let generic_uo = GenericUncompressedHeaders::RtpUdpIpv4(headers_uo);
    let mut compress_buf_uo = [0u8; 128];
    let compress_len_uo = engine
        .compress(
            cid.into(),
            Some(RohcProfile::RtpUdpIp),
            &generic_uo,
            &mut compress_buf_uo,
        )
        .unwrap();
    let compressed_uo = &compress_buf_uo[..compress_len_uo];
    let _ = engine.decompress(compressed_uo).unwrap();

    // Second IR packet with different SSRC and dynamic values
    let ssrc2 = 0xABCDE002;
    establish_ir_context(&mut engine, cid, 50, 500, true, ssrc2);

    let decomp_ctx2 = get_decompressor_context(&engine, cid);
    assert_eq!(decomp_ctx2.mode, Profile1DecompressorMode::FullContext); // Should reset to FC
    assert_eq!(decomp_ctx2.rtp_ssrc, ssrc2);
    assert_eq!(decomp_ctx2.last_reconstructed_rtp_sn_full, 50);
    assert_eq!(decomp_ctx2.last_reconstructed_rtp_ts_full, 500,);
    assert!(decomp_ctx2.last_reconstructed_rtp_marker);
    assert_eq!(decomp_ctx2.counters.fc_crc_failures, 0); // Reset on IR
}

/// Performance test for IR packet compression and decompression.
/// Marked as `ignore` as it's for manual runs and benchmarking, not CI.
#[test]
#[ignore]
fn p1_ir_packet_processing_performance() {
    let mut engine = RohcEngine::new(
        u32::MAX, // Large interval to mostly force unique IRs if SSRC changes
        DEFAULT_ENGINE_TEST_TIMEOUT,
        Arc::new(SystemClock),
    );
    engine
        .register_profile_handler(Box::new(Profile1Handler::new()))
        .unwrap();

    let num_packets = 1_000;
    let mut uncompressed_packets = Vec::with_capacity(num_packets);
    for i in 0..num_packets {
        // Vary SSRC to ensure new IR contexts are created (or at least full IR packets are sent)
        let headers = create_rtp_headers(i as u16, (i * 10) as u32, false, 0x12345000 + i as u32);
        uncompressed_packets.push(GenericUncompressedHeaders::RtpUdpIpv4(headers));
    }

    let mut compressed_packets = Vec::with_capacity(num_packets);

    let start_compress = Instant::now();
    (0..num_packets).for_each(|i| {
        let cid = i as u16; // Use unique CIDs to force new context creation
        let mut compress_buf_perf = [0u8; 128];
        let compress_len_perf = engine
            .compress(
                cid.into(),
                Some(RohcProfile::RtpUdpIp),
                &uncompressed_packets[i],
                &mut compress_buf_perf,
            )
            .unwrap();
        let compressed = compress_buf_perf[..compress_len_perf].to_vec();
        compressed_packets.push(compressed);
    });
    let compress_duration = start_compress.elapsed();
    println!(
        "IR Compression: {} packets in {:?}, {:.2} packets/sec",
        num_packets,
        compress_duration,
        num_packets as f64 / compress_duration.as_secs_f64()
    );

    let start_decompress = Instant::now();
    (0..num_packets).for_each(|i| {
        // Decompressing with unique CIDs means new decompressor contexts too
        let _ = engine.decompress(&compressed_packets[i]).unwrap();
    });
    let decompress_duration = start_decompress.elapsed();
    println!(
        "IR Decompression: {} packets in {:?}, {:.2} packets/sec",
        num_packets,
        decompress_duration,
        num_packets as f64 / decompress_duration.as_secs_f64()
    );

    // These thresholds are arbitrary and might need adjustment based on machine specs
    assert!(compress_duration.as_millis() < 200, "Compression too slow");
    assert!(
        decompress_duration.as_millis() < 200,
        "Decompression too slow"
    );
}
