//! Tests for packet decompression variants.

use super::super::constants::*;
use super::super::context::Profile1DecompressorContext;
use super::super::packet_types::Uo1Packet;
use super::super::serialization::uo1_packets::{
    prepare_generic_uo_crc_input_payload, prepare_uo1_id_specific_crc_input_payload,
    serialize_uo1_id, serialize_uo1_rtp, serialize_uo1_sn, serialize_uo1_ts,
};
use super::{
    decompress_as_uo1_id, decompress_as_uo1_rtp, decompress_as_uo1_sn, decompress_as_uo1_ts,
};
use crate::crc::CrcCalculators;
use crate::encodings::encode_lsb;
use crate::types::{ContextId, IpId, SequenceNumber, Timestamp};

fn create_test_context(
    sequence_number: u16,
    timestamp: u32,
    ssrc: u32,
) -> Profile1DecompressorContext {
    let mut context = Profile1DecompressorContext::new(ContextId::new(0));
    context.last_reconstructed_rtp_sn_full = SequenceNumber::new(sequence_number);
    context.last_reconstructed_rtp_ts_full = Timestamp::new(timestamp);
    context.rtp_ssrc = ssrc.into();
    context.ts_stride = Some(160u32);
    context
}

#[test]
fn uo1_sn_decompression_basic_sequence_number_update() {
    let crc_calculators = CrcCalculators::new();
    let mut context = create_test_context(100, 16000, 0x12345678);

    let target_sequence_number = SequenceNumber::new(105);
    let target_timestamp = Timestamp::new(16800); // 105 - 100 = 5, 5 * 160 = 800, 16000 + 800 = 16800

    // Calculate correct CRC
    let crc_input_bytes = prepare_generic_uo_crc_input_payload(
        context.rtp_ssrc,
        target_sequence_number,
        target_timestamp,
        true, // marker
    );
    let calculated_crc8 = crc_calculators.crc8(&crc_input_bytes);

    let uo1_packet = Uo1Packet {
        sn_lsb: encode_lsb(target_sequence_number.as_u64(), P1_UO1_SN_LSB_WIDTH_DEFAULT).unwrap()
            as u16,
        num_sn_lsb_bits: P1_UO1_SN_LSB_WIDTH_DEFAULT,
        marker: true,
        crc8: calculated_crc8,
        ..Default::default()
    };

    let mut packet_buffer = [0u8; 8];
    let packet_length = serialize_uo1_sn(&uo1_packet, &mut packet_buffer).unwrap();

    let result = decompress_as_uo1_sn(
        &mut context,
        &packet_buffer[..packet_length],
        &crc_calculators,
    );

    assert!(result.is_ok(), "UO-1-SN decompression should succeed");
    let headers = result.unwrap();
    assert_eq!(
        headers.rtp_sequence_number.value(),
        target_sequence_number.value(),
        "Sequence number should be correctly reconstructed"
    );
}

#[test]
fn uo1_ts_decompression_explicit_timestamp_handling() {
    let crc_calculators = CrcCalculators::new();
    let mut context = create_test_context(200, 32000, 0x87654321);

    let target_timestamp = Timestamp::new(35000);
    let ts_lsb = (target_timestamp.value() & 0xFFFF) as u16; // 16-bit LSB
    let expected_sn = context.last_reconstructed_rtp_sn_full.wrapping_add(1);

    // Calculate correct CRC
    let crc_input_bytes = prepare_generic_uo_crc_input_payload(
        context.rtp_ssrc,
        expected_sn,
        target_timestamp,
        context.last_reconstructed_rtp_marker, // UO-1-TS implies marker unchanged
    );
    let calculated_crc8 = crc_calculators.crc8(&crc_input_bytes);

    let uo1_packet = Uo1Packet {
        ts_lsb: Some(ts_lsb),
        num_ts_lsb_bits: Some(16),
        crc8: calculated_crc8,
        ..Default::default()
    };

    let mut packet_buffer = [0u8; 8];
    let packet_length = serialize_uo1_ts(&uo1_packet, &mut packet_buffer).unwrap();

    let result = decompress_as_uo1_ts(
        &mut context,
        &packet_buffer[..packet_length],
        &crc_calculators,
    );

    assert!(result.is_ok(), "UO-1-TS decompression should succeed");
    let headers = result.unwrap();
    assert_eq!(
        headers.rtp_timestamp.value(),
        target_timestamp.value(),
        "Timestamp should be explicitly reconstructed"
    );
}

#[test]
fn uo1_id_decompression_ip_identification_reconstruction() {
    let crc_calculators = CrcCalculators::new();
    let mut context = create_test_context(300, 48000, 0x55667788);

    // Set IP-ID reference for proper LSB decoding
    context.last_reconstructed_ip_id_full = IpId::new(0x1200);

    let target_ip_id = IpId::new(0x1234);
    let ip_id_lsb = encode_lsb(target_ip_id.as_u64(), P1_UO1_IP_ID_LSB_WIDTH_DEFAULT).unwrap();
    let expected_sn = context.last_reconstructed_rtp_sn_full.wrapping_add(1);
    let expected_ts = super::recovery::calculate_reconstructed_ts_implicit(&context, expected_sn);

    // Calculate correct CRC using UO-1-ID specific function
    let crc_input_bytes = prepare_uo1_id_specific_crc_input_payload(
        context.rtp_ssrc,
        expected_sn,
        expected_ts,
        context.last_reconstructed_rtp_marker,
        ip_id_lsb as u8,
    );
    let calculated_crc8 = crc_calculators.crc8(&crc_input_bytes);

    let uo1_packet = Uo1Packet {
        ip_id_lsb: Some(ip_id_lsb as u16),
        num_ip_id_lsb_bits: Some(P1_UO1_IP_ID_LSB_WIDTH_DEFAULT),
        crc8: calculated_crc8,
        ..Default::default()
    };

    let mut packet_buffer = [0u8; 8];
    let packet_length = serialize_uo1_id(&uo1_packet, &mut packet_buffer).unwrap();

    let result = decompress_as_uo1_id(
        &mut context,
        &packet_buffer[..packet_length],
        &crc_calculators,
    );

    assert!(result.is_ok(), "UO-1-ID decompression should succeed");
    let headers = result.unwrap();
    assert_eq!(
        headers.ip_identification.value(),
        target_ip_id.value(),
        "IP-ID should be correctly reconstructed"
    );
}

#[test]
fn uo1_rtp_decompression_ts_scaled_mode() {
    let crc_calculators = CrcCalculators::new();
    let mut context = create_test_context(400, 64000, 0x11223344);
    context.ts_stride = Some(160);
    context.ts_scaled_mode = true;
    context.ts_offset = 0u32.into();

    let ts_scaled = 5u8;
    let expected_sn = context.last_reconstructed_rtp_sn_full.wrapping_add(1);
    let expected_ts = context.reconstruct_ts_from_scaled(ts_scaled).unwrap();

    // Calculate correct CRC
    let crc_input_bytes = prepare_generic_uo_crc_input_payload(
        context.rtp_ssrc,
        expected_sn,
        expected_ts,
        true, // marker
    );
    let calculated_crc8 = crc_calculators.crc8(&crc_input_bytes);

    let uo1_packet = Uo1Packet {
        ts_scaled: Some(ts_scaled),
        marker: true,
        crc8: calculated_crc8,
        ..Default::default()
    };

    let mut packet_buffer = [0u8; 8];
    let packet_length = serialize_uo1_rtp(&uo1_packet, &mut packet_buffer).unwrap();

    let result = decompress_as_uo1_rtp(
        &mut context,
        &packet_buffer[..packet_length],
        &crc_calculators,
    );

    assert!(result.is_ok(), "UO-1-RTP decompression should succeed");
    let headers = result.unwrap();
    assert!(headers.rtp_marker, "Marker bit should be preserved");
}

#[test]
fn uo1_decompression_crc_recovery_attempts_search() {
    let crc_calculators = CrcCalculators::new();
    let mut context = create_test_context(600, 96000, 0x99AABBCC);

    let uo1_packet = Uo1Packet {
        sn_lsb: 8, // Valid LSB
        num_sn_lsb_bits: P1_UO1_SN_LSB_WIDTH_DEFAULT,
        marker: false,
        crc8: 0xFF, // Intentionally wrong to trigger recovery
        ..Default::default()
    };

    let mut packet_buffer = [0u8; 8];
    let packet_length = serialize_uo1_sn(&uo1_packet, &mut packet_buffer).unwrap();

    let result = decompress_as_uo1_sn(
        &mut context,
        &packet_buffer[..packet_length],
        &crc_calculators,
    );

    // Should fail due to CRC mismatch and recovery not finding valid candidate
    assert!(result.is_err(), "Should fail with intentionally wrong CRC");

    match result.unwrap_err() {
        crate::error::RohcError::Parsing(crate::error::RohcParsingError::CrcMismatch {
            ..
        }) => {
            // Expected - recovery couldn't find valid sequence number
        }
        other => panic!("Expected CRC mismatch error, got: {:?}", other),
    }
}

#[test]
fn uo1_ts_missing_mandatory_fields_fails() {
    // Create packet with missing ts_lsb but present num_ts_lsb_bits
    let uo1_packet = Uo1Packet {
        ts_lsb: None, // Missing mandatory field
        num_ts_lsb_bits: Some(16),
        crc8: 0x0,
        ..Default::default()
    };

    let mut packet_buffer = [0u8; 8];
    let result = serialize_uo1_ts(&uo1_packet, &mut packet_buffer);

    // Should fail during serialization due to missing mandatory field
    assert!(
        result.is_err(),
        "Serialization should fail with missing mandatory ts_lsb"
    );
}

#[test]
fn uo1_id_missing_mandatory_fields_fails() {
    // Create packet with missing ip_id_lsb
    let uo1_packet = Uo1Packet {
        ip_id_lsb: None, // Missing mandatory field
        num_ip_id_lsb_bits: Some(8),
        crc8: 0x0,
        ..Default::default()
    };

    let mut packet_buffer = [0u8; 8];
    let result = serialize_uo1_id(&uo1_packet, &mut packet_buffer);

    // Should fail during serialization due to missing mandatory field
    assert!(
        result.is_err(),
        "Serialization should fail with missing mandatory ip_id_lsb"
    );
}

#[test]
fn uo1_decompression_serialization_errors_handled() {
    let _crc_calculators = CrcCalculators::new();
    let _context = create_test_context(700, 112000, 0xDDEEFFAA);

    // Test that deserialization functions handle wrong packet lengths properly
    let too_short_packet = [0x80, 0x05]; // Only 2 bytes for UO-1-SN
    let deserialize_result =
        super::super::serialization::uo1_packets::deserialize_uo1_sn(&too_short_packet);
    assert!(
        deserialize_result.is_err(),
        "UO-1-SN deserialization should fail with wrong packet length"
    );

    // Test UO-1-TS deserialization with wrong length
    let too_short_ts_packet = [0x90, 0x12, 0x34]; // Only 3 bytes for UO-1-TS
    let deserialize_ts_result =
        super::super::serialization::uo1_packets::deserialize_uo1_ts(&too_short_ts_packet);
    assert!(
        deserialize_ts_result.is_err(),
        "UO-1-TS deserialization should fail with wrong packet length"
    );
}
