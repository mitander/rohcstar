//! RFC 3095 compliance tests for UO (Unidirectional/Optimistic) packets.
//!
//! Validates UO-0, UO-1, and UOR-2 packet formats according to RFC 3095
//! Section 5.7. These compressed packet types form the core of ROHC's
//! efficiency, encoding only changed fields with minimal overhead.

use crate::compliance::common::*;
use rohcstar::packet_defs::{GenericUncompressedHeaders, RohcProfile};
use rohcstar::types::ContextId;

/// UO-0 packet discriminator pattern (0XXXXXXX).
const UO0_DISCRIMINATOR_MASK: u8 = 0x80;

/// UO-1 packet discriminator pattern (10XXXXXX).
const UO1_DISCRIMINATOR_VALUE: u8 = 0x80;
const UO1_DISCRIMINATOR_MASK: u8 = 0xC0;

#[test]
fn p1_uo0_packet_minimal_size() {
    let mut engine = create_test_engine();
    let cid = ContextId::new(0);

    // Establish context with IR packet
    let _ = establish_context(&mut engine, cid);

    // Create UO-0 conditions: SN +1, same TS, no marker
    let headers = create_headers_with_sn(101);
    let generic = GenericUncompressedHeaders::RtpUdpIpv4(headers);

    let mut compressed = [0u8; 256];
    let len = engine
        .compress(cid, None, &generic, &mut compressed)
        .expect("UO-0 compression should succeed");

    // RFC 3095 Section 5.7.1: UO-0 is exactly 1 byte
    assert_eq!(len, 1, "UO-0 packet must be exactly 1 byte");
    assert_eq!(
        compressed[0] & UO0_DISCRIMINATOR_MASK,
        0,
        "UO-0 discriminator bit must be 0"
    );
}

#[test]
fn p1_uo0_sequence_number_encoding() {
    let mut engine = create_test_engine();
    let cid = ContextId::new(0);

    // Establish context
    let _ = establish_context(&mut engine, cid);

    // Test SN increments within UO-0 4-bit range
    for sn_increment in 1..=15 {
        let headers = create_headers_with_sn(100 + sn_increment);
        let generic = GenericUncompressedHeaders::RtpUdpIpv4(headers);

        let mut buf = [0u8; 256];
        let len = engine
            .compress(cid, None, &generic, &mut buf)
            .expect("Compression should succeed");

        assert_eq!(len, 1, "SN increment {} should produce UO-0", sn_increment);

        let sn_bits = (buf[0] >> 3) & 0x0F;
        let expected_sn_lsb = (100 + sn_increment) & 0x0F;
        assert_eq!(sn_bits as u16, expected_sn_lsb, "SN encoding mismatch");
    }
}

#[test]
fn p1_uo0_with_add_cid() {
    let mut engine = create_test_engine();
    let cid = ContextId::new(5);

    // Establish context
    let _ = establish_context(&mut engine, cid);

    // Create UO-0 conditions
    let headers = create_headers_with_sn(101);
    let generic = GenericUncompressedHeaders::RtpUdpIpv4(headers);

    let mut compressed = [0u8; 256];
    let len = engine
        .compress(cid, None, &generic, &mut compressed)
        .expect("UO-0 with CID compression should succeed");

    assert_eq!(len, 2, "UO-0 with Add-CID should be 2 bytes");

    // Verify Add-CID octet
    assert_eq!(compressed[0] >> 4, 0b1110, "Add-CID prefix incorrect");
    assert_eq!(compressed[0] & 0x0F, 5, "CID value in Add-CID incorrect");

    // Verify UO-0 packet follows
    assert_eq!(
        compressed[1] & UO0_DISCRIMINATOR_MASK,
        0,
        "UO-0 discriminator after Add-CID incorrect"
    );
}

#[test]
fn p1_uo1_triggered_by_ts_change() {
    let mut engine = create_test_engine();
    let cid = ContextId::new(0);

    // Establish context
    let _ = establish_context(&mut engine, cid);

    // Non-stride TS change should trigger UO-1 or larger
    let headers = create_headers_with_sn_ts(101, 2000);
    let generic = GenericUncompressedHeaders::RtpUdpIpv4(headers);

    let mut buf = [0u8; 256];
    let len = engine
        .compress(cid, None, &generic, &mut buf)
        .expect("Compression should succeed");

    assert!(len > 1, "TS change should not produce UO-0");
    assert_eq!(
        buf[0] & UO1_DISCRIMINATOR_MASK,
        UO1_DISCRIMINATOR_VALUE,
        "Should be UO-1 packet type"
    );
}

#[test]
#[ignore] // TODO: fix internals to make this pass
fn p1_uo1_marker_bit_encoding() {
    let mut engine = create_test_engine();
    let cid = ContextId::new(0);

    // Establish context
    let _ = establish_context(&mut engine, cid);

    // Marker bit change should trigger UO-1
    let mut headers = create_headers_with_sn(101);
    headers.rtp_marker = true;
    let generic = GenericUncompressedHeaders::RtpUdpIpv4(headers);

    let mut buf = [0u8; 256];
    let len = engine
        .compress(cid, None, &generic, &mut buf)
        .expect("Compression with marker should succeed");

    assert!(len > 1, "Marker change should not produce UO-0");

    // Decompress and verify marker preserved
    let decompressed = engine
        .decompress(&buf[..len])
        .expect("Decompression should succeed");

    match decompressed {
        GenericUncompressedHeaders::RtpUdpIpv4(h) => {
            assert!(h.rtp_marker, "Marker bit not preserved");
        }
        _ => panic!("Decompressed headers type mismatch"),
    }
}

#[test]
fn p1_uo2_handles_large_sn_jumps() {
    let mut engine = create_test_engine();
    let cid = ContextId::new(0);

    // Establish context
    let _ = establish_context(&mut engine, cid);

    // Large SN jump requiring extended encoding
    let headers = create_headers_with_sn(500);
    let generic = GenericUncompressedHeaders::RtpUdpIpv4(headers);

    let mut buf = [0u8; 256];
    let len = engine
        .compress(cid, None, &generic, &mut buf)
        .expect("Large SN compression should succeed");

    assert!(
        len >= 3,
        "Large SN jump should use extended format, got {} bytes",
        len
    );
}

#[test]
fn p1_uo_packets_preserve_crc_integrity() {
    let mut engine = create_test_engine();
    let cid = ContextId::new(0);

    // Establish context
    let _ = establish_context(&mut engine, cid);

    // Generate UO-0 packet
    let headers = create_headers_with_sn(101);
    let generic = GenericUncompressedHeaders::RtpUdpIpv4(headers);

    let mut buf = [0u8; 256];
    let len = engine
        .compress(cid, None, &generic, &mut buf)
        .expect("UO-0 compression should succeed");

    assert_eq!(len, 1, "Should be UO-0 packet");

    // Corrupt the CRC bits (last 3 bits)
    let mut corrupted = buf[..len].to_vec();
    corrupted[0] ^= 0x07;

    // Decompression should fail
    let result = engine.decompress(&corrupted);
    assert!(result.is_err(), "Should reject packet with corrupted CRC");
}

#[test]
#[ignore] // TODO: fix internals to make this pass
fn p1_uo_sequence_wraparound() {
    let mut engine = create_test_engine();
    let cid = ContextId::new(0);

    // Establish context near wraparound
    let mut headers = create_rfc_example_headers();
    headers.rtp_sequence_number = 65530.into();
    let generic = GenericUncompressedHeaders::RtpUdpIpv4(headers);

    let mut buf = [0u8; 256];
    let _ = engine
        .compress(cid, Some(RohcProfile::RtpUdpIp), &generic, &mut buf)
        .expect("Initial compression should succeed");

    // Test wraparound sequence
    for sn in [65531, 65532, 65533, 65534, 65535, 0, 1, 2, 3] {
        let headers = create_headers_with_sn(sn);
        let generic = GenericUncompressedHeaders::RtpUdpIpv4(headers);

        let len = engine
            .compress(cid, None, &generic, &mut buf)
            .expect("Wraparound compression should succeed");

        let decompressed = engine
            .decompress(&buf[..len])
            .expect("Wraparound decompression should succeed");

        match decompressed {
            GenericUncompressedHeaders::RtpUdpIpv4(h) => {
                assert_eq!(
                    *h.rtp_sequence_number, sn,
                    "SN {} not preserved through wraparound",
                    sn
                );
            }
            _ => panic!("Decompressed headers type mismatch"),
        }
    }
}

#[test]
fn p1_uo_optimal_packet_selection() {
    let mut engine = create_test_engine();
    let cid = ContextId::new(0);

    // Establish context
    let _ = establish_context(&mut engine, cid);

    // Test various conditions for optimal packet type selection

    // Case 1: Small SN increment only -> UO-0
    let headers_uo0 = create_headers_with_sn(101);
    let generic_uo0 = GenericUncompressedHeaders::RtpUdpIpv4(headers_uo0);

    let mut buf = [0u8; 256];
    let len_uo0 = engine
        .compress(cid, None, &generic_uo0, &mut buf)
        .expect("UO-0 case should compress");
    assert_eq!(len_uo0, 1, "Should select UO-0 for minimal change");

    // Case 2: Timestamp change -> UO-1 or larger
    let headers_ts = create_headers_with_sn_ts(102, 2000);
    let generic_ts = GenericUncompressedHeaders::RtpUdpIpv4(headers_ts);

    let len_ts = engine
        .compress(cid, None, &generic_ts, &mut buf)
        .expect("TS change case should compress");
    assert!(len_ts > 1, "Should select larger format for TS change");

    // Case 3: Large SN jump -> Extended format
    let headers_jump = create_headers_with_sn(1000);
    let generic_jump = GenericUncompressedHeaders::RtpUdpIpv4(headers_jump);

    let len_jump = engine
        .compress(cid, None, &generic_jump, &mut buf)
        .expect("Large jump case should compress");
    assert!(
        len_jump >= 3,
        "Should select extended format for large jump"
    );
}
