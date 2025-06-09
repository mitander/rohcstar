//! RFC 3095 compliance tests for IR (Initialization and Refresh) packets.
//!
//! Validates IR packet structure, encoding, and context establishment behavior
//! according to RFC 3095 Section 5.7.7. IR packets are the foundation of ROHC
//! compression, establishing initial context state between compressor and
//! decompressor.

use crate::compliance::common::*;
use rohcstar::constants::ROHC_SMALL_CID_MASK;
use rohcstar::packet_defs::{GenericUncompressedHeaders, RohcProfile};
use rohcstar::profiles::profile1::P1_ROHC_IR_PACKET_TYPE_WITH_DYN;
use rohcstar::types::ContextId;

/// Minimum IR packet size: type(1) + profile(1) + static_chain(16) + dynamic_chain(9) + CRC(1).
/// RFC 3095 IR packets contain compressed header info, not full uncompressed headers.
const P1_IR_MINIMUM_SIZE: usize = 28;

#[test]
fn p1_ir_packet_structure_conforms_to_rfc() {
    let mut engine = create_test_engine();
    let headers = create_rfc_example_headers();
    let generic_headers = GenericUncompressedHeaders::RtpUdpIpv4(headers);

    let mut compressed = [0u8; 256];
    let len = engine
        .compress(
            ContextId::new(0),
            Some(RohcProfile::RtpUdpIp),
            &generic_headers,
            &mut compressed,
        )
        .expect("IR compression should succeed");
    let packet = &compressed[..len];

    // RFC 3095 Section 5.7.7.1: IR packet format validation
    assert_eq!(
        packet[0], P1_ROHC_IR_PACKET_TYPE_WITH_DYN,
        "IR packet type byte should be 0xFD (11111101)"
    );

    assert_eq!(packet[1], 0x01, "Profile ID should be 0x01 for Profile 1");

    assert!(
        packet.len() >= P1_IR_MINIMUM_SIZE,
        "IR packet size {} below minimum {}",
        packet.len(),
        P1_IR_MINIMUM_SIZE
    );
}

#[test]
fn p1_ir_decompression_reconstructs_headers() {
    let mut engine = create_test_engine();
    let original_headers = create_rfc_example_headers();
    let generic_headers = GenericUncompressedHeaders::RtpUdpIpv4(original_headers.clone());

    // Compress
    let mut compressed = [0u8; 256];
    let len = engine
        .compress(
            ContextId::new(0),
            Some(RohcProfile::RtpUdpIp),
            &generic_headers,
            &mut compressed,
        )
        .expect("IR compression should succeed");

    // Decompress
    let decompressed = engine
        .decompress(&compressed[..len])
        .expect("IR decompression should succeed");

    // Verify all fields preserved
    match decompressed {
        GenericUncompressedHeaders::RtpUdpIpv4(headers) => {
            assert_eq!(headers.ip_src, original_headers.ip_src);
            assert_eq!(headers.ip_dst, original_headers.ip_dst);
            assert_eq!(headers.udp_src_port, original_headers.udp_src_port);
            assert_eq!(headers.udp_dst_port, original_headers.udp_dst_port);
            assert_eq!(headers.rtp_ssrc, original_headers.rtp_ssrc);
            assert_eq!(
                headers.rtp_sequence_number,
                original_headers.rtp_sequence_number
            );
            assert_eq!(headers.rtp_timestamp, original_headers.rtp_timestamp);
        }
        _ => panic!("Decompressed headers type mismatch"),
    }
}

#[test]
fn p1_ir_with_cid_uses_add_cid_octet() {
    let mut engine = create_test_engine();
    let headers = create_rfc_example_headers();
    let generic_headers = GenericUncompressedHeaders::RtpUdpIpv4(headers);

    let cid = ContextId::new(5);
    let mut compressed = [0u8; 256];
    let len = engine
        .compress(
            cid,
            Some(RohcProfile::RtpUdpIp),
            &generic_headers,
            &mut compressed,
        )
        .expect("IR compression with CID should succeed");
    let packet = &compressed[..len];

    // RFC 3095 Section 5.3.2: Add-CID octet validation
    assert_eq!(packet[0] >> 4, 0b1110, "Add-CID prefix should be 1110");
    assert_eq!(
        packet[0] & ROHC_SMALL_CID_MASK,
        5,
        "CID value in Add-CID octet incorrect"
    );

    assert_eq!(
        packet[1], P1_ROHC_IR_PACKET_TYPE_WITH_DYN,
        "IR packet type should follow Add-CID octet"
    );
}

#[test]
#[ignore] // TODO: fix RTP payload type preservation
fn p1_ir_handles_max_static_fields() {
    let mut engine = create_test_engine();
    let mut headers = create_rfc_example_headers();

    // Set all variable fields to maximum values
    headers.ip_ttl = 255;
    headers.ip_identification = 0xFFFF.into();
    headers.rtp_marker = true;
    headers.rtp_payload_type = 127;
    headers.rtp_padding = true;
    headers.rtp_extension = true;

    let generic_headers = GenericUncompressedHeaders::RtpUdpIpv4(headers.clone());

    let mut compressed = [0u8; 256];
    let len = engine
        .compress(
            ContextId::new(0),
            Some(RohcProfile::RtpUdpIp),
            &generic_headers,
            &mut compressed,
        )
        .expect("IR compression with max fields should succeed");

    // Decompress and verify all fields preserved
    let decompressed = engine
        .decompress(&compressed[..len])
        .expect("IR decompression should succeed");

    match decompressed {
        GenericUncompressedHeaders::RtpUdpIpv4(h) => {
            assert_eq!(h.ip_ttl, 255, "Max TTL not preserved");
            assert_eq!(h.ip_identification, 0xFFFF, "Max IP ID not preserved");
            assert_eq!(h.rtp_payload_type, 127, "Max payload type not preserved");
            assert!(h.rtp_marker, "Marker bit not preserved");
            assert!(h.rtp_padding, "Padding bit not preserved");
            assert!(h.rtp_extension, "Extension bit not preserved");
        }
        _ => panic!("Decompressed headers type mismatch"),
    }
}

#[test]
fn p1_ir_refresh_interval_respected() {
    let refresh_interval = 3;
    let mut engine = create_test_engine_with_refresh(refresh_interval);

    let cid = ContextId::new(0);

    let mut packet_types = Vec::new();

    // Compress multiple packets to observe refresh behavior
    for i in 0..10 {
        let h = create_headers_with_sn(100 + i);
        let generic = GenericUncompressedHeaders::RtpUdpIpv4(h);

        let mut buf = [0u8; 256];
        let _ = engine
            .compress(cid, Some(RohcProfile::RtpUdpIp), &generic, &mut buf)
            .expect("Compression should succeed");

        packet_types.push(buf[0]);
    }

    // Verify IR packets at expected intervals
    assert_eq!(
        packet_types[0], P1_ROHC_IR_PACKET_TYPE_WITH_DYN,
        "First packet should be IR"
    );
    assert_eq!(
        packet_types[3], P1_ROHC_IR_PACKET_TYPE_WITH_DYN,
        "Should refresh at interval"
    );
    assert_eq!(
        packet_types[6], P1_ROHC_IR_PACKET_TYPE_WITH_DYN,
        "Should refresh at interval"
    );
    assert_eq!(
        packet_types[9], P1_ROHC_IR_PACKET_TYPE_WITH_DYN,
        "Should refresh at interval"
    );
}

#[test]
fn p1_ir_packet_size_scales_with_content() {
    let mut engine = create_test_engine();
    let cid = ContextId::new(0);

    // Baseline IR packet
    let headers_base = create_rfc_example_headers();
    let generic_base = GenericUncompressedHeaders::RtpUdpIpv4(headers_base);

    let mut buf_base = [0u8; 256];
    let len_base = engine
        .compress(
            cid,
            Some(RohcProfile::RtpUdpIp),
            &generic_base,
            &mut buf_base,
        )
        .expect("Baseline compression should succeed");

    // IR packet with max CID requiring Add-CID
    let cid_max = ContextId::new(15);
    let mut buf_cid = [0u8; 256];
    let len_cid = engine
        .compress(
            cid_max,
            Some(RohcProfile::RtpUdpIp),
            &generic_base,
            &mut buf_cid,
        )
        .expect("CID compression should succeed");

    assert_eq!(len_cid, len_base + 1, "Add-CID should add exactly 1 byte");
}

#[test]
fn p1_ir_multiple_cids_independent() {
    let mut engine = create_test_engine();

    let cid1 = ContextId::new(1);
    let cid2 = ContextId::new(2);

    // Create different streams
    let mut headers1 = create_rfc_example_headers();
    headers1.udp_src_port = 1111;
    let generic1 = GenericUncompressedHeaders::RtpUdpIpv4(headers1.clone());

    let mut headers2 = create_rfc_example_headers();
    headers2.udp_src_port = 2222;
    let generic2 = GenericUncompressedHeaders::RtpUdpIpv4(headers2.clone());

    // Compress both
    let mut buf1 = [0u8; 256];
    let len1 = engine
        .compress(cid1, Some(RohcProfile::RtpUdpIp), &generic1, &mut buf1)
        .expect("CID1 compression should succeed");

    let mut buf2 = [0u8; 256];
    let len2 = engine
        .compress(cid2, Some(RohcProfile::RtpUdpIp), &generic2, &mut buf2)
        .expect("CID2 compression should succeed");

    // Decompress and verify independence
    let decompressed1 = engine
        .decompress(&buf1[..len1])
        .expect("CID1 decompression should succeed");

    let decompressed2 = engine
        .decompress(&buf2[..len2])
        .expect("CID2 decompression should succeed");

    match (decompressed1, decompressed2) {
        (
            GenericUncompressedHeaders::RtpUdpIpv4(h1),
            GenericUncompressedHeaders::RtpUdpIpv4(h2),
        ) => {
            assert_eq!(h1.udp_src_port, 1111, "CID1 port mismatch");
            assert_eq!(h2.udp_src_port, 2222, "CID2 port mismatch");
        }
        _ => panic!("Decompressed headers type mismatch"),
    }
}
