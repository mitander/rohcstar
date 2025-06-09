//! Debug test to examine CID 1 compression behavior

use rohcstar::RohcEngine;
use rohcstar::packet_defs::{GenericUncompressedHeaders, RohcProfile};
use rohcstar::profiles::profile1::{Profile1Handler, RtpUdpIpv4Headers};
use rohcstar::time::SystemClock;
use rohcstar::types::{ContextId, SequenceNumber, Ssrc, Timestamp};
use std::sync::Arc;
use std::time::Duration;

fn create_test_engine() -> RohcEngine {
    let mut engine = RohcEngine::new(20, Duration::from_secs(300), Arc::new(SystemClock));
    engine
        .register_profile_handler(Box::new(Profile1Handler::new()))
        .expect("Profile 1 registration should succeed");
    engine
}

fn create_test_headers() -> RtpUdpIpv4Headers {
    RtpUdpIpv4Headers {
        ip_src: "192.168.1.1".parse().unwrap(),
        ip_dst: "192.168.1.2".parse().unwrap(),
        ip_total_length: 60,
        ip_identification: 0x1234.into(),
        ip_ttl: 64,
        ip_checksum: 0,
        udp_src_port: 1234,
        udp_dst_port: 5678,
        udp_length: 40,
        udp_checksum: 0,
        rtp_version: 2,
        rtp_padding: false,
        rtp_extension: false,
        rtp_csrc_count: 0,
        rtp_marker: false,
        rtp_payload_type: 0,
        rtp_sequence_number: SequenceNumber::new(100),
        rtp_timestamp: Timestamp::new(1000),
        rtp_ssrc: Ssrc::new(0x12345678),
        rtp_csrc_list: vec![],
        ..Default::default()
    }
}

#[test]
fn debug_cid_0_compression() {
    let mut engine = create_test_engine();
    let headers = create_test_headers();
    let generic = GenericUncompressedHeaders::RtpUdpIpv4(headers);

    let mut buf = [0u8; 256];
    let len = engine
        .compress(
            ContextId::new(0),
            Some(RohcProfile::RtpUdpIp),
            &generic,
            &mut buf,
        )
        .expect("CID 0 compression should succeed");

    println!("CID 0 packet length: {}", len);
    println!("CID 0 packet bytes: {:02x?}", &buf[..len]);

    // Try decompression
    let result = engine.decompress(&buf[..len]);
    println!("CID 0 decompression result: {:?}", result.is_ok());
}

#[test]
fn debug_cid_1_compression() {
    let mut engine = create_test_engine();
    let headers = create_test_headers();
    let generic = GenericUncompressedHeaders::RtpUdpIpv4(headers);

    let mut buf = [0u8; 256];
    let len = engine
        .compress(
            ContextId::new(1),
            Some(RohcProfile::RtpUdpIp),
            &generic,
            &mut buf,
        )
        .expect("CID 1 compression should succeed");

    println!("CID 1 packet length: {}", len);
    println!("CID 1 packet bytes: {:02x?}", &buf[..len]);

    // Try decompression
    let result = engine.decompress(&buf[..len]);
    println!("CID 1 decompression result: {:?}", result);

    if let Err(e) = result {
        println!("CID 1 decompression error: {}", e);
    }
}

#[test]
fn debug_cid_1_follow_up_compression() {
    let mut engine = create_test_engine();
    let headers = create_test_headers();
    let generic = GenericUncompressedHeaders::RtpUdpIpv4(headers.clone());

    // First packet (IR)
    let mut buf1 = [0u8; 256];
    let len1 = engine
        .compress(
            ContextId::new(1),
            Some(RohcProfile::RtpUdpIp),
            &generic,
            &mut buf1,
        )
        .expect("CID 1 IR compression should succeed");

    println!("CID 1 IR packet length: {}", len1);
    println!("CID 1 IR packet bytes: {:02x?}", &buf1[..len1]);

    // Second packet (should be UO)
    let mut headers2 = headers;
    headers2.rtp_sequence_number = SequenceNumber::new(101);
    let generic2 = GenericUncompressedHeaders::RtpUdpIpv4(headers2);

    let mut buf2 = [0u8; 256];
    let len2 = engine
        .compress(ContextId::new(1), None, &generic2, &mut buf2)
        .expect("CID 1 UO compression should succeed");

    println!("CID 1 UO packet length: {}", len2);
    println!("CID 1 UO packet bytes: {:02x?}", &buf2[..len2]);

    // Try decompressing both
    let result1 = engine.decompress(&buf1[..len1]);
    println!("CID 1 IR decompression result: {:?}", result1.is_ok());

    let result2 = engine.decompress(&buf2[..len2]);
    println!("CID 1 UO decompression result: {:?}", result2);

    if let Err(e) = result2 {
        println!("CID 1 UO decompression error: {}", e);
    }
}

#[test]
fn debug_compliance_test_scenario() {
    let mut engine = create_test_engine();

    let cid1 = ContextId::new(1);
    let cid2 = ContextId::new(2);

    // Create different header patterns like the compliance test
    let mut headers1 = create_test_headers();
    headers1.udp_src_port = 1111;
    headers1.rtp_ssrc = Ssrc::new(0x11111111);

    let mut headers2 = create_test_headers();
    headers2.udp_src_port = 2222;
    headers2.rtp_ssrc = Ssrc::new(0x22222222);

    // Establish contexts
    let generic1 = GenericUncompressedHeaders::RtpUdpIpv4(headers1.clone());
    let generic2 = GenericUncompressedHeaders::RtpUdpIpv4(headers2.clone());

    let mut buf1 = [0u8; 256];
    let mut buf2 = [0u8; 256];

    let len1_initial = engine
        .compress(cid1, Some(RohcProfile::RtpUdpIp), &generic1, &mut buf1)
        .expect("CID1 initial compression should succeed");

    let len2_initial = engine
        .compress(cid2, Some(RohcProfile::RtpUdpIp), &generic2, &mut buf2)
        .expect("CID2 initial compression should succeed");

    println!(
        "CID1 initial packet length: {}, bytes: {:02x?}",
        len1_initial,
        &buf1[..len1_initial]
    );
    println!(
        "CID2 initial packet length: {}, bytes: {:02x?}",
        len2_initial,
        &buf2[..len2_initial]
    );

    // Test if IR packets decompress correctly
    println!("Testing IR packet decompression...");
    let ir1_result = engine.decompress(&buf1[..len1_initial]);
    println!("CID1 IR decompression: {:?}", ir1_result.is_ok());

    let ir2_result = engine.decompress(&buf2[..len2_initial]);
    println!("CID2 IR decompression: {:?}", ir2_result.is_ok());

    // Update contexts independently like the compliance test (iterate 1..=5)
    for i in 1..=5 {
        headers1.rtp_sequence_number = SequenceNumber::new(100 + i);
        headers2.rtp_sequence_number = SequenceNumber::new(100 + i * 2);

        let generic1_update = GenericUncompressedHeaders::RtpUdpIpv4(headers1.clone());
        let generic2_update = GenericUncompressedHeaders::RtpUdpIpv4(headers2.clone());

        let len1 = engine
            .compress(cid1, None, &generic1_update, &mut buf1)
            .expect("CID1 update compression should succeed");

        let len2 = engine
            .compress(cid2, None, &generic2_update, &mut buf2)
            .expect("CID2 update compression should succeed");

        println!(
            "Iteration {}: CID1 update packet length: {}, bytes: {:02x?}",
            i,
            len1,
            &buf1[..len1]
        );
        println!(
            "Iteration {}: CID2 update packet length: {}, bytes: {:02x?}",
            i,
            len2,
            &buf2[..len2]
        );

        // Try decompression like the compliance test
        println!("Iteration {}: Attempting CID1 decompression...", i);
        let decompressed1 = engine.decompress(&buf1[..len1]);

        println!("Iteration {}: Attempting CID2 decompression...", i);
        let decompressed2 = engine.decompress(&buf2[..len2]);

        match (&decompressed1, &decompressed2) {
            (Ok(_), Ok(_)) => println!("Iteration {}: Both decompressions succeeded!", i),
            (Err(e1), Ok(_)) => {
                println!("Iteration {}: CID1 failed: {}", i, e1);
                panic!("CID1 failed on iteration {}: {}", i, e1);
            }
            (Ok(_), Err(e2)) => {
                println!("Iteration {}: CID2 failed: {}", i, e2);
                panic!("CID2 failed on iteration {}: {}", i, e2);
            }
            (Err(e1), Err(e2)) => {
                println!("Iteration {}: Both failed: CID1={}, CID2={}", i, e1, e2);
                panic!("Both failed on iteration {}: CID1={}, CID2={}", i, e1, e2);
            }
        }

        // Verify the results match expected sequence numbers
        if let (
            Ok(GenericUncompressedHeaders::RtpUdpIpv4(h1)),
            Ok(GenericUncompressedHeaders::RtpUdpIpv4(h2)),
        ) = (&decompressed1, &decompressed2)
        {
            assert_eq!(*h1.rtp_sequence_number, 100 + i);
            assert_eq!(*h2.rtp_sequence_number, 100 + i * 2);
            println!("Iteration {}: Sequence numbers verified", i);
        }
    }
}
