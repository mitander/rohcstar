//! RFC 3095 compliance tests for context management.
//!
//! Validates context lifecycle, timeout behavior, and recovery mechanisms
//! according to RFC 3095 requirements. Context management is critical for
//! maintaining compression state consistency between endpoints.

use crate::compliance::common::*;
use rohcstar::RohcEngine;
use rohcstar::packet_defs::{GenericUncompressedHeaders, RohcProfile};
use rohcstar::profiles::profile1::{P1_ROHC_IR_PACKET_TYPE_WITH_DYN, Profile1Handler};
use rohcstar::time::mock_clock::MockClock;
use rohcstar::types::ContextId;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Short timeout for testing context expiration.
const TEST_SHORT_TIMEOUT: Duration = Duration::from_millis(100);

#[test]
fn engine_context_reinitialization_after_loss() {
    let mut engine = create_test_engine();
    let cid = ContextId::new(0);

    // Establish context
    let headers = create_rfc_example_headers();
    let generic = GenericUncompressedHeaders::RtpUdpIpv4(headers);

    let mut buf = [0u8; 256];
    let initial_len = engine
        .compress(cid, Some(RohcProfile::RtpUdpIp), &generic, &mut buf)
        .expect("Initial compression should succeed");

    // Decompress initial IR to establish decompressor context
    let _ = engine
        .decompress(&buf[..initial_len])
        .expect("Initial IR decompression should succeed");

    // Simulate complete context loss (both compressor and decompressor)
    engine.context_manager_mut().remove_compressor_context(cid);
    engine
        .context_manager_mut()
        .remove_decompressor_context(cid);

    // Next IR packet should reinitialize with fresh context
    let headers2 = create_headers_with_sn(200);
    let generic2 = GenericUncompressedHeaders::RtpUdpIpv4(headers2);

    let len = engine
        .compress(cid, Some(RohcProfile::RtpUdpIp), &generic2, &mut buf)
        .expect("Reinitialization compression should succeed");

    // Should be able to decompress with new context
    let result = engine.decompress(&buf[..len]);
    assert!(result.is_ok(), "Should reinitialize context from IR packet");
}

#[test]
fn engine_context_timeout_removes_stale() {
    let start_time = Instant::now();
    let mock_clock = Arc::new(MockClock::new(start_time));

    let mut engine = RohcEngine::new(
        TEST_IR_REFRESH_INTERVAL,
        TEST_SHORT_TIMEOUT,
        mock_clock.clone(),
    );
    engine
        .register_profile_handler(Box::new(Profile1Handler::new()))
        .expect("Profile registration should succeed");

    // Create contexts for different CIDs
    let cid_fresh = ContextId::new(1);
    let cid_stale = ContextId::new(2);

    // Establish both contexts
    let headers = create_rfc_example_headers();
    let generic = GenericUncompressedHeaders::RtpUdpIpv4(headers);

    let mut buf = [0u8; 256];
    let _ = engine
        .compress(cid_fresh, Some(RohcProfile::RtpUdpIp), &generic, &mut buf)
        .expect("Fresh CID compression should succeed");

    let _ = engine
        .compress(cid_stale, Some(RohcProfile::RtpUdpIp), &generic, &mut buf)
        .expect("Stale CID compression should succeed");

    // Advance time and refresh only cid_fresh
    mock_clock.advance(TEST_SHORT_TIMEOUT / 2);

    let headers_refresh = create_headers_with_sn(101);
    let generic_refresh = GenericUncompressedHeaders::RtpUdpIpv4(headers_refresh);

    let _ = engine
        .compress(cid_fresh, None, &generic_refresh, &mut buf)
        .expect("Fresh CID refresh should succeed");

    // Advance time past timeout for cid_stale
    mock_clock.advance(TEST_SHORT_TIMEOUT / 2 + Duration::from_millis(10));

    // Prune stale contexts
    engine.prune_stale_contexts();

    // Verify cid_fresh remains, cid_stale removed
    assert_eq!(
        engine.context_manager().compressor_context_count(),
        1,
        "Should have exactly one context after pruning"
    );

    assert!(
        engine
            .context_manager()
            .get_compressor_context(cid_fresh)
            .is_ok(),
        "Fresh context should remain"
    );

    assert!(
        engine
            .context_manager()
            .get_compressor_context(cid_stale)
            .is_err(),
        "Stale context should be removed"
    );
}

#[test]
fn engine_context_independent_state() {
    let mut engine = create_test_engine();

    let cid1 = ContextId::new(1);
    let cid2 = ContextId::new(2);

    // Create different header patterns
    let mut headers1 = create_rfc_example_headers();
    headers1.udp_src_port = 1111;
    headers1.rtp_ssrc = 0x11111111.into();

    let mut headers2 = create_rfc_example_headers();
    headers2.udp_src_port = 2222;
    headers2.rtp_ssrc = 0x22222222.into();

    // Establish contexts
    let generic1 = GenericUncompressedHeaders::RtpUdpIpv4(headers1.clone());
    let generic2 = GenericUncompressedHeaders::RtpUdpIpv4(headers2.clone());

    let mut buf1 = [0u8; 256];
    let mut buf2 = [0u8; 256];

    let ir_len1 = engine
        .compress(cid1, Some(RohcProfile::RtpUdpIp), &generic1, &mut buf1)
        .expect("CID1 initial compression should succeed");

    let ir_len2 = engine
        .compress(cid2, Some(RohcProfile::RtpUdpIp), &generic2, &mut buf2)
        .expect("CID2 initial compression should succeed");

    // Establish decompressor contexts
    let _ = engine
        .decompress(&buf1[..ir_len1])
        .expect("CID1 IR decompression should succeed");

    let _ = engine
        .decompress(&buf2[..ir_len2])
        .expect("CID2 IR decompression should succeed");

    // Update contexts independently
    for i in 1..=5 {
        headers1.rtp_sequence_number = (100 + i).into();
        headers2.rtp_sequence_number = (100 + i * 2).into();

        let generic1_update = GenericUncompressedHeaders::RtpUdpIpv4(headers1.clone());
        let generic2_update = GenericUncompressedHeaders::RtpUdpIpv4(headers2.clone());

        let len1 = engine
            .compress(cid1, None, &generic1_update, &mut buf1)
            .expect("CID1 update compression should succeed");

        let len2 = engine
            .compress(cid2, None, &generic2_update, &mut buf2)
            .expect("CID2 update compression should succeed");

        // Verify independent decompression
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
                assert_eq!(h1.udp_src_port, 1111, "CID1 port should be preserved");
                assert_eq!(h2.udp_src_port, 2222, "CID2 port should be preserved");
                assert_eq!(
                    *h1.rtp_sequence_number,
                    100 + i,
                    "CID1 sequence number should match expected"
                );
                assert_eq!(
                    *h2.rtp_sequence_number,
                    100 + i * 2,
                    "CID2 sequence number should match expected"
                );
            }
            _ => panic!("Decompressed headers type mismatch"),
        }
    }
}

#[test]
#[ignore]
// TODO: Only small-CID is supported for now, enable this test when large-CID are implemented
fn engine_context_limit_enforcement() {
    let mut engine = create_test_engine();

    // Create maximum allowed contexts (implementation dependent)
    // This test validates that the engine handles many contexts correctly
    let max_test_contexts = 100;

    let headers = create_rfc_example_headers();
    let generic = GenericUncompressedHeaders::RtpUdpIpv4(headers);

    let mut buf = [0u8; 256];

    for i in 0..max_test_contexts {
        let cid = ContextId::new(i);
        let result = engine.compress(cid, Some(RohcProfile::RtpUdpIp), &generic, &mut buf);

        assert!(
            result.is_ok(),
            "Should handle at least {} contexts",
            max_test_contexts
        );
    }

    assert_eq!(
        engine.context_manager().compressor_context_count(),
        max_test_contexts as usize,
        "Should track all created contexts"
    );
}

#[test]
fn engine_context_recovery_from_desync() {
    let mut engine = create_test_engine_with_refresh(5);
    let cid = ContextId::new(0);

    // Establish context
    let headers = create_rfc_example_headers();
    let generic = GenericUncompressedHeaders::RtpUdpIpv4(headers);

    let mut buf = [0u8; 256];
    let initial_len = engine
        .compress(cid, Some(RohcProfile::RtpUdpIp), &generic, &mut buf)
        .expect("Initial compression should succeed");

    // Decompress initial IR to establish decompressor context
    let _ = engine
        .decompress(&buf[..initial_len])
        .expect("Initial IR decompression should succeed");

    // Generate several UO packets and decompress them to maintain context sync
    for i in 1..=3 {
        let h = create_headers_with_sn(100 + i);
        let g = GenericUncompressedHeaders::RtpUdpIpv4(h);
        let len = engine
            .compress(cid, None, &g, &mut buf)
            .expect("UO compression should succeed");

        let _ = engine
            .decompress(&buf[..len])
            .expect("UO decompression should succeed");
    }

    // Simulate context desync by removing decompressor context
    // (In real scenario, this would be packet loss causing context corruption)
    engine
        .context_manager_mut()
        .remove_decompressor_context(cid);

    // Continue compressing - packet 4 should fail decompression due to missing context
    // but packet 5 should be an IR refresh that allows recovery
    for i in 4..=6 {
        let h = create_headers_with_sn(100 + i);
        let g = GenericUncompressedHeaders::RtpUdpIpv4(h);

        let len = engine
            .compress(cid, None, &g, &mut buf)
            .expect("Compression should succeed");

        let result = engine.decompress(&buf[..len]);

        if i == 4 {
            // Should fail due to missing decompressor context
            assert!(
                result.is_err(),
                "Decompression should fail at packet {} due to missing context",
                i
            );
        } else if i == 5 {
            // Should be IR refresh that recovers context
            assert_eq!(
                buf[0], P1_ROHC_IR_PACKET_TYPE_WITH_DYN,
                "Should send IR refresh at interval"
            );
            assert!(
                result.is_ok(),
                "Decompression should succeed at packet {} after IR refresh",
                i
            );
        } else {
            // Should work after IR refresh
            assert!(
                result.is_ok(),
                "Decompression should succeed at packet {}",
                i
            );
        }
    }
}

#[test]
fn engine_decompressor_context_creation() {
    let mut engine = create_test_engine();

    // Initially no contexts
    assert_eq!(
        engine.context_manager().decompressor_context_count(),
        0,
        "Should start with no decompressor contexts"
    );

    // Compress packet (creates compressor context)
    let headers = create_rfc_example_headers();
    let generic = GenericUncompressedHeaders::RtpUdpIpv4(headers);

    let mut buf = [0u8; 256];
    let len = engine
        .compress(
            ContextId::new(0),
            Some(RohcProfile::RtpUdpIp),
            &generic,
            &mut buf,
        )
        .expect("Compression should succeed");

    assert_eq!(
        engine.context_manager().compressor_context_count(),
        1,
        "Should create compressor context"
    );

    // Decompress packet (creates decompressor context)
    let _ = engine
        .decompress(&buf[..len])
        .expect("Decompression should succeed");

    assert_eq!(
        engine.context_manager().decompressor_context_count(),
        1,
        "Should create decompressor context on first packet"
    );
}
