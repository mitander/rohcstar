//! Common test utilities for RFC 3095 compliance validation.
//!
//! Provides standardized test engine creation and example header construction
//! matching RFC 3095 Section 5.7.7.4 examples. These utilities ensure consistent
//! test environments across all compliance tests.

use rohcstar::RohcEngine;
use rohcstar::packet_defs::{GenericUncompressedHeaders, RohcProfile};
use rohcstar::profiles::profile1::{Profile1Handler, RtpUdpIpv4Headers};
use rohcstar::time::SystemClock;
use rohcstar::types::{ContextId, SequenceNumber, Ssrc, Timestamp};
use std::sync::Arc;
use std::time::Duration;

/// Default IR refresh interval for test engines.
pub const TEST_IR_REFRESH_INTERVAL: u32 = 20;

/// Default context timeout for test engines.
pub const TEST_CONTEXT_TIMEOUT: Duration = Duration::from_secs(300);

/// Creates a standard test engine with Profile 1 registered.
///
/// # Returns
/// A configured `RohcEngine` with Profile 1 handler ready for testing.
pub fn create_test_engine() -> RohcEngine {
    let mut engine = RohcEngine::new(
        TEST_IR_REFRESH_INTERVAL,
        TEST_CONTEXT_TIMEOUT,
        Arc::new(SystemClock),
    );
    engine
        .register_profile_handler(Box::new(Profile1Handler::new()))
        .expect("Profile 1 registration should succeed");
    engine
}

/// Creates a test engine with custom IR refresh interval.
///
/// # Parameters
/// - `ir_refresh_interval`: Packets between forced IR refreshes
///
/// # Returns
/// A configured `RohcEngine` with specified refresh behavior.
pub fn create_test_engine_with_refresh(ir_refresh_interval: u32) -> RohcEngine {
    let mut engine = RohcEngine::new(
        ir_refresh_interval,
        TEST_CONTEXT_TIMEOUT,
        Arc::new(SystemClock),
    );
    engine
        .register_profile_handler(Box::new(Profile1Handler::new()))
        .expect("Profile 1 registration should succeed");
    engine
}

/// Creates headers matching RFC 3095 example patterns.
///
/// Provides a consistent baseline for test scenarios with typical
/// RTP/UDP/IPv4 values that exercise common compression paths.
///
/// # Returns
/// Headers with deterministic values suitable for test reproducibility.
pub fn create_rfc_example_headers() -> RtpUdpIpv4Headers {
    RtpUdpIpv4Headers {
        // IPv4 header fields
        ip_src: "192.168.1.1".parse().unwrap(),
        ip_dst: "192.168.1.2".parse().unwrap(),
        ip_total_length: 60,
        ip_identification: 0x1234.into(),
        ip_ttl: 64,
        ip_checksum: 0,

        // UDP header fields
        udp_src_port: 1234,
        udp_dst_port: 5678,
        udp_length: 40,
        udp_checksum: 0,

        // RTP header fields
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

/// Creates headers with specified sequence number.
///
/// # Parameters
/// - `sn`: RTP sequence number to set
///
/// # Returns
/// Headers identical to [`create_rfc_example_headers`] except for sequence number.
pub fn create_headers_with_sn(sn: u16) -> RtpUdpIpv4Headers {
    let mut headers = create_rfc_example_headers();
    headers.rtp_sequence_number = SequenceNumber::new(sn);
    headers
}

/// Creates headers with specified timestamp.
///
/// # Parameters
/// - `ts`: RTP timestamp to set
///
/// # Returns
/// Headers identical to [`create_rfc_example_headers`] except for timestamp.
pub fn create_headers_with_ts(ts: u32) -> RtpUdpIpv4Headers {
    let mut headers = create_rfc_example_headers();
    headers.rtp_timestamp = Timestamp::new(ts);
    headers
}

/// Creates headers with specified sequence number and timestamp.
///
/// # Parameters
/// - `sn`: RTP sequence number to set
/// - `ts`: RTP timestamp to set
///
/// # Returns
/// Headers with both fields updated from baseline.
pub fn create_headers_with_sn_ts(sn: u16, ts: u32) -> RtpUdpIpv4Headers {
    let mut headers = create_rfc_example_headers();
    headers.rtp_sequence_number = SequenceNumber::new(sn);
    headers.rtp_timestamp = Timestamp::new(ts);
    headers
}

/// Establishes a compression context by sending an IR packet.
///
/// # Parameters
/// - `engine`: The ROHC engine to use
/// - `cid`: Context ID to establish
///
/// # Returns
/// Number of bytes in the IR packet.
pub fn establish_context(engine: &mut RohcEngine, cid: ContextId) -> usize {
    let headers = create_rfc_example_headers();
    let generic = GenericUncompressedHeaders::RtpUdpIpv4(headers);

    let mut buf = [0u8; 256];
    engine
        .compress(cid, Some(RohcProfile::RtpUdpIp), &generic, &mut buf)
        .expect("IR compression should succeed")
}

/// Establishes a compression context with timestamp stride for TsScaled mode.
///
/// Sends sufficient packets to establish timestamp stride detection, enabling
/// UO-1-RTP packet usage with marker bit changes. Required for tests that
/// expect TsScaled compression capabilities.
///
/// # Parameters
/// - `engine`: The ROHC engine to use
/// - `cid`: Context ID to establish
///
/// # Returns
/// Number of bytes in the final packet.
pub fn establish_context_with_ts_stride(engine: &mut RohcEngine, cid: ContextId) -> usize {
    let mut buf = [0u8; 256];

    // Send initial IR packet
    let headers = create_rfc_example_headers();
    let generic = GenericUncompressedHeaders::RtpUdpIpv4(headers);

    let ir_len = engine
        .compress(cid, Some(RohcProfile::RtpUdpIp), &generic, &mut buf)
        .expect("IR compression should succeed");

    // Decompress IR to establish decompressor context
    let _ = engine
        .decompress(&buf[..ir_len])
        .expect("IR decompression should succeed");

    // Send 3 more packets with consistent stride to establish TsScaled mode
    // Stride of 160 is typical for audio (8kHz sample rate, 20ms packets)
    const TS_STRIDE: u32 = 160;

    let mut last_len = 0;
    for i in 1..=3 {
        let mut headers = create_rfc_example_headers();
        headers.rtp_sequence_number = SequenceNumber::new(100 + i);
        headers.rtp_timestamp = Timestamp::new(1000 + (i as u32) * TS_STRIDE);
        let generic = GenericUncompressedHeaders::RtpUdpIpv4(headers);

        last_len = engine
            .compress(cid, None, &generic, &mut buf)
            .expect("Stride establishment compression should succeed");

        // Decompress to keep contexts in sync
        let _ = engine
            .decompress(&buf[..last_len])
            .expect("Stride establishment decompression should succeed");
    }

    last_len
}
