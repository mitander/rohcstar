//! Common test utilities for ROHC Profile 1 integration tests.
//!
//! This module provides shared helper functions for creating test data, establishing
//! contexts, and asserting packet properties across all Profile 1 integration tests.

#![allow(dead_code)] // Allow dead code for unused test helpers during development

use rohcstar::engine::RohcEngine;
use rohcstar::packet_defs::{GenericUncompressedHeaders, RohcProfile};
use rohcstar::profiles::profile1::constants::{
    P1_ROHC_IR_PACKET_TYPE_STATIC_ONLY, P1_ROHC_IR_PACKET_TYPE_WITH_DYN,
    P1_TS_STRIDE_ESTABLISHMENT_THRESHOLD, P1_UO_1_SN_PACKET_TYPE_PREFIX,
};
use rohcstar::profiles::profile1::context::{
    Profile1CompressorContext, Profile1CompressorMode, Profile1DecompressorContext,
    Profile1DecompressorMode,
};
use rohcstar::profiles::profile1::protocol_types::Timestamp;
use rohcstar::profiles::profile1::{IrPacket, Profile1Handler, RtpUdpIpv4Headers};
use rohcstar::time::{SystemClock, mock_clock::MockClock};
use rohcstar::{ProfileHandler, RohcCompressorContext, RohcDecompressorContext};

use std::sync::Arc;
use std::time::{Duration, Instant};

/// Default timeout for RohcEngine instances in tests where specific timing isn't critical.
pub const DEFAULT_ENGINE_TEST_TIMEOUT: Duration = Duration::from_secs(60 * 5);

/// Default IR refresh interval for RohcEngine instances in tests.
pub const DEFAULT_ENGINE_IR_REFRESH_INTERVAL: u32 = 100;

/// Creates a RohcEngine with a SystemClock for general integration testing,
/// using default IR refresh interval and test timeout.
pub fn create_default_test_engine() -> RohcEngine {
    RohcEngine::new(
        DEFAULT_ENGINE_IR_REFRESH_INTERVAL,
        DEFAULT_ENGINE_TEST_TIMEOUT,
        Arc::new(SystemClock),
    )
}

/// Creates a RohcEngine with a SystemClock for general integration testing,
/// allowing a specific IR refresh interval.
///
/// # Parameters
/// * `ir_refresh_interval` - The interval (in packets) for IR refreshes.
pub fn create_test_engine_with_system_clock(ir_refresh_interval: u32) -> RohcEngine {
    RohcEngine::new(
        ir_refresh_interval,
        DEFAULT_ENGINE_TEST_TIMEOUT,
        Arc::new(SystemClock),
    )
}

/// Creates a RohcEngine with a controllable MockClock for time-sensitive tests.
///
/// # Parameters
/// * `ir_refresh_interval` - The interval (in packets) for IR refreshes.
/// * `timeout` - The context timeout duration.
/// * `initial_mock_time` - The starting time for the mock clock.
///
/// # Returns
/// A tuple containing the `RohcEngine` and an `Arc<MockClock>`.
pub fn create_test_engine_with_mock_clock(
    ir_refresh_interval: u32,
    timeout: Duration,
    initial_mock_time: Instant,
) -> (RohcEngine, Arc<MockClock>) {
    let mock_clock = Arc::new(MockClock::new(initial_mock_time));
    let engine = RohcEngine::new(ir_refresh_interval, timeout, mock_clock.clone());
    (engine, mock_clock)
}

/// Establishes a Profile 1 context in the ROHC engine where the compressor
/// has an active TS stride and has signaled this stride to the decompressor via an IR-DYN packet.
///
/// # Parameters
/// - `engine`: Mutable reference to the `RohcEngine`.
/// - `cid`: Context ID for the flow.
/// - `ssrc`: SSRC for the RTP flow.
/// - `initial_sn`: Initial RTP sequence number for context establishment.
/// - `initial_ts`: Initial RTP timestamp for context establishment. This will be the
///   `ts_offset` in the compressor after the stride is detected using this as a base.
/// - `stride`: The desired RTP timestamp stride to establish.
pub fn establish_ts_stride_context(
    engine: &mut RohcEngine,
    cid: u16,
    ssrc: u32,
    initial_sn: u16,
    initial_ts_for_first_ir: u32,
    stride: u32,
) {
    let mut current_sn = initial_sn;
    let mut current_ts = initial_ts_for_first_ir;
    let mut last_known_ip_id;

    establish_ir_context(engine, cid, current_sn, current_ts, false, ssrc);
    last_known_ip_id = get_compressor_context(engine, cid).last_sent_ip_id_full;

    for _i in 0..P1_TS_STRIDE_ESTABLISHMENT_THRESHOLD {
        current_sn = current_sn.wrapping_add(1);
        current_ts = current_ts.wrapping_add(stride);
        let headers =
            create_rtp_headers(current_sn, current_ts, false, ssrc).with_ip_id(last_known_ip_id);
        let generic_headers = GenericUncompressedHeaders::RtpUdpIpv4(headers);
        // We only care about updating the compressor's internal state here.
        let _ = engine
            .compress(cid, Some(RohcProfile::RtpUdpIp), &generic_headers)
            .unwrap();
        last_known_ip_id = get_compressor_context(engine, cid).last_sent_ip_id_full;
    }

    // Force a new IR. Since compressor is in ts_scaled_mode, this IR will carry ts_stride.
    // The TS of THIS IR will become the new ts_offset for BOTH compressor and decompressor.
    current_sn = current_sn.wrapping_add(1);
    current_ts = current_ts.wrapping_add(stride);

    let headers_final_ir =
        create_rtp_headers(current_sn, current_ts, false, ssrc).with_ip_id(last_known_ip_id);
    let generic_final_ir = GenericUncompressedHeaders::RtpUdpIpv4(headers_final_ir);

    // Force compressor into IR mode for this packet
    let comp_ctx_dyn = engine
        .context_manager_mut()
        .get_compressor_context_mut(cid)
        .unwrap();
    let comp_ctx = comp_ctx_dyn
        .as_any_mut()
        .downcast_mut::<Profile1CompressorContext>()
        .unwrap();
    comp_ctx.mode = Profile1CompressorMode::InitializationAndRefresh;

    let compressed_final_ir = engine
        .compress(cid, Some(RohcProfile::RtpUdpIp), &generic_final_ir)
        .unwrap();
    let _ = engine.decompress(&compressed_final_ir).unwrap();
}

/// Creates RTP/UDP/IPv4 headers with customizable fields.
/// Accepts `ts_val` as `u32` and converts to `Timestamp` internally for convenience in tests.
pub fn create_rtp_headers(sn: u16, ts_val: u32, marker: bool, ssrc: u32) -> RtpUdpIpv4Headers {
    RtpUdpIpv4Headers {
        ip_src: "192.168.0.1".parse().unwrap(),
        ip_dst: "192.168.0.2".parse().unwrap(),
        udp_src_port: 1000,
        udp_dst_port: 2000,
        rtp_ssrc: ssrc,
        rtp_sequence_number: sn,
        rtp_timestamp: Timestamp::new(ts_val),
        rtp_marker: marker,
        ip_identification: sn.wrapping_add(ssrc as u16),
        ..Default::default()
    }
}

/// Creates RTP/UDP/IPv4 headers with a fixed SSRC value.
/// Accepts `ts_val` as `u32` and converts to `Timestamp` internally.
pub fn create_rtp_headers_fixed_ssrc(sn: u16, ts_val: u32, marker: bool) -> RtpUdpIpv4Headers {
    RtpUdpIpv4Headers {
        ip_src: "192.168.0.1".parse().unwrap(),
        ip_dst: "192.168.0.2".parse().unwrap(),
        udp_src_port: 10000,
        udp_dst_port: 20000,
        rtp_ssrc: 0x12345678,
        rtp_sequence_number: sn,
        rtp_timestamp: Timestamp::new(ts_val),
        rtp_marker: marker,
        ip_identification: sn.wrapping_add(0x1234),
        ..Default::default()
    }
}

/// Creates a default IrPacket structure for testing.
/// Accepts `ts_val` as `u32` for `dyn_rtp_timestamp`.
pub fn create_ir_packet_data(cid: u16, ssrc: u32, sn: u16, ts_val: u32) -> IrPacket {
    IrPacket {
        cid,
        profile_id: RohcProfile::RtpUdpIp,
        static_ip_src: "1.1.1.1".parse().unwrap(),
        static_ip_dst: "2.2.2.2".parse().unwrap(),
        static_udp_src_port: 100,
        static_udp_dst_port: 200,
        static_rtp_ssrc: ssrc,
        dyn_rtp_sn: sn,
        dyn_rtp_timestamp: Timestamp::new(ts_val),
        dyn_rtp_marker: false, // Default marker for this helper
        ts_stride: None,       // Defaults to None for basic IR data helper
        crc8: 0,               // Placeholder, calculated by builder
    }
}

/// Establishes an IR (Initialization and Refresh) context in the ROHC engine.
/// Accepts `initial_ts_val` as `u32` and uses it to create `RtpUdpIpv4Headers`.
pub fn establish_ir_context(
    engine: &mut RohcEngine,
    cid: u16,
    initial_sn: u16,
    initial_ts_val: u32,
    initial_marker: bool,
    ssrc: u32,
) {
    if let Ok(comp_ctx_dyn) = engine.context_manager_mut().get_compressor_context_mut(cid) {
        if let Some(p1_comp_ctx) = comp_ctx_dyn
            .as_any_mut()
            .downcast_mut::<Profile1CompressorContext>()
        {
            if p1_comp_ctx.rtp_ssrc == ssrc {
                p1_comp_ctx.mode = Profile1CompressorMode::InitializationAndRefresh;
            }
        }
    }

    let mut headers_ir = create_rtp_headers(initial_sn, initial_ts_val, initial_marker, ssrc);
    if headers_ir.ip_identification == 0 && initial_sn != 0 {
        headers_ir.ip_identification = initial_sn;
    }

    let generic_ir = GenericUncompressedHeaders::RtpUdpIpv4(headers_ir);

    let compressed_ir = engine
        .compress(cid, Some(RohcProfile::RtpUdpIp), &generic_ir)
        .unwrap_or_else(|e| {
            panic!(
                "IR Compression failed during setup for SN={}, SSRC={}: {:?}",
                initial_sn, ssrc, e
            )
        });

    if cid == 0 {
        assert_eq!(
            compressed_ir[0], P1_ROHC_IR_PACKET_TYPE_WITH_DYN,
            "IR packet type check for CID 0 failed."
        );
    } else if cid <= 15 {
        assert!(
            !compressed_ir.is_empty(),
            "IR packet with Add-CID is empty."
        );
        assert_eq!(
            compressed_ir[1], P1_ROHC_IR_PACKET_TYPE_WITH_DYN,
            "Core IR packet type check for small CID failed."
        );
    }

    engine.decompress(&compressed_ir).unwrap_or_else(|e| {
        panic!(
            "IR Decompression failed during setup for SN={}, SSRC={}: {:?}",
            initial_sn, ssrc, e
        );
    });
}

/// Calculates the IP Identification value that `establish_ir_context` will
/// effectively set in the compressor's context.
pub fn get_ip_id_established_by_ir(initial_sn: u16, ssrc_used_in_ir: u32) -> u16 {
    initial_sn.wrapping_add(ssrc_used_in_ir as u16)
}

/// Checks if a packet is an IR (Initialization and Refresh) packet.
pub fn is_ir_packet(packet: &[u8], cid: u16) -> bool {
    let min_len = if cid == 0 {
        1
    } else if cid <= 15 {
        2
    } else {
        return false;
    };
    if packet.len() < min_len {
        return false;
    }
    let type_byte_index = if cid == 0 { 0 } else { 1 };
    let type_byte = packet[type_byte_index];
    type_byte == P1_ROHC_IR_PACKET_TYPE_WITH_DYN || type_byte == P1_ROHC_IR_PACKET_TYPE_STATIC_ONLY
}

/// Checks if a packet is a UO-0 packet.
pub fn is_uo0_packet(packet: &[u8], cid: u16) -> bool {
    let expected_len = if cid == 0 {
        1
    } else if cid <= 15 {
        2
    } else {
        return false;
    };
    if packet.len() != expected_len {
        return false;
    }
    let type_byte_index = if cid == 0 { 0 } else { 1 };
    let type_byte = packet[type_byte_index];
    (type_byte & 0x80) == 0x00
}

/// Checks if a packet is a UO-1-SN packet.
pub fn is_uo1_sn_packet(packet: &[u8], cid: u16) -> bool {
    let expected_len = if cid == 0 {
        3
    } else if cid <= 15 {
        4
    } else {
        return false;
    };
    if packet.len() != expected_len {
        return false;
    }
    let type_byte_index = if cid == 0 { 0 } else { 1 };
    let type_byte = packet[type_byte_index];
    (type_byte & 0xFE) == P1_UO_1_SN_PACKET_TYPE_PREFIX
}

/// Gets the Profile1 decompressor context for the given CID. Panics on failure.
pub fn get_decompressor_context(engine: &RohcEngine, cid: u16) -> &Profile1DecompressorContext {
    engine
        .context_manager()
        .get_decompressor_context(cid)
        .unwrap_or_else(|_| panic!("No decompressor context for CID {}", cid))
        .as_any()
        .downcast_ref::<Profile1DecompressorContext>()
        .unwrap_or_else(|| panic!("Context for CID {} is not Profile1DecompressorContext", cid))
}

/// Gets the Profile1 compressor context for the given CID. Panics on failure.
pub fn get_compressor_context(engine: &RohcEngine, cid: u16) -> &Profile1CompressorContext {
    engine
        .context_manager()
        .get_compressor_context(cid)
        .unwrap_or_else(|_| panic!("No compressor context for CID {}", cid))
        .as_any()
        .downcast_ref::<Profile1CompressorContext>()
        .unwrap_or_else(|| panic!("Context for CID {} is not Profile1CompressorContext", cid))
}

/// Asserts that the decompressor is in the expected mode.
pub fn assert_decompressor_mode(
    engine: &RohcEngine,
    cid: u16,
    expected_mode: Profile1DecompressorMode,
    message: &str,
) {
    let ctx = get_decompressor_context(engine, cid);
    assert_eq!(ctx.mode, expected_mode, "{}", message);
}

/// Creates a new `Profile1Handler` instance for tests.
pub fn create_profile1_handler() -> Profile1Handler {
    Profile1Handler::new()
}

/// Creates a new Profile 1 compressor context for tests.
pub fn create_profile1_compressor_context(
    handler: &Profile1Handler,
    cid: u16,
) -> Box<dyn RohcCompressorContext> {
    handler.create_compressor_context(cid, DEFAULT_ENGINE_IR_REFRESH_INTERVAL, Instant::now())
}

/// Creates a new Profile 1 compressor context with a specific IR refresh interval for tests.
pub fn create_profile1_compressor_context_with_interval(
    handler: &dyn ProfileHandler,
    cid: u16,
    ir_refresh_interval: u32,
) -> Box<dyn RohcCompressorContext> {
    handler.create_compressor_context(cid, ir_refresh_interval, Instant::now())
}

/// Creates a new Profile 1 decompressor context for tests.
pub fn create_profile1_decompressor_context(
    handler: &dyn ProfileHandler,
    cid: u16,
) -> Box<dyn RohcDecompressorContext> {
    handler.create_decompressor_context(cid, Instant::now())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rtp_headers_creation() {
        let headers = create_rtp_headers(100, 1000, true, 0x12345678);
        assert_eq!(headers.rtp_sequence_number, 100);
        assert_eq!(headers.rtp_timestamp, Timestamp::new(1000));
        assert!(headers.rtp_marker);
        assert_eq!(headers.rtp_ssrc, 0x12345678);
        assert_eq!(headers.udp_src_port, 1000);
    }

    #[test]
    fn rtp_headers_fixed_ssrc_creation() {
        let headers = create_rtp_headers_fixed_ssrc(200, 2000, false);
        assert_eq!(headers.rtp_sequence_number, 200);
        assert_eq!(headers.rtp_timestamp, Timestamp::new(2000));
        assert!(!headers.rtp_marker);
        assert_eq!(headers.rtp_ssrc, 0x12345678);
        assert_eq!(headers.udp_src_port, 10000);
    }

    #[test]
    fn ir_packet_data_creation() {
        let ir_data = create_ir_packet_data(1, 0xABCD, 10, 100);
        assert_eq!(ir_data.cid, 1);
        assert_eq!(ir_data.static_rtp_ssrc, 0xABCD);
        assert_eq!(ir_data.dyn_rtp_sn, 10);
        assert_eq!(ir_data.dyn_rtp_timestamp, Timestamp::new(100));
        assert_eq!(ir_data.ts_stride, None);
    }

    #[test]
    fn ir_packet_identification() {
        let ir_dyn = vec![P1_ROHC_IR_PACKET_TYPE_WITH_DYN];
        assert!(is_ir_packet(&ir_dyn, 0));

        let ir_static = vec![P1_ROHC_IR_PACKET_TYPE_STATIC_ONLY];
        assert!(is_ir_packet(&ir_static, 0));

        let uo0 = vec![0x00];
        assert!(!is_ir_packet(&uo0, 0));

        let ir_dyn_with_cid = vec![0xE1, P1_ROHC_IR_PACKET_TYPE_WITH_DYN];
        assert!(is_ir_packet(&ir_dyn_with_cid, 1));
    }

    #[test]
    fn engine_creation_helpers() {
        let engine_default_refresh = create_default_test_engine();
        assert_eq!(
            engine_default_refresh
                .context_manager()
                .compressor_context_count(),
            0
        );

        let engine_specific_refresh = create_test_engine_with_system_clock(50);
        assert_eq!(
            engine_specific_refresh
                .context_manager()
                .decompressor_context_count(),
            0
        );

        let (engine_mock, _mock_clock) =
            create_test_engine_with_mock_clock(20, Duration::from_secs(10), Instant::now());
        assert_eq!(engine_mock.context_manager().compressor_context_count(), 0);
    }

    #[test]
    fn profile1_context_creation_helpers() {
        let handler = create_profile1_handler();
        let comp_ctx = create_profile1_compressor_context(&handler, 1);
        assert_eq!(comp_ctx.cid(), 1);

        let decomp_ctx = create_profile1_decompressor_context(&handler, 2);
        assert_eq!(decomp_ctx.cid(), 2);

        let comp_ctx_interval = create_profile1_compressor_context_with_interval(&handler, 3, 77);
        assert_eq!(comp_ctx_interval.cid(), 3);
    }

    #[test]
    fn get_ip_id_established_by_ir_logic() {
        assert_eq!(
            get_ip_id_established_by_ir(100, 0x12345678),
            100u16.wrapping_add(0x5678)
        );
        assert_eq!(
            get_ip_id_established_by_ir(0, 0xABCD),
            0u16.wrapping_add(0xABCD)
        );
        assert_eq!(
            get_ip_id_established_by_ir(65535, 1),
            65535u16.wrapping_add(1)
        );
    }
}
