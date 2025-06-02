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

/// Creates a `RohcEngine` with a `SystemClock` for general integration testing,
/// using default IR refresh interval and test timeout values.
///
/// # Returns
/// A new `RohcEngine` instance.
pub fn create_default_test_engine() -> RohcEngine {
    RohcEngine::new(
        DEFAULT_ENGINE_IR_REFRESH_INTERVAL,
        DEFAULT_ENGINE_TEST_TIMEOUT,
        Arc::new(SystemClock),
    )
}

/// Creates a `RohcEngine` with a `SystemClock` for general integration testing,
/// allowing a specific IR refresh interval.
///
/// # Parameters
/// - `ir_refresh_interval`: The interval (in packets) for IR refreshes.
///
/// # Returns
/// A new `RohcEngine` instance configured with the given IR refresh interval.
pub fn create_test_engine_with_system_clock(ir_refresh_interval: u32) -> RohcEngine {
    RohcEngine::new(
        ir_refresh_interval,
        DEFAULT_ENGINE_TEST_TIMEOUT,
        Arc::new(SystemClock),
    )
}

/// Creates a `RohcEngine` with a controllable `MockClock` for time-sensitive tests.
///
/// This allows tests to precisely control the passage of time, which is crucial for
/// verifying context timeout logic and other time-dependent behaviors.
///
/// # Parameters
/// - `ir_refresh_interval`: The interval (in packets) for IR refreshes.
/// - `timeout`: The context timeout duration.
/// - `initial_mock_time`: The starting time for the `MockClock`.
///
/// # Returns
/// A tuple containing the configured `RohcEngine` and an `Arc<MockClock>`
/// which can be used to manipulate time during the test.
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
/// This is a complex setup utility designed to prepare the engine's state for testing
/// UO-1-RTP packets, which rely on `ts_scaled_mode` being active and a `ts_stride`
/// being established in both compressor and decompressor contexts.
///
/// # Parameters
/// - `engine`: Mutable reference to the `RohcEngine`.
/// - `cid`: Context ID for the flow.
/// - `ssrc`: SSRC for the RTP flow.
/// - `final_ir_sn_val`: The RTP sequence number for the final, definitive IR-DYN packet.
/// - `final_ir_ts_val`: The RTP timestamp for the final IR-DYN packet. This value will
///   become the `ts_offset` in both contexts after this function.
/// - `stride`: The desired RTP timestamp stride to establish.
///
/// # Panics
/// Panics if internal assertions about context state or packet generation fail.
pub fn establish_ts_stride_context_for_uo1_rtp(
    engine: &mut rohcstar::engine::RohcEngine,
    cid: u16,
    ssrc: u32,
    final_ir_sn_val: u16,
    final_ir_ts_val: u32,
    stride: u32,
) {
    // 1. Send an initial IR. Its TS will be the *initial* ts_offset for stride detection.
    let initial_setup_sn = final_ir_sn_val.wrapping_sub(1); // SN of packet *before* the final IR
    let initial_setup_ts_val = final_ir_ts_val.wrapping_sub(stride); // TS of packet *before* the final IR

    establish_ir_context(
        engine,
        cid,
        initial_setup_sn,
        initial_setup_ts_val,
        false,
        ssrc,
    );
    let ip_id_for_final_ir = get_ip_id_established_by_ir(initial_setup_sn, ssrc).wrapping_add(1);

    // 2. Directly manipulate compressor context to simulate that stride has been
    //    detected and scaled mode is active. This bypasses sending UO packets for setup,
    //    avoiding the UO-0 vs UO-1-TS selection problem.
    let comp_ctx_dyn_setup = engine
        .context_manager_mut()
        .get_compressor_context_mut(cid)
        .unwrap();
    let comp_ctx_concrete_setup = comp_ctx_dyn_setup
        .as_any_mut()
        .downcast_mut::<rohcstar::profiles::profile1::context::Profile1CompressorContext>()
        .unwrap();

    comp_ctx_concrete_setup.ts_stride = Some(stride);
    // ts_offset should be the TS of the packet *before* stride detection starts.
    // Here, it's the TS of the 'initial_setup_sn' IR.
    comp_ctx_concrete_setup.ts_offset = Timestamp::new(initial_setup_ts_val);
    comp_ctx_concrete_setup.ts_stride_packets = P1_TS_STRIDE_ESTABLISHMENT_THRESHOLD;
    comp_ctx_concrete_setup.ts_scaled_mode = true;
    // Ensure last sent fields are from the initial_setup_sn IR
    comp_ctx_concrete_setup.last_sent_rtp_sn_full = initial_setup_sn;
    comp_ctx_concrete_setup.last_sent_rtp_ts_full = Timestamp::new(initial_setup_ts_val);

    // 3. Send the definitive IR packet. Since ts_scaled_mode and ts_stride are now set
    //    in the compressor, this IR will signal TS_STRIDE. Its dynamic TS will become
    //    the new TS_OFFSET for both compressor and decompressor.
    let headers_final_ir = create_rtp_headers(final_ir_sn_val, final_ir_ts_val, false, ssrc)
        .with_ip_id(ip_id_for_final_ir);

    // Get context again to force IR mode (as above may have been just before FO->SO transition)
    let comp_ctx_dyn_final_ir = engine
        .context_manager_mut()
        .get_compressor_context_mut(cid)
        .unwrap();
    let comp_ctx_concrete_final_ir = comp_ctx_dyn_final_ir
        .as_any_mut()
        .downcast_mut::<rohcstar::profiles::profile1::context::Profile1CompressorContext>()
        .unwrap();
    comp_ctx_concrete_final_ir.mode =
        rohcstar::profiles::profile1::context::Profile1CompressorMode::InitializationAndRefresh;
    // These should persist from step 2, but ensure they are set for the IR logic
    assert!(
        comp_ctx_concrete_final_ir.ts_scaled_mode,
        "Helper: ts_scaled_mode not true before final IR build"
    );
    assert_eq!(
        comp_ctx_concrete_final_ir.ts_stride,
        Some(stride),
        "Helper: ts_stride not Some(stride) before final IR build"
    );

    let compressed_final_ir = engine
        .compress(
            cid,
            Some(RohcProfile::RtpUdpIp),
            &GenericUncompressedHeaders::RtpUdpIpv4(headers_final_ir),
        )
        .unwrap();
    assert!(
        compressed_final_ir.len() > 4,
        "Final setup IR packet too short (len {})",
        compressed_final_ir.len()
    );
    let type_byte_idx = if cid != 0 && cid <= 15 { 1 } else { 0 };
    if !compressed_final_ir.is_empty() {
        assert_eq!(
            compressed_final_ir[type_byte_idx], P1_ROHC_IR_PACKET_TYPE_WITH_DYN,
            "Final setup IR should be IR-DYN"
        );
    }
    let _ = engine.decompress(&compressed_final_ir).unwrap();

    // Verify alignment post final IR
    let comp_ctx_final_check = get_compressor_context(engine, cid);
    let decomp_ctx_final_check = get_decompressor_context(engine, cid);

    assert_eq!(
        comp_ctx_final_check.ts_offset,
        Timestamp::new(final_ir_ts_val),
        "FINAL C: ts_offset. Got {}, expected {}",
        comp_ctx_final_check.ts_offset.value(),
        final_ir_ts_val
    );
    assert!(
        comp_ctx_final_check.ts_scaled_mode,
        "FINAL C: ts_scaled_mode."
    );
    assert_eq!(
        comp_ctx_final_check.ts_stride,
        Some(stride),
        "FINAL C: ts_stride."
    );

    assert_eq!(
        decomp_ctx_final_check.ts_offset,
        Timestamp::new(final_ir_ts_val),
        "FINAL D: ts_offset. Got {}, expected {}",
        decomp_ctx_final_check.ts_offset.value(),
        final_ir_ts_val
    );
    assert!(
        decomp_ctx_final_check.ts_scaled_mode,
        "FINAL D: ts_scaled_mode."
    );
    assert_eq!(
        decomp_ctx_final_check.ts_stride,
        Some(stride),
        "FINAL D: ts_stride."
    );
}

/// Creates RTP/UDP/IPv4 headers with customizable dynamic fields and default static fields.
///
/// Static fields (IP addresses, ports) are set to predefined common values.
/// IP Identification is derived from `sn + ssrc` (lower 16 bits).
/// Accepts `ts_val` as `u32` and converts to `Timestamp` internally.
///
/// # Parameters
/// - `sn`: RTP Sequence Number.
/// - `ts_val`: RTP Timestamp value (as `u32`).
/// - `marker`: RTP Marker bit.
/// - `ssrc`: RTP SSRC identifier.
///
/// # Returns
/// An `RtpUdpIpv4Headers` struct.
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

/// Creates RTP/UDP/IPv4 headers with a fixed SSRC (0x12345678) and IP-ID (0x1234).
///
/// Useful for tests where SSRC and IP-ID variations are not the primary focus.
/// Accepts `ts_val` as `u32` and converts to `Timestamp` internally.
/// Static fields (IP addresses, ports) are set to predefined values different from `create_rtp_headers`.
///
/// # Parameters
/// - `sn`: RTP Sequence Number.
/// - `ts_val`: RTP Timestamp value (as `u32`).
/// - `marker`: RTP Marker bit.
///
/// # Returns
/// An `RtpUdpIpv4Headers` struct.
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
        ip_identification: 0x1234,
        ..Default::default()
    }
}

/// Creates a default `IrPacket` structure populated with basic test data.
///
/// The CRC8 field is set to 0 (placeholder, as it's calculated by the builder).
/// The `ts_stride` field defaults to `None`.
/// Accepts `ts_val` as `u32` for `dyn_rtp_timestamp`.
///
/// # Parameters
/// - `cid`: Context Identifier.
/// - `ssrc`: RTP SSRC for the static chain.
/// - `sn`: RTP Sequence Number for the dynamic chain.
/// - `ts_val`: RTP Timestamp value (as `u32`) for the dynamic chain.
///
/// # Returns
/// An `IrPacket` struct.
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
///
/// This function sends an IR packet through the engine's compressor and then
/// decompressor to ensure a valid Profile 1 context is established for the given CID.
/// If a compressor context for the `cid` already exists and its SSRC matches `ssrc`,
/// it forces the compressor into `InitializationAndRefresh` mode before sending the IR.
/// If `headers_ir.ip_identification` is 0 and `initial_sn` is not 0 after creation,
/// `ip_identification` is set to `initial_sn` for the IR packet.
/// Accepts `initial_ts_val` as `u32` and uses it to create `RtpUdpIpv4Headers`.
///
/// # Parameters
/// - `engine`: Mutable reference to the `RohcEngine`.
/// - `cid`: Context Identifier for the flow.
/// - `initial_sn`: Initial RTP Sequence Number for the IR packet.
/// - `initial_ts_val`: Initial RTP Timestamp value (as `u32`) for the IR packet.
/// - `initial_marker`: Initial RTP Marker bit for the IR packet.
/// - `ssrc`: SSRC for the RTP flow.
///
/// # Panics
/// Panics if compression or decompression of the IR packet fails, or if internal
/// assertions about the IR packet type (e.g., `P1_ROHC_IR_PACKET_TYPE_WITH_DYN`) fail.
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
///
/// `establish_ir_context` uses `create_rtp_headers` which by default calculates
/// `ip_identification` as `sn.wrapping_add(ssrc as u16)`.
/// This helper provides a consistent way to get this value for test assertions.
///
/// # Parameters
/// - `initial_sn`: The sequence number used to establish the IR context.
/// - `ssrc_used_in_ir`: The SSRC used to establish the IR context.
///
/// # Returns
/// The calculated IP Identification value.
pub fn get_ip_id_established_by_ir(initial_sn: u16, ssrc_used_in_ir: u32) -> u16 {
    initial_sn.wrapping_add(ssrc_used_in_ir as u16)
}

/// Checks if a given ROHC packet (core part, after Add-CID) is an IR or IR-DYN packet for Profile 1.
///
/// # Parameters
/// - `packet`: Byte slice of the core ROHC packet.
/// - `cid`: The CID of the packet flow. This determines if an Add-CID byte was stripped (not used here directly but implies caller handles it).
///
/// # Returns
/// `true` if the packet is recognized as an IR or IR-DYN type, `false` otherwise.
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

/// Checks if a given ROHC packet (core part, after Add-CID) is a UO-0 packet for Profile 1.
///
/// # Parameters
/// - `packet`: Byte slice of the core ROHC packet.
/// - `cid`: The CID of the packet flow. This influences expected length if Add-CID was present.
///
/// # Returns
/// `true` if the packet matches UO-0 criteria, `false` otherwise.
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

/// Checks if a given ROHC packet (core part, after Add-CID) is a UO-1-SN packet for Profile 1.
///
/// # Parameters
/// - `packet`: Byte slice of the core ROHC packet.
/// - `cid`: The CID of the packet flow. This influences expected length.
///
/// # Returns
/// `true` if the packet matches UO-1-SN criteria, `false` otherwise.
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

/// Retrieves an immutable reference to the `Profile1DecompressorContext` for a given CID.
///
/// # Parameters
/// - `engine`: Reference to the `RohcEngine`.
/// - `cid`: The Context ID of the decompressor context to retrieve.
///
/// # Returns
/// A reference to the `Profile1DecompressorContext`.
///
/// # Panics
/// Panics if no context is found for the CID or if the context is not of type `Profile1DecompressorContext`.
pub fn get_decompressor_context(engine: &RohcEngine, cid: u16) -> &Profile1DecompressorContext {
    engine
        .context_manager()
        .get_decompressor_context(cid)
        .unwrap_or_else(|_| panic!("No decompressor context for CID {}", cid))
        .as_any()
        .downcast_ref::<Profile1DecompressorContext>()
        .unwrap_or_else(|| panic!("Context for CID {} is not Profile1DecompressorContext", cid))
}

/// Retrieves an immutable reference to the `Profile1CompressorContext` for a given CID.
///
/// # Parameters
/// - `engine`: Reference to the `RohcEngine`.
/// - `cid`: The Context ID of the compressor context to retrieve.
///
/// # Returns
/// A reference to the `Profile1CompressorContext`.
///
/// # Panics
/// Panics if no context is found for the CID or if the context is not of type `Profile1CompressorContext`.
pub fn get_compressor_context(engine: &RohcEngine, cid: u16) -> &Profile1CompressorContext {
    engine
        .context_manager()
        .get_compressor_context(cid)
        .unwrap_or_else(|_| panic!("No compressor context for CID {}", cid))
        .as_any()
        .downcast_ref::<Profile1CompressorContext>()
        .unwrap_or_else(|| panic!("Context for CID {} is not Profile1CompressorContext", cid))
}

/// Asserts that the decompressor context for a given CID is in the expected `Profile1DecompressorMode`.
///
/// # Parameters
/// - `engine`: Reference to the `RohcEngine`.
/// - `cid`: The Context ID of the decompressor context to check.
/// - `expected_mode`: The `Profile1DecompressorMode` that the context is expected to be in.
/// - `message`: A message to include in the assertion failure if the modes do not match.
///
/// # Panics
/// Panics if the context's mode does not match `expected_mode`, or if the context cannot be found/downcast.
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
///
/// # Returns
/// A new `Profile1Handler`.
pub fn create_profile1_handler() -> Profile1Handler {
    Profile1Handler::new()
}

/// Creates a new Profile 1 compressor context using the provided handler and default IR refresh interval.
///
/// # Parameters
/// - `handler`: Reference to a `Profile1Handler`.
/// - `cid`: The Context ID for the new compressor context.
///
/// # Returns
/// A `Box<dyn RohcCompressorContext>` for Profile 1.
pub fn create_profile1_compressor_context(
    handler: &Profile1Handler,
    cid: u16,
) -> Box<dyn RohcCompressorContext> {
    handler.create_compressor_context(cid, DEFAULT_ENGINE_IR_REFRESH_INTERVAL, Instant::now())
}

/// Creates a new Profile 1 compressor context with a specific IR refresh interval.
///
/// # Parameters
/// - `handler`: Reference to a `dyn ProfileHandler` (can be `Profile1Handler`).
/// - `cid`: The Context ID for the new compressor context.
/// - `ir_refresh_interval`: The desired IR refresh interval for the context.
///
/// # Returns
/// A `Box<dyn RohcCompressorContext>` for Profile 1.
pub fn create_profile1_compressor_context_with_interval(
    handler: &dyn ProfileHandler,
    cid: u16,
    ir_refresh_interval: u32,
) -> Box<dyn RohcCompressorContext> {
    handler.create_compressor_context(cid, ir_refresh_interval, Instant::now())
}

/// Creates a new Profile 1 decompressor context using the provided handler.
///
/// # Parameters
/// - `handler`: Reference to a `dyn ProfileHandler` (can be `Profile1Handler`).
/// - `cid`: The Context ID for the new decompressor context.
///
/// # Returns
/// A `Box<dyn RohcDecompressorContext>` for Profile 1
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
