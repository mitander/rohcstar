//! Common test utilities for ROHC Profile 1 integration tests.
//!
//! This module provides shared helper functions for creating test data, establishing
//! contexts, and asserting packet properties across all Profile 1 integration tests.
#![allow(dead_code)]

use rohcstar::engine::RohcEngine;
use rohcstar::packet_defs::{GenericUncompressedHeaders, RohcProfile};
use rohcstar::profiles::profile1::constants::{
    P1_ROHC_IR_PACKET_TYPE_STATIC_ONLY, P1_ROHC_IR_PACKET_TYPE_WITH_DYN,
    P1_UO_1_SN_PACKET_TYPE_PREFIX,
};
use rohcstar::profiles::profile1::context::{
    Profile1CompressorContext, Profile1CompressorMode, Profile1DecompressorContext,
    Profile1DecompressorMode,
};
use std::time::Duration;

use rohcstar::profiles::profile1::{IrPacket, RtpUdpIpv4Headers};

// Default timeout test engines
pub const DEFAULT_ENGINE_TEST_TIMEOUT: Duration = Duration::from_secs(60 * 5);

/// Creates RTP/UDP/IPv4 headers with fully customizable fields
///
/// This is the most flexible header creation function, allowing control over
/// all dynamic fields including SSRC.
///
/// # Default values
/// - IP addresses: 192.168.0.1 -> 192.168.0.2
/// - UDP ports: 1000 -> 2000
/// - Other fields: Default trait values
pub fn create_rtp_headers(sn: u16, ts: u32, marker: bool, ssrc: u32) -> RtpUdpIpv4Headers {
    RtpUdpIpv4Headers {
        ip_src: "192.168.0.1".parse().unwrap(),
        ip_dst: "192.168.0.2".parse().unwrap(),
        udp_src_port: 1000,
        udp_dst_port: 2000,
        rtp_ssrc: ssrc,
        rtp_sequence_number: sn,
        rtp_timestamp: ts,
        rtp_marker: marker,
        ..Default::default()
    }
}

/// Creates RTP/UDP/IPv4 headers with a fixed SSRC value
///
/// Useful for tests that don't need to vary the SSRC. Uses different ports
/// than `create_rtp_headers` to help distinguish flows in multi-flow tests.
///
/// # Default values
/// - IP addresses: 192.168.0.1 -> 192.168.0.2
/// - UDP ports: 10000 -> 20000
/// - SSRC: 0x12345678
/// - Other fields: Default trait values
pub fn create_rtp_headers_fixed_ssrc(sn: u16, ts: u32, marker: bool) -> RtpUdpIpv4Headers {
    RtpUdpIpv4Headers {
        ip_src: "192.168.0.1".parse().unwrap(),
        ip_dst: "192.168.0.2".parse().unwrap(),
        udp_src_port: 10000,
        udp_dst_port: 20000,
        rtp_ssrc: 0x12345678,
        rtp_sequence_number: sn,
        rtp_timestamp: ts,
        rtp_marker: marker,
        ..Default::default()
    }
}

/// Creates a default IrPacket structure for testing
///
/// This helper creates an IrPacket with reasonable default values that can be
/// modified for specific test scenarios. The timestamp is derived from the
/// sequence number for simplicity.
///
/// # Default values
/// - Profile: RtpUdpIp
/// - IP addresses: 1.1.1.1 -> 2.2.2.2
/// - UDP ports: 100 -> 200
/// - RTP timestamp: sn * 10
/// - RTP marker: false
/// - CRC: 0 (to be calculated by builder)
pub fn create_ir_packet_data(cid: u16, ssrc: u32, sn: u16) -> IrPacket {
    IrPacket {
        cid,
        profile_id: RohcProfile::RtpUdpIp,
        static_ip_src: "1.1.1.1".parse().unwrap(),
        static_ip_dst: "2.2.2.2".parse().unwrap(),
        static_udp_src_port: 100,
        static_udp_dst_port: 200,
        static_rtp_ssrc: ssrc,
        dyn_rtp_sn: sn,
        dyn_rtp_timestamp: sn as u32 * 10, // Simple TS progression
        dyn_rtp_marker: false,
        crc8: 0, // Will be calculated by builder
    }
}

/// Establishes an IR (Initialization and Refresh) context in the ROHC engine
///
/// This function ensures that an IR packet is sent and successfully decompressed,
/// establishing a full context for subsequent UO (Uncompressed/Optimized) packet tests.
///
/// # Process
/// 1. Forces the compressor into IR mode (if context exists with same SSRC)
/// 2. Compresses an IR packet with the given parameters
/// 3. Verifies the packet is actually an IR packet
/// 4. Decompresses the packet to establish decompressor context
///
/// # Panics
/// - If compression fails
/// - If the generated packet is not an IR packet
/// - If decompression fails
pub fn establish_ir_context(
    engine: &mut RohcEngine,
    cid: u16,
    initial_sn: u16,
    initial_ts: u32,
    initial_marker: bool,
    ssrc: u32,
) {
    // Force the compressor context (if it exists) into IR mode to ensure an IR is sent
    if let Ok(comp_ctx_dyn) = engine.context_manager_mut().get_compressor_context_mut(cid) {
        if let Some(p1_comp_ctx) = comp_ctx_dyn
            .as_any_mut()
            .downcast_mut::<Profile1CompressorContext>()
        {
            // Only reset if SSRC is the same, otherwise SSRC change logic in handler will force IR
            if p1_comp_ctx.rtp_ssrc == ssrc {
                p1_comp_ctx.mode = Profile1CompressorMode::InitializationAndRefresh;
            }
        }
    }
    // If context doesn't exist, it will be created in IR mode anyway.

    let headers_ir = create_rtp_headers(initial_sn, initial_ts, initial_marker, ssrc);
    let generic_ir = GenericUncompressedHeaders::RtpUdpIpv4(headers_ir.clone());

    let compressed_ir = engine
        .compress(cid, Some(RohcProfile::RtpUdpIp), &generic_ir)
        .unwrap();

    // Verify it was actually an IR packet
    if cid == 0 {
        assert_eq!(
            compressed_ir[0], P1_ROHC_IR_PACKET_TYPE_WITH_DYN,
            "Setup compress call did not produce an IR packet"
        );
    } else if cid <= 15 {
        assert_eq!(
            compressed_ir[1], P1_ROHC_IR_PACKET_TYPE_WITH_DYN,
            "Setup compress call did not produce an IR packet (core)"
        );
    }

    engine.decompress(&compressed_ir).unwrap_or_else(|e| {
        panic!(
            "IR Decompression failed during setup for SN={}, SSRC={}: {:?}",
            initial_sn, ssrc, e
        );
    });
}

/// Checks if a packet is an IR (Initialization and Refresh) packet
///
/// Supports both IR-DYN (with dynamic chain) and IR static-only packets.
pub fn is_ir_packet(packet: &[u8], cid: u16) -> bool {
    let min_len = if cid == 0 {
        1
    } else if cid <= 15 {
        2
    } else {
        panic!("Large CIDs not supported in tests")
    };

    if packet.len() < min_len {
        return false;
    }

    let type_byte = if cid == 0 { packet[0] } else { packet[1] };
    type_byte == P1_ROHC_IR_PACKET_TYPE_WITH_DYN || type_byte == P1_ROHC_IR_PACKET_TYPE_STATIC_ONLY
}

/// Checks if a packet is a UO-0 packet
///
/// UO-0 packets are identified by:
/// - Specific length (1 byte for CID 0, 2 bytes for small CID)
/// - MSB = 0 in the type octet
pub fn is_uo0_packet(packet: &[u8], cid: u16) -> bool {
    let expected_len = if cid == 0 {
        1
    } else if cid <= 15 {
        2
    } else {
        panic!("Large CIDs not supported in tests")
    };

    if packet.len() != expected_len {
        return false;
    }

    let type_byte = if cid == 0 { packet[0] } else { packet[1] };
    (type_byte & 0x80) == 0x00 // MSB = 0 for UO-0
}

/// Checks if a packet is a UO-1-SN packet
///
/// UO-1-SN packets are identified by:
/// - Specific length (3 bytes for CID 0, 4 bytes for small CID)
/// - Type prefix = 10 (binary) in the type octet
pub fn is_uo1_sn_packet(packet: &[u8], cid: u16) -> bool {
    let expected_len = if cid == 0 {
        3
    } else if cid <= 15 {
        4
    } else {
        panic!("Large CIDs not supported in this specific test helper: is_uo1_sn_packet");
    };

    if packet.len() != expected_len {
        return false;
    }

    let type_byte = if cid == 0 { packet[0] } else { packet[1] };

    // UO-1-SN pattern is 1010000M.
    // P1_UO_1_SN_PACKET_TYPE_PREFIX is 0b10100000 (0xA0).
    // We need to check that the top 7 bits match 0b1010000.
    // The LSB is the marker bit and can be 0 or 1.
    // So, we can mask the type_byte with 0xFE (0b11111110) to ignore the LSB (marker bit),
    // and compare it against P1_UO_1_SN_PACKET_TYPE_PREFIX (which has M=0).
    (type_byte & 0xFE) == P1_UO_1_SN_PACKET_TYPE_PREFIX // P1_UO_1_SN_PACKET_TYPE_PREFIX is already 0xA0
}

/// Gets the Profile1 decompressor context for the given CID
///
/// # Panics
/// - If no decompressor context exists for the CID
/// - If the context is not a Profile1DecompressorContext
pub fn get_decompressor_context(engine: &RohcEngine, cid: u16) -> &Profile1DecompressorContext {
    let ctx_box = engine
        .context_manager()
        .get_decompressor_context(cid)
        .unwrap_or_else(|_| panic!("No decompressor context for CID {}", cid));

    ctx_box
        .as_any()
        .downcast_ref::<Profile1DecompressorContext>()
        .unwrap_or_else(|| {
            panic!(
                "Context for CID {} is not a Profile1DecompressorContext",
                cid
            )
        })
}

/// Gets the Profile1 compressor context for the given CID
///
/// # Panics
/// - If no compressor context exists for the CID
/// - If the context is not a Profile1CompressorContext
pub fn get_compressor_context(engine: &RohcEngine, cid: u16) -> &Profile1CompressorContext {
    let ctx_box = engine
        .context_manager()
        .get_compressor_context(cid)
        .unwrap_or_else(|_| panic!("No compressor context for CID {}", cid));

    ctx_box
        .as_any()
        .downcast_ref::<Profile1CompressorContext>()
        .unwrap_or_else(|| panic!("Context for CID {} is not a Profile1CompressorContext", cid))
}

/// Asserts that the decompressor is in the expected mode
pub fn assert_decompressor_mode(
    engine: &RohcEngine,
    cid: u16,
    expected_mode: Profile1DecompressorMode,
    message: &str,
) {
    let ctx = get_decompressor_context(engine, cid);
    assert_eq!(ctx.mode, expected_mode, "{}", message);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_rtp_headers() {
        let headers = create_rtp_headers(100, 1000, true, 0x12345678);
        assert_eq!(headers.rtp_sequence_number, 100);
        assert_eq!(headers.rtp_timestamp, 1000);
        assert!(headers.rtp_marker);
        assert_eq!(headers.rtp_ssrc, 0x12345678);
        assert_eq!(headers.udp_src_port, 1000);
    }

    #[test]
    fn test_create_rtp_headers_fixed_ssrc() {
        let headers = create_rtp_headers_fixed_ssrc(200, 2000, false);
        assert_eq!(headers.rtp_sequence_number, 200);
        assert_eq!(headers.rtp_timestamp, 2000);
        assert!(!headers.rtp_marker);
        assert_eq!(headers.rtp_ssrc, 0x12345678);
        assert_eq!(headers.udp_src_port, 10000);
    }

    #[test]
    fn test_is_ir_packet() {
        // IR-DYN packet
        let ir_dyn = vec![P1_ROHC_IR_PACKET_TYPE_WITH_DYN];
        assert!(is_ir_packet(&ir_dyn, 0));

        // IR static-only packet
        let ir_static = vec![P1_ROHC_IR_PACKET_TYPE_STATIC_ONLY];
        assert!(is_ir_packet(&ir_static, 0));

        // UO-0 packet (should not be IR)
        let uo0 = vec![0x00];
        assert!(!is_ir_packet(&uo0, 0));

        // With Add-CID
        let ir_dyn_with_cid = vec![0xE1, P1_ROHC_IR_PACKET_TYPE_WITH_DYN];
        assert!(is_ir_packet(&ir_dyn_with_cid, 1));
    }

    #[test]
    fn test_packet_type_identification() {
        // UO-0 packet for CID 0
        let uo0 = vec![0x45]; // Example: SN LSBs = 0b1000, CRC LSBs = 0b101 => 01000101
        assert!(is_uo0_packet(&uo0, 0));
        assert!(!is_uo1_sn_packet(&uo0, 0)); // Correctly not UO-1-SN
        assert!(!is_ir_packet(&uo0, 0));

        // UO-1-SN packet for CID 0 (Marker = true)
        let uo1_marker_true = vec![0xA1, 0x12, 0x34]; // 0xA1 = 0b10100001 (M=1)
        assert!(!is_uo0_packet(&uo1_marker_true, 0));
        assert!(
            is_uo1_sn_packet(&uo1_marker_true, 0),
            "Failed for UO-1 with M=1"
        );
        assert!(!is_ir_packet(&uo1_marker_true, 0));

        // UO-1-SN packet for CID 0 (Marker = false)
        let uo1_marker_false = vec![0xA0, 0x56, 0x78]; // 0xA0 = 0b10100000 (M=0)
        assert!(!is_uo0_packet(&uo1_marker_false, 0));
        assert!(
            is_uo1_sn_packet(&uo1_marker_false, 0),
            "Failed for UO-1 with M=0"
        );
        assert!(!is_ir_packet(&uo1_marker_false, 0));
    }
}
