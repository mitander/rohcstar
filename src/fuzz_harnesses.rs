//! Fuzz testing harnesses for Rohcstar components.
//!
//! This module contains fuzz testing targets and utilities for verifying the
//! robustness of the ROHC implementation against malformed inputs.
//! It uses the Drifter fuzzing framework to test various aspects of
//! ROHC packet processing, including compression and decompression.

use std::time::Instant;

use crate::crc::CrcCalculators;
use crate::packet_defs::RohcProfile;
use crate::profiles::profile1::{
    IrPacket as Profile1IrPacket, Profile1Handler, packet_processor::build_profile1_ir_packet,
    protocol_types::Timestamp,
};
use crate::traits::ProfileHandler;

/// Fuzz tests the Profile 1 U-mode decompressor.
///
/// Tests `Profile1Handler::decompress` with fuzzer-generated input.
///
/// # Setup
/// - Creates a Profile1Handler and decompressor context (CID 0)
/// - Attempts to establish FullContext using a known IR packet
/// - Falls back to NoContext if setup fails
///
/// # Parameters
/// - `data`: Fuzzer-generated input treated as ROHC packet
pub fn rohc_profile1_umode_decompressor_harness(data: &[u8]) {
    let p1_handler = Profile1Handler::new();
    let cid = 0u16;
    let crc_calculators = CrcCalculators::new();

    // Attempt to pre-condition the context to FullContext using a known-good IR packet.
    let sample_ir_data_for_harness = Profile1IrPacket {
        cid,
        profile_id: RohcProfile::RtpUdpIp,
        static_ip_src: "1.1.1.1"
            .parse()
            .expect("Harness: Static IP parsing failed"),
        static_ip_dst: "2.2.2.2"
            .parse()
            .expect("Harness: Static IP parsing failed"),
        static_udp_src_port: 100,
        static_udp_dst_port: 200,
        static_rtp_ssrc: 12345,
        dyn_rtp_sn: 1,
        dyn_rtp_timestamp: Timestamp::new(1000),
        dyn_rtp_marker: false,
        ts_stride: None, // Added missing field
        crc8: 0,
    };

    match build_profile1_ir_packet(&sample_ir_data_for_harness, &crc_calculators) {
        Ok(sample_ir_bytes) => {
            let mut decompressor_context_dyn =
                p1_handler.create_decompressor_context(cid, Instant::now());

            // Core IR bytes for CID 0 are the full packet (no Add-CID stripping needed)
            if p1_handler
                .decompress(decompressor_context_dyn.as_mut(), &sample_ir_bytes)
                .is_ok()
            {
                // Successfully pre-conditioned context. Now fuzz with this context.
                let _ = p1_handler.decompress(decompressor_context_dyn.as_mut(), data);
            } else {
                eprintln!(
                    "WARN: Harness failed to decompress sample IR. Fuzzing against default context."
                );
                let mut fresh_context_dyn =
                    p1_handler.create_decompressor_context(cid, Instant::now());
                let _ = p1_handler.decompress(fresh_context_dyn.as_mut(), data);
            }
        }
        Err(_e) => {
            eprintln!("WARN: Harness failed to build sample IR. Fuzzing against default context.");
            let mut fresh_context_dyn = p1_handler.create_decompressor_context(cid, Instant::now());
            let _ = p1_handler.decompress(fresh_context_dyn.as_mut(), data);
        }
    }
}
