//! Fuzz testing harnesses for Rohcstar components.
//!
//! This module contains fuzz testing targets and utilities for verifying the
//! robustness of the ROHC implementation against malformed inputs.
//! It uses the Drifter fuzzing framework to test various aspects of
//! ROHC packet processing, including compression and decompression.

use crate::packet_defs::{RohcIrProfile1Packet, RohcProfile};
use crate::packet_processor::build_ir_profile1_packet;
use crate::profiles::p1_handler::Profile1Handler;
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

    // Attempt to pre-condition the context to FullContext using a known-good IR packet.
    let sample_ir_data_for_harness = RohcIrProfile1Packet {
        cid,
        profile: RohcProfile::RtpUdpIp,
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
        dyn_rtp_timestamp: 1000,
        dyn_rtp_marker: false,
        crc8: 0,
    };

    match build_ir_profile1_packet(&sample_ir_data_for_harness) {
        Ok(sample_ir_bytes) => {
            // Attempt to process the sample IR to bring context to FullContext.
            // The decompress method expects the core packet bytes (after Add-CID is stripped).
            // build_ir_profile1_packet for CID 0 doesn't add an Add-CID octet.
            // If sample_ir_data_for_harness.cid was >0, build_ir_profile1_packet would add it,
            // and we'd need to strip it here before passing to p1_handler.decompress.
            // For CID 0, sample_ir_bytes *are* the core_packet_bytes.
            let mut decompressor_context_dyn = p1_handler.create_decompressor_context(cid);

            if p1_handler
                .decompress(decompressor_context_dyn.as_mut(), &sample_ir_bytes)
                .is_ok()
            {
                // Successfully pre-conditioned context. Now fuzz with this context.
                let _ = p1_handler.decompress(decompressor_context_dyn.as_mut(), data);
            } else {
                // Failed to decompress the known-good IR.
                // Fallback: fuzz against a fresh, default P1 context.
                eprintln!(
                    "WARN: Harness failed to decompress sample IR. Fuzzing against default context."
                );
                let mut fresh_context_dyn = p1_handler.create_decompressor_context(cid);
                let _ = p1_handler.decompress(fresh_context_dyn.as_mut(), data);
            }
        }
        Err(_e) => {
            // Failed to build the sample IR (harness setup problem)
            // Fallback to fuzzing against a fresh, default P1 context.
            eprintln!("WARN: Harness failed to build sample IR. Fuzzing against default context.");
            let mut fresh_context_dyn = p1_handler.create_decompressor_context(cid);
            let _ = p1_handler.decompress(fresh_context_dyn.as_mut(), data);
        }
    }
}
