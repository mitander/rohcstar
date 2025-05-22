//! Fuzzing harnesses for testing Rohcstar components, typically with the Drifter fuzzing framework.

use crate::packet_defs::{RohcIrProfile1Packet, RohcProfile};
use crate::packet_processor::build_ir_profile1_packet;
use crate::profiles::p1_handler::Profile1Handler;
use crate::traits::ProfileHandler;

/// Fuzzing harness for the ROHC Profile 1 U-mode decompressor.
///
/// This harness function is designed to be called by a fuzzer (like Drifter)
/// with arbitrary `data` representing a potential ROHC packet.
/// It uses the `Profile1Handler` to perform decompression.
///
/// **Setup:**
/// 1. A `Profile1Handler` is created.
/// 2. A decompressor context for Profile 1, CID 0, is created using the handler.
/// 3. A known-good ROHC IR (Initialization/Refresh) packet is constructed.
/// 4. This IR packet is processed by `handler.decompress` to attempt to bring
///    the decompressor context into a `FullContext` state. This makes
///    fuzzing more effective for compressed packet formats (UO-0, UO-1)
///    that require an established context.
/// 5. If the initial IR processing fails (either building the IR or decompressing it),
///    the harness falls back to fuzzing against a fresh, default Profile 1
///    decompressor context (typically in `NoContext` state). This ensures the harness
///    itself doesn't panic due to setup issues and can still fuzz initial packet handling.
///
/// **Fuzzing Target:**
/// The primary target is the `Profile1Handler::decompress` method with the
/// fuzzer-provided `data`. The goal is to find inputs that cause panics,
/// assertion failures, or other unexpected behavior in the decompressor logic.
///
/// # Arguments
/// * `data`: A byte slice containing the fuzzer-generated input, treated as a ROHC packet.
pub fn rohc_profile1_umode_decompressor_harness(data: &[u8]) {
    let p1_handler = Profile1Handler::new();
    let cid = 0u16;

    // Attempt to pre-condition the context to FullContext using a known-good IR packet.
    let sample_ir_data_for_harness = RohcIrProfile1Packet {
        cid, // This cid is for the content of the IR packet itself
        profile: RohcProfile::RtpUdpIp,
        // crc8 will be calculated by build_ir_profile1_packet
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

            // The `decompress` method on the handler takes `&mut dyn RohcDecompressorContext`.
            // We get this from the Box using `as_mut()`.
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
            // Failed to build the sample IR. This is a harness setup problem.
            // Fallback to fuzzing against a fresh, default P1 context.
            eprintln!("WARN: Harness failed to build sample IR. Fuzzing against default context.");
            let mut fresh_context_dyn = p1_handler.create_decompressor_context(cid);
            let _ = p1_handler.decompress(fresh_context_dyn.as_mut(), data);
        }
    }
}
