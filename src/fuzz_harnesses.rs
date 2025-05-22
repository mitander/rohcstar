use crate::context::RtpUdpIpP1DecompressorContext;
use crate::decompress_rtp_udp_ip_umode;
use crate::packet_defs::RohcProfile;
use crate::packet_processor::build_ir_profile1_packet;
use crate::protocol_types::RohcIrProfile1Packet;

/// Fuzzing harness for the ROHC Profile 1 U-mode decompressor.
///
/// This harness function is designed to be called by a fuzzer (like Drifter)
/// with arbitrary `data` representing a potential ROHC packet.
///
/// **Setup:**
/// 1. A default `RtpUdpIpP1DecompressorContext` is created.
/// 2. A known-good ROHC IR (Initialization/Refresh) packet is constructed and
///    processed by the decompressor. This aims to bring the decompressor context
///    into a `FullContext` state before fuzzing with arbitrary data. This makes
///    the fuzzing more effective for testing compressed packet formats (UO-0, UO-1)
///    that require an established context.
/// 3. If the initial IR processing fails (either building or decompressing it),
///    the harness falls back to fuzzing against a default (NoContext) decompressor state.
///    This ensures the harness itself doesn't panic due to setup issues and can still
///    fuzz the initial packet handling logic of the decompressor.
///
/// **Fuzzing Target:**
/// The primary target is `decompress_rtp_udp_ip_umode` with the fuzzer-provided `data`.
/// The goal is to find inputs that cause panics, assertion failures, or other
/// unexpected behavior in the decompressor logic.
///
/// # Arguments
/// * `data`: A byte slice containing the fuzzer-generated input, treated as a ROHC packet.
pub fn rohc_profile1_umode_decompressor_harness(data: &[u8]) {
    // Initialize a decompressor context for Profile 1, CID 0.
    let mut decompressor_context = RtpUdpIpP1DecompressorContext::new(0, RohcProfile::RtpUdpIp);

    // Attempt to pre-condition the context to FullContext using a known-good IR packet.
    // This makes fuzzing of UO-0/UO-1 packets more meaningful.
    let sample_ir_data = RohcIrProfile1Packet {
        cid: 0,
        profile: RohcProfile::RtpUdpIp,
        static_ip_src: "1.1.1.1"
            .parse()
            .expect("Static IP parsing failed in harness"),
        static_ip_dst: "2.2.2.2"
            .parse()
            .expect("Static IP parsing failed in harness"),
        static_udp_src_port: 100,
        static_udp_dst_port: 200,
        static_rtp_ssrc: 12345,
        dyn_rtp_sn: 1,
        dyn_rtp_timestamp: 1000,
        dyn_rtp_marker: false,
        ..Default::default()
    };

    match build_ir_profile1_packet(&sample_ir_data) {
        Ok(sample_ir_bytes) => {
            // Attempt to process the sample IR to bring context to FullContext
            if decompress_rtp_udp_ip_umode(&mut decompressor_context, &sample_ir_bytes).is_ok() {
                // Successfully pre-conditioned context. Now fuzz with this context.
                let _ = decompress_rtp_udp_ip_umode(&mut decompressor_context, data);
            } else {
                // Failed to decompress the known-good IR. This might indicate a deeper issue
                // in the decompressor or context setup. For fuzzing, proceed by fuzzing
                // against a fresh, NoContext state to still catch basic parsing errors.
                eprintln!(
                    "WARN: Harness failed to decompress sample IR. Fuzzing against default context."
                );
                let mut fresh_context = RtpUdpIpP1DecompressorContext::default();
                let _ = decompress_rtp_udp_ip_umode(&mut fresh_context, data);
            }
        }
        Err(_e) => {
            // Failed to build the sample IR. This is a harness setup problem.
            // Fallback to fuzzing against a fresh, NoContext state.
            eprintln!("WARN: Harness failed to build sample IR. Fuzzing against default context.");
            let mut fresh_context = RtpUdpIpP1DecompressorContext::default();
            let _ = decompress_rtp_udp_ip_umode(&mut fresh_context, data);
        }
    }
}
