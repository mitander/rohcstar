use crate::context::RtpUdpIpP1DecompressorContext;
use crate::decompress_rtp_udp_ip_umode;
use crate::packet_processor::{PROFILE_ID_RTP_UDP_IP, build_ir_profile1_packet};
use crate::protocol_types::RohcIrProfile1Packet;

pub fn rohc_decompressor_harness(data: &[u8]) {
    let mut context = RtpUdpIpP1DecompressorContext::default();

    let ir_data = RohcIrProfile1Packet {
        cid: 0,
        profile: PROFILE_ID_RTP_UDP_IP,
        crc8: 0,
        static_ip_src: "1.1.1.1".parse().unwrap(),
        static_ip_dst: "2.2.2.2".parse().unwrap(),
        static_udp_src_port: 100,
        static_udp_dst_port: 200,
        static_rtp_ssrc: 123,
        dyn_rtp_sn: 1,
        dyn_rtp_timestamp: 10,
        dyn_rtp_marker: false,
    };
    match build_ir_profile1_packet(&ir_data) {
        Ok(sample_ir_bytes) => {
            match decompress_rtp_udp_ip_umode(&mut context, &sample_ir_bytes) {
                Ok(_) => {
                    let _ = decompress_rtp_udp_ip_umode(&mut context, data);
                }
                Err(_e) => {
                    // If sample IR fails, this is a harness/base code problem.
                    // For fuzzing, we might just proceed with NoContext or panic to fix harness.
                    // For now, let's proceed fuzzing against initial context.
                    let _ = decompress_rtp_udp_ip_umode(
                        &mut RtpUdpIpP1DecompressorContext::default(),
                        data,
                    );
                }
            }
        }
        Err(_e) => {
            // Failed to build sample IR, harness issue
            let _ =
                decompress_rtp_udp_ip_umode(&mut RtpUdpIpP1DecompressorContext::default(), data);
        }
    }
}
