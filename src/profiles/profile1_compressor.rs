use crate::context::{CompressorMode, RtpUdpIpP1CompressorContext};
use crate::encodings::encode_lsb;
use crate::error::RohcError;
use crate::packet_processor::{
    PROFILE_ID_RTP_UDP_IP, build_ir_profile1_packet, build_uo0_profile1_cid0_packet,
};
use crate::protocol_types::{RohcIrProfile1Packet, RtpUdpIpv4Headers};

pub const DEFAULT_UO0_SN_LSB_WIDTH: u8 = 4;

pub fn compress_rtp_udp_ip_umode(
    context: &mut RtpUdpIpP1CompressorContext,
    uncompressed_headers: &RtpUdpIpv4Headers,
) -> Result<Vec<u8>, RohcError> {
    let init_and_refresh = (context.mode == CompressorMode::FirstOrder
        && context.ir_refresh_interval > 0
        && context.fo_packets_sent_since_ir >= (context.ir_refresh_interval - 1))
        || context.mode == CompressorMode::InitializationAndRefresh;

    if init_and_refresh {
        let ir_data = RohcIrProfile1Packet {
            cid: context.cid,
            profile: PROFILE_ID_RTP_UDP_IP,
            crc8: 0,
            static_ip_src: uncompressed_headers.ip_src,
            static_ip_dst: uncompressed_headers.ip_dst,
            static_udp_src_port: uncompressed_headers.udp_src_port,
            static_udp_dst_port: uncompressed_headers.udp_dst_port,
            static_rtp_ssrc: uncompressed_headers.rtp_ssrc,
            dyn_rtp_sn: uncompressed_headers.rtp_sequence_number,
            dyn_rtp_timestamp: uncompressed_headers.rtp_timestamp,
            dyn_rtp_marker: uncompressed_headers.rtp_marker,
        };
        let rohc_packet = build_ir_profile1_packet(&ir_data)?;

        context.last_sent_rtp_sn_full = uncompressed_headers.rtp_sequence_number;
        context.last_sent_rtp_ts_full = uncompressed_headers.rtp_timestamp;
        context.last_sent_rtp_marker = uncompressed_headers.rtp_marker;
        context.mode = CompressorMode::FirstOrder;
        context.fo_packets_sent_since_ir = 0;

        Ok(rohc_packet)
    } else {
        context.current_lsb_sn_width = DEFAULT_UO0_SN_LSB_WIDTH;
        let sn_lsb = encode_lsb(
            uncompressed_headers.rtp_sequence_number as u64,
            context.current_lsb_sn_width,
        )
        .map_err(|e| RohcError::Internal(format!("SN LSB encoding failed: {}", e)))?
            as u8;

        let crc3_input_data: Vec<u8> = uncompressed_headers
            .rtp_sequence_number
            .to_be_bytes()
            .to_vec();
        let crc3_val = crate::crc::calculate_rohc_crc3(&crc3_input_data);

        let rohc_packet = build_uo0_profile1_cid0_packet(sn_lsb, crc3_val)?;

        context.last_sent_rtp_sn_full = uncompressed_headers.rtp_sequence_number;
        context.last_sent_rtp_ts_full = uncompressed_headers.rtp_timestamp;
        context.last_sent_rtp_marker = uncompressed_headers.rtp_marker;
        context.fo_packets_sent_since_ir += 1;

        Ok(rohc_packet)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::RtpUdpIpP1CompressorContext;
    use crate::packet_processor::ADD_CID_OCTET_PREFIX_VALUE;
    use crate::protocol_types::RtpUdpIpv4Headers;

    fn get_default_uncompressed_headers() -> RtpUdpIpv4Headers {
        RtpUdpIpv4Headers {
            ip_src: "192.168.1.10".parse().unwrap(),
            ip_dst: "192.168.1.20".parse().unwrap(),
            udp_src_port: 1234,
            udp_dst_port: 5678,
            rtp_ssrc: 0x11223344,
            rtp_sequence_number: 100,
            rtp_timestamp: 1000,
            rtp_marker: false,
            ..Default::default()
        }
    }

    #[test]
    fn test_compress_first_packet_sends_ir() {
        let mut context = RtpUdpIpP1CompressorContext::new(0, PROFILE_ID_RTP_UDP_IP, 10);
        let headers = get_default_uncompressed_headers();
        context.initialize_static_part_with_uncompressed_headers(&headers);

        let rohc_packet = compress_rtp_udp_ip_umode(&mut context, &headers).unwrap();

        assert!(!rohc_packet.is_empty());
        assert_eq!(
            rohc_packet[0],
            crate::packet_processor::ROHC_IR_PACKET_TYPE_WITH_DYN
        );
        assert_eq!(context.mode, CompressorMode::FirstOrder);
        assert_eq!(context.last_sent_rtp_sn_full, headers.rtp_sequence_number);
    }

    #[test]
    fn test_compress_first_packet_sends_ir_with_cid() {
        let mut context = RtpUdpIpP1CompressorContext::new(5, PROFILE_ID_RTP_UDP_IP, 10);
        let headers = get_default_uncompressed_headers();
        context.initialize_static_part_with_uncompressed_headers(&headers);

        let rohc_packet = compress_rtp_udp_ip_umode(&mut context, &headers).unwrap();

        assert!(!rohc_packet.is_empty());
        assert_eq!(rohc_packet[0], ADD_CID_OCTET_PREFIX_VALUE | 5);
        assert_eq!(
            rohc_packet[1],
            crate::packet_processor::ROHC_IR_PACKET_TYPE_WITH_DYN
        );
        assert_eq!(context.mode, CompressorMode::FirstOrder);
    }

    #[test]
    fn test_compress_second_packet_sends_uo0() {
        let mut context = RtpUdpIpP1CompressorContext::new(0, PROFILE_ID_RTP_UDP_IP, 10);
        let mut headers1 = get_default_uncompressed_headers();
        context.initialize_static_part_with_uncompressed_headers(&headers1);

        let _ = compress_rtp_udp_ip_umode(&mut context, &headers1).unwrap();
        assert_eq!(context.mode, CompressorMode::FirstOrder);
        assert_eq!(context.fo_packets_sent_since_ir, 0);

        headers1.rtp_sequence_number += 1;
        headers1.rtp_timestamp += 160;

        let rohc_packet_uo0 = compress_rtp_udp_ip_umode(&mut context, &headers1).unwrap();

        assert_eq!(rohc_packet_uo0.len(), 1);
        assert_eq!((rohc_packet_uo0[0] & 0x80), 0x00);
        assert_eq!(context.last_sent_rtp_sn_full, headers1.rtp_sequence_number);
        assert_eq!(context.fo_packets_sent_since_ir, 1);
    }

    #[test]
    fn test_compress_ir_refresh_after_interval() {
        let refresh_interval = 3; // Send IR instead of the 3rd FO packet
        let mut context =
            RtpUdpIpP1CompressorContext::new(0, PROFILE_ID_RTP_UDP_IP, refresh_interval);
        let mut headers = get_default_uncompressed_headers();
        context.initialize_static_part_with_uncompressed_headers(&headers);

        // Packet 1: Initial IR
        let _ir_packet = compress_rtp_udp_ip_umode(&mut context, &headers).unwrap();
        assert_eq!(context.mode, CompressorMode::FirstOrder);
        assert_eq!(context.fo_packets_sent_since_ir, 0);

        // Packets that should be FO (refresh_interval - 1 of them)
        // If refresh_interval = 3, loop for i=0, 1 (sends FO1, FO2)
        for i in 0..(refresh_interval - 1) {
            headers.rtp_sequence_number += 1;
            let uo0_packet = compress_rtp_udp_ip_umode(&mut context, &headers).unwrap();
            assert_eq!(
                (uo0_packet[0] & 0x80),
                0x00,
                "Packet {} should be UO-0",
                i + 2
            ); // +2 because initial IR is 1st.
            assert_eq!(context.mode, CompressorMode::FirstOrder);
        }
        assert_eq!(context.fo_packets_sent_since_ir, refresh_interval - 1); // Should be 2 after loop

        // This packet should be IR due to refresh
        // (it would have been the `refresh_interval`-th FO packet)
        headers.rtp_sequence_number += 1;
        let next_packet = compress_rtp_udp_ip_umode(&mut context, &headers).unwrap();
        assert_eq!(
            next_packet[0], // For CID 0, IR packet starts with IR type
            crate::packet_processor::ROHC_IR_PACKET_TYPE_WITH_DYN,
            "Should be IR due to refresh. Actual: {:02X}",
            next_packet[0]
        );
        assert_eq!(context.mode, CompressorMode::FirstOrder);
        assert_eq!(context.fo_packets_sent_since_ir, 0);
    }
}
