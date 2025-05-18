use crate::context::{CompressorMode, RtpUdpIpP1CompressorContext};
use crate::encodings::{encode_lsb, value_in_lsb_interval};
use crate::error::RohcError;
use crate::packet_processor::{
    PROFILE_ID_RTP_UDP_IP, build_ir_profile1_packet, build_uo0_profile1_cid0_packet,
    build_uo1_sn_profile1_packet,
};
use crate::protocol_types::{RohcIrProfile1Packet, RtpUdpIpv4Headers};

pub const DEFAULT_UO0_SN_LSB_WIDTH: u8 = 4; // Max SN change for UO-0 (0 to 2^4-1 = 15)
fn create_crc_input_from_original_headers(
    static_context_ssrc: u32,
    current_headers: &RtpUdpIpv4Headers,
) -> Vec<u8> {
    let mut crc_input = Vec::with_capacity(4 + 2 + 1); // SSRC (u32), SN (u16), M (u8)
    crc_input.extend_from_slice(&static_context_ssrc.to_be_bytes());
    crc_input.extend_from_slice(&current_headers.rtp_sequence_number.to_be_bytes());
    crc_input.push(if current_headers.rtp_marker {
        0x01
    } else {
        0x00
    });
    // Timestamp is NOT included for UO-0/UO-1-SN CRC in this simplified model
    crc_input
}

pub fn compress_rtp_udp_ip_umode(
    context: &mut RtpUdpIpP1CompressorContext,
    uncompressed_headers: &RtpUdpIpv4Headers,
) -> Result<Vec<u8>, RohcError> {
    let mut force_ir_for_refresh = false;
    if context.mode == CompressorMode::FirstOrder
        && context.ir_refresh_interval > 0
        && context.fo_packets_sent_since_ir >= (context.ir_refresh_interval - 1)
    {
        force_ir_for_refresh = true;
    }

    let should_send_ir =
        context.mode == CompressorMode::InitializationAndRefresh || force_ir_for_refresh;

    if should_send_ir {
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
        if context.mode == CompressorMode::InitializationAndRefresh {
            context.ip_source = uncompressed_headers.ip_src;
            context.ip_destination = uncompressed_headers.ip_dst;
            context.udp_source_port = uncompressed_headers.udp_src_port;
            context.udp_destination_port = uncompressed_headers.udp_dst_port;
            context.rtp_ssrc = uncompressed_headers.rtp_ssrc;
        }
        let rohc_packet = build_ir_profile1_packet(&ir_data)?;

        context.last_sent_rtp_sn_full = uncompressed_headers.rtp_sequence_number;
        context.last_sent_rtp_ts_full = uncompressed_headers.rtp_timestamp;
        context.last_sent_rtp_marker = uncompressed_headers.rtp_marker;
        context.mode = CompressorMode::FirstOrder;
        context.fo_packets_sent_since_ir = 0;

        Ok(rohc_packet)
    } else {
        let current_sn = uncompressed_headers.rtp_sequence_number;
        let current_marker = uncompressed_headers.rtp_marker;
        let marker_changed = current_marker != context.last_sent_rtp_marker;

        let uo0_can_represent_sn = value_in_lsb_interval(
            current_sn as u64,
            context.last_sent_rtp_sn_full as u64,
            DEFAULT_UO0_SN_LSB_WIDTH,
            0,
        );

        let rohc_packet;
        // Corrected: Pass context.rtp_ssrc and uncompressed_headers
        let crc_input_bytes =
            create_crc_input_from_original_headers(context.rtp_ssrc, uncompressed_headers);

        if !marker_changed && uo0_can_represent_sn {
            context.current_lsb_sn_width = DEFAULT_UO0_SN_LSB_WIDTH;
            let sn_lsb_for_uo0 = encode_lsb(current_sn as u64, context.current_lsb_sn_width)
                .map_err(|e| {
                    RohcError::Internal(format!("SN LSB encoding for UO-0 failed: {}", e))
                })? as u8;
            let crc3_val = crate::crc::calculate_rohc_crc3(&crc_input_bytes);
            rohc_packet = build_uo0_profile1_cid0_packet(sn_lsb_for_uo0, crc3_val)?;
        } else {
            let sn_8_lsb = encode_lsb(current_sn as u64, 8).map_err(|e| {
                RohcError::Internal(format!("SN LSB encoding for UO-1 failed: {}", e))
            })? as u8;
            let crc8_val = crate::crc::calculate_rohc_crc8(&crc_input_bytes);
            rohc_packet = build_uo1_sn_profile1_packet(sn_8_lsb, current_marker, crc8_val)?;
            context.current_lsb_sn_width = 8;
        }

        context.last_sent_rtp_sn_full = current_sn;
        context.last_sent_rtp_ts_full = uncompressed_headers.rtp_timestamp;
        context.last_sent_rtp_marker = current_marker;
        context.fo_packets_sent_since_ir += 1;

        Ok(rohc_packet)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::RtpUdpIpP1CompressorContext;
    use crate::packet_processor::{
        ADD_CID_OCTET_PREFIX_VALUE, UO_1_SN_MARKER_BIT_MASK, UO_1_SN_PACKET_TYPE_BASE,
    };
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
    fn test_compress_small_sn_change_sends_uo0() {
        let mut context = RtpUdpIpP1CompressorContext::new(0, PROFILE_ID_RTP_UDP_IP, 10);
        let mut headers1 = get_default_uncompressed_headers(); // SN=100, M=false
        context.initialize_static_part_with_uncompressed_headers(&headers1);
        let _ = compress_rtp_udp_ip_umode(&mut context, &headers1).unwrap(); // IR

        headers1.rtp_sequence_number += 1; // SN=101, M=false (no change)
        let rohc_packet_uo0 = compress_rtp_udp_ip_umode(&mut context, &headers1).unwrap();

        assert_eq!(rohc_packet_uo0.len(), 1);
        assert_eq!((rohc_packet_uo0[0] & 0x80), 0x00); // UO-0 type
    }

    #[test]
    fn test_compress_marker_change_sends_uo1() {
        let mut context = RtpUdpIpP1CompressorContext::new(0, PROFILE_ID_RTP_UDP_IP, 10);
        let mut headers1 = get_default_uncompressed_headers(); // SN=100, M=false
        context.initialize_static_part_with_uncompressed_headers(&headers1);
        let _ = compress_rtp_udp_ip_umode(&mut context, &headers1).unwrap(); // IR, M becomes false in context

        headers1.rtp_sequence_number += 1; // SN=101
        headers1.rtp_marker = true; // M changes to true
        let rohc_packet_uo1 = compress_rtp_udp_ip_umode(&mut context, &headers1).unwrap();

        assert_eq!(rohc_packet_uo1.len(), 3); // UO-1-SN MVP is 3 bytes
        assert_eq!(
            rohc_packet_uo1[0],
            UO_1_SN_PACKET_TYPE_BASE | UO_1_SN_MARKER_BIT_MASK
        ); // Type + M=1
        assert!(context.last_sent_rtp_marker);
    }

    #[test]
    fn test_compress_large_sn_change_sends_uo1() {
        let mut context = RtpUdpIpP1CompressorContext::new(0, PROFILE_ID_RTP_UDP_IP, 10);
        let mut headers1 = get_default_uncompressed_headers(); // SN=100, M=false
        context.initialize_static_part_with_uncompressed_headers(&headers1);
        let _ = compress_rtp_udp_ip_umode(&mut context, &headers1).unwrap(); // IR

        // A jump larger than what UO-0 with 4 LSBs (p=0 window [100, 115]) can handle
        headers1.rtp_sequence_number += 20; // SN=120. (120 - 100 = 20). Not in [100,115]
        // value_in_lsb_interval(120, 100, 4, 0) will be false.
        let rohc_packet_uo1 = compress_rtp_udp_ip_umode(&mut context, &headers1).unwrap();

        assert_eq!(rohc_packet_uo1.len(), 3);
        assert_eq!(rohc_packet_uo1[0], UO_1_SN_PACKET_TYPE_BASE); // Type + M=0 (marker didn't change from false)
        let expected_sn_lsb_8bit = (120u16 & 0xFF) as u8;
        assert_eq!(rohc_packet_uo1[1], expected_sn_lsb_8bit);
    }

    #[test]
    fn test_compress_ir_refresh_after_interval() {
        let refresh_interval = 3;
        let mut context =
            RtpUdpIpP1CompressorContext::new(0, PROFILE_ID_RTP_UDP_IP, refresh_interval);
        let mut headers = get_default_uncompressed_headers();
        context.initialize_static_part_with_uncompressed_headers(&headers);

        let _ir_packet = compress_rtp_udp_ip_umode(&mut context, &headers).unwrap();
        assert_eq!(context.mode, CompressorMode::FirstOrder);

        for i in 0..(refresh_interval - 1) {
            headers.rtp_sequence_number += 1;
            let uo0_packet = compress_rtp_udp_ip_umode(&mut context, &headers).unwrap();
            assert_eq!(
                (uo0_packet[0] & 0x80),
                0x00,
                "Packet {} should be UO-0",
                i + 2
            );
            assert_eq!(context.mode, CompressorMode::FirstOrder);
        }
        assert_eq!(context.fo_packets_sent_since_ir, refresh_interval - 1);

        headers.rtp_sequence_number += 1;
        let next_packet = compress_rtp_udp_ip_umode(&mut context, &headers).unwrap();
        assert_eq!(
            next_packet[0],
            crate::packet_processor::ROHC_IR_PACKET_TYPE_WITH_DYN,
            "Should be IR due to refresh. Actual: {:02X}",
            next_packet[0]
        );
        assert_eq!(context.mode, CompressorMode::FirstOrder);
        assert_eq!(context.fo_packets_sent_since_ir, 0);
    }
}
