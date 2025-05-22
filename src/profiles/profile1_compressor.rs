use crate::constants::{DEFAULT_UO0_SN_LSB_WIDTH, PROFILE_ID_RTP_UDP_IP};
use crate::context::{CompressorMode, RtpUdpIpP1CompressorContext};
use crate::encodings::{encode_lsb, value_in_lsb_interval};
use crate::error::RohcError;
use crate::packet_processor::{
    build_ir_profile1_packet, build_uo0_profile1_cid0_packet, build_uo1_sn_profile1_packet,
};
use crate::protocol_types::{RohcIrProfile1Packet, RtpUdpIpv4Headers};

/// Compresses RTP/UDP/IP headers using ROHC Profile 1 in Unidirectional mode (U-mode).
///
/// This function determines whether to send an IR (Initialization/Refresh), UO-0, or UO-1 packet
/// based on the compressor context state, changes in the uncompressed headers, and the IR
/// refresh interval.
///
/// # Arguments
/// * `context`: A mutable reference to the `RtpUdpIpP1CompressorContext` for this flow.
/// * `uncompressed_headers`: The `RtpUdpIpv4Headers` of the packet to be compressed.
///
/// # Returns
/// A `Result` containing the ROHC compressed packet as a `Vec<u8>`, or a `RohcError`
/// if compression fails.
pub fn compress_rtp_udp_ip_umode(
    context: &mut RtpUdpIpP1CompressorContext,
    uncompressed_headers: &RtpUdpIpv4Headers,
) -> Result<Vec<u8>, RohcError> {
    let mut force_ir_due_to_refresh = false;
    if context.mode == CompressorMode::FirstOrder
        && context.ir_refresh_interval > 0
        && context.fo_packets_sent_since_ir >= (context.ir_refresh_interval.saturating_sub(1))
    {
        force_ir_due_to_refresh = true;
    }

    let should_send_ir_packet =
        context.mode == CompressorMode::InitializationAndRefresh || force_ir_due_to_refresh;

    if should_send_ir_packet {
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

        let rohc_packet_bytes = build_ir_profile1_packet(&ir_data)?;

        // After sending IR, the context reflects the current packet's state fully.
        context.last_sent_rtp_sn_full = uncompressed_headers.rtp_sequence_number;
        context.last_sent_rtp_ts_full = uncompressed_headers.rtp_timestamp;
        context.last_sent_rtp_marker = uncompressed_headers.rtp_marker;
        context.mode = CompressorMode::FirstOrder;
        context.fo_packets_sent_since_ir = 0;

        Ok(rohc_packet_bytes)
    } else {
        // UO packet logic
        let current_sn = uncompressed_headers.rtp_sequence_number;
        let current_marker = uncompressed_headers.rtp_marker;

        let marker_changed = current_marker != context.last_sent_rtp_marker;
        let uo0_can_represent_sn = value_in_lsb_interval(
            current_sn as u64,
            context.last_sent_rtp_sn_full as u64,
            DEFAULT_UO0_SN_LSB_WIDTH,
            0,
        );

        let rohc_packet_bytes;

        if !marker_changed && uo0_can_represent_sn {
            // Build UO-0 packet
            context.current_lsb_sn_width = DEFAULT_UO0_SN_LSB_WIDTH;
            let sn_lsb_for_uo0 = encode_lsb(current_sn as u64, context.current_lsb_sn_width)
                .map_err(|e| {
                    RohcError::Internal(format!("SN LSB encoding for UO-0 failed: {}", e))
                })? as u8;

            // CRC Input for UO-0: SSRC(ctx), SN(current), TS(ctx's last_sent), Marker(ctx's last_sent)
            let mut crc_input_for_uo0 = Vec::with_capacity(11);
            crc_input_for_uo0.extend_from_slice(&context.rtp_ssrc.to_be_bytes());
            crc_input_for_uo0.extend_from_slice(&current_sn.to_be_bytes());
            crc_input_for_uo0.extend_from_slice(&context.last_sent_rtp_ts_full.to_be_bytes());
            crc_input_for_uo0.push(if context.last_sent_rtp_marker {
                0x01
            } else {
                0x00
            });

            let crc3_value = crate::crc::calculate_rohc_crc3(&crc_input_for_uo0);
            rohc_packet_bytes = build_uo0_profile1_cid0_packet(sn_lsb_for_uo0, crc3_value)?;
        } else {
            // Build UO-1-SN packet
            let uo1_sn_lsb_width = 8;
            let sn_8_lsb = encode_lsb(current_sn as u64, uo1_sn_lsb_width).map_err(|e| {
                RohcError::Internal(format!("SN LSB encoding for UO-1 failed: {}", e))
            })? as u8;

            // CRC Input for UO-1-SN: SSRC(ctx), SN(current), TS(ctx's last_sent), Marker(current_packet_marker)
            let mut crc_input_for_uo1_sn = Vec::with_capacity(11);
            crc_input_for_uo1_sn.extend_from_slice(&context.rtp_ssrc.to_be_bytes());
            crc_input_for_uo1_sn.extend_from_slice(&current_sn.to_be_bytes());
            crc_input_for_uo1_sn.extend_from_slice(&context.last_sent_rtp_ts_full.to_be_bytes());
            crc_input_for_uo1_sn.push(if current_marker { 0x01 } else { 0x00 });

            let crc8_value = crate::crc::calculate_rohc_crc8(&crc_input_for_uo1_sn);
            rohc_packet_bytes = build_uo1_sn_profile1_packet(sn_8_lsb, current_marker, crc8_value)?;
            context.current_lsb_sn_width = uo1_sn_lsb_width;
        }

        // Update compressor context
        context.last_sent_rtp_sn_full = current_sn;
        context.last_sent_rtp_marker = current_marker;
        context.fo_packets_sent_since_ir += 1;

        Ok(rohc_packet_bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::{
        ADD_CID_OCTET_PREFIX_VALUE, ROHC_IR_PACKET_TYPE_WITH_DYN, UO_1_SN_MARKER_BIT_MASK,
        UO_1_SN_PACKET_TYPE_BASE,
    };

    fn default_uncompressed_headers() -> RtpUdpIpv4Headers {
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
    fn compress_first_packet_sends_ir() {
        let mut context = RtpUdpIpP1CompressorContext::new(0, PROFILE_ID_RTP_UDP_IP, 10);
        let headers = default_uncompressed_headers();

        let rohc_packet = compress_rtp_udp_ip_umode(&mut context, &headers).unwrap();

        assert!(!rohc_packet.is_empty());
        assert_eq!(rohc_packet[0], ROHC_IR_PACKET_TYPE_WITH_DYN);
        assert_eq!(context.mode, CompressorMode::FirstOrder);
        assert_eq!(context.last_sent_rtp_sn_full, headers.rtp_sequence_number);
        assert_eq!(context.rtp_ssrc, headers.rtp_ssrc);
        assert_eq!(context.last_sent_rtp_ts_full, headers.rtp_timestamp);
        assert_eq!(context.last_sent_rtp_marker, headers.rtp_marker);
    }

    #[test]
    fn compress_first_packet_sends_ir_with_cid() {
        let cid_value = 5;
        let mut context = RtpUdpIpP1CompressorContext::new(cid_value, PROFILE_ID_RTP_UDP_IP, 10);
        let headers = default_uncompressed_headers();

        let rohc_packet = compress_rtp_udp_ip_umode(&mut context, &headers).unwrap();

        assert!(!rohc_packet.is_empty());
        assert_eq!(rohc_packet[0], ADD_CID_OCTET_PREFIX_VALUE | cid_value as u8);
        assert_eq!(rohc_packet[1], ROHC_IR_PACKET_TYPE_WITH_DYN);
        assert_eq!(context.mode, CompressorMode::FirstOrder);
    }

    #[test]
    fn compress_small_sn_change_sends_uo0() {
        let mut context = RtpUdpIpP1CompressorContext::new(0, PROFILE_ID_RTP_UDP_IP, 10);
        let mut headers1 = default_uncompressed_headers(); // SN=100, TS=1000, M=false

        let _ = compress_rtp_udp_ip_umode(&mut context, &headers1).unwrap();
        assert_eq!(context.mode, CompressorMode::FirstOrder);
        assert_eq!(context.last_sent_rtp_sn_full, 100);
        assert_eq!(context.last_sent_rtp_ts_full, 1000);
        assert!(!context.last_sent_rtp_marker);

        headers1.rtp_sequence_number += 1; // SN=101
        headers1.rtp_timestamp = context.last_sent_rtp_ts_full; // TS=1000
        headers1.rtp_marker = context.last_sent_rtp_marker; // M=false

        let rohc_packet_uo0 = compress_rtp_udp_ip_umode(&mut context, &headers1).unwrap();

        assert_eq!(rohc_packet_uo0.len(), 1);
        assert_eq!((rohc_packet_uo0[0] & 0x80), 0x00);
        assert_eq!(context.last_sent_rtp_sn_full, 101);
        assert_eq!(context.last_sent_rtp_ts_full, headers1.rtp_timestamp);
        assert_eq!(context.last_sent_rtp_marker, headers1.rtp_marker);
    }

    #[test]
    fn compress_marker_change_sends_uo1() {
        let mut context = RtpUdpIpP1CompressorContext::new(0, PROFILE_ID_RTP_UDP_IP, 10);
        let mut headers1 = default_uncompressed_headers(); // SN=100, TS=1000, M=false

        let _ = compress_rtp_udp_ip_umode(&mut context, &headers1).unwrap();
        let ts_after_ir = context.last_sent_rtp_ts_full;

        headers1.rtp_sequence_number += 1; // SN=101
        headers1.rtp_timestamp += 160; // TS=1160
        headers1.rtp_marker = true; // M=true

        let rohc_packet_uo1 = compress_rtp_udp_ip_umode(&mut context, &headers1).unwrap();

        // Verify UO-1-SN packet structure
        assert_eq!(rohc_packet_uo1.len(), 3);
        assert_eq!(
            rohc_packet_uo1[0],
            UO_1_SN_PACKET_TYPE_BASE | UO_1_SN_MARKER_BIT_MASK
        );

        // Verify context updates
        assert_eq!(context.last_sent_rtp_sn_full, 101);
        assert!(context.last_sent_rtp_marker);
        assert_eq!(
            context.last_sent_rtp_ts_full, ts_after_ir,
            "Context TS should NOT change after sending UO-1-SN (which doesn't carry TS LSBs)"
        );
    }
    #[test]
    fn compress_large_sn_change_sends_uo1() {
        let mut context = RtpUdpIpP1CompressorContext::new(0, PROFILE_ID_RTP_UDP_IP, 10);
        let mut headers1 = default_uncompressed_headers(); // SN=100, TS=1000, M=false

        let _ = compress_rtp_udp_ip_umode(&mut context, &headers1).unwrap();

        headers1.rtp_sequence_number += 20; // SN=120, large jump
        headers1.rtp_timestamp = context.last_sent_rtp_ts_full; // TS=1000
        headers1.rtp_marker = context.last_sent_rtp_marker; //M=false

        let rohc_packet_uo1 = compress_rtp_udp_ip_umode(&mut context, &headers1).unwrap();

        assert_eq!(rohc_packet_uo1.len(), 3);
        assert_eq!(
            rohc_packet_uo1[0],
            UO_1_SN_PACKET_TYPE_BASE // Marker is false
        );
        let expected_sn_lsb_8bit = (120u16 & 0xFF) as u8;
        assert_eq!(rohc_packet_uo1[1], expected_sn_lsb_8bit);
        assert_eq!(context.last_sent_rtp_sn_full, 120);
    }

    #[test]
    fn compress_ir_refresh_triggered_after_interval() {
        let refresh_interval = 3;
        let mut context =
            RtpUdpIpP1CompressorContext::new(0, PROFILE_ID_RTP_UDP_IP, refresh_interval);
        let mut headers = default_uncompressed_headers(); // SN=100, TS=1000, M=false

        let _ir_packet = compress_rtp_udp_ip_umode(&mut context, &headers).unwrap();
        assert_eq!(context.mode, CompressorMode::FirstOrder);
        assert_eq!(context.fo_packets_sent_since_ir, 0);

        for i in 0..(refresh_interval - 1) {
            headers.rtp_sequence_number += 1; // SN=102 after 2 iterations
            headers.rtp_timestamp = context.last_sent_rtp_ts_full; // TS=1000
            headers.rtp_marker = context.last_sent_rtp_marker; // M=false

            let uo_packet = compress_rtp_udp_ip_umode(&mut context, &headers).unwrap();
            assert_eq!(
                (uo_packet[0] & 0x80),
                0x00,
                "Packet #{} (FO count {}) should be UO-0",
                i + 2,
                i + 1
            );
            assert_eq!(context.mode, CompressorMode::FirstOrder);
        }
        assert_eq!(context.fo_packets_sent_since_ir, refresh_interval - 1);

        headers.rtp_sequence_number += 1; // SN=103
        headers.rtp_timestamp += 160; // TS=1160
        headers.rtp_marker = true; // M=true

        let next_packet_after_interval = compress_rtp_udp_ip_umode(&mut context, &headers).unwrap();
        assert_eq!(
            next_packet_after_interval[0], ROHC_IR_PACKET_TYPE_WITH_DYN,
            "Packet after interval should be IR due to refresh. Actual type: 0x{:02X}",
            next_packet_after_interval[0]
        );
        assert_eq!(context.mode, CompressorMode::FirstOrder);
        assert_eq!(context.fo_packets_sent_since_ir, 0);
        assert_eq!(context.last_sent_rtp_ts_full, headers.rtp_timestamp);
        assert_eq!(context.last_sent_rtp_marker, headers.rtp_marker);
    }
}
