use crate::constants::{DEFAULT_UO0_SN_LSB_WIDTH, PROFILE_ID_RTP_UDP_IP};
use crate::context::{CompressorMode, RtpUdpIpP1CompressorContext};
use crate::encodings::{encode_lsb, value_in_lsb_interval};
use crate::error::RohcError;
use crate::packet_processor::{
    build_ir_profile1_packet, build_uo0_profile1_cid0_packet, build_uo1_sn_profile1_packet,
};
use crate::protocol_types::{RohcIrProfile1Packet, RtpUdpIpv4Headers};

/// Creates the byte sequence used as input for CRC calculation for UO-0 and UO-1 packets.
///
/// For ROHC Profile 1 (RTP/UDP/IP) U-mode, this MVP implementation includes:
/// - SSRC (from context, as it's static for the flow)
/// - RTP Sequence Number (from current uncompressed headers)
/// - RTP Marker bit (from current uncompressed headers)
///
/// Note: A more complete RFC-compliant CRC input would include more fields
/// from the original uncompressed packet, such as the RTP timestamp. This is a
/// simplification for the MVP.
///
/// # Arguments
/// * `static_context_ssrc`: The SSRC established in the compressor's context.
/// * `current_headers`: The uncompressed headers of the packet currently being processed.
///
/// # Returns
/// A `Vec<u8>` containing the bytes for CRC calculation.
fn create_crc_calculation_input(
    static_context_ssrc: u32,
    current_headers: &RtpUdpIpv4Headers,
) -> Vec<u8> {
    // Capacity: SSRC (4 bytes) + SN (2 bytes) + Marker (1 byte)
    let mut crc_input = Vec::with_capacity(4 + 2 + 1);
    crc_input.extend_from_slice(&static_context_ssrc.to_be_bytes());
    crc_input.extend_from_slice(&current_headers.rtp_sequence_number.to_be_bytes());
    // For simplicity, representing marker as a single byte (0 or 1).
    // ROHC specification details how individual bits contribute to the CRC calculation
    // when they are part of a larger header structure.
    crc_input.push(if current_headers.rtp_marker {
        0x01
    } else {
        0x00
    });
    crc_input
}

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
    // Determine if an IR packet needs to be sent due to refresh policy.
    let mut force_ir_due_to_refresh = false;
    if context.mode == CompressorMode::FirstOrder // Only refresh if already in FO mode
        && context.ir_refresh_interval > 0 // And refresh is enabled
        && context.fo_packets_sent_since_ir >= (context.ir_refresh_interval.saturating_sub(1))
    // Check against interval-1 because this packet would be the Nth FO packet.
    {
        force_ir_due_to_refresh = true;
    }

    let should_send_ir_packet =
        context.mode == CompressorMode::InitializationAndRefresh || force_ir_due_to_refresh;

    if should_send_ir_packet {
        // Build and send IR packet
        let ir_data = RohcIrProfile1Packet {
            cid: context.cid,
            profile: PROFILE_ID_RTP_UDP_IP,
            crc8: 0, // Will be calculated by build_ir_profile1_packet
            static_ip_src: uncompressed_headers.ip_src,
            static_ip_dst: uncompressed_headers.ip_dst,
            static_udp_src_port: uncompressed_headers.udp_src_port,
            static_udp_dst_port: uncompressed_headers.udp_dst_port,
            static_rtp_ssrc: uncompressed_headers.rtp_ssrc,
            dyn_rtp_sn: uncompressed_headers.rtp_sequence_number,
            dyn_rtp_timestamp: uncompressed_headers.rtp_timestamp,
            dyn_rtp_marker: uncompressed_headers.rtp_marker,
        };

        // If this is the very first packet (IR mode), establish static context fields.
        if context.mode == CompressorMode::InitializationAndRefresh {
            context.ip_source = uncompressed_headers.ip_src;
            context.ip_destination = uncompressed_headers.ip_dst;
            context.udp_source_port = uncompressed_headers.udp_src_port;
            context.udp_destination_port = uncompressed_headers.udp_dst_port;
            context.rtp_ssrc = uncompressed_headers.rtp_ssrc;
        }

        let rohc_packet_bytes = build_ir_profile1_packet(&ir_data)?;

        // Update context after sending IR
        context.last_sent_rtp_sn_full = uncompressed_headers.rtp_sequence_number;
        context.last_sent_rtp_ts_full = uncompressed_headers.rtp_timestamp;
        context.last_sent_rtp_marker = uncompressed_headers.rtp_marker;
        context.mode = CompressorMode::FirstOrder; // Transition to FO mode
        context.fo_packets_sent_since_ir = 0; // Reset FO counter

        Ok(rohc_packet_bytes)
    } else {
        // Attempt to send a UO (First Order) packet
        let current_sn = uncompressed_headers.rtp_sequence_number;
        let current_marker = uncompressed_headers.rtp_marker;

        let marker_changed = current_marker != context.last_sent_rtp_marker;

        // Check if SN can be represented by UO-0's default LSB width
        let uo0_can_represent_sn = value_in_lsb_interval(
            current_sn as u64,
            context.last_sent_rtp_sn_full as u64,
            DEFAULT_UO0_SN_LSB_WIDTH,
            0, // p_offset = 0 for UO-0 SN encoding
        );

        let rohc_packet_bytes;
        let crc_payload_bytes =
            create_crc_calculation_input(context.rtp_ssrc, uncompressed_headers);

        if !marker_changed && uo0_can_represent_sn {
            // Build UO-0 packet
            context.current_lsb_sn_width = DEFAULT_UO0_SN_LSB_WIDTH;
            let sn_lsb_for_uo0 = encode_lsb(current_sn as u64, context.current_lsb_sn_width)
                .map_err(|e| {
                    RohcError::Internal(format!("SN LSB encoding for UO-0 failed: {}", e))
                })? as u8; // UO-0 SN LSBs fit in u8
            let crc3_value = crate::crc::calculate_rohc_crc3(&crc_payload_bytes);
            rohc_packet_bytes = build_uo0_profile1_cid0_packet(sn_lsb_for_uo0, crc3_value)?;
        } else {
            // Build UO-1-SN packet (due to marker change or SN jump too large for UO-0)
            // For UO-1-SN, we typically use 8 LSBs for SN.
            let uo1_sn_lsb_width = 8;
            let sn_8_lsb = encode_lsb(current_sn as u64, uo1_sn_lsb_width).map_err(|e| {
                RohcError::Internal(format!("SN LSB encoding for UO-1 failed: {}", e))
            })? as u8;
            let crc8_value = crate::crc::calculate_rohc_crc8(&crc_payload_bytes);
            rohc_packet_bytes = build_uo1_sn_profile1_packet(sn_8_lsb, current_marker, crc8_value)?;
            context.current_lsb_sn_width = uo1_sn_lsb_width;
        }

        // Update context after sending UO packet
        context.last_sent_rtp_sn_full = current_sn;
        context.last_sent_rtp_ts_full = uncompressed_headers.rtp_timestamp; // TS not sent in UO-0/UO-1-SN
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
        // Compressor context's static parts are initialized from headers when it decides to send IR in IR mode.
        // No explicit initialize_static_part_with_uncompressed_headers call needed here as the
        // compress_rtp_udp_ip_umode function handles it internally if mode is IR.

        let rohc_packet = compress_rtp_udp_ip_umode(&mut context, &headers).unwrap();

        assert!(!rohc_packet.is_empty());
        assert_eq!(rohc_packet[0], ROHC_IR_PACKET_TYPE_WITH_DYN);
        assert_eq!(context.mode, CompressorMode::FirstOrder);
        assert_eq!(context.last_sent_rtp_sn_full, headers.rtp_sequence_number);
        assert_eq!(
            context.rtp_ssrc, headers.rtp_ssrc,
            "SSRC should be set in context from first IR"
        );
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
        let mut headers1 = default_uncompressed_headers(); // SN=100, M=false

        // Send IR first to establish context
        let _ = compress_rtp_udp_ip_umode(&mut context, &headers1).unwrap();
        assert_eq!(context.mode, CompressorMode::FirstOrder);
        assert_eq!(context.last_sent_rtp_sn_full, 100);

        headers1.rtp_sequence_number += 1; // SN=101, M=false (no marker change)
        let rohc_packet_uo0 = compress_rtp_udp_ip_umode(&mut context, &headers1).unwrap();

        assert_eq!(
            rohc_packet_uo0.len(),
            1,
            "UO-0 packet should be 1 byte for CID 0"
        );
        // Check if it's a UO-0 type (MSB is 0 for CID 0 case)
        assert_eq!(
            (rohc_packet_uo0[0] & 0x80),
            0x00,
            "Packet type should indicate UO-0 (MSB=0)"
        );
        assert_eq!(context.last_sent_rtp_sn_full, 101);
    }

    #[test]
    fn compress_marker_change_sends_uo1() {
        let mut context = RtpUdpIpP1CompressorContext::new(0, PROFILE_ID_RTP_UDP_IP, 10);
        let mut headers1 = default_uncompressed_headers(); // SN=100, M=false

        let _ = compress_rtp_udp_ip_umode(&mut context, &headers1).unwrap(); // Send IR
        assert!(!context.last_sent_rtp_marker); // Context marker should be false

        headers1.rtp_sequence_number += 1; // SN=101
        headers1.rtp_marker = true; // Marker changes to true
        let rohc_packet_uo1 = compress_rtp_udp_ip_umode(&mut context, &headers1).unwrap();

        assert_eq!(
            rohc_packet_uo1.len(),
            3,
            "UO-1-SN MVP packet should be 3 bytes"
        );
        assert_eq!(
            rohc_packet_uo1[0],                                 // Type octet
            UO_1_SN_PACKET_TYPE_BASE | UO_1_SN_MARKER_BIT_MASK, // Base for UO-1-SN + Marker bit set
            "UO-1 packet type octet mismatch"
        );
        assert!(
            context.last_sent_rtp_marker,
            "Context marker should now be true"
        );
    }

    #[test]
    fn compress_large_sn_change_sends_uo1() {
        let mut context = RtpUdpIpP1CompressorContext::new(0, PROFILE_ID_RTP_UDP_IP, 10);
        let mut headers1 = default_uncompressed_headers(); // SN=100, M=false

        let _ = compress_rtp_udp_ip_umode(&mut context, &headers1).unwrap(); // Send IR

        // A jump larger than what UO-0 with 4 LSBs (p=0 window for SN=100 is [100, 115]) can handle.
        headers1.rtp_sequence_number += 20; // SN=120.
        // (120 - 100 = 20). Not in [100,115] for 4-bit LSB.
        let rohc_packet_uo1 = compress_rtp_udp_ip_umode(&mut context, &headers1).unwrap();

        assert_eq!(rohc_packet_uo1.len(), 3, "UO-1-SN packet should be 3 bytes");
        assert_eq!(
            rohc_packet_uo1[0],
            UO_1_SN_PACKET_TYPE_BASE, // Base for UO-1-SN, Marker bit is 0 (false)
            "UO-1 packet type octet mismatch (marker should be false)"
        );
        let expected_sn_lsb_8bit = (120u16 & 0xFF) as u8; // LSB of 120
        assert_eq!(
            rohc_packet_uo1[1], expected_sn_lsb_8bit,
            "UO-1 SN LSB mismatch"
        );
    }

    #[test]
    fn compress_ir_refresh_triggered_after_interval() {
        let refresh_interval = 3; // Send IR, then 2 FO, then next should be IR
        let mut context =
            RtpUdpIpP1CompressorContext::new(0, PROFILE_ID_RTP_UDP_IP, refresh_interval);
        let mut headers = default_uncompressed_headers();

        // 1. Send initial IR
        let _ir_packet = compress_rtp_udp_ip_umode(&mut context, &headers).unwrap();
        assert_eq!(context.mode, CompressorMode::FirstOrder);
        assert_eq!(context.fo_packets_sent_since_ir, 0);

        // 2. Send FO packets up to refresh_interval - 1
        for i in 0..(refresh_interval - 1) {
            headers.rtp_sequence_number += 1;
            let uo_packet = compress_rtp_udp_ip_umode(&mut context, &headers).unwrap();
            // Check it's a UO-0 (simplest FO)
            assert_eq!(
                (uo_packet[0] & 0x80),
                0x00,
                "Packet #{} (FO count {}) should be UO-0",
                i + 2, // Overall packet number
                i + 1  // FO packet count for this loop
            );
            assert_eq!(context.mode, CompressorMode::FirstOrder);
        }
        assert_eq!(context.fo_packets_sent_since_ir, refresh_interval - 1);

        // 3. Next packet should trigger IR refresh
        headers.rtp_sequence_number += 1;
        let next_packet_after_interval = compress_rtp_udp_ip_umode(&mut context, &headers).unwrap();
        assert_eq!(
            next_packet_after_interval[0], ROHC_IR_PACKET_TYPE_WITH_DYN,
            "Packet after interval should be IR due to refresh. Actual type: 0x{:02X}",
            next_packet_after_interval[0]
        );
        assert_eq!(context.mode, CompressorMode::FirstOrder); // Stays FO after sending IR
        assert_eq!(
            context.fo_packets_sent_since_ir, 0,
            "IR refresh should reset FO counter"
        );
    }
}
