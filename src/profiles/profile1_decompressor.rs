use crate::context::{DecompressorMode, RtpUdpIpP1DecompressorContext};
use crate::encodings::decode_lsb;
use crate::error::{RohcError, RohcParsingError};
use crate::packet_processor::{
    ADD_CID_OCTET_CID_MASK, ADD_CID_OCTET_PREFIX_MASK, ADD_CID_OCTET_PREFIX_VALUE, IP_PROTOCOL_UDP,
    ROHC_IR_PACKET_TYPE_BASE, ROHC_IR_PACKET_TYPE_D_BIT_MASK, RTP_VERSION,
    parse_ir_profile1_packet, parse_uo0_profile1_cid0_packet,
};
use crate::protocol_types::{RohcIrProfile1Packet, RtpUdpIpv4Headers};

const DECOMPRESSOR_K1_THRESHOLD: u8 = 3;

pub fn decompress_rtp_udp_ip_umode(
    context: &mut RtpUdpIpP1DecompressorContext,
    rohc_packet_bytes: &[u8],
) -> Result<RtpUdpIpv4Headers, RohcError> {
    if rohc_packet_bytes.is_empty() {
        return Err(RohcError::Parsing(RohcParsingError::NotEnoughData {
            needed: 1,
            got: 0,
        }));
    }

    let mut packet_cursor = 0;
    let mut effective_cid = context.cid; // Start with current context CID

    // 1. Check for and consume Add-CID octet (for small CIDs 1-15)
    if (rohc_packet_bytes[0] & ADD_CID_OCTET_PREFIX_MASK) == ADD_CID_OCTET_PREFIX_VALUE {
        let cid_val = rohc_packet_bytes[0] & ADD_CID_OCTET_CID_MASK;
        if cid_val == 0 {
            // 11100000 is padding, not Add-CID for CID 0
            return Err(RohcError::Parsing(RohcParsingError::InvalidPacketType(
                rohc_packet_bytes[0],
            )));
        }
        effective_cid = cid_val as u16;
        packet_cursor += 1; // Consumed Add-CID octet
        if packet_cursor >= rohc_packet_bytes.len() {
            return Err(RohcError::Parsing(RohcParsingError::NotEnoughData {
                needed: packet_cursor + 1,
                got: rohc_packet_bytes.len(),
            }));
        }
    }
    // If no Add-CID octet, effective_cid remains context.cid (which is typically 0 if not yet set by an IR with Add-CID)

    let remaining_packet_slice = &rohc_packet_bytes[packet_cursor..];
    if remaining_packet_slice.is_empty() {
        return Err(RohcError::Parsing(RohcParsingError::NotEnoughData {
            needed: 1,
            got: 0,
        }));
    }
    let first_byte_of_rohc_packet = remaining_packet_slice[0];

    // 2. Determine packet type
    if (first_byte_of_rohc_packet & !ROHC_IR_PACKET_TYPE_D_BIT_MASK) == ROHC_IR_PACKET_TYPE_BASE {
        // --- IR Packet ---
        // parse_ir_profile1_packet expects to see the IR type octet first, not Add-CID.
        match parse_ir_profile1_packet(remaining_packet_slice) {
            Ok(mut parsed_ir) => {
                // Make parsed_ir mutable to set its CID
                // The CID for the context is `effective_cid` determined above.
                // The `parsed_ir.cid` from `parse_ir_profile1_packet` will be 0
                // because it doesn't parse Add-CID itself (it assumes large CID or implicit 0).
                // So, we update the logical parsed_ir.cid with our determined effective_cid.
                parsed_ir.cid = effective_cid;

                context.cid = effective_cid; // Update context's CID
                context.initialize_from_ir_packet(&parsed_ir);
                context.consecutive_crc_failures_in_fc = 0;

                Ok(reconstruct_uncompressed_headers_from_ir(&parsed_ir))
            }
            Err(e) => Err(RohcError::Parsing(e)),
        }
    } else if (first_byte_of_rohc_packet & 0x80) == 0x00 {
        // --- UO-0 Packet ---
        if context.cid != effective_cid && effective_cid != 0 {
            // This implies a UO-0 for a specific non-zero CID established via Add-CID,
            // but our current context is for a different CID.
            // For MVP, if context CID is not 0 and Add-CID was present and different, this might be an issue
            // or indicate a need to switch context. For now, we'll proceed if it's CID 0 implicitly
            // or if the Add-CID matched the context's existing CID.
            // If effective_cid is non-zero (from Add-CID) and context.cid is 0 (NoContext), it's fine.
            if context.mode != DecompressorMode::NoContext && context.cid != effective_cid {
                return Err(RohcError::ContextNotFound(effective_cid));
            }
        }
        if context.mode != DecompressorMode::FullContext {
            // Exception: if it's NoContext and we received an Add-CID for a UO-0,
            // we still wouldn't have static context. UO-0 requires FullContext.
            return Err(RohcError::InvalidState(
                "Received UO-0 packet but decompressor not in Full Context state".to_string(),
            ));
        }

        // parse_uo0_profile1_cid0_packet expects only the UO-0 byte(s)
        match parse_uo0_profile1_cid0_packet(remaining_packet_slice) {
            Ok(parsed_uo0) => {
                let reconstructed_sn = decode_lsb(
                    parsed_uo0.sn_lsb as u64,
                    context.last_reconstructed_rtp_sn_full as u64,
                    context.expected_lsb_sn_width,
                    context.p_sn,
                )
                .map_err(RohcError::Parsing)? as u16;

                let reconstructed_headers = RtpUdpIpv4Headers {
                    ip_src: context.ip_source,
                    ip_dst: context.ip_destination,
                    udp_src_port: context.udp_source_port,
                    udp_dst_port: context.udp_destination_port,
                    rtp_ssrc: context.rtp_ssrc,
                    rtp_sequence_number: reconstructed_sn,
                    rtp_timestamp: context.last_reconstructed_rtp_ts_full,
                    rtp_marker: context.last_reconstructed_rtp_marker,
                    ip_protocol: IP_PROTOCOL_UDP,
                    rtp_version: RTP_VERSION,
                    ip_ihl: 5,
                    ip_ttl: 64,
                    ..Default::default()
                };

                let crc3_input_data: Vec<u8> = reconstructed_sn.to_be_bytes().to_vec();
                let calculated_crc3 = crate::crc::calculate_rohc_crc3(&crc3_input_data);

                if calculated_crc3 == parsed_uo0.crc3 {
                    context.last_reconstructed_rtp_sn_full = reconstructed_sn;
                    context.consecutive_crc_failures_in_fc = 0;
                    context.cid = effective_cid; // Ensure context CID is aligned if UO-0 was for a specific CID
                    Ok(reconstructed_headers)
                } else {
                    context.consecutive_crc_failures_in_fc += 1;
                    if context.consecutive_crc_failures_in_fc >= DECOMPRESSOR_K1_THRESHOLD {
                        context.mode = DecompressorMode::StaticContext;
                    }
                    Err(RohcError::Parsing(RohcParsingError::CrcMismatch {
                        expected: parsed_uo0.crc3,
                        calculated: calculated_crc3,
                    }))
                }
            }
            Err(e) => Err(RohcError::Parsing(e)),
        }
    } else {
        Err(RohcError::Parsing(RohcParsingError::InvalidPacketType(
            first_byte_of_rohc_packet,
        )))
    }
}

fn reconstruct_uncompressed_headers_from_ir(ir_packet: &RohcIrProfile1Packet) -> RtpUdpIpv4Headers {
    RtpUdpIpv4Headers {
        ip_src: ir_packet.static_ip_src,
        ip_dst: ir_packet.static_ip_dst,
        udp_src_port: ir_packet.static_udp_src_port,
        udp_dst_port: ir_packet.static_udp_dst_port,
        rtp_ssrc: ir_packet.static_rtp_ssrc,
        rtp_sequence_number: ir_packet.dyn_rtp_sn,
        rtp_timestamp: ir_packet.dyn_rtp_timestamp,
        rtp_marker: ir_packet.dyn_rtp_marker,
        ip_protocol: IP_PROTOCOL_UDP,
        rtp_version: RTP_VERSION,
        ip_ihl: 5,
        ip_ttl: 64,
        ..Default::default()
    }
}

// Tests should remain largely the same.
// The key change is that decompress_rtp_udp_ip_umode now handles the Add-CID octet
// and passes the remaining slice to parse_ir_profile1_packet.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::{RtpUdpIpP1CompressorContext, RtpUdpIpP1DecompressorContext};
    use crate::packet_processor::{
        PROFILE_ID_RTP_UDP_IP, build_ir_profile1_packet, build_uo0_profile1_cid0_packet,
    };
    use crate::profiles::profile1_compressor::{
        DEFAULT_UO0_SN_LSB_WIDTH, compress_rtp_udp_ip_umode,
    };
    use crate::protocol_types::RtpUdpIpv4Headers;

    fn get_default_uncompressed_headers_for_decomp_test(sn: u16) -> RtpUdpIpv4Headers {
        RtpUdpIpv4Headers {
            ip_src: "192.168.1.10".parse().unwrap(),
            ip_dst: "192.168.1.20".parse().unwrap(),
            udp_src_port: 1234,
            udp_dst_port: 5678,
            rtp_ssrc: 0x11223344,
            rtp_sequence_number: sn,
            rtp_timestamp: 1000 + (sn as u32 * 160),
            rtp_marker: false,
            ..Default::default()
        }
    }

    #[test]
    fn test_decompress_ir_packet_cid0() {
        let mut decompressor_context = RtpUdpIpP1DecompressorContext::new(0, PROFILE_ID_RTP_UDP_IP);
        let headers = get_default_uncompressed_headers_for_decomp_test(100);

        let ir_data_to_build = RohcIrProfile1Packet {
            cid: 0, // IR for CID 0 doesn't have Add-CID octet from build_ir_profile1_packet
            profile: PROFILE_ID_RTP_UDP_IP,
            crc8: 0,
            static_ip_src: headers.ip_src,
            static_ip_dst: headers.ip_dst,
            static_udp_src_port: headers.udp_src_port,
            static_udp_dst_port: headers.udp_dst_port,
            static_rtp_ssrc: headers.rtp_ssrc,
            dyn_rtp_sn: headers.rtp_sequence_number,
            dyn_rtp_timestamp: headers.rtp_timestamp,
            dyn_rtp_marker: headers.rtp_marker,
        };
        let ir_packet_bytes = build_ir_profile1_packet(&ir_data_to_build).unwrap();

        let decompressed_headers =
            decompress_rtp_udp_ip_umode(&mut decompressor_context, &ir_packet_bytes).unwrap();

        assert_eq!(decompressor_context.mode, DecompressorMode::FullContext);
        assert_eq!(decompressor_context.cid, 0); // Context CID should be 0
        assert_eq!(decompressed_headers.rtp_ssrc, headers.rtp_ssrc);
        assert_eq!(
            decompressed_headers.rtp_sequence_number,
            headers.rtp_sequence_number
        );
    }

    #[test]
    fn test_decompress_ir_packet_with_add_cid() {
        let cid_val: u16 = 7;
        // Decompressor context might start as NoContext for CID 0, or be specifically for CID 7.
        // Let's simulate it starting fresh and learning the CID from the packet.
        let mut decompressor_context = RtpUdpIpP1DecompressorContext::new(0, PROFILE_ID_RTP_UDP_IP);
        decompressor_context.mode = DecompressorMode::NoContext;

        let headers = get_default_uncompressed_headers_for_decomp_test(100);

        let ir_data_to_build = RohcIrProfile1Packet {
            cid: cid_val, // This CID will be used by build_ir to prepend Add-CID
            profile: PROFILE_ID_RTP_UDP_IP,
            static_ip_src: headers.ip_src,
            static_ip_dst: headers.ip_dst,
            static_udp_src_port: headers.udp_src_port,
            static_udp_dst_port: headers.udp_dst_port,
            static_rtp_ssrc: headers.rtp_ssrc,
            dyn_rtp_sn: headers.rtp_sequence_number,
            dyn_rtp_timestamp: headers.rtp_timestamp,
            dyn_rtp_marker: headers.rtp_marker,
            ..Default::default() // crc8 will be calculated
        };
        let ir_packet_bytes = build_ir_profile1_packet(&ir_data_to_build).unwrap();
        // build_ir_profile1_packet prepends Add-CID if cid is 1-15.
        // `ir_packet_bytes` now starts with Add-CID for 7, then the IR type.

        let decompressed_headers =
            decompress_rtp_udp_ip_umode(&mut decompressor_context, &ir_packet_bytes).unwrap();

        assert_eq!(decompressor_context.cid, cid_val); // This was failing (left: 0, right: 7)
        assert_eq!(decompressor_context.mode, DecompressorMode::FullContext);
        assert_eq!(decompressed_headers.rtp_ssrc, headers.rtp_ssrc);
    }

    #[test]
    fn test_decompress_uo0_packet_cid0_success() {
        let mut compressor_context = RtpUdpIpP1CompressorContext::new(0, PROFILE_ID_RTP_UDP_IP, 10);
        let mut decompressor_context = RtpUdpIpP1DecompressorContext::new(0, PROFILE_ID_RTP_UDP_IP);
        decompressor_context.expected_lsb_sn_width = DEFAULT_UO0_SN_LSB_WIDTH;

        let headers1 = get_default_uncompressed_headers_for_decomp_test(100);
        compressor_context.initialize_static_part_with_uncompressed_headers(&headers1);
        let ir_packet_bytes =
            compress_rtp_udp_ip_umode(&mut compressor_context, &headers1).unwrap();
        let _ = decompress_rtp_udp_ip_umode(&mut decompressor_context, &ir_packet_bytes).unwrap();

        let headers2 = get_default_uncompressed_headers_for_decomp_test(101);
        let uo0_packet_bytes =
            compress_rtp_udp_ip_umode(&mut compressor_context, &headers2).unwrap();

        let decompressed_headers =
            decompress_rtp_udp_ip_umode(&mut decompressor_context, &uo0_packet_bytes).unwrap();

        assert_eq!(decompressor_context.cid, 0);
        assert_eq!(
            decompressed_headers.rtp_sequence_number,
            headers2.rtp_sequence_number
        );
        assert_eq!(decompressed_headers.rtp_timestamp, headers1.rtp_timestamp);
        assert_eq!(decompressed_headers.rtp_marker, headers1.rtp_marker);
    }

    #[test]
    fn test_decompress_uo0_crc_failure_leads_to_sc() {
        let mut decompressor_context = RtpUdpIpP1DecompressorContext::new(0, PROFILE_ID_RTP_UDP_IP);
        decompressor_context.mode = DecompressorMode::FullContext;
        decompressor_context.last_reconstructed_rtp_sn_full = 99;
        decompressor_context.expected_lsb_sn_width = DEFAULT_UO0_SN_LSB_WIDTH;

        let sn_lsb = crate::encodings::encode_lsb(100_u64, DEFAULT_UO0_SN_LSB_WIDTH).unwrap() as u8;
        let correct_crc3 = crate::crc::calculate_rohc_crc3(&100u16.to_be_bytes());
        let corrupted_crc3 = correct_crc3.wrapping_add(1) & 0x07;

        let uo0_packet_bytes = build_uo0_profile1_cid0_packet(sn_lsb, corrupted_crc3).unwrap();

        for i in 0..DECOMPRESSOR_K1_THRESHOLD {
            let result = decompress_rtp_udp_ip_umode(&mut decompressor_context, &uo0_packet_bytes);
            assert!(
                matches!(
                    result,
                    Err(RohcError::Parsing(RohcParsingError::CrcMismatch { .. }))
                ),
                "Iteration {} failed to produce CrcMismatch",
                i
            );
        }
        assert_eq!(decompressor_context.mode, DecompressorMode::StaticContext);
    }
}
