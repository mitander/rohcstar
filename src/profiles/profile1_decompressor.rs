use crate::constants::{
    ADD_CID_OCTET_CID_MASK, ADD_CID_OCTET_PREFIX_MASK, ADD_CID_OCTET_PREFIX_VALUE,
    DECOMPRESSOR_FC_TO_SC_CRC_FAILURE_THRESHOLD, IP_PROTOCOL_UDP, ROHC_IR_PACKET_TYPE_BASE,
    ROHC_IR_PACKET_TYPE_D_BIT_MASK, RTP_VERSION, UO_1_SN_PACKET_TYPE_BASE,
};
use crate::context::{DecompressorMode, RtpUdpIpP1DecompressorContext};
use crate::encodings::decode_lsb;
use crate::error::{RohcError, RohcParsingError};
use crate::packet_processor::{
    parse_ir_profile1_packet, parse_uo0_profile1_cid0_packet, parse_uo1_sn_profile1_packet,
};
use crate::protocol_types::{RohcIrProfile1Packet, RtpUdpIpv4Headers};

fn create_crc_input_for_verification(
    context: &RtpUdpIpP1DecompressorContext,
    reconstructed_sn: u16,
    reconstructed_marker: bool,
) -> Vec<u8> {
    let mut crc_input = Vec::with_capacity(4 + 2 + 1); // SSRC, SN, M
    crc_input.extend_from_slice(&context.rtp_ssrc.to_be_bytes());
    crc_input.extend_from_slice(&reconstructed_sn.to_be_bytes());
    crc_input.push(if reconstructed_marker { 0x01 } else { 0x00 });
    crc_input
}

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

    let mut cursor: usize = 0;
    let mut effective_cid_for_context: u16 = context.cid;

    if (rohc_packet_bytes[cursor] & ADD_CID_OCTET_PREFIX_MASK) == ADD_CID_OCTET_PREFIX_VALUE {
        let cid_val = rohc_packet_bytes[cursor] & ADD_CID_OCTET_CID_MASK;
        if cid_val == 0 {
            return Err(RohcError::Parsing(RohcParsingError::InvalidPacketType(
                rohc_packet_bytes[cursor],
            )));
        }
        effective_cid_for_context = cid_val as u16;
        cursor += 1;
        if cursor >= rohc_packet_bytes.len() {
            return Err(RohcError::Parsing(RohcParsingError::NotEnoughData {
                needed: cursor + 1,
                got: rohc_packet_bytes.len(),
            }));
        }
    }

    let core_packet_slice = &rohc_packet_bytes[cursor..];
    if core_packet_slice.is_empty() {
        return Err(RohcError::Parsing(RohcParsingError::NotEnoughData {
            needed: 1,
            got: 0,
        }));
    }
    let type_determining_byte = core_packet_slice[0];

    if (type_determining_byte & !ROHC_IR_PACKET_TYPE_D_BIT_MASK) == ROHC_IR_PACKET_TYPE_BASE {
        match parse_ir_profile1_packet(core_packet_slice) {
            Ok(mut parsed_ir) => {
                parsed_ir.cid = effective_cid_for_context; // Set the CID from Add-CID or context default

                context.cid = parsed_ir.cid;
                context.initialize_from_ir_packet(&parsed_ir);
                context.consecutive_crc_failures_in_fc = 0;
                Ok(reconstruct_uncompressed_headers_from_ir(&parsed_ir))
            }
            Err(e) => Err(RohcError::Parsing(e)),
        }
    } else if (type_determining_byte & 0xF0) == UO_1_SN_PACKET_TYPE_BASE {
        if context.cid != effective_cid_for_context && context.mode != DecompressorMode::NoContext {
            return Err(RohcError::ContextNotFound(effective_cid_for_context));
        }
        if context.mode != DecompressorMode::FullContext {
            return Err(RohcError::InvalidState(
                "Received UO-1 but not in Full Context".to_string(),
            ));
        }

        match parse_uo1_sn_profile1_packet(core_packet_slice) {
            Ok(parsed_uo1) => {
                let reconstructed_sn = decode_lsb(
                    parsed_uo1.sn_lsb as u64,
                    context.last_reconstructed_rtp_sn_full as u64,
                    parsed_uo1.num_sn_lsb_bits,
                    context.p_sn,
                )
                .map_err(RohcError::Parsing)? as u16;
                let new_marker = parsed_uo1
                    .rtp_marker_bit_changed
                    .unwrap_or(context.last_reconstructed_rtp_marker);
                let current_ts_for_reconstruction = context.last_reconstructed_rtp_ts_full;
                let reconstructed_headers = RtpUdpIpv4Headers {
                    ip_src: context.ip_source,
                    ip_dst: context.ip_destination,
                    udp_src_port: context.udp_source_port,
                    udp_dst_port: context.udp_destination_port,
                    rtp_ssrc: context.rtp_ssrc,
                    rtp_sequence_number: reconstructed_sn,
                    rtp_timestamp: current_ts_for_reconstruction,
                    rtp_marker: new_marker,
                    ip_protocol: IP_PROTOCOL_UDP,
                    rtp_version: RTP_VERSION,
                    ip_ihl: 5,
                    ip_ttl: 64,
                    ..Default::default()
                };
                let crc_input_bytes =
                    create_crc_input_for_verification(context, reconstructed_sn, new_marker);
                let calculated_crc8 = crate::crc::calculate_rohc_crc8(&crc_input_bytes);
                if calculated_crc8 == parsed_uo1.crc8 {
                    context.last_reconstructed_rtp_sn_full = reconstructed_sn;
                    context.last_reconstructed_rtp_marker = new_marker;
                    context.consecutive_crc_failures_in_fc = 0;
                    context.cid = effective_cid_for_context;
                    Ok(reconstructed_headers)
                } else {
                    context.consecutive_crc_failures_in_fc += 1;
                    if context.consecutive_crc_failures_in_fc
                        >= DECOMPRESSOR_FC_TO_SC_CRC_FAILURE_THRESHOLD
                    {
                        context.mode = DecompressorMode::StaticContext;
                    }
                    Err(RohcError::Parsing(RohcParsingError::CrcMismatch {
                        expected: parsed_uo1.crc8,
                        calculated: calculated_crc8,
                    }))
                }
            }
            Err(e) => Err(RohcError::Parsing(e)),
        }
    } else if (type_determining_byte & 0x80) == 0x00 {
        if context.cid != effective_cid_for_context && context.mode != DecompressorMode::NoContext {
            return Err(RohcError::ContextNotFound(effective_cid_for_context));
        }
        if context.mode != DecompressorMode::FullContext {
            return Err(RohcError::InvalidState(
                "Received UO-0 but not in Full Context".to_string(),
            ));
        }
        match parse_uo0_profile1_cid0_packet(core_packet_slice) {
            Ok(parsed_uo0) => {
                let reconstructed_sn = decode_lsb(
                    parsed_uo0.sn_lsb as u64,
                    context.last_reconstructed_rtp_sn_full as u64,
                    context.expected_lsb_sn_width,
                    context.p_sn,
                )
                .map_err(RohcError::Parsing)? as u16;
                let current_ts_for_reconstruction = context.last_reconstructed_rtp_ts_full;
                let current_marker_for_reconstruction = context.last_reconstructed_rtp_marker;
                let reconstructed_headers = RtpUdpIpv4Headers {
                    ip_src: context.ip_source,
                    ip_dst: context.ip_destination,
                    udp_src_port: context.udp_source_port,
                    udp_dst_port: context.udp_destination_port,
                    rtp_ssrc: context.rtp_ssrc,
                    rtp_sequence_number: reconstructed_sn,
                    rtp_timestamp: current_ts_for_reconstruction,
                    rtp_marker: current_marker_for_reconstruction,
                    ip_protocol: IP_PROTOCOL_UDP,
                    rtp_version: RTP_VERSION,
                    ip_ihl: 5,
                    ip_ttl: 64,
                    ..Default::default()
                };
                let crc_input_bytes = create_crc_input_for_verification(
                    context,
                    reconstructed_sn,
                    current_marker_for_reconstruction,
                );
                let calculated_crc3 = crate::crc::calculate_rohc_crc3(&crc_input_bytes);
                if calculated_crc3 == parsed_uo0.crc3 {
                    context.last_reconstructed_rtp_sn_full = reconstructed_sn;
                    context.consecutive_crc_failures_in_fc = 0;
                    context.cid = effective_cid_for_context;
                    Ok(reconstructed_headers)
                } else {
                    context.consecutive_crc_failures_in_fc += 1;
                    if context.consecutive_crc_failures_in_fc
                        >= DECOMPRESSOR_FC_TO_SC_CRC_FAILURE_THRESHOLD
                    {
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
            type_determining_byte,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::DEFAULT_UO0_SN_LSB_WIDTH;
    use crate::constants::PROFILE_ID_RTP_UDP_IP;
    use crate::context::{RtpUdpIpP1CompressorContext, RtpUdpIpP1DecompressorContext};
    use crate::packet_processor::{build_ir_profile1_packet, build_uo0_profile1_cid0_packet};
    use crate::profiles::profile1_compressor::compress_rtp_udp_ip_umode;
    use crate::protocol_types::RtpUdpIpv4Headers;

    fn get_default_uncompressed_headers_for_decomp_test(sn: u16) -> RtpUdpIpv4Headers {
        RtpUdpIpv4Headers {
            ip_src: "192.168.1.10".parse().unwrap(),
            ip_dst: "192.168.1.20".parse().unwrap(),
            udp_src_port: 1234,
            udp_dst_port: 5678,
            rtp_ssrc: 0x11223344,
            rtp_sequence_number: sn,
            rtp_timestamp: 1000 + (sn.wrapping_sub(100) as u32 * 160),
            rtp_marker: false,
            ip_ttl: 64,
            ..Default::default()
        }
    }

    #[test]
    fn test_decompress_ir_packet_cid0() {
        let mut decompressor_context = RtpUdpIpP1DecompressorContext::new(0, PROFILE_ID_RTP_UDP_IP);
        let headers = get_default_uncompressed_headers_for_decomp_test(100);
        let ir_data_to_build = RohcIrProfile1Packet {
            cid: 0,
            profile: PROFILE_ID_RTP_UDP_IP,
            static_ip_src: headers.ip_src,
            static_ip_dst: headers.ip_dst,
            static_udp_src_port: headers.udp_src_port,
            static_udp_dst_port: headers.udp_dst_port,
            static_rtp_ssrc: headers.rtp_ssrc,
            dyn_rtp_sn: headers.rtp_sequence_number,
            dyn_rtp_timestamp: headers.rtp_timestamp,
            dyn_rtp_marker: headers.rtp_marker,
            ..Default::default()
        };
        let ir_packet_bytes = build_ir_profile1_packet(&ir_data_to_build).unwrap();
        let decompressed_headers =
            decompress_rtp_udp_ip_umode(&mut decompressor_context, &ir_packet_bytes).unwrap();
        assert_eq!(decompressor_context.mode, DecompressorMode::FullContext);
        assert_eq!(decompressor_context.cid, 0);
        assert_eq!(decompressed_headers.rtp_ssrc, headers.rtp_ssrc);
        assert_eq!(
            decompressed_headers.rtp_sequence_number,
            headers.rtp_sequence_number
        );
    }

    #[test]
    fn test_decompress_ir_packet_with_add_cid() {
        let cid_val: u16 = 7;
        let mut decompressor_context = RtpUdpIpP1DecompressorContext::new(0, PROFILE_ID_RTP_UDP_IP);
        decompressor_context.mode = DecompressorMode::NoContext;
        let headers = get_default_uncompressed_headers_for_decomp_test(100);
        let ir_data_to_build = RohcIrProfile1Packet {
            cid: cid_val,
            profile: PROFILE_ID_RTP_UDP_IP,
            static_ip_src: headers.ip_src,
            static_ip_dst: headers.ip_dst,
            static_udp_src_port: headers.udp_src_port,
            static_udp_dst_port: headers.udp_dst_port,
            static_rtp_ssrc: headers.rtp_ssrc,
            dyn_rtp_sn: headers.rtp_sequence_number,
            dyn_rtp_timestamp: headers.rtp_timestamp,
            dyn_rtp_marker: headers.rtp_marker,
            ..Default::default()
        };
        let ir_packet_bytes = build_ir_profile1_packet(&ir_data_to_build).unwrap();
        let decompressed_headers =
            decompress_rtp_udp_ip_umode(&mut decompressor_context, &ir_packet_bytes).unwrap();
        assert_eq!(decompressor_context.cid, cid_val);
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
        let ir_headers = get_default_uncompressed_headers_for_decomp_test(99);
        decompressor_context.ip_source = ir_headers.ip_src;
        decompressor_context.ip_destination = ir_headers.ip_dst;
        decompressor_context.udp_source_port = ir_headers.udp_src_port;
        decompressor_context.udp_destination_port = ir_headers.udp_dst_port;
        decompressor_context.rtp_ssrc = ir_headers.rtp_ssrc;
        decompressor_context.last_reconstructed_rtp_sn_full = ir_headers.rtp_sequence_number;
        decompressor_context.last_reconstructed_rtp_ts_full = ir_headers.rtp_timestamp;
        decompressor_context.last_reconstructed_rtp_marker = ir_headers.rtp_marker;
        decompressor_context.mode = DecompressorMode::FullContext;
        decompressor_context.expected_lsb_sn_width = DEFAULT_UO0_SN_LSB_WIDTH;
        let sn_lsb = crate::encodings::encode_lsb(100_u64, DEFAULT_UO0_SN_LSB_WIDTH).unwrap() as u8;
        let crc_input_for_correct = create_crc_input_for_verification(
            &decompressor_context,
            100,
            decompressor_context.last_reconstructed_rtp_marker,
        );
        let correct_crc3 = crate::crc::calculate_rohc_crc3(&crc_input_for_correct);
        let corrupted_crc3 = correct_crc3.wrapping_add(1) & 0x07;
        let uo0_packet_bytes = build_uo0_profile1_cid0_packet(sn_lsb, corrupted_crc3).unwrap();
        for i in 0..DECOMPRESSOR_FC_TO_SC_CRC_FAILURE_THRESHOLD {
            let result = decompress_rtp_udp_ip_umode(&mut decompressor_context, &uo0_packet_bytes);
            assert!(
                matches!(
                    result,
                    Err(RohcError::Parsing(RohcParsingError::CrcMismatch { .. }))
                ),
                "Iteration {} failed to produce CrcMismatch. Got: {:?}",
                i,
                result
            );
        }
        assert_eq!(decompressor_context.mode, DecompressorMode::StaticContext);
    }
}
