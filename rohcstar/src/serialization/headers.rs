//! RTP/UDP/IPv4 header deserialization.

use std::net::Ipv4Addr;

use crate::constants::{
    IP_PROTOCOL_UDP, IPV4_MIN_HEADER_LENGTH_BYTES, IPV4_STANDARD_IHL, RTP_MIN_HEADER_LENGTH_BYTES,
    RTP_VERSION, UDP_HEADER_LENGTH_BYTES,
};
use crate::error::{Field, NetworkLayer, ParseContext, RohcParsingError, StructureType};
use crate::profiles::profile1::protocol_types::RtpUdpIpv4Headers;
use crate::types::Ssrc;

/// Deserializes RTP/UDP/IPv4 packet headers with validation.
pub fn deserialize_rtp_udp_ipv4_headers(
    data: &[u8],
) -> Result<RtpUdpIpv4Headers, RohcParsingError> {
    if data.len() < IPV4_MIN_HEADER_LENGTH_BYTES {
        return Err(RohcParsingError::NotEnoughData {
            needed: IPV4_MIN_HEADER_LENGTH_BYTES,
            got: data.len(),
            context: ParseContext::Ipv4HeaderMin,
        });
    }

    let ip_version_ihl = data[0];
    let ip_version = ip_version_ihl >> 4;
    if ip_version != 4 {
        return Err(RohcParsingError::InvalidIpVersion {
            expected: 4,
            got: ip_version,
        });
    }

    let ip_ihl_words = ip_version_ihl & 0x0F;
    if ip_ihl_words < IPV4_STANDARD_IHL {
        return Err(RohcParsingError::InvalidFieldValue {
            field: Field::IpIhl,
            structure: StructureType::Ipv4Header,
            expected: IPV4_STANDARD_IHL as u32,
            got: ip_ihl_words as u32,
        });
    }
    let ip_header_length_bytes = (ip_ihl_words * 4) as usize;
    if data.len() < ip_header_length_bytes {
        return Err(RohcParsingError::NotEnoughData {
            needed: ip_header_length_bytes,
            got: data.len(),
            context: ParseContext::Ipv4HeaderCalculated,
        });
    }

    let ip_dscp = data[1] >> 2;
    let ip_ecn = data[1] & 0x03;
    let ip_total_length = u16::from_be_bytes([data[2], data[3]]);
    let ip_identification = u16::from_be_bytes([data[4], data[5]]);
    let flags_and_fragment_offset = u16::from_be_bytes([data[6], data[7]]);
    let ip_dont_fragment = (flags_and_fragment_offset >> 14) & 0x01 == 1;
    let ip_more_fragments = (flags_and_fragment_offset >> 13) & 0x01 == 1;
    let ip_fragment_offset = flags_and_fragment_offset & 0x1FFF;
    let ip_ttl = data[8];
    let ip_protocol_id = data[9];
    if ip_protocol_id != IP_PROTOCOL_UDP {
        return Err(RohcParsingError::UnsupportedProtocol {
            protocol_id: ip_protocol_id,
            layer: NetworkLayer::Ip,
        });
    }
    let ip_checksum = u16::from_be_bytes([data[10], data[11]]);
    let ip_src_addr = Ipv4Addr::new(data[12], data[13], data[14], data[15]);
    let ip_dst_addr = Ipv4Addr::new(data[16], data[17], data[18], data[19]);

    let udp_start_offset = ip_header_length_bytes;
    if data.len() < udp_start_offset + UDP_HEADER_LENGTH_BYTES {
        return Err(RohcParsingError::NotEnoughData {
            needed: udp_start_offset + UDP_HEADER_LENGTH_BYTES,
            got: data.len(),
            context: ParseContext::UdpHeader,
        });
    }
    let udp_src_port = u16::from_be_bytes([data[udp_start_offset], data[udp_start_offset + 1]]);
    let udp_dst_port = u16::from_be_bytes([data[udp_start_offset + 2], data[udp_start_offset + 3]]);
    let udp_total_length =
        u16::from_be_bytes([data[udp_start_offset + 4], data[udp_start_offset + 5]]);
    let udp_checksum = u16::from_be_bytes([data[udp_start_offset + 6], data[udp_start_offset + 7]]);

    let rtp_start_offset = udp_start_offset + UDP_HEADER_LENGTH_BYTES;
    if data.len() < rtp_start_offset + RTP_MIN_HEADER_LENGTH_BYTES {
        return Err(RohcParsingError::NotEnoughData {
            needed: rtp_start_offset + RTP_MIN_HEADER_LENGTH_BYTES,
            got: data.len(),
            context: ParseContext::RtpHeaderMin,
        });
    }
    let rtp_first_byte = data[rtp_start_offset];
    let rtp_version_val = rtp_first_byte >> 6;
    if rtp_version_val != RTP_VERSION {
        return Err(RohcParsingError::InvalidFieldValue {
            field: Field::RtpVersion,
            structure: StructureType::RtpHeader,
            expected: RTP_VERSION as u32,
            got: rtp_version_val as u32,
        });
    }
    let rtp_padding_flag = (rtp_first_byte >> 5) & 0x01 == 1;
    let rtp_extension_flag = (rtp_first_byte >> 4) & 0x01 == 1;
    let rtp_csrc_count_val = rtp_first_byte & 0x0F;

    let rtp_second_byte = data[rtp_start_offset + 1];
    let rtp_marker_flag = (rtp_second_byte >> 7) & 0x01 == 1;
    let rtp_payload_type_val = rtp_second_byte & 0x7F;
    let rtp_seq_num = u16::from_be_bytes([data[rtp_start_offset + 2], data[rtp_start_offset + 3]]);
    let rtp_ts_u32 = u32::from_be_bytes([
        data[rtp_start_offset + 4],
        data[rtp_start_offset + 5],
        data[rtp_start_offset + 6],
        data[rtp_start_offset + 7],
    ]);
    let rtp_ssrc_val = Ssrc::new(u32::from_be_bytes([
        data[rtp_start_offset + 8],
        data[rtp_start_offset + 9],
        data[rtp_start_offset + 10],
        data[rtp_start_offset + 11],
    ]));

    let mut rtp_csrc_list_val = Vec::with_capacity(rtp_csrc_count_val as usize);
    let mut current_csrc_offset = rtp_start_offset + RTP_MIN_HEADER_LENGTH_BYTES;
    for _i in 0..rtp_csrc_count_val {
        if data.len() < current_csrc_offset + 4 {
            return Err(RohcParsingError::NotEnoughData {
                needed: current_csrc_offset + 4,
                got: data.len(),
                context: ParseContext::RtpHeaderMin,
            });
        }
        rtp_csrc_list_val.push(u32::from_be_bytes([
            data[current_csrc_offset],
            data[current_csrc_offset + 1],
            data[current_csrc_offset + 2],
            data[current_csrc_offset + 3],
        ]));
        current_csrc_offset += 4;
    }

    if rtp_csrc_count_val as usize != rtp_csrc_list_val.len() {
        return Err(RohcParsingError::InvalidFieldValue {
            field: Field::RtpCsrcCount,
            structure: StructureType::RtpHeader,
            expected: rtp_csrc_count_val as u32,
            got: rtp_csrc_list_val.len() as u32,
        });
    }

    Ok(RtpUdpIpv4Headers {
        ip_ihl: ip_ihl_words,
        ip_dscp,
        ip_ecn,
        ip_total_length,
        ip_identification: ip_identification.into(),
        ip_dont_fragment,
        ip_more_fragments,
        ip_fragment_offset,
        ip_ttl,
        ip_protocol: ip_protocol_id,
        ip_checksum,
        ip_src: ip_src_addr,
        ip_dst: ip_dst_addr,
        udp_src_port,
        udp_dst_port,
        udp_length: udp_total_length,
        udp_checksum,
        rtp_version: rtp_version_val,
        rtp_padding: rtp_padding_flag,
        rtp_extension: rtp_extension_flag,
        rtp_csrc_count: rtp_csrc_count_val,
        rtp_marker: rtp_marker_flag,
        rtp_payload_type: rtp_payload_type_val,
        rtp_sequence_number: rtp_seq_num.into(),
        rtp_timestamp: rtp_ts_u32.into(),
        rtp_ssrc: rtp_ssrc_val,
        rtp_csrc_list: rtp_csrc_list_val,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn p1_headers_deserialize_valid() {
        let packet_bytes = [
            0x45, 0x00, 0x00, 0x4c, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11, 0x00, 0x00, 0xc0, 0xa8,
            0x01, 0x01, 0xc0, 0xa8, 0x01, 0x02, 0x04, 0xd2, 0x16, 0x2e, 0x00, 0x38, 0x00, 0x00,
            0x80, 0x60, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x12, 0x34, 0x56, 0x78,
        ];
        let headers = deserialize_rtp_udp_ipv4_headers(&packet_bytes).unwrap();
        assert_eq!(headers.ip_src.octets(), [192, 168, 1, 1]);
    }

    #[test]
    fn p1_headers_deserialize_too_short() {
        let short_packet = [0x45];
        let result = deserialize_rtp_udp_ipv4_headers(&short_packet);
        assert!(result.is_err());
    }
}
