//! RTP/UDP/IPv4 header deserialization for Profile 1.
//!
//! This module provides functions for parsing and validating combined RTP/UDP/IPv4
//! packet headers. These functions are used primarily for testing and benchmarking
//! Profile 1 compression operations.

use std::net::Ipv4Addr;

use crate::constants::{
    IP_PROTOCOL_UDP, IPV4_MIN_HEADER_LENGTH_BYTES, IPV4_STANDARD_IHL, RTP_MIN_HEADER_LENGTH_BYTES,
    RTP_VERSION, UDP_HEADER_LENGTH_BYTES,
};
use crate::error::{Field, NetworkLayer, ParseContext, RohcParsingError, StructureType};
use crate::protocol_types::RtpUdpIpv4Headers;
use crate::types::{SequenceNumber, Ssrc, Timestamp};

// Helper structs for holding intermediate parsing results.
// These are private to the module.

struct Ipv4Header {
    ihl: u8,
    dscp: u8,
    ecn: u8,
    total_length: u16,
    identification: u16,
    dont_fragment: bool,
    more_fragments: bool,
    fragment_offset: u16,
    ttl: u8,
    protocol: u8,
    checksum: u16,
    src: Ipv4Addr,
    dst: Ipv4Addr,
}

struct UdpHeader {
    src_port: u16,
    dst_port: u16,
    length: u16,
    checksum: u16,
}

struct RtpHeader {
    version: u8,
    padding: bool,
    extension: bool,
    csrc_count: u8,
    marker: bool,
    payload_type: u8,
    sequence_number: u16,
    timestamp: u32,
    ssrc: Ssrc,
    csrc_list: Vec<u32>,
}

struct ParsedIpv4Header<'a> {
    header: Ipv4Header,
    payload: &'a [u8],
}

struct ParsedUdpHeader<'a> {
    header: UdpHeader,
    payload: &'a [u8],
}

/// Deserializes RTP/UDP/IPv4 packet headers with validation.
///
/// Parses a complete RTP/UDP/IPv4 packet and extracts all header fields
/// required for ROHC Profile 1 compression context establishment.
///
/// This function acts as an orchestrator for the individual layer parsers.
///
/// # Parameters
/// - `data`: Raw packet bytes containing IPv4, UDP, and RTP headers
///
/// # Returns
/// - `Ok(RtpUdpIpv4Headers)`: Parsed header structure with all extracted fields
/// - `Err(RohcParsingError)`: Invalid packet format or insufficient data
pub fn deserialize_rtp_udp_ipv4_headers(
    data: &[u8],
) -> Result<RtpUdpIpv4Headers, RohcParsingError> {
    let ipv4 = parse_ipv4_header(data)?;
    let udp = parse_udp_header(ipv4.payload)?;
    let rtp = parse_rtp_header(udp.payload)?;

    Ok(RtpUdpIpv4Headers {
        ip_ihl: ipv4.header.ihl,
        ip_dscp: ipv4.header.dscp,
        ip_ecn: ipv4.header.ecn,
        ip_total_length: ipv4.header.total_length,
        ip_identification: ipv4.header.identification.into(),
        ip_dont_fragment: ipv4.header.dont_fragment,
        ip_more_fragments: ipv4.header.more_fragments,
        ip_fragment_offset: ipv4.header.fragment_offset,
        ip_ttl: ipv4.header.ttl,
        ip_protocol: ipv4.header.protocol,
        ip_checksum: ipv4.header.checksum,
        ip_src: ipv4.header.src,
        ip_dst: ipv4.header.dst,
        udp_src_port: udp.header.src_port,
        udp_dst_port: udp.header.dst_port,
        udp_length: udp.header.length,
        udp_checksum: udp.header.checksum,
        rtp_version: rtp.version,
        rtp_padding: rtp.padding,
        rtp_extension: rtp.extension,
        rtp_csrc_count: rtp.csrc_count,
        rtp_marker: rtp.marker,
        rtp_payload_type: rtp.payload_type,
        rtp_sequence_number: SequenceNumber::new(rtp.sequence_number),
        rtp_timestamp: Timestamp::new(rtp.timestamp),
        rtp_ssrc: rtp.ssrc,
        rtp_csrc_list: rtp.csrc_list,
    })
}

/// Parses the IPv4 header from a byte slice.
fn parse_ipv4_header(data: &[u8]) -> Result<ParsedIpv4Header, RohcParsingError> {
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

    let ip_protocol_id = data[9];
    if ip_protocol_id != IP_PROTOCOL_UDP {
        return Err(RohcParsingError::UnsupportedProtocol {
            protocol_id: ip_protocol_id,
            layer: NetworkLayer::Ip,
        });
    }

    let flags_and_fragment_offset = u16::from_be_bytes([data[6], data[7]]);
    let header = Ipv4Header {
        ihl: ip_ihl_words,
        dscp: data[1] >> 2,
        ecn: data[1] & 0x03,
        total_length: u16::from_be_bytes([data[2], data[3]]),
        identification: u16::from_be_bytes([data[4], data[5]]),
        dont_fragment: (flags_and_fragment_offset >> 14) & 0x01 == 1,
        more_fragments: (flags_and_fragment_offset >> 13) & 0x01 == 1,
        fragment_offset: flags_and_fragment_offset & 0x1FFF,
        ttl: data[8],
        protocol: ip_protocol_id,
        checksum: u16::from_be_bytes([data[10], data[11]]),
        src: Ipv4Addr::new(data[12], data[13], data[14], data[15]),
        dst: Ipv4Addr::new(data[16], data[17], data[18], data[19]),
    };
    let payload = &data[ip_header_length_bytes..];

    Ok(ParsedIpv4Header { header, payload })
}

/// Parses the UDP header from a byte slice.
fn parse_udp_header(data: &[u8]) -> Result<ParsedUdpHeader, RohcParsingError> {
    if data.len() < UDP_HEADER_LENGTH_BYTES {
        return Err(RohcParsingError::NotEnoughData {
            needed: UDP_HEADER_LENGTH_BYTES,
            got: data.len(),
            context: ParseContext::UdpHeader,
        });
    }

    let header = UdpHeader {
        src_port: u16::from_be_bytes([data[0], data[1]]),
        dst_port: u16::from_be_bytes([data[2], data[3]]),
        length: u16::from_be_bytes([data[4], data[5]]),
        checksum: u16::from_be_bytes([data[6], data[7]]),
    };
    let payload = &data[UDP_HEADER_LENGTH_BYTES..];

    Ok(ParsedUdpHeader { header, payload })
}

/// Parses the RTP header from a byte slice.
fn parse_rtp_header(data: &[u8]) -> Result<RtpHeader, RohcParsingError> {
    if data.len() < RTP_MIN_HEADER_LENGTH_BYTES {
        return Err(RohcParsingError::NotEnoughData {
            needed: RTP_MIN_HEADER_LENGTH_BYTES,
            got: data.len(),
            context: ParseContext::RtpHeaderMin,
        });
    }

    let rtp_first_byte = data[0];
    let rtp_version = rtp_first_byte >> 6;
    if rtp_version != RTP_VERSION {
        return Err(RohcParsingError::InvalidFieldValue {
            field: Field::RtpVersion,
            structure: StructureType::RtpHeader,
            expected: RTP_VERSION as u32,
            got: rtp_version as u32,
        });
    }
    let rtp_csrc_count = rtp_first_byte & 0x0F;
    let csrc_list_bytes = (rtp_csrc_count * 4) as usize;
    let rtp_header_total_len = RTP_MIN_HEADER_LENGTH_BYTES + csrc_list_bytes;

    if data.len() < rtp_header_total_len {
        return Err(RohcParsingError::NotEnoughData {
            needed: rtp_header_total_len,
            got: data.len(),
            context: ParseContext::RtpHeaderCalculated,
        });
    }

    let rtp_second_byte = data[1];
    let mut csrc_list = Vec::with_capacity(rtp_csrc_count as usize);
    let mut csrc_offset = RTP_MIN_HEADER_LENGTH_BYTES;
    for _ in 0..rtp_csrc_count {
        csrc_list.push(u32::from_be_bytes([
            data[csrc_offset],
            data[csrc_offset + 1],
            data[csrc_offset + 2],
            data[csrc_offset + 3],
        ]));
        csrc_offset += 4;
    }

    Ok(RtpHeader {
        version: rtp_version,
        padding: (rtp_first_byte >> 5) & 0x01 == 1,
        extension: (rtp_first_byte >> 4) & 0x01 == 1,
        csrc_count: rtp_csrc_count,
        marker: (rtp_second_byte >> 7) & 0x01 == 1,
        payload_type: rtp_second_byte & 0x7F,
        sequence_number: u16::from_be_bytes([data[2], data[3]]),
        timestamp: u32::from_be_bytes([data[4], data[5], data[6], data[7]]),
        ssrc: Ssrc::new(u32::from_be_bytes([data[8], data[9], data[10], data[11]])),
        csrc_list,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // A valid, complete packet for testing the full chain and individual parts.
    // The length fields are now consistent with the actual data length (52 bytes).
    const VALID_PACKET_WITH_CSRC: &[u8] = &[
        // IPv4 Header (IHL: 5 = 20 bytes, Total Length: 52 bytes)
        0x45, 0x00, 0x00, 0x34, 0x12, 0x34, 0x40, 0x00, 0x40, 0x11, 0xb8, 0x79, 0xc0, 0xa8, 0x01,
        0x01, 0xc0, 0xa8, 0x01, 0x02, // UDP Header (8 bytes, Length: 32 bytes)
        0x04, 0xd2, 0x16, 0x2e, 0x00, 0x20, 0xca, 0xfe,
        // RTP Header (12 bytes + 2 CSRCs * 4 bytes = 20 bytes total)
        0x82, 0x60, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02, 0x12, 0x34, 0x56, 0x78, 0xAA, 0xAA, 0xAA,
        0xAA, 0xBB, 0xBB, 0xBB, 0xBB, // Payload (4 bytes)
        0xDE, 0xAD, 0xBE, 0xEF,
    ];

    #[test]
    fn deserialize_rtp_udp_ipv4_headers_valid() {
        let headers = deserialize_rtp_udp_ipv4_headers(VALID_PACKET_WITH_CSRC).unwrap();
        assert_eq!(headers.ip_src.octets(), [192, 168, 1, 1]);
        assert_eq!(headers.ip_dst.octets(), [192, 168, 1, 2]);
        assert_eq!(headers.udp_src_port, 1234);
        assert_eq!(headers.udp_dst_port, 5678);
        assert_eq!(headers.rtp_sequence_number, SequenceNumber::new(1));
        assert_eq!(headers.rtp_csrc_list, vec![0xAAAAAAAA, 0xBBBBBBBB]);
    }

    #[test]
    fn deserialize_rtp_udp_ipv4_headers_too_short() {
        let short_packet = [0x45];
        let result = deserialize_rtp_udp_ipv4_headers(&short_packet);
        assert!(matches!(
            result,
            Err(RohcParsingError::NotEnoughData { .. })
        ));
    }

    #[test]
    fn ipv4_header_parses_valid_packet() {
        let result = parse_ipv4_header(VALID_PACKET_WITH_CSRC).unwrap();
        assert_eq!(result.header.ihl, 5);
        assert_eq!(result.header.protocol, IP_PROTOCOL_UDP);
        assert_eq!(result.header.src, Ipv4Addr::new(192, 168, 1, 1));
        // Total slice len (52) - IP header len (20) = 32
        assert_eq!(result.payload.len(), 32);
    }

    #[test]
    fn ipv4_header_rejects_non_ipv4_packet() {
        let mut bad_packet = [0u8; 20];
        bad_packet[0] = 0x65; // Version 6
        let result = parse_ipv4_header(&bad_packet);
        assert!(matches!(
            result,
            Err(RohcParsingError::InvalidIpVersion { got: 6, .. })
        ));
    }

    #[test]
    fn ipv4_header_rejects_non_udp_packet() {
        let mut tcp_packet = VALID_PACKET_WITH_CSRC.to_vec();
        tcp_packet[9] = 6; // Protocol 6 is TCP
        let result = parse_ipv4_header(&tcp_packet);
        assert!(matches!(
            result,
            Err(RohcParsingError::UnsupportedProtocol { protocol_id: 6, .. })
        ));
    }

    #[test]
    fn ipv4_header_rejects_packet_with_ihl_too_short() {
        let mut bad_packet = VALID_PACKET_WITH_CSRC.to_vec();
        bad_packet[0] = 0x44; // IHL 4 is invalid (< 5)
        let result = parse_ipv4_header(&bad_packet);
        assert!(matches!(
            result,
            Err(RohcParsingError::InvalidFieldValue {
                field: Field::IpIhl,
                ..
            })
        ));
    }

    #[test]
    fn udp_header_parses_valid_datagram() {
        let udp_datagram = &VALID_PACKET_WITH_CSRC[20..]; // Start after IPv4 header
        let result = parse_udp_header(udp_datagram).unwrap();
        assert_eq!(result.header.src_port, 1234);
        assert_eq!(result.header.dst_port, 5678);
        assert_eq!(result.header.length, 32);
        // UDP datagram len (32) - UDP header len (8) = 24
        assert_eq!(result.payload.len(), 24);
    }

    #[test]
    fn udp_header_rejects_too_short_datagram() {
        let short_datagram = &[0x01, 0x02, 0x03, 0x04];
        let result = parse_udp_header(short_datagram);
        assert!(matches!(
            result,
            Err(RohcParsingError::NotEnoughData { .. })
        ));
    }

    #[test]
    fn rtp_header_parses_valid_packet_with_csrc() {
        let rtp_packet = &VALID_PACKET_WITH_CSRC[28..]; // Start after IP and UDP
        let result = parse_rtp_header(rtp_packet).unwrap();
        assert_eq!(result.version, 2);
        assert_eq!(result.csrc_count, 2);
        assert_eq!(result.payload_type, 96);
        assert_eq!(result.sequence_number, 1);
        assert_eq!(result.timestamp, 2);
        assert_eq!(result.ssrc, Ssrc::new(0x12345678));
        assert_eq!(result.csrc_list, vec![0xAAAAAAAA, 0xBBBBBBBB]);
    }

    #[test]
    fn rtp_header_parses_valid_packet_no_csrc() {
        let rtp_no_csrc: &[u8] = &[
            0x80, 0x60, 0x00, 0x05, 0x00, 0x00, 0x00, 0x0A, 0xDE, 0xAD, 0xBE, 0xEF,
        ];
        let result = parse_rtp_header(rtp_no_csrc).unwrap();
        assert_eq!(result.csrc_count, 0);
        assert_eq!(result.sequence_number, 5);
        assert_eq!(result.ssrc, Ssrc::new(0xDEADBEEF));
        assert!(result.csrc_list.is_empty());
    }

    #[test]
    fn rtp_header_rejects_invalid_version() {
        let mut bad_packet = VALID_PACKET_WITH_CSRC.to_vec();
        bad_packet[28] = 0x42; // Version 1
        let result = parse_rtp_header(&bad_packet[28..]);
        assert!(matches!(
            result,
            Err(RohcParsingError::InvalidFieldValue {
                field: Field::RtpVersion,
                ..
            })
        ));
    }

    #[test]
    fn rtp_header_rejects_packet_too_short_for_csrc() {
        let bad_packet: &[u8] = &[
            // RTP Header (CSRC Count: 2) but only one CSRC present
            0x82, 0x60, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02, 0x12, 0x34, 0x56, 0x78, 0xAA, 0xAA,
            0xAA, 0xAA,
        ];
        let result = parse_rtp_header(bad_packet);
        assert!(matches!(
            result,
            Err(RohcParsingError::NotEnoughData {
                needed: 20,
                got: 16,
                ..
            })
        ));
    }
}
