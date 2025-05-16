use crate::error::{RohcBuildingError, RohcParsingError};
use crate::protocol_types::{RohcUo0PacketProfile1, RtpUdpIpv4Headers};
use std::net::Ipv4Addr;

const IP_PROTOCOL_UDP: u8 = 17;
const RTP_VERSION: u8 = 2;

pub fn parse_rtp_udp_ipv4(data: &[u8]) -> Result<RtpUdpIpv4Headers, RohcParsingError> {
    if data.len() < 20 {
        // Minimum IPv4 header size
        return Err(RohcParsingError::NotEnoughData {
            needed: 20,
            got: data.len(),
        });
    }

    let ip_version = data[0] >> 4;
    if ip_version != 4 {
        return Err(RohcParsingError::InvalidIpVersion(ip_version));
    }
    let ip_ihl = data[0] & 0x0F;
    if ip_ihl < 5 {
        return Err(RohcParsingError::InvalidFieldValue {
            field_name: "IPv4 IHL".to_string(),
            description: "less than 5".to_string(),
        });
    }
    let ip_header_len_bytes = (ip_ihl * 4) as usize;
    if data.len() < ip_header_len_bytes {
        return Err(RohcParsingError::NotEnoughData {
            needed: ip_header_len_bytes,
            got: data.len(),
        });
    }

    let ip_dscp = data[1] >> 2;
    let ip_ecn = data[1] & 0x03;
    let ip_total_length = u16::from_be_bytes([data[2], data[3]]);
    let ip_identification = u16::from_be_bytes([data[4], data[5]]);
    let flags_fragment_offset = u16::from_be_bytes([data[6], data[7]]);
    let ip_dont_fragment = (flags_fragment_offset >> 14) & 0x01 == 1;
    let ip_more_fragments = (flags_fragment_offset >> 13) & 0x01 == 1;
    let ip_fragment_offset = flags_fragment_offset & 0x1FFF;

    let ip_ttl = data[8];
    let ip_protocol = data[9];
    if ip_protocol != IP_PROTOCOL_UDP {
        return Err(RohcParsingError::UnsupportedProtocol(ip_protocol));
    }
    let ip_checksum = u16::from_be_bytes([data[10], data[11]]);
    let ip_src = Ipv4Addr::new(data[12], data[13], data[14], data[15]);
    let ip_dst = Ipv4Addr::new(data[16], data[17], data[18], data[19]);

    let udp_offset = ip_header_len_bytes;
    if data.len() < udp_offset + 8 {
        // Minimum UDP header size
        return Err(RohcParsingError::NotEnoughData {
            needed: udp_offset + 8,
            got: data.len(),
        });
    }
    let udp_src_port = u16::from_be_bytes([data[udp_offset], data[udp_offset + 1]]);
    let udp_dst_port = u16::from_be_bytes([data[udp_offset + 2], data[udp_offset + 3]]);
    let udp_length = u16::from_be_bytes([data[udp_offset + 4], data[udp_offset + 5]]);
    let udp_checksum = u16::from_be_bytes([data[udp_offset + 6], data[udp_offset + 7]]);

    let rtp_offset = udp_offset + 8;
    if data.len() < rtp_offset + 12 {
        // Minimum RTP header size (no CSRCs)
        return Err(RohcParsingError::NotEnoughData {
            needed: rtp_offset + 12,
            got: data.len(),
        });
    }
    let rtp_version = data[rtp_offset] >> 6;
    if rtp_version != RTP_VERSION {
        return Err(RohcParsingError::InvalidFieldValue {
            field_name: "RTP Version".to_string(),
            description: format!("expected 2, got {}", rtp_version),
        });
    }
    let rtp_padding = (data[rtp_offset] >> 5) & 0x01 == 1;
    let rtp_extension = (data[rtp_offset] >> 4) & 0x01 == 1;
    let rtp_csrc_count = data[rtp_offset] & 0x0F;

    let rtp_marker = (data[rtp_offset + 1] >> 7) & 0x01 == 1;
    let rtp_payload_type = data[rtp_offset + 1] & 0x7F;
    let rtp_sequence_number = u16::from_be_bytes([data[rtp_offset + 2], data[rtp_offset + 3]]);
    let rtp_timestamp = u32::from_be_bytes([
        data[rtp_offset + 4],
        data[rtp_offset + 5],
        data[rtp_offset + 6],
        data[rtp_offset + 7],
    ]);
    let rtp_ssrc = u32::from_be_bytes([
        data[rtp_offset + 8],
        data[rtp_offset + 9],
        data[rtp_offset + 10],
        data[rtp_offset + 11],
    ]);

    let mut rtp_csrc_list = Vec::new();
    let mut current_csrc_offset = rtp_offset + 12;
    for _ in 0..rtp_csrc_count {
        if data.len() < current_csrc_offset + 4 {
            return Err(RohcParsingError::NotEnoughData {
                needed: current_csrc_offset + 4,
                got: data.len(),
            });
        }
        rtp_csrc_list.push(u32::from_be_bytes([
            data[current_csrc_offset],
            data[current_csrc_offset + 1],
            data[current_csrc_offset + 2],
            data[current_csrc_offset + 3],
        ]));
        current_csrc_offset += 4;
    }

    Ok(RtpUdpIpv4Headers {
        ip_ihl,
        ip_dscp,
        ip_ecn,
        ip_total_length,
        ip_identification,
        ip_dont_fragment,
        ip_more_fragments,
        ip_fragment_offset,
        ip_ttl,
        ip_protocol,
        ip_checksum,
        ip_src,
        ip_dst,
        udp_src_port,
        udp_dst_port,
        udp_length,
        udp_checksum,
        rtp_version,
        rtp_padding,
        rtp_extension,
        rtp_csrc_count,
        rtp_marker,
        rtp_payload_type,
        rtp_sequence_number,
        rtp_timestamp,
        rtp_ssrc,
        rtp_csrc_list,
    })
}

pub fn build_ir_profile1(
    static_info: &RtpUdpIpv4Headers,
    cid: u16, // Assume small CID for MVP for now, or needs logic for large CID representation
    _profile_id: u8, // Should be 0x01
) -> Result<Vec<u8>, RohcBuildingError> {
    // Placeholder for actual IR packet construction logic as per RFC 3095 Profile 1
    // This will involve:
    // 1. Add-CID octet if cid != 0 and small CIDs are used.
    // 2. IR packet type octet (1111110x, where x=D bit). D=1 if dynamic chain present.
    // 3. Potentially CID info if large CIDs.
    // 4. Profile octet (0x01).
    // 5. Static chain (encoding of IP/UDP/RTP static fields).
    // 6. Dynamic chain (encoding of IP/UDP/RTP dynamic fields like SN, TS, M-bit, IP-ID).
    // 7. CRC-8 over relevant parts of the packet.

    // Extremely simplified IR (conceptual)
    let mut packet = Vec::new();
    if cid > 0 && cid <= 15 {
        // Small CID
        packet.push(0xE0 | (cid as u8)); // Add-CID octet
    }
    packet.push(0xFE); // IR packet type (D=1, assumes dynamic chain)
    packet.push(0x01); // Profile ID for RTP/UDP/IP

    // Simplified static chain: just SSRC
    packet.extend_from_slice(&static_info.rtp_ssrc.to_be_bytes());
    // Simplified dynamic chain: just SN
    packet.extend_from_slice(&static_info.rtp_sequence_number.to_be_bytes());

    // CRC would be calculated here over the packet constructed so far (excluding CRC field itself)
    let crc = calculate_crc8(&packet[0..packet.len()]); // Placeholder for actual CRC calc
    packet.push(crc);

    Ok(packet)
}

// Placeholder CRC function
fn calculate_crc8(_data: &[u8]) -> u8 {
    // Implement actual ROHC CRC-8 (polynomial 0x07 = x^8 + x^2 + x + 1, init 0xFF)
    0xAB
}

// Minimal parser/builder for UO-0 for now
pub fn build_uo0_profile1(sn_lsb: u8, cid_opt: Option<u8>) -> Result<Vec<u8>, RohcBuildingError> {
    // This function builds the simplest ROHC UO-0 packet (Profile 1).
    // According to RFC 3095, section 5.7.1, a UO-0 packet starts with a '0' bit.
    // It's used for CID 0 or when the CID is implicit for the stream.
    // It does NOT contain an Add-CID octet itself. If an Add-CID octet is needed for
    // CID 1-15, that's a separate framing concern handled before this packet.
    // This function will therefore ignore cid_opt for building the UO-0 byte itself,
    // assuming the caller handles any necessary Add-CID framing externally if cid_opt is Some.
    // Or, if cid_opt is Some and not 0, this function could error, as UO-0 doesn't carry explicit non-zero CIDs.

    if let Some(cid_val) = cid_opt {
        if cid_val != 0 {
            // A UO-0 packet itself does not encode a non-zero CID.
            // Non-zero CIDs for UO-0 type streams are typically handled by an Add-CID octet
            // which *precedes* the UO-0 packet, or by large CIDs in other packet types.
            // This function is only for building the core UO-0 packet.
            return Err(RohcBuildingError::InvalidFieldValueForBuild {
                field_name: "CID".to_string(),
                description: "UO-0 packet type implies CID 0 or implicit CID; explicit non-zero CID not part of UO-0 itself.".to_string(),
            });
        }
        // If cid_opt is Some(0), it's consistent with a UO-0 for CID 0.
    }

    // UO-0 format (simplest 1-octet version for Profile 1, CID 0):
    // | 0 | SN (4 LSBs) | CRC (3 bits) |
    // This implies sn_lsb should only contain the relevant number of LSBs.
    // For this example, let's assume sn_lsb contains up to 4 LSBs for this format.
    // A more robust LSB encoding scheme would determine k (number of LSBs) from context/changes.

    if sn_lsb > 0x0F {
        // Check if sn_lsb fits in 4 bits
        return Err(RohcBuildingError::InvalidFieldValueForBuild {
            field_name: "sn_lsb".to_string(),
            description: "value too large for 4-bit SN LSB field in 1-octet UO-0".to_string(),
        });
    }

    // First bit is 0 (implicitly, by not setting the highest bit).
    // Next 4 bits are SN LSB.
    // Last 3 bits are CRC.
    let sn_field = (sn_lsb & 0x0F) << 3; // Shift SN to bits 6-3 (0 SSSS CCC)

    // Placeholder for actual 3-bit CRC calculation over original header.
    // The CRC is computed over the uncompressed header fields that are being compressed.
    // For UO-0, this is typically SN, and other fields that might change infrequently
    // but whose change isn't signaled by this UO-0 packet itself.
    // See RFC 3095 section 5.9.2.
    let crc3_placeholder = 0x01; // Must be a 3-bit value

    let packet_byte = sn_field | (crc3_placeholder & 0x07);

    Ok(vec![packet_byte])
}

pub fn parse_uo0_profile1(data: &[u8]) -> Result<RohcUo0PacketProfile1, RohcParsingError> {
    if data.is_empty() {
        return Err(RohcParsingError::NotEnoughData { needed: 1, got: 0 });
    }
    if (data[0] >> 7) != 0 {
        // First bit must be 0 for UO-0
        return Err(RohcParsingError::InvalidPacketType(data[0]));
    }
    // This parsing is highly simplified and assumes the 1-octet UO-0 format for CID 0
    // 0 | SN (4-bits) | CRC (3-bits)
    let sn_lsb = (data[0] >> 3) & 0x0F;
    let crc3 = data[0] & 0x07;

    Ok(RohcUo0PacketProfile1 {
        cid: None,
        sn_lsb,
        crc3,
    })
}

// TODO: Implement LSB/W-LSB encoding/decoding functions
// TODO: Implement actual CRC-3, CRC-7, CRC-8 calculations

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_parse_basic_rtp_udp_ipv4() {
        // IPv4 Header (20 bytes)
        let mut ip_header: [u8; 20] = [0; 20];
        ip_header[0] = 0x45; // Version 4, IHL 5 (20 bytes)
        ip_header[1] = 0x00; // DSCP, ECN
        ip_header[2..4].copy_from_slice(&((20 + 8 + 12) as u16).to_be_bytes()); // Total Length (IP+UDP+RTP)
        ip_header[8] = 64; // TTL
        ip_header[9] = 17; // Protocol UDP
        ip_header[12..16].copy_from_slice(&[192, 168, 1, 1]); // Source IP
        ip_header[16..20].copy_from_slice(&[192, 168, 1, 2]); // Dest IP
        // Calculate and set IP checksum (placeholder)
        // ...

        // UDP Header (8 bytes)
        let mut udp_header: [u8; 8] = [0; 8];
        udp_header[0..2].copy_from_slice(&12345u16.to_be_bytes()); // Source Port
        udp_header[2..4].copy_from_slice(&54321u16.to_be_bytes()); // Dest Port
        udp_header[4..6].copy_from_slice(&((8 + 12) as u16).to_be_bytes()); // Length (UDP+RTP)

        // RTP Header (12 bytes)
        let mut rtp_header: [u8; 12] = [0; 12];
        rtp_header[0] = 0x80; // Version 2, P=0, X=0, CC=0
        rtp_header[1] = 0x60; // M=1, PT=96 (dynamic)
        rtp_header[2..4].copy_from_slice(&1001u16.to_be_bytes()); // Sequence Number
        rtp_header[4..8].copy_from_slice(&3000u32.to_be_bytes()); // Timestamp
        rtp_header[8..12].copy_from_slice(&0x12345678u32.to_be_bytes()); // SSRC

        let mut packet_bytes = Vec::new();
        packet_bytes.extend_from_slice(&ip_header);
        packet_bytes.extend_from_slice(&udp_header);
        packet_bytes.extend_from_slice(&rtp_header);

        let parsed = parse_rtp_udp_ipv4(&packet_bytes).unwrap();
        assert_eq!(parsed.ip_src, Ipv4Addr::new(192, 168, 1, 1));
        assert_eq!(parsed.udp_dst_port, 54321);
        assert_eq!(parsed.rtp_ssrc, 0x12345678);
        assert_eq!(parsed.rtp_sequence_number, 1001);
        assert!(!parsed.rtp_marker);
    }

    #[test]
    fn test_build_parse_ir_profile1_simple() {
        let static_info = RtpUdpIpv4Headers::default();
        let ir_bytes = build_ir_profile1(&static_info, 1, 0x01).unwrap();
        assert!(!ir_bytes.is_empty());
    }
}
