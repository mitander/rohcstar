use crate::crc::calculate_rohc_crc8;
use crate::error::{RohcBuildingError, RohcParsingError};
use crate::protocol_types::RohcUo1PacketProfile1;
use crate::protocol_types::{RohcIrProfile1Packet, RohcUo0PacketProfile1, RtpUdpIpv4Headers};
use std::net::Ipv4Addr;

pub const IP_PROTOCOL_UDP: u8 = 17;
pub const RTP_VERSION: u8 = 2;
pub const PROFILE_ID_RTP_UDP_IP: u8 = 0x01;

pub const ROHC_IR_PACKET_TYPE_D_BIT_MASK: u8 = 0x01;
pub const ROHC_IR_PACKET_TYPE_BASE: u8 = 0b1111_1100;
pub const ROHC_IR_PACKET_TYPE_STATIC_ONLY: u8 = ROHC_IR_PACKET_TYPE_BASE;
pub const ROHC_IR_PACKET_TYPE_WITH_DYN: u8 =
    ROHC_IR_PACKET_TYPE_BASE | ROHC_IR_PACKET_TYPE_D_BIT_MASK;

pub const ADD_CID_OCTET_PREFIX_MASK: u8 = 0b1111_0000;
pub const ADD_CID_OCTET_PREFIX_VALUE: u8 = 0b1110_0000;
pub const ADD_CID_OCTET_CID_MASK: u8 = 0x0F;

pub const UO_1_SN_PACKET_TYPE_BASE: u8 = 0b10100000; // 0xA0
pub const UO_1_SN_MARKER_BIT_MASK: u8 = 0b00000001;

pub fn parse_rtp_udp_ipv4(data: &[u8]) -> Result<RtpUdpIpv4Headers, RohcParsingError> {
    if data.len() < 20 {
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

pub fn build_ir_profile1_packet(
    ir_data: &RohcIrProfile1Packet,
) -> Result<Vec<u8>, RohcBuildingError> {
    let mut packet_framing = Vec::with_capacity(3); // For Add-CID (opt), Type, Profile
    let mut crc_payload = Vec::with_capacity(32);

    if ir_data.cid > 0 && ir_data.cid <= 15 {
        packet_framing
            .push(ADD_CID_OCTET_PREFIX_VALUE | (ir_data.cid as u8 & ADD_CID_OCTET_CID_MASK));
    } else if ir_data.cid > 15 {
        return Err(RohcBuildingError::ContextInsufficient(
            "Large CID not supported in MVP IR builder".to_string(),
        ));
    }

    packet_framing.push(ROHC_IR_PACKET_TYPE_WITH_DYN);

    // Profile ID is the first byte of the CRC payload AND part of framing after Type
    packet_framing.push(ir_data.profile);
    crc_payload.push(ir_data.profile); // Start CRC payload with Profile

    if ir_data.profile != PROFILE_ID_RTP_UDP_IP {
        return Err(RohcBuildingError::InvalidFieldValueForBuild {
            field_name: "Profile ID".to_string(),
            description: format!("Expected P1 (0x01), got 0x{:02X}", ir_data.profile),
        });
    }

    crc_payload.extend_from_slice(&ir_data.static_ip_src.octets());
    crc_payload.extend_from_slice(&ir_data.static_ip_dst.octets());
    crc_payload.extend_from_slice(&ir_data.static_udp_src_port.to_be_bytes());
    crc_payload.extend_from_slice(&ir_data.static_udp_dst_port.to_be_bytes());
    crc_payload.extend_from_slice(&ir_data.static_rtp_ssrc.to_be_bytes());

    crc_payload.extend_from_slice(&ir_data.dyn_rtp_sn.to_be_bytes());
    crc_payload.extend_from_slice(&ir_data.dyn_rtp_timestamp.to_be_bytes());
    let rtp_flags: u8 = if ir_data.dyn_rtp_marker { 0x80 } else { 0x00 };
    crc_payload.push(rtp_flags);

    let crc_val = calculate_rohc_crc8(&crc_payload);

    let mut final_packet = packet_framing;
    final_packet.extend_from_slice(&crc_payload[1..]); // Append rest of crc_payload (Static + Dynamic)
    final_packet.push(crc_val);

    Ok(final_packet)
}

/// Builds a ROHC UO-0 packet (1-octet version for CID 0, Profile 1).
/// Assumes 4 LSBs for SN, 3 LSBs for CRC.
/// The `sn_4_lsb` should be the 4 least significant bits of the RTP Sequence Number.
/// The `crc3_val` is the pre-calculated 3-bit CRC over the original header.
pub fn build_uo0_profile1_cid0_packet(
    sn_4_lsb: u8,
    crc3_val: u8,
) -> Result<Vec<u8>, RohcBuildingError> {
    if sn_4_lsb > 0x0F {
        return Err(RohcBuildingError::InvalidFieldValueForBuild {
            field_name: "sn_4_lsb".to_string(),
            description: "value too large for 4-bit SN LSB field".to_string(),
        });
    }
    if crc3_val > 0x07 {
        return Err(RohcBuildingError::InvalidFieldValueForBuild {
            field_name: "crc3_val".to_string(),
            description: "value too large for 3-bit CRC field".to_string(),
        });
    }
    let packet_byte = (sn_4_lsb << 3) | crc3_val;
    Ok(vec![packet_byte])
}

pub fn parse_ir_profile1_packet(data: &[u8]) -> Result<RohcIrProfile1Packet, RohcParsingError> {
    let mut current_offset = 0;
    let mut parsed_cid: u16 = 0;

    if data.is_empty() {
        return Err(RohcParsingError::NotEnoughData { needed: 1, got: 0 });
    }
    if (data[current_offset] & ADD_CID_OCTET_PREFIX_MASK) == ADD_CID_OCTET_PREFIX_VALUE {
        let cid_val = data[current_offset] & ADD_CID_OCTET_CID_MASK;
        if cid_val == 0 {
            return Err(RohcParsingError::InvalidFieldValue {
                field_name: "Add-CID".to_string(),
                description: "Add-CID octet for CID 0 is invalid (looks like padding)".to_string(),
            });
        }
        parsed_cid = cid_val as u16;
        current_offset += 1;
        if current_offset >= data.len() {
            return Err(RohcParsingError::NotEnoughData {
                needed: current_offset + 1,
                got: data.len(),
            });
        }
    }

    if current_offset >= data.len() {
        // Check after potential Add-CID processing
        return Err(RohcParsingError::NotEnoughData {
            needed: current_offset + 1,
            got: data.len(),
        });
    }
    if (data[current_offset] & !ROHC_IR_PACKET_TYPE_D_BIT_MASK) != ROHC_IR_PACKET_TYPE_BASE {
        return Err(RohcParsingError::InvalidPacketType(data[current_offset]));
    }
    let d_bit =
        (data[current_offset] & ROHC_IR_PACKET_TYPE_D_BIT_MASK) == ROHC_IR_PACKET_TYPE_D_BIT_MASK;
    current_offset += 1;

    if current_offset >= data.len() {
        return Err(RohcParsingError::NotEnoughData {
            needed: current_offset + 1,
            got: data.len(),
        });
    }
    let profile_byte_offset = current_offset;
    let profile = data[profile_byte_offset];
    if profile != PROFILE_ID_RTP_UDP_IP {
        return Err(RohcParsingError::InvalidProfileId(profile));
    }
    current_offset += 1;

    let static_chain_base_len = 4 + 4 + 2 + 2 + 4;
    let dynamic_chain_len = if d_bit { 2 + 4 + 1 } else { 0 };
    // CRC Payload = Profile(1) + Static_chain_base + Dynamic_chain
    let crc_payload_len = 1 + static_chain_base_len + dynamic_chain_len;

    let end_of_crc_payload_exclusive = profile_byte_offset + crc_payload_len;
    let crc_byte_offset = end_of_crc_payload_exclusive;

    if data.len() < crc_byte_offset + 1 {
        return Err(RohcParsingError::NotEnoughData {
            needed: crc_byte_offset + 1,
            got: data.len(),
        });
    }

    let crc_payload_slice = &data[profile_byte_offset..crc_byte_offset];
    let received_crc = data[crc_byte_offset];
    let calculated_crc = calculate_rohc_crc8(crc_payload_slice);

    if received_crc != calculated_crc {
        return Err(RohcParsingError::CrcMismatch {
            expected: received_crc,
            calculated: calculated_crc,
        });
    }

    // current_offset is at the start of static chain (after profile byte)
    let static_ip_src = Ipv4Addr::new(
        data[current_offset],
        data[current_offset + 1],
        data[current_offset + 2],
        data[current_offset + 3],
    );
    current_offset += 4;
    let static_ip_dst = Ipv4Addr::new(
        data[current_offset],
        data[current_offset + 1],
        data[current_offset + 2],
        data[current_offset + 3],
    );
    current_offset += 4;
    let static_udp_src_port = u16::from_be_bytes([data[current_offset], data[current_offset + 1]]);
    current_offset += 2;
    let static_udp_dst_port = u16::from_be_bytes([data[current_offset], data[current_offset + 1]]);
    current_offset += 2;
    let static_rtp_ssrc = u32::from_be_bytes([
        data[current_offset],
        data[current_offset + 1],
        data[current_offset + 2],
        data[current_offset + 3],
    ]);
    current_offset += 4;

    let (dyn_rtp_sn, dyn_rtp_timestamp, dyn_rtp_marker) = if d_bit {
        if current_offset + dynamic_chain_len > crc_byte_offset {
            // Ensure dynamic chain is within CRC'd part
            return Err(RohcParsingError::NotEnoughData {
                needed: current_offset + dynamic_chain_len,
                got: crc_byte_offset,
            });
        }
        let sn = u16::from_be_bytes([data[current_offset], data[current_offset + 1]]);
        current_offset += 2;
        let ts = u32::from_be_bytes([
            data[current_offset],
            data[current_offset + 1],
            data[current_offset + 2],
            data[current_offset + 3],
        ]);
        current_offset += 4;
        let rtp_flags = data[current_offset];
        let marker = (rtp_flags & 0x80) == 0x80;
        (sn, ts, marker)
    } else {
        (0, 0, false)
    };

    Ok(RohcIrProfile1Packet {
        cid: parsed_cid,
        profile,
        crc8: received_crc,
        static_ip_src,
        static_ip_dst,
        static_udp_src_port,
        static_udp_dst_port,
        static_rtp_ssrc,
        dyn_rtp_sn,
        dyn_rtp_timestamp,
        dyn_rtp_marker,
    })
}

pub fn parse_uo0_profile1_cid0_packet(
    data: &[u8],
) -> Result<RohcUo0PacketProfile1, RohcParsingError> {
    if data.is_empty() {
        return Err(RohcParsingError::NotEnoughData { needed: 1, got: 0 });
    }
    if (data[0] & 0x80) != 0 {
        return Err(RohcParsingError::InvalidPacketType(data[0]));
    }
    let packet_byte = data[0];
    let sn_lsb = (packet_byte >> 3) & 0x0F;
    let crc3 = packet_byte & 0x07;

    Ok(RohcUo0PacketProfile1 {
        cid: None,
        sn_lsb,
        crc3,
    })
}

pub fn build_uo1_sn_profile1_packet(
    sn_8_lsb: u8,
    marker_bit: bool,
    crc8_val: u8, // Changed: take pre-calculated CRC
) -> Result<Vec<u8>, RohcBuildingError> {
    let type_byte = UO_1_SN_PACKET_TYPE_BASE
        | (if marker_bit {
            UO_1_SN_MARKER_BIT_MASK
        } else {
            0
        });

    Ok(vec![type_byte, sn_8_lsb, crc8_val])
}

pub fn parse_uo1_sn_profile1_packet(
    data: &[u8],
) -> Result<RohcUo1PacketProfile1, RohcParsingError> {
    if data.len() < 3 {
        return Err(RohcParsingError::NotEnoughData {
            needed: 3,
            got: data.len(),
        });
    }

    let type_byte = data[0];
    if (type_byte & 0xF0) != UO_1_SN_PACKET_TYPE_BASE {
        // Check leading 4 bits `1010`
        return Err(RohcParsingError::InvalidPacketType(type_byte));
    }

    let marker_bit_changed = Some((type_byte & UO_1_SN_MARKER_BIT_MASK) != 0);
    let sn_lsb_val = data[1] as u16; // This is 8 bits
    let received_crc8 = data[2];

    // CRC Verification: For UO-1, CRC is on original headers. Decompressor needs context
    // to reconstruct those original headers and then verify CRC.
    // The parser's role is to extract the fields including the received_crc8.
    // CRC verification happens in the main decompressor logic.

    Ok(RohcUo1PacketProfile1 {
        sn_lsb: sn_lsb_val,
        num_sn_lsb_bits: 8, // Fixed for this MVP UO-1 type
        rtp_marker_bit_changed: marker_bit_changed,
        crc8: received_crc8,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_parse_basic_rtp_udp_ipv4() {
        let mut ip_header: [u8; 20] = [0; 20];
        ip_header[0] = 0x45;
        ip_header[1] = 0x00;
        ip_header[2..4].copy_from_slice(&((20 + 8 + 12) as u16).to_be_bytes());
        ip_header[8] = 64;
        ip_header[9] = 17;
        ip_header[12..16].copy_from_slice(&[192, 168, 1, 1]);
        ip_header[16..20].copy_from_slice(&[192, 168, 1, 2]);

        let mut udp_header: [u8; 8] = [0; 8];
        udp_header[0..2].copy_from_slice(&12345u16.to_be_bytes());
        udp_header[2..4].copy_from_slice(&54321u16.to_be_bytes());
        udp_header[4..6].copy_from_slice(&((8 + 12) as u16).to_be_bytes());

        let mut rtp_header: [u8; 12] = [0; 12];
        rtp_header[0] = 0x80;
        rtp_header[1] = 0x60;
        rtp_header[2..4].copy_from_slice(&1001u16.to_be_bytes());
        rtp_header[4..8].copy_from_slice(&3000u32.to_be_bytes());
        rtp_header[8..12].copy_from_slice(&0x12345678u32.to_be_bytes());

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
    fn test_build_and_parse_ir_profile1_cid0() {
        let ir_data = RohcIrProfile1Packet {
            cid: 0,
            profile: PROFILE_ID_RTP_UDP_IP,
            crc8: 0,
            static_ip_src: Ipv4Addr::new(1, 2, 3, 4),
            static_ip_dst: Ipv4Addr::new(5, 6, 7, 8),
            static_udp_src_port: 1000,
            static_udp_dst_port: 2000,
            static_rtp_ssrc: 0xABCDEFFF,
            dyn_rtp_sn: 12345,
            dyn_rtp_timestamp: 543210,
            dyn_rtp_marker: true,
        };

        let built_packet = build_ir_profile1_packet(&ir_data).unwrap();

        let expected_len = 1 + (1 + 4 + 4 + 2 + 2 + 4) + (2 + 4 + 1) + 1; // Type + (Profile+Static) + Dynamic + CRC
        assert_eq!(built_packet.len(), expected_len);
        assert_eq!(built_packet[0], ROHC_IR_PACKET_TYPE_WITH_DYN);
        assert_eq!(built_packet[1], PROFILE_ID_RTP_UDP_IP);

        let parsed_packet = parse_ir_profile1_packet(&built_packet).unwrap();
        assert_eq!(parsed_packet.cid, ir_data.cid);
        assert_eq!(parsed_packet.profile, ir_data.profile);
        assert_eq!(parsed_packet.static_ip_src, ir_data.static_ip_src);
        assert_eq!(parsed_packet.static_ip_dst, ir_data.static_ip_dst);
        assert_eq!(
            parsed_packet.static_udp_src_port,
            ir_data.static_udp_src_port
        );
        assert_eq!(
            parsed_packet.static_udp_dst_port,
            ir_data.static_udp_dst_port
        );
        assert_eq!(parsed_packet.static_rtp_ssrc, ir_data.static_rtp_ssrc);
        assert_eq!(parsed_packet.dyn_rtp_sn, ir_data.dyn_rtp_sn);
        assert_eq!(parsed_packet.dyn_rtp_timestamp, ir_data.dyn_rtp_timestamp);
        assert_eq!(parsed_packet.dyn_rtp_marker, ir_data.dyn_rtp_marker);
        assert_eq!(parsed_packet.crc8, *built_packet.last().unwrap());
    }

    #[test]
    fn test_build_and_parse_ir_profile1_small_cid() {
        let ir_data = RohcIrProfile1Packet {
            cid: 7,
            profile: PROFILE_ID_RTP_UDP_IP,
            crc8: 0,
            static_ip_src: Ipv4Addr::new(10, 0, 0, 1),
            static_ip_dst: Ipv4Addr::new(10, 0, 0, 2),
            static_udp_src_port: 3000,
            static_udp_dst_port: 4000,
            static_rtp_ssrc: 0x11223344,
            dyn_rtp_sn: 500,
            dyn_rtp_timestamp: 10000,
            dyn_rtp_marker: false,
        };

        let built_packet = build_ir_profile1_packet(&ir_data).unwrap();
        let expected_len = 1 + 1 + (1 + 4 + 4 + 2 + 2 + 4) + (2 + 4 + 1) + 1; // AddCID + Type + (Profile+Static) + Dynamic + CRC
        assert_eq!(built_packet.len(), expected_len);
        assert_eq!(built_packet[0], ADD_CID_OCTET_PREFIX_VALUE | 7);
        assert_eq!(built_packet[1], ROHC_IR_PACKET_TYPE_WITH_DYN);
        assert_eq!(built_packet[2], PROFILE_ID_RTP_UDP_IP);

        let parsed_packet = parse_ir_profile1_packet(&built_packet).unwrap();
        assert_eq!(parsed_packet.cid, ir_data.cid);
    }

    #[test]
    fn test_parse_ir_crc_error() {
        let ir_data = RohcIrProfile1Packet {
            cid: 0,
            profile: PROFILE_ID_RTP_UDP_IP,
            ..Default::default()
        };
        let mut built_packet = build_ir_profile1_packet(&ir_data).unwrap();
        if !built_packet.is_empty() {
            let last_idx = built_packet.len() - 1;
            built_packet[last_idx] = built_packet[last_idx].wrapping_add(1);
        } else {
            panic!("Built packet is empty, cannot corrupt CRC");
        }

        match parse_ir_profile1_packet(&built_packet) {
            Err(RohcParsingError::CrcMismatch { .. }) => {}
            Ok(p) => panic!("Expected CRC mismatch error, got Ok({:?})", p),
            Err(e) => panic!("Expected CRC mismatch error, got other error: {:?}", e),
        }
    }

    #[test]
    fn test_build_and_parse_uo0_cid0_packet() {
        let sn_lsb: u8 = 0b1010;
        let crc3: u8 = 0b101;

        let built_packet = build_uo0_profile1_cid0_packet(sn_lsb, crc3).unwrap();
        assert_eq!(built_packet.len(), 1);
        assert_eq!(built_packet[0], (sn_lsb << 3) | crc3);
        assert_eq!(built_packet[0], 0x55);

        let parsed_packet = parse_uo0_profile1_cid0_packet(&built_packet).unwrap();
        assert_eq!(parsed_packet.cid, None);
        assert_eq!(parsed_packet.sn_lsb, sn_lsb);
        assert_eq!(parsed_packet.crc3, crc3);
    }

    #[test]
    fn test_parse_uo0_invalid_type() {
        match parse_uo0_profile1_cid0_packet(&[0x80]) {
            Err(RohcParsingError::InvalidPacketType(0x80)) => {}
            res => panic!("Expected InvalidPacketType, got {:?}", res),
        }
    }

    #[test]
    fn test_build_and_parse_uo1_sn_packet() {
        let sn_lsbs: u8 = 0xAB;
        let marker = true;

        // Simulate CRC calculation as compressor would do
        let original_sn_for_crc: u16 = 0x12AB;
        let original_ts_for_crc: u32 = 5000;
        let original_marker_for_crc = true;
        let original_ssrc_for_crc: u32 = 0xDEADBEEF;

        let mut crc_input_test = Vec::new();
        crc_input_test.extend_from_slice(&original_ssrc_for_crc.to_be_bytes());
        crc_input_test.extend_from_slice(&original_sn_for_crc.to_be_bytes());
        crc_input_test.extend_from_slice(&original_ts_for_crc.to_be_bytes());
        crc_input_test.push(if original_marker_for_crc { 0x01 } else { 0x00 });
        let expected_crc = calculate_rohc_crc8(&crc_input_test);

        // Pass the pre-calculated CRC to the builder
        let built_packet = build_uo1_sn_profile1_packet(sn_lsbs, marker, expected_crc).unwrap();
        assert_eq!(built_packet.len(), 3);
        assert_eq!(
            built_packet[0],
            UO_1_SN_PACKET_TYPE_BASE | UO_1_SN_MARKER_BIT_MASK
        );
        assert_eq!(built_packet[1], sn_lsbs);
        assert_eq!(built_packet[2], expected_crc);

        let parsed_packet = parse_uo1_sn_profile1_packet(&built_packet).unwrap();
        assert_eq!(parsed_packet.sn_lsb, sn_lsbs as u16);
        assert_eq!(parsed_packet.num_sn_lsb_bits, 8);
        assert_eq!(parsed_packet.rtp_marker_bit_changed, Some(marker));
        assert_eq!(parsed_packet.crc8, expected_crc);
    }
}
