use crate::constants::{
    ADD_CID_OCTET_CID_MASK, ADD_CID_OCTET_PREFIX_VALUE, IP_PROTOCOL_UDP, PROFILE_ID_RTP_UDP_IP,
    ROHC_IR_PACKET_TYPE_BASE, ROHC_IR_PACKET_TYPE_D_BIT_MASK, ROHC_IR_PACKET_TYPE_WITH_DYN,
    RTP_VERSION, UO_1_SN_P1_MARKER_BIT_MASK, UO_1_SN_P1_PACKET_TYPE_BASE,
};
use crate::crc::calculate_rohc_crc8; // Assuming CRC-3 is not used directly in packet_processor builders
use crate::error::{RohcBuildingError, RohcParsingError};
use crate::protocol_types::{
    RohcIrProfile1Packet, RohcUo0PacketProfile1, RohcUo1PacketProfile1, RtpUdpIpv4Headers,
};
use std::net::Ipv4Addr;

/// Minimum length of an IPv4 header in bytes (without options).
const IPV4_MIN_HEADER_LENGTH_BYTES: usize = 20;
/// Length of a UDP header in bytes.
const UDP_HEADER_LENGTH_BYTES: usize = 8;
/// Minimum length of an RTP header in bytes (without CSRC list or extension).
const RTP_MIN_HEADER_LENGTH_BYTES: usize = 12;

/// Parses uncompressed RTP/UDP/IPv4 headers from a raw byte slice.
///
/// This function expects the byte slice to start with the IPv4 header, followed by
/// the UDP header, and then the RTP header. It performs basic validation for lengths
/// and protocol identifiers.
///
/// # Arguments
/// * `data`: A byte slice containing the raw header data.
///
/// # Returns
/// A `Result` containing the parsed `RtpUdpIpv4Headers` or a `RohcParsingError`
/// if parsing fails (e.g., insufficient data, invalid protocol versions).
pub fn parse_rtp_udp_ipv4(data: &[u8]) -> Result<RtpUdpIpv4Headers, RohcParsingError> {
    if data.len() < IPV4_MIN_HEADER_LENGTH_BYTES {
        return Err(RohcParsingError::NotEnoughData {
            needed: IPV4_MIN_HEADER_LENGTH_BYTES,
            got: data.len(),
        });
    }

    let ip_version = data[0] >> 4;
    if ip_version != 4 {
        return Err(RohcParsingError::InvalidIpVersion(ip_version));
    }
    let ip_ihl_words = data[0] & 0x0F; // IHL is in 4-byte words
    if ip_ihl_words < 5 {
        return Err(RohcParsingError::InvalidFieldValue {
            field_name: "IPv4 IHL".to_string(),
            description: format!("must be at least 5 words, got {}", ip_ihl_words),
        });
    }
    let ip_header_length_bytes = (ip_ihl_words * 4) as usize;
    if data.len() < ip_header_length_bytes {
        return Err(RohcParsingError::NotEnoughData {
            needed: ip_header_length_bytes,
            got: data.len(),
        });
    }

    let ip_dscp = data[1] >> 2;
    let ip_ecn = data[1] & 0x03;
    let ip_total_length = u16::from_be_bytes([data[2], data[3]]);
    let ip_identification = u16::from_be_bytes([data[4], data[5]]);
    let flags_and_fragment_offset = u16::from_be_bytes([data[6], data[7]]);
    let ip_dont_fragment = (flags_and_fragment_offset >> 14) & 0x01 == 1; // Bit 1 (0-indexed from MSB)
    let ip_more_fragments = (flags_and_fragment_offset >> 13) & 0x01 == 1; // Bit 2
    let ip_fragment_offset = flags_and_fragment_offset & 0x1FFF; // Lower 13 bits

    let ip_ttl = data[8];
    let ip_protocol_id = data[9];
    if ip_protocol_id != IP_PROTOCOL_UDP {
        return Err(RohcParsingError::UnsupportedProtocol(ip_protocol_id));
    }
    let ip_checksum = u16::from_be_bytes([data[10], data[11]]);
    let ip_src_addr = Ipv4Addr::new(data[12], data[13], data[14], data[15]);
    let ip_dst_addr = Ipv4Addr::new(data[16], data[17], data[18], data[19]);

    let udp_start_offset = ip_header_length_bytes;
    if data.len() < udp_start_offset + UDP_HEADER_LENGTH_BYTES {
        return Err(RohcParsingError::NotEnoughData {
            needed: udp_start_offset + UDP_HEADER_LENGTH_BYTES,
            got: data.len(),
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
        });
    }
    let rtp_first_byte = data[rtp_start_offset];
    let rtp_version_val = rtp_first_byte >> 6;
    if rtp_version_val != RTP_VERSION {
        return Err(RohcParsingError::InvalidFieldValue {
            field_name: "RTP Version".to_string(),
            description: format!("expected {}, got {}", RTP_VERSION, rtp_version_val),
        });
    }
    let rtp_padding_flag = (rtp_first_byte >> 5) & 0x01 == 1;
    let rtp_extension_flag = (rtp_first_byte >> 4) & 0x01 == 1;
    let rtp_csrc_count_val = rtp_first_byte & 0x0F;

    let rtp_second_byte = data[rtp_start_offset + 1];
    let rtp_marker_flag = (rtp_second_byte >> 7) & 0x01 == 1;
    let rtp_payload_type_val = rtp_second_byte & 0x7F;
    let rtp_seq_num = u16::from_be_bytes([data[rtp_start_offset + 2], data[rtp_start_offset + 3]]);
    let rtp_ts_val = u32::from_be_bytes([
        data[rtp_start_offset + 4],
        data[rtp_start_offset + 5],
        data[rtp_start_offset + 6],
        data[rtp_start_offset + 7],
    ]);
    let rtp_ssrc_val = u32::from_be_bytes([
        data[rtp_start_offset + 8],
        data[rtp_start_offset + 9],
        data[rtp_start_offset + 10],
        data[rtp_start_offset + 11],
    ]);

    let mut rtp_csrc_list_val = Vec::with_capacity(rtp_csrc_count_val as usize);
    let mut current_csrc_offset = rtp_start_offset + RTP_MIN_HEADER_LENGTH_BYTES;
    for _ in 0..rtp_csrc_count_val {
        if data.len() < current_csrc_offset + 4 {
            // Not enough data for the next CSRC identifier
            return Err(RohcParsingError::NotEnoughData {
                needed: current_csrc_offset + 4,
                got: data.len(),
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

    Ok(RtpUdpIpv4Headers {
        ip_ihl: ip_ihl_words,
        ip_dscp,
        ip_ecn,
        ip_total_length,
        ip_identification,
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
        rtp_sequence_number: rtp_seq_num,
        rtp_timestamp: rtp_ts_val,
        rtp_ssrc: rtp_ssrc_val,
        rtp_csrc_list: rtp_csrc_list_val,
    })
}

/// Builds a ROHC IR (Initialization and Refresh) packet for Profile 1 (RTP/UDP/IP).
///
/// This function constructs the IR packet bytes based on the provided `RohcIrProfile1Packet` data.
/// It handles optional Add-CID octet, packet type, profile ID, static chain, dynamic chain,
/// and calculates the CRC-8.
///
/// # Arguments
/// * `ir_data`: A reference to `RohcIrProfile1Packet` containing all necessary field values.
///   The `crc8` field in `ir_data` is ignored; CRC is calculated by this function.
///
/// # Returns
/// A `Result` containing the built IR packet as a `Vec<u8>`, or a `RohcBuildingError`
/// if packet construction fails (e.g., invalid CID for Add-CID, unsupported profile).
pub fn build_ir_profile1_packet(
    ir_data: &RohcIrProfile1Packet,
) -> Result<Vec<u8>, RohcBuildingError> {
    // Estimate capacity: Add-CID (1, optional) + Type (1) + Profile (1) + Static (16) + Dynamic (7) + CRC (1)
    let mut final_packet_bytes = Vec::with_capacity(1 + 1 + 1 + 16 + 7 + 1);
    // CRC payload starts *after* Type octet and *includes* Profile octet.
    let mut crc_payload_bytes = Vec::with_capacity(1 + 16 + 7);

    if ir_data.cid > 0 && ir_data.cid <= 15 {
        final_packet_bytes
            .push(ADD_CID_OCTET_PREFIX_VALUE | (ir_data.cid as u8 & ADD_CID_OCTET_CID_MASK));
    } else if ir_data.cid > 15 {
        // Large CIDs require different encoding not covered in this MVP IR builder.
        return Err(RohcBuildingError::ContextInsufficient(
            "Large CID not supported for IR packet Add-CID in MVP builder.".to_string(),
        ));
    }
    // For CID 0, no Add-CID octet is prepended.

    // Packet type is always IR with dynamic chain for Profile 1 U-mode MVP.
    final_packet_bytes.push(ROHC_IR_PACKET_TYPE_WITH_DYN);

    if ir_data.profile != PROFILE_ID_RTP_UDP_IP {
        return Err(RohcBuildingError::InvalidFieldValueForBuild {
            field_name: "Profile ID".to_string(),
            description: format!(
                "Expected ROHC Profile 1 (0x{:02X}), got 0x{:02X}",
                PROFILE_ID_RTP_UDP_IP, ir_data.profile
            ),
        });
    }
    final_packet_bytes.push(ir_data.profile);
    crc_payload_bytes.push(ir_data.profile); // Profile is the first byte of CRC payload

    crc_payload_bytes.extend_from_slice(&ir_data.static_ip_src.octets());
    crc_payload_bytes.extend_from_slice(&ir_data.static_ip_dst.octets());
    crc_payload_bytes.extend_from_slice(&ir_data.static_udp_src_port.to_be_bytes());
    crc_payload_bytes.extend_from_slice(&ir_data.static_udp_dst_port.to_be_bytes());
    crc_payload_bytes.extend_from_slice(&ir_data.static_rtp_ssrc.to_be_bytes());

    crc_payload_bytes.extend_from_slice(&ir_data.dyn_rtp_sn.to_be_bytes());
    crc_payload_bytes.extend_from_slice(&ir_data.dyn_rtp_timestamp.to_be_bytes());
    // RTP flags octet: M-bit is MSB, other bits reserved (0 for U-mode P1 IR).
    crc_payload_bytes.push(if ir_data.dyn_rtp_marker { 0x80 } else { 0x00 });

    let calculated_crc8 = calculate_rohc_crc8(&crc_payload_bytes);

    // Append the CRC payload (Static + Dynamic chain part) to the framing.
    // `crc_payload_bytes[0]` was Profile, which is already in `final_packet_bytes`.
    final_packet_bytes.extend_from_slice(&crc_payload_bytes[1..]);
    final_packet_bytes.push(calculated_crc8); // Append calculated CRC

    Ok(final_packet_bytes)
}

/// Builds a ROHC UO-0 packet for Profile 1, specifically for CID 0 (1-octet version).
///
/// This packet type is highly compressed, containing only LSBs of the RTP Sequence Number
/// and a 3-bit CRC.
///
/// # Arguments
/// * `sn_4_lsb`: The 4 least significant bits of the RTP Sequence Number.
/// * `crc3_value`: The pre-calculated 3-bit CRC over the (reconstructed) original header.
///
/// # Returns
/// A `Result` containing the 1-byte UO-0 packet as `Vec<u8>`, or a `RohcBuildingError`
/// if input values are out of range.
pub fn build_uo0_profile1_cid0_packet(
    sn_4_lsb: u8,
    crc3_value: u8,
) -> Result<Vec<u8>, RohcBuildingError> {
    if sn_4_lsb > 0x0F {
        // Max value for 4 bits
        return Err(RohcBuildingError::InvalidFieldValueForBuild {
            field_name: "sn_4_lsb".to_string(),
            description: "value exceeds 4-bit representation.".to_string(),
        });
    }
    if crc3_value > 0x07 {
        // Max value for 3 bits
        return Err(RohcBuildingError::InvalidFieldValueForBuild {
            field_name: "crc3_value".to_string(),
            description: "value exceeds 3-bit representation.".to_string(),
        });
    }
    // Packet format for UO-0 (CID 0): SSSS CPreferenceKey (S=SN LSB, C=CRC LSB)
    // First bit must be 0. Structure is `0 SSS S CPreferenceKey` per RFC3095 5.7.4.
    // For UO-0 this means the first bit is 0, then 4 bits SN, then 3 bits CRC.
    // This translates to `0b0(sn_4_lsb)(crc3_value)`.
    // However, the type `0...` is distinct from Add-CID.
    // If MSB is 0, it's UO-0. `(sn_4_lsb << 3)` places SN in bits 7-4 (0-indexed).
    // Then `| crc3_value` places CRC in bits 2-0.
    // Example: sn_lsb=0b1010, crc3=0b101 => 0b01010101 = 0x55
    let packet_byte = (sn_4_lsb << 3) | crc3_value;
    Ok(vec![packet_byte])
}

/// Parses a ROHC IR (Initialization and Refresh) packet for Profile 1 (RTP/UDP/IP).
///
/// This function expects the `data` slice to start with the ROHC packet type octet
/// (i.e., after any Add-CID octet has been processed and removed by the caller).
/// It validates the packet type, profile, and CRC-8.
///
/// # Arguments
/// * `data`: A byte slice containing the IR packet data, starting from the type octet.
///
/// # Returns
/// A `Result` containing the parsed `RohcIrProfile1Packet` or a `RohcParsingError`.
/// The `cid` field in the returned struct will be 0 by default; the caller should
/// update it if an Add-CID octet was present.
pub fn parse_ir_profile1_packet(data: &[u8]) -> Result<RohcIrProfile1Packet, RohcParsingError> {
    // This parser assumes Add-CID octet is handled by the main decompressor dispatch logic.
    // The `cid` in RohcIrProfile1Packet will be set by the dispatcher.
    let mut current_offset = 0;

    if data.is_empty() {
        return Err(RohcParsingError::NotEnoughData { needed: 1, got: 0 });
    }
    let packet_type_octet = data[current_offset];
    if (packet_type_octet & !ROHC_IR_PACKET_TYPE_D_BIT_MASK) != ROHC_IR_PACKET_TYPE_BASE {
        return Err(RohcParsingError::InvalidPacketType(packet_type_octet));
    }
    let d_bit_is_set =
        (packet_type_octet & ROHC_IR_PACKET_TYPE_D_BIT_MASK) == ROHC_IR_PACKET_TYPE_D_BIT_MASK;
    current_offset += 1;

    if current_offset >= data.len() {
        return Err(RohcParsingError::NotEnoughData {
            needed: current_offset + 1, // Need Profile ID
            got: data.len(),
        });
    }
    let profile_octet_value = data[current_offset]; // This is also the first byte of CRC payload
    if profile_octet_value != PROFILE_ID_RTP_UDP_IP {
        return Err(RohcParsingError::InvalidProfileId(profile_octet_value));
    }
    // current_offset now points to the start of the static chain within the CRC payload.
    // (Profile octet is data[current_offset], static chain starts at data[current_offset + 1])

    // Static chain for Profile 1: IP_Src(4) + IP_Dst(4) + UDP_Src(2) + UDP_Dst(2) + RTP_SSRC(4) = 16 bytes
    const STATIC_CHAIN_LENGTH: usize = 16;
    // Dynamic chain for Profile 1 (if D-bit set): SN(2) + TS(4) + Flags(1) = 7 bytes
    const DYNAMIC_CHAIN_LENGTH: usize = if ROHC_IR_PACKET_TYPE_WITH_DYN
        == (ROHC_IR_PACKET_TYPE_BASE | ROHC_IR_PACKET_TYPE_D_BIT_MASK)
    {
        7
    } else {
        0
    };

    let crc_payload_start_offset = current_offset;
    let crc_payload_length = 1
        + STATIC_CHAIN_LENGTH
        + (if d_bit_is_set {
            DYNAMIC_CHAIN_LENGTH
        } else {
            0
        });

    let crc_octet_offset = crc_payload_start_offset + crc_payload_length;

    if data.len() < crc_octet_offset + 1 {
        // Need 1 byte for CRC itself
        return Err(RohcParsingError::NotEnoughData {
            needed: crc_octet_offset + 1,
            got: data.len(),
        });
    }

    let crc_payload_slice = &data[crc_payload_start_offset..crc_octet_offset];
    let received_crc8_value = data[crc_octet_offset];
    let calculated_crc8_value = calculate_rohc_crc8(crc_payload_slice);

    if received_crc8_value != calculated_crc8_value {
        return Err(RohcParsingError::CrcMismatch {
            expected: received_crc8_value,
            calculated: calculated_crc8_value,
        });
    }

    current_offset += 1; // Move past Profile ID to start of static chain
    let static_ip_src_addr = Ipv4Addr::new(
        data[current_offset],
        data[current_offset + 1],
        data[current_offset + 2],
        data[current_offset + 3],
    );
    current_offset += 4;
    let static_ip_dst_addr = Ipv4Addr::new(
        data[current_offset],
        data[current_offset + 1],
        data[current_offset + 2],
        data[current_offset + 3],
    );
    current_offset += 4;
    let static_udp_src_port_val =
        u16::from_be_bytes([data[current_offset], data[current_offset + 1]]);
    current_offset += 2;
    let static_udp_dst_port_val =
        u16::from_be_bytes([data[current_offset], data[current_offset + 1]]);
    current_offset += 2;
    let static_rtp_ssrc_val = u32::from_be_bytes([
        data[current_offset],
        data[current_offset + 1],
        data[current_offset + 2],
        data[current_offset + 3],
    ]);
    current_offset += 4; // End of static chain

    let (dyn_rtp_sn_val, dyn_rtp_ts_val, dyn_rtp_marker_val) = if d_bit_is_set {
        // Bounds check already implicitly done by overall length check for CRC
        let sn = u16::from_be_bytes([data[current_offset], data[current_offset + 1]]);
        current_offset += 2;
        let ts = u32::from_be_bytes([
            data[current_offset],
            data[current_offset + 1],
            data[current_offset + 2],
            data[current_offset + 3],
        ]);
        let rtp_flags_octet = data[current_offset + 4]; // Flags octet
        let marker = (rtp_flags_octet & 0x80) == 0x80; // M-bit is MSB
        (sn, ts, marker)
    } else {
        // IR packet without dynamic chain (D-bit = 0)
        (0, 0, false) // Default values if no dynamic chain
    };

    Ok(RohcIrProfile1Packet {
        cid: 0, // Caller (dispatcher) should set this based on Add-CID or implicit context
        profile: profile_octet_value,
        crc8: received_crc8_value,
        static_ip_src: static_ip_src_addr,
        static_ip_dst: static_ip_dst_addr,
        static_udp_src_port: static_udp_src_port_val,
        static_udp_dst_port: static_udp_dst_port_val,
        static_rtp_ssrc: static_rtp_ssrc_val,
        dyn_rtp_sn: dyn_rtp_sn_val,
        dyn_rtp_timestamp: dyn_rtp_ts_val,
        dyn_rtp_marker: dyn_rtp_marker_val,
    })
}

/// Parses a ROHC UO-0 packet for Profile 1, assuming CID 0 (1-octet version).
///
/// The `data` slice should contain exactly the 1-byte UO-0 packet.
/// The first bit of this byte must be 0 to be a valid UO-0 for CID 0.
///
/// # Arguments
/// * `data`: A byte slice containing the 1-byte UO-0 packet.
///
/// # Returns
/// A `Result` containing the parsed `RohcUo0PacketProfile1` or a `RohcParsingError`.
/// The `cid` field in the returned struct will be `None`, indicating implicit CID 0.
pub fn parse_uo0_profile1_cid0_packet(
    data: &[u8],
) -> Result<RohcUo0PacketProfile1, RohcParsingError> {
    if data.is_empty() {
        return Err(RohcParsingError::NotEnoughData { needed: 1, got: 0 });
    }
    if data.len() > 1 {
        // This parser is specifically for the 1-octet UO-0 for CID 0.
        // If Add-CID was present, it should have been stripped by the caller.
        return Err(RohcParsingError::InvalidFieldValue {
            field_name: "UO-0 Packet (CID 0)".to_string(),
            description: format!("expected 1 byte, got {}", data.len()),
        });
    }

    let packet_byte = data[0];
    // For UO-0 CID 0, the packet type starts with a 0 bit.
    if (packet_byte & 0x80) != 0 {
        // MSB must be 0
        return Err(RohcParsingError::InvalidPacketType(packet_byte));
    }
    // Format: 0 SSS S CPreferenceKey (0 + 4 bits SN LSB + 3 bits CRC LSB)
    let sn_lsb_val = (packet_byte >> 3) & 0x0F; // Extract bits 6-3 (0-indexed)
    let crc3_val = packet_byte & 0x07; // Extract bits 2-0

    Ok(RohcUo0PacketProfile1 {
        cid: None,
        sn_lsb: sn_lsb_val,
        crc3: crc3_val,
    })
}

/// Builds a ROHC UO-1-SN packet for Profile 1.
///
/// This variant of UO-1 carries 8 LSBs of the RTP Sequence Number and the RTP Marker bit,
/// along with an 8-bit CRC.
///
/// # Arguments
/// * `sn_8_lsb`: The 8 least significant bits of the RTP Sequence Number.
/// * `marker_bit_value`: The value of the RTP Marker bit to be encoded.
/// * `crc8_value`: The pre-calculated 8-bit CRC over the (reconstructed) original header.
///
/// # Returns
/// A `Result` containing the 3-byte UO-1-SN packet as `Vec<u8>`, or a `RohcBuildingError`.
pub fn build_uo1_sn_profile1_packet(
    sn_8_lsb: u8,
    marker_bit_value: bool,
    crc8_value: u8,
) -> Result<Vec<u8>, RohcBuildingError> {
    // Type octet for UO-1-SN: `1010...M`
    // The lower 4 bits are for other UO-1 extensions, 0000 for basic SN.
    // The LSB (bit 0) is the Marker bit.
    let type_octet = UO_1_SN_P1_PACKET_TYPE_BASE
        | (if marker_bit_value {
            UO_1_SN_P1_MARKER_BIT_MASK
        } else {
            0
        });

    Ok(vec![type_octet, sn_8_lsb, crc8_value])
}

/// Parses a ROHC UO-1-SN packet for Profile 1.
///
/// This function expects the `data` slice to start with the ROHC UO-1-SN packet type octet
/// (i.e., after any Add-CID octet has been processed). It extracts the SN LSBs,
/// marker bit, and the received CRC-8. CRC verification itself is done by the decompressor
/// logic using the context.
///
/// # Arguments
/// * `data`: A byte slice containing the UO-1-SN packet data (typically 3 bytes).
///
/// # Returns
/// A `Result` containing the parsed `RohcUo1PacketProfile1` or a `RohcParsingError`.
pub fn parse_uo1_sn_profile1_packet(
    data: &[u8],
) -> Result<RohcUo1PacketProfile1, RohcParsingError> {
    if data.len() < 3 {
        // UO-1-SN is 3 bytes: Type, SN_LSB, CRC8
        return Err(RohcParsingError::NotEnoughData {
            needed: 3,
            got: data.len(),
        });
    }

    let type_octet = data[0];
    // Check prefix `1010` for UO-1-SN family.
    if (type_octet & 0xF0) != UO_1_SN_P1_PACKET_TYPE_BASE {
        return Err(RohcParsingError::InvalidPacketType(type_octet));
    }

    // Lower 4 bits of type_octet might be for other UO-1 extensions,
    // for UO-1-SN these are typically 0, except for the marker bit.
    let marker_bit_is_set = (type_octet & UO_1_SN_P1_MARKER_BIT_MASK) != 0;
    let sn_lsb_8_bits_val = data[1];
    let received_crc8_val = data[2];

    Ok(RohcUo1PacketProfile1 {
        sn_lsb: sn_lsb_8_bits_val as u16,
        num_sn_lsb_bits: 8,
        rtp_marker_bit_value: Some(marker_bit_is_set),
        crc8: received_crc8_val,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn parse_basic_rtp_udp_ipv4_packet() {
        // Construct a sample packet byte array
        let mut ip_header_bytes: [u8; IPV4_MIN_HEADER_LENGTH_BYTES] =
            [0; IPV4_MIN_HEADER_LENGTH_BYTES];
        ip_header_bytes[0] = 0x45; // Version 4, IHL 5
        ip_header_bytes[1] = 0x00; // DSCP, ECN
        ip_header_bytes[2..4].copy_from_slice(
            &((IPV4_MIN_HEADER_LENGTH_BYTES + UDP_HEADER_LENGTH_BYTES + RTP_MIN_HEADER_LENGTH_BYTES) as u16)
                .to_be_bytes(), // Total Length
        );
        ip_header_bytes[8] = 64; // TTL
        ip_header_bytes[9] = IP_PROTOCOL_UDP; // Protocol UDP
        ip_header_bytes[12..16].copy_from_slice(&[192, 168, 1, 1]); // Src IP
        ip_header_bytes[16..20].copy_from_slice(&[192, 168, 1, 2]); // Dst IP

        let mut udp_header_bytes: [u8; UDP_HEADER_LENGTH_BYTES] = [0; UDP_HEADER_LENGTH_BYTES];
        udp_header_bytes[0..2].copy_from_slice(&12345u16.to_be_bytes()); // Src Port
        udp_header_bytes[2..4].copy_from_slice(&54321u16.to_be_bytes()); // Dst Port
        udp_header_bytes[4..6].copy_from_slice(
            &((UDP_HEADER_LENGTH_BYTES + RTP_MIN_HEADER_LENGTH_BYTES) as u16).to_be_bytes(), // UDP Length
        );

        let mut rtp_header_bytes: [u8; RTP_MIN_HEADER_LENGTH_BYTES] =
            [0; RTP_MIN_HEADER_LENGTH_BYTES];
        rtp_header_bytes[0] = 0x80; // Version 2, P=0, X=0, CC=0
        rtp_header_bytes[1] = 0x60; // M=0, Payload Type 96 (example)
        rtp_header_bytes[2..4].copy_from_slice(&1001u16.to_be_bytes()); // Seq Num
        rtp_header_bytes[4..8].copy_from_slice(&3000u32.to_be_bytes()); // Timestamp
        rtp_header_bytes[8..12].copy_from_slice(&0x12345678u32.to_be_bytes()); // SSRC

        let mut full_packet_bytes = Vec::new();
        full_packet_bytes.extend_from_slice(&ip_header_bytes);
        full_packet_bytes.extend_from_slice(&udp_header_bytes);
        full_packet_bytes.extend_from_slice(&rtp_header_bytes);

        let parsed_headers = parse_rtp_udp_ipv4(&full_packet_bytes).unwrap();
        assert_eq!(parsed_headers.ip_src, Ipv4Addr::new(192, 168, 1, 1));
        assert_eq!(parsed_headers.udp_dst_port, 54321);
        assert_eq!(parsed_headers.rtp_ssrc, 0x12345678);
        assert_eq!(parsed_headers.rtp_sequence_number, 1001);
        assert!(!parsed_headers.rtp_marker); // M=0 in rtp_header_bytes[1]
        assert_eq!(parsed_headers.rtp_payload_type, 96);
    }

    #[test]
    fn build_and_parse_ir_profile1_for_cid0() {
        let ir_data_content = RohcIrProfile1Packet {
            cid: 0,
            profile: PROFILE_ID_RTP_UDP_IP,
            static_ip_src: Ipv4Addr::new(1, 2, 3, 4),
            static_ip_dst: Ipv4Addr::new(5, 6, 7, 8),
            static_udp_src_port: 1000,
            static_udp_dst_port: 2000,
            static_rtp_ssrc: 0xABCDEFFF,
            dyn_rtp_sn: 12345,
            dyn_rtp_timestamp: 543210,
            dyn_rtp_marker: true,
            ..Default::default()
        };

        let built_packet_bytes = build_ir_profile1_packet(&ir_data_content).unwrap();

        // Expected length for CID 0 IR: Type(1) + Profile(1) + Static(16) + Dynamic(7) + CRC(1) = 26
        let expected_length = 1 + 1 + 16 + 7 + 1;
        assert_eq!(built_packet_bytes.len(), expected_length);
        assert_eq!(built_packet_bytes[0], ROHC_IR_PACKET_TYPE_WITH_DYN); // Type octet
        assert_eq!(built_packet_bytes[1], PROFILE_ID_RTP_UDP_IP); // Profile octet

        // Parse, assuming Add-CID was handled (none for CID 0)
        let parsed_packet_data = parse_ir_profile1_packet(&built_packet_bytes).unwrap();
        // `parsed_packet_data.cid` will be 0 as parser doesn't infer from lack of Add-CID.
        // Dispatcher would set it. For this test, compare content against ir_data_content.
        assert_eq!(parsed_packet_data.profile, ir_data_content.profile);
        assert_eq!(
            parsed_packet_data.static_ip_src,
            ir_data_content.static_ip_src
        );
        assert_eq!(parsed_packet_data.dyn_rtp_sn, ir_data_content.dyn_rtp_sn);
        assert_eq!(
            parsed_packet_data.dyn_rtp_marker,
            ir_data_content.dyn_rtp_marker
        );
        assert_eq!(parsed_packet_data.crc8, *built_packet_bytes.last().unwrap());
    }

    #[test]
    fn build_and_parse_ir_profile1_for_small_cid() {
        let cid_value = 7u16;
        let ir_data_content = RohcIrProfile1Packet {
            cid: cid_value,
            profile: PROFILE_ID_RTP_UDP_IP,
            static_ip_src: Ipv4Addr::new(10, 0, 0, 1),
            static_ip_dst: Ipv4Addr::new(10, 0, 0, 2),
            ..Default::default()
        };

        let built_packet_bytes = build_ir_profile1_packet(&ir_data_content).unwrap();
        // Expected length for small CID IR: AddCID(1) + Type(1) + Profile(1) + Static(16) + Dynamic(7) + CRC(1) = 27
        let expected_length_with_add_cid = 1 + 1 + 1 + 16 + 7 + 1;
        assert_eq!(built_packet_bytes.len(), expected_length_with_add_cid);
        assert_eq!(
            built_packet_bytes[0],
            ADD_CID_OCTET_PREFIX_VALUE | (cid_value as u8)
        ); // Add-CID
        assert_eq!(built_packet_bytes[1], ROHC_IR_PACKET_TYPE_WITH_DYN); // Type
        assert_eq!(built_packet_bytes[2], PROFILE_ID_RTP_UDP_IP); // Profile

        // To parse, strip the Add-CID octet first as parse_ir_profile1_packet expects to start at Type
        let core_ir_packet_slice = &built_packet_bytes[1..];
        let parsed_packet_data = parse_ir_profile1_packet(core_ir_packet_slice).unwrap();
        // The CID in parsed_packet_data will be 0 as it's not derived by this specific parser.
        // The dispatcher is responsible for associating the CID from Add-CID with the context.
        assert_eq!(parsed_packet_data.profile, ir_data_content.profile);
        assert_eq!(
            parsed_packet_data.static_ip_src,
            ir_data_content.static_ip_src
        );
    }

    #[test]
    fn parse_ir_packet_handles_crc_error() {
        let ir_data_content = RohcIrProfile1Packet {
            cid: 0,
            profile: PROFILE_ID_RTP_UDP_IP,
            ..Default::default()
        };
        let mut built_packet_bytes = build_ir_profile1_packet(&ir_data_content).unwrap();

        // Corrupt the CRC
        if !built_packet_bytes.is_empty() {
            let crc_index = built_packet_bytes.len() - 1;
            built_packet_bytes[crc_index] = built_packet_bytes[crc_index].wrapping_add(1);
        } else {
            panic!("Built IR packet is empty, cannot corrupt CRC for test.");
        }

        match parse_ir_profile1_packet(&built_packet_bytes) {
            Err(RohcParsingError::CrcMismatch { .. }) => { /* Expected */ }
            Ok(p) => panic!("Expected CrcMismatch error, but got Ok({:?})", p),
            Err(e) => panic!("Expected CrcMismatch error, but got other error: {:?}", e),
        }
    }

    #[test]
    fn build_and_parse_uo0_cid0_packet_valid() {
        let sn_lsb_val: u8 = 0b1010; // Example 4-bit SN LSB
        let crc3_val: u8 = 0b101; // Example 3-bit CRC

        let built_packet_bytes = build_uo0_profile1_cid0_packet(sn_lsb_val, crc3_val).unwrap();
        assert_eq!(built_packet_bytes.len(), 1);
        // Expected byte: 0b0 (UO-0 type bit) + 1010 (SN) + 101 (CRC) = 0b01010101 = 0x55
        assert_eq!(built_packet_bytes[0], (sn_lsb_val << 3) | crc3_val);
        assert_eq!(built_packet_bytes[0], 0x55);

        let parsed_packet_data = parse_uo0_profile1_cid0_packet(&built_packet_bytes).unwrap();
        assert_eq!(
            parsed_packet_data.cid, None,
            "CID should be None for implicit CID 0 UO-0"
        );
        assert_eq!(parsed_packet_data.sn_lsb, sn_lsb_val);
        assert_eq!(parsed_packet_data.crc3, crc3_val);
    }

    #[test]
    fn parse_uo0_cid0_packet_invalid_type_bit() {
        // UO-0 for CID 0 must have MSB=0. If MSB=1, it's not this packet type.
        match parse_uo0_profile1_cid0_packet(&[0x80]) {
            // MSB is 1
            Err(RohcParsingError::InvalidPacketType(0x80)) => { /* Expected */ }
            res => panic!(
                "Expected InvalidPacketType for UO-0 with MSB=1, got {:?}",
                res
            ),
        }
    }

    #[test]
    fn parse_uo0_cid0_packet_too_long() {
        match parse_uo0_profile1_cid0_packet(&[0x55, 0x00]) {
            // 2 bytes, expected 1
            Err(RohcParsingError::InvalidFieldValue { field_name, .. })
                if field_name == "UO-0 Packet (CID 0)" =>
            { /* Expected */ }
            res => panic!(
                "Expected InvalidFieldValue for oversized UO-0, got {:?}",
                res
            ),
        }
    }

    #[test]
    fn build_and_parse_uo1_sn_packet_valid() {
        let sn_8_lsb_val: u8 = 0xAB;
        let marker_val = true;
        let crc8_val: u8 = 0xCD; // Example CRC

        let built_packet_bytes =
            build_uo1_sn_profile1_packet(sn_8_lsb_val, marker_val, crc8_val).unwrap();
        assert_eq!(built_packet_bytes.len(), 3);
        // Expected type octet: UO_1_SN_PACKET_TYPE_BASE (10100000) | UO_1_SN_MARKER_BIT_MASK (00000001) = 10100001
        assert_eq!(
            built_packet_bytes[0],
            UO_1_SN_P1_PACKET_TYPE_BASE | UO_1_SN_P1_MARKER_BIT_MASK
        );
        assert_eq!(built_packet_bytes[1], sn_8_lsb_val);
        assert_eq!(built_packet_bytes[2], crc8_val);

        // Parse, assuming Add-CID was handled (none for this direct parse test)
        let parsed_packet_data = parse_uo1_sn_profile1_packet(&built_packet_bytes).unwrap();
        assert_eq!(parsed_packet_data.sn_lsb, sn_8_lsb_val as u16);
        assert_eq!(parsed_packet_data.num_sn_lsb_bits, 8);
        assert_eq!(parsed_packet_data.rtp_marker_bit_value, Some(marker_val));
        assert_eq!(parsed_packet_data.crc8, crc8_val);
    }

    #[test]
    fn parse_uo1_sn_packet_invalid_type_prefix() {
        // Type octet 0b11000001 does not start with 1010...
        match parse_uo1_sn_profile1_packet(&[0xC1, 0xAB, 0xCD]) {
            Err(RohcParsingError::InvalidPacketType(0xC1)) => { /* Expected */ }
            res => panic!(
                "Expected InvalidPacketType for wrong UO-1 prefix, got {:?}",
                res
            ),
        }
    }

    #[test]
    fn parse_uo1_sn_packet_too_short() {
        match parse_uo1_sn_profile1_packet(&[0xA1, 0xAB]) {
            // Only 2 bytes, needs 3
            Err(RohcParsingError::NotEnoughData { needed, got }) => {
                assert_eq!(needed, 3);
                assert_eq!(got, 2);
            }
            res => panic!("Expected NotEnoughData for short UO-1, got {:?}", res),
        }
    }
}
