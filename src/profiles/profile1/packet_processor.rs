//! ROHC (Robust Header Compression) Profile 1 specific packet parsing and building functions.
//!
//! This module provides the low-level utilities to:
//! 1. Parse raw byte arrays representing ROHC Profile 1 packets (IR, UO-0, UO-1-SN)
//!    into their corresponding structured Rust types (`IrPacket`, `Uo0Packet`, `Uo1Packet`).
//! 2. Build raw byte arrays (for transmission) from these Profile 1 packet structs.
//! 3. Parse uncompressed RTP/UDP/IPv4 headers from a raw byte stream into the
//!    `RtpUdpIpv4Headers` struct.

use std::net::Ipv4Addr;

use super::constants::*;
use super::packet_types::{IrPacket, Uo0Packet, Uo1Packet};
use super::protocol_types::RtpUdpIpv4Headers;
use crate::constants::{
    IP_PROTOCOL_UDP, IPV4_MIN_HEADER_LENGTH_BYTES, IPV4_STANDARD_IHL,
    ROHC_ADD_CID_FEEDBACK_PREFIX_VALUE, ROHC_SMALL_CID_MASK, RTP_MIN_HEADER_LENGTH_BYTES,
    RTP_VERSION, UDP_HEADER_LENGTH_BYTES,
};
use crate::crc::calculate_rohc_crc8;
use crate::error::{RohcBuildingError, RohcParsingError};
use crate::packet_defs::RohcProfile;

/// Parses raw bytes representing an RTP/UDP/IPv4 packet into `RtpUdpIpv4Headers`.
///
/// This function assumes the input `data` starts with the IPv4 header. It performs
/// basic validation of header lengths and protocol types.
///
/// # Parameters
/// - `data`: A byte slice starting with the IPv4 header.
///
/// # Returns
/// A `Result` containing the parsed `RtpUdpIpv4Headers` or a `RohcParsingError`.
pub fn parse_rtp_udp_ipv4_headers(data: &[u8]) -> Result<RtpUdpIpv4Headers, RohcParsingError> {
    if data.len() < IPV4_MIN_HEADER_LENGTH_BYTES {
        return Err(RohcParsingError::NotEnoughData {
            needed: IPV4_MIN_HEADER_LENGTH_BYTES,
            got: data.len(),
            context: "IPv4 header (minimum)".to_string(),
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
            field_name: "IPv4 IHL".to_string(),
            structure_name: "IPv4 Header".to_string(),
            description: format!(
                "Must be at least {} words, got {}.",
                IPV4_STANDARD_IHL, ip_ihl_words
            ),
        });
    }
    let ip_header_length_bytes = (ip_ihl_words * 4) as usize;
    if data.len() < ip_header_length_bytes {
        return Err(RohcParsingError::NotEnoughData {
            needed: ip_header_length_bytes,
            got: data.len(),
            context: "IPv4 header (calculated IHL)".to_string(),
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
            layer: "IP".to_string(),
        });
    }
    let ip_checksum = u16::from_be_bytes([data[10], data[11]]);
    let ip_src_addr = Ipv4Addr::new(data[12], data[13], data[14], data[15]);
    let ip_dst_addr = Ipv4Addr::new(data[16], data[17], data[18], data[19]);
    // Ignoring IP options for simplicity as ROHC P1 typically doesn't handle varying options.

    let udp_start_offset = ip_header_length_bytes;
    if data.len() < udp_start_offset + UDP_HEADER_LENGTH_BYTES {
        return Err(RohcParsingError::NotEnoughData {
            needed: udp_start_offset + UDP_HEADER_LENGTH_BYTES,
            got: data.len(),
            context: "UDP header".to_string(),
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
            context: "RTP header (minimum)".to_string(),
        });
    }
    let rtp_first_byte = data[rtp_start_offset];
    let rtp_version_val = rtp_first_byte >> 6;
    if rtp_version_val != RTP_VERSION {
        return Err(RohcParsingError::InvalidFieldValue {
            field_name: "RTP Version".to_string(),
            structure_name: "RTP Header".to_string(),
            description: format!("Expected {}, got {}.", RTP_VERSION, rtp_version_val),
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
    for _i in 0..rtp_csrc_count_val {
        if data.len() < current_csrc_offset + 4 {
            return Err(RohcParsingError::NotEnoughData {
                needed: current_csrc_offset + 4,
                got: data.len(),
                context: format!("RTP CSRC list item {}", _i + 1),
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

    // Basic validation for CSRC count
    // This case should ideally be caught by NotEnoughData if list is short,
    // but good as a sanity check.
    if rtp_csrc_count_val as usize != rtp_csrc_list_val.len() {
        return Err(RohcParsingError::InvalidFieldValue {
            field_name: "RTP CSRC Count".to_string(),
            structure_name: "RTP Header".to_string(),
            description: "Mismatch between CSRC count field and actual CSRC data present."
                .to_string(),
        });
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

/// Builds a ROHC Profile 1 IR (Initialization/Refresh) packet.
///
/// This function constructs the byte representation of an IR or IR-DYN packet.
/// It includes an Add-CID octet if the CID is small and non-zero.
/// The CRC-8 is calculated over the profile, static chain, and dynamic chain (if present).
///
/// # Parameters
/// - `ir_data`: A reference to `IrPacket` containing all necessary field values.
///
/// # Returns
/// A `Result` containing the built IR packet as `Vec<u8>`, or a `RohcBuildingError`.
pub fn build_profile1_ir_packet(ir_data: &IrPacket) -> Result<Vec<u8>, RohcBuildingError> {
    // Max estimated size: Add-CID (1) + Type (1) + Profile (1) + Static (16) + Dynamic (7) + CRC (1) = 27
    let mut final_packet = Vec::with_capacity(27);
    let mut crc_payload =
        Vec::with_capacity(1 + P1_STATIC_CHAIN_LENGTH_BYTES + P1_DYNAMIC_CHAIN_LENGTH_BYTES);

    // 1. Add-CID Octet (Optional)
    if ir_data.cid > 0 && ir_data.cid <= 15 {
        final_packet
            .push(ROHC_ADD_CID_FEEDBACK_PREFIX_VALUE | (ir_data.cid as u8 & ROHC_SMALL_CID_MASK));
    } else if ir_data.cid > 15 {
        // ROHC supports larger CIDs, but they require a 2-byte encoding after Add-CID prefix,
        // or are sent in IR-DYN packets without Add-CID if CID > 0 and fits in large CID encoding.
        // This builder currently only supports small CIDs (1-15) with Add-CID, or CID 0 implicitly.
        return Err(RohcBuildingError::InvalidFieldValueForBuild {
            field_name: "CID".to_string(),
            description: format!(
                "Large CID {} for IR packet Add-CID not supported by this simple builder.",
                ir_data.cid
            ),
        });
    }
    // For CID 0, no Add-CID octet is prepended.

    // 2. ROHC Packet Type Octet (Always IR-DYN for this P1 MVP)
    // P1_ROHC_IR_PACKET_TYPE_WITH_DYN implies D-bit is 1.
    final_packet.push(P1_ROHC_IR_PACKET_TYPE_WITH_DYN);

    // 3. Profile Identifier (Start of CRC payload)
    let profile_u8: u8 = ir_data.profile.into();
    if profile_u8 != u8::from(RohcProfile::RtpUdpIp) {
        // Compare with actual P1 ID
        return Err(RohcBuildingError::InvalidFieldValueForBuild {
            field_name: "Profile ID".to_string(),
            description: format!(
                "IR packet is for ROHC Profile 1 (0x{:02X}), but got 0x{:02X}.",
                u8::from(RohcProfile::RtpUdpIp),
                profile_u8
            ),
        });
    }
    final_packet.push(profile_u8);
    crc_payload.push(profile_u8);

    // 4. Static Chain (Part of CRC payload)
    crc_payload.extend_from_slice(&ir_data.static_ip_src.octets());
    crc_payload.extend_from_slice(&ir_data.static_ip_dst.octets());
    crc_payload.extend_from_slice(&ir_data.static_udp_src_port.to_be_bytes());
    crc_payload.extend_from_slice(&ir_data.static_udp_dst_port.to_be_bytes());
    crc_payload.extend_from_slice(&ir_data.static_rtp_ssrc.to_be_bytes());

    // 5. Dynamic Chain (Part of CRC payload, as D-bit is assumed 1)
    crc_payload.extend_from_slice(&ir_data.dyn_rtp_sn.to_be_bytes());
    crc_payload.extend_from_slice(&ir_data.dyn_rtp_timestamp.to_be_bytes());
    // RTP flags octet for Profile 1 IR-DYN: M-bit is MSB, other bits reserved (0).
    crc_payload.push(if ir_data.dyn_rtp_marker { 0x80 } else { 0x00 });

    // 6. Calculate CRC-8 over (Profile + Static Chain + Dynamic Chain)
    let calculated_crc8 = calculate_rohc_crc8(&crc_payload);

    // Append the chain part of crc_payload (Static + Dynamic) to final_packet
    // crc_payload[0] was Profile ID, which is already in final_packet.
    final_packet.extend_from_slice(&crc_payload[1..]);

    // 7. Append CRC-8
    final_packet.push(calculated_crc8);

    Ok(final_packet)
}

/// Parses a ROHC Profile 1 IR (Initialization/Refresh) packet.
///
/// The input `data` should be the core IR packet content, starting with the
/// ROHC packet type octet (i.e., after any Add-CID octet has been processed by the engine).
/// The `cid_from_engine` should be provided by the caller (ROHC engine) which
/// determined it from the Add-CID octet or implicit rules (e.g., CID 0).
///
/// # Parameters
/// - `data`: Byte slice of the core IR packet.
/// - `cid_from_engine`: The CID determined by the ROHC engine.
///
/// # Returns
/// A `Result` containing the parsed `IrPacket` or a `RohcParsingError`.
pub fn parse_profile1_ir_packet(
    data: &[u8],
    cid_from_engine: u16,
) -> Result<IrPacket, RohcParsingError> {
    let mut offset = 0;

    if data.is_empty() {
        return Err(RohcParsingError::NotEnoughData {
            needed: 1,
            got: 0,
            context: "IR Packet Type".to_string(),
        });
    }
    let packet_type_octet = data[offset];
    offset += 1;

    // Check if it's an IR packet (static or dynamic) for Profile 1
    if (packet_type_octet & !P1_ROHC_IR_PACKET_TYPE_D_BIT_MASK) != P1_ROHC_IR_PACKET_TYPE_BASE {
        return Err(RohcParsingError::InvalidPacketType {
            discriminator: packet_type_octet,
            profile_id: Some(RohcProfile::RtpUdpIp.into()),
        });
    }
    let d_bit_is_set = (packet_type_octet & P1_ROHC_IR_PACKET_TYPE_D_BIT_MASK) != 0;

    let expected_chain_length = P1_STATIC_CHAIN_LENGTH_BYTES
        + if d_bit_is_set {
            P1_DYNAMIC_CHAIN_LENGTH_BYTES
        } else {
            0
        };
    let expected_crc_payload_length = 1 + expected_chain_length;
    let expected_total_core_packet_length = offset + expected_crc_payload_length; // Type + Profile + Chains + CRC

    if data.len() < expected_total_core_packet_length {
        return Err(RohcParsingError::NotEnoughData {
            needed: expected_total_core_packet_length,
            got: data.len(),
            context: "IR Packet core (Type + Profile + Chains + CRC)".to_string(),
        });
    }

    let profile_octet = data[offset];
    if profile_octet != u8::from(RohcProfile::RtpUdpIp) {
        return Err(RohcParsingError::InvalidProfileId(profile_octet));
    }

    let crc_payload_slice = &data[offset..offset + expected_crc_payload_length];
    let received_crc8 = data[offset + expected_crc_payload_length];
    let calculated_crc8 = calculate_rohc_crc8(crc_payload_slice);

    if received_crc8 != calculated_crc8 {
        return Err(RohcParsingError::CrcMismatch {
            expected: received_crc8,
            calculated: calculated_crc8,
            crc_type: "ROHC-CRC8".to_string(),
        });
    }
    offset += 1;

    let static_ip_src = Ipv4Addr::new(
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    );
    offset += 4;
    let static_ip_dst = Ipv4Addr::new(
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    );
    offset += 4;
    let static_udp_src_port = u16::from_be_bytes([data[offset], data[offset + 1]]);
    offset += 2;
    let static_udp_dst_port = u16::from_be_bytes([data[offset], data[offset + 1]]);
    offset += 2;
    let static_rtp_ssrc = u32::from_be_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ]);
    offset += 4;

    let (dyn_rtp_sn, dyn_rtp_timestamp, dyn_rtp_marker) = if d_bit_is_set {
        // Bounds check for dynamic chain was implicitly part of overall length check
        let sn = u16::from_be_bytes([data[offset], data[offset + 1]]);
        offset += 2;
        let ts = u32::from_be_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
        ]);
        offset += 4;
        let rtp_flags_octet = data[offset];
        let marker = (rtp_flags_octet & 0x80) == 0x80;
        (sn, ts, marker)
    } else {
        // IR packet without dynamic chain (D-bit = 0).
        (0, 0, false)
    };

    Ok(IrPacket {
        cid: cid_from_engine, // Use CID determined by the engine
        profile: RohcProfile::from(profile_octet),
        crc8: received_crc8,
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

/// Builds a ROHC Profile 1 UO-0 packet.
///
/// For CID 0, this is a 1-byte packet: `0SSSSCCC` (SN LSBs + CRC3 LSBs).
/// For small CIDs (1-15), an Add-CID octet is prepended.
///
/// # Parameters
/// - `packet_data`: A reference to `Uo0Packet` containing the SN LSBs, CRC3, and optional CID.
///
/// # Returns
/// A `Result` containing the built UO-0 packet as `Vec<u8>`, or a `RohcBuildingError`.
pub fn build_profile1_uo0_packet(packet_data: &Uo0Packet) -> Result<Vec<u8>, RohcBuildingError> {
    if packet_data.sn_lsb >= (1 << P1_UO0_SN_LSB_WIDTH_DEFAULT) {
        // e.g., > 15 if width is 4
        return Err(RohcBuildingError::InvalidFieldValueForBuild {
            field_name: "sn_lsb".to_string(),
            description: format!(
                "Value {} exceeds {} -bit representation for UO-0 SN.",
                packet_data.sn_lsb, P1_UO0_SN_LSB_WIDTH_DEFAULT
            ),
        });
    }
    if packet_data.crc3 > 0x07 {
        return Err(RohcBuildingError::InvalidFieldValueForBuild {
            field_name: "crc3".to_string(),
            description: "Value exceeds 3-bit representation for CRC3.".to_string(),
        });
    }

    let mut final_packet = Vec::with_capacity(2); // Add-CID + UO-0

    if let Some(cid_val) = packet_data.cid {
        if cid_val > 0 && cid_val <= 15 {
            final_packet.push(ROHC_ADD_CID_FEEDBACK_PREFIX_VALUE | (cid_val & ROHC_SMALL_CID_MASK));
        } else {
            return Err(RohcBuildingError::InvalidFieldValueForBuild {
                field_name: "cid".to_string(),
                description: format!("Invalid CID {} for UO-0 Add-CID encoding.", cid_val),
            });
        }
    }

    // RFC 3095, Section 5.7.4: `0 | SN (4 bits) | CRC-3 (3 bits)`
    // Shift SN to align before CRC3.
    let core_byte = (packet_data.sn_lsb << 3) | packet_data.crc3;
    final_packet.push(core_byte);

    Ok(final_packet)
}

/// Parses a ROHC Profile 1 UO-0 packet.
///
/// Assumes `data` is the 1-byte core UO-0 packet (after Add-CID processing).
/// The `cid_from_engine` is the CID determined by the engine.
///
/// # Parameters
/// - `data`: 1-byte slice for the core UO-0 packet.
/// - `cid_from_engine`: Optional small CID (1-15) if Add-CID was present, else None for CID 0.
///
/// # Returns
/// A `Result` containing the parsed `Uo0Packet` or a `RohcParsingError`.
pub fn parse_profile1_uo0_packet(
    data: &[u8],
    cid_from_engine: Option<u8>,
) -> Result<Uo0Packet, RohcParsingError> {
    if data.len() != 1 {
        return Err(RohcParsingError::InvalidFieldValue {
            field_name: "UO-0 Core Packet Length".to_string(),
            structure_name: "UO-0 Packet".to_string(),
            description: format!("Expected 1 byte for core UO-0 packet, got {}.", data.len()),
        });
    }

    // UO-0 packet type always starts with a '0' bit (MSB).
    let packet_byte = data[0];
    if (packet_byte & 0x80) != 0 {
        return Err(RohcParsingError::InvalidPacketType {
            discriminator: packet_byte,
            profile_id: Some(RohcProfile::RtpUdpIp.into()),
        });
    }

    // Format for UO-0 (CID 0): `0 SSSS CCC` (S=SN LSB, C=CRC LSB)
    // SN LSBs are bits 6-3 (0-indexed from MSB, so shift right by 3, then mask)
    let sn_lsb_val = (packet_byte >> 3) & ((1 << P1_UO0_SN_LSB_WIDTH_DEFAULT) - 1);
    // CRC LSBs are bits 2-0
    let crc3_val = packet_byte & 0x07;

    Ok(Uo0Packet {
        cid: cid_from_engine,
        sn_lsb: sn_lsb_val,
        crc3: crc3_val,
    })
}

/// Builds a ROHC Profile 1 UO-1-SN packet.
///
/// This creates the core 3-byte UO-1-SN packet: Type (1) + SN LSB (1) + CRC-8 (1).
/// It does NOT prepend an Add-CID octet; the ROHC engine or handler should do that if needed.
///
/// # Parameters
/// - `packet_data`: A reference to `Uo1Packet` containing SN LSBs, marker, and CRC-8.
///   `num_sn_lsb_bits` must be 8 for this function.
///
/// # Returns
/// A `Result` containing the 3-byte core UO-1-SN packet as `Vec<u8>`, or a `RohcBuildingError`.
pub fn build_profile1_uo1_sn_packet(packet_data: &Uo1Packet) -> Result<Vec<u8>, RohcBuildingError> {
    if packet_data.num_sn_lsb_bits != P1_UO1_SN_LSB_WIDTH_DEFAULT {
        // Typically 8 for P1 UO-1-SN
        return Err(RohcBuildingError::InvalidFieldValueForBuild {
            field_name: "num_sn_lsb_bits".to_string(),
            description: format!(
                "Profile 1 UO-1-SN builder expects {} LSBs for SN, got {}.",
                P1_UO1_SN_LSB_WIDTH_DEFAULT, packet_data.num_sn_lsb_bits
            ),
        });
    }
    if packet_data.sn_lsb > 0xFF {
        // SN LSB must fit in 1 byte
        return Err(RohcBuildingError::InvalidFieldValueForBuild {
            field_name: "sn_lsb".to_string(),
            description: "Value for UO-1-SN LSB exceeds 8-bit representation.".to_string(),
        });
    }
    let marker_bit = packet_data.rtp_marker_bit_value.ok_or_else(|| {
        RohcBuildingError::InvalidFieldValueForBuild {
            field_name: "rtp_marker_bit_value".to_string(),
            description: "UO-1-SN packet requires the RTP marker bit value.".to_string(),
        }
    })?;

    // Type octet for UO-1-SN (Profile 1): `1010000M`
    let type_octet = P1_UO_1_SN_PACKET_TYPE_PREFIX
        | (if marker_bit {
            P1_UO_1_SN_MARKER_BIT_MASK
        } else {
            0
        });

    let core_packet_bytes = vec![type_octet, packet_data.sn_lsb as u8, packet_data.crc8];

    if let Some(cid_val) = packet_data.cid {
        if cid_val > 0 && cid_val <= 15 {
            let mut final_packet = Vec::with_capacity(1 + core_packet_bytes.len());
            final_packet.push(ROHC_ADD_CID_FEEDBACK_PREFIX_VALUE | (cid_val & ROHC_SMALL_CID_MASK));
            final_packet.extend_from_slice(&core_packet_bytes);
            Ok(final_packet)
        } else if cid_val == 0 {
            // CID 0 for UO-1 means no Add-CID
            Ok(core_packet_bytes)
        } else {
            Err(RohcBuildingError::InvalidFieldValueForBuild {
                field_name: "cid".to_string(),
                description: format!(
                    "Invalid CID {} for UO-1 Add-CID encoding; expected 0 or 1-15.",
                    cid_val
                ),
            })
        }
    } else {
        // No CID provided (implicitly CID 0)
        Ok(core_packet_bytes)
    }
}

/// Parses a ROHC Profile 1 UO-1-SN packet.
///
/// Assumes `data` is the core UO-1-SN packet (typically 3 bytes), after Add-CID processing.
///
/// # Parameters
/// - `data`: Byte slice of the core UO-1-SN packet.
///
/// # Returns
/// A `Result` containing the parsed `Uo1Packet` or a `RohcParsingError`.
pub fn parse_profile1_uo1_sn_packet(data: &[u8]) -> Result<Uo1Packet, RohcParsingError> {
    // Standard P1 UO-1-SN is 3 bytes: Type (1), SN LSB (1), CRC-8 (1)
    let expected_len = 1 + (P1_UO1_SN_LSB_WIDTH_DEFAULT / 8) as usize + 1; // Type + SN_bytes + CRC8
    if data.len() < expected_len {
        return Err(RohcParsingError::NotEnoughData {
            needed: expected_len,
            got: data.len(),
            context: "UO-1-SN Packet".to_string(),
        });
    }

    // Check for UO-1 prefix `1010xxxx` (P1_UO_1_SN_PACKET_TYPE_PREFIX is `10100000`).
    // The lower bits might define sub-types of UO-1. For UO-1-SN, it's `1010000M`.
    let type_octet = data[0];
    if (type_octet & 0xF0) != (P1_UO_1_SN_PACKET_TYPE_PREFIX & 0xF0) {
        return Err(RohcParsingError::InvalidPacketType {
            discriminator: type_octet,
            profile_id: Some(RohcProfile::RtpUdpIp.into()),
        });
    }

    // Further check if it's specifically UO-1-SN (bits 3-1 are 000)
    if (type_octet & 0b0000_1110) != 0 {
        return Err(RohcParsingError::InvalidPacketType {
            discriminator: type_octet,
            profile_id: Some(RohcProfile::RtpUdpIp.into()),
        });
    }

    let marker_bit_is_set = (type_octet & P1_UO_1_SN_MARKER_BIT_MASK) != 0;
    let sn_lsb_val = data[1];
    let received_crc8 = data[2];

    Ok(Uo1Packet {
        cid: None,
        sn_lsb: sn_lsb_val as u16,
        num_sn_lsb_bits: P1_UO1_SN_LSB_WIDTH_DEFAULT,
        rtp_marker_bit_value: Some(marker_bit_is_set),
        ts_lsb: None, // This parser is specific to UO-1-SN
        num_ts_lsb_bits: None,
        crc8: received_crc8,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::DEFAULT_IPV4_TTL;
    use crate::packet_defs::RohcProfile;

    // Helper to create a basic RTP/UDP/IPv4 header byte stream for parsing tests
    fn build_sample_rtp_packet_bytes(sn: u16, ssrc: u32) -> Vec<u8> {
        let mut buf = Vec::new();
        // IPv4 (20 bytes)
        buf.extend_from_slice(&[0x45, 0x00]); // Version+IHL, DSCP+ECN
        buf.extend_from_slice(&((20 + 8 + 12) as u16).to_be_bytes()); // Total Length
        buf.extend_from_slice(&[0x00, 0x00, 0x40, 0x00]); // ID, Flags+FragOffset (DF set)
        buf.extend_from_slice(&[DEFAULT_IPV4_TTL, IP_PROTOCOL_UDP]); // TTL, Protocol
        buf.extend_from_slice(&[0x00, 0x00]); // Header Checksum (dummy)
        buf.extend_from_slice(&[192, 168, 0, 1]); // Src IP
        buf.extend_from_slice(&[192, 168, 0, 2]); // Dst IP
        // UDP (8 bytes)
        buf.extend_from_slice(&10000u16.to_be_bytes()); // Src Port
        buf.extend_from_slice(&20000u16.to_be_bytes()); // Dst Port
        buf.extend_from_slice(&((8 + 12) as u16).to_be_bytes()); // Length
        buf.extend_from_slice(&[0x00, 0x00]); // Checksum (dummy)
        // RTP (12 bytes)
        buf.extend_from_slice(&[0x80, 0x00]); // V=2,P=0,X=0,CC=0, M=0,PT=0
        buf.extend_from_slice(&sn.to_be_bytes()); // Seq Num
        buf.extend_from_slice(&1000u32.to_be_bytes()); // Timestamp
        buf.extend_from_slice(&ssrc.to_be_bytes()); // SSRC
        buf
    }

    #[test]
    fn parse_rtp_udp_ipv4_headers_valid() {
        let packet_bytes = build_sample_rtp_packet_bytes(123, 0x12345678);
        let headers = parse_rtp_udp_ipv4_headers(&packet_bytes).unwrap();
        assert_eq!(headers.ip_src, "192.168.0.1".parse::<Ipv4Addr>().unwrap());
        assert_eq!(headers.udp_dst_port, 20000);
        assert_eq!(headers.rtp_sequence_number, 123);
        assert_eq!(headers.rtp_ssrc, 0x12345678);
    }

    #[test]
    fn parse_rtp_udp_ipv4_headers_too_short() {
        let short_packet = vec![0x45, 0x00]; // Only 2 bytes
        let result = parse_rtp_udp_ipv4_headers(&short_packet);
        assert!(
            matches!(result, Err(RohcParsingError::NotEnoughData {needed, got, ..}) if needed == IPV4_MIN_HEADER_LENGTH_BYTES && got == 2)
        );
    }

    #[test]
    fn build_and_parse_ir_packet_cid0() {
        let ir_content = IrPacket {
            cid: 0,
            profile: RohcProfile::RtpUdpIp,
            static_ip_src: "1.1.1.1".parse().unwrap(),
            static_ip_dst: "2.2.2.2".parse().unwrap(),
            static_udp_src_port: 100,
            static_udp_dst_port: 200,
            static_rtp_ssrc: 0xABC,
            dyn_rtp_sn: 10,
            dyn_rtp_timestamp: 100,
            dyn_rtp_marker: true,
            crc8: 0, // Will be calculated by builder
        };
        let built_bytes = build_profile1_ir_packet(&ir_content).unwrap();
        // Expected length: Type(1)+Profile(1)+Static(16)+Dynamic(7)+CRC(1) = 26
        assert_eq!(
            built_bytes.len(),
            1 + 1 + P1_STATIC_CHAIN_LENGTH_BYTES + P1_DYNAMIC_CHAIN_LENGTH_BYTES + 1
        );
        assert_eq!(built_bytes[0], P1_ROHC_IR_PACKET_TYPE_WITH_DYN);

        let parsed_ir = parse_profile1_ir_packet(&built_bytes, 0).unwrap();
        assert_eq!(parsed_ir.cid, 0);
        assert_eq!(parsed_ir.static_rtp_ssrc, ir_content.static_rtp_ssrc);
        assert_eq!(parsed_ir.dyn_rtp_sn, ir_content.dyn_rtp_sn);
        assert_eq!(parsed_ir.dyn_rtp_marker, ir_content.dyn_rtp_marker);
        assert_eq!(parsed_ir.crc8, built_bytes.last().copied().unwrap());
    }

    #[test]
    fn build_and_parse_ir_packet_small_cid() {
        let ir_content = IrPacket {
            cid: 5,
            ..Default::default()
        };
        let built_bytes = build_profile1_ir_packet(&ir_content).unwrap();
        // Expected: AddCID(1)+Type(1)+Profile(1)+Static(16)+Dynamic(7)+CRC(1) = 27
        assert_eq!(
            built_bytes.len(),
            1 + 1 + 1 + P1_STATIC_CHAIN_LENGTH_BYTES + P1_DYNAMIC_CHAIN_LENGTH_BYTES + 1
        );
        assert_eq!(built_bytes[0], ROHC_ADD_CID_FEEDBACK_PREFIX_VALUE | 5);
        assert_eq!(built_bytes[1], P1_ROHC_IR_PACKET_TYPE_WITH_DYN);

        // parse_profile1_ir_packet expects core packet data (after Add-CID)
        let parsed_ir = parse_profile1_ir_packet(&built_bytes[1..], 5).unwrap();
        assert_eq!(parsed_ir.cid, 5);
    }

    #[test]
    fn parse_ir_packet_crc_mismatch() {
        let ir_content = IrPacket {
            cid: 0,
            ..Default::default()
        };
        let mut built_bytes = build_profile1_ir_packet(&ir_content).unwrap();
        let crc_idx = built_bytes.len() - 1;
        built_bytes[crc_idx] = built_bytes[crc_idx].wrapping_add(1); // Corrupt CRC

        let result = parse_profile1_ir_packet(&built_bytes, 0);
        assert!(matches!(result, Err(RohcParsingError::CrcMismatch { .. })));
    }

    #[test]
    fn build_and_parse_uo0_packet_cid0() {
        let uo0_data = Uo0Packet {
            cid: None,
            sn_lsb: 0x0A,
            crc3: 0x05,
        }; // SN=10, CRC=5
        let built_bytes = build_profile1_uo0_packet(&uo0_data).unwrap();
        assert_eq!(built_bytes.len(), 1);
        assert_eq!(built_bytes[0], (0x0A << 3) | 0x05); // 0b01010101 = 0x55

        let parsed_uo0 = parse_profile1_uo0_packet(&built_bytes, None).unwrap();
        assert_eq!(parsed_uo0.cid, None);
        assert_eq!(parsed_uo0.sn_lsb, 0x0A);
        assert_eq!(parsed_uo0.crc3, 0x05);
    }

    #[test]
    fn build_and_parse_uo0_packet_small_cid() {
        let uo0_data = Uo0Packet {
            cid: Some(7),
            sn_lsb: 0x03,
            crc3: 0x01,
        };
        let built_bytes = build_profile1_uo0_packet(&uo0_data).unwrap();
        assert_eq!(built_bytes.len(), 2); // AddCID + UO0 byte
        assert_eq!(built_bytes[0], ROHC_ADD_CID_FEEDBACK_PREFIX_VALUE | 7);
        assert_eq!(built_bytes[1], (0x03 << 3) | 0x01);

        let parsed_uo0 = parse_profile1_uo0_packet(&built_bytes[1..], Some(7)).unwrap();
        assert_eq!(parsed_uo0.cid, Some(7));
        assert_eq!(parsed_uo0.sn_lsb, 0x03);
    }

    #[test]
    fn build_and_parse_uo1_sn_packet_cid0_marker_true() {
        let uo1_data = Uo1Packet {
            sn_lsb: 0xAB,
            num_sn_lsb_bits: 8,
            rtp_marker_bit_value: Some(true),
            crc8: 0xCD,
            ..Default::default()
        };
        // build_profile1_uo1_sn_packet does not handle Add-CID itself.
        let built_core_bytes = build_profile1_uo1_sn_packet(&uo1_data).unwrap();
        assert_eq!(built_core_bytes.len(), 3);
        let expected_type_octet = P1_UO_1_SN_PACKET_TYPE_PREFIX | P1_UO_1_SN_MARKER_BIT_MASK;
        assert_eq!(built_core_bytes[0], expected_type_octet);
        assert_eq!(built_core_bytes[1], 0xAB);
        assert_eq!(built_core_bytes[2], 0xCD);

        let parsed_uo1 = parse_profile1_uo1_sn_packet(&built_core_bytes).unwrap();
        assert_eq!(parsed_uo1.sn_lsb, 0xAB);
        assert_eq!(parsed_uo1.num_sn_lsb_bits, 8);
        assert_eq!(parsed_uo1.rtp_marker_bit_value, Some(true));
        assert_eq!(parsed_uo1.crc8, 0xCD);
    }

    #[test]
    fn parse_uo1_sn_wrong_type_subfield() {
        // Type octet 10101000 (0xA8) has bits 3-1 non-zero, not UO-1-SN
        let bytes = vec![0xA8, 0x12, 0x34];
        let result = parse_profile1_uo1_sn_packet(&bytes);
        assert!(matches!(
            result,
            Err(RohcParsingError::InvalidPacketType {
                discriminator: 0xA8,
                ..
            })
        ));
    }
}
