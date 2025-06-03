//! ROHC (Robust Header Compression) Profile 1 specific packet parsing and building functions.
//!
//! This module provides the low-level utilities to:
//! 1. Parse raw byte arrays representing ROHC Profile 1 packets (IR, UO-0, UO-1-SN, etc.)
//!    into their corresponding structured Rust types (`IrPacket`, `Uo0Packet`, `Uo1Packet`).
//! 2. Build raw byte arrays (for transmission) from these Profile 1 packet structs.
//! 3. Parse uncompressed RTP/UDP/IPv4 headers from a raw byte stream into the
//!    `RtpUdpIpv4Headers` struct.

use std::net::Ipv4Addr;

use super::constants::*;
use super::packet_types::{IrPacket, Uo0Packet, Uo1Packet};
use super::protocol_types::{RtpUdpIpv4Headers, Timestamp};
use crate::constants::{
    IP_PROTOCOL_UDP, IPV4_MIN_HEADER_LENGTH_BYTES, IPV4_STANDARD_IHL,
    ROHC_ADD_CID_FEEDBACK_PREFIX_VALUE, ROHC_SMALL_CID_MASK, RTP_MIN_HEADER_LENGTH_BYTES,
    RTP_VERSION, UDP_HEADER_LENGTH_BYTES,
};
use crate::crc::CrcCalculators;
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
/// The parsed RTP/UDP/IPv4 headers.
///
/// # Errors
/// - [`RohcParsingError::NotEnoughData`] - Insufficient data for header parsing
/// - [`RohcParsingError::InvalidIpVersion`] - Non-IPv4 packet
/// - [`RohcParsingError::UnsupportedProtocol`] - Non-UDP protocol in IP header
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
    let rtp_ts_u32 = u32::from_be_bytes([
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
    for i in 0..rtp_csrc_count_val {
        if data.len() < current_csrc_offset + 4 {
            return Err(RohcParsingError::NotEnoughData {
                needed: current_csrc_offset + 4,
                got: data.len(),
                context: format!("RTP CSRC list item {}", i + 1),
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
        rtp_timestamp: Timestamp::new(rtp_ts_u32),
        rtp_ssrc: rtp_ssrc_val,
        rtp_csrc_list: rtp_csrc_list_val,
    })
}

/// Builds a ROHC Profile 1 IR (Initialization/Refresh) packet.
///
/// This function constructs the byte representation of an IR or IR-DYN packet.
/// It includes an Add-CID octet if the CID is small and non-zero.
/// The CRC-8 is calculated over the profile, static chain, and dynamic chain (if present).
/// If `ir_data.ts_stride` is `Some`, the TS_STRIDE_PRESENT flag is set in the RTP_Flags
/// octet and the 4-byte stride value is appended to the dynamic chain.
///
/// # Parameters
/// - `ir_data`: A reference to `IrPacket` containing all necessary field values.
/// - `crc_calculators`: An instance of `CrcCalculators` for CRC-8 computation.
///
/// # Returns
/// The built IR packet as a byte vector.
///
/// # Errors
/// - [`RohcBuildingError`] - Packet construction fails due to invalid field values
pub fn build_profile1_ir_packet(
    ir_data: &IrPacket,
    crc_calculators: &CrcCalculators,
) -> Result<Vec<u8>, RohcBuildingError> {
    debug_assert_eq!(
        ir_data.profile_id,
        RohcProfile::RtpUdpIp,
        "IR packet must be for Profile 1"
    );

    let mut final_packet_bytes = Vec::with_capacity(32);

    // Add-CID octet if needed
    if ir_data.cid > 0 && ir_data.cid <= 15 {
        final_packet_bytes
            .push(ROHC_ADD_CID_FEEDBACK_PREFIX_VALUE | (ir_data.cid as u8 & ROHC_SMALL_CID_MASK));
    } else if ir_data.cid > 15 {
        return Err(RohcBuildingError::InvalidFieldValueForBuild {
            field_name: "CID".to_string(),
            description: format!(
                "Large CID {} for IR packet Add-CID not supported by this builder.",
                ir_data.cid
            ),
        });
    }

    // Packet type octet
    final_packet_bytes.push(P1_ROHC_IR_PACKET_TYPE_WITH_DYN);

    // Profile ID
    let profile_u8: u8 = ir_data.profile_id.into();
    if profile_u8 != u8::from(RohcProfile::RtpUdpIp) {
        return Err(RohcBuildingError::InvalidFieldValueForBuild {
            field_name: "Profile ID".to_string(),
            description: format!(
                "IR packet is for ROHC Profile 1 (0x{:02X}), but got 0x{:02X}.",
                u8::from(RohcProfile::RtpUdpIp),
                profile_u8
            ),
        });
    }
    final_packet_bytes.push(profile_u8);

    // Static chain
    let static_chain_start_index_in_final = final_packet_bytes.len();
    final_packet_bytes.extend_from_slice(&ir_data.static_ip_src.octets());
    final_packet_bytes.extend_from_slice(&ir_data.static_ip_dst.octets());
    final_packet_bytes.extend_from_slice(&ir_data.static_udp_src_port.to_be_bytes());
    final_packet_bytes.extend_from_slice(&ir_data.static_udp_dst_port.to_be_bytes());
    final_packet_bytes.extend_from_slice(&ir_data.static_rtp_ssrc.to_be_bytes());

    // Dynamic chain
    let dynamic_chain_start_index_in_final = final_packet_bytes.len();
    final_packet_bytes.extend_from_slice(&ir_data.dyn_rtp_sn.to_be_bytes());
    final_packet_bytes.extend_from_slice(&ir_data.dyn_rtp_timestamp.to_be_bytes());

    let mut rtp_flags_octet = 0u8;
    if ir_data.dyn_rtp_marker {
        rtp_flags_octet |= P1_IR_DYN_RTP_FLAGS_MARKER_BIT_MASK;
    }
    if ir_data.ts_stride.is_some() {
        rtp_flags_octet |= P1_IR_DYN_RTP_FLAGS_TS_STRIDE_BIT_MASK;
    }
    final_packet_bytes.push(rtp_flags_octet);

    if let Some(stride_val) = ir_data.ts_stride {
        final_packet_bytes.extend_from_slice(&stride_val.to_be_bytes());
    }

    let crc_payload_len = 1
        + P1_STATIC_CHAIN_LENGTH_BYTES
        + P1_BASE_DYNAMIC_CHAIN_LENGTH_BYTES
        + if ir_data.ts_stride.is_some() {
            P1_TS_STRIDE_EXTENSION_LENGTH_BYTES
        } else {
            0
        };

    debug_assert!(
        crc_payload_len <= 32,
        "CRC payload too large for stack buffer"
    );

    let mut crc_payload = [0u8; 32]; // Max: 1 + 16 + 7 + 4 = 28 bytes
    crc_payload[0] = profile_u8;
    crc_payload[1..1 + P1_STATIC_CHAIN_LENGTH_BYTES].copy_from_slice(
        &final_packet_bytes[static_chain_start_index_in_final..dynamic_chain_start_index_in_final],
    );
    let dynamic_len = final_packet_bytes.len() - dynamic_chain_start_index_in_final;
    crc_payload[1 + P1_STATIC_CHAIN_LENGTH_BYTES..1 + P1_STATIC_CHAIN_LENGTH_BYTES + dynamic_len]
        .copy_from_slice(&final_packet_bytes[dynamic_chain_start_index_in_final..]);

    let calculated_crc8 = crc_calculators.crc8(&crc_payload[..crc_payload_len]);
    final_packet_bytes.push(calculated_crc8);

    debug_assert!(
        final_packet_bytes.len() >= 26,
        "IR packet too short: {} bytes",
        final_packet_bytes.len()
    );

    Ok(final_packet_bytes)
}

/// Parses a ROHC Profile 1 IR (Initialization/Refresh) packet.
///
/// The input `core_packet_bytes` should be the ROHC packet content starting
/// with the ROHC packet type octet.
/// The `cid_from_engine` must be provided by the caller.
/// This function now checks for and parses the optional TS_STRIDE extension
/// in the dynamic chain if the corresponding flag in RTP_Flags is set.
///
/// # Parameters
/// - `core_packet_bytes`: Byte slice of the core IR packet.
/// - `cid_from_engine`: The CID determined by the ROHC engine.
/// - `crc_calculators`: An instance of `CrcCalculators` for CRC-8 verification.
///
/// # Returns
/// The parsed IR packet data.
///
/// # Errors
/// - [`RohcParsingError`] - Not enough data, invalid type, or CRC mismatch
pub fn parse_profile1_ir_packet(
    core_packet_bytes: &[u8],
    cid_from_engine: u16,
    crc_calculators: &CrcCalculators,
) -> Result<IrPacket, RohcParsingError> {
    debug_assert!(!core_packet_bytes.is_empty(), "IR packet cannot be empty");

    let mut current_offset_for_fields = 0;

    if core_packet_bytes.is_empty() {
        return Err(RohcParsingError::NotEnoughData {
            needed: 1,
            got: 0,
            context: "IR Packet Type Octet".to_string(),
        });
    }
    let packet_type_octet = core_packet_bytes[current_offset_for_fields];
    current_offset_for_fields += 1; // Now points to ProfileID byte index in core_packet_bytes

    if (packet_type_octet & !P1_ROHC_IR_PACKET_TYPE_D_BIT_MASK) != P1_ROHC_IR_PACKET_TYPE_BASE {
        return Err(RohcParsingError::InvalidPacketType {
            discriminator: packet_type_octet,
            profile_id: Some(RohcProfile::RtpUdpIp.into()),
        });
    }
    let d_bit_set = (packet_type_octet & P1_ROHC_IR_PACKET_TYPE_D_BIT_MASK) != 0;

    let mut dynamic_chain_len_for_crc = 0;
    let mut ts_stride_present_flag_for_crc = false;

    if d_bit_set {
        dynamic_chain_len_for_crc = P1_BASE_DYNAMIC_CHAIN_LENGTH_BYTES;
        // RTP_Flags at byte 24: Type(1) + ProfileID(1) + Static(16) + SN(2) + TS(4) = 24
        const RTP_FLAGS_ABSOLUTE_IDX: usize = 24;

        if core_packet_bytes.len() > RTP_FLAGS_ABSOLUTE_IDX {
            let rtp_flags_octet_val = core_packet_bytes[RTP_FLAGS_ABSOLUTE_IDX];
            if (rtp_flags_octet_val & P1_IR_DYN_RTP_FLAGS_TS_STRIDE_BIT_MASK) != 0 {
                dynamic_chain_len_for_crc += P1_TS_STRIDE_EXTENSION_LENGTH_BYTES;
                ts_stride_present_flag_for_crc = true;
            }
        } else if P1_BASE_DYNAMIC_CHAIN_LENGTH_BYTES > 0 {
            return Err(RohcParsingError::NotEnoughData {
                needed: RTP_FLAGS_ABSOLUTE_IDX + 1,
                got: core_packet_bytes.len(),
                context: "IR Packet (RTP_Flags for CRC check)".to_string(),
            });
        }
    }

    let crc_payload_start_index_in_core = current_offset_for_fields; // Starts from ProfileID
    let crc_payload_len_for_validation =
        1 + P1_STATIC_CHAIN_LENGTH_BYTES + dynamic_chain_len_for_crc;
    let crc_octet_index_in_core = crc_payload_start_index_in_core + crc_payload_len_for_validation;

    if core_packet_bytes.len() <= crc_octet_index_in_core {
        return Err(RohcParsingError::NotEnoughData {
            needed: crc_octet_index_in_core + 1,
            got: core_packet_bytes.len(),
            context: "IR Packet (CRC field and defined payload)".to_string(),
        });
    }

    let crc_payload_slice =
        &core_packet_bytes[crc_payload_start_index_in_core..crc_octet_index_in_core];
    let received_crc8 = core_packet_bytes[crc_octet_index_in_core];
    let calculated_crc8 = crc_calculators.crc8(crc_payload_slice);

    if received_crc8 != calculated_crc8 {
        return Err(RohcParsingError::CrcMismatch {
            expected: received_crc8,
            calculated: calculated_crc8,
            crc_type: "ROHC-CRC8".to_string(),
        });
    }

    let profile_octet = core_packet_bytes[current_offset_for_fields];
    if profile_octet != u8::from(RohcProfile::RtpUdpIp) {
        return Err(RohcParsingError::InvalidProfileId(profile_octet));
    }
    current_offset_for_fields += 1; // Past Profile ID

    let static_ip_src = Ipv4Addr::new(
        core_packet_bytes[current_offset_for_fields],
        core_packet_bytes[current_offset_for_fields + 1],
        core_packet_bytes[current_offset_for_fields + 2],
        core_packet_bytes[current_offset_for_fields + 3],
    );
    current_offset_for_fields += 4;
    let static_ip_dst = Ipv4Addr::new(
        core_packet_bytes[current_offset_for_fields],
        core_packet_bytes[current_offset_for_fields + 1],
        core_packet_bytes[current_offset_for_fields + 2],
        core_packet_bytes[current_offset_for_fields + 3],
    );
    current_offset_for_fields += 4;
    let static_udp_src_port = u16::from_be_bytes([
        core_packet_bytes[current_offset_for_fields],
        core_packet_bytes[current_offset_for_fields + 1],
    ]);
    current_offset_for_fields += 2;
    let static_udp_dst_port = u16::from_be_bytes([
        core_packet_bytes[current_offset_for_fields],
        core_packet_bytes[current_offset_for_fields + 1],
    ]);
    current_offset_for_fields += 2;
    let static_rtp_ssrc = u32::from_be_bytes([
        core_packet_bytes[current_offset_for_fields],
        core_packet_bytes[current_offset_for_fields + 1],
        core_packet_bytes[current_offset_for_fields + 2],
        core_packet_bytes[current_offset_for_fields + 3],
    ]);
    current_offset_for_fields += 4;

    let (dyn_rtp_sn, dyn_rtp_timestamp_val, dyn_rtp_marker, parsed_ts_stride) = if d_bit_set {
        let sn = u16::from_be_bytes([
            core_packet_bytes[current_offset_for_fields],
            core_packet_bytes[current_offset_for_fields + 1],
        ]);
        current_offset_for_fields += 2;
        let ts_val = u32::from_be_bytes([
            core_packet_bytes[current_offset_for_fields],
            core_packet_bytes[current_offset_for_fields + 1],
            core_packet_bytes[current_offset_for_fields + 2],
            core_packet_bytes[current_offset_for_fields + 3],
        ]);
        current_offset_for_fields += 4;
        let rtp_flags_octet_val = core_packet_bytes[current_offset_for_fields];
        current_offset_for_fields += 1;
        let marker = (rtp_flags_octet_val & P1_IR_DYN_RTP_FLAGS_MARKER_BIT_MASK) != 0;

        let mut temp_ts_stride = None;
        if ts_stride_present_flag_for_crc {
            if core_packet_bytes.len()
                < current_offset_for_fields + P1_TS_STRIDE_EXTENSION_LENGTH_BYTES
            {
                return Err(RohcParsingError::NotEnoughData {
                    needed: current_offset_for_fields + P1_TS_STRIDE_EXTENSION_LENGTH_BYTES,
                    got: core_packet_bytes.len(),
                    context: "IR Packet TS_STRIDE Extension".to_string(),
                });
            }
            temp_ts_stride = Some(u32::from_be_bytes([
                core_packet_bytes[current_offset_for_fields],
                core_packet_bytes[current_offset_for_fields + 1],
                core_packet_bytes[current_offset_for_fields + 2],
                core_packet_bytes[current_offset_for_fields + 3],
            ]));
        }
        (sn, ts_val, marker, temp_ts_stride)
    } else {
        (0, 0, false, None)
    };

    Ok(IrPacket {
        cid: cid_from_engine,
        profile_id: RohcProfile::from(profile_octet),
        crc8: received_crc8,
        static_ip_src,
        static_ip_dst,
        static_udp_src_port,
        static_udp_dst_port,
        static_rtp_ssrc,
        dyn_rtp_sn,
        dyn_rtp_timestamp: Timestamp::new(dyn_rtp_timestamp_val),
        dyn_rtp_marker,
        ts_stride: parsed_ts_stride,
    })
}

/// Builds a ROHC Profile 1 UO-0 packet.
///
/// # Parameters
/// - `packet_data`: Data for the UO-0 packet.
///
/// # Returns
/// The built UO-0 packet as a byte vector.
///
/// # Errors
/// - [`RohcBuildingError`] - Invalid field values for UO-0 packet
pub fn build_profile1_uo0_packet(packet_data: &Uo0Packet) -> Result<Vec<u8>, RohcBuildingError> {
    debug_assert!(
        packet_data.sn_lsb < (1 << P1_UO0_SN_LSB_WIDTH_DEFAULT),
        "SN LSB value {} too large for {} bits",
        packet_data.sn_lsb,
        P1_UO0_SN_LSB_WIDTH_DEFAULT
    );
    debug_assert!(
        packet_data.crc3 <= 0x07,
        "CRC3 value {} too large",
        packet_data.crc3
    );

    if packet_data.sn_lsb >= (1 << P1_UO0_SN_LSB_WIDTH_DEFAULT) {
        return Err(RohcBuildingError::InvalidFieldValueForBuild {
            field_name: "sn_lsb".to_string(),
            description: format!(
                "Value {} exceeds {}-bit representation for UO-0 SN.",
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

    let mut final_packet = Vec::with_capacity(2);

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

    let core_byte = (packet_data.sn_lsb << 3) | packet_data.crc3;
    final_packet.push(core_byte);

    debug_assert!(
        final_packet.len() <= 2,
        "UO-0 packet too long: {} bytes",
        final_packet.len()
    );

    Ok(final_packet)
}

/// Parses a ROHC Profile 1 UO-0 packet.
///
/// # Parameters
/// - `core_packet_data`: Byte slice of the core UO-0 packet (single byte).
/// - `cid_from_engine`: Optional CID if Add-CID was processed by the engine.
///
/// # Returns
/// The parsed UO-0 packet data.
///
/// # Errors
/// - [`RohcParsingError`] - Incorrect length or invalid packet type
pub fn parse_profile1_uo0_packet(
    core_packet_data: &[u8],
    cid_from_engine: Option<u8>,
) -> Result<Uo0Packet, RohcParsingError> {
    debug_assert_eq!(
        core_packet_data.len(),
        1,
        "UO-0 core packet must be exactly 1 byte"
    );

    if core_packet_data.len() != 1 {
        return Err(RohcParsingError::InvalidFieldValue {
            field_name: "UO-0 Core Packet Length".to_string(),
            structure_name: "UO-0 Packet".to_string(),
            description: format!(
                "Expected 1 byte for core UO-0 packet, got {}.",
                core_packet_data.len()
            ),
        });
    }

    let packet_byte = core_packet_data[0];
    if (packet_byte & 0x80) != 0 {
        return Err(RohcParsingError::InvalidPacketType {
            discriminator: packet_byte,
            profile_id: Some(RohcProfile::RtpUdpIp.into()),
        });
    }

    let sn_lsb_val = (packet_byte >> 3) & ((1 << P1_UO0_SN_LSB_WIDTH_DEFAULT) - 1);
    let crc3_val = packet_byte & 0x07;

    debug_assert!(sn_lsb_val < 16, "SN LSB value {} out of range", sn_lsb_val);
    debug_assert!(crc3_val <= 7, "CRC3 value {} out of range", crc3_val);

    Ok(Uo0Packet {
        cid: cid_from_engine,
        sn_lsb: sn_lsb_val,
        crc3: crc3_val,
    })
}

/// Builds a ROHC Profile 1 UO-1-SN packet.
///
/// # Parameters
/// - `packet_data`: Data for the UO-1-SN packet.
///
/// # Returns
/// The built UO-1-SN packet as a byte vector.
///
/// # Errors
/// - [`RohcBuildingError`] - Invalid field values for UO-1-SN packet
pub fn build_profile1_uo1_sn_packet(packet_data: &Uo1Packet) -> Result<Vec<u8>, RohcBuildingError> {
    debug_assert_eq!(
        packet_data.num_sn_lsb_bits, P1_UO1_SN_LSB_WIDTH_DEFAULT,
        "UO-1-SN requires {} LSB bits, got {}",
        P1_UO1_SN_LSB_WIDTH_DEFAULT, packet_data.num_sn_lsb_bits
    );
    debug_assert!(
        packet_data.sn_lsb <= 0xFF,
        "SN LSB value {} too large for 8 bits",
        packet_data.sn_lsb
    );

    if packet_data.num_sn_lsb_bits != P1_UO1_SN_LSB_WIDTH_DEFAULT {
        return Err(RohcBuildingError::InvalidFieldValueForBuild {
            field_name: "num_sn_lsb_bits".to_string(),
            description: format!(
                "Profile 1 UO-1-SN builder expects {} LSBs for SN, got {}.",
                P1_UO1_SN_LSB_WIDTH_DEFAULT, packet_data.num_sn_lsb_bits
            ),
        });
    }
    if packet_data.sn_lsb > 0xFF {
        return Err(RohcBuildingError::InvalidFieldValueForBuild {
            field_name: "sn_lsb".to_string(),
            description: "Value for UO-1-SN LSB exceeds 8-bit representation.".to_string(),
        });
    }

    let type_octet = P1_UO_1_SN_PACKET_TYPE_PREFIX
        | (if packet_data.marker {
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
            Ok(core_packet_bytes)
        } else {
            Err(RohcBuildingError::InvalidFieldValueForBuild {
                field_name: "cid".to_string(),
                description: format!(
                    "Invalid CID {} for UO-1-SN Add-CID; expected 0 or 1-15.",
                    cid_val
                ),
            })
        }
    } else {
        Ok(core_packet_bytes)
    }
}

/// Parses a ROHC Profile 1 UO-1-SN packet.
///
/// # Parameters
/// - `core_packet_bytes`: Byte slice of the core UO-1-SN packet.
///
/// # Returns
/// The parsed UO-1-SN packet data.
///
/// # Errors
/// - [`RohcParsingError`] - Not enough data or invalid packet type
pub fn parse_profile1_uo1_sn_packet(
    core_packet_bytes: &[u8],
) -> Result<Uo1Packet, RohcParsingError> {
    let expected_len = 1 + (P1_UO1_SN_LSB_WIDTH_DEFAULT / 8) as usize + 1;
    debug_assert_eq!(expected_len, 3, "UO-1-SN should be 3 bytes");

    if core_packet_bytes.len() < expected_len {
        return Err(RohcParsingError::NotEnoughData {
            needed: expected_len,
            got: core_packet_bytes.len(),
            context: "UO-1-SN Packet Core".to_string(),
        });
    }

    let type_octet = core_packet_bytes[0];
    if (type_octet & !P1_UO_1_SN_MARKER_BIT_MASK) != P1_UO_1_SN_PACKET_TYPE_PREFIX {
        return Err(RohcParsingError::InvalidPacketType {
            discriminator: type_octet,
            profile_id: Some(RohcProfile::RtpUdpIp.into()),
        });
    }

    let marker_bit_set = (type_octet & P1_UO_1_SN_MARKER_BIT_MASK) != 0;
    let sn_lsb_val = core_packet_bytes[1];
    let received_crc8 = core_packet_bytes[2];

    Ok(Uo1Packet {
        cid: None,
        sn_lsb: sn_lsb_val as u16,
        num_sn_lsb_bits: P1_UO1_SN_LSB_WIDTH_DEFAULT,
        marker: marker_bit_set,
        ts_lsb: None,
        num_ts_lsb_bits: None,
        ip_id_lsb: None,
        num_ip_id_lsb_bits: None,
        ts_scaled: None,
        crc8: received_crc8,
    })
}

/// Builds a ROHC Profile 1 UO-1-TS packet.
///
/// # Parameters
/// - `packet_data`: Data for the UO-1-TS packet.
///
/// # Returns
/// The built UO-1-TS packet as a byte vector.
///
/// # Errors
/// - [`RohcBuildingError`] - Invalid field values for UO-1-TS packet
pub fn build_profile1_uo1_ts_packet(packet_data: &Uo1Packet) -> Result<Vec<u8>, RohcBuildingError> {
    let ts_lsb =
        packet_data
            .ts_lsb
            .ok_or_else(|| RohcBuildingError::InvalidFieldValueForBuild {
                field_name: "ts_lsb".to_string(),
                description: "UO-1-TS requires timestamp LSBs".to_string(),
            })?;
    let num_ts_bits = packet_data.num_ts_lsb_bits.ok_or_else(|| {
        RohcBuildingError::InvalidFieldValueForBuild {
            field_name: "num_ts_lsb_bits".to_string(),
            description: "UO-1-TS requires timestamp LSB bit count".to_string(),
        }
    })?;

    debug_assert_eq!(
        num_ts_bits, P1_UO1_TS_LSB_WIDTH_DEFAULT,
        "UO-1-TS requires {} LSB bits, got {}",
        P1_UO1_TS_LSB_WIDTH_DEFAULT, num_ts_bits
    );

    if num_ts_bits != P1_UO1_TS_LSB_WIDTH_DEFAULT {
        return Err(RohcBuildingError::InvalidFieldValueForBuild {
            field_name: "num_ts_lsb_bits".to_string(),
            description: format!(
                "Profile 1 UO-1-TS builder expects {} LSBs for TS, got {}.",
                P1_UO1_TS_LSB_WIDTH_DEFAULT, num_ts_bits
            ),
        });
    }

    let type_octet = P1_UO_1_TS_DISCRIMINATOR;
    let core_packet_bytes = vec![
        type_octet,
        (ts_lsb >> 8) as u8,
        (ts_lsb & 0xFF) as u8,
        packet_data.crc8,
    ];

    if let Some(cid_val) = packet_data.cid {
        if cid_val > 0 && cid_val <= 15 {
            let mut final_packet = Vec::with_capacity(1 + core_packet_bytes.len());
            final_packet.push(ROHC_ADD_CID_FEEDBACK_PREFIX_VALUE | (cid_val & ROHC_SMALL_CID_MASK));
            final_packet.extend_from_slice(&core_packet_bytes);
            Ok(final_packet)
        } else if cid_val == 0 {
            Ok(core_packet_bytes)
        } else {
            Err(RohcBuildingError::InvalidFieldValueForBuild {
                field_name: "cid".to_string(),
                description: format!(
                    "Invalid CID {} for UO-1-TS Add-CID; expected 0 or 1-15.",
                    cid_val
                ),
            })
        }
    } else {
        Ok(core_packet_bytes)
    }
}

/// Parses a ROHC Profile 1 UO-1-TS packet.
///
/// # Parameters
/// - `core_packet_bytes`: Byte slice of the core UO-1-TS packet.
///
/// # Returns
/// The parsed UO-1-TS packet data.
///
/// # Errors
/// - [`RohcParsingError`] - Not enough data or invalid packet type
pub fn parse_profile1_uo1_ts_packet(
    core_packet_bytes: &[u8],
) -> Result<Uo1Packet, RohcParsingError> {
    let expected_len = 1 + (P1_UO1_TS_LSB_WIDTH_DEFAULT / 8) as usize + 1;
    debug_assert_eq!(expected_len, 4, "UO-1-TS should be 4 bytes");

    if core_packet_bytes.len() < expected_len {
        return Err(RohcParsingError::NotEnoughData {
            needed: expected_len,
            got: core_packet_bytes.len(),
            context: "UO-1-TS Packet Core".to_string(),
        });
    }

    let type_octet = core_packet_bytes[0];
    if (type_octet & P1_UO_1_TS_TYPE_MASK) != (P1_UO_1_TS_DISCRIMINATOR & P1_UO_1_TS_TYPE_MASK) {
        return Err(RohcParsingError::InvalidPacketType {
            discriminator: type_octet,
            profile_id: Some(RohcProfile::RtpUdpIp.into()),
        });
    }

    let ts_lsb_val = u16::from_be_bytes([core_packet_bytes[1], core_packet_bytes[2]]);
    let received_crc8 = core_packet_bytes[3];

    Ok(Uo1Packet {
        cid: None,
        sn_lsb: 0,
        num_sn_lsb_bits: 0,
        marker: false,
        ts_lsb: Some(ts_lsb_val),
        num_ts_lsb_bits: Some(P1_UO1_TS_LSB_WIDTH_DEFAULT),
        ip_id_lsb: None,
        num_ip_id_lsb_bits: None,
        ts_scaled: None,
        crc8: received_crc8,
    })
}

/// Builds a ROHC Profile 1 UO-1-ID packet.
///
/// # Parameters
/// - `packet_data`: Data for the UO-1-ID packet.
///
/// # Returns
/// The built UO-1-ID packet as a byte vector.
///
/// # Errors
/// - [`RohcBuildingError`] - Invalid field values for UO-1-ID packet
pub fn build_profile1_uo1_id_packet(packet_data: &Uo1Packet) -> Result<Vec<u8>, RohcBuildingError> {
    let ip_id_lsb =
        packet_data
            .ip_id_lsb
            .ok_or_else(|| RohcBuildingError::InvalidFieldValueForBuild {
                field_name: "ip_id_lsb".to_string(),
                description: "UO-1-ID requires IP-ID LSBs".to_string(),
            })?;
    let num_ip_id_bits = packet_data.num_ip_id_lsb_bits.ok_or_else(|| {
        RohcBuildingError::InvalidFieldValueForBuild {
            field_name: "num_ip_id_lsb_bits".to_string(),
            description: "UO-1-ID requires IP-ID LSB bit count".to_string(),
        }
    })?;

    debug_assert_eq!(
        num_ip_id_bits, P1_UO1_IPID_LSB_WIDTH_DEFAULT,
        "UO-1-ID requires {} LSB bits, got {}",
        P1_UO1_IPID_LSB_WIDTH_DEFAULT, num_ip_id_bits
    );
    debug_assert!(
        ip_id_lsb <= 0xFF,
        "IP-ID LSB value {} too large for 8 bits",
        ip_id_lsb
    );

    if num_ip_id_bits != P1_UO1_IPID_LSB_WIDTH_DEFAULT {
        return Err(RohcBuildingError::InvalidFieldValueForBuild {
            field_name: "num_ip_id_lsb_bits".to_string(),
            description: format!(
                "Profile 1 UO-1-ID builder expects {} LSBs for IP-ID, got {}.",
                P1_UO1_IPID_LSB_WIDTH_DEFAULT, num_ip_id_bits
            ),
        });
    }
    if ip_id_lsb > 0xFF {
        return Err(RohcBuildingError::InvalidFieldValueForBuild {
            field_name: "ip_id_lsb".to_string(),
            description: "Value for UO-1-ID LSB exceeds 8-bit representation.".to_string(),
        });
    }

    let type_octet = P1_UO_1_ID_DISCRIMINATOR;
    let core_packet_bytes = vec![type_octet, ip_id_lsb as u8, packet_data.crc8];

    if let Some(cid_val) = packet_data.cid {
        if cid_val > 0 && cid_val <= 15 {
            let mut final_packet = Vec::with_capacity(1 + core_packet_bytes.len());
            final_packet.push(ROHC_ADD_CID_FEEDBACK_PREFIX_VALUE | (cid_val & ROHC_SMALL_CID_MASK));
            final_packet.extend_from_slice(&core_packet_bytes);
            Ok(final_packet)
        } else if cid_val == 0 {
            Ok(core_packet_bytes)
        } else {
            Err(RohcBuildingError::InvalidFieldValueForBuild {
                field_name: "cid".to_string(),
                description: format!(
                    "Invalid CID {} for UO-1-ID Add-CID; expected 0 or 1-15.",
                    cid_val
                ),
            })
        }
    } else {
        Ok(core_packet_bytes)
    }
}

/// Parses a ROHC Profile 1 UO-1-ID packet.
///
/// # Parameters
/// - `core_packet_bytes`: Byte slice of the core UO-1-ID packet.
///
/// # Returns
/// The parsed UO-1-ID packet data.
///
/// # Errors
/// - [`RohcParsingError`] - Not enough data or invalid packet type
pub fn parse_profile1_uo1_id_packet(
    core_packet_bytes: &[u8],
) -> Result<Uo1Packet, RohcParsingError> {
    let expected_len = 1 + (P1_UO1_IPID_LSB_WIDTH_DEFAULT / 8) as usize + 1;
    debug_assert_eq!(expected_len, 3, "UO-1-ID should be 3 bytes");

    if core_packet_bytes.len() < expected_len {
        return Err(RohcParsingError::NotEnoughData {
            needed: expected_len,
            got: core_packet_bytes.len(),
            context: "UO-1-ID Packet Core".to_string(),
        });
    }

    let type_octet = core_packet_bytes[0];
    if type_octet != P1_UO_1_ID_DISCRIMINATOR {
        return Err(RohcParsingError::InvalidPacketType {
            discriminator: type_octet,
            profile_id: Some(RohcProfile::RtpUdpIp.into()),
        });
    }

    let ip_id_lsb_val = core_packet_bytes[1];
    let received_crc8 = core_packet_bytes[2];

    Ok(Uo1Packet {
        cid: None,
        sn_lsb: 0,
        num_sn_lsb_bits: 0,
        marker: false,
        ts_lsb: None,
        num_ts_lsb_bits: None,
        ip_id_lsb: Some(ip_id_lsb_val as u16),
        num_ip_id_lsb_bits: Some(P1_UO1_IPID_LSB_WIDTH_DEFAULT),
        ts_scaled: None,
        crc8: received_crc8,
    })
}

/// Builds a ROHC Profile 1 UO-1-RTP packet.
///
/// # Parameters
/// - `packet_data`: Data for the UO-1-RTP packet.
///
/// # Returns
/// The built UO-1-RTP packet as a byte vector.
///
/// # Errors
/// - [`RohcBuildingError`] - Invalid field values for UO-1-RTP packet
pub fn build_profile1_uo1_rtp_packet(
    packet_data: &Uo1Packet,
) -> Result<Vec<u8>, RohcBuildingError> {
    let ts_scaled_val =
        packet_data
            .ts_scaled
            .ok_or_else(|| RohcBuildingError::InvalidFieldValueForBuild {
                field_name: "ts_scaled".to_string(),
                description: "UO-1-RTP requires a TS_SCALED value.".to_string(),
            })?;

    debug_assert!(
        ts_scaled_val <= P1_TS_SCALED_MAX_VALUE as u8,
        "TS_SCALED value {} too large",
        ts_scaled_val
    );

    let type_octet = P1_UO_1_RTP_DISCRIMINATOR_BASE
        | (if packet_data.marker {
            P1_UO_1_RTP_MARKER_BIT_MASK
        } else {
            0
        });

    let core_packet_bytes = vec![type_octet, ts_scaled_val, packet_data.crc8];

    if let Some(cid_val) = packet_data.cid {
        if cid_val > 0 && cid_val <= 15 {
            let mut final_packet = Vec::with_capacity(1 + core_packet_bytes.len());
            final_packet.push(ROHC_ADD_CID_FEEDBACK_PREFIX_VALUE | (cid_val & ROHC_SMALL_CID_MASK));
            final_packet.extend_from_slice(&core_packet_bytes);
            Ok(final_packet)
        } else if cid_val == 0 {
            Ok(core_packet_bytes)
        } else {
            Err(RohcBuildingError::InvalidFieldValueForBuild {
                field_name: "cid".to_string(),
                description: format!(
                    "Invalid CID {} for UO-1-RTP Add-CID encoding; expected 0 or 1-15.",
                    cid_val
                ),
            })
        }
    } else {
        Ok(core_packet_bytes)
    }
}

/// Parses a ROHC Profile 1 UO-1-RTP packet.
///
/// # Parameters
/// - `core_packet_bytes`: Byte slice of the core UO-1-RTP packet.
///
/// # Returns
/// The parsed UO-1-RTP packet data.
///
/// # Errors
/// - [`RohcParsingError`] - Not enough data or invalid packet type
pub fn parse_profile1_uo1_rtp_packet(
    core_packet_bytes: &[u8],
) -> Result<Uo1Packet, RohcParsingError> {
    let expected_len = 3;
    debug_assert_eq!(expected_len, 3, "UO-1-RTP should be 3 bytes");

    if core_packet_bytes.len() < expected_len {
        return Err(RohcParsingError::NotEnoughData {
            needed: expected_len,
            got: core_packet_bytes.len(),
            context: "UO-1-RTP Packet Core".to_string(),
        });
    }

    let type_octet = core_packet_bytes[0];

    if (type_octet & 0b1111_1110) != P1_UO_1_RTP_DISCRIMINATOR_BASE {
        return Err(RohcParsingError::InvalidPacketType {
            discriminator: type_octet,
            profile_id: Some(RohcProfile::RtpUdpIp.into()),
        });
    }

    let marker_bit_set = (type_octet & P1_UO_1_RTP_MARKER_BIT_MASK) != 0;
    let ts_scaled_val = core_packet_bytes[1];
    let received_crc8 = core_packet_bytes[2];

    Ok(Uo1Packet {
        cid: None,
        sn_lsb: 0,
        num_sn_lsb_bits: 0,
        marker: marker_bit_set,
        ts_lsb: None,
        num_ts_lsb_bits: None,
        ip_id_lsb: None,
        num_ip_id_lsb_bits: None,
        ts_scaled: Some(ts_scaled_val),
        crc8: received_crc8,
    })
}

/// Prepares a generic UO packet CRC input payload on the stack.
///
/// The CRC input consists of:
/// - SSRC (4 bytes)
/// - SN (2 bytes)
/// - TS (4 bytes)
/// - Marker (1 byte)
///   Total: 11 bytes
///
/// # Parameters
/// - `context_ssrc`: The SSRC from the context.
/// - `sn_for_crc`: The sequence number for CRC calculation.
/// - `ts_for_crc`: The timestamp for CRC calculation.
/// - `marker_for_crc`: The marker bit for CRC calculation.
///
/// # Returns
/// A fixed-size array containing the CRC input payload.
#[inline]
pub(crate) fn prepare_generic_uo_crc_input_payload(
    context_ssrc: u32,
    sn_for_crc: u16,
    ts_for_crc: Timestamp,
    marker_for_crc: bool,
) -> [u8; P1_UO_CRC_INPUT_LENGTH_BYTES] {
    debug_assert_eq!(
        P1_UO_CRC_INPUT_LENGTH_BYTES, 11,
        "CRC input should be 11 bytes"
    );

    let mut crc_input = [0u8; P1_UO_CRC_INPUT_LENGTH_BYTES];

    crc_input[0..4].copy_from_slice(&context_ssrc.to_be_bytes());
    crc_input[4..6].copy_from_slice(&sn_for_crc.to_be_bytes());
    crc_input[6..10].copy_from_slice(&ts_for_crc.to_be_bytes());
    crc_input[10] = if marker_for_crc { 0x01 } else { 0x00 };

    crc_input
}

/// Prepares a UO-1-ID specific CRC input payload on the stack.
///
/// The CRC input consists of:
/// - SSRC (4 bytes)
/// - SN (2 bytes)
/// - TS (4 bytes)
/// - Marker (1 byte)
/// - IP-ID LSB (1 byte)
///   Total: 12 bytes
///
/// # Parameters
/// - `context_ssrc`: The SSRC from the context.
/// - `sn_for_crc`: The sequence number for CRC calculation.
/// - `ts_for_crc`: The timestamp for CRC calculation.
/// - `marker_for_crc`: The marker bit for CRC calculation.
/// - `ip_id_lsb_for_crc`: The IP-ID LSB value for CRC calculation.
///
/// # Returns
/// A fixed-size array containing the CRC input payload.
#[inline]
pub(crate) fn prepare_uo1_id_specific_crc_input_payload(
    context_ssrc: u32,
    sn_for_crc: u16,
    ts_for_crc: Timestamp,
    marker_for_crc: bool,
    ip_id_lsb_for_crc: u8,
) -> [u8; P1_UO_CRC_INPUT_LENGTH_BYTES + 1] {
    debug_assert_eq!(
        P1_UO_CRC_INPUT_LENGTH_BYTES + 1,
        12,
        "CRC input should be 12 bytes"
    );

    let mut crc_input = [0u8; P1_UO_CRC_INPUT_LENGTH_BYTES + 1];

    crc_input[0..4].copy_from_slice(&context_ssrc.to_be_bytes());
    crc_input[4..6].copy_from_slice(&sn_for_crc.to_be_bytes());
    crc_input[6..10].copy_from_slice(&ts_for_crc.to_be_bytes());
    crc_input[10] = if marker_for_crc { 0x01 } else { 0x00 };
    crc_input[11] = ip_id_lsb_for_crc;

    crc_input
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::DEFAULT_IPV4_TTL;
    use crate::packet_defs::RohcProfile;
    use crate::profiles::profile1::constants::{
        P1_UO_1_RTP_DISCRIMINATOR_BASE, P1_UO_1_RTP_MARKER_BIT_MASK,
    };

    fn build_sample_rtp_packet_bytes(sn: u16, ssrc: u32, ts_val: u32) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&[0x45, 0x00]);
        buf.extend_from_slice(&((20 + 8 + 12) as u16).to_be_bytes());
        buf.extend_from_slice(&[0x00, 0x00, 0x40, 0x00]);
        buf.extend_from_slice(&[DEFAULT_IPV4_TTL, IP_PROTOCOL_UDP]);
        buf.extend_from_slice(&[0x00, 0x00]);
        buf.extend_from_slice(&[192, 168, 0, 1]);
        buf.extend_from_slice(&[192, 168, 0, 2]);
        buf.extend_from_slice(&10000u16.to_be_bytes());
        buf.extend_from_slice(&20000u16.to_be_bytes());
        buf.extend_from_slice(&((8 + 12) as u16).to_be_bytes());
        buf.extend_from_slice(&[0x00, 0x00]);
        buf.extend_from_slice(&[0x80, 0x00]);
        buf.extend_from_slice(&sn.to_be_bytes());
        buf.extend_from_slice(&ts_val.to_be_bytes());
        buf.extend_from_slice(&ssrc.to_be_bytes());
        buf
    }

    #[test]
    fn parse_rtp_udp_ipv4_headers_valid() {
        let packet_bytes = build_sample_rtp_packet_bytes(123, 0x12345678, 1000);
        let headers = parse_rtp_udp_ipv4_headers(&packet_bytes).unwrap();
        assert_eq!(headers.rtp_sequence_number, 123);
        assert_eq!(headers.rtp_timestamp, Timestamp::new(1000));
    }

    #[test]
    fn parse_rtp_udp_ipv4_headers_too_short() {
        let short_packet = vec![0x45, 0x00];
        let result = parse_rtp_udp_ipv4_headers(&short_packet);
        assert!(
            matches!(result, Err(RohcParsingError::NotEnoughData {needed, got, ..}) if needed == IPV4_MIN_HEADER_LENGTH_BYTES && got == 2)
        );
    }

    #[test]
    fn build_and_parse_ir_packet_cid0() {
        let crc_calculators = CrcCalculators::new();
        let ir_content = IrPacket {
            cid: 0,
            profile_id: RohcProfile::RtpUdpIp,
            static_ip_src: "1.1.1.1".parse().unwrap(),
            static_ip_dst: "2.2.2.2".parse().unwrap(),
            static_udp_src_port: 100,
            static_udp_dst_port: 200,
            static_rtp_ssrc: 0xABC,
            dyn_rtp_sn: 10,
            dyn_rtp_timestamp: Timestamp::new(100),
            dyn_rtp_marker: true,
            ts_stride: None, // No TS stride for this test case
            crc8: 0,
        };
        let built_bytes = build_profile1_ir_packet(&ir_content, &crc_calculators).unwrap();
        assert_eq!(built_bytes.len(), 26); // CID 0: type(1) + profile(1) + static(16) + dyn(7) + crc(1)
        assert_eq!(built_bytes[0], P1_ROHC_IR_PACKET_TYPE_WITH_DYN);

        let parsed_ir = parse_profile1_ir_packet(&built_bytes, 0, &crc_calculators).unwrap();
        assert_eq!(parsed_ir.cid, 0);
        assert_eq!(parsed_ir.static_rtp_ssrc, ir_content.static_rtp_ssrc);
        assert_eq!(parsed_ir.dyn_rtp_sn, ir_content.dyn_rtp_sn);
        assert_eq!(parsed_ir.dyn_rtp_timestamp, ir_content.dyn_rtp_timestamp);
        assert_eq!(parsed_ir.dyn_rtp_marker, ir_content.dyn_rtp_marker);
        assert_eq!(parsed_ir.ts_stride, None);
        assert_eq!(parsed_ir.crc8, built_bytes.last().copied().unwrap());
    }

    #[test]
    fn build_and_parse_ir_packet_cid0_with_ts_stride() {
        let crc_calculators = CrcCalculators::new();
        let ir_content = IrPacket {
            cid: 0,
            profile_id: RohcProfile::RtpUdpIp,
            static_ip_src: "1.1.1.1".parse().unwrap(),
            static_ip_dst: "2.2.2.2".parse().unwrap(),
            static_udp_src_port: 100,
            static_udp_dst_port: 200,
            static_rtp_ssrc: 0xABC,
            dyn_rtp_sn: 10,
            dyn_rtp_timestamp: Timestamp::new(100),
            dyn_rtp_marker: false,
            ts_stride: Some(160), // With TS stride
            crc8: 0,
        };
        let built_bytes = build_profile1_ir_packet(&ir_content, &crc_calculators).unwrap();
        assert_eq!(built_bytes.len(), 30); // +4 bytes for TS_STRIDE extension
        assert_eq!(built_bytes[0], P1_ROHC_IR_PACKET_TYPE_WITH_DYN);

        let rtp_flags_octet_absolute_index = 24;
        assert_eq!(
            built_bytes[rtp_flags_octet_absolute_index] & P1_IR_DYN_RTP_FLAGS_TS_STRIDE_BIT_MASK,
            P1_IR_DYN_RTP_FLAGS_TS_STRIDE_BIT_MASK,
            "TS Stride bit not set in IR"
        );

        let parsed_ir = parse_profile1_ir_packet(&built_bytes, 0, &crc_calculators).unwrap();
        assert_eq!(parsed_ir.cid, 0);
        assert_eq!(parsed_ir.static_rtp_ssrc, ir_content.static_rtp_ssrc);
        assert_eq!(parsed_ir.dyn_rtp_sn, ir_content.dyn_rtp_sn);
        assert_eq!(parsed_ir.dyn_rtp_timestamp, ir_content.dyn_rtp_timestamp);
        assert_eq!(parsed_ir.dyn_rtp_marker, ir_content.dyn_rtp_marker);
        assert_eq!(parsed_ir.ts_stride, Some(160));
        assert_eq!(parsed_ir.crc8, built_bytes.last().copied().unwrap());
    }

    #[test]
    fn build_and_parse_ir_packet_small_cid() {
        let crc_calculators = CrcCalculators::new();
        let ir_content_ts_val: u32 = 50;
        let ir_content = IrPacket {
            cid: 5,
            dyn_rtp_timestamp: Timestamp::new(ir_content_ts_val),
            profile_id: RohcProfile::RtpUdpIp,
            static_ip_src: "0.0.0.0".parse().unwrap(),
            static_ip_dst: "0.0.0.0".parse().unwrap(),
            static_udp_src_port: 0,
            static_udp_dst_port: 0,
            static_rtp_ssrc: 0,
            dyn_rtp_sn: 0,
            dyn_rtp_marker: false,
            ts_stride: None,
            crc8: 0,
        };
        let built_bytes = build_profile1_ir_packet(&ir_content, &crc_calculators).unwrap();
        assert_eq!(built_bytes.len(), 27); // +1 byte for Add-CID
        assert_eq!(built_bytes[0], ROHC_ADD_CID_FEEDBACK_PREFIX_VALUE | 5);
        assert_eq!(built_bytes[1], P1_ROHC_IR_PACKET_TYPE_WITH_DYN);

        let parsed_ir = parse_profile1_ir_packet(&built_bytes[1..], 5, &crc_calculators).unwrap();
        assert_eq!(parsed_ir.cid, 5);
        assert_eq!(
            parsed_ir.dyn_rtp_timestamp,
            Timestamp::new(ir_content_ts_val)
        );
        assert_eq!(parsed_ir.static_rtp_ssrc, 0);
        assert_eq!(parsed_ir.dyn_rtp_sn, 0);
        assert_eq!(parsed_ir.ts_stride, None);
    }

    #[test]
    fn parse_ir_packet_crc_mismatch() {
        let crc_calculators = CrcCalculators::new();
        let ir_content = IrPacket {
            cid: 0,
            dyn_rtp_timestamp: Timestamp::new(100),
            ..Default::default()
        };
        let mut built_bytes = build_profile1_ir_packet(&ir_content, &crc_calculators).unwrap();
        let crc_idx = built_bytes.len() - 1;
        built_bytes[crc_idx] = built_bytes[crc_idx].wrapping_add(1);

        let result = parse_profile1_ir_packet(&built_bytes, 0, &crc_calculators);
        assert!(matches!(result, Err(RohcParsingError::CrcMismatch { .. })));
    }

    #[test]
    fn build_and_parse_uo1_rtp_packet_cid0_marker_false() {
        let uo1_rtp_data = Uo1Packet {
            cid: None, // Implicit CID 0
            marker: false,
            ts_scaled: Some(123),
            crc8: 0xAB,
            ..Default::default()
        };

        let built_bytes = build_profile1_uo1_rtp_packet(&uo1_rtp_data).unwrap();
        assert_eq!(built_bytes.len(), 3);
        assert_eq!(built_bytes[0], P1_UO_1_RTP_DISCRIMINATOR_BASE); // M=0
        assert_eq!(built_bytes[1], 123); // TS_SCALED
        assert_eq!(built_bytes[2], 0xAB); // CRC

        let parsed = parse_profile1_uo1_rtp_packet(&built_bytes).unwrap();
        assert_eq!(parsed.ts_scaled, Some(123));
        assert!(!parsed.marker);
        assert_eq!(parsed.crc8, 0xAB);
    }

    #[test]
    fn build_and_parse_uo1_rtp_packet_cid0_marker_true() {
        let uo1_rtp_data = Uo1Packet {
            cid: None,
            marker: true,
            ts_scaled: Some(10),
            crc8: 0xCD,
            ..Default::default()
        };

        let built_bytes = build_profile1_uo1_rtp_packet(&uo1_rtp_data).unwrap();
        assert_eq!(built_bytes.len(), 3);
        assert_eq!(
            built_bytes[0],
            P1_UO_1_RTP_DISCRIMINATOR_BASE | P1_UO_1_RTP_MARKER_BIT_MASK
        ); // M=1
        assert_eq!(built_bytes[1], 10);
        assert_eq!(built_bytes[2], 0xCD);

        let parsed = parse_profile1_uo1_rtp_packet(&built_bytes).unwrap();
        assert_eq!(parsed.ts_scaled, Some(10));
        assert!(parsed.marker);
        assert_eq!(parsed.crc8, 0xCD);
    }

    #[test]
    fn build_and_parse_uo1_rtp_packet_small_cid() {
        let uo1_rtp_data = Uo1Packet {
            cid: Some(5),
            marker: false,
            ts_scaled: Some(255),
            crc8: 0xFE,
            ..Default::default()
        };

        let built_bytes = build_profile1_uo1_rtp_packet(&uo1_rtp_data).unwrap();
        assert_eq!(built_bytes.len(), 4); // Add-CID + core packet
        assert_eq!(built_bytes[0], ROHC_ADD_CID_FEEDBACK_PREFIX_VALUE | 5);
        assert_eq!(built_bytes[1], P1_UO_1_RTP_DISCRIMINATOR_BASE); // M=0
        assert_eq!(built_bytes[2], 255);
        assert_eq!(built_bytes[3], 0xFE);

        let parsed = parse_profile1_uo1_rtp_packet(&built_bytes[1..]).unwrap(); // Parse core part
        assert_eq!(parsed.ts_scaled, Some(255));
        assert!(!parsed.marker);
        assert_eq!(parsed.crc8, 0xFE);
    }

    #[test]
    fn build_uo1_rtp_packet_missing_ts_scaled() {
        let uo1_rtp_data = Uo1Packet {
            cid: None,
            marker: false,
            ts_scaled: None, // Missing
            crc8: 0xAB,
            ..Default::default()
        };
        let result = build_profile1_uo1_rtp_packet(&uo1_rtp_data);
        assert!(
            matches!(result, Err(RohcBuildingError::InvalidFieldValueForBuild { field_name, .. }) if field_name == "ts_scaled")
        );
    }

    #[test]
    fn parse_uo1_rtp_packet_too_short() {
        let short_packet = vec![P1_UO_1_RTP_DISCRIMINATOR_BASE, 123]; // Missing CRC
        let result = parse_profile1_uo1_rtp_packet(&short_packet);
        assert!(matches!(
            result,
            Err(RohcParsingError::NotEnoughData {
                needed: 3,
                got: 2,
                ..
            })
        ));
    }

    #[test]
    fn parse_uo1_rtp_wrong_discriminator() {
        let wrong_packet = vec![P1_UO_1_SN_PACKET_TYPE_PREFIX, 123, 0xAB]; // UO-1-SN type
        let result = parse_profile1_uo1_rtp_packet(&wrong_packet);
        assert!(matches!(
            result,
            Err(RohcParsingError::InvalidPacketType { .. })
        ));
    }

    #[test]
    fn test_generic_uo_crc_input_payload() {
        let ssrc = 0x12345678u32;
        let sn = 0xABCDu16;
        let ts = Timestamp::new(0xDEADBEEF);
        let marker = true;

        let payload = prepare_generic_uo_crc_input_payload(ssrc, sn, ts, marker);

        assert_eq!(payload.len(), 11);
        assert_eq!(&payload[0..4], &ssrc.to_be_bytes());
        assert_eq!(&payload[4..6], &sn.to_be_bytes());
        assert_eq!(&payload[6..10], &ts.to_be_bytes());
        assert_eq!(payload[10], 0x01);
    }

    #[test]
    fn test_uo1_id_specific_crc_input_payload() {
        let ssrc = 0x87654321u32;
        let sn = 0x1234u16;
        let ts = Timestamp::new(0xCAFEBABE);
        let marker = false;
        let ip_id_lsb = 0x42u8;

        let payload = prepare_uo1_id_specific_crc_input_payload(ssrc, sn, ts, marker, ip_id_lsb);

        assert_eq!(payload.len(), 12);
        assert_eq!(&payload[0..4], &ssrc.to_be_bytes());
        assert_eq!(&payload[4..6], &sn.to_be_bytes());
        assert_eq!(&payload[6..10], &ts.to_be_bytes());
        assert_eq!(payload[10], 0x00);
        assert_eq!(payload[11], ip_id_lsb);
    }
}
