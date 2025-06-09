//! ROHC (Robust Header Compression) Profile 1 specific packet serialization and deserialization functions.
//!
//! This module provides the low-level utilities to:
//! 1. Deserialize raw byte arrays representing ROHC Profile 1 packets (IR, UO-0, UO-1-SN, etc.)
//!    into their corresponding structured Rust types (`IrPacket`, `Uo0Packet`, `Uo1Packet`).
//! 2. Serialize these Profile 1 packet structs into raw byte arrays for transmission.
//! 3. Parse uncompressed RTP/UDP/IPv4 headers from a raw byte stream into the
//!    `RtpUdpIpv4Headers` struct.

use std::net::Ipv4Addr;

use super::constants::*;
use super::packet_types::{IrPacket, Uo0Packet, Uo1Packet};
use super::protocol_types::RtpUdpIpv4Headers;
use crate::constants::{
    DEFAULT_IPV4_TTL, IP_PROTOCOL_UDP, IPV4_MIN_HEADER_LENGTH_BYTES, IPV4_STANDARD_IHL,
    ROHC_ADD_CID_FEEDBACK_PREFIX_VALUE, ROHC_SMALL_CID_MASK, RTP_MIN_HEADER_LENGTH_BYTES,
    RTP_VERSION, UDP_HEADER_LENGTH_BYTES,
};
use crate::crc::CrcCalculators;
use crate::error::{RohcBuildingError, RohcParsingError};
use crate::packet_defs::RohcProfile;
use crate::types::{ContextId, SequenceNumber, Ssrc, Timestamp};

/// Deserializes raw bytes representing an RTP/UDP/IPv4 packet into `RtpUdpIpv4Headers`.
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
pub fn deserialize_rtp_udp_ipv4_headers(
    data: &[u8],
) -> Result<RtpUdpIpv4Headers, RohcParsingError> {
    if data.len() < IPV4_MIN_HEADER_LENGTH_BYTES {
        return Err(RohcParsingError::NotEnoughData {
            needed: IPV4_MIN_HEADER_LENGTH_BYTES,
            got: data.len(),
            context: crate::error::ParseContext::Ipv4HeaderMin,
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
            field: crate::error::Field::IpIhl,
            structure: crate::error::StructureType::Ipv4Header,
            expected: IPV4_STANDARD_IHL as u32,
            got: ip_ihl_words as u32,
        });
    }
    let ip_header_length_bytes = (ip_ihl_words * 4) as usize;
    if data.len() < ip_header_length_bytes {
        return Err(RohcParsingError::NotEnoughData {
            needed: ip_header_length_bytes,
            got: data.len(),
            context: crate::error::ParseContext::Ipv4HeaderCalculated,
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
            layer: crate::error::NetworkLayer::Ip,
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
            context: crate::error::ParseContext::UdpHeader,
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
            context: crate::error::ParseContext::RtpHeaderMin,
        });
    }
    let rtp_first_byte = data[rtp_start_offset];
    let rtp_version_val = rtp_first_byte >> 6;
    if rtp_version_val != RTP_VERSION {
        return Err(RohcParsingError::InvalidFieldValue {
            field: crate::error::Field::RtpVersion,
            structure: crate::error::StructureType::RtpHeader,
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
                context: crate::error::ParseContext::RtpHeaderMin, // CSRC parsing is part of RTP header
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
            field: crate::error::Field::RtpCsrcCount,
            structure: crate::error::StructureType::RtpHeader,
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

/// Serializes a ROHC Profile 1 IR (Initialization/Refresh) packet into provided buffer.
///
/// This function serializes an `IrPacket` structure into its byte representation for transmission.
/// It includes an Add-CID octet if the CID is small and non-zero.
/// The CRC-8 is calculated over the profile, static chain, and dynamic chain (if present).
/// If `ir_data.ts_stride` is `Some`, the TS_STRIDE_PRESENT flag is set in the RTP_Flags
/// octet and the 4-byte stride value is appended to the dynamic chain.
///
/// # Parameters
/// - `ir_data`: A reference to `IrPacket` containing all necessary field values.
/// - `crc_calculators`: An instance of `CrcCalculators` for CRC-8 computation.
/// - `out`: Output buffer to write the serialized packet into.
///
/// # Returns
/// The number of bytes written to the output buffer.
///
/// # Errors
/// - [`RohcBuildingError`] - Packet serialization fails due to invalid field values
pub fn serialize_ir(
    ir_data: &IrPacket,
    crc_calculators: &CrcCalculators,
    out: &mut [u8],
) -> Result<usize, RohcBuildingError> {
    debug_assert_eq!(
        ir_data.profile_id,
        RohcProfile::RtpUdpIp,
        "IR packet must be for Profile 1"
    );

    let mut bytes_written = 0;

    // Calculate required size
    let required_size = 1 // Packet type
        + 1 // Profile ID
        + P1_STATIC_CHAIN_LENGTH_BYTES
        + P1_BASE_DYNAMIC_CHAIN_LENGTH_BYTES
        + 1 // CRC8
        + if ir_data.cid > 0 && ir_data.cid <= 15 { 1 } else { 0 } // Add-CID
        + if ir_data.ts_stride.is_some() { P1_TS_STRIDE_EXTENSION_LENGTH_BYTES } else { 0 }; // TS_STRIDE extension

    if out.len() < required_size {
        return Err(RohcBuildingError::InvalidFieldValueForBuild {
            field: crate::error::Field::BufferSize,
            value: out.len() as u32,
            max_bits: required_size as u8,
        });
    }

    // Add-CID octet if needed
    if ir_data.cid > 0 && ir_data.cid <= 15 {
        out[bytes_written] =
            ROHC_ADD_CID_FEEDBACK_PREFIX_VALUE | (ir_data.cid.0 as u8 & ROHC_SMALL_CID_MASK);
        bytes_written += 1;
    } else if ir_data.cid > 15 {
        return Err(RohcBuildingError::InvalidFieldValueForBuild {
            field: crate::error::Field::Cid,
            value: ir_data.cid.0 as u32,
            max_bits: 4, // Small CID range is 0-15
        });
    }

    // Packet type octet
    out[bytes_written] = P1_ROHC_IR_PACKET_TYPE_WITH_DYN; // D-bit is always 1 if dynamic chain is present
    bytes_written += 1;

    // Profile ID
    let profile_u8: u8 = ir_data.profile_id.into();
    if profile_u8 != u8::from(RohcProfile::RtpUdpIp) {
        return Err(RohcBuildingError::InvalidFieldValueForBuild {
            field: crate::error::Field::ProfileId,
            value: profile_u8 as u32,
            max_bits: 8, // Expected value is u8::from(RohcProfile::RtpUdpIp)
        });
    }
    out[bytes_written] = profile_u8;
    bytes_written += 1;

    // Static chain
    out[bytes_written..bytes_written + 4].copy_from_slice(&ir_data.static_ip_src.octets());
    bytes_written += 4;
    out[bytes_written..bytes_written + 4].copy_from_slice(&ir_data.static_ip_dst.octets());
    bytes_written += 4;
    out[bytes_written..bytes_written + 2]
        .copy_from_slice(&ir_data.static_udp_src_port.to_be_bytes());
    bytes_written += 2;
    out[bytes_written..bytes_written + 2]
        .copy_from_slice(&ir_data.static_udp_dst_port.to_be_bytes());
    bytes_written += 2;
    out[bytes_written..bytes_written + 4].copy_from_slice(&ir_data.static_rtp_ssrc.to_be_bytes());
    bytes_written += 4;

    // Dynamic chain
    out[bytes_written..bytes_written + 2].copy_from_slice(&ir_data.dyn_rtp_sn.to_be_bytes());
    bytes_written += 2;
    out[bytes_written..bytes_written + 4].copy_from_slice(&ir_data.dyn_rtp_timestamp.to_be_bytes());
    bytes_written += 4;
    out[bytes_written] = ir_data.dyn_ip_ttl;
    bytes_written += 1;
    out[bytes_written..bytes_written + 2].copy_from_slice(&ir_data.dyn_ip_id.to_be_bytes());
    bytes_written += 2;

    let mut rtp_flags_octet = 0u8;
    if ir_data.dyn_rtp_marker {
        rtp_flags_octet |= P1_IR_DYN_RTP_FLAGS_MARKER_BIT_MASK;
    }
    if ir_data.ts_stride.is_some() {
        rtp_flags_octet |= P1_IR_DYN_RTP_FLAGS_TS_STRIDE_BIT_MASK;
    }
    out[bytes_written] = rtp_flags_octet;
    bytes_written += 1;

    if let Some(stride_val) = ir_data.ts_stride {
        out[bytes_written..bytes_written + 4].copy_from_slice(&stride_val.to_be_bytes());
        bytes_written += 4;
    }

    // Determine start of core packet (for CRC calculation)
    let core_packet_start_in_out = if ir_data.cid > 0 && ir_data.cid <= 15 {
        1
    } else {
        0
    };
    // CRC payload starts from ProfileID byte relative to the overall `out` buffer.
    // ProfileID is at (core_packet_start_in_out + 1) because PacketType is the first byte of core.
    let crc_payload_start_in_out = core_packet_start_in_out + 1;
    // CRC payload ends just before where the CRC itself will be written.
    // `bytes_written` currently points to where the CRC will be written.
    let crc_payload_end_in_out = bytes_written;

    let calculated_crc8 =
        crc_calculators.crc8(&out[crc_payload_start_in_out..crc_payload_end_in_out]);
    out[bytes_written] = calculated_crc8;
    bytes_written += 1;

    debug_assert!(
        bytes_written == required_size,
        "IR packet actual written size {} differs from calculated required size {}",
        bytes_written,
        required_size
    );

    Ok(bytes_written)
}

/// Deserializes a ROHC Profile 1 IR (Initialization/Refresh) packet.
///
/// The input `core_packet_bytes` should be the ROHC packet content starting
/// with the ROHC packet type octet.
/// The `cid_from_engine` must be provided by the caller.
/// This function checks for and deserializes the optional TS_STRIDE extension
/// in the dynamic chain if the corresponding flag in RTP_Flags is set.
///
/// # Parameters
/// - `core_packet_bytes`: Byte slice of the core IR packet.
/// - `cid_from_engine`: The CID determined by the ROHC engine.
/// - `crc_calculators`: An instance of `CrcCalculators` for CRC-8 verification.
///
/// # Returns
/// The deserialized IR packet data.
///
/// # Errors
/// - [`RohcParsingError`] - Not enough data, invalid type, or CRC mismatch
pub fn deserialize_ir(
    core_packet_bytes: &[u8],
    cid_from_engine: ContextId,
    crc_calculators: &CrcCalculators,
) -> Result<IrPacket, RohcParsingError> {
    debug_assert!(!core_packet_bytes.is_empty(), "IR packet cannot be empty");

    let mut current_offset_for_fields = 0;

    if core_packet_bytes.is_empty() {
        return Err(RohcParsingError::NotEnoughData {
            needed: 1,
            got: 0,
            context: crate::error::ParseContext::IrPacketTypeOctet,
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
    let mut ts_stride_present_flag_for_crc_logic = false;

    if d_bit_set {
        dynamic_chain_len_for_crc = P1_BASE_DYNAMIC_CHAIN_LENGTH_BYTES;
        // Index of RTP_Flags within core_packet_bytes:
        // PacketType(1) + ProfileID(1) + StaticChain(16) + SN(2) + TS(4) + TTL(1) + IP_ID(2) = index 27
        const RTP_FLAGS_IDX_IN_CORE: usize = 1
            + 1
            + P1_STATIC_CHAIN_LENGTH_BYTES
            + P1_SN_LENGTH_BYTES
            + P1_TS_LENGTH_BYTES
            + 1
            + P1_IP_ID_LENGTH_BYTES;

        if core_packet_bytes.len() > RTP_FLAGS_IDX_IN_CORE {
            let rtp_flags_octet_val = core_packet_bytes[RTP_FLAGS_IDX_IN_CORE];
            if (rtp_flags_octet_val & P1_IR_DYN_RTP_FLAGS_TS_STRIDE_BIT_MASK) != 0 {
                dynamic_chain_len_for_crc += P1_TS_STRIDE_EXTENSION_LENGTH_BYTES;
                ts_stride_present_flag_for_crc_logic = true;
            }
        } else if P1_BASE_DYNAMIC_CHAIN_LENGTH_BYTES > 0 {
            return Err(RohcParsingError::NotEnoughData {
                needed: RTP_FLAGS_IDX_IN_CORE + 1,
                got: core_packet_bytes.len(),
                context: crate::error::ParseContext::IrPacketRtpFlags,
            });
        }
    }

    // CRC payload starts from ProfileID byte. current_offset_for_fields is at ProfileID.
    let crc_payload_start_index_in_core = current_offset_for_fields;
    let crc_payload_len_for_validation =
        1 + P1_STATIC_CHAIN_LENGTH_BYTES + dynamic_chain_len_for_crc; // ProfileID(1) + Static + Dyn
    let crc_octet_index_in_core = crc_payload_start_index_in_core + crc_payload_len_for_validation;

    if core_packet_bytes.len() <= crc_octet_index_in_core {
        return Err(RohcParsingError::NotEnoughData {
            needed: crc_octet_index_in_core + 1,
            got: core_packet_bytes.len(),
            context: crate::error::ParseContext::IrPacketCrcAndPayload,
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
            crc_type: crate::error::CrcType::Rohc8,
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
    let static_rtp_ssrc = Ssrc::new(u32::from_be_bytes([
        core_packet_bytes[current_offset_for_fields],
        core_packet_bytes[current_offset_for_fields + 1],
        core_packet_bytes[current_offset_for_fields + 2],
        core_packet_bytes[current_offset_for_fields + 3],
    ]));
    current_offset_for_fields += 4;

    let (
        dyn_rtp_sn,
        dyn_rtp_timestamp_val,
        dyn_rtp_marker,
        dyn_ip_ttl_val,
        dyn_ip_id_val,
        parsed_ts_stride,
    ) = if d_bit_set {
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
        let dyn_ip_ttl = core_packet_bytes[current_offset_for_fields];
        current_offset_for_fields += 1;
        let dyn_ip_id_val = u16::from_be_bytes([
            core_packet_bytes[current_offset_for_fields],
            core_packet_bytes[current_offset_for_fields + 1],
        ]);
        current_offset_for_fields += 2;
        let rtp_flags_octet_val = core_packet_bytes[current_offset_for_fields];
        current_offset_for_fields += 1;
        let marker = (rtp_flags_octet_val & P1_IR_DYN_RTP_FLAGS_MARKER_BIT_MASK) != 0;

        let mut temp_ts_stride = None;
        if ts_stride_present_flag_for_crc_logic {
            if core_packet_bytes.len()
                < current_offset_for_fields + P1_TS_STRIDE_EXTENSION_LENGTH_BYTES
            {
                return Err(RohcParsingError::NotEnoughData {
                    needed: current_offset_for_fields + P1_TS_STRIDE_EXTENSION_LENGTH_BYTES,
                    got: core_packet_bytes.len(),
                    context: crate::error::ParseContext::IrPacketTsStrideExtension,
                });
            }
            temp_ts_stride = Some(u32::from_be_bytes([
                core_packet_bytes[current_offset_for_fields],
                core_packet_bytes[current_offset_for_fields + 1],
                core_packet_bytes[current_offset_for_fields + 2],
                core_packet_bytes[current_offset_for_fields + 3],
            ]));
        }
        (
            sn,
            ts_val,
            marker,
            dyn_ip_ttl,
            dyn_ip_id_val,
            temp_ts_stride,
        )
    } else {
        (0, 0, false, DEFAULT_IPV4_TTL, 0, None)
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
        dyn_rtp_sn: SequenceNumber::new(dyn_rtp_sn),
        dyn_rtp_timestamp: Timestamp::new(dyn_rtp_timestamp_val),
        dyn_rtp_marker,
        dyn_ip_ttl: dyn_ip_ttl_val,
        dyn_ip_id: dyn_ip_id_val.into(),
        ts_stride: parsed_ts_stride,
    })
}

/// Serializes a ROHC Profile 1 UO-0 packet into provided buffer.
///
/// UO-0 packets are the most compact ROHC packet type, containing only sequence number
/// LSBs and CRC when all other fields (timestamp, IP-ID, marker) remain static.
/// Used for minimal compression overhead in stable RTP streams.
///
/// # Parameters
/// - `packet_data`: Data for the UO-0 packet.
/// - `out`: Output buffer to write the serialized packet into.
///
/// # Returns
/// The number of bytes written to the output buffer.
///
/// # Errors
/// - [`RohcBuildingError`] - Invalid field values for UO-0 packet
pub fn serialize_uo0(packet_data: &Uo0Packet, out: &mut [u8]) -> Result<usize, RohcBuildingError> {
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
            field: crate::error::Field::SnLsb,
            value: packet_data.sn_lsb as u32,
            max_bits: P1_UO0_SN_LSB_WIDTH_DEFAULT,
        });
    }
    if packet_data.crc3 > 0x07 {
        return Err(RohcBuildingError::InvalidFieldValueForBuild {
            field: crate::error::Field::Crc3,
            value: packet_data.crc3 as u32,
            max_bits: 3,
        });
    }

    let required_size = 1 + if packet_data.cid.is_some() && packet_data.cid.unwrap() > 0 {
        1
    } else {
        0
    };
    if out.len() < required_size {
        return Err(RohcBuildingError::InvalidFieldValueForBuild {
            field: crate::error::Field::BufferSize,
            value: out.len() as u32,
            max_bits: required_size as u8,
        });
    }

    let mut bytes_written = 0;

    if let Some(cid_val) = packet_data.cid {
        if cid_val > 0 && cid_val <= 15 {
            out[bytes_written] =
                ROHC_ADD_CID_FEEDBACK_PREFIX_VALUE | (*cid_val as u8 & ROHC_SMALL_CID_MASK);
            bytes_written += 1;
        } else if cid_val > 15 {
            return Err(RohcBuildingError::InvalidFieldValueForBuild {
                field: crate::error::Field::Cid,
                value: *cid_val as u32,
                max_bits: 4,
            });
        }
    }

    let core_byte = (packet_data.sn_lsb << 3) | packet_data.crc3;
    out[bytes_written] = core_byte;
    bytes_written += 1;

    debug_assert!(
        bytes_written == required_size,
        "UO-0 packet actual written size {} differs from calculated required size {}",
        bytes_written,
        required_size
    );

    Ok(bytes_written)
}

/// Deserializes a ROHC Profile 1 UO-0 packet.
///
/// # Parameters
/// - `core_packet_data`: Byte slice of the core UO-0 packet (single byte).
/// - `cid_from_engine`: Optional CID if Add-CID was processed by the engine.
///
/// # Returns
/// The deserialized UO-0 packet data.
///
/// # Errors
/// - [`RohcParsingError`] - Incorrect length or invalid packet type
pub fn deserialize_uo0(
    core_packet_data: &[u8],
    cid_from_engine: Option<ContextId>,
) -> Result<Uo0Packet, RohcParsingError> {
    // Hot path optimization: Assume correct length since UO-0 is pre-discriminated
    debug_assert_eq!(
        core_packet_data.len(),
        1,
        "UO-0 core packet must be exactly 1 byte"
    );

    // Fast path: Skip runtime length check for hot path performance
    // Length is guaranteed by packet discrimination at engine level
    let packet_byte = unsafe { *core_packet_data.get_unchecked(0) };

    // Debug verification of discriminator (removed in release builds)
    debug_assert_eq!(packet_byte & 0x80, 0, "UO-0 discriminator check failed");

    // Optimized bit extraction using constants
    let sn_lsb_val = (packet_byte >> 3) & 0x0F; // 4 bits mask for P1_UO0_SN_LSB_WIDTH_DEFAULT
    let crc3_val = packet_byte & 0x07;

    debug_assert!(sn_lsb_val < 16, "SN LSB value {} out of range", sn_lsb_val);
    debug_assert!(crc3_val <= 7, "CRC3 value {} out of range", crc3_val);

    Ok(Uo0Packet {
        cid: cid_from_engine,
        sn_lsb: sn_lsb_val,
        crc3: crc3_val,
    })
}

/// Serializes a ROHC Profile 1 UO-1-SN packet into provided buffer.
///
/// UO-1-SN packets compress sequence number changes with marker bit updates when
/// timestamp remains predictable (following established stride). Provides efficient
/// compression for RTP streams with consistent timing but changing voice activity.
///
/// # Parameters
/// - `packet_data`: Data for the UO-1-SN packet.
/// - `out`: Output buffer to write the serialized packet into.
///
/// # Returns
/// The number of bytes written to the output buffer.
///
/// # Errors
/// - [`RohcBuildingError`] - Invalid field values for UO-1-SN packet
pub fn serialize_uo1_sn(
    packet_data: &Uo1Packet,
    out: &mut [u8],
) -> Result<usize, RohcBuildingError> {
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
            field: crate::error::Field::NumSnLsbBits,
            value: packet_data.num_sn_lsb_bits as u32,
            max_bits: P1_UO1_SN_LSB_WIDTH_DEFAULT,
        });
    }
    if packet_data.sn_lsb > 0xFF {
        return Err(RohcBuildingError::InvalidFieldValueForBuild {
            field: crate::error::Field::SnLsb,
            value: packet_data.sn_lsb as u32,
            max_bits: 8,
        });
    }

    let required_size = 3 + if packet_data.cid.is_some() && packet_data.cid.unwrap() > 0 {
        1
    } else {
        0
    };
    if out.len() < required_size {
        return Err(RohcBuildingError::InvalidFieldValueForBuild {
            field: crate::error::Field::BufferSize,
            value: out.len() as u32,
            max_bits: required_size as u8,
        });
    }

    let mut bytes_written = 0;

    if let Some(cid_val) = packet_data.cid {
        if cid_val > 0 && cid_val <= 15 {
            out[bytes_written] =
                ROHC_ADD_CID_FEEDBACK_PREFIX_VALUE | (*cid_val as u8 & ROHC_SMALL_CID_MASK);
            bytes_written += 1;
        } else if cid_val > 15 {
            return Err(RohcBuildingError::InvalidFieldValueForBuild {
                field: crate::error::Field::Cid,
                value: *cid_val as u32,
                max_bits: 4,
            });
        }
    }

    let type_octet = P1_UO_1_SN_PACKET_TYPE_PREFIX
        | (if packet_data.marker {
            P1_UO_1_SN_MARKER_BIT_MASK
        } else {
            0
        });

    out[bytes_written] = type_octet;
    bytes_written += 1;
    out[bytes_written] = packet_data.sn_lsb as u8;
    bytes_written += 1;
    out[bytes_written] = packet_data.crc8;
    bytes_written += 1;

    debug_assert!(
        bytes_written == required_size,
        "UO-1-SN packet actual written size {} differs from calculated required size {}",
        bytes_written,
        required_size
    );

    Ok(bytes_written)
}

/// Deserializes a ROHC Profile 1 UO-1-SN packet.
///
/// # Parameters
/// - `core_packet_bytes`: Byte slice of the core UO-1-SN packet.
///
/// # Returns
/// The deserialized UO-1-SN packet data.
///
/// # Errors
/// - [`RohcParsingError`] - Not enough data or invalid packet type
pub fn deserialize_uo1_sn(core_packet_bytes: &[u8]) -> Result<Uo1Packet, RohcParsingError> {
    let expected_len = 1 + (P1_UO1_SN_LSB_WIDTH_DEFAULT / 8) as usize + 1;
    debug_assert_eq!(expected_len, 3, "UO-1-SN should be 3 bytes");

    if core_packet_bytes.len() < expected_len {
        return Err(RohcParsingError::NotEnoughData {
            needed: expected_len,
            got: core_packet_bytes.len(),
            context: crate::error::ParseContext::Uo1SnPacketCore,
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

/// Serializes a ROHC Profile 1 UO-1-TS packet into provided buffer.
///
/// UO-1-TS packets compress timestamp changes when sequence number increments by one
/// and other fields remain static. Handles irregular timestamp patterns that don't
/// follow established stride, common in adaptive audio codecs.
///
/// # Parameters
/// - `packet_data`: Data for the UO-1-TS packet.
/// - `out`: Output buffer to write the serialized packet into.
///
/// # Returns
/// The number of bytes written to the output buffer.
///
/// # Errors
/// - [`RohcBuildingError`] - Invalid field values for UO-1-TS packet
pub fn serialize_uo1_ts(
    packet_data: &Uo1Packet,
    out: &mut [u8],
) -> Result<usize, RohcBuildingError> {
    let ts_lsb = packet_data
        .ts_lsb
        .ok_or(RohcBuildingError::ContextInsufficient {
            field: crate::error::Field::TsLsb,
        })?;
    let num_ts_bits =
        packet_data
            .num_ts_lsb_bits
            .ok_or(RohcBuildingError::ContextInsufficient {
                field: crate::error::Field::NumTsLsbBits,
            })?;

    debug_assert_eq!(
        num_ts_bits, P1_UO1_TS_LSB_WIDTH_DEFAULT,
        "UO-1-TS requires {} LSB bits, got {}",
        P1_UO1_TS_LSB_WIDTH_DEFAULT, num_ts_bits
    );

    if num_ts_bits != P1_UO1_TS_LSB_WIDTH_DEFAULT {
        return Err(RohcBuildingError::InvalidFieldValueForBuild {
            field: crate::error::Field::NumTsLsbBits,
            value: num_ts_bits as u32,
            max_bits: P1_UO1_TS_LSB_WIDTH_DEFAULT,
        });
    }

    let required_size = 4 + if packet_data.cid.is_some() && packet_data.cid.unwrap() > 0 {
        1
    } else {
        0
    };
    if out.len() < required_size {
        return Err(RohcBuildingError::InvalidFieldValueForBuild {
            field: crate::error::Field::BufferSize,
            value: out.len() as u32,
            max_bits: required_size as u8,
        });
    }

    let mut bytes_written = 0;

    if let Some(cid_val) = packet_data.cid {
        if cid_val > 0 && cid_val <= 15 {
            out[bytes_written] =
                ROHC_ADD_CID_FEEDBACK_PREFIX_VALUE | (*cid_val as u8 & ROHC_SMALL_CID_MASK);
            bytes_written += 1;
        } else if cid_val > 15 {
            return Err(RohcBuildingError::InvalidFieldValueForBuild {
                field: crate::error::Field::Cid,
                value: *cid_val as u32,
                max_bits: 4,
            });
        }
    }

    // P1_UO_1_TS_DISCRIMINATOR (0b11110010) has marker bit as 0.
    // P1_UO_1_TS_TYPE_MASK (0b11111110) is used to clear existing marker.
    // Then OR with actual marker.
    let type_octet = (P1_UO_1_TS_DISCRIMINATOR & P1_UO_1_TS_TYPE_MASK)
        | (if packet_data.marker {
            P1_UO_1_TS_MARKER_BIT_MASK
        } else {
            0
        });
    out[bytes_written] = type_octet;
    bytes_written += 1;
    out[bytes_written..bytes_written + 2].copy_from_slice(&ts_lsb.to_be_bytes());
    bytes_written += 2;
    out[bytes_written] = packet_data.crc8;
    bytes_written += 1;

    debug_assert!(
        bytes_written == required_size,
        "UO-1-TS packet actual written size {} differs from calculated required size {}",
        bytes_written,
        required_size
    );

    Ok(bytes_written)
}

/// Deserializes a ROHC Profile 1 UO-1-TS packet.
///
/// # Parameters
/// - `core_packet_bytes`: Byte slice of the core UO-1-TS packet.
///
/// # Returns
/// The deserialized UO-1-TS packet data.
///
/// # Errors
/// - [`RohcParsingError`] - Not enough data or invalid packet type
pub fn deserialize_uo1_ts(core_packet_bytes: &[u8]) -> Result<Uo1Packet, RohcParsingError> {
    let expected_len = 1 + (P1_UO1_TS_LSB_WIDTH_DEFAULT / 8) as usize + 1;
    debug_assert_eq!(expected_len, 4, "UO-1-TS should be 4 bytes");

    if core_packet_bytes.len() < expected_len {
        return Err(RohcParsingError::NotEnoughData {
            needed: expected_len,
            got: core_packet_bytes.len(),
            context: crate::error::ParseContext::Uo1TsPacketCore,
        });
    }

    let type_octet = core_packet_bytes[0];
    // Check if base type (1111001x & 11111110 = 11110010) matches
    if (type_octet & P1_UO_1_TS_TYPE_MASK) != (P1_UO_1_TS_DISCRIMINATOR & P1_UO_1_TS_TYPE_MASK) {
        return Err(RohcParsingError::InvalidPacketType {
            discriminator: type_octet,
            profile_id: Some(RohcProfile::RtpUdpIp.into()),
        });
    }

    let marker_bit_set = (type_octet & P1_UO_1_TS_MARKER_BIT_MASK) != 0;
    let ts_lsb_val = u16::from_be_bytes([core_packet_bytes[1], core_packet_bytes[2]]);
    let received_crc8 = core_packet_bytes[3];

    Ok(Uo1Packet {
        cid: None,
        sn_lsb: 0,
        num_sn_lsb_bits: 0,
        marker: marker_bit_set,
        ts_lsb: Some(ts_lsb_val),
        num_ts_lsb_bits: Some(P1_UO1_TS_LSB_WIDTH_DEFAULT),
        ip_id_lsb: None,
        num_ip_id_lsb_bits: None,
        ts_scaled: None,
        crc8: received_crc8,
    })
}

/// Serializes a ROHC Profile 1 UO-1-ID packet into provided buffer.
///
/// UO-1-ID packets compress IP identification field changes when sequence number
/// increments by one and timestamp follows established stride. Used for streams
/// where IP fragmentation characteristics change but timing remains predictable.
///
/// # Parameters
/// - `packet_data`: Data for the UO-1-ID packet.
/// - `out`: Output buffer to write the serialized packet into.
///
/// # Returns
/// The number of bytes written to the output buffer.
///
/// # Errors
/// - [`RohcBuildingError`] - Invalid field values for UO-1-ID packet
pub fn serialize_uo1_id(
    packet_data: &Uo1Packet,
    out: &mut [u8],
) -> Result<usize, RohcBuildingError> {
    let ip_id_lsb = packet_data
        .ip_id_lsb
        .ok_or(RohcBuildingError::ContextInsufficient {
            field: crate::error::Field::IpIdLsb,
        })?;
    let num_ip_id_bits =
        packet_data
            .num_ip_id_lsb_bits
            .ok_or(RohcBuildingError::ContextInsufficient {
                field: crate::error::Field::NumIpIdLsbBits,
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
            field: crate::error::Field::NumIpIdLsbBits,
            value: num_ip_id_bits as u32,
            max_bits: P1_UO1_IPID_LSB_WIDTH_DEFAULT,
        });
    }
    if ip_id_lsb > 0xFF {
        return Err(RohcBuildingError::InvalidFieldValueForBuild {
            field: crate::error::Field::IpIdLsb,
            value: ip_id_lsb as u32,
            max_bits: 8,
        });
    }

    let required_size = 3 + if packet_data.cid.is_some() && packet_data.cid.unwrap() > 0 {
        1
    } else {
        0
    };
    if out.len() < required_size {
        return Err(RohcBuildingError::InvalidFieldValueForBuild {
            field: crate::error::Field::BufferSize,
            value: out.len() as u32,
            max_bits: required_size as u8,
        });
    }

    let mut bytes_written = 0;

    if let Some(cid_val) = packet_data.cid {
        if cid_val > 0 && cid_val <= 15 {
            out[bytes_written] =
                ROHC_ADD_CID_FEEDBACK_PREFIX_VALUE | (*cid_val as u8 & ROHC_SMALL_CID_MASK);
            bytes_written += 1;
        } else if cid_val > 15 {
            return Err(RohcBuildingError::InvalidFieldValueForBuild {
                field: crate::error::Field::Cid,
                value: *cid_val as u32,
                max_bits: 4,
            });
        }
    }

    let type_octet = P1_UO_1_ID_DISCRIMINATOR;
    out[bytes_written] = type_octet;
    bytes_written += 1;
    out[bytes_written] = ip_id_lsb as u8;
    bytes_written += 1;
    out[bytes_written] = packet_data.crc8;
    bytes_written += 1;

    debug_assert!(
        bytes_written == required_size,
        "UO-1-ID packet actual written size {} differs from calculated required size {}",
        bytes_written,
        required_size
    );

    Ok(bytes_written)
}

/// Deserializes a ROHC Profile 1 UO-1-ID packet.
///
/// # Parameters
/// - `core_packet_bytes`: Byte slice of the core UO-1-ID packet.
///
/// # Returns
/// The deserialized UO-1-ID packet data.
///
/// # Errors
/// - [`RohcParsingError`] - Not enough data or invalid packet type
pub fn deserialize_uo1_id(core_packet_bytes: &[u8]) -> Result<Uo1Packet, RohcParsingError> {
    let expected_len = 1 + (P1_UO1_IPID_LSB_WIDTH_DEFAULT / 8) as usize + 1;
    debug_assert_eq!(expected_len, 3, "UO-1-ID should be 3 bytes");

    if core_packet_bytes.len() < expected_len {
        return Err(RohcParsingError::NotEnoughData {
            needed: expected_len,
            got: core_packet_bytes.len(),
            context: crate::error::ParseContext::Uo1IdPacketCore,
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
        marker: false, // UO-1-ID does not convey marker
        ts_lsb: None,
        num_ts_lsb_bits: None,
        ip_id_lsb: Some(ip_id_lsb_val as u16),
        num_ip_id_lsb_bits: Some(P1_UO1_IPID_LSB_WIDTH_DEFAULT),
        ts_scaled: None,
        crc8: received_crc8,
    })
}

/// Serializes a ROHC Profile 1 UO-1-RTP packet into provided buffer.
///
/// UO-1-RTP packets use scaled timestamp encoding for efficient compression when
/// timestamp changes follow established stride patterns. Contains TS_SCALED field
/// representing timestamp delta as a multiple of stride for optimal compression.
///
/// # Parameters
/// - `packet_data`: Data for the UO-1-RTP packet.
/// - `out`: Output buffer to write the serialized packet into.
///
/// # Returns
/// The number of bytes written to the output buffer.
///
/// # Errors
/// - [`RohcBuildingError`] - Invalid field values for UO-1-RTP packet
pub fn serialize_uo1_rtp(
    packet_data: &Uo1Packet,
    out: &mut [u8],
) -> Result<usize, RohcBuildingError> {
    let ts_scaled_val = packet_data
        .ts_scaled
        .ok_or(RohcBuildingError::ContextInsufficient {
            field: crate::error::Field::TsScaled,
        })?;

    debug_assert!(
        ts_scaled_val <= P1_TS_SCALED_MAX_VALUE as u8,
        "TS_SCALED value {} too large",
        ts_scaled_val
    );

    let required_size = 3 + if packet_data.cid.is_some() && packet_data.cid.unwrap() > 0 {
        1
    } else {
        0
    };
    if out.len() < required_size {
        return Err(RohcBuildingError::InvalidFieldValueForBuild {
            field: crate::error::Field::BufferSize,
            value: out.len() as u32,
            max_bits: required_size as u8,
        });
    }

    let mut bytes_written = 0;

    if let Some(cid_val) = packet_data.cid {
        if cid_val > 0 && cid_val <= 15 {
            out[bytes_written] =
                ROHC_ADD_CID_FEEDBACK_PREFIX_VALUE | (*cid_val as u8 & ROHC_SMALL_CID_MASK);
            bytes_written += 1;
        } else if cid_val > 15 {
            return Err(RohcBuildingError::InvalidFieldValueForBuild {
                field: crate::error::Field::Cid,
                value: *cid_val as u32,
                max_bits: 4,
            });
        }
    }

    let type_octet = P1_UO_1_RTP_DISCRIMINATOR_BASE
        | (if packet_data.marker {
            P1_UO_1_RTP_MARKER_BIT_MASK
        } else {
            0
        });

    out[bytes_written] = type_octet;
    bytes_written += 1;
    out[bytes_written] = ts_scaled_val;
    bytes_written += 1;
    out[bytes_written] = packet_data.crc8;
    bytes_written += 1;

    debug_assert!(
        bytes_written == required_size,
        "UO-1-RTP packet actual written size {} differs from calculated required size {}",
        bytes_written,
        required_size
    );

    Ok(bytes_written)
}

/// Deserializes a ROHC Profile 1 UO-1-RTP packet.
///
/// # Parameters
/// - `core_packet_bytes`: Byte slice of the core UO-1-RTP packet.
///
/// # Returns
/// The deserialized UO-1-RTP packet data.
///
/// # Errors
/// - [`RohcParsingError`] - Not enough data or invalid packet type
pub fn deserialize_uo1_rtp(core_packet_bytes: &[u8]) -> Result<Uo1Packet, RohcParsingError> {
    let expected_len = 3;
    debug_assert_eq!(expected_len, 3, "UO-1-RTP should be 3 bytes");

    if core_packet_bytes.len() < expected_len {
        return Err(RohcParsingError::NotEnoughData {
            needed: expected_len,
            got: core_packet_bytes.len(),
            context: crate::error::ParseContext::Uo1RtpPacketCore,
        });
    }

    let type_octet = core_packet_bytes[0];

    if (type_octet & !P1_UO_1_RTP_MARKER_BIT_MASK) != P1_UO_1_RTP_DISCRIMINATOR_BASE {
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
    context_ssrc: Ssrc,
    sn_for_crc: SequenceNumber,
    ts_for_crc: Timestamp,
    marker_for_crc: bool,
) -> [u8; P1_UO_CRC_INPUT_LENGTH_BYTES] {
    debug_assert_eq!(
        P1_UO_CRC_INPUT_LENGTH_BYTES, 11,
        "CRC input should be 11 bytes"
    );

    let mut crc_input = [0u8; P1_UO_CRC_INPUT_LENGTH_BYTES];

    crc_input[0..4].copy_from_slice(&context_ssrc.to_be_bytes());
    crc_input[4..6].copy_from_slice(&sn_for_crc.0.to_be_bytes());
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
    context_ssrc: Ssrc,
    sn_for_crc: SequenceNumber,
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
    crc_input[4..6].copy_from_slice(&sn_for_crc.0.to_be_bytes());
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
        P1_UO_1_RTP_DISCRIMINATOR_BASE, P1_UO_1_RTP_MARKER_BIT_MASK, P1_UO_1_TS_DISCRIMINATOR,
        P1_UO_1_TS_MARKER_BIT_MASK, P1_UO_1_TS_TYPE_MASK,
    };

    const TEST_IR_BUF_SIZE: usize = 64;
    const TEST_UO_BUF_SIZE: usize = 16; // Sufficient for UO-0, UO-1 packets

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
    fn deserialize_rtp_udp_ipv4_headers_valid() {
        let packet_bytes = build_sample_rtp_packet_bytes(123, 0x12345678, 1000);
        let headers = deserialize_rtp_udp_ipv4_headers(&packet_bytes).unwrap();
        assert_eq!(headers.rtp_sequence_number, 123);
        assert_eq!(headers.rtp_timestamp, 1000);
    }

    #[test]
    fn deserialize_rtp_udp_ipv4_headers_too_short() {
        let short_packet = vec![0x45, 0x00];
        let result = deserialize_rtp_udp_ipv4_headers(&short_packet);
        assert!(
            matches!(result, Err(RohcParsingError::NotEnoughData {needed, got, ..}) if needed == IPV4_MIN_HEADER_LENGTH_BYTES && got == 2)
        );
    }

    #[test]
    fn build_and_parse_ir_packet_cid0() {
        let crc_calculators = CrcCalculators::new();
        let ir_content = IrPacket {
            cid: 0.into(),
            profile_id: RohcProfile::RtpUdpIp,
            static_ip_src: "1.1.1.1".parse().unwrap(),
            static_ip_dst: "2.2.2.2".parse().unwrap(),
            static_udp_src_port: 100,
            static_udp_dst_port: 200,
            static_rtp_ssrc: 0xABC.into(),
            dyn_rtp_sn: 10.into(),
            dyn_rtp_timestamp: 100.into(),
            dyn_rtp_marker: true,
            dyn_ip_ttl: 64,
            dyn_ip_id: 0.into(),
            ts_stride: None,
            crc8: 0,
        };
        let mut buf = [0u8; TEST_IR_BUF_SIZE];
        let len = serialize_ir(&ir_content, &crc_calculators, &mut buf).unwrap();
        let built_bytes_slice = &buf[..len];

        assert_eq!(built_bytes_slice.len(), 29);
        assert_eq!(built_bytes_slice[0], P1_ROHC_IR_PACKET_TYPE_WITH_DYN);

        let parsed_ir = deserialize_ir(built_bytes_slice, 0.into(), &crc_calculators).unwrap();
        assert_eq!(parsed_ir.cid, 0);
        assert_eq!(parsed_ir.static_rtp_ssrc, ir_content.static_rtp_ssrc);
        assert_eq!(parsed_ir.dyn_rtp_sn, 10);
        assert_eq!(parsed_ir.dyn_rtp_timestamp, 100);
        assert_eq!(parsed_ir.dyn_rtp_marker, ir_content.dyn_rtp_marker);
        assert_eq!(parsed_ir.ts_stride, None);
        assert_eq!(parsed_ir.crc8, built_bytes_slice.last().copied().unwrap());
    }

    #[test]
    fn build_and_parse_ir_packet_cid0_with_ts_stride() {
        let crc_calculators = CrcCalculators::new();
        let ir_content = IrPacket {
            cid: 0.into(),
            profile_id: RohcProfile::RtpUdpIp,
            static_ip_src: "1.1.1.1".parse().unwrap(),
            static_ip_dst: "2.2.2.2".parse().unwrap(),
            static_udp_src_port: 100,
            static_udp_dst_port: 200,
            static_rtp_ssrc: 0xABC.into(),
            dyn_rtp_sn: 10.into(),
            dyn_rtp_timestamp: 100.into(),
            dyn_rtp_marker: false,
            dyn_ip_ttl: 64,
            dyn_ip_id: 0.into(),
            ts_stride: Some(160),
            crc8: 0,
        };
        let mut buf = [0u8; TEST_IR_BUF_SIZE];
        let len = serialize_ir(&ir_content, &crc_calculators, &mut buf).unwrap();
        let built_bytes_slice = &buf[..len];

        assert_eq!(built_bytes_slice.len(), 33);
        assert_eq!(built_bytes_slice[0], P1_ROHC_IR_PACKET_TYPE_WITH_DYN);

        let rtp_flags_octet_idx_in_core = 27;
        assert_eq!(
            built_bytes_slice[rtp_flags_octet_idx_in_core] & P1_IR_DYN_RTP_FLAGS_TS_STRIDE_BIT_MASK,
            P1_IR_DYN_RTP_FLAGS_TS_STRIDE_BIT_MASK,
            "TS Stride bit not set in IR"
        );

        let parsed_ir = deserialize_ir(built_bytes_slice, 0.into(), &crc_calculators).unwrap();
        assert_eq!(parsed_ir.cid, 0);
        assert_eq!(parsed_ir.static_rtp_ssrc, ir_content.static_rtp_ssrc);
        assert_eq!(parsed_ir.dyn_rtp_sn, 10);
        assert_eq!(parsed_ir.dyn_rtp_timestamp, 100);
        assert_eq!(parsed_ir.dyn_rtp_marker, ir_content.dyn_rtp_marker);
        assert_eq!(parsed_ir.ts_stride, Some(160));
        assert_eq!(parsed_ir.crc8, built_bytes_slice.last().copied().unwrap());
    }

    #[test]
    fn build_and_parse_ir_packet_small_cid() {
        let crc_calculators = CrcCalculators::new();
        let ir_content_ts_val: u32 = 50;
        let ir_content = IrPacket {
            cid: 5.into(),
            dyn_rtp_timestamp: ir_content_ts_val.into(),
            profile_id: RohcProfile::RtpUdpIp,
            static_ip_src: "0.0.0.0".parse().unwrap(),
            static_ip_dst: "0.0.0.0".parse().unwrap(),
            static_udp_src_port: 0,
            static_udp_dst_port: 0,
            static_rtp_ssrc: 0.into(),
            dyn_rtp_sn: 0.into(),
            dyn_rtp_marker: false,
            dyn_ip_ttl: 64,
            dyn_ip_id: 0.into(),
            ts_stride: None,
            crc8: 0,
        };
        let mut buf = [0u8; TEST_IR_BUF_SIZE];
        let len = serialize_ir(&ir_content, &crc_calculators, &mut buf).unwrap();
        let built_bytes_slice = &buf[..len];

        assert_eq!(built_bytes_slice.len(), 30);
        assert_eq!(built_bytes_slice[0], ROHC_ADD_CID_FEEDBACK_PREFIX_VALUE | 5);
        assert_eq!(built_bytes_slice[1], P1_ROHC_IR_PACKET_TYPE_WITH_DYN);

        let parsed_ir =
            deserialize_ir(&built_bytes_slice[1..], 5.into(), &crc_calculators).unwrap();
        assert_eq!(parsed_ir.cid, 5);
        assert_eq!(parsed_ir.dyn_rtp_timestamp, ir_content_ts_val);
        assert_eq!(parsed_ir.static_rtp_ssrc, 0);
        assert_eq!(parsed_ir.dyn_rtp_sn, 0);
        assert_eq!(parsed_ir.ts_stride, None);
    }

    #[test]
    fn parse_ir_packet_crc_mismatch() {
        let crc_calculators = CrcCalculators::new();
        let ir_content = IrPacket {
            cid: 0.into(),
            dyn_rtp_timestamp: 100.into(),
            ..Default::default()
        };
        let mut buf = [0u8; TEST_IR_BUF_SIZE];
        let len = serialize_ir(&ir_content, &crc_calculators, &mut buf).unwrap();
        let crc_idx = len - 1;
        buf[crc_idx] = buf[crc_idx].wrapping_add(1);
        let built_bytes_slice = &buf[..len];

        let result = deserialize_ir(built_bytes_slice, 0.into(), &crc_calculators);
        assert!(matches!(result, Err(RohcParsingError::CrcMismatch { .. })));
    }

    #[test]
    fn build_and_parse_uo0_packet_cid0() {
        let uo0_data = Uo0Packet {
            cid: None,
            sn_lsb: 0x0A,
            crc3: 0x05,
        };
        let mut buf = [0u8; TEST_UO_BUF_SIZE];
        let len = serialize_uo0(&uo0_data, &mut buf).unwrap();
        let built_bytes_slice = &buf[..len];

        assert_eq!(built_bytes_slice.len(), 1);
        assert_eq!(built_bytes_slice[0], (0x0A << 3) | 0x05);

        let parsed = deserialize_uo0(built_bytes_slice, None).unwrap();
        assert_eq!(parsed.sn_lsb, 0x0A);
        assert_eq!(parsed.crc3, 0x05);
        assert_eq!(parsed.cid, None);
    }

    #[test]
    fn build_and_parse_uo0_packet_small_cid() {
        let uo0_data = Uo0Packet {
            cid: Some(ContextId::new(3)),
            sn_lsb: 0x01,
            crc3: 0x02,
        };
        let mut buf = [0u8; TEST_UO_BUF_SIZE];
        let len = serialize_uo0(&uo0_data, &mut buf).unwrap();
        let built_bytes_slice = &buf[..len];

        assert_eq!(built_bytes_slice.len(), 2);
        assert_eq!(built_bytes_slice[0], ROHC_ADD_CID_FEEDBACK_PREFIX_VALUE | 3);
        assert_eq!(built_bytes_slice[1], (0x01 << 3) | 0x02);

        let parsed = deserialize_uo0(&built_bytes_slice[1..], Some(3.into())).unwrap();
        assert_eq!(parsed.sn_lsb, 0x01);
        assert_eq!(parsed.crc3, 0x02);
        assert_eq!(parsed.cid, Some(3.into()));
    }

    #[test]
    fn build_and_parse_uo1_sn_packet_cid0_marker_false() {
        let uo1_sn_data = Uo1Packet {
            cid: None,
            num_sn_lsb_bits: P1_UO1_SN_LSB_WIDTH_DEFAULT,
            sn_lsb: 0xAB,
            marker: false,
            crc8: 0xCD,
            ..Default::default()
        };
        let mut buf = [0u8; TEST_UO_BUF_SIZE];
        let len = serialize_uo1_sn(&uo1_sn_data, &mut buf).unwrap();
        let built_bytes_slice = &buf[..len];

        assert_eq!(built_bytes_slice.len(), 3);
        assert_eq!(built_bytes_slice[0], P1_UO_1_SN_PACKET_TYPE_PREFIX);
        assert_eq!(built_bytes_slice[1], 0xAB);
        assert_eq!(built_bytes_slice[2], 0xCD);

        let parsed = deserialize_uo1_sn(built_bytes_slice).unwrap();
        assert_eq!(parsed.sn_lsb, 0xAB);
        assert!(!parsed.marker);
        assert_eq!(parsed.crc8, 0xCD);
    }

    #[test]
    fn build_and_parse_uo1_ts_packet_cid0_marker_true() {
        let uo1_ts_data = Uo1Packet {
            cid: None,
            num_ts_lsb_bits: Some(P1_UO1_TS_LSB_WIDTH_DEFAULT),
            ts_lsb: Some(0x1234),
            marker: true,
            crc8: 0x56,
            ..Default::default()
        };
        let mut buf = [0u8; TEST_UO_BUF_SIZE];
        let len = serialize_uo1_ts(&uo1_ts_data, &mut buf).unwrap();
        let built_bytes_slice = &buf[..len];

        assert_eq!(built_bytes_slice.len(), 4);
        assert_eq!(
            built_bytes_slice[0],
            (P1_UO_1_TS_DISCRIMINATOR & P1_UO_1_TS_TYPE_MASK) | P1_UO_1_TS_MARKER_BIT_MASK
        );
        assert_eq!(built_bytes_slice[1], 0x12);
        assert_eq!(built_bytes_slice[2], 0x34);
        assert_eq!(built_bytes_slice[3], 0x56);

        let parsed = deserialize_uo1_ts(built_bytes_slice).unwrap();
        assert_eq!(parsed.ts_lsb, Some(0x1234));
        assert!(parsed.marker);
        assert_eq!(parsed.crc8, 0x56);
    }

    #[test]
    fn build_and_parse_uo1_id_packet_cid0() {
        let uo1_id_data = Uo1Packet {
            cid: None,
            num_ip_id_lsb_bits: Some(P1_UO1_IPID_LSB_WIDTH_DEFAULT),
            ip_id_lsb: Some(0x78),
            marker: false,
            crc8: 0x9A,
            ..Default::default()
        };
        let mut buf = [0u8; TEST_UO_BUF_SIZE];
        let len = serialize_uo1_id(&uo1_id_data, &mut buf).unwrap();
        let built_bytes_slice = &buf[..len];

        assert_eq!(built_bytes_slice.len(), 3);
        assert_eq!(built_bytes_slice[0], P1_UO_1_ID_DISCRIMINATOR);
        assert_eq!(built_bytes_slice[1], 0x78);
        assert_eq!(built_bytes_slice[2], 0x9A);

        let parsed = deserialize_uo1_id(built_bytes_slice).unwrap();
        assert_eq!(parsed.ip_id_lsb, Some(0x78));
        assert!(!parsed.marker);
        assert_eq!(parsed.crc8, 0x9A);
    }

    #[test]
    fn build_and_parse_uo1_rtp_packet_cid0_marker_false() {
        let uo1_rtp_data = Uo1Packet {
            cid: None,
            marker: false,
            ts_scaled: Some(123),
            crc8: 0xAB,
            ..Default::default()
        };
        let mut buf = [0u8; TEST_UO_BUF_SIZE];
        let len = serialize_uo1_rtp(&uo1_rtp_data, &mut buf).unwrap();
        let built_bytes_slice = &buf[..len];

        assert_eq!(built_bytes_slice.len(), 3);
        assert_eq!(built_bytes_slice[0], P1_UO_1_RTP_DISCRIMINATOR_BASE);
        assert_eq!(built_bytes_slice[1], 123);
        assert_eq!(built_bytes_slice[2], 0xAB);

        let parsed = deserialize_uo1_rtp(built_bytes_slice).unwrap();
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
        let mut buf = [0u8; TEST_UO_BUF_SIZE];
        let len = serialize_uo1_rtp(&uo1_rtp_data, &mut buf).unwrap();
        let built_bytes_slice = &buf[..len];

        assert_eq!(built_bytes_slice.len(), 3);
        assert_eq!(
            built_bytes_slice[0],
            P1_UO_1_RTP_DISCRIMINATOR_BASE | P1_UO_1_RTP_MARKER_BIT_MASK
        );
        assert_eq!(built_bytes_slice[1], 10);
        assert_eq!(built_bytes_slice[2], 0xCD);

        let parsed = deserialize_uo1_rtp(built_bytes_slice).unwrap();
        assert_eq!(parsed.ts_scaled, Some(10));
        assert!(parsed.marker);
        assert_eq!(parsed.crc8, 0xCD);
    }

    #[test]
    fn build_and_parse_uo1_rtp_packet_small_cid() {
        let uo1_rtp_data = Uo1Packet {
            cid: Some(5.into()),
            marker: false,
            ts_scaled: Some(255),
            crc8: 0xFE,
            ..Default::default()
        };
        let mut buf = [0u8; TEST_UO_BUF_SIZE];
        let len = serialize_uo1_rtp(&uo1_rtp_data, &mut buf).unwrap();
        let built_bytes_slice = &buf[..len];

        assert_eq!(built_bytes_slice.len(), 4);
        assert_eq!(built_bytes_slice[0], ROHC_ADD_CID_FEEDBACK_PREFIX_VALUE | 5);
        assert_eq!(built_bytes_slice[1], P1_UO_1_RTP_DISCRIMINATOR_BASE);
        assert_eq!(built_bytes_slice[2], 255);
        assert_eq!(built_bytes_slice[3], 0xFE);

        let parsed = deserialize_uo1_rtp(&built_bytes_slice[1..]).unwrap();
        assert_eq!(parsed.ts_scaled, Some(255));
        assert!(!parsed.marker);
        assert_eq!(parsed.crc8, 0xFE);
    }

    #[test]
    fn build_uo1_rtp_packet_missing_ts_scaled() {
        let uo1_rtp_data = Uo1Packet {
            cid: None,
            marker: false,
            ts_scaled: None,
            crc8: 0xAB,
            ..Default::default()
        };
        let mut buf = [0u8; TEST_UO_BUF_SIZE];
        let result = serialize_uo1_rtp(&uo1_rtp_data, &mut buf);
        assert!(
            matches!(result, Err(RohcBuildingError::ContextInsufficient { field, .. }) if field == crate::error::Field::TsScaled)
        );
    }

    #[test]
    fn parse_uo1_rtp_packet_too_short() {
        let short_packet = vec![P1_UO_1_RTP_DISCRIMINATOR_BASE, 123];
        let result = deserialize_uo1_rtp(&short_packet);
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
        let wrong_packet = vec![P1_UO_1_SN_PACKET_TYPE_PREFIX, 123, 0xAB];
        let result = deserialize_uo1_rtp(&wrong_packet);
        assert!(matches!(
            result,
            Err(RohcParsingError::InvalidPacketType { .. })
        ));
    }

    #[test]
    fn test_generic_uo_crc_input_payload() {
        let ssrc = 0x12345678.into();
        let sn_val = 0xABCDu16;
        let ts_val = 0xDEADBEEFu32;
        let marker = true;

        let ts_arg = ts_val.into();
        let sn_arg = sn_val.into();

        let payload = prepare_generic_uo_crc_input_payload(ssrc, sn_arg, ts_arg, marker);

        assert_eq!(payload.len(), 11);
        assert_eq!(&payload[0..4], &0x12345678u32.to_be_bytes());
        assert_eq!(&payload[4..6], &sn_val.to_be_bytes());
        assert_eq!(&payload[6..10], &ts_val.to_be_bytes());
        assert_eq!(payload[10], 0x01);
    }

    #[test]
    fn test_uo1_id_specific_crc_input_payload() {
        let ssrc = 0x87654321.into();
        let sn_val = 0x1234u16;
        let ts_val = 0xCAFEBABE_u32;
        let marker = false;
        let ip_id_lsb = 0x42u8;

        let ts_arg = ts_val.into();
        let sn_arg = sn_val.into();

        let payload =
            prepare_uo1_id_specific_crc_input_payload(ssrc, sn_arg, ts_arg, marker, ip_id_lsb);

        assert_eq!(payload.len(), 12);
        assert_eq!(&payload[0..4], &0x87654321u32.to_be_bytes());
        assert_eq!(&payload[4..6], &sn_val.to_be_bytes());
        assert_eq!(&payload[6..10], &ts_val.to_be_bytes());
        assert_eq!(payload[10], 0x00);
        assert_eq!(payload[11], ip_id_lsb);
    }
}
