//! IR (Initialization/Refresh) packet serialization and deserialization for Profile 1.
//!
//! This module handles the creation and parsing of IR packets, which carry static
//! and dynamic chain information for context initialization or refresh operations.
//! IR packets are used when establishing new contexts or recovering from errors.

use std::net::Ipv4Addr;

use crate::constants::{DEFAULT_IPV4_TTL, ROHC_ADD_CID_FEEDBACK_PREFIX_VALUE, ROHC_SMALL_CID_MASK};
use crate::crc::CrcCalculators;
use crate::error::{CrcType, Field, ParseContext, RohcBuildingError, RohcParsingError};
use crate::packet_defs::RohcProfile;
use crate::types::{ContextId, SequenceNumber, Ssrc, Timestamp};

use super::super::constants::*;
use super::super::packet_types::IrPacket;

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

    let required_size = 1
        + 1
        + P1_STATIC_CHAIN_LENGTH_BYTES
        + P1_BASE_DYNAMIC_CHAIN_LENGTH_BYTES
        + 1
        + if ir_data.cid > 0 && ir_data.cid <= 15 {
            1
        } else {
            0
        }
        + if ir_data.ts_stride.is_some() {
            P1_TS_STRIDE_EXTENSION_LENGTH_BYTES
        } else {
            0
        };

    if out.len() < required_size {
        return Err(RohcBuildingError::InvalidFieldValueForBuild {
            field: Field::BufferSize,
            value: out.len() as u32,
            max_bits: required_size as u8,
        });
    }

    if ir_data.cid > 0 && ir_data.cid <= 15 {
        out[bytes_written] =
            ROHC_ADD_CID_FEEDBACK_PREFIX_VALUE | (ir_data.cid.0 as u8 & ROHC_SMALL_CID_MASK);
        bytes_written += 1;
    } else if ir_data.cid > 15 {
        return Err(RohcBuildingError::InvalidFieldValueForBuild {
            field: Field::Cid,
            value: ir_data.cid.0 as u32,
            max_bits: 4,
        });
    }

    out[bytes_written] = P1_ROHC_IR_PACKET_TYPE_WITH_DYN;
    bytes_written += 1;

    let profile_id: u8 = ir_data.profile_id.into();
    if profile_id != u8::from(RohcProfile::RtpUdpIp) {
        return Err(RohcBuildingError::InvalidFieldValueForBuild {
            field: Field::ProfileId,
            value: profile_id as u32,
            max_bits: 8,
        });
    }
    out[bytes_written] = profile_id;
    bytes_written += 1;

    debug_assert!(
        bytes_written + 4 <= out.len(),
        "Buffer overflow: {} + 4 > {}",
        bytes_written,
        out.len()
    );

    out[bytes_written..bytes_written + 4].copy_from_slice(&ir_data.static_ip_src.octets());
    bytes_written += 4;

    debug_assert!(
        bytes_written + 4 <= out.len(),
        "Buffer overflow: {} + 4 > {}",
        bytes_written,
        out.len()
    );

    out[bytes_written..bytes_written + 4].copy_from_slice(&ir_data.static_ip_dst.octets());
    bytes_written += 4;

    debug_assert!(
        bytes_written + 2 <= out.len(),
        "Buffer overflow: {} + 2 > {}",
        bytes_written,
        out.len()
    );

    out[bytes_written..bytes_written + 2]
        .copy_from_slice(&ir_data.static_udp_src_port.to_be_bytes());
    bytes_written += 2;

    debug_assert!(
        bytes_written + 2 <= out.len(),
        "Buffer overflow: {} + 2 > {}",
        bytes_written,
        out.len()
    );

    out[bytes_written..bytes_written + 2]
        .copy_from_slice(&ir_data.static_udp_dst_port.to_be_bytes());
    bytes_written += 2;

    debug_assert!(
        bytes_written + 4 <= out.len(),
        "Buffer overflow: {} + 4 > {}",
        bytes_written,
        out.len()
    );

    out[bytes_written..bytes_written + 4].copy_from_slice(&ir_data.static_rtp_ssrc.to_be_bytes());
    bytes_written += 4;

    debug_assert!(
        bytes_written + 3 <= out.len(),
        "Buffer overflow: {} + 3 > {}",
        bytes_written,
        out.len()
    );

    out[bytes_written..bytes_written + 3].copy_from_slice(&[
        ir_data.static_rtp_payload_type,
        ir_data.static_rtp_extension as u8,
        ir_data.static_rtp_padding as u8,
    ]);
    bytes_written += 3;

    debug_assert!(
        bytes_written + 2 <= out.len(),
        "Buffer overflow: {} + 2 > {}",
        bytes_written,
        out.len()
    );

    out[bytes_written..bytes_written + 2].copy_from_slice(&ir_data.dyn_rtp_sn.to_be_bytes());
    bytes_written += 2;

    debug_assert!(
        bytes_written + 4 <= out.len(),
        "Buffer overflow: {} + 4 > {}",
        bytes_written,
        out.len()
    );

    out[bytes_written..bytes_written + 4].copy_from_slice(&ir_data.dyn_rtp_timestamp.to_be_bytes());
    bytes_written += 4;

    debug_assert!(
        bytes_written < out.len(),
        "Buffer overflow: {} + 1 > {}",
        bytes_written,
        out.len()
    );

    out[bytes_written] = ir_data.dyn_ip_ttl;
    bytes_written += 1;

    debug_assert!(
        bytes_written + 2 <= out.len(),
        "Buffer overflow: {} + 2 > {}",
        bytes_written,
        out.len()
    );

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

    let core_packet_start_in_out = if ir_data.cid > 0 && ir_data.cid <= 15 {
        1
    } else {
        0
    };
    let crc_payload_start_in_out = core_packet_start_in_out + 1;
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
pub(crate) fn deserialize_ir(
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
            context: ParseContext::IrPacketTypeOctet,
        });
    }
    let packet_type_octet = core_packet_bytes[current_offset_for_fields];
    current_offset_for_fields += 1;

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
                context: ParseContext::IrPacketRtpFlags,
            });
        }
    }

    let crc_payload_start_index_in_core = current_offset_for_fields;
    let crc_payload_len_for_validation =
        1 + P1_STATIC_CHAIN_LENGTH_BYTES + dynamic_chain_len_for_crc;
    let crc_octet_index_in_core = crc_payload_start_index_in_core + crc_payload_len_for_validation;

    if core_packet_bytes.len() <= crc_octet_index_in_core {
        return Err(RohcParsingError::NotEnoughData {
            needed: crc_octet_index_in_core + 1,
            got: core_packet_bytes.len(),
            context: ParseContext::IrPacketCrcAndPayload,
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
            crc_type: CrcType::Rohc8,
        });
    }

    let profile_octet = core_packet_bytes[current_offset_for_fields];
    if profile_octet != u8::from(RohcProfile::RtpUdpIp) {
        return Err(RohcParsingError::InvalidProfileId(profile_octet));
    }
    current_offset_for_fields += 1;

    debug_assert!(
        current_offset_for_fields + 4 <= core_packet_bytes.len(),
        "Buffer overflow: {} + 4 > {}",
        current_offset_for_fields,
        core_packet_bytes.len()
    );

    let static_ip_src = Ipv4Addr::new(
        core_packet_bytes[current_offset_for_fields],
        core_packet_bytes[current_offset_for_fields + 1],
        core_packet_bytes[current_offset_for_fields + 2],
        core_packet_bytes[current_offset_for_fields + 3],
    );
    current_offset_for_fields += 4;

    debug_assert!(
        current_offset_for_fields + 4 <= core_packet_bytes.len(),
        "Buffer overflow: {} + 4 > {}",
        current_offset_for_fields,
        core_packet_bytes.len()
    );

    let static_ip_dst = Ipv4Addr::new(
        core_packet_bytes[current_offset_for_fields],
        core_packet_bytes[current_offset_for_fields + 1],
        core_packet_bytes[current_offset_for_fields + 2],
        core_packet_bytes[current_offset_for_fields + 3],
    );
    current_offset_for_fields += 4;

    debug_assert!(
        current_offset_for_fields + 2 <= core_packet_bytes.len(),
        "Buffer overflow: {} + 2 > {}",
        current_offset_for_fields,
        core_packet_bytes.len()
    );

    let static_udp_src_port = u16::from_be_bytes([
        core_packet_bytes[current_offset_for_fields],
        core_packet_bytes[current_offset_for_fields + 1],
    ]);
    current_offset_for_fields += 2;

    debug_assert!(
        current_offset_for_fields + 2 <= core_packet_bytes.len(),
        "Buffer overflow: {} + 2 > {}",
        current_offset_for_fields,
        core_packet_bytes.len()
    );

    let static_udp_dst_port = u16::from_be_bytes([
        core_packet_bytes[current_offset_for_fields],
        core_packet_bytes[current_offset_for_fields + 1],
    ]);
    current_offset_for_fields += 2;

    debug_assert!(
        current_offset_for_fields + 4 <= core_packet_bytes.len(),
        "Buffer overflow: {} + 4 > {}",
        current_offset_for_fields,
        core_packet_bytes.len()
    );

    let static_rtp_ssrc = Ssrc::new(u32::from_be_bytes([
        core_packet_bytes[current_offset_for_fields],
        core_packet_bytes[current_offset_for_fields + 1],
        core_packet_bytes[current_offset_for_fields + 2],
        core_packet_bytes[current_offset_for_fields + 3],
    ]));
    current_offset_for_fields += 4;

    let rtp_fields = &core_packet_bytes[current_offset_for_fields..current_offset_for_fields + 3];
    let static_rtp_payload_type = rtp_fields[0];
    let static_rtp_extension = rtp_fields[1] == 1;
    let static_rtp_padding = rtp_fields[2] == 1;
    current_offset_for_fields += 3;

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
                    context: ParseContext::IrPacketTsStrideExtension,
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
        static_rtp_payload_type,
        static_rtp_extension,
        static_rtp_padding,
        dyn_rtp_sn: SequenceNumber::new(dyn_rtp_sn),
        dyn_rtp_timestamp: Timestamp::new(dyn_rtp_timestamp_val),
        dyn_rtp_marker,
        dyn_ip_ttl: dyn_ip_ttl_val,
        dyn_ip_id: dyn_ip_id_val.into(),
        ts_stride: parsed_ts_stride,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crc::CrcCalculators;

    #[test]
    fn p1_ir_roundtrip() {
        let crc_calculators = CrcCalculators::new();
        let ir_content = IrPacket {
            cid: 0.into(),
            ..Default::default()
        };

        let mut buf = [0u8; 256];
        let len = serialize_ir(&ir_content, &crc_calculators, &mut buf).unwrap();
        let built_bytes_slice = &buf[..len];

        let parsed_ir = deserialize_ir(built_bytes_slice, 0.into(), &crc_calculators).unwrap();
        assert_eq!(parsed_ir.cid, ir_content.cid);
    }
}
