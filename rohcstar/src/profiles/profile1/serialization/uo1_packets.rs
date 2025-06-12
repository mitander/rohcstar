//! UO-1 packet serialization and deserialization for Profile 1.
//!
//! This module handles the creation and parsing of UO-1 (Unidirectional Optimistic, Order 1)
//! packet variants: UO-1-SN, UO-1-TS, UO-1-ID, and UO-1-RTP. Each variant carries different
//! combinations of sequence number, timestamp, IP-ID, and marker bit information depending
//! on which fields have changed since the last packet.

use super::super::constants::*;
use super::super::packet_types::Uo1Packet;
use crate::constants::{ROHC_ADD_CID_FEEDBACK_PREFIX_VALUE, ROHC_SMALL_CID_MASK};
use crate::error::{Field, ParseContext, RohcBuildingError, RohcParsingError};
use crate::packet_defs::RohcProfile;
use crate::types::{SequenceNumber, Ssrc, Timestamp};

/// Serializes a ROHC Profile 1 UO-1-SN packet into provided buffer.
///
/// UO-1-SN packets compress sequence number changes with marker bit updates when
/// timestamp remains predictable (following established stride). Provides efficient
/// compression for RTP streams with consistent timing but changing voice activity.
///
/// # Parameters
/// - `packet_data`: UO-1 packet structure containing SN LSBs, marker bit, and CRC
/// - `out`: Output buffer to write serialized packet bytes
///
/// # Returns
/// - `Ok(usize)`: Number of bytes written to output buffer
/// - `Err(RohcBuildingError)`: Invalid field values or insufficient buffer space
pub(crate) fn serialize_uo1_sn(
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
            field: Field::NumSnLsbBits,
            value: packet_data.num_sn_lsb_bits as u32,
            max_bits: P1_UO1_SN_LSB_WIDTH_DEFAULT,
        });
    }
    if packet_data.sn_lsb > 0xFF {
        return Err(RohcBuildingError::InvalidFieldValueForBuild {
            field: Field::SnLsb,
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
            field: Field::BufferSize,
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
                field: Field::Cid,
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
/// Parses UO-1-SN packet format and extracts sequence number LSBs, marker bit,
/// and CRC value from the compressed packet structure.
///
/// # Parameters
/// - `core_packet_bytes`: Raw packet bytes excluding any CID encoding
///
/// # Returns
/// - `Ok(Uo1Packet)`: Parsed packet structure with extracted fields
/// - `Err(RohcParsingError)`: Invalid packet format or insufficient data
pub(crate) fn deserialize_uo1_sn(core_packet_bytes: &[u8]) -> Result<Uo1Packet, RohcParsingError> {
    let expected_len = 1 + (P1_UO1_SN_LSB_WIDTH_DEFAULT / 8) as usize + 1;
    debug_assert_eq!(expected_len, 3, "UO-1-SN should be 3 bytes");

    if core_packet_bytes.len() < expected_len {
        return Err(RohcParsingError::NotEnoughData {
            needed: expected_len,
            got: core_packet_bytes.len(),
            context: ParseContext::Uo1SnPacketCore,
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
/// - `packet_data`: UO-1 packet structure containing TS LSBs and CRC
/// - `out`: Output buffer to write serialized packet bytes
///
/// # Returns
/// - `Ok(usize)`: Number of bytes written to output buffer
/// - `Err(RohcBuildingError)`: Invalid field values or insufficient buffer space
pub(crate) fn serialize_uo1_ts(
    packet_data: &Uo1Packet,
    out: &mut [u8],
) -> Result<usize, RohcBuildingError> {
    let ts_lsb = packet_data
        .ts_lsb
        .ok_or(RohcBuildingError::ContextInsufficient {
            field: Field::TsLsb,
        })?;
    let num_ts_bits =
        packet_data
            .num_ts_lsb_bits
            .ok_or(RohcBuildingError::ContextInsufficient {
                field: Field::NumTsLsbBits,
            })?;

    debug_assert_eq!(
        num_ts_bits, P1_UO1_TS_LSB_WIDTH_DEFAULT,
        "UO-1-TS requires {} LSB bits, got {}",
        P1_UO1_TS_LSB_WIDTH_DEFAULT, num_ts_bits
    );

    if num_ts_bits != P1_UO1_TS_LSB_WIDTH_DEFAULT {
        return Err(RohcBuildingError::InvalidFieldValueForBuild {
            field: Field::NumTsLsbBits,
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
            field: Field::BufferSize,
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
                field: Field::Cid,
                value: *cid_val as u32,
                max_bits: 4,
            });
        }
    }

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
/// Parses UO-1-TS packet format and extracts timestamp LSBs and CRC value
/// from the compressed packet structure.
///
/// # Parameters
/// - `core_packet_bytes`: Raw packet bytes excluding any CID encoding
///
/// # Returns
/// - `Ok(Uo1Packet)`: Parsed packet structure with extracted timestamp fields
/// - `Err(RohcParsingError)`: Invalid packet format or insufficient data
pub(crate) fn deserialize_uo1_ts(core_packet_bytes: &[u8]) -> Result<Uo1Packet, RohcParsingError> {
    let expected_len = 1 + (P1_UO1_TS_LSB_WIDTH_DEFAULT / 8) as usize + 1;
    debug_assert_eq!(expected_len, 4, "UO-1-TS should be 4 bytes");

    if core_packet_bytes.len() < expected_len {
        return Err(RohcParsingError::NotEnoughData {
            needed: expected_len,
            got: core_packet_bytes.len(),
            context: ParseContext::Uo1TsPacketCore,
        });
    }

    let type_octet = core_packet_bytes[0];
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
/// - `packet_data`: UO-1 packet structure containing IP-ID LSBs and CRC
/// - `out`: Output buffer to write serialized packet bytes
///
/// # Returns
/// - `Ok(usize)`: Number of bytes written to output buffer
/// - `Err(RohcBuildingError)`: Invalid field values or insufficient buffer space
pub(crate) fn serialize_uo1_id(
    packet_data: &Uo1Packet,
    out: &mut [u8],
) -> Result<usize, RohcBuildingError> {
    let ip_id_lsb = packet_data
        .ip_id_lsb
        .ok_or(RohcBuildingError::ContextInsufficient {
            field: Field::IpIdLsb,
        })?;
    let num_ip_id_bits =
        packet_data
            .num_ip_id_lsb_bits
            .ok_or(RohcBuildingError::ContextInsufficient {
                field: Field::NumIpIdLsbBits,
            })?;

    debug_assert_eq!(
        num_ip_id_bits, P1_UO1_IP_ID_LSB_WIDTH_DEFAULT,
        "UO-1-ID requires {} LSB bits, got {}",
        P1_UO1_IP_ID_LSB_WIDTH_DEFAULT, num_ip_id_bits
    );
    debug_assert!(
        ip_id_lsb <= 0xFF,
        "IP-ID LSB value {} too large for 8 bits",
        ip_id_lsb
    );

    if num_ip_id_bits != P1_UO1_IP_ID_LSB_WIDTH_DEFAULT {
        return Err(RohcBuildingError::InvalidFieldValueForBuild {
            field: Field::NumIpIdLsbBits,
            value: num_ip_id_bits as u32,
            max_bits: P1_UO1_IP_ID_LSB_WIDTH_DEFAULT,
        });
    }
    if ip_id_lsb > 0xFF {
        return Err(RohcBuildingError::InvalidFieldValueForBuild {
            field: Field::IpIdLsb,
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
            field: Field::BufferSize,
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
                field: Field::Cid,
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
/// Parses UO-1-ID packet format and extracts IP identification LSBs and CRC value
/// from the compressed packet structure.
///
/// # Parameters
/// - `core_packet_bytes`: Raw packet bytes excluding any CID encoding
///
/// # Returns
/// - `Ok(Uo1Packet)`: Parsed packet structure with extracted IP-ID fields
/// - `Err(RohcParsingError)`: Invalid packet format or insufficient data
pub(crate) fn deserialize_uo1_id(core_packet_bytes: &[u8]) -> Result<Uo1Packet, RohcParsingError> {
    let expected_len = 1 + (P1_UO1_IP_ID_LSB_WIDTH_DEFAULT / 8) as usize + 1;
    debug_assert_eq!(expected_len, 3, "UO-1-ID should be 3 bytes");

    if core_packet_bytes.len() < expected_len {
        return Err(RohcParsingError::NotEnoughData {
            needed: expected_len,
            got: core_packet_bytes.len(),
            context: ParseContext::Uo1IdPacketCore,
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
        num_ip_id_lsb_bits: Some(P1_UO1_IP_ID_LSB_WIDTH_DEFAULT),
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
/// - `packet_data`: UO-1 packet structure containing TS_SCALED, marker bit, and CRC
/// - `out`: Output buffer to write serialized packet bytes
///
/// # Returns
/// - `Ok(usize)`: Number of bytes written to output buffer
/// - `Err(RohcBuildingError)`: Invalid field values or insufficient buffer space
pub(crate) fn serialize_uo1_rtp(
    packet_data: &Uo1Packet,
    out: &mut [u8],
) -> Result<usize, RohcBuildingError> {
    let ts_scaled_val = packet_data
        .ts_scaled
        .ok_or(RohcBuildingError::ContextInsufficient {
            field: Field::TsScaled,
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
            field: Field::BufferSize,
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
                field: Field::Cid,
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
/// Parses UO-1-RTP packet format and extracts scaled timestamp, marker bit,
/// and CRC value from the compressed packet structure.
///
/// # Parameters
/// - `core_packet_bytes`: Raw packet bytes excluding any CID encoding
///
/// # Returns
/// - `Ok(Uo1Packet)`: Parsed packet structure with extracted TS_SCALED fields
/// - `Err(RohcParsingError)`: Invalid packet format or insufficient data
pub(crate) fn deserialize_uo1_rtp(core_packet_bytes: &[u8]) -> Result<Uo1Packet, RohcParsingError> {
    let expected_len = 3;
    debug_assert_eq!(expected_len, 3, "UO-1-RTP should be 3 bytes");

    if core_packet_bytes.len() < expected_len {
        return Err(RohcParsingError::NotEnoughData {
            needed: expected_len,
            got: core_packet_bytes.len(),
            context: ParseContext::Uo1RtpPacketCore,
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

/// Prepares CRC input payload for generic UO packet validation.
///
/// Creates the standardized byte sequence used for CRC calculation in UO-0, UO-1-SN,
/// UO-1-TS, and UO-1-RTP packets. This payload represents the essential header fields
/// that must remain consistent between compressor and decompressor.
///
/// # Parameters
/// - `context_ssrc`: RTP SSRC from compressor context
/// - `sn_for_crc`: Sequence number to include in CRC calculation
/// - `ts_for_crc`: Timestamp to include in CRC calculation
/// - `marker_for_crc`: RTP marker bit to include in CRC calculation
///
/// # Returns
/// Fixed-size array containing the CRC input payload (11 bytes)
#[inline]
pub fn prepare_generic_uo_crc_input_payload(
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

/// Prepares a generic UO packet CRC input payload into provided buffer.
///
/// Zero-allocation version that writes directly to the provided buffer.
/// Returns the number of bytes written.
///
/// # Parameters
/// - `context_ssrc`: RTP SSRC from compressor context
/// - `sn_for_crc`: Sequence number to include in CRC calculation
/// - `ts_for_crc`: Timestamp to include in CRC calculation
/// - `marker_for_crc`: RTP marker bit to include in CRC calculation
/// - `buf`: Output buffer to write CRC input payload into
///
/// # Returns
/// Number of bytes written to the buffer (always 11)
#[inline]
pub fn prepare_generic_uo_crc_input_into_buf(
    context_ssrc: Ssrc,
    sn_for_crc: SequenceNumber,
    ts_for_crc: Timestamp,
    marker_for_crc: bool,
    buf: &mut [u8],
) -> usize {
    debug_assert!(
        buf.len() >= P1_UO_CRC_INPUT_LENGTH_BYTES,
        "Buffer overflow: {} < {}",
        buf.len(),
        P1_UO_CRC_INPUT_LENGTH_BYTES
    );

    buf[0..4].copy_from_slice(&context_ssrc.to_be_bytes());
    buf[4..6].copy_from_slice(&sn_for_crc.0.to_be_bytes());
    buf[6..10].copy_from_slice(&ts_for_crc.to_be_bytes());
    buf[10] = if marker_for_crc { 0x01 } else { 0x00 };

    P1_UO_CRC_INPUT_LENGTH_BYTES
}

/// Prepares a UO-1-ID specific CRC input payload on the stack.
///
/// Creates the standardized byte sequence used for CRC calculation in UO-1-ID packets.
/// This extends the generic UO CRC input with the IP-ID LSB field for UO-1-ID validation.
///
/// # Parameters
/// - `context_ssrc`: RTP SSRC from compressor context
/// - `sn_for_crc`: Sequence number to include in CRC calculation
/// - `ts_for_crc`: Timestamp to include in CRC calculation
/// - `marker_for_crc`: RTP marker bit to include in CRC calculation
/// - `ip_id_lsb_for_crc`: IP-ID LSB value specific to UO-1-ID packets
///
/// # Returns
/// Fixed-size array containing the CRC input payload (12 bytes)
#[inline]
pub fn prepare_uo1_id_specific_crc_input_payload(
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

/// Prepares a UO-1-ID specific CRC input payload into provided buffer.
///
/// Zero-allocation version that writes directly to the provided buffer.
/// Returns the number of bytes written.
///
/// # Parameters
/// - `context_ssrc`: RTP SSRC from compressor context
/// - `sn_for_crc`: Sequence number to include in CRC calculation
/// - `ts_for_crc`: Timestamp to include in CRC calculation
/// - `marker_for_crc`: RTP marker bit to include in CRC calculation
/// - `ip_id_lsb_for_crc`: IP-ID LSB value specific to UO-1-ID packets
/// - `buf`: Output buffer to write CRC input payload into
///
/// # Returns
/// Number of bytes written to the buffer (always 12)
#[inline]
pub fn prepare_uo1_id_specific_crc_input_into_buf(
    context_ssrc: Ssrc,
    sn_for_crc: SequenceNumber,
    ts_for_crc: Timestamp,
    marker_for_crc: bool,
    ip_id_lsb_for_crc: u8,
    buf: &mut [u8],
) -> usize {
    debug_assert!(
        buf.len() > P1_UO_CRC_INPUT_LENGTH_BYTES,
        "Buffer overflow: {} < {}",
        buf.len(),
        P1_UO_CRC_INPUT_LENGTH_BYTES + 1
    );

    buf[0..4].copy_from_slice(&context_ssrc.to_be_bytes());
    buf[4..6].copy_from_slice(&sn_for_crc.0.to_be_bytes());
    buf[6..10].copy_from_slice(&ts_for_crc.to_be_bytes());
    buf[10] = if marker_for_crc { 0x01 } else { 0x00 };
    buf[11] = ip_id_lsb_for_crc;

    P1_UO_CRC_INPUT_LENGTH_BYTES + 1
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn p1_uo1_sn_roundtrip() {
        let uo1_sn_data = Uo1Packet {
            cid: None,
            sn_lsb: 123,
            num_sn_lsb_bits: 8,
            marker: true,
            crc8: 0xAB,
            ..Default::default()
        };

        let mut buf = [0u8; 16];
        let len = serialize_uo1_sn(&uo1_sn_data, &mut buf).unwrap();
        let built_bytes_slice = &buf[..len];

        let parsed = deserialize_uo1_sn(built_bytes_slice).unwrap();
        assert_eq!(parsed.sn_lsb, 123);
        assert!(parsed.marker);
        assert_eq!(parsed.crc8, 0xAB);
    }
}
