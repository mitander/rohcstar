//! UO-0 packet serialization and deserialization for Profile 1.
//!
//! This module handles the creation and parsing of UO-0 (Unidirectional Optimistic, Order 0)
//! packets, which are the most compressed packet type in ROHC Profile 1. UO-0 packets
//! carry only sequence number LSBs and CRC when no other fields have changed.

use super::super::constants::*;
use super::super::packet_types::Uo0Packet;
use crate::constants::{ROHC_ADD_CID_FEEDBACK_PREFIX_VALUE, ROHC_SMALL_CID_MASK};
use crate::error::{Field, ParseContext, RohcBuildingError, RohcParsingError};
use crate::types::ContextId;

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
pub(crate) fn serialize_uo0(
    packet_data: &Uo0Packet,
    out: &mut [u8],
) -> Result<usize, RohcBuildingError> {
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
            field: Field::SnLsb,
            value: packet_data.sn_lsb as u32,
            max_bits: P1_UO0_SN_LSB_WIDTH_DEFAULT,
        });
    }
    if packet_data.crc3 > 0x07 {
        return Err(RohcBuildingError::InvalidFieldValueForBuild {
            field: Field::Crc3,
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
pub(crate) fn deserialize_uo0(
    core_packet_data: &[u8],
    cid_from_engine: Option<ContextId>,
) -> Result<Uo0Packet, RohcParsingError> {
    if core_packet_data.is_empty() {
        return Err(RohcParsingError::NotEnoughData {
            needed: 1,
            got: core_packet_data.len(),
            context: ParseContext::UoPacketTypeDiscriminator,
        });
    }

    debug_assert_eq!(
        core_packet_data.len(),
        1,
        "UO-0 core packet must be exactly 1 byte"
    );

    let packet_byte = core_packet_data[0];

    debug_assert_eq!(packet_byte & 0x80, 0, "UO-0 discriminator check failed");

    let sn_lsb_val = (packet_byte >> 3) & 0x0F;
    let crc3_val = packet_byte & 0x07;

    debug_assert!(sn_lsb_val < 16, "SN LSB value {} out of range", sn_lsb_val);
    debug_assert!(crc3_val <= 7, "CRC3 value {} out of range", crc3_val);

    Ok(Uo0Packet {
        cid: cid_from_engine,
        sn_lsb: sn_lsb_val,
        crc3: crc3_val,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn p1_uo0_roundtrip() {
        let uo0_data = Uo0Packet {
            cid: Some(0.into()),
            sn_lsb: 5,
            crc3: 3,
        };

        let mut buf = [0u8; 16];
        let len = serialize_uo0(&uo0_data, &mut buf).unwrap();
        let built_bytes_slice = &buf[..len];

        let parsed = deserialize_uo0(built_bytes_slice, Some(0.into())).unwrap();
        assert_eq!(parsed.sn_lsb, 5);
        assert_eq!(parsed.crc3, 3);
    }
}
