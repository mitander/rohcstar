//! Zero-allocation packet building utilities.
//!
//! This module provides stack-allocated alternatives to the existing packet
//! serialization functions. Functions return fixed-size arrays to eliminate
//! heap allocations in hot paths.

use super::constants::*;
use super::packet_types::{Uo0Packet, Uo1Packet};
use crate::constants::{ROHC_ADD_CID_FEEDBACK_PREFIX_VALUE, ROHC_SMALL_CID_MASK};
use crate::error::RohcBuildingError;

/// Maximum size for UO-0 packets (Add-CID + UO-0 byte).
pub const UO0_MAX_SIZE: usize = 2;

/// Maximum size for UO-1 packets (Add-CID + packet data).
pub const UO1_MAX_SIZE: usize = 5;

/// Zero-allocation UO-0 packet builder.
///
/// Returns a fixed-size array and actual length to avoid heap allocation.
/// For hot paths where allocation-free operation is critical.
///
/// # Returns
/// Tuple of (packet_data, actual_length)
pub fn build_uo0_packet(
    packet_data: &Uo0Packet,
) -> Result<([u8; UO0_MAX_SIZE], usize), RohcBuildingError> {
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

    let mut buf = [0u8; UO0_MAX_SIZE];
    let mut pos = 0;

    // Add-CID octet if needed
    if let Some(cid_val) = packet_data.cid {
        if cid_val > 0 && cid_val <= 15 {
            buf[pos] = ROHC_ADD_CID_FEEDBACK_PREFIX_VALUE | (*cid_val as u8 & ROHC_SMALL_CID_MASK);
            pos += 1;
        } else if cid_val > 15 {
            return Err(RohcBuildingError::InvalidFieldValueForBuild {
                field: crate::error::Field::Cid,
                value: *cid_val as u32,
                max_bits: 4,
            });
        }
    }

    // Core UO-0 byte: SN(4 bits) + CRC3(3 bits)
    let core_byte = (packet_data.sn_lsb << 3) | packet_data.crc3;
    buf[pos] = core_byte;
    pos += 1;

    Ok((buf, pos))
}

/// Zero-allocation UO-1-SN packet builder.
///
/// Returns a fixed-size array and actual length to avoid heap allocation.
pub fn build_uo1_sn_packet(
    packet_data: &Uo1Packet,
) -> Result<([u8; UO1_MAX_SIZE], usize), RohcBuildingError> {
    let mut buf = [0u8; UO1_MAX_SIZE];
    let mut pos = 0;

    // Add-CID octet if needed
    if let Some(cid_val) = packet_data.cid {
        if cid_val > 0 && cid_val <= 15 {
            buf[pos] = ROHC_ADD_CID_FEEDBACK_PREFIX_VALUE | (*cid_val as u8 & ROHC_SMALL_CID_MASK);
            pos += 1;
        } else if cid_val > 15 {
            return Err(RohcBuildingError::InvalidFieldValueForBuild {
                field: crate::error::Field::Cid,
                value: *cid_val as u32,
                max_bits: 4,
            });
        }
    }

    // UO-1-SN packet format
    let sn_lsb = packet_data.sn_lsb;
    let marker_bit = if packet_data.marker { 0x08 } else { 0x00 };
    buf[pos] = P1_UO_1_SN_PACKET_TYPE_PREFIX | marker_bit | (((sn_lsb >> 3) & 0x07) as u8);
    buf[pos + 1] =
        (((sn_lsb & 0x07) << 5) as u8) | ((packet_data.ip_id_lsb.unwrap_or(0) & 0x1F) as u8);
    buf[pos + 2] = packet_data.crc8;
    pos += 3;

    Ok((buf, pos))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::ContextId;

    #[test]
    fn build_uo0_packet_zero_cid() {
        let packet = Uo0Packet {
            cid: Some(ContextId::new(0)),
            sn_lsb: 5,
            crc3: 3,
        };

        let (buf, len) = build_uo0_packet(&packet).unwrap();
        assert_eq!(len, 1);
        assert_eq!(buf[0], (5 << 3) | 3); // SN=5, CRC3=3
    }

    #[test]
    fn build_uo0_packet_with_add_cid() {
        let packet = Uo0Packet {
            cid: Some(ContextId::new(7)),
            sn_lsb: 5,
            crc3: 3,
        };

        let (buf, len) = build_uo0_packet(&packet).unwrap();
        assert_eq!(len, 2);
        assert_eq!(buf[0], ROHC_ADD_CID_FEEDBACK_PREFIX_VALUE | 7); // Add-CID
        assert_eq!(buf[1], (5 << 3) | 3); // SN=5, CRC3=3
    }

    #[test]
    fn build_uo1_sn_packet_basic() {
        let packet = Uo1Packet {
            cid: Some(ContextId::new(0)),
            sn_lsb: 42,
            ip_id_lsb: Some(15),
            marker: true,
            crc8: 0xAB,
            ..Default::default()
        };

        let (buf, len) = build_uo1_sn_packet(&packet).unwrap();
        assert_eq!(len, 3);
        // Verify packet structure
        assert_eq!(buf[0] & 0xF0, P1_UO_1_SN_PACKET_TYPE_PREFIX);
        assert_eq!(buf[0] & 0x08, 0x08); // Marker bit set
        assert_eq!(buf[2], 0xAB); // CRC8
    }
}
