//! ROHC (Robust Header Compression) Profile 1 packet type discriminator logic.
//!
//! This module defines an enum (`Profile1PacketType`) to represent the different
//! packet types based on their first byte discriminator, as used in ROHC Profile 1.
//! It provides a way to parse the first byte of a ROHC packet and determine its type
//! in a structured manner, replacing complex bitmask operations in the handler.

use super::constants::*;

/// Represents the discriminated type of a ROHC Profile 1 packet based on its first byte.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Profile1PacketType {
    /// Initialization/Refresh packet with static chain only (D-bit = 0).
    IrStatic,
    /// Initialization/Refresh packet with static and dynamic chains (D-bit = 1).
    IrDynamic,
    /// Unidirectional Optimistic type 0 packet.
    Uo0,
    /// Unidirectional Optimistic type 1, Sequence Number variant.
    /// Includes the marker bit value from the packet.
    Uo1Sn { marker: bool },
    /// Unidirectional Optimistic type 1, Timestamp variant.
    Uo1Ts,
    /// Unidirectional Optimistic type 1, IP-ID variant.
    Uo1Id,
    /// Unidirectional Optimistic type 1, RTP variant (carries TS_SCALED).
    /// Includes the marker bit value from the packet.
    Uo1Rtp { marker: bool },
    /// An unknown or unrecognized packet type for Profile 1.
    /// Contains the problematic first byte.
    Unknown(u8),
}

impl Profile1PacketType {
    /// Determines the `Profile1PacketType` from the first byte of a core ROHC packet.
    ///
    /// This function assumes the input `byte` is the first byte of the ROHC packet
    /// *after* any Add-CID octet processing has been handled by the ROHC engine.
    /// The order of checks is important to correctly discriminate between UO-1 variants.
    pub fn from_first_byte(byte: u8) -> Self {
        // Check for IR / IR-DYN packets (Type: 1111110D)
        if (byte & !P1_ROHC_IR_PACKET_TYPE_D_BIT_MASK) == P1_ROHC_IR_PACKET_TYPE_BASE {
            if (byte & P1_ROHC_IR_PACKET_TYPE_D_BIT_MASK) != 0 {
                Profile1PacketType::IrDynamic
            } else {
                Profile1PacketType::IrStatic
            }
        }
        // Check for UO-0 packets (Type: 0xxxxxxx)
        else if (byte & 0x80) == 0x00 {
            Profile1PacketType::Uo0
        }
        // Check for UO-1 base prefix (Type: 101xxxxx)
        else if (byte & 0xE0) == P1_UO_1_TS_PACKET_TYPE_PREFIX {
            // Check most specific UO-1 variants first: RTP, ID, TS, then SN

            if (byte & 0b1111_1110) == P1_UO_1_RTP_DISCRIMINATOR_BASE {
                let marker = (byte & P1_UO_1_RTP_MARKER_BIT_MASK) != 0;
                Profile1PacketType::Uo1Rtp { marker }
            } else if byte == P1_UO_1_ID_DISCRIMINATOR {
                Profile1PacketType::Uo1Id
            } else if (byte & P1_UO_1_TS_TYPE_MASK) == P1_UO_1_TS_DISCRIMINATOR {
                Profile1PacketType::Uo1Ts
            } else if (byte & !P1_UO_1_SN_MARKER_BIT_MASK) == P1_UO_1_SN_PACKET_TYPE_PREFIX {
                let marker = (byte & P1_UO_1_SN_MARKER_BIT_MASK) != 0;
                Profile1PacketType::Uo1Sn { marker }
            } else {
                Profile1PacketType::Unknown(byte)
            }
        } else {
            Profile1PacketType::Unknown(byte)
        }
    }

    /// Checks if the packet type is `IrStatic` or `IrDynamic`.
    pub fn is_ir(&self) -> bool {
        matches!(
            self,
            Profile1PacketType::IrStatic | Profile1PacketType::IrDynamic
        )
    }

    /// Checks if the packet type is `Uo0`.
    pub fn is_uo0(&self) -> bool {
        matches!(self, Profile1PacketType::Uo0)
    }

    /// Checks if the packet type is any UO-1 variant.
    pub fn is_uo1(&self) -> bool {
        matches!(
            self,
            Profile1PacketType::Uo1Sn { .. }
                | Profile1PacketType::Uo1Ts
                | Profile1PacketType::Uo1Id
                | Profile1PacketType::Uo1Rtp { .. }
        )
    }

    /// Identifies packets that normally update the dynamic part of the ROHC context.
    pub fn is_dynamic_updating(&self) -> bool {
        match self {
            Profile1PacketType::IrDynamic
            | Profile1PacketType::Uo1Sn { .. }
            | Profile1PacketType::Uo1Ts
            | Profile1PacketType::Uo1Id
            | Profile1PacketType::Uo1Rtp { .. } => true,
            Profile1PacketType::Unknown(_) => true, // Conservatively assume unknown might have
            // been an updater
            Profile1PacketType::IrStatic | Profile1PacketType::Uo0 => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_first_byte_ir_packets() {
        assert_eq!(
            Profile1PacketType::from_first_byte(P1_ROHC_IR_PACKET_TYPE_STATIC_ONLY),
            Profile1PacketType::IrStatic
        );
        assert_eq!(
            Profile1PacketType::from_first_byte(P1_ROHC_IR_PACKET_TYPE_WITH_DYN),
            Profile1PacketType::IrDynamic
        );
    }

    #[test]
    fn from_first_byte_uo0_packet() {
        assert_eq!(
            Profile1PacketType::from_first_byte(0x00),
            Profile1PacketType::Uo0
        );
        assert_eq!(
            Profile1PacketType::from_first_byte(0x7F),
            Profile1PacketType::Uo0
        );
    }

    #[test]
    fn from_first_byte_uo1_sn_packets() {
        assert_eq!(
            Profile1PacketType::from_first_byte(P1_UO_1_SN_PACKET_TYPE_PREFIX), // 10100000
            Profile1PacketType::Uo1Sn { marker: false }
        );
        assert_eq!(
            Profile1PacketType::from_first_byte(
                P1_UO_1_SN_PACKET_TYPE_PREFIX | P1_UO_1_SN_MARKER_BIT_MASK // 10100001
            ),
            Profile1PacketType::Uo1Sn { marker: true }
        );
    }

    #[test]
    fn from_first_byte_uo1_ts_packet() {
        assert_eq!(
            Profile1PacketType::from_first_byte(P1_UO_1_TS_DISCRIMINATOR), // 10100100
            Profile1PacketType::Uo1Ts
        );
    }

    #[test]
    fn from_first_byte_uo1_id_packet() {
        assert_eq!(
            Profile1PacketType::from_first_byte(P1_UO_1_ID_DISCRIMINATOR), // 10101100
            Profile1PacketType::Uo1Id
        );
    }

    #[test]
    fn from_first_byte_uo1_rtp_packets() {
        assert_eq!(
            Profile1PacketType::from_first_byte(P1_UO_1_RTP_DISCRIMINATOR_BASE), // 10101000
            Profile1PacketType::Uo1Rtp { marker: false }
        );
        assert_eq!(
            Profile1PacketType::from_first_byte(
                P1_UO_1_RTP_DISCRIMINATOR_BASE | P1_UO_1_RTP_MARKER_BIT_MASK // 10101001
            ),
            Profile1PacketType::Uo1Rtp { marker: true }
        );
        // Ensure UO-1-RTP is preferred over UO-1-SN for matching bit patterns
        assert_ne!(
            Profile1PacketType::from_first_byte(0xA8),
            Profile1PacketType::Uo1Sn { marker: false }
        );
    }

    #[test]
    fn from_first_byte_unknown_packets() {
        assert_eq!(
            Profile1PacketType::from_first_byte(0x80), // Not UO-0, not 101xxxxx, not IR
            Profile1PacketType::Unknown(0x80)
        );
        assert_eq!(
            Profile1PacketType::from_first_byte(0xFF), /* Not IR, UO-0. If 101xxxx, it's unknown
                                                        * variant */
            Profile1PacketType::Unknown(0xFF)
        );
        assert_eq!(
            Profile1PacketType::from_first_byte(0xF0), // Not specific IR
            Profile1PacketType::Unknown(0xF0)
        );
        // UO-1 prefix with undefined TSI=001
        assert_eq!(
            Profile1PacketType::from_first_byte(0b10100010),
            Profile1PacketType::Unknown(0b10100010)
        );
        // UO-1 prefix with undefined TSI=111
        assert_eq!(
            Profile1PacketType::from_first_byte(0b10111110),
            Profile1PacketType::Unknown(0b10111110)
        );
    }

    #[test]
    fn packet_type_is_ir() {
        assert!(Profile1PacketType::IrStatic.is_ir());
        assert!(Profile1PacketType::IrDynamic.is_ir());
        assert!(!Profile1PacketType::Uo0.is_ir());
        assert!(!Profile1PacketType::Uo1Sn { marker: false }.is_ir());
        assert!(!Profile1PacketType::Uo1Rtp { marker: false }.is_ir());
    }

    #[test]
    fn packet_type_is_uo0() {
        assert!(Profile1PacketType::Uo0.is_uo0());
        assert!(!Profile1PacketType::IrStatic.is_uo0());
        assert!(!Profile1PacketType::Uo1Ts.is_uo0());
    }

    #[test]
    fn packet_type_is_uo1() {
        assert!(Profile1PacketType::Uo1Sn { marker: true }.is_uo1());
        assert!(Profile1PacketType::Uo1Ts.is_uo1());
        assert!(Profile1PacketType::Uo1Id.is_uo1());
        assert!(Profile1PacketType::Uo1Rtp { marker: true }.is_uo1());
        assert!(!Profile1PacketType::Uo0.is_uo1());
        assert!(!Profile1PacketType::IrDynamic.is_uo1());
    }

    #[test]
    fn packet_type_is_dynamically_updating() {
        assert!(Profile1PacketType::IrDynamic.is_dynamic_updating());
        assert!(Profile1PacketType::Uo1Sn { marker: false }.is_dynamic_updating());
        assert!(Profile1PacketType::Uo1Ts.is_dynamic_updating());
        assert!(Profile1PacketType::Uo1Id.is_dynamic_updating());
        assert!(Profile1PacketType::Uo1Rtp { marker: false }.is_dynamic_updating());
        assert!(Profile1PacketType::Unknown(0xFF).is_dynamic_updating());

        assert!(!Profile1PacketType::IrStatic.is_dynamic_updating());
        assert!(!Profile1PacketType::Uo0.is_dynamic_updating());
    }
}
