//! ROHC (Robust Header Compression) Profile 1 packet type discriminator logic.
//!
//! This module defines an enum (`Profile1PacketType`) to represent the different
//! packet types based on their first byte discriminator, as used in ROHC Profile 1.
//! It provides a way to parse the first byte of a ROHC packet and determine its type
//! in a structured manner, replacing complex bitmask operations in the handler.

use crate::profiles::profile1::constants::*;

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
    // Future: Add Feedback types if relevant for U-mode error reporting or extended uses.
    // Future: Add SO (Second Order) specific types if their discriminators are distinct
    //         and not just UO-0/UO-1 used in SO state.
    /// An unknown or unrecognized packet type for Profile 1.
    /// Contains the problematic first byte.
    Unknown(u8),
}

impl Profile1PacketType {
    /// Determines the `Profile1PacketType` from the first byte of a core ROHC packet.
    ///
    /// This function assumes the input `byte` is the first byte of the ROHC packet
    /// *after* any Add-CID octet processing has been handled by the ROHC engine.
    ///
    /// # Parameter
    ///
    /// * `byte` - The first byte of the core ROHC Profile 1 packet.
    ///
    /// # Returns
    ///
    /// The corresponding `Profile1PacketType`.
    pub fn from_first_byte(byte: u8) -> Self {
        // Check for IR / IR-DYN packets (Type: 1111110D)
        if (byte & !P1_ROHC_IR_PACKET_TYPE_D_BIT_MASK) == P1_ROHC_IR_PACKET_TYPE_BASE {
            if (byte & P1_ROHC_IR_PACKET_TYPE_D_BIT_MASK) != 0 {
                // D-bit is 1
                Profile1PacketType::IrDynamic
            } else {
                // D-bit is 0
                Profile1PacketType::IrStatic
            }
        }
        // Check for UO-0 packets (Type: 0xxxxxxx)
        else if (byte & 0x80) == 0x00 {
            Profile1PacketType::Uo0
        }
        // Check for UO-1 base prefix (Type: 101xxxxx)
        else if (byte & P1_UO_1_TS_PACKET_TYPE_PREFIX/*0xA0, effectively checks 101.....*/)
            == P1_UO_1_TS_PACKET_TYPE_PREFIX
        {
            // Discriminate between UO-1 variants
            // UO-1-TS (Type: 10100100 = 0xA4)
            if (byte & P1_UO_1_TS_TYPE_MASK) == (P1_UO_1_TS_DISCRIMINATOR & P1_UO_1_TS_TYPE_MASK) {
                Profile1PacketType::Uo1Ts
            }
            // UO-1-ID (Type: 10101100 = 0xAC)
            else if byte == P1_UO_1_ID_DISCRIMINATOR {
                Profile1PacketType::Uo1Id
            }
            // UO-1-SN (Type: 1010000M)
            // Check that bits 3-1 (TSI field in UO-1 general format) are 000
            else if (byte & !P1_UO_1_SN_MARKER_BIT_MASK) == P1_UO_1_SN_PACKET_TYPE_PREFIX {
                let marker = (byte & P1_UO_1_SN_MARKER_BIT_MASK) != 0;
                Profile1PacketType::Uo1Sn { marker }
            }
            // If it matched UO-1 prefix but none of the above specific UO-1 types
            else {
                Profile1PacketType::Unknown(byte)
            }
        }
        // If none of the above, it's an unknown type for Profile 1
        else {
            Profile1PacketType::Unknown(byte)
        }
    }

    /// Returns `true` if the packet type is `IrStatic` or `IrDynamic`.
    pub fn is_ir(&self) -> bool {
        matches!(
            self,
            Profile1PacketType::IrStatic | Profile1PacketType::IrDynamic
        )
    }

    /// Returns `true` if the packet type is `Uo0`.
    pub fn is_uo0(&self) -> bool {
        matches!(self, Profile1PacketType::Uo0)
    }

    /// Returns `true` if the packet type is any UO-1 variant (`Uo1Sn`, `Uo1Ts`, `Uo1Id`).
    pub fn is_uo1(&self) -> bool {
        matches!(
            self,
            Profile1PacketType::Uo1Sn { .. }
                | Profile1PacketType::Uo1Ts
                | Profile1PacketType::Uo1Id
        )
    }

    /// Identifies packets that normally update the dynamic part of the ROHC context.
    /// This is relevant for state transition logic like SC->NC (K2/N2 rule).
    ///
    /// IR-DYN, UO-1-SN, UO-1-TS, and UO-1-ID are considered dynamic updaters.
    /// IR-Static primarily updates static context. UO-0 relies on existing dynamic context.
    /// Unknown packets are conservatively considered as potential (failed) updaters.
    ///
    /// # Returns
    ///
    /// `true` if the packet type is considered a dynamic updater, `false` otherwise.
    pub fn is_dynamically_updating_type(&self) -> bool {
        match self {
            Profile1PacketType::IrDynamic | // IR-DYN explicitly carries full dynamic info
            Profile1PacketType::Uo1Sn { .. } |
            Profile1PacketType::Uo1Ts |
            Profile1PacketType::Uo1Id => true,
            Profile1PacketType::Unknown(_) => true, // A failed parse of an unknown type might have been an updater
            Profile1PacketType::IrStatic |
            Profile1PacketType::Uo0 => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profiles::profile1::constants::*; // Import constants for direct use in tests

    #[test]
    fn test_from_first_byte_ir_packets() {
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
    fn test_from_first_byte_uo0_packet() {
        assert_eq!(
            Profile1PacketType::from_first_byte(0x00),
            Profile1PacketType::Uo0
        ); // 0 SSSS CCC
        assert_eq!(
            Profile1PacketType::from_first_byte(0x7F),
            Profile1PacketType::Uo0
        );
    }

    #[test]
    fn test_from_first_byte_uo1_sn_packets() {
        assert_eq!(
            Profile1PacketType::from_first_byte(P1_UO_1_SN_PACKET_TYPE_PREFIX | 0x00),
            Profile1PacketType::Uo1Sn { marker: false }
        ); // 10100000
        assert_eq!(
            Profile1PacketType::from_first_byte(
                P1_UO_1_SN_PACKET_TYPE_PREFIX | P1_UO_1_SN_MARKER_BIT_MASK
            ),
            Profile1PacketType::Uo1Sn { marker: true }
        ); // 10100001
    }

    #[test]
    fn test_from_first_byte_uo1_ts_packet() {
        assert_eq!(
            Profile1PacketType::from_first_byte(P1_UO_1_TS_DISCRIMINATOR),
            Profile1PacketType::Uo1Ts
        ); // 10100100
    }

    #[test]
    fn test_from_first_byte_uo1_id_packet() {
        assert_eq!(
            Profile1PacketType::from_first_byte(P1_UO_1_ID_DISCRIMINATOR),
            Profile1PacketType::Uo1Id
        ); // 10101100
    }

    #[test]
    fn test_from_first_byte_unknown_packets() {
        assert_eq!(
            Profile1PacketType::from_first_byte(0x80),
            Profile1PacketType::Unknown(0x80)
        ); // Not UO-0, not UO-1 prefix, not IR
        assert_eq!(
            Profile1PacketType::from_first_byte(0xFF),
            Profile1PacketType::Unknown(0xFF)
        ); // Not UO-0, UO-1 prefix but not recognized variant, not IR
        assert_eq!(
            Profile1PacketType::from_first_byte(0xF0),
            Profile1PacketType::Unknown(0xF0)
        ); // Not specific IR
        assert_eq!(
            Profile1PacketType::from_first_byte(0b10100010),
            Profile1PacketType::Unknown(0b10100010)
        ); // UO-1 prefix, but TSI=001 (undefined for MVP)
    }

    #[test]
    fn test_is_ir() {
        assert!(Profile1PacketType::IrStatic.is_ir());
        assert!(Profile1PacketType::IrDynamic.is_ir());
        assert!(!Profile1PacketType::Uo0.is_ir());
        assert!(!Profile1PacketType::Uo1Sn { marker: false }.is_ir());
    }

    #[test]
    fn test_is_uo0() {
        assert!(Profile1PacketType::Uo0.is_uo0());
        assert!(!Profile1PacketType::IrStatic.is_uo0());
        assert!(!Profile1PacketType::Uo1Ts.is_uo0());
    }

    #[test]
    fn test_is_uo1() {
        assert!(Profile1PacketType::Uo1Sn { marker: true }.is_uo1());
        assert!(Profile1PacketType::Uo1Ts.is_uo1());
        assert!(Profile1PacketType::Uo1Id.is_uo1());
        assert!(!Profile1PacketType::Uo0.is_uo1());
        assert!(!Profile1PacketType::IrDynamic.is_uo1());
    }

    #[test]
    fn test_is_dynamically_updating_type() {
        assert!(Profile1PacketType::IrDynamic.is_dynamically_updating_type());
        assert!(Profile1PacketType::Uo1Sn { marker: false }.is_dynamically_updating_type());
        assert!(Profile1PacketType::Uo1Ts.is_dynamically_updating_type());
        assert!(Profile1PacketType::Uo1Id.is_dynamically_updating_type());
        assert!(Profile1PacketType::Unknown(0xFF).is_dynamically_updating_type());

        assert!(!Profile1PacketType::IrStatic.is_dynamically_updating_type());
        assert!(!Profile1PacketType::Uo0.is_dynamically_updating_type());
    }
}
