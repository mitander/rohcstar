//! ROHC packet type definitions and identifiers.
//!
//! Defines enums and structs for ROHC packet formats and profiles.

use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;

use crate::constants::*;
use crate::protocol_types::RtpUdpIpv4Headers;

/// Supported ROHC profile identifiers.
///
/// Each profile specifies a different set of protocols that can be compressed.
/// The numeric values correspond to the profile identifiers defined in the ROHC RFCs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum RohcProfile {
    /// Uncompressed mode (profile 0x0000)
    Uncompressed = PROFILE_ID_UNCOMPRESSED,
    /// RTP/UDP/IP compression (profile 0x0001)
    RtpUdpIp = PROFILE_ID_RTP_UDP_IP,
    /// UDP/IP compression (profile 0x0002)
    UdpIp = PROFILE_ID_UDP_IP,
    /// IP-only compression (profile 0x0003)
    Ip = PROFILE_ID_IP_ONLY,
    /// TCP/IP compression (profile 0x0006)
    TcpIp = PROFILE_ID_TCP_IP,
    /// Unknown or unsupported profile
    Unknown(u8),
}

impl From<u8> for RohcProfile {
    fn from(value: u8) -> Self {
        match value {
            PROFILE_ID_UNCOMPRESSED => RohcProfile::Uncompressed,
            PROFILE_ID_RTP_UDP_IP => RohcProfile::RtpUdpIp,
            PROFILE_ID_UDP_IP => RohcProfile::UdpIp,
            PROFILE_ID_IP_ONLY => RohcProfile::Ip,
            PROFILE_ID_TCP_IP => RohcProfile::TcpIp,
            unknown_id => RohcProfile::Unknown(unknown_id),
        }
    }
}

impl From<RohcProfile> for u8 {
    fn from(profile: RohcProfile) -> Self {
        match profile {
            RohcProfile::Uncompressed => PROFILE_ID_UNCOMPRESSED,
            RohcProfile::RtpUdpIp => PROFILE_ID_RTP_UDP_IP,
            RohcProfile::UdpIp => PROFILE_ID_UDP_IP,
            RohcProfile::Ip => PROFILE_ID_IP_ONLY,
            RohcProfile::TcpIp => PROFILE_ID_TCP_IP,
            RohcProfile::Unknown(val) => val,
        }
    }
}

/// Container for different uncompressed header types.
///
/// Provides a unified interface for profile handlers to work with
/// various header formats.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GenericUncompressedHeaders {
    RtpUdpIpv4(RtpUdpIpv4Headers),
    // Placeholder for other header types, e.g., UdpIpv4, Ipv4, etc.
}

impl GenericUncompressedHeaders {
    /// Attempts to return a reference to the inner `RtpUdpIpv4Headers`.
    ///
    /// # Returns
    /// `Some(&RtpUdpIpv4Headers)` if the enum variant is `RtpUdpIpv4`, `None` otherwise.
    pub fn as_rtp_udp_ipv4(&self) -> Option<&RtpUdpIpv4Headers> {
        match self {
            GenericUncompressedHeaders::RtpUdpIpv4(headers) => Some(headers),
        }
    }

    /// Attempts to return a mutable reference to the inner `RtpUdpIpv4Headers`.
    ///
    /// # Returns
    /// `Some(&mut RtpUdpIpv4Headers)` if the enum variant is `RtpUdpIpv4`, `None` otherwise.
    pub fn as_rtp_udp_ipv4_mut(&mut self) -> Option<&mut RtpUdpIpv4Headers> {
        match self {
            GenericUncompressedHeaders::RtpUdpIpv4(headers) => Some(headers),
        }
    }
}

/// Identifies ROHC packet types from their initial byte(s).
///
/// This enum is used by the ROHC engine to determine the type of an incoming ROHC packet.
/// The determination is based on the first byte of the ROHC packet (after any CID information
/// has been processed and stripped by a higher-level dispatcher if applicable).
///
/// The dispatcher should handle CID processing (e.g., Add-CID octets) before
/// passing the core packet (starting with the type-specific byte) to a function
/// that uses this discriminator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RohcPacketDiscriminator {
    /// ROHC Initialization and Refresh packet with a dynamic part (D-bit = 1).
    IrDyn,
    /// ROHC Initialization and Refresh packet with only a static part (D-bit = 0).
    IrStatic,
    /// ROHC Unidirectional Optimistic type 0 packet.
    /// For CID 0, these packets start with a '0' bit pattern: `0xxxxxxx`.
    /// For other CIDs, an Add-CID octet would have been prepended and stripped by the dispatcher.
    Uo0,
    /// ROHC Unidirectional Optimistic type 1, SN variant (Profile 1: `1010000M`).
    Uo1Sn,
    /// ROHC Unidirectional Optimistic type 1, TS variant (Profile 1: `1010001M` - not fully implemented).
    Uo1Ts, // Placeholder for UO-1-TS if it gets a distinct first byte pattern
    /// ROHC Unidirectional Optimistic type 1, IP-ID variant (Profile 1: `1010010M` - not fully implemented).
    Uo1IpId, // Placeholder for UO-1-IP-ID
    /// ROHC Unidirectional Optimistic type 2 packet (e.g., `110xxxxx` - not fully implemented).
    Uo2,
    /// ROHC Feedback packet (type 1) (e.g., `1111000x` - not fully implemented).
    Feedback1,
    /// ROHC Feedback packet (type 2) (e.g., `1111001x` - not fully implemented).
    Feedback2,
    // Note: Add-CID octets (1110xxxx) are expected to be handled by the dispatcher
    // before this discriminator is used on the subsequent byte.
    // Padding (e.g., an Add-CID for CID 0: 11100000) should also be handled by dispatcher.
    /// Unrecognized or unsupported ROHC packet type based on the first byte.
    /// Contains the first byte of the core ROHC packet.
    Unknown(u8),
}

impl RohcPacketDiscriminator {
    /// Determines a ROHC packet discriminator from the first byte of a *core* ROHC packet.
    ///
    /// It is assumed that any leading Add-CID octet has already been processed and
    /// stripped by a higher-level dispatcher, and `byte` is the first octet
    /// of the actual ROHC packet (e.g., the IR type octet, UO-0 octet, etc.).
    ///
    /// NOTE: This should be reworked when we implement support for more profiles.
    /// It should be able to handle different discriminator schemes etc. by then.
    ///
    /// # Parameters
    /// - `byte`: The first byte of the core ROHC packet.
    ///
    /// # Returns
    /// The `RohcPacketDiscriminator` corresponding to the packet type.
    pub fn from_first_byte(byte: u8) -> Self {
        // Order of checks matters here. More specific patterns first.

        // IR packets: 1111110x
        if (byte & !ROHC_IR_PACKET_TYPE_D_BIT_MASK) == ROHC_IR_PACKET_TYPE_BASE {
            return if (byte & ROHC_IR_PACKET_TYPE_D_BIT_MASK) != 0 {
                Self::IrDyn
            } else {
                Self::IrStatic
            };
        }

        // UO-0 (for any CID, after Add-CID stripping): 0xxxxxxx
        if (byte & 0x80) == 0 {
            return Self::Uo0;
        }

        // UO-1-SN (Profile 1): 1010000M (where M is marker bit)
        // This also covers other UO-1 variants if their prefix is 1010.
        // More specific UO-1 checks might be needed if first byte isn't unique.
        if (byte & 0b11111110) == UO_1_SN_P1_PACKET_TYPE_BASE {
            // For now, assume any 1010000x is UO-1-SN for Profile 1.
            // Future: could check lower bits for UO-1-TS, UO-1-IP-ID if they have unique first bytes.
            return Self::Uo1Sn;
        }

        Self::Unknown(byte)
    }
}

/// ROHC IR packet data for Profile 1 (RTP/UDP/IP).
/// This structure holds the fields that are transmitted in an IR or IR-DYN packet
/// for ROHC Profile 1.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RohcIrProfile1Packet {
    /// Context Identifier (CID) for this ROHC flow.
    /// This field is typically set by the dispatcher based on an Add-CID octet
    /// or implicitly if no Add-CID is present (e.g., for CID 0).
    /// The parser for IR packets might default this, relying on the dispatcher.
    pub cid: u16,
    /// ROHC Profile Identifier (e.g., 0x01 for RTP/UDP/IP).
    pub profile: RohcProfile,
    /// Calculated CRC-8 over the IR packet's payload (Profile + Static Chain + Dynamic Chain).
    pub crc8: u8,
    // Static Part
    pub static_ip_src: std::net::Ipv4Addr,
    pub static_ip_dst: std::net::Ipv4Addr,
    pub static_udp_src_port: u16,
    pub static_udp_dst_port: u16,
    pub static_rtp_ssrc: u32,
    // Dynamic Part (present if D-bit was 1 in IR type octet)
    pub dyn_rtp_sn: u16,
    pub dyn_rtp_timestamp: u32,
    pub dyn_rtp_marker: bool,
}

impl Default for RohcIrProfile1Packet {
    /// Creates a default `RohcIrProfile1Packet`.
    /// Note: The `cid` and `crc8` fields, and all static/dynamic fields,
    /// should be properly set before building or after parsing.
    fn default() -> Self {
        Self {
            cid: 0, // Default CID, dispatcher should manage actual CID
            profile: RohcProfile::RtpUdpIp,
            crc8: 0, // CRC should be calculated during build or verified during parse
            static_ip_src: Ipv4Addr::UNSPECIFIED,
            static_ip_dst: Ipv4Addr::UNSPECIFIED,
            static_udp_src_port: 0,
            static_udp_dst_port: 0,
            static_rtp_ssrc: 0,
            dyn_rtp_sn: 0,
            dyn_rtp_timestamp: 0,
            dyn_rtp_marker: false,
        }
    }
}

/// ROHC UO-0 packet data for Profile 1 (RTP/UDP/IP).
/// This packet type is highly compressed, typically 1 byte for CID 0,
/// and carries LSBs of the RTP Sequence Number and a 3-bit CRC.
#[derive(Debug, Clone, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
pub struct RohcUo0PacketProfile1 {
    /// Context Identifier (CID).
    /// `None` if this UO-0 packet is for the implicit CID 0 (i.e., no Add-CID octet was present).
    /// `Some(u8)` if an Add-CID octet was processed by the dispatcher, providing the small CID.
    /// Note: UO-0 typically uses small CIDs or CID 0.
    pub cid: Option<u8>, // For CID 0 or small CIDs from Add-CID
    /// Least Significant Bits of the RTP Sequence Number (typically 4 bits).
    pub sn_lsb: u8,
    /// 3-bit CRC calculated over parts of the reconstructed uncompressed header.
    pub crc3: u8,
}

/// ROHC UO-1 packet data for Profile 1 (RTP/UDP/IP).
/// This variant focuses on UO-1-SN but can be extended for other UO-1 types.
/// It carries LSBs for SN, the RTP Marker bit, and an 8-bit CRC.
/// It can also optionally carry LSBs for Timestamp or IP-ID in other UO-1 forms.
#[derive(Debug, Clone, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
pub struct RohcUo1PacketProfile1 {
    // For simplicity in UO-1 parsing/building in packet_processor
    // doesn't explicitly handle Add-CID itself. Dispatcher would.

    // Fields for UO-1-SN
    /// Least Significant Bits of the RTP Sequence Number.
    pub sn_lsb: u16, // Can be more than 8 bits for some UO-1 variants, though P1 UO-1-SN is often 8.
    /// Number of LSBs used for the `sn_lsb` field.
    pub num_sn_lsb_bits: u8,
    /// Value of the RTP Marker bit. `Some(bool)` if conveyed by this packet.
    pub rtp_marker_bit_value: Option<bool>, // Marker is often part of UO-1-SN type

    // Optional fields for other UO-1 variants (e.g., UO-1-TS, UO-1-IP-ID)
    /// Least Significant Bits of the RTP Timestamp (if UO-1-TS variant).
    pub ts_lsb: Option<u16>,
    /// Number of LSBs used for `ts_lsb`.
    pub num_ts_lsb_bits: Option<u8>,
    // pub ip_id_lsb: Option<u16>, // For UO-1-IP-ID
    // pub num_ip_id_lsb_bits: Option<u8>,
    /// 8-bit CRC. UO-1 packets typically use an 8-bit CRC.
    pub crc8: u8,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rtp_udp_ipv4_headers_serde_roundtrip() {
        let original = RtpUdpIpv4Headers {
            ip_src: "1.2.3.4".parse().unwrap(),
            ip_dst: "5.6.7.8".parse().unwrap(),
            rtp_sequence_number: 12345,
            ..Default::default()
        };

        let serialized = serde_json::to_string(&original).unwrap();
        println!("Serialized RtpUdpIpv4Headers: {}", serialized);
        let deserialized: RtpUdpIpv4Headers = serde_json::from_str(&serialized).unwrap();

        assert_eq!(original, deserialized);
    }

    #[test]
    fn rohc_ir_profile1_packet_serde_roundtrip() {
        let original = RohcIrProfile1Packet {
            static_ip_src: "10.0.0.1".parse().unwrap(),
            dyn_rtp_sn: 555,
            ..Default::default()
        };

        let serialized = serde_json::to_string(&original).unwrap();
        println!("Serialized RohcIrProfile1Packet: {}", serialized);
        let deserialized: RohcIrProfile1Packet = serde_json::from_str(&serialized).unwrap();

        assert_eq!(original, deserialized);
    }

    #[test]
    fn rohc_uo0_profile1_packet_serde_roundtrip() {
        let original = RohcUo0PacketProfile1 {
            cid: Some(1),
            sn_lsb: 0x0A,
            crc3: 0x05,
        };
        let serialized = serde_json::to_string(&original).unwrap();
        let deserialized: RohcUo0PacketProfile1 = serde_json::from_str(&serialized).unwrap();
        assert_eq!(original, deserialized);
    }

    #[test]
    fn rohc_uo1_profile1_packet_serde_roundtrip() {
        let original = RohcUo1PacketProfile1 {
            sn_lsb: 0xABCD,
            num_sn_lsb_bits: 16,
            rtp_marker_bit_value: Some(true),
            crc8: 0xFF,
            ts_lsb: Some(0x1234),
            num_ts_lsb_bits: Some(16),
        };
        let serialized = serde_json::to_string(&original).unwrap();
        let deserialized: RohcUo1PacketProfile1 = serde_json::from_str(&serialized).unwrap();
        assert_eq!(original, deserialized);
    }

    #[test]
    fn rohc_packet_discriminator_from_first_byte_ir_packets() {
        assert_eq!(
            RohcPacketDiscriminator::from_first_byte(ROHC_IR_PACKET_TYPE_STATIC_ONLY),
            RohcPacketDiscriminator::IrStatic
        );
        assert_eq!(
            RohcPacketDiscriminator::from_first_byte(ROHC_IR_PACKET_TYPE_WITH_DYN),
            RohcPacketDiscriminator::IrDyn
        );
    }

    #[test]
    fn rohc_packet_discriminator_from_first_byte_uo0_packet() {
        // UO-0 for CID 0: 0xxxxxxx (MSB is 0)
        assert_eq!(
            RohcPacketDiscriminator::from_first_byte(0b01010101),
            RohcPacketDiscriminator::Uo0
        );
        assert_eq!(
            RohcPacketDiscriminator::from_first_byte(0b00000000),
            RohcPacketDiscriminator::Uo0
        );
        assert_eq!(
            RohcPacketDiscriminator::from_first_byte(0b01111111),
            RohcPacketDiscriminator::Uo0
        );
    }

    #[test]
    fn rohc_packet_discriminator_from_first_byte_uo1_sn_packet() {
        // UO-1-SN (Profile 1): 1010000M
        assert_eq!(
            RohcPacketDiscriminator::from_first_byte(UO_1_SN_P1_PACKET_TYPE_BASE), // M=0
            RohcPacketDiscriminator::Uo1Sn
        );
        assert_eq!(
            RohcPacketDiscriminator::from_first_byte(
                UO_1_SN_P1_PACKET_TYPE_BASE | UO_1_SN_P1_MARKER_BIT_MASK
            ), // M=1
            RohcPacketDiscriminator::Uo1Sn
        );
    }

    #[test]
    fn rohc_packet_discriminator_from_first_byte_unknown() {
        // Example of a byte that doesn't match known patterns (e.g., reserved or part of a multi-byte sequence not handled here)
        // 11000000 could be a UOR-2 start, but this basic discriminator doesn't know it yet.
        assert_eq!(
            RohcPacketDiscriminator::from_first_byte(0b11000000),
            RohcPacketDiscriminator::Unknown(0b11000000)
        );
        // An Add-CID octet like 0b11100001 should NOT be passed to this function directly.
        // It should be processed by a dispatcher first. If it were passed, it would be Unknown.
        assert_eq!(
            RohcPacketDiscriminator::from_first_byte(ADD_CID_OCTET_PREFIX_VALUE | 0x01),
            RohcPacketDiscriminator::Unknown(ADD_CID_OCTET_PREFIX_VALUE | 0x01)
        );
    }
}
