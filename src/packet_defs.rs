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
}

impl GenericUncompressedHeaders {
    pub fn as_rtp_udp_ipv4(&self) -> Option<&RtpUdpIpv4Headers> {
        match self {
            GenericUncompressedHeaders::RtpUdpIpv4(headers) => Some(headers),
        }
    }
    pub fn as_rtp_udp_ipv4_mut(&mut self) -> Option<&mut RtpUdpIpv4Headers> {
        match self {
            GenericUncompressedHeaders::RtpUdpIpv4(headers) => Some(headers),
        }
    }
}

/// Identifies ROHC packet types from initial bytes.
///
/// Used by the ROHC engine to route packets to the correct handler.
/// Identifies ROHC packet types from initial bytes.
///
/// This enum is used by the ROHC engine to determine the type of a packet
/// based on its initial bytes, allowing for proper routing to the appropriate
/// handler. It supports both small and large CIDs (Context Identifiers).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RohcPacketDiscriminator {
    /// ROHC Initialization and Refresh packet (dynamic part present).
    IrDyn,
    /// ROHC Initialization and Refresh packet (static part only).
    IrStatic,
    /// ROHC Unidirectional Optimistic type 0 packet (typically for CID 0).
    Uo0,
    /// ROHC Unidirectional Optimistic type 1, SN variant.
    Uo1Sn,
    /// ROHC Unidirectional Optimistic type 2 packet.
    Uo2,
    /// ROHC Feedback packet (type 1).
    Feedback1,
    /// ROHC Feedback packet (type 2).
    Feedback2,
    /// Potentially an Add-CID octet (engine should strip this and re-evaluate next byte).
    PossibleAddCid,
    /// Padding or reserved.
    Padding, // e.g. 0b11100000 if it's *only* an Add-CID for CID 0 which is padding
    /// Unrecognized or unsupported packet type. Contains the first byte.
    Unknown(u8),
}

impl RohcPacketDiscriminator {
    /// Determines a ROHC packet discriminator from its first byte.
    ///
    /// NOTE: This should be reworked when we implement support for more profiles.
    /// It should be able to handle different discriminator schemes etc. by then.
    pub fn from_first_byte(byte: u8) -> Self {
        // Order of checks matters here. More specific patterns first.
        if (byte & ADD_CID_OCTET_PREFIX_MASK) == ADD_CID_OCTET_PREFIX_VALUE {
            // If it's an Add-CID for CID 0 (0b11100000), it's padding.
            // Otherwise, it's an Add-CID prefixing another packet type.
            // The top-level dispatcher should handle stripping Add-CID and then
            // re-calling this or a similar function on the *next* byte.
            // For this local discriminator, we mark it as possibly AddCid.
            return if byte == ADD_CID_OCTET_PREFIX_VALUE {
                RohcPacketDiscriminator::Padding
            } else {
                RohcPacketDiscriminator::PossibleAddCid
            };
        }

        match byte {
            // IR packets: 1111110x
            b if (b & !ROHC_IR_PACKET_TYPE_D_BIT_MASK) == ROHC_IR_PACKET_TYPE_BASE => {
                if (b & ROHC_IR_PACKET_TYPE_D_BIT_MASK) != 0 {
                    Self::IrDyn
                } else {
                    Self::IrStatic
                }
            }
            // UO-0 (for CID 0): 0xxxxxxx (excluding patterns caught by Add-CID above)
            b if (b & 0x80) == 0 => Self::Uo0,
            // UO-1-SN (Profile 1): 1010000M (where M is marker bit)
            b if (b & 0b11111110) == UO_1_SN_P1_PACKET_TYPE_BASE => Self::Uo1Sn,
            _ => Self::Unknown(byte),
        }
    }
}

/// ROHC IR packet data for Profile 1 (RTP/UDP/IP).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RohcIrProfile1Packet {
    /// Context Identifier (CID) for this ROHC flow.
    /// Set by the dispatcher based on Add-CID or implicit context.
    pub cid: u16,
    /// ROHC Profile Identifier.
    pub profile: RohcProfile,
    /// Calculated CRC-8 over the IR packet.
    pub crc8: u8,
    pub static_ip_src: std::net::Ipv4Addr,
    pub static_ip_dst: std::net::Ipv4Addr,
    pub static_udp_src_port: u16,
    pub static_udp_dst_port: u16,
    pub static_rtp_ssrc: u32,
    pub dyn_rtp_sn: u16,
    pub dyn_rtp_timestamp: u32,
    pub dyn_rtp_marker: bool,
}

impl Default for RohcIrProfile1Packet {
    fn default() -> Self {
        Self {
            cid: 0,
            profile: RohcProfile::RtpUdpIp,
            crc8: 0,
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

/// ROHC UO-0 packet for Profile 1 (RTP/UDP/IP).
#[derive(Debug, Clone, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
pub struct RohcUo0PacketProfile1 {
    /// Context Identifier (CID). `None` for implicit CID 0 packets.
    /// `Some(u8)` if an Add-CID octet was processed by the dispatcher.
    pub cid: Option<u8>,
    pub sn_lsb: u8,
    pub crc3: u8,
}

/// ROHC UO-1 packet for Profile 1 with SN LSBs and Marker.
#[derive(Debug, Clone, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
pub struct RohcUo1PacketProfile1 {
    pub sn_lsb: u16,
    pub num_sn_lsb_bits: u8,
    pub rtp_marker_bit_value: Option<bool>,
    pub crc8: u8,
    pub ts_lsb: Option<u16>,
    pub num_ts_lsb_bits: Option<u8>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet_defs::RohcIrProfile1Packet;

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
            ..Default::default()
        };
        let serialized = serde_json::to_string(&original).unwrap();
        let deserialized: RohcUo1PacketProfile1 = serde_json::from_str(&serialized).unwrap();
        assert_eq!(original, deserialized);
    }
}
