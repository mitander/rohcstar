//! Definitions for ROHC-specific packet types, profile identifiers, and related enums.

use serde::{Deserialize, Serialize};

use crate::constants::*;
use crate::protocol_types::RtpUdpIpv4Headers;

/// Represents ROHC Profile Identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum RohcProfile {
    Uncompressed = PROFILE_ID_UNCOMPRESSED, // Assuming you'll define this constant
    RtpUdpIp = PROFILE_ID_RTP_UDP_IP,
    UdpIp = PROFILE_ID_UDP_IP, // Assuming constant PROFILE_ID_UDP_IP
    Ip = PROFILE_ID_IP_ONLY,   // Assuming constant PROFILE_ID_IP_ONLY
    TcpIp = PROFILE_ID_TCP_IP, // Assuming constant PROFILE_ID_TCP_IP
    // Placeholder for ROHCv2 profiles if needed later
    // RohcEth = 0x0008, // Example for Ethernet profile
    Unknown(u8), // Fallback for unrecognized profile IDs
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
            RohcProfile::Unknown(val) => val, // Or panic, or a reserved "error" ID
        }
    }
}

/// Generic wrapper for different types of uncompressed packet headers.
///
/// This allows profile handlers to receive and return various header types
/// through a common interface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GenericUncompressedHeaders {
    RtpUdpIpv4(RtpUdpIpv4Headers),
    // Example for future profiles:
    // UdpIpv4(UdpIpv4Headers),
    // TcpIpv4(TcpIpv4Headers),
}

// Forward RtpUdpIpv4Headers methods if needed, or require matching. Example:
impl GenericUncompressedHeaders {
    pub fn as_rtp_udp_ipv4(&self) -> Option<&RtpUdpIpv4Headers> {
        match self {
            GenericUncompressedHeaders::RtpUdpIpv4(headers) => Some(headers),
            // _ => None,
        }
    }
    pub fn as_rtp_udp_ipv4_mut(&mut self) -> Option<&mut RtpUdpIpv4Headers> {
        match self {
            GenericUncompressedHeaders::RtpUdpIpv4(headers) => Some(headers),
            // _ => None,
        }
    }
}

/// Discriminator for identifying the high-level type of a ROHC packet
/// based on its initial octet(s).
///
/// This is used by the main ROHC engine/dispatcher to route packets to the
/// appropriate `ProfileHandler` or to specific logic within a handler.
/// The `from_first_byte` method provides a basic interpretation. More complex
/// dispatching (e.g., handling Add-CID followed by a type) is done by the engine.
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
    // Add other UO-1 variants as they are defined, e.g.:
    // Uo1SnTs,
    // Uo1Id,
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
    /// Note: This function provides a basic classification. A full dispatcher
    /// needs to handle Add-CID octets (which means looking at the *next* byte
    /// for the actual ROHC packet type) and multi-byte discriminators if any.
    /// This primarily helps a `ProfileHandler` distinguish core packet types
    /// *after* Add-CID has been potentially stripped by a higher-level dispatcher.
    ///
    /// NOTE: this should be reworked when we implement support for more profiles.
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
            // Add future UO-1 variants here, e.g., UO-1-TS
            // b if (b & 0xF0) == UO_1_TYPE_TS_VARIANT_BASE => Self::Uo1SnTs,

            // Example placeholder for UO-2 (starts 110xxxxx typically for RTP)
            // b if (b & 0xE0) == ROHC_UO2_PACKET_TYPE_BASE => Self::Uo2,

            // Example placeholder for Feedback (starts 11110xxx usually)
            // b if (b & 0xF8) == ROHC_FEEDBACK_TYPE_1_BASE => Self::Feedback1,
            // b if (b & 0xF8) == ROHC_FEEDBACK_TYPE_2_BASE => Self::Feedback2,
            _ => Self::Unknown(byte),
        }
    }
}

// --- ROHC Packet Data Structs (Moved from protocol_types.rs) ---
// These structs represent the *logical content* of specific ROHC packets for a given profile.
// They are used by profile handlers after parsing the raw bytes.

/// Represents the data structure for a ROHC IR (Initialization and Refresh) packet
/// specific to Profile 1 (RTP/UDP/IP).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RohcIrProfile1Packet {
    /// Context Identifier (CID) for this ROHC flow.
    /// This is set by the dispatcher based on Add-CID or implicit context.
    pub cid: u16,
    /// ROHC Profile Identifier.
    pub profile: RohcProfile, // Changed from u8
    /// Calculated CRC-8 over the IR packet.
    pub crc8: u8,
    // Static chain fields remain the same
    pub static_ip_src: std::net::Ipv4Addr,
    pub static_ip_dst: std::net::Ipv4Addr,
    pub static_udp_src_port: u16,
    pub static_udp_dst_port: u16,
    pub static_rtp_ssrc: u32,
    // Dynamic chain fields remain the same
    pub dyn_rtp_sn: u16,
    pub dyn_rtp_timestamp: u32,
    pub dyn_rtp_marker: bool,
}

/// Represents a ROHC UO-0 (Unidirectional, Optimistic, Type 0) packet for Profile 1.
#[derive(Debug, Clone, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
pub struct RohcUo0PacketProfile1 {
    /// Context Identifier (CID). `None` for implicit CID 0 packets.
    /// `Some(u8)` if an Add-CID octet was processed by the dispatcher.
    pub cid: Option<u8>,
    pub sn_lsb: u8,
    pub crc3: u8,
}

/// Represents a ROHC UO-1 (Unidirectional, Optimistic, Type 1) packet for Profile 1,
/// specifically the variant carrying SN LSBs and Marker information.
#[derive(Debug, Clone, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
pub struct RohcUo1PacketProfile1 {
    // CID handled by dispatcher if Add-CID was present.
    pub sn_lsb: u16,
    pub num_sn_lsb_bits: u8,
    pub rtp_marker_bit_value: Option<bool>, // Carries the actual marker value
    pub crc8: u8,
    // Add fields for TS LSBs if this struct is to be used for UO-1-TS variants
    // pub ts_lsb: Option<u16>,
    // pub num_ts_lsb_bits: Option<u8>,
}

// TODO: Define constants like PROFILE_ID_UNCOMPRESSED, PROFILE_ID_UDP_IP etc. in constants.rs
// For now, I've used them in RohcProfile enum assuming they will be added.
// If they are not specific u8 values but just variants, the From<u8>/From<RohcProfile> for u8
// will need to map to arbitrary u8 values if direct u8 representation is needed.
// For now, using existing PROFILE_ID_RTP_UDP_IP which is 0x01.
