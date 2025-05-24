//! ROHC (Robust Header Compression) Profile 1 specific ROHC packet type definitions.
//!
//! This module contains Rust structures that represent the various ROHC packet
//! formats used in Profile 1 (RTP/UDP/IP compression) as outlined in RFC 3095.
//! These structures are used by the Profile 1 packet processor for parsing
//! incoming ROHC packets and for building outgoing ROHC packets.

use crate::packet_defs::RohcProfile;
use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;

/// Represents the data contained within a ROHC Profile 1 IR (Initialization/Refresh) packet.
///
/// IR packets are crucial for establishing and synchronizing the compression context
/// between the compressor and decompressor. They convey both static chain information
/// (which rarely changes) and dynamic chain information (which changes frequently).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IrPacket {
    /// Context Identifier (CID) associated with this ROHC flow.
    /// For an incoming IR packet, this might be derived by the ROHC engine from
    /// an Add-CID octet or be implicit (e.g., CID 0). For an outgoing IR packet,
    /// this is the CID of the compressor's context.
    pub cid: u16,
    /// ROHC Profile Identifier. For Profile 1, this must be `RohcProfile::RtpUdpIp`.
    pub profile_id: RohcProfile,
    /// The 8-bit CRC calculated over the IR packet's payload (which includes the
    /// profile octet, static chain, and dynamic chain if present).
    pub crc8: u8,

    /// Source IPv4 address.
    pub static_ip_src: Ipv4Addr,
    /// Destination IPv4 address.
    pub static_ip_dst: Ipv4Addr,
    /// UDP source port.
    pub static_udp_src_port: u16,
    /// UDP destination port.
    pub static_udp_dst_port: u16,
    /// RTP Synchronization Source (SSRC) identifier.
    pub static_rtp_ssrc: u32,

    // These are present if the D-bit was set in the IR packet type octet,
    // indicating an IR-DYN packet. For an IR packet (D-bit = 0), these might hold
    // default or last known values, but are not strictly part of the "dynamic chain"
    // payload in that specific packet format. However, the struct holds them for completeness
    // as context initialization always requires them.
    /// RTP sequence number.
    pub dyn_rtp_sn: u16,
    /// RTP timestamp.
    pub dyn_rtp_timestamp: u32,
    /// RTP marker bit.
    pub dyn_rtp_marker: bool,
}

impl Default for IrPacket {
    /// Creates a default `IrPacket` for Profile 1.
    ///
    /// Note: Fields like `cid`, `crc8`, and all static/dynamic header fields
    /// must be appropriately set based on the actual packet data or context
    /// before this struct is used for building or after it's populated from parsing.
    /// The `profile` field defaults to `RohcProfile::RtpUdpIp`.
    fn default() -> Self {
        Self {
            cid: 0,                            // Typically set by engine or context
            profile_id: RohcProfile::RtpUdpIp, // Specific to Profile 1
            crc8: 0,                           // Must be calculated or verified
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

/// Represents the data contained within a ROHC Profile 1 UO-0 (Unidirectional Optimistic type 0) packet.
///
/// UO-0 packets are highly compressed, often only 1 byte for CID 0 flows.
/// They carry LSB-encoded parts of the RTP Sequence Number and a 3-bit CRC.
/// The RTP Marker bit and Timestamp are implicitly assumed to be unchanged from the context.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Uo0Packet {
    /// Context Identifier (CID).
    /// - `None`: Indicates this UO-0 packet is for the implicit CID 0 (no Add-CID octet was present).
    /// - `Some(u8)`: Indicates an Add-CID octet was processed by the ROHC engine,
    ///   providing the small CID (1-15) for this packet.
    pub cid: Option<u8>,

    /// Least Significant Bits (LSBs) of the RTP Sequence Number.
    /// For Profile 1 UO-0, this is typically 4 bits.
    pub sn_lsb: u8,

    /// The 3-bit CRC calculated over parts of the (conceptually) reconstructed uncompressed header.
    pub crc3: u8,
}

/// Represents data for ROHC Profile 1 UO-1 (Unidirectional Optimistic type 1) packets.
///
/// UO-1 packets offer more robust updates than UO-0. This struct primarily covers
/// UO-1-SN (carrying LSBs of SN and the Marker bit). It can be extended or specialized
/// for other UO-1 variants like UO-1-TS (Timestamp) or UO-1-ID (IP-ID).
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Uo1Packet {
    /// Context Identifier (CID).
    /// - `None`: Indicates this UO-1 packet is for the implicit CID 0.
    /// - `Some(u8)`: Indicates an Add-CID octet should be prepended for this small CID (1-15).
    pub cid: Option<u8>,
    /// Least Significant Bits (LSBs) of the RTP Sequence Number.
    pub sn_lsb: u16, // For UO-1-SN, this is often 8 bits, but field allows for more.
    /// Number of LSBs used for the `sn_lsb` field (e.g., 8 for standard UO-1-SN).
    pub num_sn_lsb_bits: u8,

    /// Value of the RTP Marker bit.
    /// `Some(bool)` if explicitly conveyed by this UO-1 packet (typical for UO-1-SN).
    /// `None` if not conveyed by this particular UO-1 variant.
    pub marker: bool,

    /// Optional Least Significant Bits (LSBs) of the RTP Timestamp.
    /// Present for UO-1-TS variants.
    pub ts_lsb: Option<u16>, // Typically 16 bits if present.
    /// Optional number of LSBs used for `ts_lsb`.
    pub num_ts_lsb_bits: Option<u8>,

    /// The 8-bit CRC. UO-1 packets typically use an 8-bit CRC for error detection.
    pub crc8: u8,
    // TODO: pub ip_id_lsb: Option<u16>, // UO-1-IP-ID
    // TODO: pub num_ip_id_lsb_bits: Option<u8>, // UO-1-IP-ID
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn ir_packet_defaults_and_construction() {
        let default_ir = IrPacket::default();
        assert_eq!(default_ir.cid, 0);
        assert_eq!(default_ir.profile_id, RohcProfile::RtpUdpIp);
        assert_eq!(default_ir.static_ip_src, Ipv4Addr::UNSPECIFIED);
        assert_eq!(default_ir.dyn_rtp_sn, 0);

        let custom_ir = IrPacket {
            cid: 5,
            profile_id: RohcProfile::RtpUdpIp,
            crc8: 0xAB,
            static_ip_src: "1.2.3.4".parse().unwrap(),
            static_ip_dst: "5.6.7.8".parse().unwrap(),
            static_udp_src_port: 1000,
            static_udp_dst_port: 2000,
            static_rtp_ssrc: 0x12345678,
            dyn_rtp_sn: 100,
            dyn_rtp_timestamp: 1000,
            dyn_rtp_marker: true,
        };
        assert_eq!(custom_ir.cid, 5);
        assert_eq!(custom_ir.static_rtp_ssrc, 0x12345678);
        assert!(custom_ir.dyn_rtp_marker);
    }

    #[test]
    fn uo0_packet_defaults_and_construction() {
        let default_uo0 = Uo0Packet::default();
        assert_eq!(default_uo0.cid, None);
        assert_eq!(default_uo0.sn_lsb, 0);
        assert_eq!(default_uo0.crc3, 0);

        let custom_uo0_cid0 = Uo0Packet {
            cid: None,
            sn_lsb: 0x0A, // 10
            crc3: 0x05,   // 5
        };
        assert_eq!(custom_uo0_cid0.sn_lsb, 10);

        let custom_uo0_cid5 = Uo0Packet {
            cid: Some(5),
            sn_lsb: 0x0F, // 15
            crc3: 0x07,   // 7
        };
        assert_eq!(custom_uo0_cid5.cid, Some(5));
        assert_eq!(custom_uo0_cid5.crc3, 7);
    }

    #[test]
    fn uo1_packet_defaults_and_construction() {
        let default_uo1 = Uo1Packet::default();
        assert_eq!(default_uo1.sn_lsb, 0);
        assert_eq!(default_uo1.num_sn_lsb_bits, 0); // Default u8 is 0
        assert_eq!(default_uo1.marker, false);
        assert_eq!(default_uo1.ts_lsb, None);
        assert_eq!(default_uo1.crc8, 0);

        let custom_uo1_sn = Uo1Packet {
            cid: None,
            sn_lsb: 0xAB, // 171
            num_sn_lsb_bits: 8,
            marker: true,
            ts_lsb: None,
            num_ts_lsb_bits: None,
            crc8: 0xCD,
        };
        assert_eq!(custom_uo1_sn.sn_lsb, 0xAB);
        assert_eq!(custom_uo1_sn.num_sn_lsb_bits, 8);
        assert_eq!(custom_uo1_sn.marker, true);

        let custom_uo1_ts = Uo1Packet {
            cid: None,
            sn_lsb: 0x1234,
            num_sn_lsb_bits: 16, // Could be for a different UO-1 variant
            marker: false,
            ts_lsb: Some(0x5678),
            num_ts_lsb_bits: Some(16),
            crc8: 0xEF,
        };
        assert_eq!(custom_uo1_ts.ts_lsb, Some(0x5678));
        assert_eq!(custom_uo1_ts.num_ts_lsb_bits, Some(16));
    }

    #[test]
    fn packet_types_serde_roundtrip() {
        let ir = IrPacket {
            cid: 1,
            profile_id: RohcProfile::RtpUdpIp,
            crc8: 1,
            static_ip_src: "1.1.1.1".parse().unwrap(),
            static_ip_dst: "2.2.2.2".parse().unwrap(),
            static_udp_src_port: 10,
            static_udp_dst_port: 20,
            static_rtp_ssrc: 30,
            dyn_rtp_sn: 40,
            dyn_rtp_timestamp: 50,
            dyn_rtp_marker: true,
        };
        let ser_ir = serde_json::to_string(&ir).unwrap();
        let de_ir: IrPacket = serde_json::from_str(&ser_ir).unwrap();
        assert_eq!(ir, de_ir);

        let uo0 = Uo0Packet {
            cid: Some(2),
            sn_lsb: 3,
            crc3: 4,
        };
        let ser_uo0 = serde_json::to_string(&uo0).unwrap();
        let de_uo0: Uo0Packet = serde_json::from_str(&ser_uo0).unwrap();
        assert_eq!(uo0, de_uo0);

        let uo1 = Uo1Packet {
            cid: None,
            sn_lsb: 5,
            num_sn_lsb_bits: 8,
            marker: false,
            ts_lsb: Some(6),
            num_ts_lsb_bits: Some(16),
            crc8: 7,
        };
        let ser_uo1 = serde_json::to_string(&uo1).unwrap();
        let de_uo1: Uo1Packet = serde_json::from_str(&ser_uo1).unwrap();
        assert_eq!(uo1, de_uo1);
    }
}
