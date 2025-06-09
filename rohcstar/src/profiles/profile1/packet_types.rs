//! ROHC (Robust Header Compression) Profile 1 specific ROHC packet type definitions.
//!
//! This module contains Rust structures that represent the various ROHC packet
//! formats used in Profile 1 (RTP/UDP/IP compression) as outlined in RFC 3095.
//! These structures are used by the Profile 1 packet processor for parsing
//! incoming ROHC packets and for building outgoing ROHC packets.

use crate::packet_defs::RohcProfile;
use crate::types::{ContextId, IpId, SequenceNumber, Ssrc, Timestamp};
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
    pub cid: ContextId,
    /// ROHC Profile Identifier. For Profile 1, this must be `RohcProfile::RtpUdpIp`.
    pub profile_id: RohcProfile,
    /// The 8-bit CRC calculated over the IR packet's payload.
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
    pub static_rtp_ssrc: Ssrc,

    /// RTP sequence number from dynamic chain.
    pub dyn_rtp_sn: SequenceNumber,
    /// RTP timestamp from dynamic chain.
    pub dyn_rtp_timestamp: Timestamp,
    /// RTP marker bit from dynamic chain.
    pub dyn_rtp_marker: bool,
    /// IP TTL from dynamic chain.
    pub dyn_ip_ttl: u8,
    /// IP identification from dynamic chain.
    pub dyn_ip_id: IpId,
    /// Optional RTP timestamp stride value from the IR-DYN packet's extension.
    /// Present if the compressor is signaling TS stride for TS_SCALED mode.
    pub ts_stride: Option<u32>,
}

impl Default for IrPacket {
    /// Creates a default `IrPacket` for Profile 1.
    fn default() -> Self {
        Self {
            cid: ContextId::new(0),
            profile_id: RohcProfile::RtpUdpIp,
            crc8: 0,
            static_ip_src: Ipv4Addr::UNSPECIFIED,
            static_ip_dst: Ipv4Addr::UNSPECIFIED,
            static_udp_src_port: 0,
            static_udp_dst_port: 0,
            static_rtp_ssrc: Ssrc::new(0),
            dyn_rtp_sn: SequenceNumber::new(0),
            dyn_rtp_timestamp: Timestamp::new(0),
            dyn_rtp_marker: false,
            dyn_ip_ttl: crate::constants::DEFAULT_IPV4_TTL,
            dyn_ip_id: 0.into(),
            ts_stride: None,
        }
    }
}

/// Represents data for ROHC Profile 1 UO-0 (Unidirectional Optimistic type 0) packet.
///
/// UO-0 packets are highly compressed. They carry LSB-encoded parts of the
/// RTP Sequence Number and a 3-bit CRC.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Uo0Packet {
    /// Optional small Context Identifier (CID), if an Add-CID octet was present.
    pub cid: Option<ContextId>,
    /// Least Significant Bits (LSBs) of the RTP Sequence Number.
    pub sn_lsb: u8,
    /// The 3-bit CRC.
    pub crc3: u8,
}

/// Represents data for ROHC Profile 1 UO-1 (Unidirectional Optimistic type 1) packets.
///
/// This struct is a general container for UO-1 variants. Specific fields are populated
/// based on the UO-1 sub-type (e.g., UO-1-SN, UO-1-TS, UO-1-ID, UO-1-RTP).
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Uo1Packet {
    /// Optional small Context Identifier (CID).
    pub cid: Option<ContextId>,
    /// Least Significant Bits (LSBs) of the RTP Sequence Number (used in UO-1-SN).
    pub sn_lsb: u16,
    /// Number of LSBs used for `sn_lsb` (used in UO-1-SN).
    pub num_sn_lsb_bits: u8,
    /// Value of the RTP Marker bit (used in UO-1-SN and UO-1-RTP).
    pub marker: bool,
    /// Optional LSBs of the RTP Timestamp (for UO-1-TS).
    pub ts_lsb: Option<u16>,
    /// Optional number of LSBs for `ts_lsb` (for UO-1-TS).
    pub num_ts_lsb_bits: Option<u8>,
    /// Optional LSBs of the IP Identification (for UO-1-ID).
    pub ip_id_lsb: Option<u16>,
    /// Optional number of LSBs for `ip_id_lsb` (for UO-1-ID).
    pub num_ip_id_lsb_bits: Option<u8>,
    /// Optional TS_SCALED value for UO-1-RTP packets.
    /// Represents `(current_ts - ts_offset) / ts_stride`.
    pub ts_scaled: Option<u8>,
    /// The 8-bit CRC.
    pub crc8: u8,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ir_packet_defaults_and_construction() {
        let default_ir = IrPacket::default();
        assert_eq!(default_ir.cid, 0);
        assert_eq!(default_ir.profile_id, RohcProfile::RtpUdpIp);
        assert_eq!(default_ir.static_ip_src, Ipv4Addr::UNSPECIFIED);
        assert_eq!(default_ir.dyn_rtp_sn, 0);
        assert_eq!(default_ir.dyn_rtp_timestamp, 0);
        assert_eq!(default_ir.ts_stride, None);

        let custom_ir = IrPacket {
            cid: 5.into(),
            profile_id: RohcProfile::RtpUdpIp,
            crc8: 0xAB,
            static_ip_src: "1.2.3.4".parse().unwrap(),
            static_ip_dst: "5.6.7.8".parse().unwrap(),
            static_udp_src_port: 1000,
            static_udp_dst_port: 2000,
            static_rtp_ssrc: 0x12345678.into(),
            dyn_rtp_sn: 100.into(),
            dyn_rtp_timestamp: 1000.into(),
            dyn_rtp_marker: true,
            dyn_ip_ttl: 64,
            dyn_ip_id: 0.into(),
            ts_stride: Some(160),
        };
        assert_eq!(custom_ir.cid, 5);
        assert_eq!(custom_ir.static_rtp_ssrc, 0x12345678);
        assert_eq!(custom_ir.dyn_rtp_timestamp, 1000);
        assert!(custom_ir.dyn_rtp_marker);
        assert_eq!(custom_ir.ts_stride, Some(160));
    }

    #[test]
    fn uo0_packet_defaults_and_construction() {
        let default_uo0 = Uo0Packet::default();
        assert_eq!(default_uo0.cid, None);
        assert_eq!(default_uo0.sn_lsb, 0);
        assert_eq!(default_uo0.crc3, 0);

        let custom_uo0_cid0 = Uo0Packet {
            cid: None,
            sn_lsb: 0x0A,
            crc3: 0x05,
        };
        assert_eq!(custom_uo0_cid0.sn_lsb, 10);

        let custom_uo0_cid5 = Uo0Packet {
            cid: Some(5.into()),
            sn_lsb: 0x0F,
            crc3: 0x07,
        };
        assert_eq!(custom_uo0_cid5.cid, Some(5.into()));
        assert_eq!(custom_uo0_cid5.crc3, 7);
    }

    #[test]
    fn uo1_packet_defaults_and_construction() {
        let default_uo1 = Uo1Packet::default();
        assert_eq!(default_uo1.sn_lsb, 0);
        assert_eq!(default_uo1.num_sn_lsb_bits, 0);
        assert!(!default_uo1.marker);
        assert_eq!(default_uo1.ts_lsb, None);
        assert_eq!(default_uo1.ts_scaled, None);
        assert_eq!(default_uo1.crc8, 0);

        let custom_uo1_sn = Uo1Packet {
            cid: None,
            sn_lsb: 0xAB,
            num_sn_lsb_bits: 8,
            marker: true,
            crc8: 0xCD,
            ..Default::default()
        };
        assert_eq!(custom_uo1_sn.sn_lsb, 0xAB);
        assert!(custom_uo1_sn.marker);
        assert_eq!(custom_uo1_sn.ts_scaled, None);

        let custom_uo1_rtp = Uo1Packet {
            cid: None,
            marker: true,
            ts_scaled: Some(123),
            crc8: 0xEF,
            ..Default::default()
        };
        assert!(custom_uo1_rtp.marker);
        assert_eq!(custom_uo1_rtp.ts_scaled, Some(123));
    }

    #[test]
    fn packet_types_serde_roundtrip() {
        let ir = IrPacket {
            cid: 1.into(),
            profile_id: RohcProfile::RtpUdpIp,
            crc8: 1,
            static_ip_src: "1.1.1.1".parse().unwrap(),
            static_ip_dst: "2.2.2.2".parse().unwrap(),
            static_udp_src_port: 10,
            static_udp_dst_port: 20,
            static_rtp_ssrc: 30.into(),
            dyn_rtp_sn: 40.into(),
            dyn_rtp_timestamp: 50.into(),
            dyn_rtp_marker: true,
            dyn_ip_ttl: 255,
            dyn_ip_id: 0.into(),
            ts_stride: Some(80),
        };
        let ser_ir = serde_json::to_string(&ir).unwrap();
        let de_ir: IrPacket = serde_json::from_str(&ser_ir).unwrap();
        assert_eq!(ir, de_ir);

        let uo0 = Uo0Packet {
            cid: Some(2.into()),
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
            ip_id_lsb: None,
            num_ip_id_lsb_bits: None,
            ts_scaled: Some(10),
            crc8: 7,
        };
        let ser_uo1 = serde_json::to_string(&uo1).unwrap();
        let de_uo1: Uo1Packet = serde_json::from_str(&ser_uo1).unwrap();
        assert_eq!(uo1, de_uo1);
    }
}
