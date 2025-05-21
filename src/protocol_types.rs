use serde::{Deserialize, Serialize};
use serde_with::{DisplayFromStr, serde_as};
use std::net::Ipv4Addr;

/// Represents the combined headers of an RTP/UDP/IPv4 packet.
///
/// This structure is used to hold uncompressed header information before compression
/// or after decompression. It includes fields from IPv4, UDP, and RTP headers.
#[serde_as]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RtpUdpIpv4Headers {
    /// IP Header Length (IHL): Number of 32-bit words in the IPv4 header. Typically 5.
    pub ip_ihl: u8,
    /// Differentiated Services Code Point (DSCP): Used for Quality of Service.
    pub ip_dscp: u8,
    /// Explicit Congestion Notification (ECN).
    pub ip_ecn: u8,
    /// Total Length: Entire packet size in bytes, including header and data.
    pub ip_total_length: u16,
    /// Identification: Used for uniquely identifying fragments of an original IP datagram.
    pub ip_identification: u16,
    /// Don't Fragment (DF) flag.
    pub ip_dont_fragment: bool,
    /// More Fragments (MF) flag.
    pub ip_more_fragments: bool,
    /// Fragment Offset: Indicates where in the original datagram this fragment belongs.
    pub ip_fragment_offset: u16,
    /// Time To Live (TTL): Limits the lifespan of data in a computer or network.
    pub ip_ttl: u8,
    /// Protocol: Identifies the next level protocol (e.g., UDP is 17).
    pub ip_protocol: u8,
    /// Header Checksum: For error checking of the IP header.
    pub ip_checksum: u16,
    /// Source IP Address. Serialized from/to string.
    #[serde_as(as = "DisplayFromStr")]
    pub ip_src: Ipv4Addr,
    /// Destination IP Address. Serialized from/to string.
    #[serde_as(as = "DisplayFromStr")]
    pub ip_dst: Ipv4Addr,
    /// UDP Source Port.
    pub udp_src_port: u16,
    /// UDP Destination Port.
    pub udp_dst_port: u16,
    /// UDP Length: Length in bytes of UDP header and UDP data.
    pub udp_length: u16,
    /// UDP Checksum: For error checking of UDP header and data.
    pub udp_checksum: u16,
    /// RTP Version (V): Typically 2.
    pub rtp_version: u8,
    /// RTP Padding (P) bit.
    pub rtp_padding: bool,
    /// RTP Extension (X) bit.
    pub rtp_extension: bool,
    /// RTP CSRC Count (CC): Number of contributing source identifiers.
    pub rtp_csrc_count: u8,
    /// RTP Marker (M) bit.
    pub rtp_marker: bool,
    /// RTP Payload Type (PT).
    pub rtp_payload_type: u8,
    /// RTP Sequence Number (SN).
    pub rtp_sequence_number: u16,
    /// RTP Timestamp.
    pub rtp_timestamp: u32,
    /// RTP Synchronization Source (SSRC) identifier.
    pub rtp_ssrc: u32,
    /// RTP Contributing Source (CSRC) identifiers list.
    pub rtp_csrc_list: Vec<u32>,
}

impl Default for RtpUdpIpv4Headers {
    fn default() -> Self {
        Self {
            ip_ihl: 5, // Minimum IPv4 header length (5 words * 4 bytes/word = 20 bytes)
            ip_dscp: 0,
            ip_ecn: 0,
            ip_total_length: 0, // Should be calculated based on payload
            ip_identification: 0,
            ip_dont_fragment: false, // Often true for RTP to avoid fragmentation issues
            ip_more_fragments: false,
            ip_fragment_offset: 0,
            ip_ttl: 64,      // Common default TTL
            ip_protocol: 17, // UDP
            ip_checksum: 0,  // Should be calculated
            ip_src: Ipv4Addr::UNSPECIFIED,
            ip_dst: Ipv4Addr::UNSPECIFIED,
            udp_src_port: 0,
            udp_dst_port: 0,
            udp_length: 0,   // Should be calculated (UDP header + RTP header + payload)
            udp_checksum: 0, // Optional for IPv4, often 0 if not calculated
            rtp_version: 2,  // Standard RTP version
            rtp_padding: false,
            rtp_extension: false,
            rtp_csrc_count: 0,
            rtp_marker: false,
            rtp_payload_type: 0, // Should be set according to media
            rtp_sequence_number: 0,
            rtp_timestamp: 0,
            rtp_ssrc: 0, // Should be a unique random value
            rtp_csrc_list: Vec::new(),
        }
    }
}

/// Represents the data structure for a ROHC IR (Initialization and Refresh) packet
/// specific to Profile 1 (RTP/UDP/IP).
///
/// This packet is used to establish or refresh the compression context.
#[serde_as]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RohcIrProfile1Packet {
    /// Context Identifier (CID) for this ROHC flow.
    pub cid: u16,
    /// ROHC Profile Identifier (e.g., 0x01 for RTP/UDP/IP).
    pub profile: u8,
    /// Calculated CRC-8 over the IR packet (excluding Add-CID and Type, but including Profile).
    pub crc8: u8,
    /// Source IP Address. Serialized from/to string.
    #[serde_as(as = "DisplayFromStr")]
    pub static_ip_src: Ipv4Addr,
    /// Destination IP Address. Serialized from/to string.
    #[serde_as(as = "DisplayFromStr")]
    pub static_ip_dst: Ipv4Addr,
    /// UDP Source Port.
    pub static_udp_src_port: u16,
    /// UDP Destination Port.
    pub static_udp_dst_port: u16,
    /// RTP Synchronization Source (SSRC) identifier.
    pub static_rtp_ssrc: u32,
    /// RTP Sequence Number.
    pub dyn_rtp_sn: u16,
    /// RTP Timestamp.
    pub dyn_rtp_timestamp: u32,
    /// RTP Marker bit.
    pub dyn_rtp_marker: bool,
}

impl Default for RohcIrProfile1Packet {
    fn default() -> Self {
        Self {
            cid: 0,
            profile: crate::constants::PROFILE_ID_RTP_UDP_IP, // Default to Profile 1
            crc8: 0, // CRC should be calculated before sending
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

/// Represents a ROHC UO-0 (Unidirectional, Optimistic, Type 0) packet for Profile 1.
///
/// This is a highly compressed packet type, typically one octet for CID 0,
/// carrying LSBs of the RTP Sequence Number and a 3-bit CRC.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct RohcUo0PacketProfile1 {
    /// Optional Context Identifier (CID). `None` for CID 0 packets where CID is implicit.
    /// `Some(u8)` if an Add-CID octet was present.
    pub cid: Option<u8>, // For small CIDs 1-15 if Add-CID octet is used.
    /// Least Significant Bits (LSBs) of the RTP Sequence Number.
    /// The number of bits is defined by the context (typically 4 for UO-0).
    pub sn_lsb: u8,
    /// 3-bit CRC calculated over the (reconstructed) original uncompressed header.
    pub crc3: u8,
}

/// Represents a ROHC UO-1 (Unidirectional, Optimistic, Type 1) packet for Profile 1.
///
/// This packet type is used when more information needs to be conveyed than UO-0 allows,
/// such as changes in the RTP Marker bit or when more LSBs of the SN are needed.
/// This specific variant focuses on SN and Marker changes.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct RohcUo1PacketProfile1 {
    // Note: CID is handled by Add-CID octet if present, not part of this core UO-1 struct.
    /// Least Significant Bits (LSBs) of the RTP Sequence Number.
    pub sn_lsb: u16, // Can hold up to 16 bits, actual bits used depend on packet format variant
    /// Number of LSBs of the SN actually present in this packet (e.g., 8 for UO-1-SN).
    pub num_sn_lsb_bits: u8,
    /// Indicates if the RTP Marker bit value, as represented in this packet.
    /// `Some(true)` if marker is set in this packet, `Some(false)` if not.
    /// For UO-1-SN, this directly reflects the marker bit in the type octet.
    /// Other UO-1 variants might not carry this explicitly.
    pub rtp_marker_bit_value: Option<bool>,
    /// 8-bit CRC calculated over the (reconstructed) original uncompressed header.
    pub crc8: u8,
}

// Test module remains unchanged from the original as it already aligns well.
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
        };
        let serialized = serde_json::to_string(&original).unwrap();
        let deserialized: RohcUo1PacketProfile1 = serde_json::from_str(&serialized).unwrap();
        assert_eq!(original, deserialized);
    }
}
