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
