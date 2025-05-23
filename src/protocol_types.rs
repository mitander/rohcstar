//! Core ROHC protocol types.
//!
//! Defines protocol types used in the ROHC implementation.
use serde::{Deserialize, Serialize};
use serde_with::{DisplayFromStr, serde_as};
use std::net::Ipv4Addr;

use crate::constants::{DEFAULT_IPV4_TTL, IP_PROTOCOL_UDP, RTP_VERSION};

/// Combined RTP/UDP/IPv4 headers for ROHC compression/decompression.
///
/// This structure represents the uncompressed headers that ROHC Profile 1
/// operates on. It contains all fields from the IPv4, UDP, and RTP headers
/// that may be needed for compression and decompression.
#[serde_as]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RtpUdpIpv4Headers {
    /// IPv4 header length in 32-bit words (usually 5).
    pub ip_ihl: u8,
    /// DSCP for QoS.
    pub ip_dscp: u8,
    /// ECN bits.
    pub ip_ecn: u8,
    /// Total packet length (header + payload) in bytes.
    pub ip_total_length: u16,
    /// IP fragmentation ID.
    pub ip_identification: u16,
    /// If true, don't fragment packet.
    pub ip_dont_fragment: bool,
    /// If true, more fragments follow.
    pub ip_more_fragments: bool,
    /// Fragment offset in 8-byte units.
    pub ip_fragment_offset: u16,
    /// IP Time To Live (TTL).
    pub ip_ttl: u8,
    /// IP protocol number (17 = UDP).
    pub ip_protocol: u8,
    /// IPv4 header checksum.
    pub ip_checksum: u16,
    /// Source IP address.
    #[serde_as(as = "DisplayFromStr")]
    pub ip_src: Ipv4Addr,
    /// Destination IP address.
    #[serde_as(as = "DisplayFromStr")]
    pub ip_dst: Ipv4Addr,
    /// Source UDP port.
    pub udp_src_port: u16,
    /// Destination UDP port.
    pub udp_dst_port: u16,
    /// UDP length (header + payload) in bytes.
    pub udp_length: u16,
    /// UDP checksum (optional in IPv4).
    pub udp_checksum: u16,
    /// RTP version (2 = standard).
    pub rtp_version: u8,
    /// If true, payload has padding.
    pub rtp_padding: bool,
    /// If true, RTP header has extension.
    pub rtp_extension: bool,
    /// Number of CSRC identifiers.
    pub rtp_csrc_count: u8,
    /// Marker bit (payload type dependent).
    pub rtp_marker: bool,
    /// RTP payload type (media format).
    pub rtp_payload_type: u8,
    /// RTP sequence number.
    pub rtp_sequence_number: u16,
    /// RTP timestamp (clock rate is payload dependent).
    pub rtp_timestamp: u32,
    /// SSRC (random per stream).
    pub rtp_ssrc: u32,
    /// List of CSRC identifiers.
    pub rtp_csrc_list: Vec<u32>,
}

impl Default for RtpUdpIpv4Headers {
    fn default() -> Self {
        Self {
            ip_ihl: DEFAULT_IPV4_TTL, // Minimum IPv4 header length (5 words * 4 bytes/word = 20 bytes)
            ip_dscp: 0,
            ip_ecn: 0,
            ip_total_length: 0, // Should be calculated based on payload
            ip_identification: 0,
            ip_dont_fragment: false, // Often true for RTP to avoid fragmentation issues
            ip_more_fragments: false,
            ip_fragment_offset: 0,
            ip_ttl: DEFAULT_IPV4_TTL,     // Common default TTL
            ip_protocol: IP_PROTOCOL_UDP, // UDP
            ip_checksum: 0,               // Should be calculated
            ip_src: Ipv4Addr::UNSPECIFIED,
            ip_dst: Ipv4Addr::UNSPECIFIED,
            udp_src_port: 0,
            udp_dst_port: 0,
            udp_length: 0, // Should be calculated (UDP header + RTP header + payload)
            udp_checksum: 0,
            rtp_version: RTP_VERSION, // Standard RTP version
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
