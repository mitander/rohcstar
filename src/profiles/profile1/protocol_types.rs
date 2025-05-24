//! Protocol header types specific to ROHC (Robust Header Compression) Profile 1 (RTP/UDP/IP).
//!
//! This module defines the structure for representing combined uncompressed
//! RTP/UDP/IPv4 headers, which are the target for compression and the result
//! of decompression for Profile 1.

use serde::{Deserialize, Serialize};
use serde_with::{DisplayFromStr, serde_as};
use std::net::Ipv4Addr;

use crate::constants::{
    DEFAULT_IPV4_TTL, IP_PROTOCOL_UDP, IPV4_STANDARD_IHL, RTP_MAX_CSRC_COUNT, RTP_VERSION,
};

/// Represents the combined uncompressed headers for an RTP/UDP/IPv4 packet.
///
/// This structure is used by ROHC Profile 1 to:
/// - Receive uncompressed headers for compression.
/// - Store reconstructed headers after decompression.
/// - Hold static and dynamic field values within the compression/decompression contexts.
#[serde_as]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RtpUdpIpv4Headers {
    // IPv4 Fields
    /// IPv4 Version (should be 4). Implicit, not usually stored as ROHC P1 assumes IPv4.
    // pub ip_version: u8,
    /// IPv4 Internet Header Length (IHL) in 32-bit words. Typically 5 for no options.
    pub ip_ihl: u8,
    /// Differentiated Services Code Point (DSCP).
    pub ip_dscp: u8,
    /// Explicit Congestion Notification (ECN).
    pub ip_ecn: u8,
    /// Total length of the IP datagram (header + data) in bytes.
    pub ip_total_length: u16,
    /// IP identification field, used for fragmentation and reassembly.
    pub ip_identification: u16,
    /// "Don't Fragment" (DF) flag in the IP header.
    pub ip_dont_fragment: bool,
    /// "More Fragments" (MF) flag in the IP header.
    pub ip_more_fragments: bool,
    /// Fragment offset in 8-byte units.
    pub ip_fragment_offset: u16,
    /// Time To Live (TTL) for the IP datagram.
    pub ip_ttl: u8,
    /// Protocol number of the encapsulated protocol (should be 17 for UDP).
    pub ip_protocol: u8,
    /// IPv4 header checksum.
    pub ip_checksum: u16,
    /// Source IPv4 address.
    #[serde_as(as = "DisplayFromStr")]
    pub ip_src: Ipv4Addr,
    /// Destination IPv4 address.
    #[serde_as(as = "DisplayFromStr")]
    pub ip_dst: Ipv4Addr,
    // pub ip_options: Vec<u8>, // ROHC P1 typically doesn't handle varying IP options well.

    // UDP Fields
    /// UDP source port.
    pub udp_src_port: u16,
    /// UDP destination port.
    pub udp_dst_port: u16,
    /// Length of the UDP segment (header + data) in bytes.
    pub udp_length: u16,
    /// UDP checksum (optional in IPv4).
    pub udp_checksum: u16,

    // RTP Fields
    /// RTP version (should be 2).
    pub rtp_version: u8,
    /// RTP padding (P) bit. True if padding bytes are present at the end of the payload.
    pub rtp_padding: bool,
    /// RTP extension (X) bit. True if the fixed RTP header is followed by an extension header.
    pub rtp_extension: bool,
    /// RTP Contributing Source (CSRC) count (CC field). Number of CSRC identifiers.
    pub rtp_csrc_count: u8, // Should be consistent with rtp_csrc_list.len()
    /// RTP marker (M) bit. Its meaning is profile-specific.
    pub rtp_marker: bool,
    /// RTP payload type (PT). Identifies the format of the RTP payload.
    pub rtp_payload_type: u8,
    /// RTP sequence number. Incremented for each RTP data packet sent.
    pub rtp_sequence_number: u16,
    /// RTP timestamp. Reflects the sampling instant of the first octet in the RTP data packet.
    pub rtp_timestamp: u32,
    /// RTP Synchronization Source (SSRC) identifier. Uniquely identifies the source of an RTP stream.
    pub rtp_ssrc: u32,
    /// List of RTP Contributing Source (CSRC) identifiers.
    pub rtp_csrc_list: Vec<u32>,
}

impl Default for RtpUdpIpv4Headers {
    fn default() -> Self {
        Self {
            // IPv4 Defaults
            ip_ihl: IPV4_STANDARD_IHL,
            ip_dscp: 0,
            ip_ecn: 0,
            ip_total_length: 0, // Should be calculated by the sender based on actual payload.
            ip_identification: 0, // Often 0 or a counter for non-fragmented packets.
            ip_dont_fragment: false, // True is common for RTP to avoid IP fragmentation.
            ip_more_fragments: false,
            ip_fragment_offset: 0,
            ip_ttl: DEFAULT_IPV4_TTL,
            ip_protocol: IP_PROTOCOL_UDP,
            ip_checksum: 0, // Should be calculated by the sender.
            ip_src: Ipv4Addr::UNSPECIFIED,
            ip_dst: Ipv4Addr::UNSPECIFIED,

            // UDP Defaults
            udp_src_port: 0,
            udp_dst_port: 0,
            udp_length: 0, // Should be calculated (UDP header + RTP header + payload).
            udp_checksum: 0, // Optional for IPv4; often 0 if not calculated.

            // RTP Defaults
            rtp_version: RTP_VERSION,
            rtp_padding: false,
            rtp_extension: false,
            rtp_csrc_count: 0,
            rtp_marker: false,
            rtp_payload_type: 0, // Application specific, 0 is not a valid dynamic type.
            rtp_sequence_number: 0, // Should be randomized or start from a chosen value.
            rtp_timestamp: 0,    // Should be related to media clock.
            rtp_ssrc: 0,         // Should be a unique random value per stream.
            rtp_csrc_list: Vec::new(),
        }
    }
}

impl RtpUdpIpv4Headers {
    /// A simple constructor for tests or basic setup, using minimal default values.
    /// SSRC should typically be randomized for real streams.
    #[cfg(any(test, feature = "test_utils"))]
    pub fn new_simple(
        ip_src: Ipv4Addr,
        ip_dst: Ipv4Addr,
        udp_src_port: u16,
        udp_dst_port: u16,
        rtp_ssrc: u32,
        rtp_sequence_number: u16,
        rtp_timestamp: u32,
        rtp_marker: bool,
    ) -> Self {
        let mut headers = Self {
            ip_src,
            ip_dst,
            udp_src_port,
            udp_dst_port,
            rtp_ssrc,
            rtp_sequence_number,
            rtp_timestamp,
            rtp_marker,
            ..Default::default()
        };
        // Recalculate lengths (simplified for this constructor)
        // Actual IP total length and UDP length depend on RTP payload size which isn't known here.
        // ROHC primarily compresses headers, so exact lengths of payload part are less critical
        // for the ROHC logic itself, but good to have reasonable defaults.
        let rtp_header_size = 12 + (headers.rtp_csrc_list.len() * 4) as u16; // CSRC handling not in simple
        headers.udp_length = 8 + rtp_header_size; // UDP header + RTP header (no payload)
        headers.ip_total_length = 20 + headers.udp_length; // IPv4 header + UDP segment
        headers
    }

    /// Validates that the CSRC count matches the length of the CSRC list.
    pub fn validate_csrc_count(&self) -> bool {
        self.rtp_csrc_count as usize == self.rtp_csrc_list.len()
            && self.rtp_csrc_count <= RTP_MAX_CSRC_COUNT
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn default_headers_have_sane_values() {
        let headers = RtpUdpIpv4Headers::default();
        assert_eq!(headers.ip_ihl, IPV4_STANDARD_IHL);
        assert_eq!(headers.ip_protocol, IP_PROTOCOL_UDP);
        assert_eq!(headers.rtp_version, RTP_VERSION);
        assert!(headers.ip_src.is_unspecified());
        assert!(headers.validate_csrc_count());
    }

    #[test]
    fn new_simple_constructor_sets_basic_fields() {
        let headers = RtpUdpIpv4Headers::new_simple(
            Ipv4Addr::new(1, 1, 1, 1),
            Ipv4Addr::new(2, 2, 2, 2),
            1000,
            2000,
            0x12345678,
            100,
            10000,
            true,
        );
        assert_eq!(headers.ip_src, Ipv4Addr::new(1, 1, 1, 1));
        assert_eq!(headers.udp_dst_port, 2000);
        assert_eq!(headers.rtp_ssrc, 0x12345678);
        assert_eq!(headers.rtp_sequence_number, 100);
        assert!(headers.rtp_marker);
        assert!(headers.validate_csrc_count());
    }

    #[test]
    fn validate_csrc_count_logic() {
        let mut headers = RtpUdpIpv4Headers::default();
        assert!(headers.validate_csrc_count());

        headers.rtp_csrc_list.push(1);
        headers.rtp_csrc_count = 0; // Mismatch
        assert!(!headers.validate_csrc_count());

        headers.rtp_csrc_count = 1; // Match
        assert!(headers.validate_csrc_count());

        headers.rtp_csrc_count = RTP_MAX_CSRC_COUNT + 1; // Too many
        headers.rtp_csrc_list = vec![0; (RTP_MAX_CSRC_COUNT + 1) as usize];
        assert!(!headers.validate_csrc_count());

        headers.rtp_csrc_count = RTP_MAX_CSRC_COUNT;
        headers.rtp_csrc_list = vec![0; RTP_MAX_CSRC_COUNT as usize];
        assert!(headers.validate_csrc_count());
    }

    #[test]
    fn serde_rtp_udp_ipv4_headers_roundtrip() {
        let original = RtpUdpIpv4Headers::new_simple(
            "192.168.1.10".parse().unwrap(),
            "10.0.0.1".parse().unwrap(),
            12345,
            54321,
            rand::random(), // SSRC
            1001,
            3000,
            false,
        );

        let serialized = serde_json::to_string_pretty(&original).unwrap();
        println!("Serialized RtpUdpIpv4Headers:\n{}", serialized);
        let deserialized: RtpUdpIpv4Headers = serde_json::from_str(&serialized).unwrap();

        assert_eq!(original, deserialized);
    }
}
