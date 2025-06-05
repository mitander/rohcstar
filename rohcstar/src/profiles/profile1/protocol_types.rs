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
use crate::types::{IpId, SequenceNumber, Ssrc, Timestamp};

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
    // pub ip_version: u8, // Implicitly 4 for this profile
    /// IPv4 Internet Header Length (IHL) in 32-bit words. Typically 5 for no options.
    pub ip_ihl: u8,
    /// Differentiated Services Code Point (DSCP).
    pub ip_dscp: u8,
    /// Explicit Congestion Notification (ECN).
    pub ip_ecn: u8,
    /// Total length of the IP datagram (header + data) in bytes.
    pub ip_total_length: u16,
    /// IP identification field, used for fragmentation and reassembly.
    pub ip_identification: IpId,
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
    pub rtp_csrc_count: u8,
    /// RTP marker (M) bit. Its meaning is profile-specific.
    pub rtp_marker: bool,
    /// RTP payload type (PT). Identifies the format of the RTP payload.
    pub rtp_payload_type: u8,
    /// RTP sequence number. Incremented for each RTP data packet sent.
    pub rtp_sequence_number: SequenceNumber,
    /// RTP timestamp. Reflects the sampling instant of the first octet in the RTP data packet.
    pub rtp_timestamp: Timestamp,
    /// RTP Synchronization Source (SSRC) identifier. Uniquely identifies the source of an RTP stream.
    pub rtp_ssrc: Ssrc,
    /// List of RTP Contributing Source (CSRC) identifiers.
    pub rtp_csrc_list: Vec<u32>,
}

impl Default for RtpUdpIpv4Headers {
    fn default() -> Self {
        Self {
            ip_ihl: IPV4_STANDARD_IHL,
            ip_dscp: 0,
            ip_ecn: 0,
            ip_total_length: 0,
            ip_identification: IpId::new(0),
            ip_dont_fragment: false,
            ip_more_fragments: false,
            ip_fragment_offset: 0,
            ip_ttl: DEFAULT_IPV4_TTL,
            ip_protocol: IP_PROTOCOL_UDP,
            ip_checksum: 0,
            ip_src: Ipv4Addr::UNSPECIFIED,
            ip_dst: Ipv4Addr::UNSPECIFIED,
            udp_src_port: 0,
            udp_dst_port: 0,
            udp_length: 0,
            udp_checksum: 0,
            rtp_version: RTP_VERSION,
            rtp_padding: false,
            rtp_extension: false,
            rtp_csrc_count: 0,
            rtp_marker: false,
            rtp_payload_type: 0,
            rtp_sequence_number: SequenceNumber::new(0),
            rtp_timestamp: Timestamp::new(0),
            rtp_ssrc: Ssrc::new(0),
            rtp_csrc_list: Vec::new(),
        }
    }
}

impl RtpUdpIpv4Headers {
    /// Validates that the CSRC count matches the length of the CSRC list and max count.
    ///
    /// # Returns
    /// `true` if CSRC count is valid, `false` otherwise.
    pub fn is_csrc_count_valid(&self) -> bool {
        self.rtp_csrc_count as usize == self.rtp_csrc_list.len()
            && self.rtp_csrc_count <= RTP_MAX_CSRC_COUNT
    }

    /// Sets the IP Identification field for these headers.
    /// Primarily a test helper.
    ///
    /// # Returns
    /// Headers with the specified IP identification value.
    pub fn with_ip_id(mut self, ip_id: IpId) -> Self {
        self.ip_identification = ip_id;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test helper structure for creating `RtpUdpIpv4Headers`.
    #[derive(Debug, Clone)]
    pub struct TestData {
        pub ip_src: Ipv4Addr,
        pub ip_dst: Ipv4Addr,
        pub udp_src_port: u16,
        pub udp_dst_port: u16,
        pub rtp_ssrc: Ssrc,
        pub rtp_sequence_number: SequenceNumber,
        pub rtp_timestamp: Timestamp,
        pub rtp_marker: bool,
    }

    impl TestData {
        /// Converts `TestData` into `RtpUdpIpv4Headers`.
        pub fn to_rtp_headers(config: TestData) -> RtpUdpIpv4Headers {
            let mut headers = RtpUdpIpv4Headers {
                ip_src: config.ip_src,
                ip_dst: config.ip_dst,
                udp_src_port: config.udp_src_port,
                udp_dst_port: config.udp_dst_port,
                rtp_ssrc: config.rtp_ssrc,
                rtp_sequence_number: config.rtp_sequence_number,
                rtp_timestamp: config.rtp_timestamp,
                rtp_marker: config.rtp_marker,
                ..Default::default()
            };
            // Simplified length calculation for tests
            let rtp_header_size = 12 + (headers.rtp_csrc_list.len() * 4) as u16;
            headers.udp_length = 8 + rtp_header_size;
            headers.ip_total_length = 20 + headers.udp_length;
            headers
        }
    }

    #[test]
    fn default_headers_have_sane_values() {
        let headers = RtpUdpIpv4Headers::default();
        assert_eq!(headers.ip_ihl, IPV4_STANDARD_IHL);
        assert_eq!(headers.ip_protocol, IP_PROTOCOL_UDP);
        assert_eq!(headers.rtp_version, RTP_VERSION);
        assert!(headers.ip_src.is_unspecified());
        assert!(headers.is_csrc_count_valid());
        assert_eq!(headers.rtp_timestamp, 0);
    }

    #[test]
    fn new_simple_constructor_sets_basic_fields() {
        let test_data = TestData {
            ip_src: Ipv4Addr::new(1, 1, 1, 1),
            ip_dst: Ipv4Addr::new(2, 2, 2, 2),
            udp_src_port: 1000,
            udp_dst_port: 2000,
            rtp_ssrc: 0x12345678.into(),
            rtp_sequence_number: 100.into(),
            rtp_timestamp: 10000.into(),
            rtp_marker: true,
        };
        let headers = TestData::to_rtp_headers(test_data);

        assert_eq!(headers.ip_src, Ipv4Addr::new(1, 1, 1, 1));
        assert_eq!(headers.udp_dst_port, 2000);
        assert_eq!(headers.rtp_ssrc, 0x12345678);
        assert_eq!(headers.rtp_sequence_number, 100);
        assert_eq!(headers.rtp_timestamp, 10000);
        assert!(headers.rtp_marker);
        assert!(headers.is_csrc_count_valid());
    }

    #[test]
    fn validate_csrc_count_logic() {
        let mut headers = RtpUdpIpv4Headers::default();
        assert!(headers.is_csrc_count_valid());

        headers.rtp_csrc_list.push(1);
        headers.rtp_csrc_count = 0; // Mismatch
        assert!(!headers.is_csrc_count_valid());

        headers.rtp_csrc_count = 1; // Match
        assert!(headers.is_csrc_count_valid());

        headers.rtp_csrc_count = RTP_MAX_CSRC_COUNT + 1; // Too many
        headers.rtp_csrc_list = vec![0; (RTP_MAX_CSRC_COUNT + 1) as usize];
        assert!(!headers.is_csrc_count_valid());

        headers.rtp_csrc_count = RTP_MAX_CSRC_COUNT;
        headers.rtp_csrc_list = vec![0; RTP_MAX_CSRC_COUNT as usize];
        assert!(headers.is_csrc_count_valid());
    }

    #[test]
    fn serde_rtp_udp_ipv4_headers_roundtrip() {
        let test_data = TestData {
            ip_src: Ipv4Addr::new(192, 168, 1, 10),
            ip_dst: Ipv4Addr::new(10, 0, 0, 1),
            udp_src_port: 12345,
            udp_dst_port: 54321,
            rtp_ssrc: rand::random::<u32>().into(),
            rtp_sequence_number: 1001.into(),
            rtp_timestamp: 3000.into(),
            rtp_marker: false,
        };
        let headers = TestData::to_rtp_headers(test_data);

        let serialized = serde_json::to_string_pretty(&headers).unwrap();
        let deserialized: RtpUdpIpv4Headers = serde_json::from_str(&serialized).unwrap();

        assert_eq!(headers, deserialized);
    }

    #[test]
    fn with_ip_id_helper() {
        let headers1 = RtpUdpIpv4Headers::default();
        assert_eq!(headers1.ip_identification, 0);

        let headers2 = headers1.with_ip_id(IpId::new(12345));
        assert_eq!(headers2.ip_identification, 12345);

        let headers3 = headers2.with_ip_id(IpId::new(5));
        assert_eq!(headers3.ip_identification, 5);
    }

    #[test]
    fn timestamp_newtype_methods() {
        let ts1 = Timestamp::new(100);
        assert_eq!(ts1.value(), 100);
        let ts2 = ts1.wrapping_add(50);
        assert_eq!(ts2.value(), 150);
        assert_eq!(ts2.wrapping_diff(ts1), 50);

        let ts_max = Timestamp::new(u32::MAX);
        let ts_wrap = ts_max.wrapping_add(1);
        assert_eq!(ts_wrap.value(), 0);
        assert_eq!(ts1.to_be_bytes(), 100u32.to_be_bytes());
    }
}
