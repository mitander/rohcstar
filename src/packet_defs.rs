//! Generic ROHC (Robust Header Compression) packet definitions and identifiers.
//!
//! This module defines enums and structs that are broadly applicable across
//! different ROHC profiles, such as the `RohcProfile` identifier and a
//! generic container for various uncompressed header types.

use bytes::Bytes;
use serde::{Deserialize, Serialize};

/// Supported ROHC profile identifiers.
///
/// Each profile specifies a different set of protocols that can be compressed.
/// The numeric values correspond to the profile identifiers defined in ROHC RFCs.
/// This enum is central to dispatching packets to the correct profile handler.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum RohcProfile {
    /// ROHC Uncompressed Profile (Profile 0x0000).
    /// Used for passthrough of uncompressed packets.
    Uncompressed = 0x00,
    /// ROHC RTP/UDP/IP Profile (Profile 0x0001).
    /// Compresses Real-time Transport Protocol, User Datagram Protocol, and Internet Protocol headers.
    RtpUdpIp = 0x01,
    /// ROHC UDP/IP Profile (Profile 0x0002).
    /// Compresses User Datagram Protocol and Internet Protocol headers.
    UdpIp = 0x02,
    /// ROHC IP-only Profile (Profile 0x0003).
    /// Compresses Internet Protocol headers.
    Ip = 0x03,
    /// ROHC TCP/IP Profile (Profile 0x0006).
    /// Compresses Transmission Control Protocol and Internet Protocol headers.
    TcpIp = 0x06,
    // ESP/IP (Profile 0x0004) and others could be added here.
    /// Represents an unknown or unsupported ROHC profile.
    /// The enclosed `u8` is the unrecognized profile identifier.
    Unknown(u8),
}

impl From<u8> for RohcProfile {
    fn from(value: u8) -> Self {
        match value {
            0x00 => RohcProfile::Uncompressed,
            0x01 => RohcProfile::RtpUdpIp,
            0x02 => RohcProfile::UdpIp,
            0x03 => RohcProfile::Ip,
            0x06 => RohcProfile::TcpIp,
            unknown_id => RohcProfile::Unknown(unknown_id),
        }
    }
}

impl From<RohcProfile> for u8 {
    fn from(profile: RohcProfile) -> Self {
        match profile {
            RohcProfile::Uncompressed => 0x00,
            RohcProfile::RtpUdpIp => 0x01,
            RohcProfile::UdpIp => 0x02,
            RohcProfile::Ip => 0x03,
            RohcProfile::TcpIp => 0x06,
            RohcProfile::Unknown(val) => val,
        }
    }
}

/// A generic container for various types of uncompressed protocol headers.
///
/// This enum allows profile handlers to work with different header formats
/// through a unified interface. Each variant will correspond to the set of
/// headers a specific ROHC profile (or a group of similar profiles) can process.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GenericUncompressedHeaders {
    /// Uncompressed headers for RTP/UDP/IPv4, typically processed by ROHC Profile 1.
    /// The actual struct `RtpUdpIpv4Headers` will be defined within the Profile 1 module.
    /// We use a fully qualified path here to indicate its future location.
    RtpUdpIpv4(crate::profiles::profile1::protocol_types::RtpUdpIpv4Headers),

    /// A raw byte payload primarily for testing or for profiles that handle opaque data.
    /// This allows mock profile handlers to easily construct and inspect `GenericUncompressedHeaders`.
    TestRaw(Bytes),
}

impl GenericUncompressedHeaders {
    /// Attempts to return a reference to RTP/UDP/IPv4 headers.
    ///
    /// # Returns
    /// `Some(&RtpUdpIpv4Headers)` if the variant is `RtpUdpIpv4`, otherwise `None`.
    pub fn as_rtp_udp_ipv4(
        &self,
    ) -> Option<&crate::profiles::profile1::protocol_types::RtpUdpIpv4Headers> {
        match self {
            GenericUncompressedHeaders::RtpUdpIpv4(headers) => Some(headers),
            _ => None,
        }
    }

    /// Attempts to return a mutable reference to RTP/UDP/IPv4 headers.
    ///
    /// # Returns
    /// `Some(&mut RtpUdpIpv4Headers)` if the variant is `RtpUdpIpv4`, otherwise `None`.
    pub fn as_rtp_udp_ipv4_mut(
        &mut self,
    ) -> Option<&mut crate::profiles::profile1::protocol_types::RtpUdpIpv4Headers> {
        match self {
            GenericUncompressedHeaders::RtpUdpIpv4(headers) => Some(headers),
            _ => None,
        }
    }

    /// Creates a `GenericUncompressedHeaders::TestRaw` variant from a byte vector.
    /// Available for testing purposes.
    #[cfg(test)]
    pub fn new_test_raw(data: Vec<u8>) -> Self {
        Self::TestRaw(Bytes::from(data))
    }

    /// Attempts to return a reference to the inner `Bytes` if the variant is `TestRaw`.
    #[cfg(test)]
    pub fn as_test_raw(&self) -> Option<&Bytes> {
        match self {
            GenericUncompressedHeaders::TestRaw(bytes) => Some(bytes),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;

    #[test]
    fn rohc_profile_from_u8() {
        assert_eq!(RohcProfile::from(0x00), RohcProfile::Uncompressed);
        assert_eq!(RohcProfile::from(0x01), RohcProfile::RtpUdpIp);
        assert_eq!(RohcProfile::from(0x02), RohcProfile::UdpIp);
        assert_eq!(RohcProfile::from(0x03), RohcProfile::Ip);
        assert_eq!(RohcProfile::from(0x06), RohcProfile::TcpIp);
        assert_eq!(RohcProfile::from(0xFF), RohcProfile::Unknown(0xFF));
    }

    #[test]
    fn rohc_profile_into_u8() {
        assert_eq!(u8::from(RohcProfile::Uncompressed), 0x00);
        assert_eq!(u8::from(RohcProfile::RtpUdpIp), 0x01);
        assert_eq!(u8::from(RohcProfile::UdpIp), 0x02);
        assert_eq!(u8::from(RohcProfile::Ip), 0x03);
        assert_eq!(u8::from(RohcProfile::TcpIp), 0x06);
        assert_eq!(u8::from(RohcProfile::Unknown(0xFF)), 0xFF);
    }

    #[test]
    fn rohc_profile_serde_roundtrip() {
        let original_profiles = vec![
            RohcProfile::Uncompressed,
            RohcProfile::RtpUdpIp,
            RohcProfile::Unknown(0xFA),
        ];
        let serialized = serde_json::to_string(&original_profiles).unwrap();
        let deserialized: Vec<RohcProfile> = serde_json::from_str(&serialized).unwrap();
        assert_eq!(original_profiles, deserialized);
    }

    #[test]
    fn generic_uncompressed_headers_test_raw_construction_and_accessors() {
        let data_vec = vec![10, 20, 30];
        let mut headers_raw = GenericUncompressedHeaders::new_test_raw(data_vec.clone());

        // Test construction and `as_test_raw`
        if let Some(bytes) = headers_raw.as_test_raw() {
            assert_eq!(bytes, &Bytes::from(data_vec));
        } else {
            panic!("Expected TestRaw variant after new_test_raw");
        }

        // Test that other accessors return None for the TestRaw variant
        assert!(
            headers_raw.as_rtp_udp_ipv4().is_none(),
            "as_rtp_udp_ipv4 should be None for TestRaw"
        );
        assert!(
            headers_raw.as_rtp_udp_ipv4_mut().is_none(),
            "as_rtp_udp_ipv4_mut should be None for TestRaw"
        );
    }

    #[test]
    fn generic_uncompressed_headers_accessor_signatures_exist() {
        // Create a TestRaw variant for testing the non-matching cases of RtpUdpIpv4 accessors
        let data_vec = vec![1, 2, 3];
        let mut headers_raw = GenericUncompressedHeaders::new_test_raw(data_vec);

        // Call the accessors to ensure they compile and work for the None case
        let _ = headers_raw.as_rtp_udp_ipv4();
        let _ = headers_raw.as_rtp_udp_ipv4_mut();
        let _ = headers_raw.as_test_raw();
    }
}
