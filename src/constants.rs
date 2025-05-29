//! Generic ROHC (Robust Header Compression) protocol constants and bitmasks.
//!
//! Defines constants broadly applicable across the ROHC framework or standard
//! protocol identifiers used by multiple ROHC profiles. Profile-specific
//! constants should reside within their respective profile modules.

// --- ROHC General Constants ---

/// Default interval (packets) for IR refresh by a compressor. Used by Profile 1.
pub const DEFAULT_IR_REFRESH_INTERVAL: u32 = 20;
/// Default `p` offset for W-LSB decoding of sequence numbers.
pub const DEFAULT_WLSB_P_OFFSET: i64 = 0;

// --- ROHC Packet Structure Constants (RFC 3095, Sec 5.2.3, 5.7.3) ---

/// Mask for the prefix of an Add-CID or ROHC Feedback (Type 0) octet.
pub const ROHC_ADD_CID_FEEDBACK_PREFIX_MASK: u8 = 0b1110_0000; // E0
/// Expected prefix value for an Add-CID or ROHC Feedback (Type 0) octet.
pub const ROHC_ADD_CID_FEEDBACK_PREFIX_VALUE: u8 = 0b1110_0000; // E0
/// Mask to extract the small CID (0-15) from an Add-CID octet.
pub const ROHC_SMALL_CID_MASK: u8 = 0x0F;

/// Base value for generic IR packet type discriminators (bits 7-1: `1111110`).
pub const ROHC_GENERIC_IR_PACKET_TYPE_BASE: u8 = 0b1111_1100; // 0xFC
/// Mask for the D-bit (Dynamic Chain present) in an IR packet type's LSB.
pub const ROHC_GENERIC_IR_D_BIT_MASK: u8 = 0b0000_0001; // 0x01

// --- ROHC Profile Identifiers (see `crate::packet_defs::RohcProfile` enum for primary type) ---

/// ROHC Uncompressed Profile Identifier (0x0000).
pub const PROFILE_ID_UNCOMPRESSED: u8 = 0x00;
/// ROHC RTP/UDP/IP Profile Identifier (0x0001).
pub const PROFILE_ID_RTP_UDP_IP: u8 = 0x01;
/// ROHC UDP/IP Profile Identifier (0x0002).
pub const PROFILE_ID_UDP_IP: u8 = 0x02;
/// ROHC IP-only Profile Identifier (0x0003).
pub const PROFILE_ID_IP_ONLY: u8 = 0x03;
/// ROHC ESP/IP Profile Identifier (0x0004).
pub const PROFILE_ID_ESP_IP: u8 = 0x04;
/// ROHC TCP/IP Profile Identifier (0x0006).
pub const PROFILE_ID_TCP_IP: u8 = 0x06;

// --- Standard Internet Protocol Numbers (IANA Assigned) ---

/// IP protocol number for ICMP (Internet Control Message Protocol).
pub const IP_PROTOCOL_ICMP: u8 = 1;
/// IP protocol number for TCP (Transmission Control Protocol).
pub const IP_PROTOCOL_TCP: u8 = 6;
/// IP protocol number for UDP (User Datagram Protocol).
pub const IP_PROTOCOL_UDP: u8 = 17;
/// IP protocol number for ESP (Encapsulating Security Payload).
pub const IP_PROTOCOL_ESP: u8 = 50;
/// IP protocol number for AH (Authentication Header).
pub const IP_PROTOCOL_AH: u8 = 51;

// --- General Header Field Constants ---

// IPv4
/// Minimum IPv4 header length in bytes (5 words * 4 bytes/word).
pub const IPV4_MIN_HEADER_LENGTH_BYTES: usize = 20;
/// Standard IPv4 IHL (Internet Header Length) in 32-bit words (no options).
pub const IPV4_STANDARD_IHL: u8 = 5;
/// Default IPv4 TTL (Time To Live) for reconstructed headers.
pub const DEFAULT_IPV4_TTL: u8 = 64;

// UDP
/// UDP header length in bytes (fixed size).
pub const UDP_HEADER_LENGTH_BYTES: usize = 8;

// RTP (RFC 3550)
/// RTP version number (typically 2).
pub const RTP_VERSION: u8 = 2;
/// Minimum RTP header length in bytes (no CSRC list).
pub const RTP_MIN_HEADER_LENGTH_BYTES: usize = 12;
/// Maximum number of CSRC identifiers in an RTP header.
pub const RTP_MAX_CSRC_COUNT: u8 = 15;
/// Minimum value for an RTP payload type.
pub const RTP_PAYLOAD_TYPE_MIN: u8 = 0;
/// Maximum value for an RTP payload type (excluding RTCP types).
pub const RTP_PAYLOAD_TYPE_MAX: u8 = 127;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profile_id_constants_are_correct() {
        assert_eq!(PROFILE_ID_UNCOMPRESSED, 0x00);
        assert_eq!(PROFILE_ID_RTP_UDP_IP, 0x01);
        assert_eq!(PROFILE_ID_UDP_IP, 0x02);
        assert_eq!(PROFILE_ID_IP_ONLY, 0x03);
        assert_eq!(PROFILE_ID_TCP_IP, 0x06);
    }

    #[test]
    fn ip_protocol_constants_are_correct() {
        assert_eq!(IP_PROTOCOL_UDP, 17);
        assert_eq!(IP_PROTOCOL_TCP, 6);
    }

    #[test]
    fn add_cid_constants_are_correct() {
        // Example: an Add-CID octet for CID 5
        let add_cid_octet_for_cid_5 = ROHC_ADD_CID_FEEDBACK_PREFIX_VALUE | 5; // 0xE5
        assert_eq!(
            add_cid_octet_for_cid_5 & ROHC_ADD_CID_FEEDBACK_PREFIX_MASK,
            ROHC_ADD_CID_FEEDBACK_PREFIX_VALUE
        );
        assert_eq!(add_cid_octet_for_cid_5 & ROHC_SMALL_CID_MASK, 5);

        // Example: CID 0 (often implicit, but can be signaled with Add-CID for padding)
        let add_cid_octet_for_cid_0 = ROHC_ADD_CID_FEEDBACK_PREFIX_VALUE; // 0xE0
        assert_eq!(add_cid_octet_for_cid_0 & ROHC_SMALL_CID_MASK, 0);
    }

    #[test]
    fn header_length_constants_are_correct() {
        assert_eq!(IPV4_MIN_HEADER_LENGTH_BYTES, 20);
        assert_eq!(UDP_HEADER_LENGTH_BYTES, 8);
        assert_eq!(RTP_MIN_HEADER_LENGTH_BYTES, 12);
    }

    #[test]
    fn default_operational_params() {
        assert_eq!(DEFAULT_IR_REFRESH_INTERVAL, 20);
        assert_eq!(DEFAULT_WLSB_P_OFFSET, 0);
    }
}
