//! Generic ROHC (Robust Header Compression) protocol constants and bitmasks.
//!
//! This module defines constants that are broadly applicable across the ROHC
//! framework or are standard protocol identifiers used by multiple ROHC profiles.
//! Profile-specific constants should reside within their respective profile modules.

// --- ROHC Profile Identifiers ---
// These are fundamental to identifying which profile is in use.

/// ROHC Uncompressed Profile Identifier (Profile 0x0000).
pub const PROFILE_ID_UNCOMPRESSED: u8 = 0x00;
/// ROHC RTP/UDP/IP Profile Identifier (Profile 0x0001).
pub const PROFILE_ID_RTP_UDP_IP: u8 = 0x01;
/// ROHC UDP/IP Profile Identifier (Profile 0x0002).
pub const PROFILE_ID_UDP_IP: u8 = 0x02;
/// ROHC IP-only Profile Identifier (Profile 0x0003).
pub const PROFILE_ID_IP_ONLY: u8 = 0x03;
/// ROHC ESP/IP Profile Identifier (Profile 0x0004).
pub const PROFILE_ID_ESP_IP: u8 = 0x04;
/// ROHC TCP/IP Profile Identifier (Profile 0x0006).
pub const PROFILE_ID_TCP_IP: u8 = 0x06;
// Add other globally recognized ROHC profile IDs as needed.

// --- Standard Internet Protocol Numbers ---
// These are IANA assigned and used by various profiles.

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

// --- Common ROHC Packet Structure Constants ---
// These relate to ROHC mechanisms that might be common across profiles, like CID handling.

/// Mask to extract the prefix of an Add-CID octet.
/// An Add-CID octet is typically used to signal a small Context Identifier.
/// Defined in RFC 3095, Section 5.2.3. ROHC feedback also uses this prefix scheme.
pub const ROHC_ADD_CID_FEEDBACK_PREFIX_MASK: u8 = 0b1110_0000; // E0

/// Expected value for the prefix of an Add-CID octet or ROHC feedback (Type 0).
pub const ROHC_ADD_CID_FEEDBACK_PREFIX_VALUE: u8 = 0b1110_0000; // E0

/// Mask to extract the (small) CID value from an Add-CID octet.
/// This covers CIDs 0-15 when used with the ROHC_ADD_CID_FEEDBACK_PREFIX_VALUE.
pub const ROHC_SMALL_CID_MASK: u8 = 0x0F;

// Based on RFC 3095, Section 5.7.3, for IR and IR-DYN packets.
// These are common for profiles like P0, P1, P2.
/// Generic base value for an IR packet type discriminator (bits 7-1: `1111110`).
pub const ROHC_GENERIC_IR_PACKET_TYPE_BASE: u8 = 0b1111_1100; // 0xFC
/// Generic mask for the D-bit (Dynamic Chain present) in an IR packet type's LSB.
pub const ROHC_GENERIC_IR_D_BIT_MASK: u8 = 0b0000_0001; // 0x01

// --- General Header Field Constants ---
// Values that are standard or common defaults in network protocols relevant to ROHC.

/// Minimum IPv4 header length in bytes (20 bytes = 5 words * 4 bytes/word).
pub const IPV4_MIN_HEADER_LENGTH_BYTES: usize = 20;
/// Standard IPv4 header length in 32-bit words (when no options are present).
pub const IPV4_STANDARD_IHL: u8 = 5;

/// UDP header length in bytes (fixed size).
pub const UDP_HEADER_LENGTH_BYTES: usize = 8;

/// Minimum RTP header length in bytes (fixed header without CSRC list).
pub const RTP_MIN_HEADER_LENGTH_BYTES: usize = 12;
/// RTP (Real-time Transport Protocol) version number (typically 2).
pub const RTP_VERSION: u8 = 2;
/// Maximum number of CSRC identifiers in an RTP header (as per RFC 3550).
pub const RTP_MAX_CSRC_COUNT: u8 = 15;

/// Default interval (in number of relevant packets) after which an IR-style
/// packet might be sent by a compressor for context refresh.
/// Specific profiles will define how they use this.
pub const DEFAULT_IR_REFRESH_INTERVAL: u32 = 20; // Profile 1 uses this.

/// Default `p` offset value for W-LSB (Window-based Least Significant Bits)
/// decoding of sequence numbers. A value of 0 typically means the interpretation
/// window starts at the reference value `v_ref`.
pub const DEFAULT_WLSB_P_OFFSET: i64 = 0;

/// Default IPv4 TTL (Time To Live) value often used for reconstructed headers.
pub const DEFAULT_IPV4_TTL: u8 = 64;
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
        let add_cid_octet_for_cid_0 = ROHC_ADD_CID_FEEDBACK_PREFIX_VALUE | 0; // 0xE0
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
