//! ROHC protocol constants and bitmasks.
//!
//! Defines protocol identifiers, packet type discriminators, bit masks,
//! encoding parameters, and other constants used throughout the ROHC
//! implementation as specified in RFC 3095 and related standards.

// --- Protocol Identifiers ---

/// Uncompressed passthrough profile (0x0000)
pub const PROFILE_ID_UNCOMPRESSED: u8 = 0x00;
/// RTP/UDP/IP compression profile (0x0001)
pub const PROFILE_ID_RTP_UDP_IP: u8 = 0x01;
/// ROHC Profile Identifier for UDP/IP compression (Profile 0x0002).
pub const PROFILE_ID_UDP_IP: u8 = 0x02;
/// ROHC Profile Identifier for IP-only compression (Profile 0x0003).
pub const PROFILE_ID_IP_ONLY: u8 = 0x03;
/// ROHC Profile Identifier for TCP/IP compression (Profile 0x0006).
pub const PROFILE_ID_TCP_IP: u8 = 0x06;
// Add other profile IDs as needed (e.g., ROHCv2, ESP)

/// IP protocol number for UDP (User Datagram Protocol).
pub const IP_PROTOCOL_UDP: u8 = 17;
/// RTP (Real-time Transport Protocol) version number (typically 2).
pub const RTP_VERSION: u8 = 2;

// --- Protocol Header Lengths ---

/// Minimum IPv4 header length in bytes (20 bytes = 5 words × 4 bytes/word).
pub const IPV4_MIN_HEADER_LENGTH_BYTES: usize = 20;
/// Standard IPv4 header length in 32-bit words (no options).
pub const IPV4_STANDARD_IHL: u8 = 5;
/// UDP header length in bytes (fixed size).
pub const UDP_HEADER_LENGTH_BYTES: usize = 8;
/// Minimum RTP header length in bytes (fixed header without CSRC).
pub const RTP_MIN_HEADER_LENGTH_BYTES: usize = 12;

// --- Protocol Field Limits ---

/// Maximum number of CSRC identifiers in RTP header (RFC 3550).
pub const RTP_MAX_CSRC_COUNT: u8 = 15;
/// Default IPv4 TTL value for reconstructed headers.
pub const DEFAULT_IPV4_TTL: u8 = 64;
/// Minimum RTP payload type value.
pub const RTP_PAYLOAD_TYPE_MIN: u8 = 0;
/// Maximum RTP payload type value.
pub const RTP_PAYLOAD_TYPE_MAX: u8 = 127;

// --- Packet Type Discriminators ---

// IR (Initialization & Refresh) Packet Types
/// Base value for an IR packet type discriminator (first 7 bits).
pub const ROHC_IR_PACKET_TYPE_BASE: u8 = 0b1111_1100;
/// Mask for the D-bit in an IR packet type, indicating presence of a dynamic chain.
pub const ROHC_IR_PACKET_TYPE_D_BIT_MASK: u8 = 0b0000_0001;
/// Discriminator for an IR packet containing only a static chain (D-bit = 0).
pub const ROHC_IR_PACKET_TYPE_STATIC_ONLY: u8 = ROHC_IR_PACKET_TYPE_BASE;
/// Discriminator for an IR packet containing both static and dynamic chains (D-bit = 1).
pub const ROHC_IR_PACKET_TYPE_WITH_DYN: u8 =
    ROHC_IR_PACKET_TYPE_BASE | ROHC_IR_PACKET_TYPE_D_BIT_MASK;

// ROHC Add-CID Octet Components
/// Mask to extract the prefix of an Add-CID octet (identifies it as Add-CID).
pub const ADD_CID_OCTET_PREFIX_MASK: u8 = 0b1111_0000;
/// Expected value for the prefix of an Add-CID octet.
pub const ADD_CID_OCTET_PREFIX_VALUE: u8 = 0b1110_0000;
/// Mask to extract the (small) CID value from an Add-CID octet.
pub const ADD_CID_OCTET_CID_MASK: u8 = 0x0F; // Covers CIDs 1-15

// ROHC UO-0 (Unidirectional Optimistic, Type 0) Packet Discriminator Pattern
// For CID 0, UO-0 packets start with a '0' bit: 0xxxxxxx.
// Checked by `(byte & 0x80) == 0` after Add-CID processing.
// No single constant defines all UO-0, as the rest of the bits are SN/CRC.

// ROHC UO-1 (Unidirectional Optimistic, Type 1) Packet Discriminator Components for Profile 1
/// Base value for a UO-1-SN packet type discriminator (Profile 1: `1010000M`).
/// The lower bits might vary for other UO-1 extensions or profiles.
pub const UO_1_SN_P1_PACKET_TYPE_BASE: u8 = 0b1010_0000;
/// Mask for the Marker (M) bit in a UO-1-SN (Profile 1) packet's type octet.
pub const UO_1_SN_P1_MARKER_BIT_MASK: u8 = 0b0000_0001;

// --- LSB Encoding Related Defaults ---

/// Default number of LSBs used for encoding the RTP Sequence Number in UO-0 packets for Profile 1.
pub const DEFAULT_PROFILE1_UO0_SN_LSB_WIDTH: u8 = 4;
/// Default number of LSBs for RTP Sequence Number in UO-1-SN packets for Profile 1.
pub const DEFAULT_PROFILE1_UO1_SN_LSB_WIDTH: u8 = 8;
/// Default number of LSBs for RTP Timestamp if/when UO-1-TS is implemented for Profile 1.
pub const DEFAULT_PROFILE1_UO1_TS_LSB_WIDTH: u8 = 16;

// --- Decompressor Specific Thresholds ---

/// Number of consecutive CRC failures in Full Context (FC) mode before
/// the decompressor transitions to Static Context (SC) mode.
pub const DECOMPRESSOR_FC_TO_SC_CRC_FAILURE_THRESHOLD: u8 = 3;
/// Number of CRC failures (k1 out of n1) that trigger FC->SC transition.
/// These are implementation-specific values based on RFC 3095 5.3.2.2.3.
pub const DECOMPRESSOR_FC_TO_SC_K1: u8 = 3;
pub const DECOMPRESSOR_FC_TO_SC_N1: u8 = 10;
/// Number of CRC failures (k2 out of n2) in updating packets that trigger SC->NC transition.
pub const DECOMPRESSOR_SC_TO_NC_K2: u8 = 3;
pub const DECOMPRESSOR_SC_TO_NC_N2: u8 = 10;

// --- Default Operational Parameters ---

/// Default interval (in number of FO packets) after which an IR packet
/// should be sent by the compressor for context refresh.
pub const DEFAULT_IR_REFRESH_INTERVAL: u32 = 20;
/// Default `p` offset value for W-LSB decoding of sequence numbers.
pub const DEFAULT_P_SN_OFFSET: i64 = 0;
/// Default `p` offset value for W-LSB decoding of timestamps (if/when implemented).
pub const DEFAULT_P_TS_OFFSET: i64 = 0;
/// Default `p` offset value for W-LSB decoding of IP-ID (if/when implemented).
pub const DEFAULT_P_IPID_OFFSET: i64 = 0;

// --- Profile 1 Specific Chain Lengths ---

/// Static chain length for Profile 1 (RTP/UDP/IP) in bytes.
/// IP_Src(4) + IP_Dst(4) + UDP_Src(2) + UDP_Dst(2) + RTP_SSRC(4) = 16 bytes
pub const PROFILE1_STATIC_CHAIN_LENGTH: usize = 16;
/// Dynamic chain length for Profile 1 (RTP/UDP/IP) in bytes when D-bit is set.
/// SN(2) + TS(4) + Flags(1) = 7 bytes
pub const PROFILE1_DYNAMIC_CHAIN_LENGTH: usize = 7;

// --- CRC Input Lengths ---

/// Length of CRC input for Profile 1 UO packets in bytes.
/// SSRC(4) + SN(2) + TS(4) + Marker(1) = 11 bytes
pub const PROFILE1_UO_CRC_INPUT_LENGTH: usize = 11;
