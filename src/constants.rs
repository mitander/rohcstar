//! Centralized protocol constants used throughout the Rohcstar library.
//!
//! This module defines standard protocol identifiers (which are also often
//! represented by the `RohcProfile` enum in `packet_defs.rs`), ROHC packet
//! type discriminators, bit masks, default LSB widths, and operational parameters.

// --- Standard Protocol Identifiers ---
// These are often directly associated with variants in the `RohcProfile` enum.
// Defining them as const u8 here can still be useful for direct use in packet
// parsing/building logic or when a raw u8 is needed.

/// ROHC Profile Identifier for Uncompressed passthrough (Profile 0x0000).
pub const PROFILE_ID_UNCOMPRESSED: u8 = 0x00;
/// ROHC Profile Identifier for RTP/UDP/IP compression (Profile 0x0001).
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

// --- ROHC Packet Framing and Type Discriminators ---

// ROHC IR (Initialization & Refresh) Packet Type Components
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
// This is usually checked by `(byte & 0x80) == 0` after Add-CID processing.
// No single constant defines all UO-0, as the rest of the bits are SN/CRC.

// ROHC UO-1 (Unidirectional Optimistic, Type 1) Packet Discriminator Components for Profile 1
/// Base value for a UO-1-SN packet type discriminator (Profile 1: `1010000M`).
/// The lower bits might vary for other UO-1 extensions or profiles.
pub const UO_1_SN_P1_PACKET_TYPE_BASE: u8 = 0b1010_0000;
/// Mask for the Marker (M) bit in a UO-1-SN (Profile 1) packet's type octet.
pub const UO_1_SN_P1_MARKER_BIT_MASK: u8 = 0b0000_0001;

// Example for a potential UO-1-TS variant (if you define one)
// pub const UO_1_TS_P1_PACKET_TYPE_BASE: u8 = 0b1011_0000; // e.g., starts with 1011
// pub const UO_1_TS_P1_MARKER_BIT_MASK: u8 = 0b0000_0001; // If marker is also LSB

// --- LSB Encoding Related Defaults ---

/// Default number of LSBs used for encoding the RTP Sequence Number in UO-0 packets for Profile 1.
pub const DEFAULT_PROFILE1_UO0_SN_LSB_WIDTH: u8 = 4;
/// Default number of LSBs for RTP Sequence Number in UO-1-SN packets for Profile 1.
pub const DEFAULT_PROFILE1_UO1_SN_LSB_WIDTH: u8 = 8;
/// Default number of LSBs for RTP Timestamp if/when UO-1-TS is implemented for Profile 1.
pub const DEFAULT_PROFILE1_UO1_TS_LSB_WIDTH: u8 = 16; // Example, can be tuned

// --- Decompressor Specific Thresholds ---

/// Number of consecutive CRC failures in Full Context (FC) mode before
/// the decompressor transitions to Static Context (SC) mode.
pub const DECOMPRESSOR_FC_TO_SC_CRC_FAILURE_THRESHOLD: u8 = 3;

// --- Default Operational Parameters ---

/// Default interval (in number of FO packets) after which an IR packet
/// should be sent by the compressor for context refresh.
pub const DEFAULT_IR_REFRESH_INTERVAL: u32 = 20;
/// Default `p` offset value for W-LSB decoding of sequence numbers.
pub const DEFAULT_P_SN_OFFSET_DECOMPRESSOR: i64 = 0;
/// Default `p` offset value for W-LSB decoding of timestamps (if/when implemented).
pub const DEFAULT_P_TS_OFFSET_DECOMPRESSOR: i64 = 0;
