//! Constants specific to ROHC (Robust Header Compression) Profile 1 (RTP/UDP/IP).
//!
//! These constants are used exclusively by the Profile 1 implementation and
//! include packet type discriminators, LSB widths, chain lengths, and default
//! operational parameters relevant to RFC 3095 for RTP/UDP/IP compression.

// --- Profile 1 Packet Type Discriminators and Components ---

// IR (Initialization & Refresh) Packet Types for Profile 1
// Based on RFC 3095, Section 5.7.3.
/// Base value for an IR packet type discriminator (first 7 bits: `1111110`).
pub const P1_ROHC_IR_PACKET_TYPE_BASE: u8 = 0b1111_1100; // 0xFC
/// Mask for the D-bit (Dynamic Chain present) in an IR packet type.
pub const P1_ROHC_IR_PACKET_TYPE_D_BIT_MASK: u8 = 0b0000_0001; // 0x01
/// Discriminator for an IR packet containing only a static chain (D-bit = 0).
pub const P1_ROHC_IR_PACKET_TYPE_STATIC_ONLY: u8 = P1_ROHC_IR_PACKET_TYPE_BASE; // 0xFC
/// Discriminator for an IR packet containing both static and dynamic chains (D-bit = 1).
pub const P1_ROHC_IR_PACKET_TYPE_WITH_DYN: u8 =
    P1_ROHC_IR_PACKET_TYPE_BASE | P1_ROHC_IR_PACKET_TYPE_D_BIT_MASK; // 0xFD

// UO-1 (Unidirectional Optimistic, Type 1) Packet Discriminator Components for Profile 1
// Based on RFC 3095, Section 5.7.5 (UO-1-SN).
/// Base value for a UO-1-SN packet type discriminator (Profile 1: `1010000M`).
/// The lower 3 bits are typically 000 for basic SN, and the M bit is the LSB.
pub const P1_UO_1_SN_PACKET_TYPE_PREFIX: u8 = 0b1010_0000; // 0xA0
/// Mask for the Marker (M) bit in a UO-1-SN (Profile 1) packet's type octet.
pub const P1_UO_1_SN_MARKER_BIT_MASK: u8 = 0b0000_0001; // 0x01

// UO-1-TS (Unidirectional Optimistic, Type 1 with Timestamp) Packet Discriminator Components
// Based on RFC 3095, Section 5.7.5 (UO-1-TS).
/// Base value for a UO-1-TS packet type discriminator (Profile 1: `101xxxxx`).
/// The format is `101TSI M` where TSI indicates TS variant and M is the marker bit.
/// For UO-1-TS, TSI is `010` and M bit MUST be `0`.
pub const P1_UO_1_TS_PACKET_TYPE_PREFIX: u8 = 0b1010_0000; // 0xA0 (Same base prefix as UO-1)
/// Specific discriminator for UO-1-TS packets (TSI=`010`, M=`0` => `10100100`).
pub const P1_UO_1_TS_DISCRIMINATOR: u8 = 0b1010_0100; // 0xA4
/// Mask to check the UO-1-TS type, ensuring TSI bits are `010` and M bit is `0`.
/// This mask checks bits 7-0 as `11111110`.
pub const P1_UO_1_TS_TYPE_MASK: u8 = 0b1111_1110; // 0xFE

// UO-1-ID (Unidirectional Optimistic, Type 1 with IP-ID) Packet Discriminator
/// Specific discriminator for UO-1-ID packets (TSI=`110`, M=`0` => `10101100`).
pub const P1_UO_1_ID_DISCRIMINATOR: u8 = 0b1010_1100; // 0xAC

// --- Profile 1 LSB Encoding Default Widths ---
// These are typical LSB bit-widths used in Profile 1 packets.

/// Default number of LSBs used for encoding the RTP Sequence Number in UO-0 packets.
/// RFC 3095, Section 5.7.4 suggests 4 bits.
pub const P1_UO0_SN_LSB_WIDTH_DEFAULT: u8 = 4;
/// Default number of LSBs for RTP Sequence Number in UO-1-SN packets.
/// RFC 3095, Section 5.7.5 suggests 8 bits.
pub const P1_UO1_SN_LSB_WIDTH_DEFAULT: u8 = 8;
/// Default number of LSBs for RTP Timestamp if/when UO-1-TS is implemented for Profile 1.
/// RFC 3095, Section 5.7.5 suggests 16 bits for TS LSBs.
pub const P1_UO1_TS_LSB_WIDTH_DEFAULT: u8 = 16;
/// Default number of LSBs for IP-ID if/when UO-1-ID is implemented for Profile 1.
/// RFC 3095, Section 5.7.5 suggests 8 bits for IP-ID LSBs.
pub const P1_UO1_IPID_LSB_WIDTH_DEFAULT: u8 = 8;

// --- Profile 1 Decompressor State Transition Thresholds ---
// Based on recommendations in RFC 3095, Section 5.3.2.2.3 (Mode Transitions).
// These are example values; implementations might make them configurable.

/// Number of consecutive CRC failures in Full Context (FC) mode before
/// the decompressor transitions to Static Context (SC) mode.
pub const P1_DECOMPRESSOR_FC_TO_SC_CRC_FAILURE_THRESHOLD: u8 = 3; // Example value
/// Number of CRC failures (k1) out of n1 packets that trigger FC->SC transition.
pub const P1_DECOMPRESSOR_FC_TO_SC_K1: u8 = 3; // Example value
/// Window size (n1) for FC->SC transition based on k1 failures.
pub const P1_DECOMPRESSOR_FC_TO_SC_N1: u8 = 10; // Example value
/// Number of CRC failures (k2) out of n2 updating packets that trigger SC->NC transition.
pub const P1_DECOMPRESSOR_SC_TO_NC_K2: u8 = 3; // Example value
/// Window size (n2) for SC->NC transition based on k2 failures.
pub const P1_DECOMPRESSOR_SC_TO_NC_N2: u8 = 10; // Example value

// --- Profile 1 Decompressor State Transition Thresholds (SO related) ---
/// Number of consecutive First Order (FO) packets successfully sent before
/// compressor may transition to Second Order (SO) state.
pub const P1_COMPRESSOR_FO_TO_SO_THRESHOLD: u32 = 15; // Example value, e.g., after 15 UO packets
/// Number of consecutive successfully decompressed packets in Full Context (FC)
/// before decompressor may transition to Second Order (SO) state.
pub const P1_DECOMPRESSOR_FC_TO_SO_THRESHOLD_STREAK: u32 = 20; // Example value
/// Initial static confidence level upon entering SO state.
pub const P1_SO_INITIAL_STATIC_CONFIDENCE: u32 = 10; // Example value
/// Initial dynamic confidence level upon entering SO state.
pub const P1_SO_INITIAL_DYNAMIC_CONFIDENCE: u32 = 10; // Example value
/// Confidence boost upon successful UO/IR packet processing in SO state.
pub const P1_SO_SUCCESS_CONFIDENCE_BOOST: u32 = 1; // Example value
/// Confidence penalty upon failed packet processing in SO state.
pub const P1_SO_FAILURE_CONFIDENCE_PENALTY: u32 = 2; // Example value
/// Confidence threshold below which dynamic confidence triggers SO->NC.
pub const P1_SO_TO_NC_CONFIDENCE_THRESHOLD: u32 = 3; // Example value
/// Max consecutive failures in SO before triggering SO->NC.
pub const P1_SO_MAX_CONSECUTIVE_FAILURES: u32 = 5; // Example value

// --- Profile 1 W-LSB Default `p` Offsets ---
// These are the default 'p' values for W-LSB interpretation intervals.
// RFC 3095, Section 4.5.1. p=0 is a common starting point.

/// Default `p` offset value for W-LSB decoding of RTP Sequence Numbers.
pub const P1_DEFAULT_P_SN_OFFSET: i64 = 0;
/// Default `p` offset value for W-LSB decoding of RTP Timestamps.
pub const P1_DEFAULT_P_TS_OFFSET: i64 = 0;
/// Default `p` offset value for W-LSB decoding of IP Identification.
pub const P1_DEFAULT_P_IPID_OFFSET: i64 = 0;

// --- Profile 1 Specific Chain Lengths (RFC 3095, Section 5.8) ---

/// Static chain length for Profile 1 (RTP/UDP/IP) in bytes.
/// Includes: IP_Src(4) + IP_Dst(4) + UDP_Src(2) + UDP_Dst(2) + RTP_SSRC(4) = 16 bytes.
pub const P1_STATIC_CHAIN_LENGTH_BYTES: usize = 16;
/// Base dynamic chain length for Profile 1 (RTP/UDP/IP) in bytes when the D-bit is set in an IR packet.
/// Includes: RTP_SN(2) + RTP_TS(4) + RTP_Flags(1) = 7 bytes.
/// (RTP_Flags octet contains M-bit and other flags like TS_STRIDE_PRESENT).
/// Note: Actual length varies if TS_STRIDE is present.
pub const P1_BASE_DYNAMIC_CHAIN_LENGTH_BYTES: usize = 7;
/// Length of the TS_STRIDE field when present in the IR dynamic chain, in bytes.
pub const P1_TS_STRIDE_EXTENSION_LENGTH_BYTES: usize = 4;

// --- Profile 1 IR Dynamic Chain RTP Flags Bitmasks ---
/// Bitmask for the Marker (M) bit in the RTP_Flags octet of the IR dynamic chain. (MSB: Bit 7)
pub const P1_IR_DYN_RTP_FLAGS_MARKER_BIT_MASK: u8 = 0x80;
// pub const P1_IR_DYN_RTP_FLAGS_X_BIT_MASK: u8 = 0x01; // (LSB: Bit 0 for EXTENSION, if needed)
/// Bitmask for the TS_STRIDE_PRESENT flag in the RTP_Flags octet of the IR dynamic chain. (Bit 1)
pub const P1_IR_DYN_RTP_FLAGS_TS_STRIDE_BIT_MASK: u8 = 0x02;

// --- Profile 1 CRC Input Lengths ---

/// Length of the data over which CRC is calculated for Profile 1 UO-0 and UO-1 packets, in bytes.
/// This typically includes SSRC, SN, TS, and Marker.
/// SSRC(4) + SN(2) + TS(4) + Marker(1 bit, usually conveyed in 1 byte for CRC input construction) = 11 bytes.
/// Note: The actual marker bit is 1 bit, but for constructing a byte stream for CRC,
/// it's often represented as a full byte (e.g., 0x01 or 0x00).
pub const P1_UO_CRC_INPUT_LENGTH_BYTES: usize = 11;

// --- Profile 1 TS Stride Constants ---
/// Minimum number of packets with consistent TS increment before establishing stride.
/// (RFC 3095, Section 4.5.4, parameter k_stride).
pub const P1_TS_STRIDE_ESTABLISHMENT_THRESHOLD: u32 = 3;
/// Maximum value for TS_SCALED field (fits in 8 bits).
/// (RFC 3095, Section 5.7.5, UO-1-RTP packet format).
pub const P1_TS_SCALED_MAX_VALUE: u32 = 255;
/// Discriminator base for UO-1-RTP packets (TSI=100, M variable).
/// Format: `1010100M`.
pub const P1_UO_1_RTP_DISCRIMINATOR_BASE: u8 = 0b1010_1000; // 0xA8
/// Mask to extract the Marker (M) bit from a UO-1-RTP packet's type octet.
pub const P1_UO_1_RTP_MARKER_BIT_MASK: u8 = 0b0000_0001; // 0x01

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ir_packet_type_constants_are_correct() {
        assert_eq!(P1_ROHC_IR_PACKET_TYPE_BASE, 0xFC);
        assert_eq!(P1_ROHC_IR_PACKET_TYPE_D_BIT_MASK, 0x01);
        assert_eq!(P1_ROHC_IR_PACKET_TYPE_STATIC_ONLY, 0xFC);
        assert_eq!(P1_ROHC_IR_PACKET_TYPE_WITH_DYN, 0xFD);
    }

    #[test]
    fn uo1_sn_constants_are_correct() {
        assert_eq!(P1_UO_1_SN_PACKET_TYPE_PREFIX, 0xA0);
        assert_eq!(P1_UO_1_SN_MARKER_BIT_MASK, 0x01);
    }

    #[test]
    fn uo1_ts_constants_are_correct() {
        assert_eq!(P1_UO_1_TS_PACKET_TYPE_PREFIX, 0xA0);
        assert_eq!(P1_UO_1_TS_DISCRIMINATOR, 0xA4);
        assert_eq!(P1_UO_1_TS_TYPE_MASK, 0xFE);
    }

    #[test]
    fn uo1_id_constants_are_correct() {
        assert_eq!(P1_UO_1_ID_DISCRIMINATOR, 0xAC);
    }

    #[test]
    fn lsb_width_defaults_are_set() {
        assert_eq!(P1_UO0_SN_LSB_WIDTH_DEFAULT, 4);
        assert_eq!(P1_UO1_SN_LSB_WIDTH_DEFAULT, 8);
        assert_eq!(P1_UO1_TS_LSB_WIDTH_DEFAULT, 16);
        assert_eq!(P1_UO1_IPID_LSB_WIDTH_DEFAULT, 8);
    }

    #[test]
    fn chain_length_constants_are_correct() {
        assert_eq!(P1_STATIC_CHAIN_LENGTH_BYTES, 16);
        assert_eq!(P1_BASE_DYNAMIC_CHAIN_LENGTH_BYTES, 7);
        assert_eq!(P1_TS_STRIDE_EXTENSION_LENGTH_BYTES, 4);
    }

    #[test]
    fn ir_dyn_rtp_flags_masks_are_correct() {
        assert_eq!(P1_IR_DYN_RTP_FLAGS_MARKER_BIT_MASK, 0x80);
        assert_eq!(P1_IR_DYN_RTP_FLAGS_TS_STRIDE_BIT_MASK, 0x02);
    }

    #[test]
    fn crc_input_length_is_correct() {
        assert_eq!(P1_UO_CRC_INPUT_LENGTH_BYTES, 11);
    }

    #[test]
    fn compressor_threshold_constants_are_correct() {
        assert_eq!(P1_COMPRESSOR_FO_TO_SO_THRESHOLD, 15);
    }

    #[test]
    fn decompressor_so_threshold_constants_are_set() {
        assert_eq!(P1_DECOMPRESSOR_FC_TO_SO_THRESHOLD_STREAK, 20);
        assert_eq!(P1_SO_INITIAL_DYNAMIC_CONFIDENCE, 10);
        assert_eq!(P1_SO_MAX_CONSECUTIVE_FAILURES, 5);
        assert_eq!(P1_SO_TO_NC_CONFIDENCE_THRESHOLD, 3);
    }

    #[test]
    fn ts_stride_constants_are_correct() {
        assert_eq!(P1_TS_STRIDE_ESTABLISHMENT_THRESHOLD, 3);
        assert_eq!(P1_TS_SCALED_MAX_VALUE, 255);
        assert_eq!(P1_UO_1_RTP_DISCRIMINATOR_BASE, 0xA8);
        assert_eq!(P1_UO_1_RTP_MARKER_BIT_MASK, 0x01);
    }
}
