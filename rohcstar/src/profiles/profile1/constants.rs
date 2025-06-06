//! Constants specific to ROHC (Robust Header Compression) Profile 1 (RTP/UDP/IP).
//!
//! Values are derived from RFC 3095 for RTP/UDP/IP compression.

// --- Profile 1 Packet Type Discriminators and Components (RFC 3095, Sec 5.7) ---

// IR (Initialization & Refresh) Packet Types (Sec 5.7.3)
/// Base for IR packet type discriminator (`1111110D`).
pub const P1_ROHC_IR_PACKET_TYPE_BASE: u8 = 0b1111_1100; // 0xFC
/// Mask for D-bit (Dynamic Chain present) in IR packet type.
pub const P1_ROHC_IR_PACKET_TYPE_D_BIT_MASK: u8 = 0b0000_0001; // 0x01
/// IR packet with static chain only (D-bit = 0).
pub const P1_ROHC_IR_PACKET_TYPE_STATIC_ONLY: u8 = P1_ROHC_IR_PACKET_TYPE_BASE; // 0xFC
/// IR packet with static and dynamic chains (D-bit = 1).
pub const P1_ROHC_IR_PACKET_TYPE_WITH_DYN: u8 =
    P1_ROHC_IR_PACKET_TYPE_BASE | P1_ROHC_IR_PACKET_TYPE_D_BIT_MASK; // 0xFD

// UO-1 (Unidirectional Optimistic, Type 1) Discriminators (Sec 5.7.5)
/// Base for UO-1-SN packet type (`1010000M`).
pub const P1_UO_1_SN_PACKET_TYPE_PREFIX: u8 = 0b1010_0000; // 0xA0
/// Mask for Marker (M) bit in UO-1-SN type octet.
pub const P1_UO_1_SN_MARKER_BIT_MASK: u8 = 0b0000_0001; // 0x01

/// Base prefix for UO-1-TS packet type (`101xxxxx`).
pub const P1_UO_1_TS_PACKET_TYPE_PREFIX: u8 = 0b1010_0000; // 0xA0
/// Discriminator for UO-1-TS (TSI=`010`, M=`0` => `10100100`).
pub const P1_UO_1_TS_DISCRIMINATOR: u8 = 0b1010_0100; // 0xA4
/// Mask for UO-1-TS type (checks TSI=`010`, M=`0`).
pub const P1_UO_1_TS_TYPE_MASK: u8 = 0b1111_1110; // 0xFE
/// Mask for Marker (M) bit in UO-1-TS type octet.
pub const P1_UO_1_TS_MARKER_BIT_MASK: u8 = 0b0000_0001; // 0x01

/// Discriminator for UO-1-ID (TSI=`110`, M=`0` => `10101100`).
pub const P1_UO_1_ID_DISCRIMINATOR: u8 = 0b1010_1100; // 0xAC

/// Discriminator base for UO-1-RTP (TSI=`100`, M variable => `1010100M`).
pub const P1_UO_1_RTP_DISCRIMINATOR_BASE: u8 = 0b1010_1000; // 0xA8
/// Mask for Marker (M) bit in UO-1-RTP type octet.
pub const P1_UO_1_RTP_MARKER_BIT_MASK: u8 = 0b0000_0001; // 0x01

// --- Profile 1 LSB Encoding Default Widths (RFC 3095, Sec 5.7) ---
/// Default LSBs for RTP SN in UO-0 packets (4 bits).
pub const P1_UO0_SN_LSB_WIDTH_DEFAULT: u8 = 4;
/// Default LSBs for RTP SN in UO-1-SN packets (8 bits).
pub const P1_UO1_SN_LSB_WIDTH_DEFAULT: u8 = 8;
/// Default LSBs for RTP TS in UO-1-TS packets (16 bits).
pub const P1_UO1_TS_LSB_WIDTH_DEFAULT: u8 = 16;
/// Default LSBs for IP-ID in UO-1-ID packets (8 bits).
pub const P1_UO1_IPID_LSB_WIDTH_DEFAULT: u8 = 8;

// --- Profile 1 Decompressor Mode Transition Thresholds (RFC 3095, Sec 5.3.2.2.3) ---
/// Consecutive CRC failures in FC mode before FC -> SC transition.
pub const P1_DECOMPRESSOR_FC_TO_SC_CRC_FAILURE_THRESHOLD: u8 = 3;
/// k1 CRC failures out of n1 packets for FC -> SC transition.
pub const P1_DECOMPRESSOR_FC_TO_SC_K1: u8 = 3;
/// Window size n1 for FC -> SC transition based on k1 failures.
pub const P1_DECOMPRESSOR_FC_TO_SC_N1: u8 = 10;
/// k2 CRC failures out of n2 updating packets for SC -> NC transition.
pub const P1_DECOMPRESSOR_SC_TO_NC_K2: u8 = 3;
/// Window size n2 for SC -> NC transition based on k2 failures.
pub const P1_DECOMPRESSOR_SC_TO_NC_N2: u8 = 10;

// --- Profile 1 Compressor/Decompressor SO Mode Thresholds ---
/// Consecutive FO packets sent before compressor FO -> SO transition.
pub const P1_COMPRESSOR_FO_TO_SO_THRESHOLD: u32 = 15;
/// Consecutive successful FC packets before decompressor FC -> SO transition.
pub const P1_DECOMPRESSOR_FC_TO_SO_THRESHOLD_STREAK: u32 = 20;
/// Initial static confidence on entering SO state.
pub const P1_SO_INITIAL_STATIC_CONFIDENCE: u32 = 10;
/// Initial dynamic confidence on entering SO state.
pub const P1_SO_INITIAL_DYNAMIC_CONFIDENCE: u32 = 10;
/// Confidence boost on successful SO packet processing.
pub const P1_SO_SUCCESS_CONFIDENCE_BOOST: u32 = 1;
/// Confidence penalty on failed SO packet processing.
pub const P1_SO_FAILURE_CONFIDENCE_PENALTY: u32 = 2;
/// Dynamic confidence threshold for SO -> NC transition.
pub const P1_SO_TO_NC_CONFIDENCE_THRESHOLD: u32 = 3;
/// Max consecutive failures in SO before SO -> NC transition.
pub const P1_SO_MAX_CONSECUTIVE_FAILURES: u32 = 5;

// --- Profile 1 W-LSB Default `p` Offsets (RFC 3095, Sec 4.5.1) ---
/// Default `p` offset for W-LSB decoding of RTP SN.
pub const P1_DEFAULT_P_SN_OFFSET: i64 = 0;
/// Default `p` offset for W-LSB decoding of RTP TS.
pub const P1_DEFAULT_P_TS_OFFSET: i64 = 0;
/// Default `p` offset for W-LSB decoding of IP-ID.
pub const P1_DEFAULT_P_IPID_OFFSET: i64 = 0;

// --- Profile 1 Chain Lengths (RFC 3095, Sec 5.8) ---
/// Static chain length (IP_Src/Dst, UDP_Src/Dst, RTP_SSRC) in bytes. (16 bytes)
pub const P1_STATIC_CHAIN_LENGTH_BYTES: usize = 16;
/// Base dynamic chain length for IR-DYN (RTP_SN, RTP_TS, RTP_Flags) in bytes. (7 bytes)
pub const P1_BASE_DYNAMIC_CHAIN_LENGTH_BYTES: usize = 7;
/// Length of TS_STRIDE extension in IR-DYN dynamic chain, in bytes. (4 bytes)
pub const P1_TS_STRIDE_EXTENSION_LENGTH_BYTES: usize = 4;

// --- Field Size Constants ---
/// RTP Sequence Number field length in bytes.
pub const P1_SN_LENGTH_BYTES: usize = 2;
/// RTP Timestamp field length in bytes.
pub const P1_TS_LENGTH_BYTES: usize = 4;

// --- Profile 1 IR Dynamic Chain RTP Flags Bitmasks (RFC 3095, Sec 5.7.7.2) ---
/// Mask for Marker (M) bit in IR-DYN RTP_Flags octet (MSB: Bit 7).
pub const P1_IR_DYN_RTP_FLAGS_MARKER_BIT_MASK: u8 = 0x80;
/// Mask for TS_STRIDE_PRESENT flag in IR-DYN RTP_Flags octet (Bit 1).
pub const P1_IR_DYN_RTP_FLAGS_TS_STRIDE_BIT_MASK: u8 = 0x02;

// --- Profile 1 CRC Input Construction (Internal Detail) ---
/// Length of data for CRC calculation for UO-0/UO-1 (SSRC, SN, TS, Marker). (11 bytes)
pub const P1_UO_CRC_INPUT_LENGTH_BYTES: usize = 11;

// --- Profile 1 TS Stride Constants (RFC 3095, Sec 4.5.4, 5.7.5) ---
/// Min packets for consistent TS increment to establish stride (k_stride).
pub const P1_TS_STRIDE_ESTABLISHMENT_THRESHOLD: u32 = 3;
/// Max value for TS_SCALED field in UO-1-RTP (8 bits).
pub const P1_TS_SCALED_MAX_VALUE: u32 = 255;

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
