/// IP protocol number for UDP (User Datagram Protocol).
pub const IP_PROTOCOL_UDP: u8 = 17;
/// RTP (Real-time Transport Protocol) version number (typically 2).
pub const RTP_VERSION: u8 = 2;
/// ROHC Profile Identifier for RTP/UDP/IP compression (Profile 0x0001).
pub const PROFILE_ID_RTP_UDP_IP: u8 = 0x01;

/// Mask for the D-bit in an IR packet type, indicating presence of a dynamic chain.
pub const ROHC_IR_PACKET_TYPE_D_BIT_MASK: u8 = 0x01;
/// Base value for an IR packet type discriminator (first 7 bits).
pub const ROHC_IR_PACKET_TYPE_BASE: u8 = 0b1111_1100;
/// Discriminator for an IR packet containing only a static chain.
pub const ROHC_IR_PACKET_TYPE_STATIC_ONLY: u8 = ROHC_IR_PACKET_TYPE_BASE;
/// Discriminator for an IR packet containing both static and dynamic chains (D-bit set).
pub const ROHC_IR_PACKET_TYPE_WITH_DYN: u8 =
    ROHC_IR_PACKET_TYPE_BASE | ROHC_IR_PACKET_TYPE_D_BIT_MASK;

/// Mask to extract the prefix of an Add-CID octet (identifies it as Add-CID).
pub const ADD_CID_OCTET_PREFIX_MASK: u8 = 0b1111_0000;
/// Expected value for the prefix of an Add-CID octet.
pub const ADD_CID_OCTET_PREFIX_VALUE: u8 = 0b1110_0000;
/// Mask to extract the (small) CID value from an Add-CID octet.
pub const ADD_CID_OCTET_CID_MASK: u8 = 0x0F;

/// Base value for a UO-1-SN packet type discriminator (first 4 bits).
/// UO-1-SN packets start with `1010...`.
pub const UO_1_SN_PACKET_TYPE_BASE: u8 = 0b1010_0000;
/// Mask for the Marker (M) bit in a UO-1-SN packet's type octet.
pub const UO_1_SN_MARKER_BIT_MASK: u8 = 0b0000_0001;

/// Default number of LSBs used for encoding the RTP Sequence Number in UO-0 packets.
pub const DEFAULT_UO0_SN_LSB_WIDTH: u8 = 4;

/// Number of consecutive CRC failures in Full Context (FC) mode before
/// the decompressor transitions to Static Context (SC) mode.
pub const DECOMPRESSOR_FC_TO_SC_CRC_FAILURE_THRESHOLD: u8 = 3;

/// Default interval (in number of FO packets) after which an IR packet
/// should be sent by the compressor for context refresh.
pub const DEFAULT_IR_REFRESH_INTERVAL: u32 = 20;
