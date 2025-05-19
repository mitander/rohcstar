// General protocol identifiers
pub const IP_PROTOCOL_UDP: u8 = 17;
pub const RTP_VERSION: u8 = 2;
pub const PROFILE_ID_RTP_UDP_IP: u8 = 0x01;

// ROHC IR packet constants
pub const ROHC_IR_PACKET_TYPE_D_BIT_MASK: u8 = 0x01;
pub const ROHC_IR_PACKET_TYPE_BASE: u8 = 0b1111_1100;
pub const ROHC_IR_PACKET_TYPE_STATIC_ONLY: u8 = ROHC_IR_PACKET_TYPE_BASE;
pub const ROHC_IR_PACKET_TYPE_WITH_DYN: u8 =
    ROHC_IR_PACKET_TYPE_BASE | ROHC_IR_PACKET_TYPE_D_BIT_MASK;

// ROHC Add-CID octet constants
pub const ADD_CID_OCTET_PREFIX_MASK: u8 = 0b1111_0000;
pub const ADD_CID_OCTET_PREFIX_VALUE: u8 = 0b1110_0000;
pub const ADD_CID_OCTET_CID_MASK: u8 = 0x0F;

// UO-1 specific constants
pub const UO_1_SN_PACKET_TYPE_BASE: u8 = 0b10100000;
pub const UO_1_SN_MARKER_BIT_MASK: u8 = 0b00000001;

// LSB Encoding related defaults
pub const DEFAULT_UO0_SN_LSB_WIDTH: u8 = 4;

// Decompressor specific thresholds
pub const DECOMPRESSOR_FC_TO_SC_CRC_FAILURE_THRESHOLD: u8 = 3;

// Default operational parameters
pub const DEFAULT_IR_REFRESH_INTERVAL: u32 = 20;
