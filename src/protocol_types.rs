use std::net::Ipv4Addr;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RtpUdpIpv4Headers {
    pub ip_ihl: u8,
    pub ip_dscp: u8,
    pub ip_ecn: u8,
    pub ip_total_length: u16,
    pub ip_identification: u16,
    pub ip_dont_fragment: bool,
    pub ip_more_fragments: bool,
    pub ip_fragment_offset: u16,
    pub ip_ttl: u8,
    pub ip_protocol: u8,
    pub ip_checksum: u16,
    pub ip_src: Ipv4Addr,
    pub ip_dst: Ipv4Addr,
    pub udp_src_port: u16,
    pub udp_dst_port: u16,
    pub udp_length: u16,
    pub udp_checksum: u16,
    pub rtp_version: u8,
    pub rtp_padding: bool,
    pub rtp_extension: bool,
    pub rtp_csrc_count: u8,
    pub rtp_marker: bool,
    pub rtp_payload_type: u8,
    pub rtp_sequence_number: u16,
    pub rtp_timestamp: u32,
    pub rtp_ssrc: u32,
    pub rtp_csrc_list: Vec<u32>,
}

impl Default for RtpUdpIpv4Headers {
    fn default() -> Self {
        Self {
            ip_ihl: 5,
            ip_dscp: 0,
            ip_ecn: 0,
            ip_total_length: 0,
            ip_identification: 0,
            ip_dont_fragment: false,
            ip_more_fragments: false,
            ip_fragment_offset: 0,
            ip_ttl: 64,
            ip_protocol: 17, // Default to UDP
            ip_checksum: 0,
            ip_src: Ipv4Addr::UNSPECIFIED,
            ip_dst: Ipv4Addr::UNSPECIFIED,
            udp_src_port: 0,
            udp_dst_port: 0,
            udp_length: 0,
            udp_checksum: 0,
            rtp_version: 2,
            rtp_padding: false,
            rtp_extension: false,
            rtp_csrc_count: 0,
            rtp_marker: false,
            rtp_payload_type: 0,
            rtp_sequence_number: 0,
            rtp_timestamp: 0,
            rtp_ssrc: 0,
            rtp_csrc_list: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RohcIrProfile1Packet {
    pub cid: u16,
    pub profile: u8,
    pub crc8: u8,
    pub static_ip_src: Ipv4Addr,
    pub static_ip_dst: Ipv4Addr,
    pub static_udp_src_port: u16,
    pub static_udp_dst_port: u16,
    pub static_rtp_ssrc: u32,
    pub dyn_rtp_sn: u16,
    pub dyn_rtp_timestamp: u32,
    pub dyn_rtp_marker: bool,
}

impl Default for RohcIrProfile1Packet {
    fn default() -> Self {
        Self {
            cid: 0,
            profile: 0x01, // ROHC Profile 1 for RTP/UDP/IP
            crc8: 0,
            static_ip_src: Ipv4Addr::UNSPECIFIED,
            static_ip_dst: Ipv4Addr::UNSPECIFIED,
            static_udp_src_port: 0,
            static_udp_dst_port: 0,
            static_rtp_ssrc: 0,
            dyn_rtp_sn: 0,
            dyn_rtp_timestamp: 0,
            dyn_rtp_marker: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RohcUo0PacketProfile1 {
    pub cid: Option<u8>,
    pub sn_lsb: u8,
    pub crc3: u8,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RohcUo1PacketProfile1 {
    // For UO-1, CID is usually implicit (0) or handled by Add-CID octet if present.
    // The packet type itself (e.g., 100000xx for base UO-1) implies Profile 1 specific fields.
    // We'll represent the most common fields for a UO-1 that primarily updates SN.
    // Other variants (UO-1-TS, UO-1-ID) would have Option<u16/u32> for those.
    pub sn_lsb: u16,         // The LSBs of the sequence number.
    pub num_sn_lsb_bits: u8, // Actual number of LSBs for SN present in the packet.

    // For Profile 1 UO-1, M (Marker) bit might be conveyed.
    // Let's add it. Often packed with SN or as an extension bit.
    pub rtp_marker_bit_changed: Option<bool>, // None if not present/changed, Some(new_val) if present

    // UO-1 packets for Profile 1 typically have an 8-bit CRC.
    pub crc8: u8,
}
