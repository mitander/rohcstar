use serde::{Deserialize, Serialize};
use serde_with::{DisplayFromStr, serde_as};
use std::net::Ipv4Addr;

#[serde_as]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
    #[serde_as(as = "DisplayFromStr")]
    pub ip_src: Ipv4Addr,
    #[serde_as(as = "DisplayFromStr")]
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
            ip_protocol: 17,
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

#[serde_as]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RohcIrProfile1Packet {
    pub cid: u16,
    pub profile: u8,
    pub crc8: u8,
    #[serde_as(as = "DisplayFromStr")]
    pub static_ip_src: Ipv4Addr,
    #[serde_as(as = "DisplayFromStr")]
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
            profile: 0x01,
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

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct RohcUo0PacketProfile1 {
    pub cid: Option<u8>,
    pub sn_lsb: u8,
    pub crc3: u8,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct RohcUo1PacketProfile1 {
    pub sn_lsb: u16,
    pub num_sn_lsb_bits: u8,
    pub rtp_marker_bit_changed: Option<bool>,
    pub crc8: u8,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rtp_udp_ipv4_headers_serde_roundtrip() {
        let original = RtpUdpIpv4Headers {
            ip_src: "1.2.3.4".parse().unwrap(),
            ip_dst: "5.6.7.8".parse().unwrap(),
            rtp_sequence_number: 12345,
            ..Default::default()
        };

        let serialized = serde_json::to_string(&original).unwrap();
        println!("Serialized RtpUdpIpv4Headers: {}", serialized);
        let deserialized: RtpUdpIpv4Headers = serde_json::from_str(&serialized).unwrap();

        assert_eq!(original, deserialized);
    }

    #[test]
    fn test_rohc_ir_profile1_packet_serde_roundtrip() {
        let original = RohcIrProfile1Packet {
            static_ip_src: "10.0.0.1".parse().unwrap(),
            dyn_rtp_sn: 555,
            ..Default::default()
        };

        let serialized = serde_json::to_string(&original).unwrap();
        println!("Serialized RohcIrProfile1Packet: {}", serialized);
        let deserialized: RohcIrProfile1Packet = serde_json::from_str(&serialized).unwrap();

        assert_eq!(original, deserialized);
    }

    #[test]
    fn test_rohc_uo0_profile1_packet_serde_roundtrip() {
        let original = RohcUo0PacketProfile1 {
            cid: Some(1),
            sn_lsb: 0x0A,
            crc3: 0x05,
        };
        let serialized = serde_json::to_string(&original).unwrap();
        let deserialized: RohcUo0PacketProfile1 = serde_json::from_str(&serialized).unwrap();
        assert_eq!(original, deserialized);
    }

    #[test]
    fn test_rohc_uo1_profile1_packet_serde_roundtrip() {
        let original = RohcUo1PacketProfile1 {
            sn_lsb: 0xABCD,
            num_sn_lsb_bits: 16,
            rtp_marker_bit_changed: Some(true),
            crc8: 0xFF,
        };
        let serialized = serde_json::to_string(&original).unwrap();
        let deserialized: RohcUo1PacketProfile1 = serde_json::from_str(&serialized).unwrap();
        assert_eq!(original, deserialized);
    }
}
