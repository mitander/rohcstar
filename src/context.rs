use crate::constants::{
    DEFAULT_IR_REFRESH_INTERVAL, DEFAULT_UO0_SN_LSB_WIDTH, PROFILE_ID_RTP_UDP_IP,
};
use crate::protocol_types::RtpUdpIpv4Headers;
use std::net::Ipv4Addr;

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum CompressorMode {
    #[default]
    InitializationAndRefresh,
    FirstOrder,
}

#[derive(Debug, Clone)]
pub struct RtpUdpIpP1CompressorContext {
    pub profile_id: u8,
    pub cid: u16,

    pub ip_source: Ipv4Addr,
    pub ip_destination: Ipv4Addr,
    pub udp_source_port: u16,
    pub udp_destination_port: u16,
    pub rtp_ssrc: u32,

    pub mode: CompressorMode,
    pub last_sent_rtp_sn_full: u16,
    pub last_sent_rtp_ts_full: u32,
    pub last_sent_rtp_marker: bool,

    pub current_lsb_sn_width: u8,

    pub fo_packets_sent_since_ir: u32,
    pub ir_refresh_interval: u32,
}

impl RtpUdpIpP1CompressorContext {
    pub fn new(cid: u16, profile_id: u8, ir_refresh_interval: u32) -> Self {
        Self {
            profile_id,
            cid,
            ip_source: Ipv4Addr::UNSPECIFIED,
            ip_destination: Ipv4Addr::UNSPECIFIED,
            udp_source_port: 0,
            udp_destination_port: 0,
            rtp_ssrc: 0,
            mode: CompressorMode::InitializationAndRefresh,
            last_sent_rtp_sn_full: 0,
            last_sent_rtp_ts_full: 0,
            last_sent_rtp_marker: false,
            current_lsb_sn_width: 4,
            fo_packets_sent_since_ir: 0,
            ir_refresh_interval,
        }
    }

    pub fn initialize_static_part_with_uncompressed_headers(
        &mut self,
        headers: &RtpUdpIpv4Headers,
    ) {
        self.ip_source = headers.ip_src;
        self.ip_destination = headers.ip_dst;
        self.udp_source_port = headers.udp_src_port;
        self.udp_destination_port = headers.udp_dst_port;
        self.rtp_ssrc = headers.rtp_ssrc;
        self.last_sent_rtp_sn_full = headers.rtp_sequence_number;
        self.last_sent_rtp_ts_full = headers.rtp_timestamp;
        self.last_sent_rtp_marker = headers.rtp_marker;
        self.mode = CompressorMode::InitializationAndRefresh;
        self.fo_packets_sent_since_ir = 0;
    }
}

impl Default for RtpUdpIpP1CompressorContext {
    fn default() -> Self {
        Self::new(0, PROFILE_ID_RTP_UDP_IP, DEFAULT_IR_REFRESH_INTERVAL)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum DecompressorMode {
    #[default]
    NoContext,
    StaticContext,
    FullContext,
}

#[derive(Debug, Clone)]
pub struct RtpUdpIpP1DecompressorContext {
    pub profile_id: u8,
    pub cid: u16,

    pub ip_source: Ipv4Addr,
    pub ip_destination: Ipv4Addr,
    pub udp_source_port: u16,
    pub udp_destination_port: u16,
    pub rtp_ssrc: u32,

    pub mode: DecompressorMode,
    pub last_reconstructed_rtp_sn_full: u16,
    pub last_reconstructed_rtp_ts_full: u32,
    pub last_reconstructed_rtp_marker: bool,

    pub expected_lsb_sn_width: u8,
    pub p_sn: i64,

    pub consecutive_crc_failures_in_fc: u8,
}

impl RtpUdpIpP1DecompressorContext {
    pub fn new(cid: u16, profile_id: u8) -> Self {
        Self {
            profile_id,
            cid,
            ip_source: Ipv4Addr::UNSPECIFIED,
            ip_destination: Ipv4Addr::UNSPECIFIED,
            udp_source_port: 0,
            udp_destination_port: 0,
            rtp_ssrc: 0,
            mode: DecompressorMode::NoContext,
            last_reconstructed_rtp_sn_full: 0,
            last_reconstructed_rtp_ts_full: 0,
            last_reconstructed_rtp_marker: false,
            expected_lsb_sn_width: DEFAULT_UO0_SN_LSB_WIDTH,
            p_sn: 0,
            consecutive_crc_failures_in_fc: 0,
        }
    }

    pub fn initialize_from_ir_packet(
        &mut self,
        ir_packet: &crate::protocol_types::RohcIrProfile1Packet,
    ) {
        self.ip_source = ir_packet.static_ip_src;
        self.ip_destination = ir_packet.static_ip_dst;
        self.udp_source_port = ir_packet.static_udp_src_port;
        self.udp_destination_port = ir_packet.static_udp_dst_port;
        self.rtp_ssrc = ir_packet.static_rtp_ssrc;

        self.last_reconstructed_rtp_sn_full = ir_packet.dyn_rtp_sn;
        self.last_reconstructed_rtp_ts_full = ir_packet.dyn_rtp_timestamp;
        self.last_reconstructed_rtp_marker = ir_packet.dyn_rtp_marker;

        self.mode = DecompressorMode::FullContext;
        self.consecutive_crc_failures_in_fc = 0;
    }
}

impl Default for RtpUdpIpP1DecompressorContext {
    fn default() -> Self {
        Self::new(0, PROFILE_ID_RTP_UDP_IP)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol_types::RtpUdpIpv4Headers;

    #[test]
    fn compressor_context_initialization() {
        let headers = RtpUdpIpv4Headers::default();
        let mut context = RtpUdpIpP1CompressorContext::new(1, 0x01, 50);
        assert_eq!(context.mode, CompressorMode::InitializationAndRefresh);

        context.initialize_static_part_with_uncompressed_headers(&headers);

        assert_eq!(context.ip_source, headers.ip_src);
        assert_eq!(context.rtp_ssrc, headers.rtp_ssrc);
        assert_eq!(context.last_sent_rtp_sn_full, headers.rtp_sequence_number);
        assert_eq!(context.mode, CompressorMode::InitializationAndRefresh);
        assert_eq!(context.fo_packets_sent_since_ir, 0);
        assert_eq!(context.ir_refresh_interval, 50);
    }

    #[test]
    fn decompressor_context_initialization_from_ir() {
        let ir_packet = crate::protocol_types::RohcIrProfile1Packet::default();
        let mut context = RtpUdpIpP1DecompressorContext::new(1, 0x01);
        assert_eq!(context.mode, DecompressorMode::NoContext);

        context.initialize_from_ir_packet(&ir_packet);

        assert_eq!(context.ip_source, ir_packet.static_ip_src);
        assert_eq!(context.rtp_ssrc, ir_packet.static_rtp_ssrc);
        assert_eq!(context.last_reconstructed_rtp_sn_full, ir_packet.dyn_rtp_sn);
        assert_eq!(context.mode, DecompressorMode::FullContext);
        assert_eq!(context.consecutive_crc_failures_in_fc, 0);
    }
}
