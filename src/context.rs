use crate::constants::{
    DEFAULT_IR_REFRESH_INTERVAL, DEFAULT_UO0_SN_LSB_WIDTH, PROFILE_ID_RTP_UDP_IP,
};
use crate::protocol_types::{RohcIrProfile1Packet, RtpUdpIpv4Headers};
use std::net::Ipv4Addr;

/// Defines the operational modes for a ROHC compressor.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum CompressorMode {
    /// Initial state or after a refresh. The compressor must send an IR or IR-DYN packet.
    #[default]
    InitializationAndRefresh,
    /// Compressor has successfully sent an IR/IR-DYN and is now sending compressed packets (e.g., UO-0, UO-1).
    FirstOrder,
}

/// Context for a ROHC Profile 1 (RTP/UDP/IP) compressor.
///
/// Stores static and dynamic information about the header fields being compressed,
/// as well as the compressor's operational state.
#[derive(Debug, Clone)]
pub struct RtpUdpIpP1CompressorContext {
    /// ROHC Profile Identifier used by this context (e.g., 0x01 for RTP/UDP/IP).
    pub profile_id: u8,
    /// Context Identifier (CID) for this ROHC flow.
    pub cid: u16,
    /// Source IP Address.
    pub ip_source: Ipv4Addr,
    /// Destination IP Address.
    pub ip_destination: Ipv4Addr,
    /// UDP Source Port.
    pub udp_source_port: u16,
    /// UDP Destination Port.
    pub udp_destination_port: u16,
    /// RTP Synchronization Source (SSRC) identifier.
    pub rtp_ssrc: u32,
    /// Current operational mode of the compressor (e.g., IR, FO).
    pub mode: CompressorMode,
    /// The full RTP Sequence Number of the last packet sent.
    pub last_sent_rtp_sn_full: u16,
    /// The full RTP Timestamp of the last packet sent.
    pub last_sent_rtp_ts_full: u32,
    /// The RTP Marker bit value of the last packet sent.
    pub last_sent_rtp_marker: bool,
    /// Number of LSBs currently used for encoding the RTP Sequence Number.
    /// This can vary (e.g., 4 for UO-0, 8 for UO-1-SN).
    pub current_lsb_sn_width: u8,
    // pub current_lsb_ts_width: u8, // For future use with TS LSB encoding
    /// Number of First Order (FO) packets sent since the last IR packet.
    /// Used to trigger IR refresh.
    pub fo_packets_sent_since_ir: u32,
    /// Configured interval (in number of FO packets) for sending IR refresh packets.
    /// If 0, IR refresh is disabled (not typical for robust operation).
    pub ir_refresh_interval: u32,
}

impl RtpUdpIpP1CompressorContext {
    /// Creates a new `RtpUdpIpP1CompressorContext`.
    ///
    /// Initializes with the specified CID, profile ID, and IR refresh interval.
    /// Other fields are set to default values, typically representing an uninitialized state.
    /// The static part of the context should be initialized using
    /// `initialize_static_part_with_uncompressed_headers` before first use.
    ///
    /// # Arguments
    /// * `cid`: The Context Identifier for this flow.
    /// * `profile_id`: The ROHC Profile ID (e.g., `PROFILE_ID_RTP_UDP_IP`).
    /// * `ir_refresh_interval`: How often (in terms of FO packets) to send an IR refresh.
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
            current_lsb_sn_width: DEFAULT_UO0_SN_LSB_WIDTH,
            fo_packets_sent_since_ir: 0,
            ir_refresh_interval,
        }
    }

    /// Initializes or updates the static part of the compressor context using uncompressed headers.
    ///
    /// This function should be called when:
    /// 1. The context is first created and an uncompressed packet is available.
    /// 2. The static fields (IP addresses, ports, SSRC) of the uncompressed flow change,
    ///    necessitating a context re-initialization (typically leading to sending an IR packet).
    ///
    /// Sets the compressor mode to `InitializationAndRefresh` and resets the IR refresh counter.
    ///
    /// # Arguments
    /// * `headers`: The `RtpUdpIpv4Headers` from the current uncompressed packet.
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

        self.fo_packets_sent_since_ir = 0;
        self.mode = CompressorMode::InitializationAndRefresh;
    }
}

impl Default for RtpUdpIpP1CompressorContext {
    /// Creates a default `RtpUdpIpP1CompressorContext`.
    /// Uses CID 0, Profile 1, and a default IR refresh interval.
    fn default() -> Self {
        Self::new(0, PROFILE_ID_RTP_UDP_IP, DEFAULT_IR_REFRESH_INTERVAL)
    }
}

/// Defines the operational modes for a ROHC decompressor.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum DecompressorMode {
    /// No context established. The decompressor expects an IR packet.
    #[default]
    NoContext,
    /// Only static context established (e.g., after an IR-STATIC or if dynamic part is unreliable).
    /// Expects IR-DYN or UO packets that can update the dynamic part.
    StaticContext,
    /// Full context established. The decompressor can process highly compressed packets (e.g., UO-0).
    FullContext,
}

/// Default p_offset for SN LSB decoding in U-mode.
/// A value of 0 means the LSB interpretation window starts at v_ref.
const DEFAULT_P_SN_OFFSET: i64 = 0;

/// Context for a ROHC Profile 1 (RTP/UDP/IP) decompressor.
///
/// Stores static and dynamic information reconstructed from ROHC packets,
/// as well as the decompressor's operational state.
#[derive(Debug, Clone)]
pub struct RtpUdpIpP1DecompressorContext {
    /// ROHC Profile Identifier used by this context (e.g., 0x01 for RTP/UDP/IP).
    pub profile_id: u8,
    /// Context Identifier (CID) for this ROHC flow.
    pub cid: u16,
    /// Source IP Address.
    pub ip_source: Ipv4Addr,
    /// Destination IP Address.
    pub ip_destination: Ipv4Addr,
    /// UDP Source Port.
    pub udp_source_port: u16,
    /// UDP Destination Port.
    pub udp_destination_port: u16,
    /// RTP Synchronization Source (SSRC) identifier.
    pub rtp_ssrc: u32,
    /// Current operational mode of the decompressor (e.g., NC, SC, FC).
    pub mode: DecompressorMode,
    /// The full RTP Sequence Number of the last successfully reconstructed packet.
    pub last_reconstructed_rtp_sn_full: u16,
    /// The full RTP Timestamp of the last successfully reconstructed packet.
    pub last_reconstructed_rtp_ts_full: u32,
    /// The RTP Marker bit value of the last successfully reconstructed packet.
    pub last_reconstructed_rtp_marker: bool,
    /// Expected number of LSBs for the RTP Sequence Number in upcoming UO-0 packets.
    pub expected_lsb_sn_width: u8,
    /// The `p` parameter (interpretation interval offset) for LSB decoding of the RTP Sequence Number.
    /// Used in W-LSB to define the window `[v_ref - p, v_ref - p + 2^k - 1]`.
    pub p_sn: i64,
    // pub expected_lsb_ts_width: u8, // For future use with TS LSB decoding
    // pub p_ts: i64,                  // For future use
    /// Number of consecutive CRC failures encountered while in Full Context (FC) mode.
    pub consecutive_crc_failures_in_fc: u8,
}

impl RtpUdpIpP1DecompressorContext {
    /// Creates a new `RtpUdpIpP1DecompressorContext`.
    ///
    /// Initializes with the specified CID and profile ID.
    /// `p_sn` is set to its default offset.
    /// Other fields are set to default values, typically representing an uninitialized state (`NoContext`).
    ///
    /// # Arguments
    /// * `cid`: The Context Identifier for this flow.
    /// * `profile_id`: The ROHC Profile ID (e.g., `PROFILE_ID_RTP_UDP_IP`).
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
            p_sn: DEFAULT_P_SN_OFFSET,
            consecutive_crc_failures_in_fc: 0,
        }
    }

    /// Initializes or updates the decompressor context using data from a parsed IR packet.
    ///
    /// This function is called when an IR or IR-DYN packet is successfully parsed.
    /// It populates both static and dynamic fields of the context, transitions
    /// the decompressor mode to `FullContext`, and resets `p_sn` to its default.
    ///
    /// # Arguments
    /// * `ir_packet`: A reference to the parsed `RohcIrProfile1Packet`.
    pub fn initialize_from_ir_packet(&mut self, ir_packet: &RohcIrProfile1Packet) {
        self.profile_id = ir_packet.profile;
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
        self.expected_lsb_sn_width = DEFAULT_UO0_SN_LSB_WIDTH;
        self.p_sn = DEFAULT_P_SN_OFFSET;
    }
}

impl Default for RtpUdpIpP1DecompressorContext {
    /// Creates a default `RtpUdpIpP1DecompressorContext`.
    /// Uses CID 0, Profile 1, and default `p_sn`. Mode is `NoContext`.
    fn default() -> Self {
        Self::new(0, PROFILE_ID_RTP_UDP_IP)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol_types::{RohcIrProfile1Packet, RtpUdpIpv4Headers};

    #[test]
    fn compressor_context_initialization_and_static_update() {
        let headers = RtpUdpIpv4Headers {
            ip_src: "1.1.1.1".parse().unwrap(),
            rtp_ssrc: 123,
            rtp_sequence_number: 10,
            rtp_timestamp: 100,
            rtp_marker: false,
            ..Default::default()
        };
        let mut context = RtpUdpIpP1CompressorContext::new(1, PROFILE_ID_RTP_UDP_IP, 50);
        assert_eq!(context.mode, CompressorMode::InitializationAndRefresh);
        assert_eq!(context.ip_source, Ipv4Addr::UNSPECIFIED);

        context.initialize_static_part_with_uncompressed_headers(&headers);

        assert_eq!(context.ip_source, headers.ip_src);
        assert_eq!(context.rtp_ssrc, headers.rtp_ssrc);
        assert_eq!(context.last_sent_rtp_sn_full, headers.rtp_sequence_number);
        assert_eq!(context.last_sent_rtp_ts_full, headers.rtp_timestamp);
        assert_eq!(context.last_sent_rtp_marker, headers.rtp_marker);
        assert_eq!(context.mode, CompressorMode::InitializationAndRefresh);
        assert_eq!(context.fo_packets_sent_since_ir, 0);
        assert_eq!(context.ir_refresh_interval, 50);
    }

    #[test]
    fn decompressor_context_initialization_from_ir() {
        let ir_packet_data = RohcIrProfile1Packet {
            cid: 5,
            profile: PROFILE_ID_RTP_UDP_IP,
            static_ip_src: "10.0.0.1".parse().unwrap(),
            static_ip_dst: "10.0.0.2".parse().unwrap(),
            static_udp_src_port: 1000,
            static_udp_dst_port: 2000,
            static_rtp_ssrc: 0xABCDEFFF,
            dyn_rtp_sn: 12345,
            dyn_rtp_timestamp: 543210,
            dyn_rtp_marker: true,
            crc8: 0,
        };
        let mut context = RtpUdpIpP1DecompressorContext::new(5, PROFILE_ID_RTP_UDP_IP);
        assert_eq!(context.mode, DecompressorMode::NoContext);
        assert_eq!(context.p_sn, DEFAULT_P_SN_OFFSET);

        context.initialize_from_ir_packet(&ir_packet_data);

        assert_eq!(context.cid, 5);
        assert_eq!(context.profile_id, ir_packet_data.profile);
        assert_eq!(context.ip_source, ir_packet_data.static_ip_src);
        assert_eq!(context.rtp_ssrc, ir_packet_data.static_rtp_ssrc);
        assert_eq!(
            context.last_reconstructed_rtp_sn_full,
            ir_packet_data.dyn_rtp_sn
        );
        assert_eq!(
            context.last_reconstructed_rtp_ts_full,
            ir_packet_data.dyn_rtp_timestamp
        );
        assert_eq!(
            context.last_reconstructed_rtp_marker,
            ir_packet_data.dyn_rtp_marker
        );
        assert_eq!(context.mode, DecompressorMode::FullContext);
        assert_eq!(context.consecutive_crc_failures_in_fc, 0);
        assert_eq!(context.expected_lsb_sn_width, DEFAULT_UO0_SN_LSB_WIDTH);
        assert_eq!(context.p_sn, DEFAULT_P_SN_OFFSET);
    }

    #[test]
    fn decompressor_context_default_values() {
        let context = RtpUdpIpP1DecompressorContext::default();
        assert_eq!(context.cid, 0);
        assert_eq!(context.profile_id, PROFILE_ID_RTP_UDP_IP);
        assert_eq!(context.mode, DecompressorMode::NoContext);
        assert_eq!(context.expected_lsb_sn_width, DEFAULT_UO0_SN_LSB_WIDTH);
        assert_eq!(context.p_sn, DEFAULT_P_SN_OFFSET);
        assert_eq!(context.consecutive_crc_failures_in_fc, 0);
    }

    #[test]
    fn compressor_context_default_values() {
        let context = RtpUdpIpP1CompressorContext::default();
        assert_eq!(context.cid, 0);
        assert_eq!(context.profile_id, PROFILE_ID_RTP_UDP_IP);
        assert_eq!(context.mode, CompressorMode::InitializationAndRefresh);
        assert_eq!(context.current_lsb_sn_width, DEFAULT_UO0_SN_LSB_WIDTH);
        assert_eq!(context.ir_refresh_interval, DEFAULT_IR_REFRESH_INTERVAL);
        assert_eq!(context.fo_packets_sent_since_ir, 0);
    }
}
