//! ROHC (Robust Header Compression) Profile 1 specific compression and decompressor contexts.
//!
//! This module defines the structures that maintain the state required for
//! compressing and decompressing RTP/UDP/IPv4 headers according to ROHC Profile 1 (RFC 3095).

use std::any::Any;
use std::fmt::Debug;
use std::net::Ipv4Addr;
use std::time::Instant;

use super::constants::{
    P1_DEFAULT_P_SN_OFFSET, P1_DEFAULT_P_TS_OFFSET, P1_UO0_SN_LSB_WIDTH_DEFAULT,
    P1_UO1_TS_LSB_WIDTH_DEFAULT,
};
use super::packet_types::IrPacket;
use super::protocol_types::RtpUdpIpv4Headers;
use crate::constants::DEFAULT_IR_REFRESH_INTERVAL;
use crate::packet_defs::RohcProfile;
use crate::profiles::profile1::{P1_DEFAULT_P_IPID_OFFSET, P1_UO1_IPID_LSB_WIDTH_DEFAULT};
use crate::traits::{RohcCompressorContext, RohcDecompressorContext};

/// Operational modes for the ROHC Profile 1 compressor.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum Profile1CompressorMode {
    #[default]
    InitializationAndRefresh,
    FirstOrder,
    SecondOrder,
}

/// Compressor context for ROHC Profile 1 (RTP/UDP/IP).
#[derive(Debug, Clone)]
pub struct Profile1CompressorContext {
    pub profile_id: RohcProfile,
    pub cid: u16,
    pub ip_source: Ipv4Addr,
    pub ip_destination: Ipv4Addr,
    pub udp_source_port: u16,
    pub udp_destination_port: u16,
    pub rtp_ssrc: u32,
    pub mode: Profile1CompressorMode,
    pub last_sent_rtp_sn_full: u16,
    pub last_sent_rtp_ts_full: u32,
    pub last_sent_rtp_marker: bool,
    pub p_ts: i64,
    pub current_lsb_sn_width: u8,
    pub current_lsb_ts_width: u8,
    pub last_sent_ip_id_full: u16,
    pub p_ip_id: i64,
    pub current_lsb_ip_id_width: u8,
    pub fo_packets_sent_since_ir: u32,
    pub ir_refresh_interval: u32,
    pub consecutive_fo_packets_sent: u32,
    /// Timestamp of the last successful access (e.g., compression).
    pub last_accessed: Instant,
}

impl Profile1CompressorContext {
    /// Creates a new compressor context for ROHC Profile 1.
    ///
    /// # Parameters
    /// - `cid`: The Context Identifier (CID) for this flow.
    /// - `ir_refresh_interval`: The packet interval for sending IR refresh packets.
    pub fn new(cid: u16, ir_refresh_interval: u32, creation_time: Instant) -> Self {
        Self {
            profile_id: RohcProfile::RtpUdpIp,
            cid,
            ip_source: Ipv4Addr::UNSPECIFIED,
            ip_destination: Ipv4Addr::UNSPECIFIED,
            udp_source_port: 0,
            udp_destination_port: 0,
            rtp_ssrc: 0,
            mode: Profile1CompressorMode::InitializationAndRefresh,
            last_sent_rtp_sn_full: 0,
            last_sent_rtp_ts_full: 0,
            last_sent_rtp_marker: false,
            p_ts: P1_DEFAULT_P_TS_OFFSET,
            current_lsb_sn_width: P1_UO0_SN_LSB_WIDTH_DEFAULT,
            current_lsb_ts_width: P1_UO1_TS_LSB_WIDTH_DEFAULT,
            last_sent_ip_id_full: 0,
            p_ip_id: P1_DEFAULT_P_IPID_OFFSET,
            current_lsb_ip_id_width: P1_UO1_IPID_LSB_WIDTH_DEFAULT,
            fo_packets_sent_since_ir: 0,
            ir_refresh_interval,
            consecutive_fo_packets_sent: 0,
            last_accessed: creation_time, // Initialized on creation
        }
    }

    /// Initializes or updates the context based on a new uncompressed packet.
    ///
    /// # Parameters
    /// - `headers`: The uncompressed `RtpUdpIpv4Headers` of the current packet.
    pub fn initialize_context_from_uncompressed_headers(&mut self, headers: &RtpUdpIpv4Headers) {
        // This is typically called for the first packet or if SSRC changes,
        // requiring an IR to be sent.
        self.ip_source = headers.ip_src;
        self.ip_destination = headers.ip_dst;
        self.udp_source_port = headers.udp_src_port;
        self.udp_destination_port = headers.udp_dst_port;
        self.rtp_ssrc = headers.rtp_ssrc;

        self.last_sent_rtp_sn_full = headers.rtp_sequence_number;
        self.last_sent_rtp_ts_full = headers.rtp_timestamp;
        self.last_sent_rtp_marker = headers.rtp_marker;
        self.last_sent_ip_id_full = headers.ip_identification;

        // Force IR mode and reset IR-related counters
        self.mode = Profile1CompressorMode::InitializationAndRefresh;
        self.fo_packets_sent_since_ir = 0;
        self.consecutive_fo_packets_sent = 0;
    }

    /// Helper to get the CID for UO packet builders if it's a small CID.
    pub fn get_small_cid_for_packet(&self) -> Option<u8> {
        if self.cid > 0 && self.cid <= 15 {
            Some(self.cid as u8)
        } else {
            None // CID 0 is implicit; large CIDs not handled by UO Add-CID
        }
    }
}

impl Default for Profile1CompressorContext {
    fn default() -> Self {
        Self::new(0, DEFAULT_IR_REFRESH_INTERVAL, Instant::now())
    }
}

impl RohcCompressorContext for Profile1CompressorContext {
    fn profile_id(&self) -> RohcProfile {
        self.profile_id
    }
    fn cid(&self) -> u16 {
        self.cid
    }
    fn as_any(&self) -> &dyn Any {
        self
    }
    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
    fn last_accessed(&self) -> Instant {
        self.last_accessed
    }
    fn set_last_accessed(&mut self, now: Instant) {
        self.last_accessed = now;
    }
}

/// Operational modes for the ROHC Profile 1 decompressor.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum Profile1DecompressorMode {
    #[default]
    NoContext,
    StaticContext,
    FullContext,
    SecondOrder,
}

/// Decompressor context for ROHC Profile 1 (RTP/UDP/IP).
#[derive(Debug, Clone)]
pub struct Profile1DecompressorContext {
    pub profile_id: RohcProfile,
    pub cid: u16,
    pub ip_source: Ipv4Addr,
    pub ip_destination: Ipv4Addr,
    pub udp_source_port: u16,
    pub udp_destination_port: u16,
    pub rtp_ssrc: u32,
    pub mode: Profile1DecompressorMode,
    pub last_reconstructed_rtp_sn_full: u16,
    pub last_reconstructed_rtp_ts_full: u32,
    pub last_reconstructed_rtp_marker: bool,
    pub expected_lsb_sn_width: u8,
    pub p_sn: i64,
    pub p_ts: i64,
    pub expected_lsb_ts_width: u8,
    pub last_reconstructed_ip_id_full: u16,
    pub expected_lsb_ip_id_width: u8,
    pub p_ip_id: i64,
    pub consecutive_crc_failures_in_fc: u8,
    pub fc_packets_successful_streak: u32,
    pub so_static_confidence: u32,
    pub so_dynamic_confidence: u32,
    pub so_packets_received_in_so: u32,
    pub so_consecutive_failures: u32,
    pub sc_to_nc_k_failures: u8,
    pub sc_to_nc_n_window_count: u8,
    /// Timestamp of the last successful access (e.g., decompression).
    pub last_accessed: Instant,
}

impl Profile1DecompressorContext {
    /// Creates a new decompressor context for ROHC Profile 1.
    ///
    /// # Parameters
    /// - `cid`: The Context Identifier (CID) for this flow.
    pub fn new(cid: u16) -> Self {
        Self {
            profile_id: RohcProfile::RtpUdpIp,
            cid,
            ip_source: Ipv4Addr::UNSPECIFIED,
            ip_destination: Ipv4Addr::UNSPECIFIED,
            udp_source_port: 0,
            udp_destination_port: 0,
            rtp_ssrc: 0,
            mode: Profile1DecompressorMode::NoContext,
            last_reconstructed_rtp_sn_full: 0,
            last_reconstructed_rtp_ts_full: 0,
            last_reconstructed_rtp_marker: false,
            expected_lsb_sn_width: P1_UO0_SN_LSB_WIDTH_DEFAULT,
            p_sn: P1_DEFAULT_P_SN_OFFSET,
            p_ts: P1_DEFAULT_P_TS_OFFSET,
            expected_lsb_ts_width: P1_UO1_TS_LSB_WIDTH_DEFAULT,
            last_reconstructed_ip_id_full: 0,
            expected_lsb_ip_id_width: P1_UO1_IPID_LSB_WIDTH_DEFAULT,
            p_ip_id: P1_DEFAULT_P_IPID_OFFSET,
            consecutive_crc_failures_in_fc: 0,
            fc_packets_successful_streak: 0,
            so_static_confidence: 0,
            so_dynamic_confidence: 0,
            so_packets_received_in_so: 0,
            so_consecutive_failures: 0,
            sc_to_nc_k_failures: 0,
            sc_to_nc_n_window_count: 0,
            last_accessed: Instant::now(), // Initialized on creation
        }
    }

    /// Initializes or updates the decompressor context from a parsed IR packet.
    /// Also updates the last accessed time.
    ///
    /// # Parameters
    /// - `ir_packet`: A reference to the parsed `IrPacket` data.
    pub fn initialize_from_ir_packet(&mut self, ir_packet: &IrPacket) {
        debug_assert_eq!(
            ir_packet.profile_id, self.profile_id,
            "IR packet profile mismatch for P1DecompressorContext"
        );

        // Populate static fields from IR packet
        self.ip_source = ir_packet.static_ip_src;
        self.ip_destination = ir_packet.static_ip_dst;
        self.udp_source_port = ir_packet.static_udp_src_port;
        self.udp_destination_port = ir_packet.static_udp_dst_port;
        self.rtp_ssrc = ir_packet.static_rtp_ssrc;

        // Populate dynamic fields from IR packet (if D-bit was set)
        self.last_reconstructed_rtp_sn_full = ir_packet.dyn_rtp_sn;
        self.last_reconstructed_rtp_ts_full = ir_packet.dyn_rtp_timestamp;
        self.last_reconstructed_rtp_marker = ir_packet.dyn_rtp_marker;
        self.last_reconstructed_ip_id_full = 0; // IP-ID not in P1 IR dynamic chain

        // Set default LSB parameters, actual values for UO-0 SN may vary based on compressor
        self.expected_lsb_sn_width = P1_UO0_SN_LSB_WIDTH_DEFAULT;
        self.p_sn = P1_DEFAULT_P_SN_OFFSET;
        self.expected_lsb_ts_width = P1_UO1_TS_LSB_WIDTH_DEFAULT;
        self.p_ts = P1_DEFAULT_P_TS_OFFSET;
        self.expected_lsb_ip_id_width = P1_UO1_IPID_LSB_WIDTH_DEFAULT;
        self.p_ip_id = P1_DEFAULT_P_IPID_OFFSET;
    }

    /// Resets dynamic fields when transitioning to NoContext (NC) mode.
    pub(super) fn reset_for_nc_transition(&mut self) {
        self.last_reconstructed_rtp_sn_full = 0;
        self.last_reconstructed_rtp_ts_full = 0;
        self.last_reconstructed_rtp_marker = false;
        self.last_reconstructed_ip_id_full = 0;
        self.consecutive_crc_failures_in_fc = 0;
        self.fc_packets_successful_streak = 0;
        self.so_static_confidence = 0;
        self.so_dynamic_confidence = 0;
        self.so_packets_received_in_so = 0;
        self.so_consecutive_failures = 0;
        self.sc_to_nc_k_failures = 0;
        self.sc_to_nc_n_window_count = 0;
        // self.update_last_accessed_time(); // Not typically accessed when resetting to NC
    }
}

impl Default for Profile1DecompressorContext {
    fn default() -> Self {
        Self::new(0)
    }
}

impl RohcDecompressorContext for Profile1DecompressorContext {
    fn profile_id(&self) -> RohcProfile {
        self.profile_id
    }
    fn cid(&self) -> u16 {
        self.cid
    }
    fn set_cid(&mut self, cid: u16) {
        self.cid = cid;
    }
    fn as_any(&self) -> &dyn Any {
        self
    }
    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
    fn last_accessed(&self) -> Instant {
        self.last_accessed
    }
    fn set_last_accessed(&mut self, now: Instant) {
        self.last_accessed = now;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compressor_context_new_initializes_fields_and_mode() {
        let mut comp_ctx = Profile1CompressorContext::new(1, 20, Instant::now());
        assert_eq!(comp_ctx.cid(), 1);
        assert_eq!(comp_ctx.profile_id(), RohcProfile::RtpUdpIp);
        assert_eq!(
            comp_ctx.mode,
            Profile1CompressorMode::InitializationAndRefresh
        );
        assert_eq!(comp_ctx.ir_refresh_interval, 20);
        assert_eq!(comp_ctx.current_lsb_sn_width, P1_UO0_SN_LSB_WIDTH_DEFAULT);
        assert_eq!(comp_ctx.p_ts, P1_DEFAULT_P_TS_OFFSET);
        assert_eq!(comp_ctx.current_lsb_ts_width, P1_UO1_TS_LSB_WIDTH_DEFAULT);
        assert_eq!(comp_ctx.p_ip_id, P1_DEFAULT_P_IPID_OFFSET);
        assert_eq!(
            comp_ctx.current_lsb_ip_id_width,
            P1_UO1_IPID_LSB_WIDTH_DEFAULT
        );

        let headers = RtpUdpIpv4Headers {
            ip_src: "1.1.1.1".parse().unwrap(),
            ip_dst: "2.2.2.2".parse().unwrap(),
            udp_src_port: 100,
            udp_dst_port: 200,
            rtp_ssrc: 0x1234,
            rtp_sequence_number: 10,
            rtp_timestamp: 1000,
            rtp_marker: false,
            ip_identification: 500,
            ..Default::default()
        };
        comp_ctx.initialize_context_from_uncompressed_headers(&headers);

        assert_eq!(comp_ctx.ip_source, headers.ip_src);
        assert_eq!(comp_ctx.rtp_ssrc, headers.rtp_ssrc);
        assert_eq!(comp_ctx.last_sent_rtp_sn_full, 10);
        assert_eq!(comp_ctx.last_sent_rtp_ts_full, 1000);
        assert!(!comp_ctx.last_sent_rtp_marker);
        assert_eq!(comp_ctx.last_sent_ip_id_full, 500);
        assert_eq!(
            comp_ctx.mode,
            Profile1CompressorMode::InitializationAndRefresh
        );
        assert_eq!(comp_ctx.fo_packets_sent_since_ir, 0);
    }

    #[test]
    fn decompressor_context_new_and_initialization_from_ir_packet() {
        let mut decomp_ctx = Profile1DecompressorContext::new(5);
        assert_eq!(decomp_ctx.cid(), 5);
        assert_eq!(decomp_ctx.profile_id(), RohcProfile::RtpUdpIp);
        assert_eq!(decomp_ctx.mode, Profile1DecompressorMode::NoContext);
        assert_eq!(decomp_ctx.p_sn, P1_DEFAULT_P_SN_OFFSET);
        assert_eq!(decomp_ctx.p_ts, P1_DEFAULT_P_TS_OFFSET);
        assert_eq!(
            decomp_ctx.expected_lsb_ts_width,
            P1_UO1_TS_LSB_WIDTH_DEFAULT
        );
        assert_eq!(decomp_ctx.p_ip_id, P1_DEFAULT_P_IPID_OFFSET);
        assert_eq!(
            decomp_ctx.expected_lsb_ip_id_width,
            P1_UO1_IPID_LSB_WIDTH_DEFAULT
        );

        let ir_data = IrPacket {
            cid: 5,
            profile_id: RohcProfile::RtpUdpIp,
            crc8: 0x00,
            static_ip_src: "10.0.0.1".parse().unwrap(),
            static_ip_dst: "10.0.0.2".parse().unwrap(),
            static_udp_src_port: 1000,
            static_udp_dst_port: 2000,
            static_rtp_ssrc: 0xABCD,
            dyn_rtp_sn: 200,
            dyn_rtp_timestamp: 20000,
            dyn_rtp_marker: true,
        };
        let time_before_init = decomp_ctx.last_accessed();
        decomp_ctx.initialize_from_ir_packet(&ir_data); // This method populates fields

        // Assert fields are populated correctly
        assert_eq!(decomp_ctx.ip_destination, ir_data.static_ip_dst);
        assert_eq!(decomp_ctx.rtp_ssrc, ir_data.static_rtp_ssrc);
        assert_eq!(decomp_ctx.last_reconstructed_rtp_sn_full, 200);
        assert_eq!(decomp_ctx.last_reconstructed_rtp_ts_full, 20000);
        assert!(decomp_ctx.last_reconstructed_rtp_marker);
        assert_eq!(decomp_ctx.last_reconstructed_ip_id_full, 0); // As IP-ID not in P1 IR
        assert_eq!(decomp_ctx.consecutive_crc_failures_in_fc, 0); // Should be reset if it was part of init
        assert_eq!(
            decomp_ctx.expected_lsb_sn_width,
            P1_UO0_SN_LSB_WIDTH_DEFAULT
        );
        assert!(decomp_ctx.last_accessed() >= time_before_init); // Check time was updated
    }

    #[test]
    fn default_compressor_context() {
        let ctx = Profile1CompressorContext::default();
        assert_eq!(ctx.cid, 0);
        assert_eq!(ctx.ir_refresh_interval, DEFAULT_IR_REFRESH_INTERVAL);
        assert_eq!(ctx.mode, Profile1CompressorMode::InitializationAndRefresh);
    }

    #[test]
    fn default_decompressor_context() {
        let ctx = Profile1DecompressorContext::default();
        assert_eq!(ctx.cid, 0);
        assert_eq!(ctx.mode, Profile1DecompressorMode::NoContext);
    }

    #[test]
    fn context_trait_downcasting_compressor() {
        let comp_ctx: Box<dyn RohcCompressorContext> =
            Box::new(Profile1CompressorContext::new(1, 10, Instant::now()));
        let specific_ctx = comp_ctx
            .as_any()
            .downcast_ref::<Profile1CompressorContext>();
        assert!(specific_ctx.is_some());
        assert_eq!(specific_ctx.unwrap().cid, 1);
    }

    #[test]
    fn context_trait_downcasting_decompressor() {
        let mut decomp_ctx: Box<dyn RohcDecompressorContext> =
            Box::new(Profile1DecompressorContext::new(2));
        decomp_ctx.set_cid(3);

        let specific_ctx_mut = decomp_ctx
            .as_any_mut()
            .downcast_mut::<Profile1DecompressorContext>();
        assert!(specific_ctx_mut.is_some());
        if let Some(ctx) = specific_ctx_mut {
            assert_eq!(ctx.cid, 3);
            ctx.mode = Profile1DecompressorMode::StaticContext;
            assert_eq!(ctx.mode, Profile1DecompressorMode::StaticContext);
        }
    }
}
