//! ROHC (Robust Header Compression) Profile 1 specific compression and decompressor contexts.
//!
//! This module defines the structures that maintain the state required for
//! compressing and decompressing RTP/UDP/IPv4 headers according to ROHC Profile 1 (RFC 3095).

use std::any::Any;
use std::fmt::Debug;
use std::net::Ipv4Addr;

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
///
/// These modes dictate the type of ROHC packets the compressor should generate.
/// Transitions between modes are governed by the ROHC state machine logic for Profile 1.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum Profile1CompressorMode {
    /// Initial state or after a context refresh.
    /// In this mode, the compressor must send an IR (Initialization/Refresh)
    /// or IR-DYN packet to establish or re-establish context with the decompressor.
    #[default]
    InitializationAndRefresh,
    /// First Order compression state.
    /// After context is established, the compressor sends UO-0 or UO-1 packets,
    /// which are more compressed than IR packets.
    FirstOrder,
    /// Second Order compression state.
    /// Represents a highly stable context; compressor continues to send optimized UO packets.
    SecondOrder,
}

/// Compressor context for ROHC Profile 1 (RTP/UDP/IP).
///
/// This structure tracks all necessary state for the compressor to make decisions
/// on how to compress outgoing RTP/UDP/IPv4 packets according to Profile 1 rules.
#[derive(Debug, Clone)]
pub struct Profile1CompressorContext {
    /// The ROHC Profile Identifier this context operates under (always `RohcProfile::RtpUdpIp`).
    pub profile_id: RohcProfile,
    /// The Context Identifier (CID) for this specific ROHC flow.
    pub cid: u16,

    // Static Part of the Context (derived from the first packet of the flow)
    pub ip_source: Ipv4Addr,
    pub ip_destination: Ipv4Addr,
    pub udp_source_port: u16,
    pub udp_destination_port: u16,
    pub rtp_ssrc: u32,

    /// Current operational mode of the Profile 1 compressor.
    pub mode: Profile1CompressorMode,
    /// The full RTP Sequence Number of the last successfully compressed and sent packet.
    pub last_sent_rtp_sn_full: u16,
    /// The full RTP Timestamp of the last successfully compressed and sent packet.
    pub last_sent_rtp_ts_full: u32,
    /// The RTP Marker bit value of the last successfully compressed and sent packet.
    pub last_sent_rtp_marker: bool,

    /// The `p` parameter for W-LSB encoding of RTP Timestamp.
    pub p_ts: i64,
    /// Number of LSBs currently being used for RTP Sequence Number encoding
    /// (e.g., 4 for UO-0, 8 for UO-1-SN).
    pub current_lsb_sn_width: u8,
    /// Number of LSBs currently being used for RTP Timestamp encoding
    /// (e.g., 16 for UO-1-TS).
    pub current_lsb_ts_width: u8,

    /// The full IP Identification of the last successfully compressed and sent packet.
    pub last_sent_ip_id_full: u16,
    /// The `p` parameter for W-LSB encoding of IP Identification.
    pub p_ip_id: i64,
    /// Number of LSBs currently being used for IP-ID encoding.
    pub current_lsb_ip_id_width: u8,

    /// Counter for the number of First Order (FO) packets sent since the last IR packet.
    /// Used to trigger periodic IR refreshes for context robustness.
    pub fo_packets_sent_since_ir: u32,
    /// The configured interval (in number of FO packets) after which an IR packet
    /// should be sent for context refresh. If 0, IR refresh based on count is disabled.
    pub ir_refresh_interval: u32,

    /// Counter for the number of First Order (FO) packets sent consecutively.
    /// Used to determine transition to Second Order (SO) state. Reset on IR.
    pub consecutive_fo_packets_sent: u32,
}

impl Profile1CompressorContext {
    /// Creates a new compressor context for ROHC Profile 1.
    ///
    /// The context is initialized in `InitializationAndRefresh` mode.
    /// Static fields (IP addresses, ports, SSRC) are set to default unspecified
    /// values and should be populated using `initialize_static_fields` upon
    /// processing the first packet of a new flow.
    ///
    /// # Parameters
    /// - `cid`: The Context Identifier (CID) for this flow.
    /// - `ir_refresh_interval`: The packet interval for sending IR refresh packets.
    ///
    /// # Returns
    /// A new `Profile1CompressorContext` instance.
    pub fn new(cid: u16, ir_refresh_interval: u32) -> Self {
        Self {
            profile_id: RohcProfile::RtpUdpIp,
            cid,
            ip_source: Ipv4Addr::UNSPECIFIED,
            ip_destination: Ipv4Addr::UNSPECIFIED,
            udp_source_port: 0,
            udp_destination_port: 0,
            rtp_ssrc: 0,
            mode: Profile1CompressorMode::InitializationAndRefresh,
            last_sent_rtp_sn_full: 0, // Should be initialized from first packet
            last_sent_rtp_ts_full: 0, // Should be initialized from first packet
            last_sent_rtp_marker: false,
            p_ts: P1_DEFAULT_P_TS_OFFSET,
            current_lsb_sn_width: P1_UO0_SN_LSB_WIDTH_DEFAULT,
            current_lsb_ts_width: P1_UO1_TS_LSB_WIDTH_DEFAULT,
            fo_packets_sent_since_ir: 0,
            last_sent_ip_id_full: 0, // Initialize IP-ID state
            p_ip_id: P1_DEFAULT_P_IPID_OFFSET,
            current_lsb_ip_id_width: P1_UO1_IPID_LSB_WIDTH_DEFAULT,
            ir_refresh_interval,
            consecutive_fo_packets_sent: 0,
        }
    }

    /// Initializes or updates the static and dynamic parts of the compressor context
    /// based on a new uncompressed packet. This is typically called for the first packet
    /// of a flow or when a significant change in static fields is detected (though ROHC P1
    /// typically assumes static fields remain constant for a given CID).
    ///
    /// Sets the mode to `InitializationAndRefresh` to ensure an IR packet is sent.
    ///
    /// # Parameters
    /// - `headers`: The uncompressed `RtpUdpIpv4Headers` of the current packet.
    pub fn initialize_context_from_uncompressed_headers(&mut self, headers: &RtpUdpIpv4Headers) {
        self.ip_source = headers.ip_src;
        self.ip_destination = headers.ip_dst;
        self.udp_source_port = headers.udp_src_port;
        self.udp_destination_port = headers.udp_dst_port;
        self.rtp_ssrc = headers.rtp_ssrc;

        self.last_sent_rtp_sn_full = headers.rtp_sequence_number;
        self.last_sent_rtp_ts_full = headers.rtp_timestamp;
        self.last_sent_rtp_marker = headers.rtp_marker;
        self.last_sent_ip_id_full = headers.ip_identification;

        self.mode = Profile1CompressorMode::InitializationAndRefresh;
        self.fo_packets_sent_since_ir = 0;
        self.consecutive_fo_packets_sent = 0;
    }

    /// Helper to get the CID for UO packet builders if it's a small CID.
    /// Returns `None` for CID 0 (no Add-CID octet) or if CID > 15.
    pub fn get_small_cid_for_packet(&self) -> Option<u8> {
        if self.cid > 0 && self.cid <= 15 {
            Some(self.cid as u8)
        } else if self.cid == 0 {
            None
        } else {
            // Large CIDs not typically sent with Add-CID for UO packets.
            // The packet builder should handle this appropriately, possibly erroring.
            None
        }
    }
}

impl Default for Profile1CompressorContext {
    /// Creates a default `Profile1CompressorContext` with CID 0 and default IR refresh interval.
    fn default() -> Self {
        Self::new(0, DEFAULT_IR_REFRESH_INTERVAL)
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
}

/// Operational modes for the ROHC Profile 1 decompressor.
///
/// These modes reflect the decompressor's confidence in its context synchronization
/// with the compressor. (NC = No Context, SC = Static Context, FC = Full Context).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum Profile1DecompressorMode {
    /// No Context (NC): The decompressor has no established context for the CID.
    /// It requires an IR packet to initialize.
    #[default]
    NoContext,
    /// Static Context (SC): Only the static part of the context is reliably known.
    /// The decompressor might have received an IR packet without a dynamic part,
    /// or transitioned from Full Context due to errors. It needs an IR-DYN or
    /// a UO-1 packet with sufficient information to potentially reach Full Context.
    StaticContext,
    /// Full Context (FC): Both static and dynamic parts of the context are established.
    /// The decompressor can process highly compressed packets like UO-0.
    FullContext,
    /// Second Order (SO): Highest compression state, implies a very stable context.
    /// Decompressor continues to process optimized UO packets and monitors context validity.
    SecondOrder,
}

/// Decompressor context for ROHC Profile 1 (RTP/UDP/IP).
///
/// This structure holds the state information required by the decompressor to
/// correctly reconstruct original RTP/UDP/IPv4 headers from incoming ROHC Profile 1 packets.
#[derive(Debug, Clone)]
pub struct Profile1DecompressorContext {
    pub profile_id: RohcProfile,
    pub cid: u16,

    // Static Part of the Context (established by IR packets)
    pub ip_source: Ipv4Addr,
    pub ip_destination: Ipv4Addr,
    pub udp_source_port: u16,
    pub udp_destination_port: u16,
    pub rtp_ssrc: u32,

    /// Current operational mode of the Profile 1 decompressor.
    pub mode: Profile1DecompressorMode,
    /// The full RTP Sequence Number of the last successfully reconstructed packet.
    pub last_reconstructed_rtp_sn_full: u16,
    /// The full RTP Timestamp of the last successfully reconstructed packet.
    pub last_reconstructed_rtp_ts_full: u32,
    /// The RTP Marker bit value of the last successfully reconstructed packet.
    pub last_reconstructed_rtp_marker: bool,

    /// Expected number of LSBs for the RTP Sequence Number in UO-0 packets,
    /// typically learned from the compressor or defaulted.
    pub expected_lsb_sn_width: u8, // For UO-0 primarily
    /// The `p` parameter (interpretation interval offset) for W-LSB decoding
    /// of the RTP Sequence Number.
    pub p_sn: i64,

    /// The `p` parameter for W-LSB decoding of RTP Timestamp.
    pub p_ts: i64,
    /// Expected number of LSBs for the RTP Timestamp in UO-1-TS packets.
    pub expected_lsb_ts_width: u8,

    /// The full IP Identification of the last successfully reconstructed packet.
    pub last_reconstructed_ip_id_full: u16,
    /// Expected number of LSBs for the IP Identification in UO-1-ID packets.
    pub expected_lsb_ip_id_width: u8,
    /// The `p` parameter for W-LSB decoding of IP Identification.
    pub p_ip_id: i64,

    /// Counter for consecutive CRC failures encountered while in Full Context (FC) mode.
    /// Used to trigger a fallback to Static Context (SC) mode.
    pub consecutive_crc_failures_in_fc: u8,
    /// Counter for consecutive successful packet decodings in FC mode.
    /// Used to trigger a transition to Second Order (SO) mode.
    pub fc_packets_successful_streak: u32,

    // SO State specific fields
    /// Confidence in the static part of the context while in SO mode.
    pub so_static_confidence: u32,
    /// Confidence in the dynamic part of the context while in SO mode.
    pub so_dynamic_confidence: u32,
    /// Number of packets successfully received while in SO mode.
    pub so_packets_received_in_so: u32,
    /// Number of consecutive packet processing failures while in SO mode.
    pub so_consecutive_failures: u32,
    // Thresholds for SO->NC transition are constants.

    // SC State specific fields for SC->NC transition
    /// Counts consecutive failures of updating packets within the SC_TO_NC window.
    pub sc_to_nc_k_failures: u8,
    /// Counts packets received in SC mode within the current SC_TO_NC window.
    pub sc_to_nc_n_window_count: u8,
}

impl Profile1DecompressorContext {
    /// Creates a new decompressor context for ROHC Profile 1.
    ///
    /// Initializes in `NoContext` mode, awaiting an IR packet for context establishment.
    ///
    /// # Parameters
    /// - `cid`: The Context Identifier (CID) for this flow.
    ///
    /// # Returns
    /// A new `Profile1DecompressorContext` instance.
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
        }
    }

    /// Initializes or updates the decompressor context from a parsed IR packet.
    ///
    /// This function transitions the context to `FullContext` mode and populates
    /// all static and dynamic fields based on the information in the IR packet.
    ///
    /// # Parameters
    /// - `ir_packet`: A reference to the parsed `IrPacket` data.
    pub fn initialize_from_ir_packet(&mut self, ir_packet: &IrPacket) {
        debug_assert_eq!(
            ir_packet.profile_id, self.profile_id,
            "IR packet profile mismatch for P1DecompressorContext"
        );

        self.ip_source = ir_packet.static_ip_src;
        self.ip_destination = ir_packet.static_ip_dst;
        self.udp_source_port = ir_packet.static_udp_src_port;
        self.udp_destination_port = ir_packet.static_udp_dst_port;
        self.rtp_ssrc = ir_packet.static_rtp_ssrc;

        self.last_reconstructed_rtp_sn_full = ir_packet.dyn_rtp_sn;
        self.last_reconstructed_rtp_ts_full = ir_packet.dyn_rtp_timestamp;
        self.last_reconstructed_rtp_marker = ir_packet.dyn_rtp_marker;

        // IP-ID is not part of Profile 1 IR packet dynamic chain.
        // It will be learned from the first UO-1-ID or similar packet.
        // For now, after an IR, assume it's 0 or an unknown default.
        self.last_reconstructed_ip_id_full = 0;

        self.mode = Profile1DecompressorMode::FullContext;
        self.consecutive_crc_failures_in_fc = 0;
        self.expected_lsb_sn_width = P1_UO0_SN_LSB_WIDTH_DEFAULT;
        self.p_sn = P1_DEFAULT_P_SN_OFFSET;
        self.p_ts = P1_DEFAULT_P_TS_OFFSET;
        self.expected_lsb_ts_width = P1_UO1_TS_LSB_WIDTH_DEFAULT;
        self.expected_lsb_ip_id_width = P1_UO1_IPID_LSB_WIDTH_DEFAULT;
        self.p_ip_id = P1_DEFAULT_P_IPID_OFFSET;
        self.fc_packets_successful_streak = 0; // Reset streak on IR
        // Reset SO fields too, as IR effectively re-syncs to FC or SC
        self.so_static_confidence = 0;
        self.so_dynamic_confidence = 0;
        self.so_packets_received_in_so = 0;
        self.so_consecutive_failures = 0;
        self.sc_to_nc_k_failures = 0;
        self.sc_to_nc_n_window_count = 0;
    }

    /// Resets fields when transitioning to NoContext (NC) mode from any other mode.
    /// Static fields (IPs, ports, SSRC) are preserved.
    pub(super) fn reset_for_nc_transition(&mut self) {
        // Dynamic fields related to last reconstructed packet
        self.last_reconstructed_rtp_sn_full = 0;
        self.last_reconstructed_rtp_ts_full = 0;
        self.last_reconstructed_rtp_marker = false;
        self.last_reconstructed_ip_id_full = 0;

        // FC mode counters
        self.consecutive_crc_failures_in_fc = 0;
        self.fc_packets_successful_streak = 0;

        // SO mode counters and confidence
        self.so_static_confidence = 0;
        self.so_dynamic_confidence = 0;
        self.so_packets_received_in_so = 0;
        self.so_consecutive_failures = 0;

        // SC mode counters
        self.sc_to_nc_k_failures = 0;
        self.sc_to_nc_n_window_count = 0;

        // Optional but good practice
        self.expected_lsb_sn_width = P1_UO0_SN_LSB_WIDTH_DEFAULT;
        self.p_sn = P1_DEFAULT_P_SN_OFFSET;
        self.expected_lsb_ts_width = P1_UO1_TS_LSB_WIDTH_DEFAULT;
        self.p_ts = P1_DEFAULT_P_TS_OFFSET;
        self.expected_lsb_ip_id_width = P1_UO1_IPID_LSB_WIDTH_DEFAULT;
        self.p_ip_id = P1_DEFAULT_P_IPID_OFFSET;
    }
}

impl Default for Profile1DecompressorContext {
    /// Creates a default `Profile1DecompressorContext` with CID 0.
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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compressor_context_new_initializes_fields_and_mode() {
        let mut comp_ctx = Profile1CompressorContext::new(1, 20);
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
        decomp_ctx.initialize_from_ir_packet(&ir_data);

        assert_eq!(decomp_ctx.ip_destination, ir_data.static_ip_dst);
        assert_eq!(decomp_ctx.rtp_ssrc, ir_data.static_rtp_ssrc);
        assert_eq!(decomp_ctx.last_reconstructed_rtp_sn_full, 200);
        assert_eq!(decomp_ctx.last_reconstructed_rtp_ts_full, 20000);
        assert!(decomp_ctx.last_reconstructed_rtp_marker);
        assert_eq!(decomp_ctx.last_reconstructed_ip_id_full, 0);
        assert_eq!(decomp_ctx.mode, Profile1DecompressorMode::FullContext);
        assert_eq!(decomp_ctx.consecutive_crc_failures_in_fc, 0);
        assert_eq!(
            decomp_ctx.expected_lsb_sn_width,
            P1_UO0_SN_LSB_WIDTH_DEFAULT
        );
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
            Box::new(Profile1CompressorContext::new(1, 10));
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
