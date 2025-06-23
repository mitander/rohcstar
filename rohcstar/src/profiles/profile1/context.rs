//! ROHC (Robust Header Compression) Profile 1 specific compression and decompressor contexts.
//!
//! This module defines the structures that maintain the state required for
//! compressing and decompressing RTP/UDP/IPv4 headers according to ROHC Profile 1 (RFC 3095).

use std::any::Any;
use std::fmt::Debug;
use std::net::Ipv4Addr;
use std::time::Instant;

use super::constants::{
    P1_DEFAULT_P_IP_ID_OFFSET, P1_DEFAULT_P_SN_OFFSET, P1_DEFAULT_P_TS_OFFSET,
    P1_TS_SCALED_MAX_VALUE, P1_TS_STRIDE_ESTABLISHMENT_THRESHOLD, P1_UO0_SN_LSB_WIDTH_DEFAULT,
    P1_UO1_IP_ID_LSB_WIDTH_DEFAULT, P1_UO1_TS_LSB_WIDTH_DEFAULT,
};
use super::packet_types::IrPacket;
use super::state_types::StateCounters;
use crate::constants::{DEFAULT_IPV4_TTL, DEFAULT_IR_REFRESH_INTERVAL};
use crate::packet_defs::RohcProfile;
use crate::protocol_types::RtpUdpIpv4Headers;
use crate::traits::{RohcCompressorContext, RohcDecompressorContext};
use crate::types::{ContextId, IpId, SequenceNumber, Ssrc, Timestamp};

/// Operational modes for the ROHC Profile 1 compressor.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum Profile1CompressorMode {
    /// Initial state, forces IR packet transmission.
    #[default]
    InitializationAndRefresh,
    /// Compressor sends First-Order (FO) packets (UO-1, UOR-2 if applicable).
    FirstOrder,
    /// Compressor sends Second-Order (SO) packets (typically UO-0).
    SecondOrder,
}

/// Compressor context for ROHC Profile 1 (RTP/UDP/IP).
///
/// Holds all state information necessary for the compressor side, including
/// static and dynamic fields of the last sent packet, LSB encoding parameters,
/// state machine variables, and TS Stride detection information.
#[derive(Debug, Clone)]
pub struct Profile1CompressorContext {
    /// Profile identifier for this context.
    pub profile_id: RohcProfile,
    /// Context Identifier.
    pub cid: ContextId,
    /// Source IPv4 address from the static chain.
    pub ip_source: Ipv4Addr,
    /// Destination IPv4 address from the static chain.
    pub ip_destination: Ipv4Addr,
    /// IP TTL from the original packet
    pub ip_ttl: u8,
    /// UDP source port from the static chain.
    pub udp_source_port: u16,
    /// UDP destination port from the static chain.
    pub udp_destination_port: u16,
    /// RTP SSRC from the static chain.
    pub rtp_ssrc: Ssrc,
    /// Current operational mode of the compressor for this context.
    pub mode: Profile1CompressorMode,
    /// Full value of the RTP Sequence Number of the last sent packet.
    pub last_sent_rtp_sn_full: SequenceNumber,
    /// Full value of the RTP Timestamp of the last sent packet.
    pub last_sent_rtp_ts_full: Timestamp,
    /// RTP Marker bit of the last sent packet.
    pub last_sent_rtp_marker: bool,
    /// W-LSB `p` offset for timestamp encoding/decoding.
    pub p_ts: i64,
    /// Current number of LSBs used for SN encoding.
    pub current_lsb_sn_width: u8,
    /// Current number of LSBs used for TS encoding (if applicable for current packet type).
    pub current_lsb_ts_width: u8,
    /// Full value of the IP Identification of the last sent packet.
    pub last_sent_ip_id_full: IpId,
    /// W-LSB `p` offset for IP-ID encoding/decoding.
    pub p_ip_id: i64,
    /// Current number of LSBs used for IP-ID encoding (if applicable for current packet type).
    pub current_lsb_ip_id_width: u8,
    /// Number of First Order (FO) packets sent since the last IR packet.
    pub fo_packets_sent_since_ir: u32,
    /// Configured interval for sending IR refresh packets (0 means no periodic refresh based on
    /// count).
    pub ir_refresh_interval: u32,
    /// Number of consecutive FO packets sent (used for FO -> SO transition).
    pub consecutive_fo_packets_sent: u32,
    /// Timestamp of the last successful access (e.g., compression operation).
    pub last_accessed: Instant,
    /// Detected timestamp stride (constant TS increment); `None` if no stride active.
    pub ts_stride: Option<u32>,
    /// Base timestamp (`TS_Offset`) for TS_SCALED calculation. This is the RTP Timestamp
    /// of the packet immediately *preceding* the first packet that established the current
    /// `ts_stride`.
    pub ts_offset: Timestamp,
    /// Number of consecutive packets observed with the current `ts_stride`.
    pub ts_stride_packets: u32,
    /// Flag indicating if TS_SCALED compression mode is currently active for outgoing packets.
    pub ts_scaled_mode: bool,
    /// Potential stride value during detection phase (before RFC-compliant confirmation).
    pub potential_ts_stride: Option<u32>,
    /// Flag indicating an IR packet is required due to context state changes.
    pub ir_required: bool,
    /// Last SN for which stride detection was performed (to avoid duplicate detection).
    pub last_stride_detection_sn: SequenceNumber,
}

impl Profile1CompressorContext {
    /// Validates critical invariants for compressor context state.
    fn debug_validate_invariants(&self) {
        debug_assert!(
            self.ts_stride.is_none_or(|s| s > 0),
            "Invalid stride: stride must be positive or None"
        );
        debug_assert!(
            !self.ts_scaled_mode || self.ts_stride.is_some(),
            "State violation: scaled mode requires stride"
        );
        debug_assert!(
            self.fo_packets_sent_since_ir <= self.ir_refresh_interval
                || self.ir_refresh_interval == 0,
            "Counter overflow: {} > {}",
            self.fo_packets_sent_since_ir,
            self.ir_refresh_interval
        );
        debug_assert!(
            self.consecutive_fo_packets_sent <= self.fo_packets_sent_since_ir,
            "Counter overflow: {} > {}",
            self.consecutive_fo_packets_sent,
            self.fo_packets_sent_since_ir
        );
        debug_assert!(
            self.current_lsb_sn_width > 0 && self.current_lsb_sn_width <= 16,
            "Range violation: {} not in 1-16",
            self.current_lsb_sn_width
        );
        debug_assert!(
            self.current_lsb_ts_width > 0 && self.current_lsb_ts_width <= 32,
            "Range violation: {} not in 1-32",
            self.current_lsb_ts_width
        );
        debug_assert!(
            self.current_lsb_ip_id_width > 0 && self.current_lsb_ip_id_width <= 16,
            "Range violation: {} not in 1-16",
            self.current_lsb_ip_id_width
        );
    }

    /// Creates a new compressor context for ROHC Profile 1.
    ///
    /// Initializes all fields to their default or specified startup values.
    /// The context starts in `InitializationAndRefresh` mode.
    /// TS Stride related fields are initialized to a state indicating no stride detected.
    ///
    /// An `ir_refresh_interval` of 0 disables periodic refresh based on packet count,
    /// though IRs may still be sent for other reasons.
    pub fn new(cid: ContextId, ir_refresh_interval: u32, creation_time: Instant) -> Self {
        let context = Self {
            profile_id: RohcProfile::RtpUdpIp,
            cid,
            ip_source: Ipv4Addr::UNSPECIFIED,
            ip_destination: Ipv4Addr::UNSPECIFIED,
            ip_ttl: DEFAULT_IPV4_TTL,
            udp_source_port: 0,
            udp_destination_port: 0,
            rtp_ssrc: Ssrc::new(0),
            mode: Profile1CompressorMode::InitializationAndRefresh,
            last_sent_rtp_sn_full: SequenceNumber::default(),
            last_sent_rtp_ts_full: Timestamp::default(),
            last_sent_rtp_marker: false,
            p_ts: P1_DEFAULT_P_TS_OFFSET,
            current_lsb_sn_width: P1_UO0_SN_LSB_WIDTH_DEFAULT,
            current_lsb_ts_width: P1_UO1_TS_LSB_WIDTH_DEFAULT,
            last_sent_ip_id_full: IpId::default(),
            p_ip_id: P1_DEFAULT_P_IP_ID_OFFSET,
            current_lsb_ip_id_width: P1_UO1_IP_ID_LSB_WIDTH_DEFAULT,
            fo_packets_sent_since_ir: 0,
            ir_refresh_interval,
            consecutive_fo_packets_sent: 0,
            last_accessed: creation_time,
            ts_stride: None,
            ts_offset: Timestamp::default(),
            ts_stride_packets: 0,
            ts_scaled_mode: false,
            potential_ts_stride: None,
            ir_required: false,
            last_stride_detection_sn: SequenceNumber::default(),
        };

        context.debug_validate_invariants();

        context
    }

    /// Initializes or re-initializes the context based on a new uncompressed packet.
    ///
    /// This is typically called for the first packet of a flow or if a significant
    /// change (like SSRC changing) mandates a context reset and an IR packet.
    /// Static fields are updated, dynamic fields are set from the current packet,
    /// and the compressor mode is forced to `InitializationAndRefresh`.
    /// TS Stride detection state is also reset.
    pub fn initialize_context_from_uncompressed_headers(&mut self, headers: &RtpUdpIpv4Headers) {
        self.ip_source = headers.ip_src;
        self.ip_destination = headers.ip_dst;
        self.ip_ttl = headers.ip_ttl;
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

        // Reset TS stride detection state
        self.ts_stride = None;
        self.ts_offset = Timestamp::new(0); // Will be properly set by first call to detect_ts_stride
        self.ts_stride_packets = 0;
        self.ts_scaled_mode = false;
        self.potential_ts_stride = None;
        self.ir_required = false;
        self.last_stride_detection_sn = SequenceNumber::default();

        self.debug_validate_invariants();
    }

    /// Small CID value for this context, if applicable.
    ///
    /// Small CIDs are in the range 1-15 and can be embedded directly in certain packet types.
    pub fn get_small_cid_for_packet(&self) -> Option<ContextId> {
        if self.cid > 0 && self.cid <= 15 {
            Some(self.cid)
        } else {
            None
        }
    }

    /// Updates the TS stride detection logic based on the timestamp of the current packet.
    ///
    /// This method should be called with the `current_packet_ts` *before*
    /// `self.last_sent_rtp_ts_full` is updated to `current_packet_ts`.
    /// It checks if the difference between `current_packet_ts` and the
    /// `last_sent_rtp_ts_full` (timestamp of the previously sent packet) matches
    /// the currently suspected `ts_stride`.
    /// Updates TS Stride detection and possibly activates TS_SCALED mode.
    ///
    /// Analyzes the timestamp difference pattern between consecutive packets to detect
    /// a consistent stride value, enabling TS_SCALED compression mode when a pattern
    /// is established for `P1_TS_STRIDE_ESTABLISHMENT_THRESHOLD` packets.
    ///
    /// Returns `false` (reserved for future stride detection signaling).
    pub fn detect_ts_stride(
        &mut self,
        current_packet_ts: Timestamp,
        current_packet_sn: SequenceNumber,
    ) -> bool {
        if self.rtp_ssrc == 0 {
            return false;
        }
        if self.last_sent_rtp_ts_full.value() == 0 && self.ts_stride_packets == 0 {
            return false;
        }

        // Make stride detection idempotent - don't process the same packet twice
        if current_packet_sn == self.last_stride_detection_sn {
            return false;
        }
        self.last_stride_detection_sn = current_packet_sn;

        let ts_diff = current_packet_ts.wrapping_diff(self.last_sent_rtp_ts_full);

        match (self.ts_stride, self.potential_ts_stride) {
            (None, None) => {
                if ts_diff > 0 {
                    // Start detection phase with potential stride
                    self.potential_ts_stride = Some(ts_diff);
                    self.ts_offset = self.last_sent_rtp_ts_full;
                    self.ts_stride_packets = 1;
                    self.ts_scaled_mode = false;
                }
            }
            (None, Some(potential_stride)) => {
                if ts_diff > 0 && ts_diff == potential_stride {
                    // Confirmation matches - count towards establishment
                    self.ts_stride_packets = self.ts_stride_packets.saturating_add(1);

                    if self.ts_stride_packets >= P1_TS_STRIDE_ESTABLISHMENT_THRESHOLD {
                        // RFC 3095 compliant stride establishment requires 3 confirmations
                        self.ts_stride = Some(potential_stride);
                        self.potential_ts_stride = None;
                    }
                } else {
                    // Confirmation failed, restart detection
                    self.potential_ts_stride = None;
                    self.ts_stride_packets = 0;
                    self.ts_scaled_mode = false;

                    if ts_diff > 0 {
                        self.potential_ts_stride = Some(ts_diff);
                        self.ts_offset = self.last_sent_rtp_ts_full;
                        self.ts_stride_packets = 1;
                    }
                }
            }
            (Some(established_stride), _) => {
                if established_stride > 0 && ts_diff > 0 && (ts_diff % established_stride == 0) {
                    // TS advancing consistently with established stride
                    self.ts_stride_packets = self.ts_stride_packets.saturating_add(1);
                } else if ts_diff == 0 {
                    // Same timestamp, no stride advancement - don't break stride detection
                    // This happens when multiple packets have the same timestamp
                } else {
                    // Stride broken, start detecting new stride
                    self.ts_stride = None;
                    self.ts_scaled_mode = false;

                    if ts_diff > 0 {
                        // Start detection for new stride
                        self.potential_ts_stride = Some(ts_diff);
                        self.ts_offset = self.last_sent_rtp_ts_full;
                        self.ts_stride_packets = 1;
                    } else {
                        // No valid new stride, reset completely
                        self.potential_ts_stride = None;
                        self.ts_offset = Timestamp::new(0);
                        self.ts_stride_packets = 0;
                    }
                }
            }
        }
        false
    }

    /// Calculates the TS_SCALED value if TS scaled mode is active for the given timestamp.
    ///
    /// Formula: `TS_SCALED = (current_packet_ts - ts_offset) / ts_stride`.
    /// `ts_offset` is the timestamp of the packet that occurred *before* the
    /// sequence of N packets that established the stride.
    ///
    /// Returns `None` if stride is not established or result exceeds 8 bits.
    pub fn calculate_ts_scaled(&self, current_packet_ts: Timestamp) -> Option<u8> {
        if !self.ts_scaled_mode {
            return None;
        }

        let stride_val = self
            .ts_stride
            .expect("ts_stride cannot be None if ts_scaled_mode is true");
        debug_assert!(
            stride_val > 0,
            "Invalid stride: {} must be positive",
            stride_val
        );
        if stride_val == 0 {
            return None;
        }

        let offset_from_base = current_packet_ts.wrapping_diff(self.ts_offset);

        if offset_from_base % stride_val != 0 {
            return None; // Not aligned with stride
        }
        // Guard against invalid backwards jumps; wrapping edge cases handled by max value check
        if current_packet_ts.value() < self.ts_offset.value() && offset_from_base != 0 {
            // Complex wrapping case - rely on modulo and max value validation
        }

        let scaled_value_u32 = offset_from_base / stride_val;

        if scaled_value_u32 <= P1_TS_SCALED_MAX_VALUE {
            Some(scaled_value_u32 as u8)
        } else {
            None // TS_SCALED would overflow the 8-bit field.
        }
    }
}

impl Default for Profile1CompressorContext {
    /// Creates a default `Profile1CompressorContext`.
    /// CID is 0, IR refresh interval uses `DEFAULT_IR_REFRESH_INTERVAL`.
    fn default() -> Self {
        Self::new(
            ContextId::new(0),
            DEFAULT_IR_REFRESH_INTERVAL,
            Instant::now(),
        )
    }
}

impl RohcCompressorContext for Profile1CompressorContext {
    fn profile_id(&self) -> RohcProfile {
        self.profile_id
    }

    fn cid(&self) -> ContextId {
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

    fn update_access_time(&mut self, now: Instant) {
        self.last_accessed = now;
    }
}

/// Operational modes for the ROHC Profile 1 decompressor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Profile1DecompressorMode {
    /// No context established. Awaits an IR packet.
    #[default]
    NoContext,
    /// Static context established (from IR), dynamic context needs resynchronization.
    StaticContext,
    /// Full dynamic and static context established.
    FullContext,
    /// Second Order state, highly optimized compression.
    SecondOrder,
}

/// Decompressor context for ROHC Profile 1 (RTP/UDP/IP).
///
/// Holds all state information necessary for the decompressor side, including
/// the static chain, reconstructed dynamic fields of the last successfully
/// decompressed packet, LSB decoding parameters, state machine variables, and
/// TS Stride information received or inferred.
#[derive(Debug, Clone)]
pub struct Profile1DecompressorContext {
    /// Profile identifier for this context.
    pub profile_id: RohcProfile,
    /// Context Identifier.
    pub cid: ContextId,
    /// Source IPv4 address from the static chain.
    pub ip_source: Ipv4Addr,
    /// Destination IPv4 address from the static chain.
    pub ip_destination: Ipv4Addr,
    /// UDP source port from the static chain.
    pub udp_source_port: u16,
    /// UDP destination port from the static chain.
    pub udp_destination_port: u16,
    /// RTP SSRC from the static chain.
    pub rtp_ssrc: Ssrc,
    /// RTP payload type indicating the format of the RTP payload.
    pub rtp_payload_type: u8,
    /// RTP extension header profile/type identifier.
    pub rtp_extension: bool,
    /// RTP padding configuration or pattern.
    pub rtp_padding: bool,
    /// IP TTL from the original packet
    pub ip_ttl: u8,
    /// Current operational mode of the decompressor for this context.
    pub mode: Profile1DecompressorMode,
    /// Full value of the RTP Sequence Number from the last reconstructed packet.
    pub last_reconstructed_rtp_sn_full: SequenceNumber,
    /// Full value of the RTP Timestamp from the last reconstructed packet.
    pub last_reconstructed_rtp_ts_full: Timestamp,
    /// RTP Marker bit from the last reconstructed packet.
    pub last_reconstructed_rtp_marker: bool,
    /// Expected number of LSBs for SN decoding (can change based on packet type).
    pub expected_lsb_sn_width: u8,
    /// W-LSB `p` offset for SN decoding.
    pub p_sn: i64,
    /// W-LSB `p` offset for TS decoding.
    pub p_ts: i64,
    /// Expected number of LSBs for TS decoding.
    pub expected_lsb_ts_width: u8,
    /// Full value of the IP Identification from the last reconstructed packet.
    pub last_reconstructed_ip_id_full: IpId,
    /// Expected number of LSBs for IP-ID decoding.
    pub expected_lsb_ip_id_width: u8,
    /// W-LSB `p` offset for IP-ID decoding.
    pub p_ip_id: i64,
    /// Aggregated state machine counters.
    pub counters: StateCounters,
    /// Timestamp of the last successful access (e.g., decompression operation).
    pub last_accessed: Instant,
    /// Timestamp stride established from an IR-DYN packet or inferred; `None` if not active.
    pub ts_stride: Option<u32>,
    /// Base timestamp (`TS_Offset`) for reconstructing TS from TS_SCALED. Set by IR-DYN or
    /// inference.
    pub ts_offset: Timestamp,
    /// Flag indicating if the decompressor expects/uses TS_SCALED values.
    /// Activated by IR-DYN with TS_STRIDE or successful UO-1-RTP decoding.
    pub ts_scaled_mode: bool,
    /// Potential stride value during detection phase (before RFC-compliant confirmation).
    /// This mirrors the compressor's potential_ts_stride for consistent implicit TS calculation.
    pub potential_ts_stride: Option<u32>,
}

impl Profile1DecompressorContext {
    /// Validates critical invariants for decompressor context state.
    fn debug_validate_invariants(&self) {
        debug_assert!(
            self.ts_stride.is_none_or(|s| s > 0),
            "Invalid stride: stride must be positive or None"
        );
        debug_assert!(
            !self.ts_scaled_mode || self.ts_stride.is_some(),
            "State violation: scaled mode requires stride"
        );
        debug_assert!(
            self.expected_lsb_sn_width > 0 && self.expected_lsb_sn_width <= 16,
            "Range violation: {} not in 1-16",
            self.expected_lsb_sn_width
        );
        debug_assert!(
            self.expected_lsb_ts_width > 0 && self.expected_lsb_ts_width <= 32,
            "Range violation: {} not in 1-32",
            self.expected_lsb_ts_width
        );
        debug_assert!(
            self.expected_lsb_ip_id_width > 0 && self.expected_lsb_ip_id_width <= 16,
            "Range violation: {} not in 1-16",
            self.expected_lsb_ip_id_width
        );
        debug_assert!(
            self.counters.fc_crc_failures <= 10,
            "Counter overflow: {} > 10",
            self.counters.fc_crc_failures
        );
    }

    /// Creates a new decompressor context for ROHC Profile 1.
    ///
    /// Initializes all fields to their default or unspecified startup values. The context starts
    /// in `NoContext` mode. TS Stride fields are initialized to indicate no active stride.
    pub fn new(cid: ContextId) -> Self {
        let context = Self {
            profile_id: RohcProfile::RtpUdpIp,
            cid,
            ip_source: Ipv4Addr::UNSPECIFIED,
            ip_destination: Ipv4Addr::UNSPECIFIED,
            udp_source_port: 0,
            udp_destination_port: 0,
            rtp_ssrc: Ssrc::new(0),
            rtp_payload_type: 0,
            rtp_extension: false,
            rtp_padding: false,
            ip_ttl: DEFAULT_IPV4_TTL,
            mode: Profile1DecompressorMode::NoContext,
            last_reconstructed_rtp_sn_full: SequenceNumber::new(0),
            last_reconstructed_rtp_ts_full: Timestamp::new(0),
            last_reconstructed_rtp_marker: false,
            expected_lsb_sn_width: P1_UO0_SN_LSB_WIDTH_DEFAULT,
            p_sn: P1_DEFAULT_P_SN_OFFSET,
            p_ts: P1_DEFAULT_P_TS_OFFSET,
            expected_lsb_ts_width: P1_UO1_TS_LSB_WIDTH_DEFAULT,
            last_reconstructed_ip_id_full: IpId::new(0),
            expected_lsb_ip_id_width: P1_UO1_IP_ID_LSB_WIDTH_DEFAULT,
            p_ip_id: P1_DEFAULT_P_IP_ID_OFFSET,
            counters: StateCounters::default(),
            last_accessed: Instant::now(),
            ts_stride: None,
            ts_offset: Timestamp::new(0),
            ts_scaled_mode: false,
            potential_ts_stride: None,
        };

        context.debug_validate_invariants();

        context
    }

    /// Initializes or updates the decompressor context from a parsed IR packet.
    ///
    /// Static fields are populated from the IR packet. Dynamic fields related to
    /// RTP (SN, TS, Marker) are also set. IP-ID is typically reset for Profile 1
    /// as it's not part of the IR-DYN dynamic chain.
    /// If the IR packet contains a TS_STRIDE extension, the decompressor's
    /// TS stride information (`ts_stride`, `ts_offset`, `ts_scaled_mode`) is updated accordingly.
    /// The `last_accessed` time is **not** updated by this method; the caller should handle that.
    pub fn initialize_from_ir_packet(&mut self, ir_packet: &IrPacket) {
        debug_assert_eq!(
            ir_packet.profile_id, self.profile_id,
            "IR packet profile mismatch for P1DecompressorContext"
        );

        self.ip_source = ir_packet.static_ip_src;
        self.ip_destination = ir_packet.static_ip_dst;
        self.ip_ttl = ir_packet.dyn_ip_ttl;
        self.udp_source_port = ir_packet.static_udp_src_port;
        self.udp_destination_port = ir_packet.static_udp_dst_port;
        self.rtp_ssrc = ir_packet.static_rtp_ssrc;
        self.rtp_payload_type = ir_packet.static_rtp_payload_type;
        self.rtp_extension = ir_packet.static_rtp_extension;
        self.rtp_padding = ir_packet.static_rtp_padding;

        self.last_reconstructed_rtp_sn_full = ir_packet.dyn_rtp_sn;
        self.last_reconstructed_rtp_ts_full = ir_packet.dyn_rtp_timestamp;
        self.last_reconstructed_rtp_marker = ir_packet.dyn_rtp_marker;
        self.last_reconstructed_ip_id_full = ir_packet.dyn_ip_id;

        self.expected_lsb_sn_width = P1_UO0_SN_LSB_WIDTH_DEFAULT;
        self.p_sn = P1_DEFAULT_P_SN_OFFSET;
        self.expected_lsb_ts_width = P1_UO1_TS_LSB_WIDTH_DEFAULT;
        self.p_ts = P1_DEFAULT_P_TS_OFFSET;
        self.expected_lsb_ip_id_width = P1_UO1_IP_ID_LSB_WIDTH_DEFAULT;
        self.p_ip_id = P1_DEFAULT_P_IP_ID_OFFSET;

        self.ts_stride = ir_packet.ts_stride;
        self.ts_offset = ir_packet.dyn_rtp_timestamp;
        self.ts_scaled_mode = ir_packet.ts_stride.is_some();
        self.potential_ts_stride = None; // Reset stride detection state

        self.debug_validate_invariants();
    }

    /// Reconstructs the full RTP Timestamp from a received TS_SCALED value.
    ///
    /// Formula: `TS_reconstructed = ts_offset + (ts_scaled_received * ts_stride)`.
    /// This method relies on `ts_stride` being `Some` and `ts_offset` being correctly set,
    /// typically after an IR-DYN packet with TS_STRIDE was processed or from inference.
    ///
    /// Returns `None` if TS_STRIDE is not established.
    pub fn reconstruct_ts_from_scaled(&self, ts_scaled_received: u8) -> Option<Timestamp> {
        let stride_val = self.ts_stride?;
        debug_assert!(
            stride_val > 0,
            "Invalid stride: {} must be positive",
            stride_val
        );

        let reconstructed_ts_val = self
            .ts_offset
            .value()
            .wrapping_add(ts_scaled_received as u32 * stride_val);
        Some(reconstructed_ts_val.into())
    }

    /// Mimics compressor's stride detection to keep potential_ts_stride synchronized.
    ///
    /// Updates potential stride for consecutive packets (SN delta = 1).
    ///
    /// Follows compressor logic to keep decompressor synchronized for implicit TS calculations.
    /// Only modifies potential_ts_stride, never breaks established stride.
    fn update_potential_stride_consecutive(
        &mut self,
        current_ts: Timestamp,
        current_sn: SequenceNumber,
    ) {
        if self.rtp_ssrc == 0 || self.last_reconstructed_rtp_ts_full.value() == 0 {
            return;
        }

        let sn_delta = current_sn.wrapping_sub(self.last_reconstructed_rtp_sn_full);
        if sn_delta != 1 {
            return;
        }

        let ts_diff = current_ts.wrapping_diff(self.last_reconstructed_rtp_ts_full);
        if ts_diff > 0 {
            self.potential_ts_stride = Some(ts_diff);
            if self.ts_stride.is_none() {
                self.ts_offset = self.last_reconstructed_rtp_ts_full;
            }
        }
    }

    /// Infers stride from decompressed packet and validates consistency.
    ///
    /// Updates potential stride for consecutive packets and breaks established stride
    /// if inconsistent patterns are detected. Called after successful decompression.
    pub fn infer_ts_stride_from_decompressed_ts(
        &mut self,
        new_ts: Timestamp,
        new_sn: SequenceNumber,
    ) {
        self.update_potential_stride_consecutive(new_ts, new_sn);

        if self.rtp_ssrc == 0 || (self.ts_scaled_mode && self.ts_stride.is_some()) {
            return;
        }

        let sn_delta = new_sn.wrapping_sub(self.last_reconstructed_rtp_sn_full);
        let ts_diff = new_ts.wrapping_diff(self.last_reconstructed_rtp_ts_full);

        if sn_delta == 0 && ts_diff != 0 {
            // Same SN, different TS - always breaks stride
            self.break_stride();
        } else if sn_delta != 0 && ts_diff == 0 {
            // SN changed, TS same - breaks stride
            self.break_stride();
        } else if sn_delta > 0 && sn_delta < 0x8000 && ts_diff > 0 && ts_diff < u32::MAX / 2 {
            // Forward advancement - check clean division
            if ts_diff % (sn_delta as u32) != 0 {
                self.break_stride();
            } else {
                let unit_stride = ts_diff / (sn_delta as u32);
                if unit_stride == 0 {
                    self.break_stride();
                } else if let Some(established) = self.ts_stride {
                    if unit_stride != established {
                        // Stride changed - break and set new potential stride if consecutive
                        self.ts_stride = None;
                        self.ts_offset = Timestamp::new(0);
                        self.ts_scaled_mode = false;
                        if sn_delta == 1 {
                            self.potential_ts_stride = Some(unit_stride);
                            self.ts_offset = self.last_reconstructed_rtp_ts_full;
                        } else {
                            self.potential_ts_stride = None;
                        }
                    }
                }
            }
        } else if sn_delta >= 0x8000 || ts_diff >= u32::MAX / 2 {
            // Large reverse wrap - break stride
            self.break_stride();
        }
    }

    /// Breaks established stride and resets related state.
    fn break_stride(&mut self) {
        self.ts_stride = None;
        self.ts_offset = Timestamp::new(0);
        self.ts_scaled_mode = false;
        self.potential_ts_stride = None;
    }
}

impl Default for Profile1DecompressorContext {
    /// Creates a default `Profile1DecompressorContext`.
    /// CID is 0. Context starts in `NoContext` mode.
    fn default() -> Self {
        Self::new(ContextId::default())
    }
}

impl RohcDecompressorContext for Profile1DecompressorContext {
    fn profile_id(&self) -> RohcProfile {
        self.profile_id
    }

    fn cid(&self) -> ContextId {
        self.cid
    }

    fn assign_cid(&mut self, cid: ContextId) {
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

    fn update_access_time(&mut self, now: Instant) {
        self.last_accessed = now;
    }
}

#[cfg(test)]
mod tests {
    use std::time::Instant;

    use super::*;
    use crate::constants::DEFAULT_IR_REFRESH_INTERVAL;
    use crate::packet_defs::RohcProfile;
    use crate::profiles::profile1::constants::{
        P1_DEFAULT_P_IP_ID_OFFSET, P1_DEFAULT_P_SN_OFFSET, P1_DEFAULT_P_TS_OFFSET,
        P1_TS_STRIDE_ESTABLISHMENT_THRESHOLD, P1_UO0_SN_LSB_WIDTH_DEFAULT,
        P1_UO1_IP_ID_LSB_WIDTH_DEFAULT, P1_UO1_TS_LSB_WIDTH_DEFAULT,
    };
    use crate::profiles::profile1::packet_types::IrPacket;
    use crate::protocol_types::RtpUdpIpv4Headers;
    use crate::traits::{RohcCompressorContext, RohcDecompressorContext};

    #[test]
    fn compressor_context_new_initializes_fields_and_mode() {
        let time = Instant::now();
        let mut comp_ctx = Profile1CompressorContext::new(1.into(), 20, time);
        assert_eq!(comp_ctx.cid(), 1); // ContextId compared with u16/u32 directly
        assert_eq!(comp_ctx.profile_id(), RohcProfile::RtpUdpIp);
        assert_eq!(
            comp_ctx.mode,
            Profile1CompressorMode::InitializationAndRefresh
        );
        assert_eq!(comp_ctx.ir_refresh_interval, 20);
        assert_eq!(comp_ctx.current_lsb_sn_width, P1_UO0_SN_LSB_WIDTH_DEFAULT);
        assert_eq!(comp_ctx.p_ts, P1_DEFAULT_P_TS_OFFSET);
        assert_eq!(comp_ctx.current_lsb_ts_width, P1_UO1_TS_LSB_WIDTH_DEFAULT);
        assert_eq!(comp_ctx.p_ip_id, P1_DEFAULT_P_IP_ID_OFFSET);
        assert_eq!(
            comp_ctx.current_lsb_ip_id_width,
            P1_UO1_IP_ID_LSB_WIDTH_DEFAULT
        );
        // TS Stride fields
        assert_eq!(comp_ctx.ts_stride, None);
        assert_eq!(comp_ctx.ts_offset, 0);
        assert_eq!(comp_ctx.ts_stride_packets, 0);
        assert!(!comp_ctx.ts_scaled_mode);
        assert_eq!(comp_ctx.last_accessed, time);

        let headers = RtpUdpIpv4Headers {
            ip_src: "1.1.1.1".parse().unwrap(),
            ip_dst: "2.2.2.2".parse().unwrap(),
            udp_src_port: 100,
            udp_dst_port: 200,
            rtp_ssrc: 0x1234.into(),
            rtp_sequence_number: 10.into(),
            rtp_timestamp: 1000.into(),
            rtp_marker: false,
            ip_identification: 500.into(),
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
        // TS Stride fields after init
        assert_eq!(comp_ctx.ts_stride, None);
        assert_eq!(comp_ctx.ts_offset, 0);
        assert_eq!(comp_ctx.ts_stride_packets, 0);
        assert!(!comp_ctx.ts_scaled_mode);
    }

    #[test]
    fn compressor_ts_stride_detection_logic() {
        let mut comp_ctx = Profile1CompressorContext::new(1.into(), 20, Instant::now());
        comp_ctx.rtp_ssrc = 0x1234.into(); // Simulate initialized SSRC
        comp_ctx.last_sent_rtp_ts_full = 1000.into();

        // Packet 1 (ts_diff = 160) -> Starts detection phase
        assert!(!comp_ctx.detect_ts_stride(1160.into(), 101.into()));
        assert_eq!(comp_ctx.ts_stride, None); // Not yet established
        assert_eq!(comp_ctx.potential_ts_stride, Some(160)); // In detection phase
        assert_eq!(comp_ctx.ts_offset, 1000);
        assert_eq!(comp_ctx.ts_stride_packets, 1);
        assert!(!comp_ctx.ts_scaled_mode);
        comp_ctx.last_sent_rtp_ts_full = 1160.into(); // Update after detection

        // Packet 2 (ts_diff = 160) -> Second confirmation, still in detection phase
        assert!(!comp_ctx.detect_ts_stride(1320.into(), 102.into()));
        assert_eq!(comp_ctx.ts_stride, None); // Not yet established (threshold=3)
        assert_eq!(comp_ctx.potential_ts_stride, Some(160)); // Still in detection phase
        assert_eq!(comp_ctx.ts_offset, 1000); // ts_offset remains from initial stride detection
        assert_eq!(comp_ctx.ts_stride_packets, 2);
        assert!(!comp_ctx.ts_scaled_mode);
        comp_ctx.last_sent_rtp_ts_full = 1320.into();

        // Packet 3 (ts_diff = 160) -> Third confirmation, stride now established
        assert!(!comp_ctx.detect_ts_stride(1480.into(), 103.into()));
        assert_eq!(comp_ctx.ts_stride, Some(160)); // Now established (threshold=3)
        assert_eq!(comp_ctx.potential_ts_stride, None); // Detection phase complete
        assert_eq!(comp_ctx.ts_offset, 1000);
        assert_eq!(comp_ctx.ts_stride_packets, 3);
        assert!(!comp_ctx.ts_scaled_mode); // Not automatically activated
        comp_ctx.last_sent_rtp_ts_full = 1480.into();

        // Packet 4 (ts_diff = 160) -> Continues stride detection
        assert!(!comp_ctx.detect_ts_stride(1640.into(), 104.into())); // Returns false (no auto-activation)
        assert_eq!(comp_ctx.ts_stride, Some(160));
        assert_eq!(comp_ctx.ts_stride_packets, 4);
        assert!(!comp_ctx.ts_scaled_mode); // Not automatically activated
        comp_ctx.last_sent_rtp_ts_full = 1640.into();

        // Packet 5 (ts_diff = 100) -> Stride broken, attempts to start new detection
        assert!(!comp_ctx.detect_ts_stride(1740.into(), 105.into()));
        assert_eq!(comp_ctx.ts_stride, None); // Broken, back to None
        assert_eq!(comp_ctx.potential_ts_stride, Some(100)); // New detection started
        assert_eq!(comp_ctx.ts_offset, 1640);
        assert_eq!(comp_ctx.ts_stride_packets, 1);
        assert!(!comp_ctx.ts_scaled_mode);
        comp_ctx.last_sent_rtp_ts_full = 1740.into();
    }

    #[test]
    fn compressor_calculate_ts_scaled_logic() {
        let mut comp_ctx = Profile1CompressorContext::new(1.into(), 20, Instant::now());
        comp_ctx.rtp_ssrc = 0x1234.into();
        comp_ctx.ts_stride = Some(160);
        comp_ctx.ts_offset = 1000.into();
        comp_ctx.ts_stride_packets = P1_TS_STRIDE_ESTABLISHMENT_THRESHOLD;
        comp_ctx.ts_scaled_mode = true;

        assert_eq!(comp_ctx.calculate_ts_scaled(1000.into()), Some(0));
        assert_eq!(comp_ctx.calculate_ts_scaled(1160.into()), Some(1));
        assert_eq!(comp_ctx.calculate_ts_scaled(1480.into()), Some(3));

        let far_ts = (1000 + 200 * 160).into();
        assert_eq!(comp_ctx.calculate_ts_scaled(far_ts), Some(200));

        let overflow_ts = (1000 + 300 * 160).into();
        assert_eq!(comp_ctx.calculate_ts_scaled(overflow_ts), None);

        assert_eq!(comp_ctx.calculate_ts_scaled(1650.into()), None);

        let ts_before_offset = 900.into(); // Not aligned with offset + N*stride
        assert_eq!(comp_ctx.calculate_ts_scaled(ts_before_offset), None);

        comp_ctx.ts_scaled_mode = false;
        assert_eq!(comp_ctx.calculate_ts_scaled(1160.into()), None);
    }

    #[test]
    fn default_compressor_context() {
        let ctx = Profile1CompressorContext::default();
        assert_eq!(ctx.cid, 0);
        assert_eq!(ctx.ir_refresh_interval, DEFAULT_IR_REFRESH_INTERVAL);
        assert_eq!(ctx.mode, Profile1CompressorMode::InitializationAndRefresh);
        assert_eq!(ctx.ts_stride, None);
    }

    #[test]
    fn context_trait_downcasting_compressor() {
        let comp_ctx_dyn: Box<dyn RohcCompressorContext> =
            Box::new(Profile1CompressorContext::new(1.into(), 10, Instant::now()));
        let specific_ctx = comp_ctx_dyn
            .as_any()
            .downcast_ref::<Profile1CompressorContext>();
        assert!(specific_ctx.is_some());
        if let Some(s_ctx) = specific_ctx {
            // Renamed to avoid conflict
            assert_eq!(s_ctx.cid, 1);
        }
    }

    // --- Profile1DecompressorContext Tests ---

    // Helper to create a context for decompressor inference unit tests
    fn test_decomp_ctx(
        initial_sn: u16,
        initial_ts: u32,
        initial_stride: Option<u32>,
        initial_offset_ts: u32,
    ) -> Profile1DecompressorContext {
        let mut ctx = Profile1DecompressorContext::new(0.into());
        ctx.rtp_ssrc = 0x12345678.into();
        ctx.last_reconstructed_rtp_sn_full = initial_sn.into();
        ctx.last_reconstructed_rtp_ts_full = initial_ts.into();
        ctx.ts_stride = initial_stride;
        ctx.ts_offset = initial_offset_ts.into();
        ctx.ts_scaled_mode = false;
        if initial_stride.is_some() && initial_offset_ts == 0 && initial_ts != 0 {
            ctx.ts_offset = initial_ts.into();
        }
        ctx
    }

    #[test]
    fn infer_ts_stride_initial_detection_sn_delta_1() {
        let mut ctx = test_decomp_ctx(100, 1000, None, 0);
        ctx.infer_ts_stride_from_decompressed_ts(1160.into(), 101.into());
        assert_eq!(ctx.ts_stride, None); // Stride not immediately established
        assert_eq!(ctx.potential_ts_stride, Some(160)); // Potential stride detected
        assert_eq!(ctx.ts_offset, 1000); // Offset is prev packet's TS
    }

    #[test]
    fn infer_ts_stride_initial_detection_sn_delta_gt_1() {
        let mut ctx = test_decomp_ctx(100, 1000, None, 0);
        ctx.infer_ts_stride_from_decompressed_ts(1800.into(), 105.into()); // delta_sn=5, delta_ts=800, unit_stride=160
        assert_eq!(ctx.ts_stride, None); // Stride not immediately established
        assert_eq!(ctx.potential_ts_stride, None); // Not updated for sn_delta > 1
        assert_eq!(ctx.ts_offset, Timestamp::new(0)); // Not updated when potential stride not detected
    }

    #[test]
    fn infer_ts_stride_consistent_stride_sn_delta_1() {
        let mut ctx = test_decomp_ctx(100, 1000, Some(160), 1000); // initial_offset_ts = 1000 matches last_ts
        ctx.infer_ts_stride_from_decompressed_ts(1160.into(), 101.into());
        assert_eq!(ctx.ts_stride, Some(160));
        assert_eq!(ctx.ts_offset, 1000); // Offset updated to last_ts (which was 1000)
    }

    #[test]
    fn infer_ts_stride_consistent_stride_sn_delta_gt_1() {
        let mut ctx = test_decomp_ctx(100, 1000, Some(160), 1000);
        ctx.infer_ts_stride_from_decompressed_ts(1480.into(), 103.into()); // delta_sn=3, delta_ts=480, unit_stride=160
        assert_eq!(ctx.ts_stride, Some(160));
        assert_eq!(ctx.ts_offset, 1000); // Offset updated to last_ts
    }

    #[test]
    fn infer_ts_stride_changed_stride_sn_delta_1() {
        let mut ctx = test_decomp_ctx(100, 1000, Some(160), 1000);
        ctx.infer_ts_stride_from_decompressed_ts(1080.into(), 101.into()); // New unit_stride=80
        assert_eq!(ctx.ts_stride, None); // Stride broken due to change
        assert_eq!(ctx.potential_ts_stride, Some(80)); // New potential stride detected
        assert_eq!(ctx.ts_offset, 1000); // Offset updated to last_ts
    }

    #[test]
    fn infer_ts_stride_changed_stride_sn_delta_gt_1() {
        let mut ctx = test_decomp_ctx(100, 1000, Some(160), 1000);
        ctx.infer_ts_stride_from_decompressed_ts(1160.into(), 102.into()); // unit stride = 80
        assert_eq!(ctx.ts_stride, None); // Stride broken due to change
        assert_eq!(ctx.potential_ts_stride, None); // Only tracks sn_delta=1
        assert_eq!(ctx.ts_offset, Timestamp::new(0)); // Reset when stride broken
    }

    #[test]
    fn infer_ts_stride_calculates_new_unit_stride_if_consistent() {
        let mut ctx = test_decomp_ctx(100, 1000, Some(160), 1000);
        ctx.infer_ts_stride_from_decompressed_ts(1170.into(), 102.into()); // unit_stride=85
        assert_eq!(
            ctx.ts_stride, None,
            "Stride should be broken when it doesn't match established stride"
        );
        assert_eq!(ctx.potential_ts_stride, None); // Not updated for sn_delta > 1
        assert_eq!(ctx.ts_offset, Timestamp::new(0)); // Reset when stride broken
        assert!(!ctx.ts_scaled_mode);
    }

    #[test]
    fn infer_ts_stride_broken_if_ts_not_cleanly_divisible_by_sn_delta() {
        let mut ctx = test_decomp_ctx(100, 1000, Some(160), 1000);
        ctx.infer_ts_stride_from_decompressed_ts(1171.into(), 102.into()); // 171 % 2 != 0
        assert_eq!(
            ctx.ts_stride, None,
            "Stride should be None if TS change is not a clean multiple of SN change for unit \
             stride"
        );
        assert_eq!(ctx.ts_offset, Timestamp::new(0)); // Offset reset when stride becomes None
        assert!(!ctx.ts_scaled_mode);
    }

    #[test]
    fn infer_ts_stride_broken_ts_decreases() {
        let mut ctx = test_decomp_ctx(100, 1000, Some(160), 1000);
        ctx.infer_ts_stride_from_decompressed_ts(900.into(), 101.into());
        assert_eq!(ctx.ts_stride, None, "Stride should be None if TS decreases");
        assert_eq!(ctx.ts_offset, Timestamp::new(0));
        assert!(!ctx.ts_scaled_mode);
    }

    #[test]
    fn infer_ts_stride_broken_sn_decreases_significant_wrap() {
        let mut ctx = test_decomp_ctx(10, 1000, Some(160), 1000);
        ctx.infer_ts_stride_from_decompressed_ts(1160.into(), 65530.into());
        assert_eq!(ctx.ts_stride, None);
        assert_eq!(ctx.ts_offset, Timestamp::new(0));
    }

    #[test]
    fn infer_ts_stride_sn_same_ts_changes() {
        let mut ctx = test_decomp_ctx(100, 1000, Some(160), 1000);
        ctx.infer_ts_stride_from_decompressed_ts(1100.into(), 100.into());
        assert_eq!(ctx.ts_stride, None);
        assert_eq!(ctx.ts_offset, Timestamp::new(0));
    }

    #[test]
    fn infer_ts_stride_sn_changes_ts_same() {
        let mut ctx = test_decomp_ctx(100, 1000, Some(160), 1000);
        ctx.infer_ts_stride_from_decompressed_ts(1000.into(), 101.into());
        assert_eq!(ctx.ts_stride, None);
        assert_eq!(ctx.ts_offset, Timestamp::new(0));
    }

    #[test]
    fn infer_ts_stride_no_change_in_sn_or_ts() {
        let mut ctx = test_decomp_ctx(100, 1000, Some(160), 1000);
        ctx.infer_ts_stride_from_decompressed_ts(1000.into(), 100.into()); // No change
        assert_eq!(ctx.ts_stride, Some(160)); // Stride remains
        assert_eq!(ctx.ts_offset, 1000); // ts_offset remains what it was
    }

    #[test]
    fn infer_ts_stride_ignored_if_scaled_mode_and_stride_known() {
        let mut ctx = test_decomp_ctx(100, 1000, Some(160), 1000);
        ctx.ts_scaled_mode = true;
        ctx.infer_ts_stride_from_decompressed_ts(1080.into(), 101.into()); // This would normally change stride to 80
        assert_eq!(ctx.ts_stride, Some(160)); // But it's ignored
        assert_eq!(ctx.ts_offset, 1000);
    }

    #[test]
    fn infer_ts_stride_ssrc_zero_no_inference() {
        let mut ctx = Profile1DecompressorContext::new(0.into()); // ssrc is 0 by default from new() then gets set
        if ctx.rtp_ssrc == 0 {
            // Ensure ssrc is indeed 0 for this test path
            ctx.last_reconstructed_rtp_sn_full = 100.into();
            ctx.last_reconstructed_rtp_ts_full = 1000.into();
            ctx.infer_ts_stride_from_decompressed_ts(1160.into(), 101.into());
            assert_eq!(ctx.ts_stride, None);
        } else {
            // If new() doesn't guarantee SSRC 0, this test might need adjustment or a more direct
            // setup. For now, assuming default ssrc is 0 or can be set to 0 before
            // other fields for this test. A more robust way would be:
            let mut ctx_ssrc_zero = Profile1DecompressorContext::new(0.into());
            ctx_ssrc_zero.rtp_ssrc = 0.into(); // Explicitly set SSRC to 0
            ctx_ssrc_zero.last_reconstructed_rtp_sn_full = 100.into();
            ctx_ssrc_zero.last_reconstructed_rtp_ts_full = 1000.into();
            ctx_ssrc_zero.infer_ts_stride_from_decompressed_ts(1160.into(), 101.into());
            assert_eq!(ctx_ssrc_zero.ts_stride, None);
        }
    }

    #[test]
    fn decompressor_context_new_and_initialization_from_ir_packet() {
        let time = Instant::now();
        let mut decomp_ctx = Profile1DecompressorContext::new(5.into());
        decomp_ctx.last_accessed = time;

        assert_eq!(decomp_ctx.cid(), 5);
        assert_eq!(decomp_ctx.profile_id(), RohcProfile::RtpUdpIp);
        assert_eq!(decomp_ctx.mode, Profile1DecompressorMode::NoContext);
        assert_eq!(decomp_ctx.p_sn, P1_DEFAULT_P_SN_OFFSET);
        assert_eq!(decomp_ctx.p_ts, P1_DEFAULT_P_TS_OFFSET);
        assert_eq!(
            decomp_ctx.expected_lsb_ts_width,
            P1_UO1_TS_LSB_WIDTH_DEFAULT
        );
        assert_eq!(decomp_ctx.p_ip_id, P1_DEFAULT_P_IP_ID_OFFSET);
        assert_eq!(
            decomp_ctx.expected_lsb_ip_id_width,
            P1_UO1_IP_ID_LSB_WIDTH_DEFAULT
        );
        assert_eq!(decomp_ctx.ts_stride, None);
        assert_eq!(decomp_ctx.ts_offset, 0);
        assert!(!decomp_ctx.ts_scaled_mode);
        assert_eq!(decomp_ctx.last_accessed, time);

        let ir_data = IrPacket {
            cid: 5.into(),
            profile_id: RohcProfile::RtpUdpIp,
            crc8: 0x00,
            static_ip_src: "10.0.0.1".parse().unwrap(),
            static_ip_dst: "10.0.0.2".parse().unwrap(),
            static_udp_src_port: 1000,
            static_udp_dst_port: 2000,
            static_rtp_ssrc: 0xABCD.into(),
            static_rtp_payload_type: 0,
            static_rtp_extension: false,
            static_rtp_padding: false,
            dyn_rtp_sn: 200.into(),
            dyn_rtp_timestamp: 20000.into(),
            dyn_rtp_marker: true,
            dyn_ip_ttl: 64,
            dyn_ip_id: 0.into(),
            ts_stride: None,
        };

        decomp_ctx.initialize_from_ir_packet(&ir_data);

        assert_eq!(decomp_ctx.ip_destination, ir_data.static_ip_dst);
        assert_eq!(decomp_ctx.rtp_ssrc, ir_data.static_rtp_ssrc);
        assert_eq!(decomp_ctx.last_reconstructed_rtp_sn_full, 200);
        assert_eq!(decomp_ctx.last_reconstructed_rtp_ts_full, 20000);
        assert!(decomp_ctx.last_reconstructed_rtp_marker);
        assert_eq!(decomp_ctx.last_reconstructed_ip_id_full, 0);
        assert_eq!(
            decomp_ctx.expected_lsb_sn_width,
            P1_UO0_SN_LSB_WIDTH_DEFAULT
        );
        assert_eq!(decomp_ctx.ts_stride, None);
        assert_eq!(decomp_ctx.ts_offset, 20000); // ts_offset becomes dyn_rtp_timestamp from IR
        assert!(!decomp_ctx.ts_scaled_mode); // ts_scaled_mode is false if ir_packet.ts_stride is None
    }

    #[test]
    fn decompressor_init_from_ir_with_stride_extension() {
        let mut decomp_ctx = Profile1DecompressorContext::new(1.into());
        let ir_data_with_stride = IrPacket {
            cid: 1.into(),
            profile_id: RohcProfile::RtpUdpIp,
            crc8: 0,
            static_ip_src: "1.1.1.1".parse().unwrap(),
            static_ip_dst: "2.2.2.2".parse().unwrap(),
            static_udp_src_port: 100,
            static_udp_dst_port: 200,
            static_rtp_ssrc: 0x1234.into(),
            static_rtp_payload_type: 0,
            static_rtp_extension: false,
            static_rtp_padding: false,
            dyn_rtp_sn: 50.into(),
            dyn_rtp_timestamp: 5000.into(),
            dyn_rtp_marker: false,
            dyn_ip_ttl: 64,
            dyn_ip_id: 0.into(),
            ts_stride: Some(160),
        };
        decomp_ctx.initialize_from_ir_packet(&ir_data_with_stride);
        assert_eq!(decomp_ctx.ts_stride, Some(160));
        assert_eq!(decomp_ctx.ts_offset, 5000); // ts_offset is dyn_rtp_timestamp from IR
        assert!(decomp_ctx.ts_scaled_mode); // ts_scaled_mode true because ir_packet.ts_stride is Some
    }

    #[test]
    fn decompressor_reconstruct_ts_from_scaled_logic() {
        let mut decomp_ctx = Profile1DecompressorContext::new(1.into());

        // Test case 1: Stride is None, should return None
        decomp_ctx.ts_stride = None;
        decomp_ctx.ts_offset = 1000.into(); // Offset doesn't matter if stride is None
        assert_eq!(
            decomp_ctx.reconstruct_ts_from_scaled(1),
            None,
            "Should be None if stride is None"
        );

        // Test case 2: Stride is Some, successful reconstruction
        decomp_ctx.ts_stride = Some(160);
        decomp_ctx.ts_offset = 1000.into();
        assert_eq!(
            decomp_ctx.reconstruct_ts_from_scaled(0),
            Some(1000.into()), // Compares Option<Timestamp> with Option<u32>
            "Reconstruction for ts_scaled = 0 failed"
        );
        assert_eq!(
            decomp_ctx.reconstruct_ts_from_scaled(1),
            Some(1160.into()), // offset + 1 * stride
            "Reconstruction for ts_scaled = 1 failed"
        );
        assert_eq!(
            decomp_ctx.reconstruct_ts_from_scaled(3),
            Some((1000 + 3 * 160).into()), // 1480
            "Reconstruction for ts_scaled = 3 failed"
        );
    }

    #[test]
    fn default_decompressor_context() {
        let ctx = Profile1DecompressorContext::default();
        assert_eq!(ctx.cid, 0);
        assert_eq!(ctx.mode, Profile1DecompressorMode::NoContext);
        assert_eq!(ctx.ts_stride, None);
    }

    #[test]
    fn context_trait_downcasting_decompressor() {
        let mut decomp_ctx_dyn: Box<dyn RohcDecompressorContext> =
            Box::new(Profile1DecompressorContext::new(2.into()));
        decomp_ctx_dyn.assign_cid(3.into());

        let specific_ctx_mut = decomp_ctx_dyn
            .as_any_mut()
            .downcast_mut::<Profile1DecompressorContext>();
        assert!(specific_ctx_mut.is_some());
        if let Some(s_ctx) = specific_ctx_mut {
            assert_eq!(s_ctx.cid, 3);
            s_ctx.mode = Profile1DecompressorMode::StaticContext;
            assert_eq!(s_ctx.mode, Profile1DecompressorMode::StaticContext);
        }
    }

    /// Test that potential_ts_stride is properly reset during IR initialization.
    /// This addresses the incomplete context state reset bug.
    #[test]
    fn ir_initialization_resets_potential_stride() {
        let mut context = Profile1DecompressorContext::new(ContextId::new(0));

        // Simulate having a potential stride from previous use
        context.potential_ts_stride = Some(160);

        let ir_packet = IrPacket {
            cid: ContextId::new(0),
            profile_id: RohcProfile::RtpUdpIp,
            static_rtp_ssrc: 0x12345678.into(),
            dyn_rtp_sn: SequenceNumber::new(100),
            dyn_rtp_timestamp: Timestamp::new(16000),
            ts_stride: None, // No stride in IR packet
            ..Default::default()
        };

        // Initialize context from IR packet
        context.initialize_from_ir_packet(&ir_packet);

        // Verify that potential_ts_stride was reset
        assert!(
            context.potential_ts_stride.is_none(),
            "potential_ts_stride should be reset to None during IR initialization"
        );

        // Verify other stride-related fields are properly set
        assert_eq!(context.ts_stride, None);
        assert_eq!(context.ts_offset, Timestamp::new(16000));
        assert!(!context.ts_scaled_mode);
    }

    /// Test that IR initialization with TS_STRIDE still resets potential_ts_stride.
    #[test]
    fn ir_initialization_with_stride_resets_potential_stride() {
        let mut context = Profile1DecompressorContext::new(ContextId::new(0));

        // Simulate having a different potential stride from previous use
        context.potential_ts_stride = Some(320);

        let ir_packet = IrPacket {
            cid: ContextId::new(0),
            profile_id: RohcProfile::RtpUdpIp,
            static_rtp_ssrc: 0x12345678.into(),
            dyn_rtp_sn: SequenceNumber::new(100),
            dyn_rtp_timestamp: Timestamp::new(16000),
            ts_stride: Some(160), // Stride provided in IR packet
            ..Default::default()
        };

        // Initialize context from IR packet
        context.initialize_from_ir_packet(&ir_packet);

        // Verify that potential_ts_stride was reset even when stride is provided
        assert!(
            context.potential_ts_stride.is_none(),
            "potential_ts_stride should be reset to None even when IR has stride"
        );

        // Verify stride-related fields are properly set from IR
        assert_eq!(context.ts_stride, Some(160));
        assert_eq!(context.ts_offset, Timestamp::new(16000));
        assert!(context.ts_scaled_mode);
    }

    /// Test that repeated IR packets don't cause state accumulation.
    #[test]
    fn repeated_ir_packets_maintain_clean_state() {
        let mut context = Profile1DecompressorContext::new(ContextId::new(0));

        // Process first IR packet
        let ir_packet_1 = IrPacket {
            cid: ContextId::new(0),
            profile_id: RohcProfile::RtpUdpIp,
            static_rtp_ssrc: 0x11111111.into(),
            dyn_rtp_sn: SequenceNumber::new(100),
            dyn_rtp_timestamp: Timestamp::new(10000),
            ts_stride: Some(160),
            ..Default::default()
        };

        context.initialize_from_ir_packet(&ir_packet_1);

        // Simulate some stride detection state
        context.potential_ts_stride = Some(320); // This should be cleared by next IR

        // Process second IR packet with different parameters
        let ir_packet_2 = IrPacket {
            cid: ContextId::new(0),
            profile_id: RohcProfile::RtpUdpIp,
            static_rtp_ssrc: 0x22222222.into(),
            dyn_rtp_sn: SequenceNumber::new(500),
            dyn_rtp_timestamp: Timestamp::new(50000),
            ts_stride: None, // No stride this time
            ..Default::default()
        };

        context.initialize_from_ir_packet(&ir_packet_2);

        // Verify that all state was properly reset and updated
        assert_eq!(context.rtp_ssrc.value(), 0x22222222);
        assert_eq!(
            context.last_reconstructed_rtp_sn_full,
            SequenceNumber::new(500)
        );
        assert_eq!(
            context.last_reconstructed_rtp_ts_full,
            Timestamp::new(50000)
        );
        assert_eq!(context.ts_stride, None);
        assert!(!context.ts_scaled_mode);
        assert!(
            context.potential_ts_stride.is_none(),
            "potential_ts_stride should be reset by second IR packet"
        );
    }
}
