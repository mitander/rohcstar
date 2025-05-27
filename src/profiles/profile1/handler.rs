//! ROHC (Robust Header Compression) Profile 1 (RTP/UDP/IP) handler implementation.
//!
//! This module provides the concrete implementation of the `ProfileHandler` trait
//! for ROHC Profile 1. It orchestrates the compression and decompression of
//! RTP/UDP/IPv4 packet headers according to the rules specified in RFC 3095.

use super::constants::*;
use super::context::{
    Profile1CompressorContext, Profile1CompressorMode, Profile1DecompressorContext,
    Profile1DecompressorMode,
};
use super::discriminator::Profile1PacketType;
use super::packet_processor::{
    build_profile1_ir_packet, build_profile1_uo0_packet, build_profile1_uo1_id_packet,
    build_profile1_uo1_sn_packet, build_profile1_uo1_ts_packet, parse_profile1_ir_packet,
    parse_profile1_uo0_packet, parse_profile1_uo1_id_packet, parse_profile1_uo1_sn_packet,
    parse_profile1_uo1_ts_packet,
};
use super::packet_types::{IrPacket, Uo0Packet, Uo1Packet};
use super::protocol_types::RtpUdpIpv4Headers;
use crate::constants::{DEFAULT_IPV4_TTL, IP_PROTOCOL_UDP, IPV4_STANDARD_IHL, RTP_VERSION};
use crate::crc;
use crate::encodings::{decode_lsb, encode_lsb};
use crate::error::{RohcError, RohcParsingError};
use crate::packet_defs::{GenericUncompressedHeaders, RohcProfile};
use crate::traits::{ProfileHandler, RohcCompressorContext, RohcDecompressorContext};

/// Implements the ROHC Profile 1 (RTP/UDP/IP) compression and decompression logic.
///
/// This handler is responsible for:
/// - Creating and managing Profile 1 specific compressor and decompressor contexts.
/// - Processing uncompressed RTP/UDP/IPv4 headers and generating corresponding
///   ROHC Profile 1 packets (IR, UO-0, UO-1-SN, UO-1-TS etc.).
/// - Parsing incoming ROHC Profile 1 packets and reconstructing the original
///   RTP/UDP/IPv4 headers.
/// - Managing state transitions within the Profile 1 contexts for both compressor and decompressor.
#[derive(Debug, Default)]
pub struct Profile1Handler;

impl Profile1Handler {
    /// Creates a new instance of the `Profile1Handler`.
    pub fn new() -> Self {
        Profile1Handler
    }

    /// Determines if an IR packet must be sent by the compressor based on context and current headers.
    ///
    /// An IR packet is forced if:
    /// - The compressor is in `InitializationAndRefresh` mode.
    /// - The IR refresh interval (`fo_packets_sent_since_ir`) has been met.
    /// - The SSRC of the current packet differs from the SSRC established in the context.
    ///
    /// # Parameters
    /// - `context`: A reference to the current `Profile1CompressorContext`.
    /// - `uncompressed_headers`: A reference to the current uncompressed headers being processed.
    ///
    /// # Returns
    /// `true` if an IR packet should be sent, `false` otherwise.
    fn should_force_ir(
        &self,
        context: &Profile1CompressorContext,
        uncompressed_headers: &RtpUdpIpv4Headers,
    ) -> bool {
        if context.mode == Profile1CompressorMode::InitializationAndRefresh {
            return true;
        }
        if context.ir_refresh_interval > 0
            && context.fo_packets_sent_since_ir >= context.ir_refresh_interval.saturating_sub(1)
        {
            return true;
        }
        if context.rtp_ssrc != 0 && context.rtp_ssrc != uncompressed_headers.rtp_ssrc {
            return true;
        }
        // TODO: Add logic for FO->IR transition if LSB encoding becomes insufficient for SN/TS/IP-ID.
        false
    }

    /// Handles the compressor logic for sending an IR (Initialization/Refresh) packet.
    ///
    /// This function is called when an IR packet is deemed necessary. It initializes or
    /// re-initializes the compressor context from the uncompressed headers (especially if
    /// SSRC changed or it's the first packet), populates an `IrPacket` structure,
    /// builds the ROHC IR packet bytes using `build_profile1_ir_packet`, and updates the
    /// compressor context state to `FirstOrder`, resetting IR-related counters.
    ///
    /// # Parameters
    /// - `context`: A mutable reference to the `Profile1CompressorContext`.
    /// - `uncompressed_headers`: The uncompressed `RtpUdpIpv4Headers` to be encapsulated.
    ///
    /// # Returns
    /// A `Result` containing the built IR packet as `Vec<u8>`, or a `RohcError` if building fails.
    fn compress_as_ir(
        &self,
        context: &mut Profile1CompressorContext,
        uncompressed_headers: &RtpUdpIpv4Headers,
    ) -> Result<Vec<u8>, RohcError> {
        if context.mode == Profile1CompressorMode::InitializationAndRefresh
            || context.rtp_ssrc == 0
            || context.rtp_ssrc != uncompressed_headers.rtp_ssrc
        {
            context.initialize_context_from_uncompressed_headers(uncompressed_headers);
        }

        let ir_data = IrPacket {
            cid: context.cid,
            profile_id: self.profile_id(),
            crc8: 0,
            static_ip_src: uncompressed_headers.ip_src,
            static_ip_dst: uncompressed_headers.ip_dst,
            static_udp_src_port: uncompressed_headers.udp_src_port,
            static_udp_dst_port: uncompressed_headers.udp_dst_port,
            static_rtp_ssrc: uncompressed_headers.rtp_ssrc,
            dyn_rtp_sn: uncompressed_headers.rtp_sequence_number,
            dyn_rtp_timestamp: uncompressed_headers.rtp_timestamp,
            dyn_rtp_marker: uncompressed_headers.rtp_marker,
        };

        let rohc_packet_bytes = build_profile1_ir_packet(&ir_data).map_err(RohcError::Building)?;

        context.last_sent_rtp_sn_full = uncompressed_headers.rtp_sequence_number;
        context.last_sent_rtp_ts_full = uncompressed_headers.rtp_timestamp;
        context.last_sent_rtp_marker = uncompressed_headers.rtp_marker;
        context.last_sent_ip_id_full = uncompressed_headers.ip_identification;
        context.mode = Profile1CompressorMode::FirstOrder;
        context.fo_packets_sent_since_ir = 0;
        context.consecutive_fo_packets_sent = 0;

        Ok(rohc_packet_bytes)
    }

    /// Handles the compressor logic for sending UO (Unidirectional Optimistic) packets.
    ///
    /// This function determines the most appropriate UO packet type (UO-0, UO-1-TS, UO-1-ID, or UO-1-SN)
    /// based on which header fields have changed relative to the compressor's context.
    /// It then calls the respective `build_compress_uo*` helper to construct the packet.
    /// After successful UO packet construction, it updates the compressor's context,
    /// including dynamic fields and counters for FO->SO transition and IR refresh.
    ///
    /// # Parameters
    /// - `context`: A mutable reference to the `Profile1CompressorContext`.
    /// - `uncompressed_headers`: The current uncompressed `RtpUdpIpv4Headers` to compress.
    ///
    /// # Returns
    /// A `Result` containing the built UO packet as `Vec<u8>`, or a `RohcError`.
    fn compress_as_uo(
        &self,
        context: &mut Profile1CompressorContext,
        uncompressed_headers: &RtpUdpIpv4Headers,
    ) -> Result<Vec<u8>, RohcError> {
        let current_sn = uncompressed_headers.rtp_sequence_number;
        let current_ts = uncompressed_headers.rtp_timestamp;
        let current_marker = uncompressed_headers.rtp_marker;
        let current_ip_id = uncompressed_headers.ip_identification;

        let marker_unchanged = current_marker == context.last_sent_rtp_marker;
        let sn_diff = current_sn.wrapping_sub(context.last_sent_rtp_sn_full);
        let sn_encodable_for_uo0 = sn_diff > 0 && sn_diff < 16;
        let ts_changed_significantly = current_ts != context.last_sent_rtp_ts_full;
        let sn_incremented_by_one = current_sn == context.last_sent_rtp_sn_full.wrapping_add(1);
        let ip_id_changed = current_ip_id != context.last_sent_ip_id_full;
        let ip_id_conditions_for_uo1_id = ip_id_changed && (context.current_lsb_ip_id_width > 0);

        let final_rohc_packet_bytes = if marker_unchanged
            && sn_encodable_for_uo0
            && !ts_changed_significantly
            && !ip_id_changed
        {
            self.build_compress_uo0(context, current_sn)?
        } else if marker_unchanged
            && ts_changed_significantly
            && sn_incremented_by_one
            && !ip_id_changed
        {
            self.build_compress_uo1_ts(context, current_sn, current_ts)?
        } else if marker_unchanged
            && ip_id_conditions_for_uo1_id
            && sn_incremented_by_one
            && !ts_changed_significantly
        {
            self.build_compress_uo1_id(context, current_sn, current_ip_id)?
        } else {
            self.build_compress_uo1_sn(context, current_sn, current_marker)?
        };

        context.last_sent_rtp_sn_full = current_sn;
        context.last_sent_rtp_ts_full = current_ts;
        context.last_sent_rtp_marker = current_marker;
        context.last_sent_ip_id_full = current_ip_id;

        if context.mode == Profile1CompressorMode::FirstOrder {
            context.consecutive_fo_packets_sent += 1;
            if context.consecutive_fo_packets_sent >= P1_COMPRESSOR_FO_TO_SO_THRESHOLD {
                context.mode = Profile1CompressorMode::SecondOrder;
            }
        }
        context.fo_packets_sent_since_ir += 1;

        Ok(final_rohc_packet_bytes)
    }

    /// Builds a ROHC Profile 1 UO-0 packet's byte representation.
    ///
    /// # Parameters
    /// - `context`: Mutable reference to `Profile1CompressorContext`.
    /// - `current_sn`: The full sequence number of the current packet to be compressed.
    ///
    /// # Returns
    /// `Result<Vec<u8>, RohcError>` containing the built UO-0 packet.
    fn build_compress_uo0(
        &self,
        context: &mut Profile1CompressorContext,
        current_sn: u16,
    ) -> Result<Vec<u8>, RohcError> {
        let sn_lsb_val = encode_lsb(current_sn as u64, P1_UO0_SN_LSB_WIDTH_DEFAULT)? as u8;
        let crc_input_bytes = self.build_uo_crc_input(
            context.rtp_ssrc,
            current_sn,
            context.last_sent_rtp_ts_full,
            context.last_sent_rtp_marker,
        );
        let crc3_val = crc::calculate_rohc_crc3(&crc_input_bytes);
        let uo0_data = Uo0Packet {
            cid: context.get_small_cid_for_packet(),
            sn_lsb: sn_lsb_val,
            crc3: crc3_val,
        };
        context.current_lsb_sn_width = P1_UO0_SN_LSB_WIDTH_DEFAULT;
        build_profile1_uo0_packet(&uo0_data).map_err(RohcError::Building)
    }

    /// Builds a ROHC Profile 1 UO-1-TS packet's byte representation.
    ///
    /// # Parameters
    /// - `context`: Mutable reference to `Profile1CompressorContext`.
    /// - `current_sn`: The full sequence number.
    /// - `current_ts`: The full timestamp of the current packet.
    ///
    /// # Returns
    /// `Result<Vec<u8>, RohcError>` containing the built UO-1-TS packet.
    fn build_compress_uo1_ts(
        &self,
        context: &mut Profile1CompressorContext,
        current_sn: u16,
        current_ts: u32,
    ) -> Result<Vec<u8>, RohcError> {
        let ts_lsb_val = encode_lsb(current_ts as u64, P1_UO1_TS_LSB_WIDTH_DEFAULT)? as u16;
        let crc_input_bytes = self.build_uo_crc_input(
            context.rtp_ssrc,
            current_sn,
            current_ts,
            context.last_sent_rtp_marker,
        );
        let calculated_crc8 = crc::calculate_rohc_crc8(&crc_input_bytes);
        let uo1_ts_packet_data = Uo1Packet {
            cid: context.get_small_cid_for_packet(),
            marker: false,
            ts_lsb: Some(ts_lsb_val),
            num_ts_lsb_bits: Some(P1_UO1_TS_LSB_WIDTH_DEFAULT),
            crc8: calculated_crc8,
            ..Default::default()
        };
        context.current_lsb_ts_width = P1_UO1_TS_LSB_WIDTH_DEFAULT;
        build_profile1_uo1_ts_packet(&uo1_ts_packet_data).map_err(RohcError::Building)
    }

    /// Builds a ROHC Profile 1 UO-1-SN packet's byte representation.
    ///
    /// # Parameters
    /// - `context`: Mutable reference to `Profile1CompressorContext`.
    /// - `current_sn`: The full sequence number of the current packet.
    /// - `current_marker`: The marker bit of the current packet.
    ///
    /// # Returns
    /// `Result<Vec<u8>, RohcError>` containing the built UO-1-SN packet.
    fn build_compress_uo1_sn(
        &self,
        context: &mut Profile1CompressorContext,
        current_sn: u16,
        current_marker: bool,
    ) -> Result<Vec<u8>, RohcError> {
        let sn_lsb_val = encode_lsb(current_sn as u64, P1_UO1_SN_LSB_WIDTH_DEFAULT)? as u16;
        let crc_input_bytes = self.build_uo_crc_input(
            context.rtp_ssrc,
            current_sn,
            context.last_sent_rtp_ts_full,
            current_marker,
        );
        let calculated_crc8 = crc::calculate_rohc_crc8(&crc_input_bytes);
        let uo1_sn_data = Uo1Packet {
            cid: context.get_small_cid_for_packet(),
            sn_lsb: sn_lsb_val,
            num_sn_lsb_bits: P1_UO1_SN_LSB_WIDTH_DEFAULT,
            marker: current_marker,
            crc8: calculated_crc8,
            ..Default::default()
        };
        context.current_lsb_sn_width = P1_UO1_SN_LSB_WIDTH_DEFAULT;
        build_profile1_uo1_sn_packet(&uo1_sn_data).map_err(RohcError::Building)
    }

    /// Builds a ROHC Profile 1 UO-1-ID packet's byte representation.
    ///
    /// # Parameters
    /// - `context`: Mutable reference to `Profile1CompressorContext`.
    /// - `current_sn`: The full sequence number.
    /// - `current_ip_id`: The full IP Identification of the current packet.
    ///
    /// # Returns
    /// `Result<Vec<u8>, RohcError>` containing the built UO-1-ID packet.
    fn build_compress_uo1_id(
        &self,
        context: &mut Profile1CompressorContext,
        current_sn: u16,
        current_ip_id: u16,
    ) -> Result<Vec<u8>, RohcError> {
        let ip_id_lsb_for_packet_field =
            encode_lsb(current_ip_id as u64, P1_UO1_IPID_LSB_WIDTH_DEFAULT)? as u8;

        let crc_input_bytes = self.build_uo1_id_crc_input(
            context.rtp_ssrc,
            current_sn,
            context.last_sent_rtp_ts_full,
            context.last_sent_rtp_marker,
            ip_id_lsb_for_packet_field,
        );
        let calculated_crc8 = crc::calculate_rohc_crc8(&crc_input_bytes);

        let uo1_id_packet_data = Uo1Packet {
            cid: context.get_small_cid_for_packet(),
            ip_id_lsb: Some(ip_id_lsb_for_packet_field as u16),
            num_ip_id_lsb_bits: Some(P1_UO1_IPID_LSB_WIDTH_DEFAULT),
            crc8: calculated_crc8,
            ..Default::default()
        };
        build_profile1_uo1_id_packet(&uo1_id_packet_data).map_err(RohcError::Building)
    }

    /// Determines if the decompressor should transition from Second Order (SO) to No Context (NC).
    ///
    /// # Parameters
    /// - `context`: An immutable reference to the `Profile1DecompressorContext`.
    ///
    /// # Returns
    /// `true` if a transition from SO to No Context (NC) is warranted, `false` otherwise.
    fn should_transition_so_to_nc(&self, context: &Profile1DecompressorContext) -> bool {
        if context.so_consecutive_failures >= P1_SO_MAX_CONSECUTIVE_FAILURES {
            return true;
        }
        if context.so_dynamic_confidence < P1_SO_TO_NC_CONFIDENCE_THRESHOLD {
            return true;
        }
        false
    }

    /// Determines if the decompressor should transition from Static Context (SC) to No Context (NC).
    ///
    /// According to ROHC Profile 1 (RFC 3095, Section 5.3.2.2.3), this transition
    /// occurs if `K2` (`P1_DECOMPRESSOR_SC_TO_NC_K2`) out of `N2` (`P1_DECOMPRESSOR_SC_TO_NC_N2`)
    /// "updating" packets fail to be decompressed correctly while in SC mode.
    ///
    /// # Parameters
    /// - `context`: An immutable reference to the `Profile1DecompressorContext` currently in SC state.
    ///
    /// # Returns
    /// `true` if a transition from SC to No Context (NC) is warranted, `false` otherwise.
    fn should_transition_sc_to_nc(&self, context: &Profile1DecompressorContext) -> bool {
        // Transition if k_failures (sc_to_nc_k_failures) >= K2.
        // The N2 windowing logic (incrementing sc_to_nc_n_window_count and resetting
        // both counters if N2 is reached without K2 failures) is handled by the caller
        // (decompress_in_sc_state).
        context.sc_to_nc_k_failures >= P1_DECOMPRESSOR_SC_TO_NC_K2
    }

    /// Decompresses an IR packet and transitions decompressor context to FullContext.
    ///
    /// # Parameters
    /// - `context`: Mutable reference to `Profile1DecompressorContext`.
    /// - `packet_bytes`: Slice containing the core IR packet.
    ///
    /// # Returns
    /// `Result<GenericUncompressedHeaders, RohcError>`.
    fn decompress_as_ir(
        &self,
        context: &mut Profile1DecompressorContext,
        packet_bytes: &[u8],
    ) -> Result<GenericUncompressedHeaders, RohcError> {
        match self._parse_and_reconstruct_ir(context, packet_bytes) {
            Ok(reconstructed_rtp_headers) => {
                context.mode = Profile1DecompressorMode::FullContext;
                context.consecutive_crc_failures_in_fc = 0;
                context.fc_packets_successful_streak = 0;
                context.so_static_confidence = 0;
                context.so_dynamic_confidence = 0;
                context.so_packets_received_in_so = 0;
                context.so_consecutive_failures = 0;
                context.sc_to_nc_k_failures = 0;
                context.sc_to_nc_n_window_count = 0;

                Ok(GenericUncompressedHeaders::RtpUdpIpv4(
                    reconstructed_rtp_headers,
                ))
            }
            Err(e) => Err(e),
        }
    }

    /// Decompresses a UO-0 packet when the decompressor is in FullContext mode.
    ///
    /// # Parameters
    /// - `context`: Mutable reference to `Profile1DecompressorContext`.
    /// - `packet_bytes`: Slice containing the core UO-0 packet data.
    ///
    /// # Returns
    /// `Result<GenericUncompressedHeaders, RohcError>`.
    fn decompress_as_uo0(
        &self,
        context: &mut Profile1DecompressorContext,
        packet_bytes: &[u8],
    ) -> Result<GenericUncompressedHeaders, RohcError> {
        match self._parse_and_reconstruct_uo0(context, packet_bytes) {
            Ok(reconstructed_rtp_headers) => {
                context.consecutive_crc_failures_in_fc = 0;
                context.fc_packets_successful_streak += 1;

                if context.fc_packets_successful_streak >= P1_DECOMPRESSOR_FC_TO_SO_THRESHOLD_STREAK
                {
                    context.mode = Profile1DecompressorMode::SecondOrder;
                    context.so_static_confidence = P1_SO_INITIAL_STATIC_CONFIDENCE;
                    context.so_dynamic_confidence = P1_SO_INITIAL_DYNAMIC_CONFIDENCE;
                    context.so_packets_received_in_so = 0;
                    context.so_consecutive_failures = 0;
                    context.fc_packets_successful_streak = 0;
                }
                Ok(GenericUncompressedHeaders::RtpUdpIpv4(
                    reconstructed_rtp_headers,
                ))
            }
            Err(e) => {
                context.consecutive_crc_failures_in_fc += 1;
                context.fc_packets_successful_streak = 0;
                if context.consecutive_crc_failures_in_fc
                    >= P1_DECOMPRESSOR_FC_TO_SC_CRC_FAILURE_THRESHOLD
                {
                    context.mode = Profile1DecompressorMode::StaticContext;
                    context.sc_to_nc_k_failures = 0;
                    context.sc_to_nc_n_window_count = 0;
                }
                Err(e)
            }
        }
    }

    /// Decompresses a UO-1-SN packet when decompressor is in FullContext mode.
    ///
    /// # Parameters
    /// - `context`: Mutable reference to `Profile1DecompressorContext`.
    /// - `packet_bytes`: Slice containing the core UO-1-SN packet data.
    ///
    /// # Returns
    /// `Result<GenericUncompressedHeaders, RohcError>`.
    fn decompress_as_uo1_sn(
        &self,
        context: &mut Profile1DecompressorContext,
        packet_bytes: &[u8],
    ) -> Result<GenericUncompressedHeaders, RohcError> {
        match self._parse_and_reconstruct_uo1_sn(context, packet_bytes) {
            Ok(reconstructed_rtp_headers) => {
                context.consecutive_crc_failures_in_fc = 0;
                context.fc_packets_successful_streak += 1;
                if context.fc_packets_successful_streak >= P1_DECOMPRESSOR_FC_TO_SO_THRESHOLD_STREAK
                {
                    context.mode = Profile1DecompressorMode::SecondOrder;
                    context.so_static_confidence = P1_SO_INITIAL_STATIC_CONFIDENCE;
                    context.so_dynamic_confidence = P1_SO_INITIAL_DYNAMIC_CONFIDENCE;
                    context.so_packets_received_in_so = 0;
                    context.so_consecutive_failures = 0;
                    context.fc_packets_successful_streak = 0;
                }
                Ok(GenericUncompressedHeaders::RtpUdpIpv4(
                    reconstructed_rtp_headers,
                ))
            }
            Err(e) => {
                context.consecutive_crc_failures_in_fc += 1;
                context.fc_packets_successful_streak = 0;
                if context.consecutive_crc_failures_in_fc
                    >= P1_DECOMPRESSOR_FC_TO_SC_CRC_FAILURE_THRESHOLD
                {
                    context.mode = Profile1DecompressorMode::StaticContext;
                    context.sc_to_nc_k_failures = 0;
                    context.sc_to_nc_n_window_count = 0;
                }
                Err(e)
            }
        }
    }

    /// Decompresses a UO-1-TS packet when decompressor is in FullContext mode.
    ///
    /// # Parameters
    /// - `context`: Mutable reference to `Profile1DecompressorContext`.
    /// - `packet_bytes`: Slice containing the core UO-1-TS packet data.
    ///
    /// # Returns
    /// `Result<GenericUncompressedHeaders, RohcError>`.
    fn decompress_as_uo1_ts(
        &self,
        context: &mut Profile1DecompressorContext,
        packet_bytes: &[u8],
    ) -> Result<GenericUncompressedHeaders, RohcError> {
        match self._parse_and_reconstruct_uo1_ts(context, packet_bytes) {
            Ok(reconstructed_rtp_headers) => {
                context.consecutive_crc_failures_in_fc = 0;
                context.fc_packets_successful_streak += 1;
                if context.fc_packets_successful_streak >= P1_DECOMPRESSOR_FC_TO_SO_THRESHOLD_STREAK
                {
                    context.mode = Profile1DecompressorMode::SecondOrder;
                    context.so_static_confidence = P1_SO_INITIAL_STATIC_CONFIDENCE;
                    context.so_dynamic_confidence = P1_SO_INITIAL_DYNAMIC_CONFIDENCE;
                    context.so_packets_received_in_so = 0;
                    context.so_consecutive_failures = 0;
                    context.fc_packets_successful_streak = 0;
                }
                Ok(GenericUncompressedHeaders::RtpUdpIpv4(
                    reconstructed_rtp_headers,
                ))
            }
            Err(e) => {
                context.consecutive_crc_failures_in_fc += 1;
                context.fc_packets_successful_streak = 0;
                if context.consecutive_crc_failures_in_fc
                    >= P1_DECOMPRESSOR_FC_TO_SC_CRC_FAILURE_THRESHOLD
                {
                    context.mode = Profile1DecompressorMode::StaticContext;
                    context.sc_to_nc_k_failures = 0;
                    context.sc_to_nc_n_window_count = 0;
                }
                Err(e)
            }
        }
    }

    /// Decompresses a UO-1-ID packet when decompressor is in FullContext mode.
    ///
    /// # Parameters
    /// - `context`: Mutable reference to `Profile1DecompressorContext`.
    /// - `packet_bytes`: Slice containing the core UO-1-ID packet data.
    ///
    /// # Returns
    /// `Result<GenericUncompressedHeaders, RohcError>`.
    fn decompress_as_uo1_id(
        &self,
        context: &mut Profile1DecompressorContext,
        packet_bytes: &[u8],
    ) -> Result<GenericUncompressedHeaders, RohcError> {
        match self._parse_and_reconstruct_uo1_id(context, packet_bytes) {
            Ok(reconstructed_rtp_headers) => {
                context.consecutive_crc_failures_in_fc = 0;
                context.fc_packets_successful_streak += 1;
                if context.fc_packets_successful_streak >= P1_DECOMPRESSOR_FC_TO_SO_THRESHOLD_STREAK
                {
                    context.mode = Profile1DecompressorMode::SecondOrder;
                    context.so_static_confidence = P1_SO_INITIAL_STATIC_CONFIDENCE;
                    context.so_dynamic_confidence = P1_SO_INITIAL_DYNAMIC_CONFIDENCE;
                    context.so_packets_received_in_so = 0;
                    context.so_consecutive_failures = 0;
                    context.fc_packets_successful_streak = 0;
                }
                Ok(GenericUncompressedHeaders::RtpUdpIpv4(
                    reconstructed_rtp_headers,
                ))
            }
            Err(e) => {
                context.consecutive_crc_failures_in_fc += 1;
                context.fc_packets_successful_streak = 0;
                if context.consecutive_crc_failures_in_fc
                    >= P1_DECOMPRESSOR_FC_TO_SC_CRC_FAILURE_THRESHOLD
                {
                    context.mode = Profile1DecompressorMode::StaticContext;
                    context.sc_to_nc_k_failures = 0;
                    context.sc_to_nc_n_window_count = 0;
                }
                Err(e)
            }
        }
    }

    /// Handles decompression of packets when the decompressor is in Static Context (SC) state.
    ///
    /// # Parameters
    /// - `context`: A mutable reference to the `Profile1DecompressorContext`.
    /// - `packet_bytes`: A byte slice containing the core ROHC packet data.
    /// - `discriminated_type`: The `Profile1PacketType` as determined from the first byte.
    ///
    /// # Returns
    /// `Result<GenericUncompressedHeaders, RohcError>`. Context mode might change.
    fn decompress_in_sc_state(
        &self,
        context: &mut Profile1DecompressorContext,
        packet_bytes: &[u8],
        discriminated_type: Profile1PacketType,
    ) -> Result<GenericUncompressedHeaders, RohcError> {
        debug_assert_eq!(context.mode, Profile1DecompressorMode::StaticContext);

        let parse_reconstruct_result: Result<GenericUncompressedHeaders, RohcError>;
        let mut is_failure_of_dynamic_updater_parse = false;

        match discriminated_type {
            Profile1PacketType::Uo1Ts => {
                let res = self._parse_and_reconstruct_uo1_ts(context, packet_bytes);
                if res.is_err() {
                    is_failure_of_dynamic_updater_parse = true;
                }
                parse_reconstruct_result = res.map(GenericUncompressedHeaders::RtpUdpIpv4);
            }
            Profile1PacketType::Uo1Id => {
                let res = self._parse_and_reconstruct_uo1_id(context, packet_bytes);
                if res.is_err() {
                    is_failure_of_dynamic_updater_parse = true;
                }
                parse_reconstruct_result = res.map(GenericUncompressedHeaders::RtpUdpIpv4);
            }
            Profile1PacketType::Uo1Sn { .. } => {
                let res = self._parse_and_reconstruct_uo1_sn(context, packet_bytes);
                if res.is_err() {
                    is_failure_of_dynamic_updater_parse = true;
                }
                parse_reconstruct_result = res.map(GenericUncompressedHeaders::RtpUdpIpv4);
            }
            Profile1PacketType::Uo0 => {
                is_failure_of_dynamic_updater_parse = false;
                parse_reconstruct_result = Err(RohcError::InvalidState(
                    "UO-0 packet received in StaticContext mode; cannot establish dynamic context."
                        .to_string(),
                ));
            }
            Profile1PacketType::Unknown(val) => {
                is_failure_of_dynamic_updater_parse = true;
                parse_reconstruct_result =
                    Err(RohcError::Parsing(RohcParsingError::InvalidPacketType {
                        discriminator: val,
                        profile_id: Some(self.profile_id().into()),
                    }));
            }
            Profile1PacketType::IrStatic | Profile1PacketType::IrDynamic => {
                return Err(RohcError::Internal(
                    "IR packet unexpectedly routed to decompress_in_sc_state.".to_string(),
                ));
            }
        }

        match parse_reconstruct_result {
            Ok(headers) => {
                context.sc_to_nc_k_failures = 0;
                context.sc_to_nc_n_window_count = 0;
                Ok(headers)
            }
            Err(ref e) => {
                context.sc_to_nc_n_window_count = context.sc_to_nc_n_window_count.saturating_add(1);

                if is_failure_of_dynamic_updater_parse && !matches!(e, RohcError::InvalidState(_)) {
                    context.sc_to_nc_k_failures = context.sc_to_nc_k_failures.saturating_add(1);
                }

                if self.should_transition_sc_to_nc(context) {
                    context.mode = Profile1DecompressorMode::NoContext;
                    context.reset_for_nc_transition();
                } else if context.sc_to_nc_n_window_count >= P1_DECOMPRESSOR_SC_TO_NC_N2 {
                    context.sc_to_nc_k_failures = 0;
                    context.sc_to_nc_n_window_count = 0;
                }
                Err(e.clone())
            }
        }
    }

    /// Handles decompression of packets when the decompressor is in Second Order (SO) state.
    ///
    /// # Parameters
    /// - `context`: A mutable reference to the `Profile1DecompressorContext`.
    /// - `packet_bytes`: A byte slice containing the core ROHC packet data.
    /// - `discriminated_type`: The `Profile1PacketType` as determined from the first byte.
    ///
    /// # Returns
    /// `Result<GenericUncompressedHeaders, RohcError>`. Context mode might change to `NoContext`.
    fn decompress_in_so_state(
        &self,
        context: &mut Profile1DecompressorContext,
        packet_bytes: &[u8],
        discriminated_type: Profile1PacketType,
    ) -> Result<GenericUncompressedHeaders, RohcError> {
        debug_assert_eq!(context.mode, Profile1DecompressorMode::SecondOrder);

        let parse_reconstruct_result: Result<GenericUncompressedHeaders, RohcError>;

        match discriminated_type {
            Profile1PacketType::Uo1Ts => {
                parse_reconstruct_result = self
                    ._parse_and_reconstruct_uo1_ts(context, packet_bytes)
                    .map(GenericUncompressedHeaders::RtpUdpIpv4);
            }
            Profile1PacketType::Uo1Id => {
                parse_reconstruct_result = self
                    ._parse_and_reconstruct_uo1_id(context, packet_bytes)
                    .map(GenericUncompressedHeaders::RtpUdpIpv4);
            }
            Profile1PacketType::Uo1Sn { .. } => {
                parse_reconstruct_result = self
                    ._parse_and_reconstruct_uo1_sn(context, packet_bytes)
                    .map(GenericUncompressedHeaders::RtpUdpIpv4);
            }
            Profile1PacketType::Uo0 => {
                parse_reconstruct_result = self
                    ._parse_and_reconstruct_uo0(context, packet_bytes)
                    .map(GenericUncompressedHeaders::RtpUdpIpv4);
            }
            Profile1PacketType::Unknown(val) => {
                parse_reconstruct_result =
                    Err(RohcError::Parsing(RohcParsingError::InvalidPacketType {
                        discriminator: val,
                        profile_id: Some(self.profile_id().into()),
                    }));
            }
            Profile1PacketType::IrStatic | Profile1PacketType::IrDynamic => {
                return Err(RohcError::Internal(
                    "IR packet unexpectedly routed to decompress_in_so_state.".to_string(),
                ));
            }
        }

        match parse_reconstruct_result {
            Ok(headers) => {
                debug_assert_eq!(context.mode, Profile1DecompressorMode::SecondOrder);
                context.so_dynamic_confidence = context
                    .so_dynamic_confidence
                    .saturating_add(P1_SO_SUCCESS_CONFIDENCE_BOOST);
                context.so_consecutive_failures = 0;
                context.so_packets_received_in_so =
                    context.so_packets_received_in_so.saturating_add(1);
                Ok(headers)
            }
            Err(e) => {
                debug_assert_eq!(context.mode, Profile1DecompressorMode::SecondOrder);
                context.so_dynamic_confidence = context
                    .so_dynamic_confidence
                    .saturating_sub(P1_SO_FAILURE_CONFIDENCE_PENALTY);
                context.so_consecutive_failures = context.so_consecutive_failures.saturating_add(1);
                if self.should_transition_so_to_nc(context) {
                    context.mode = Profile1DecompressorMode::NoContext;
                    context.reset_for_nc_transition();
                }
                Err(e)
            }
        }
    }

    /// Internal helper: Parses an IR packet and updates decompressor context.
    ///
    /// # Parameters
    /// - `context`: A mutable reference to the `Profile1DecompressorContext`.
    /// - `packet_bytes`: Slice containing the core IR packet data.
    ///
    /// # Returns
    /// `Result<RtpUdpIpv4Headers, RohcError>`: The reconstructed headers.
    fn _parse_and_reconstruct_ir(
        &self,
        context: &mut Profile1DecompressorContext,
        packet_bytes: &[u8],
    ) -> Result<RtpUdpIpv4Headers, RohcError> {
        let parsed_ir = parse_profile1_ir_packet(packet_bytes, context.cid())?;
        if parsed_ir.profile_id != self.profile_id() {
            return Err(RohcError::Parsing(RohcParsingError::InvalidProfileId(
                parsed_ir.profile_id.into(),
            )));
        }

        context.ip_source = parsed_ir.static_ip_src;
        context.ip_destination = parsed_ir.static_ip_dst;
        context.udp_source_port = parsed_ir.static_udp_src_port;
        context.udp_destination_port = parsed_ir.static_udp_dst_port;
        context.rtp_ssrc = parsed_ir.static_rtp_ssrc;
        context.last_reconstructed_rtp_sn_full = parsed_ir.dyn_rtp_sn;
        context.last_reconstructed_rtp_ts_full = parsed_ir.dyn_rtp_timestamp;
        context.last_reconstructed_rtp_marker = parsed_ir.dyn_rtp_marker;
        context.last_reconstructed_ip_id_full = 0;

        Ok(self.reconstruct_full_headers(
            context,
            parsed_ir.dyn_rtp_sn,
            parsed_ir.dyn_rtp_timestamp,
            parsed_ir.dyn_rtp_marker,
            context.last_reconstructed_ip_id_full,
        ))
    }

    /// Internal helper: Parses a UO-0 packet and updates decompressor context.
    ///
    /// # Parameters
    /// - `context`: Mutable reference to `Profile1DecompressorContext`.
    /// - `packet_bytes`: Slice containing the core UO-0 packet data.
    ///
    /// # Returns
    /// `Result<RtpUdpIpv4Headers, RohcError>` containing reconstructed headers.
    fn _parse_and_reconstruct_uo0(
        &self,
        context: &mut Profile1DecompressorContext,
        packet_bytes: &[u8],
    ) -> Result<RtpUdpIpv4Headers, RohcError> {
        let cid_for_parse = if context.cid() == 0 {
            None
        } else {
            Some(context.cid() as u8)
        };
        let parsed_uo0 = parse_profile1_uo0_packet(packet_bytes, cid_for_parse)?;

        let decoded_sn = decode_lsb(
            parsed_uo0.sn_lsb as u64,
            context.last_reconstructed_rtp_sn_full as u64,
            context.expected_lsb_sn_width,
            context.p_sn,
        )? as u16;

        let marker_for_header = context.last_reconstructed_rtp_marker;
        let ts_for_header = context.last_reconstructed_rtp_ts_full;
        let ip_id_for_header = context.last_reconstructed_ip_id_full;

        let crc_input_bytes = self.build_uo_crc_input(
            context.rtp_ssrc,
            decoded_sn,
            ts_for_header,
            marker_for_header,
        );
        let calculated_crc3 = crc::calculate_rohc_crc3(&crc_input_bytes);

        if calculated_crc3 != parsed_uo0.crc3 {
            return Err(RohcError::Parsing(RohcParsingError::CrcMismatch {
                expected: parsed_uo0.crc3,
                calculated: calculated_crc3,
                crc_type: "ROHC-CRC3".to_string(),
            }));
        }
        context.last_reconstructed_rtp_sn_full = decoded_sn;
        Ok(self.reconstruct_full_headers(
            context,
            decoded_sn,
            ts_for_header,
            marker_for_header,
            ip_id_for_header,
        ))
    }

    /// Internal helper: Parses UO-1-SN, decodes SN/Marker, validates CRC, updates dynamic fields.
    ///
    /// # Parameters
    /// - `context`: Mutable reference to `Profile1DecompressorContext`.
    /// - `packet_bytes`: Slice containing the core UO-1-SN packet data.
    ///
    /// # Returns
    /// `Result<RtpUdpIpv4Headers, RohcError>`
    fn _parse_and_reconstruct_uo1_sn(
        &self,
        context: &mut Profile1DecompressorContext,
        packet_bytes: &[u8],
    ) -> Result<RtpUdpIpv4Headers, RohcError> {
        let parsed_uo1 = parse_profile1_uo1_sn_packet(packet_bytes)?;
        let decoded_sn = decode_lsb(
            parsed_uo1.sn_lsb as u64,
            context.last_reconstructed_rtp_sn_full as u64,
            parsed_uo1.num_sn_lsb_bits,
            context.p_sn,
        )? as u16;

        let marker_for_header = parsed_uo1.marker;
        let ts_for_header = context.last_reconstructed_rtp_ts_full;
        let ip_id_for_header = context.last_reconstructed_ip_id_full;

        let crc_input_bytes = self.build_uo_crc_input(
            context.rtp_ssrc,
            decoded_sn,
            ts_for_header,
            marker_for_header,
        );
        if crc::calculate_rohc_crc8(&crc_input_bytes) != parsed_uo1.crc8 {
            return Err(RohcError::Parsing(RohcParsingError::CrcMismatch {
                expected: parsed_uo1.crc8,
                calculated: crc::calculate_rohc_crc8(&crc_input_bytes),
                crc_type: "ROHC-CRC8".to_string(),
            }));
        }
        context.last_reconstructed_rtp_sn_full = decoded_sn;
        context.last_reconstructed_rtp_marker = marker_for_header;
        Ok(self.reconstruct_full_headers(
            context,
            decoded_sn,
            ts_for_header,
            marker_for_header,
            ip_id_for_header,
        ))
    }

    /// Internal helper: Parses UO-1-TS, decodes TS (SN is SN+1), validates CRC, updates dynamic fields.
    ///
    /// # Parameters
    /// - `context`: Mutable reference to `Profile1DecompressorContext`.
    /// - `packet_bytes`: Slice containing the core UO-1-TS packet data.
    ///
    /// # Returns
    /// `Result<RtpUdpIpv4Headers, RohcError>`
    fn _parse_and_reconstruct_uo1_ts(
        &self,
        context: &mut Profile1DecompressorContext,
        packet_bytes: &[u8],
    ) -> Result<RtpUdpIpv4Headers, RohcError> {
        let parsed_uo1_ts = parse_profile1_uo1_ts_packet(packet_bytes)?;
        let reconstructed_sn = context.last_reconstructed_rtp_sn_full.wrapping_add(1);
        let marker_for_header = context.last_reconstructed_rtp_marker;
        let ip_id_for_header = context.last_reconstructed_ip_id_full;

        let decoded_ts = decode_lsb(
            parsed_uo1_ts.ts_lsb.unwrap_or(0) as u64,
            context.last_reconstructed_rtp_ts_full as u64,
            parsed_uo1_ts
                .num_ts_lsb_bits
                .unwrap_or(P1_UO1_TS_LSB_WIDTH_DEFAULT),
            context.p_ts,
        )? as u32;

        let crc_input_bytes = self.build_uo_crc_input(
            context.rtp_ssrc,
            reconstructed_sn,
            decoded_ts,
            marker_for_header,
        );
        if crc::calculate_rohc_crc8(&crc_input_bytes) != parsed_uo1_ts.crc8 {
            return Err(RohcError::Parsing(RohcParsingError::CrcMismatch {
                expected: parsed_uo1_ts.crc8,
                calculated: crc::calculate_rohc_crc8(&crc_input_bytes),
                crc_type: "ROHC-CRC8".to_string(),
            }));
        }
        context.last_reconstructed_rtp_sn_full = reconstructed_sn;
        context.last_reconstructed_rtp_ts_full = decoded_ts;
        Ok(self.reconstruct_full_headers(
            context,
            reconstructed_sn,
            decoded_ts,
            marker_for_header,
            ip_id_for_header,
        ))
    }

    /// Internal helper: Parses UO-1-ID, decodes IP-ID (SN is SN+1), validates CRC, updates dynamic fields.
    ///
    /// # Parameters
    /// - `context`: Mutable reference to `Profile1DecompressorContext`.
    /// - `packet_bytes`: Slice containing the core UO-1-ID packet data.
    ///
    /// # Returns
    /// `Result<RtpUdpIpv4Headers, RohcError>`
    fn _parse_and_reconstruct_uo1_id(
        &self,
        context: &mut Profile1DecompressorContext,
        packet_bytes: &[u8],
    ) -> Result<RtpUdpIpv4Headers, RohcError> {
        let parsed_uo1_id = parse_profile1_uo1_id_packet(packet_bytes)?;
        let reconstructed_sn = context.last_reconstructed_rtp_sn_full.wrapping_add(1);
        let ts_for_header = context.last_reconstructed_rtp_ts_full;
        let marker_for_header = context.last_reconstructed_rtp_marker;

        let received_ip_id_lsb_val = parsed_uo1_id.ip_id_lsb.unwrap_or(0);
        let num_ip_id_lsb_bits = parsed_uo1_id
            .num_ip_id_lsb_bits
            .unwrap_or(P1_UO1_IPID_LSB_WIDTH_DEFAULT);

        let decoded_ip_id = decode_lsb(
            received_ip_id_lsb_val as u64,
            context.last_reconstructed_ip_id_full as u64,
            num_ip_id_lsb_bits,
            context.p_ip_id,
        )? as u16;

        let crc_input_bytes = self.build_uo1_id_crc_input(
            context.rtp_ssrc,
            reconstructed_sn,
            ts_for_header,
            marker_for_header,
            received_ip_id_lsb_val as u8,
        );
        if crc::calculate_rohc_crc8(&crc_input_bytes) != parsed_uo1_id.crc8 {
            return Err(RohcError::Parsing(RohcParsingError::CrcMismatch {
                expected: parsed_uo1_id.crc8,
                calculated: crc::calculate_rohc_crc8(&crc_input_bytes),
                crc_type: "ROHC-CRC8".to_string(),
            }));
        }
        context.last_reconstructed_rtp_sn_full = reconstructed_sn;
        context.last_reconstructed_ip_id_full = decoded_ip_id;
        Ok(self.reconstruct_full_headers(
            context,
            reconstructed_sn,
            ts_for_header,
            marker_for_header,
            decoded_ip_id,
        ))
    }
    /// Reconstructs full `RtpUdpIpv4Headers` from context and decoded dynamic fields.
    ///
    /// # Parameters
    /// - `context`: An immutable reference to `Profile1DecompressorContext`.
    /// - `sn`: The decoded RTP Sequence Number.
    /// - `ts`: The decoded RTP Timestamp.
    /// - `marker`: The decoded RTP Marker bit.
    /// - `ip_id`: The decoded IP Identification.
    ///
    /// # Returns
    /// Fully reconstructed `RtpUdpIpv4Headers`.
    fn reconstruct_full_headers(
        &self,
        context: &Profile1DecompressorContext,
        sn: u16,
        ts: u32,
        marker: bool,
        ip_id: u16,
    ) -> RtpUdpIpv4Headers {
        RtpUdpIpv4Headers {
            ip_src: context.ip_source,
            ip_dst: context.ip_destination,
            udp_src_port: context.udp_source_port,
            udp_dst_port: context.udp_destination_port,
            rtp_ssrc: context.rtp_ssrc,
            rtp_sequence_number: sn,
            rtp_timestamp: ts,
            rtp_marker: marker,
            ip_ihl: IPV4_STANDARD_IHL,
            ip_dscp: 0,
            ip_ecn: 0,
            ip_total_length: 0,
            ip_identification: ip_id,
            ip_dont_fragment: true,
            ip_more_fragments: false,
            ip_fragment_offset: 0,
            ip_ttl: DEFAULT_IPV4_TTL,
            ip_protocol: IP_PROTOCOL_UDP,
            ip_checksum: 0,
            udp_length: 0,
            udp_checksum: 0,
            rtp_version: RTP_VERSION,
            rtp_padding: false,
            rtp_extension: false,
            rtp_csrc_count: 0,
            rtp_payload_type: 0,
            rtp_csrc_list: Vec::new(),
        }
    }

    /// Creates byte slice input for CRC calculation for UO-0 and UO-1 packets.
    /// Format: SSRC(4), SN(2), TS(4), Marker(1).
    ///
    /// # Parameters
    /// - `context_ssrc`: The SSRC from the context.
    /// - `sn`: The full sequence number (current or reconstructed).
    /// - `ts`: The full timestamp (current or from context).
    /// - `marker`: The marker bit value.
    ///
    /// # Returns
    /// `Vec<u8>` containing the CRC input.
    fn build_uo_crc_input(&self, context_ssrc: u32, sn: u16, ts: u32, marker: bool) -> Vec<u8> {
        let mut crc_input = Vec::with_capacity(P1_UO_CRC_INPUT_LENGTH_BYTES);
        crc_input.extend_from_slice(&context_ssrc.to_be_bytes());
        crc_input.extend_from_slice(&sn.to_be_bytes());
        crc_input.extend_from_slice(&ts.to_be_bytes());
        crc_input.push(if marker { 0x01 } else { 0x00 });
        crc_input
    }

    /// Creates byte slice input for CRC calculation for UO-1-ID packets.
    /// Format: SSRC(4), SN(2), TS(4), Marker(1), IP-ID LSBs(1 for 8-bit width).
    ///
    /// # Parameters
    /// - `context_ssrc`: The SSRC from the context.
    /// - `sn`: The full sequence number.
    /// - `ts`: The full timestamp.
    /// - `marker`: The marker bit value.
    /// - `ip_id_lsb`: The LSB of the IP-ID (typically 8 bits).
    ///
    /// # Returns
    /// `Vec<u8>` containing the CRC input.
    fn build_uo1_id_crc_input(
        &self,
        context_ssrc: u32,
        sn: u16,
        ts: u32,
        marker: bool,
        ip_id_lsb: u8,
    ) -> Vec<u8> {
        let mut crc_input = Vec::with_capacity(P1_UO_CRC_INPUT_LENGTH_BYTES + 1);
        crc_input.extend_from_slice(&context_ssrc.to_be_bytes());
        crc_input.extend_from_slice(&sn.to_be_bytes());
        crc_input.extend_from_slice(&ts.to_be_bytes());
        crc_input.push(if marker { 0x01 } else { 0x00 });
        crc_input.push(ip_id_lsb);
        crc_input
    }
} // END OF impl Profile1Handler

impl ProfileHandler for Profile1Handler {
    /// Returns the ROHC Profile Identifier that this handler implements (`RohcProfile::RtpUdpIp`).
    fn profile_id(&self) -> RohcProfile {
        RohcProfile::RtpUdpIp
    }

    /// Creates a new, Profile 1 specific compressor context.
    ///
    /// # Parameters
    /// - `cid`: The Context Identifier (0-65535) for the new flow.
    /// - `ir_refresh_interval`: The suggested interval (in packets) for IR refreshes.
    fn create_compressor_context(
        &self,
        cid: u16,
        ir_refresh_interval: u32,
    ) -> Box<dyn RohcCompressorContext> {
        Box::new(Profile1CompressorContext::new(cid, ir_refresh_interval))
    }

    /// Creates a new, Profile 1 specific decompressor context.
    ///
    /// # Parameters
    /// - `cid`: The Context Identifier (0-65535) for the new flow.
    fn create_decompressor_context(&self, cid: u16) -> Box<dyn RohcDecompressorContext> {
        Box::new(Profile1DecompressorContext::new(cid))
    }

    /// Compresses a set of uncompressed RTP/UDP/IPv4 headers using ROHC Profile 1 logic.
    ///
    /// # Parameters
    /// - `context_dyn`: A mutable reference to a `RohcCompressorContext`.
    /// - `headers_generic`: The `GenericUncompressedHeaders` to be compressed.
    ///
    /// # Returns
    /// A `Result` containing the ROHC-compressed packet as `Vec<u8>`, or a `RohcError`.
    fn compress(
        &self,
        context_dyn: &mut dyn RohcCompressorContext,
        headers_generic: &GenericUncompressedHeaders,
    ) -> Result<Vec<u8>, RohcError> {
        let context = context_dyn
            .as_any_mut()
            .downcast_mut::<Profile1CompressorContext>()
            .ok_or_else(|| {
                RohcError::Internal("P1Handler::compress: Incorrect context type.".to_string())
            })?;

        let uncompressed_headers = match headers_generic {
            GenericUncompressedHeaders::RtpUdpIpv4(h) => h,
            _ => return Err(RohcError::UnsupportedProfile(u8::from(context.profile_id))),
        };

        if context.rtp_ssrc != 0 && context.rtp_ssrc != uncompressed_headers.rtp_ssrc {
            context.initialize_context_from_uncompressed_headers(uncompressed_headers);
        }

        if self.should_force_ir(context, uncompressed_headers) {
            self.compress_as_ir(context, uncompressed_headers)
        } else {
            self.compress_as_uo(context, uncompressed_headers)
        }
    }

    /// Decompresses a ROHC Profile 1 packet.
    ///
    /// # Parameters
    /// - `context_dyn`: A mutable reference to a `RohcDecompressorContext`.
    /// - `packet_bytes`: A slice containing the core ROHC Profile 1 packet data.
    ///
    /// # Returns
    /// A `Result` containing the reconstructed `GenericUncompressedHeaders`, or a `RohcError`.
    fn decompress(
        &self,
        context_dyn: &mut dyn RohcDecompressorContext,
        packet_bytes: &[u8],
    ) -> Result<GenericUncompressedHeaders, RohcError> {
        let context = context_dyn
            .as_any_mut()
            .downcast_mut::<Profile1DecompressorContext>()
            .ok_or_else(|| {
                RohcError::Internal("P1Handler::decompress: Incorrect context type.".to_string())
            })?;

        if packet_bytes.is_empty() {
            return Err(RohcError::Parsing(RohcParsingError::NotEnoughData {
                needed: 1,
                got: 0,
                context: "ROHC packet".to_string(),
            }));
        }

        let first_byte = packet_bytes[0];
        let discriminated_type = Profile1PacketType::from_first_byte(first_byte);

        if context.mode == Profile1DecompressorMode::NoContext {
            if discriminated_type.is_ir() {
                return self.decompress_as_ir(context, packet_bytes);
            } else {
                return Err(RohcError::InvalidState(
                    "Non-IR packet received but decompressor is in NoContext mode.".to_string(),
                ));
            }
        }

        if discriminated_type.is_ir() {
            return self.decompress_as_ir(context, packet_bytes);
        }

        match context.mode {
            Profile1DecompressorMode::StaticContext => {
                self.decompress_in_sc_state(context, packet_bytes, discriminated_type)
            }
            Profile1DecompressorMode::SecondOrder => {
                if discriminated_type.is_uo0() || discriminated_type.is_uo1() {
                    self.decompress_in_so_state(context, packet_bytes, discriminated_type)
                } else {
                    Err(RohcError::InvalidState(format!(
                        "Packet type {:?} not processable by SO decompressor.",
                        discriminated_type
                    )))
                }
            }
            Profile1DecompressorMode::FullContext => match discriminated_type {
                Profile1PacketType::Uo1Ts => self.decompress_as_uo1_ts(context, packet_bytes),
                Profile1PacketType::Uo1Id => self.decompress_as_uo1_id(context, packet_bytes),
                Profile1PacketType::Uo1Sn { .. } => {
                    self.decompress_as_uo1_sn(context, packet_bytes)
                }
                Profile1PacketType::Uo0 => self.decompress_as_uo0(context, packet_bytes),
                Profile1PacketType::Unknown(val) => {
                    Err(RohcError::Parsing(RohcParsingError::InvalidPacketType {
                        discriminator: val,
                        profile_id: Some(self.profile_id().into()),
                    }))
                }
                Profile1PacketType::IrStatic | Profile1PacketType::IrDynamic => {
                    unreachable!("IR packets should be handled before FC mode dispatch")
                }
            },
            Profile1DecompressorMode::NoContext => {
                unreachable!("NoContext should be handled before general mode dispatch")
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crc;
    use crate::encodings::encode_lsb;
    use crate::packet_defs::RohcProfile;
    use crate::profiles::profile1::packet_processor::{
        build_profile1_ir_packet, build_profile1_uo0_packet, build_profile1_uo1_sn_packet,
        build_profile1_uo1_ts_packet,
    };
    use crate::profiles::profile1::packet_types::{IrPacket, Uo0Packet, Uo1Packet};

    // Helper to setup a context in SO mode for testing decompress_in_so_state.
    fn setup_context_in_so_mode(cid: u16) -> Profile1DecompressorContext {
        let mut ctx = Profile1DecompressorContext::new(cid);
        ctx.mode = Profile1DecompressorMode::SecondOrder;
        ctx.rtp_ssrc = 0x12345678;
        ctx.last_reconstructed_rtp_sn_full = 100;
        ctx.last_reconstructed_rtp_ts_full = 1000;
        ctx.last_reconstructed_rtp_marker = false;
        ctx.last_reconstructed_ip_id_full = 100;
        ctx.expected_lsb_sn_width = P1_UO0_SN_LSB_WIDTH_DEFAULT;
        ctx.so_static_confidence = P1_SO_INITIAL_STATIC_CONFIDENCE;
        ctx.so_dynamic_confidence = P1_SO_INITIAL_DYNAMIC_CONFIDENCE;
        ctx.so_packets_received_in_so = 0;
        ctx.so_consecutive_failures = 0;
        ctx
    }

    // Helper to create a default context and then force it into SC mode
    fn setup_context_in_sc_mode_via_fc_failures(cid: u16) -> Profile1DecompressorContext {
        let handler = Profile1Handler::new();
        let mut ctx = Profile1DecompressorContext::new(cid);

        ctx.mode = Profile1DecompressorMode::FullContext;
        ctx.rtp_ssrc = 0x12345678;
        ctx.last_reconstructed_rtp_sn_full = 50;
        ctx.last_reconstructed_rtp_ts_full = 500;
        ctx.last_reconstructed_rtp_marker = false;
        ctx.last_reconstructed_ip_id_full = 50;
        ctx.expected_lsb_sn_width = P1_UO0_SN_LSB_WIDTH_DEFAULT;
        ctx.consecutive_crc_failures_in_fc = 0;
        ctx.fc_packets_successful_streak = 0;
        ctx.sc_to_nc_k_failures = 0;
        ctx.sc_to_nc_n_window_count = 0;

        let sn_for_fc_fail = ctx.last_reconstructed_rtp_sn_full.wrapping_add(1);
        let good_crc_val = crc::calculate_rohc_crc3(&handler.build_uo_crc_input(
            ctx.rtp_ssrc,
            sn_for_fc_fail,
            ctx.last_reconstructed_rtp_ts_full,
            ctx.last_reconstructed_rtp_marker,
        ));
        let bad_crc = (good_crc_val + 1) & 0x07;

        let uo0_bad_crc_data = Uo0Packet {
            cid: None,
            sn_lsb: encode_lsb(sn_for_fc_fail as u64, P1_UO0_SN_LSB_WIDTH_DEFAULT).unwrap() as u8,
            crc3: bad_crc,
        };
        let uo0_bad_crc_bytes = build_profile1_uo0_packet(&uo0_bad_crc_data).unwrap();

        for i in 0..P1_DECOMPRESSOR_FC_TO_SC_CRC_FAILURE_THRESHOLD {
            let res = handler.decompress_as_uo0(&mut ctx, &uo0_bad_crc_bytes);
            assert!(res.is_err(), "FC UO-0 setup iter {} should fail", i);
        }
        assert_eq!(
            ctx.mode,
            Profile1DecompressorMode::StaticContext,
            "Context should be SC"
        );
        assert_eq!(ctx.sc_to_nc_k_failures, 0, "SC k_failures init");
        assert_eq!(ctx.sc_to_nc_n_window_count, 0, "SC n_window_count init");
        ctx
    }

    #[test]
    fn decompress_rejects_uo0_in_no_context_and_static_context_modes() {
        let handler = Profile1Handler::new();
        let uo0_packet_data = Uo0Packet {
            cid: None,
            sn_lsb: 1,
            crc3: 0,
        };
        let uo0_bytes = build_profile1_uo0_packet(&uo0_packet_data).unwrap();

        let mut nc_ctx_dyn: Box<dyn RohcDecompressorContext> =
            Box::new(Profile1DecompressorContext::new(0));
        let result_nc = handler.decompress(nc_ctx_dyn.as_mut(), &uo0_bytes);
        match result_nc {
            Err(RohcError::InvalidState(msg)) => {
                assert!(
                    msg.contains("Non-IR packet received but decompressor is in NoContext mode.")
                );
            }
            _ => panic!(
                "Expected InvalidState for UO-0 in NoContext, got {:?}",
                result_nc
            ),
        }

        let mut sc_ctx = Profile1DecompressorContext::new(0);
        sc_ctx.mode = Profile1DecompressorMode::StaticContext;
        sc_ctx.rtp_ssrc = 0x12345678;
        let mut sc_ctx_dyn: Box<dyn RohcDecompressorContext> = Box::new(sc_ctx);
        let result_sc = handler.decompress(sc_ctx_dyn.as_mut(), &uo0_bytes);

        assert!(
            matches!(result_sc, Err(RohcError::InvalidState(_))),
            "Expected InvalidState for UO-0 in SC, got {:?}",
            result_sc
        );
        if let Err(RohcError::InvalidState(msg)) = result_sc {
            assert!(msg.contains("UO-0 packet received in StaticContext mode"));
        }
        let final_sc_ctx = sc_ctx_dyn
            .as_any()
            .downcast_ref::<Profile1DecompressorContext>()
            .unwrap();
        assert_eq!(
            final_sc_ctx.sc_to_nc_n_window_count, 1,
            "SC N_window count for UO-0 attempt"
        );
        assert_eq!(
            final_sc_ctx.sc_to_nc_k_failures, 0,
            "SC K_failures not incremented by UO-0 InvalidState"
        );
    }

    #[test]
    fn decompress_in_sc_state_processes_valid_uo1_sn_and_resets_counters() {
        let handler = Profile1Handler::new();
        let mut ctx = setup_context_in_sc_mode_via_fc_failures(0);
        ctx.sc_to_nc_k_failures = 1;
        ctx.sc_to_nc_n_window_count = 2;

        let ssrc = ctx.rtp_ssrc;
        let last_sn = ctx.last_reconstructed_rtp_sn_full;
        let last_ts = ctx.last_reconstructed_rtp_ts_full;
        let next_sn = last_sn.wrapping_add(1);
        let new_marker = true;

        let uo1_sn_data = Uo1Packet {
            cid: None,
            sn_lsb: encode_lsb(next_sn as u64, P1_UO1_SN_LSB_WIDTH_DEFAULT).unwrap() as u16,
            num_sn_lsb_bits: P1_UO1_SN_LSB_WIDTH_DEFAULT,
            marker: new_marker,
            crc8: crc::calculate_rohc_crc8(
                &handler.build_uo_crc_input(ssrc, next_sn, last_ts, new_marker),
            ),
            ..Default::default()
        };
        let packet_bytes = build_profile1_uo1_sn_packet(&uo1_sn_data).unwrap();
        let mut ctx_dyn: Box<dyn RohcDecompressorContext> = Box::new(ctx);

        let result = handler.decompress(ctx_dyn.as_mut(), &packet_bytes);
        assert!(
            result.is_ok(),
            "Valid UO-1-SN in SC should succeed: {:?}",
            result.err()
        );

        let final_ctx = ctx_dyn
            .as_any()
            .downcast_ref::<Profile1DecompressorContext>()
            .unwrap();
        assert_eq!(
            final_ctx.mode,
            Profile1DecompressorMode::StaticContext,
            "Should remain SC"
        );
        assert_eq!(final_ctx.last_reconstructed_rtp_sn_full, next_sn);
        assert!(final_ctx.last_reconstructed_rtp_marker);
        assert_eq!(final_ctx.sc_to_nc_k_failures, 0, "SC k_failures reset");
        assert_eq!(
            final_ctx.sc_to_nc_n_window_count, 0,
            "SC n_window_count reset"
        );
    }

    #[test]
    fn decompress_in_sc_state_triggers_nc_transition_after_k2_failures() {
        let handler = Profile1Handler::new();
        let mut ctx_dyn: Box<dyn RohcDecompressorContext> =
            Box::new(setup_context_in_sc_mode_via_fc_failures(0));

        let uo1_bad_crc_data = Uo1Packet {
            cid: None,
            sn_lsb: 1,
            num_sn_lsb_bits: P1_UO1_SN_LSB_WIDTH_DEFAULT,
            marker: false,
            crc8: 0,
            ..Default::default()
        };
        let packet_bytes_bad_crc = build_profile1_uo1_sn_packet(&uo1_bad_crc_data).unwrap();

        for i in 0..P1_DECOMPRESSOR_SC_TO_NC_K2 {
            let result = handler.decompress(ctx_dyn.as_mut(), &packet_bytes_bad_crc);
            assert!(result.is_err(), "Bad UO-1-SN in SC iter {} should fail", i);
        }

        let final_ctx = ctx_dyn
            .as_any()
            .downcast_ref::<Profile1DecompressorContext>()
            .unwrap();
        assert_eq!(
            final_ctx.mode,
            Profile1DecompressorMode::NoContext,
            "Should transition to NC"
        );
        assert_eq!(final_ctx.sc_to_nc_k_failures, 0);
        assert_eq!(final_ctx.sc_to_nc_n_window_count, 0);
    }

    #[test]
    fn decompress_in_sc_state_resets_n2_window_if_k2_not_met() {
        let handler = Profile1Handler::new();
        let ctx_initial = setup_context_in_sc_mode_via_fc_failures(0);
        let mut ctx_dyn: Box<dyn RohcDecompressorContext> = Box::new(ctx_initial.clone());

        let uo1_bad_crc_data = Uo1Packet {
            cid: None,
            sn_lsb: 1,
            num_sn_lsb_bits: 8,
            marker: false,
            crc8: 0,
            ..Default::default()
        };
        let packet_bytes_bad_crc = build_profile1_uo1_sn_packet(&uo1_bad_crc_data).unwrap();

        let good_uo1_sn_data = Uo1Packet {
            cid: None,
            sn_lsb: encode_lsb(
                (ctx_initial.last_reconstructed_rtp_sn_full + 10) as u64,
                P1_UO1_SN_LSB_WIDTH_DEFAULT,
            )
            .unwrap() as u16,
            num_sn_lsb_bits: P1_UO1_SN_LSB_WIDTH_DEFAULT,
            marker: true,
            crc8: crc::calculate_rohc_crc8(&handler.build_uo_crc_input(
                ctx_initial.rtp_ssrc,
                ctx_initial.last_reconstructed_rtp_sn_full + 10,
                ctx_initial.last_reconstructed_rtp_ts_full,
                true,
            )),
            ..Default::default()
        };
        let packet_bytes_good = build_profile1_uo1_sn_packet(&good_uo1_sn_data).unwrap();

        for _ in 0..(P1_DECOMPRESSOR_SC_TO_NC_K2 - 1) {
            assert!(
                handler
                    .decompress(ctx_dyn.as_mut(), &packet_bytes_bad_crc)
                    .is_err()
            );
        }
        for _ in (P1_DECOMPRESSOR_SC_TO_NC_K2 - 1)..P1_DECOMPRESSOR_SC_TO_NC_N2 {
            assert!(
                handler
                    .decompress(ctx_dyn.as_mut(), &packet_bytes_good)
                    .is_ok()
            );
        }

        let final_ctx = ctx_dyn
            .as_any()
            .downcast_ref::<Profile1DecompressorContext>()
            .unwrap();
        assert_eq!(
            final_ctx.mode,
            Profile1DecompressorMode::StaticContext,
            "Should remain SC"
        );
        assert_eq!(
            final_ctx.sc_to_nc_k_failures, 0,
            "K_failures reset after N2 window"
        );
        assert_eq!(
            final_ctx.sc_to_nc_n_window_count, 0,
            "N_window_count reset after N2 window"
        );
    }

    #[test]
    fn decompress_ir_in_sc_mode_transitions_to_fc() {
        let handler = Profile1Handler::new();
        let ctx_sc = setup_context_in_sc_mode_via_fc_failures(0);
        let mut ctx_dyn: Box<dyn RohcDecompressorContext> = Box::new(ctx_sc.clone());

        let ir_data = IrPacket {
            cid: ctx_sc.cid,
            profile_id: RohcProfile::RtpUdpIp,
            static_rtp_ssrc: ctx_sc.rtp_ssrc.wrapping_add(1),
            dyn_rtp_sn: ctx_sc.last_reconstructed_rtp_sn_full.wrapping_add(100),
            dyn_rtp_timestamp: ctx_sc.last_reconstructed_rtp_ts_full.wrapping_add(1000),
            dyn_rtp_marker: true,
            static_ip_src: ctx_sc.ip_source,
            static_ip_dst: ctx_sc.ip_destination,
            static_udp_src_port: ctx_sc.udp_source_port,
            static_udp_dst_port: ctx_sc.udp_destination_port,
            crc8: 0,
        };
        let ir_packet_bytes = build_profile1_ir_packet(&ir_data).unwrap();

        let result = handler.decompress(ctx_dyn.as_mut(), &ir_packet_bytes);
        assert!(
            result.is_ok(),
            "IR decompression in SC failed: {:?}",
            result.err()
        );

        let final_ctx = ctx_dyn
            .as_any()
            .downcast_ref::<Profile1DecompressorContext>()
            .unwrap();
        assert_eq!(
            final_ctx.mode,
            Profile1DecompressorMode::FullContext,
            "IR in SC should transition to FC"
        );
        assert_eq!(final_ctx.rtp_ssrc, ir_data.static_rtp_ssrc);
        assert_eq!(final_ctx.sc_to_nc_k_failures, 0);
    }

    #[test]
    fn decompress_so_mode_dispatches_uo0_correctly() {
        let handler = Profile1Handler::new();
        let ctx_so_initial = setup_context_in_so_mode(0);
        let mut ctx_dyn: Box<dyn RohcDecompressorContext> = Box::new(ctx_so_initial.clone());

        let next_sn_for_uo0 = ctx_so_initial
            .last_reconstructed_rtp_sn_full
            .wrapping_add(1);
        let sn_lsb = encode_lsb(next_sn_for_uo0 as u64, P1_UO0_SN_LSB_WIDTH_DEFAULT).unwrap() as u8;
        let crc_input = handler.build_uo_crc_input(
            ctx_so_initial.rtp_ssrc,
            next_sn_for_uo0,
            ctx_so_initial.last_reconstructed_rtp_ts_full,
            ctx_so_initial.last_reconstructed_rtp_marker,
        );
        let crc3 = crc::calculate_rohc_crc3(&crc_input);
        let uo0_data = Uo0Packet {
            cid: None,
            sn_lsb,
            crc3,
        };
        let packet_bytes = build_profile1_uo0_packet(&uo0_data).unwrap();

        let result = handler.decompress(ctx_dyn.as_mut(), &packet_bytes);
        assert!(
            result.is_ok(),
            "Decompression in SO for UO-0 failed: {:?}",
            result.err()
        );

        let final_ctx = ctx_dyn
            .as_any()
            .downcast_ref::<Profile1DecompressorContext>()
            .unwrap();
        assert_eq!(
            final_ctx.mode,
            Profile1DecompressorMode::SecondOrder,
            "Should remain SO"
        );
        assert_eq!(
            final_ctx.so_dynamic_confidence,
            P1_SO_INITIAL_DYNAMIC_CONFIDENCE + P1_SO_SUCCESS_CONFIDENCE_BOOST
        );
    }

    #[test]
    fn decompress_fc_mode_dispatches_uo1_ts_correctly() {
        let handler = Profile1Handler::new();
        let mut ctx_fc = Profile1DecompressorContext::new(0);
        ctx_fc.mode = Profile1DecompressorMode::FullContext;
        ctx_fc.rtp_ssrc = 0xABCDEF01;
        ctx_fc.last_reconstructed_rtp_sn_full = 50;
        ctx_fc.last_reconstructed_rtp_ts_full = 5000;
        ctx_fc.last_reconstructed_rtp_marker = true;
        ctx_fc.expected_lsb_ts_width = P1_UO1_TS_LSB_WIDTH_DEFAULT;
        let mut ctx_dyn: Box<dyn RohcDecompressorContext> = Box::new(ctx_fc.clone());

        let expected_sn = 51;
        let new_ts = 5500;
        let ts_lsb = encode_lsb(new_ts as u64, P1_UO1_TS_LSB_WIDTH_DEFAULT).unwrap() as u16;
        let crc_input = handler.build_uo_crc_input(
            ctx_fc.rtp_ssrc,
            expected_sn,
            new_ts,
            ctx_fc.last_reconstructed_rtp_marker,
        );
        let crc8 = crc::calculate_rohc_crc8(&crc_input);
        let uo1_ts_data = Uo1Packet {
            cid: None,
            ts_lsb: Some(ts_lsb),
            num_ts_lsb_bits: Some(P1_UO1_TS_LSB_WIDTH_DEFAULT),
            crc8,
            ..Default::default()
        };
        let packet_bytes = build_profile1_uo1_ts_packet(&uo1_ts_data).unwrap();

        let result = handler.decompress(ctx_dyn.as_mut(), &packet_bytes);
        assert!(
            result.is_ok(),
            "FC Decompression of UO-1-TS failed: {:?}",
            result.err()
        );
        let headers = result.unwrap().as_rtp_udp_ipv4().unwrap().clone();
        assert_eq!(headers.rtp_sequence_number, expected_sn);
        assert_eq!(headers.rtp_timestamp, new_ts);
    }
}
