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
#[derive(Debug, Default)]
pub struct Profile1Handler;

impl Profile1Handler {
    /// Creates a new instance of the `Profile1Handler`.
    pub fn new() -> Self {
        Profile1Handler
    }

    /// Determines if an IR packet must be sent by the compressor.
    ///
    /// An IR packet is forced if: (RFC 3095, Sec 5.5, 5.6, 4.5.1)
    /// - Compressor is in `InitializationAndRefresh` mode.
    /// - IR refresh interval met.
    /// - SSRC change detected.
    /// - Significant SN, TS, or IP-ID jump occurs that might exceed UO LSB encoding capabilities.
    ///
    /// # Parameters
    /// - `context`: Reference to the current `Profile1CompressorContext`.
    /// - `uncompressed_headers`: Reference to the current uncompressed headers.
    ///
    /// # Returns
    /// `true` if an IR packet should be sent, `false` otherwise.
    fn should_force_ir(
        &self,
        context: &Profile1CompressorContext,
        uncompressed_headers: &RtpUdpIpv4Headers,
    ) -> bool {
        if context.mode == Profile1CompressorMode::InitializationAndRefresh {
            // Compressor explicitly set to IR mode (e.g., first packet for CID, or manual reset)
            return true;
        }

        if context.ir_refresh_interval > 0
            && context.fo_packets_sent_since_ir >= context.ir_refresh_interval.saturating_sub(1)
        {
            // IR refresh interval met (RFC 3095, Sec 5.5 - robustness mechanism)
            return true;
        }

        if context.rtp_ssrc != 0 && context.rtp_ssrc != uncompressed_headers.rtp_ssrc {
            // SSRC change mandates a new context initialization (RFC 3095, Sec 5.6)
            return true;
        }

        // Check for LSB insufficiency due to large jumps (RFC 3095, Sec 4.5.1 - W-LSB ambiguity).
        // If a field changes by more than roughly half its LSB encoding range for UO-1 packets,
        // send IR to prevent potential decompressor misinterpretation.

        let sn_k = P1_UO1_SN_LSB_WIDTH_DEFAULT;
        if sn_k > 0 && sn_k < 16 {
            let max_safe_sn_delta: u16 = 1 << (sn_k.saturating_sub(1));
            let current_sn = uncompressed_headers.rtp_sequence_number;
            let diff_sn_abs = current_sn.wrapping_sub(context.last_sent_rtp_sn_full);
            let diff_sn_abs_alt = context.last_sent_rtp_sn_full.wrapping_sub(current_sn);
            if core::cmp::min(diff_sn_abs, diff_sn_abs_alt) > max_safe_sn_delta {
                return true;
            }
        }

        let ts_k = P1_UO1_TS_LSB_WIDTH_DEFAULT;
        if ts_k > 0 && ts_k < 32 {
            let max_safe_ts_delta: u32 = 1 << (ts_k.saturating_sub(1));
            let current_ts = uncompressed_headers.rtp_timestamp;
            let diff_ts_abs = current_ts.wrapping_sub(context.last_sent_rtp_ts_full);
            let diff_ts_abs_alt = context.last_sent_rtp_ts_full.wrapping_sub(current_ts);
            if core::cmp::min(diff_ts_abs, diff_ts_abs_alt) > max_safe_ts_delta {
                return true;
            }
        }

        if uncompressed_headers.ip_identification != context.last_sent_ip_id_full {
            let ipid_k = P1_UO1_IPID_LSB_WIDTH_DEFAULT;
            if ipid_k > 0 && ipid_k < 16 {
                let max_safe_ipid_delta: u16 = 1 << (ipid_k.saturating_sub(1));
                let current_ip_id = uncompressed_headers.ip_identification;
                let diff_ipid_abs = current_ip_id.wrapping_sub(context.last_sent_ip_id_full);
                let diff_ipid_abs_alt = context.last_sent_ip_id_full.wrapping_sub(current_ip_id);
                if core::cmp::min(diff_ipid_abs, diff_ipid_abs_alt) > max_safe_ipid_delta {
                    return true;
                }
            }
        }
        false
    }

    /// Handles compressor logic for sending an IR packet.
    ///
    /// # Parameters
    /// - `context`: Mutable reference to the `Profile1CompressorContext`.
    /// - `uncompressed_headers`: The uncompressed headers.
    ///
    /// # Returns
    /// `Result<Vec<u8>, RohcError>` containing the built IR packet.
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

    /// Handles compressor logic for sending UO packets.
    /// Decides UO type based on field changes relative to context.
    ///
    /// # Parameters
    /// - `context`: Mutable reference to the `Profile1CompressorContext`.
    /// - `uncompressed_headers`: The current uncompressed headers.
    ///
    /// # Returns
    /// `Result<Vec<u8>, RohcError>` containing the built UO packet.
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

        // Determine which UO packet type is most appropriate based on field changes.
        // (RFC 3095, Sec 5.7 provides the detailed rules for packet type selection)
        let final_rohc_packet_bytes = if marker_unchanged
            && sn_encodable_for_uo0
            && !ts_changed_significantly
            && !ip_id_changed
        {
            // UO-0: Minimal changes, SN fits UO-0 LSBs (RFC 3095, 5.7.4)
            self.build_compress_uo0(context, current_sn)?
        } else if marker_unchanged
            && ts_changed_significantly
            && sn_incremented_by_one
            && !ip_id_changed
        {
            // UO-1-TS: Marker, IP-ID same; SN is +1; TS changed (RFC 3095, 5.7.5)
            self.build_compress_uo1_ts(context, current_sn, current_ts)?
        } else if marker_unchanged
            && ip_id_conditions_for_uo1_id
            && sn_incremented_by_one
            && !ts_changed_significantly
        {
            // UO-1-ID: Marker, TS same; SN is +1; IP-ID changed (RFC 3095, 5.7.5)
            self.build_compress_uo1_id(context, current_sn, current_ip_id)?
        } else {
            // UO-1-SN: Fallback for marker changes or larger/irregular SN jumps (RFC 3095, 5.7.5)
            self.build_compress_uo1_sn(context, current_sn, current_marker)?
        };

        context.last_sent_rtp_sn_full = current_sn;
        context.last_sent_rtp_ts_full = current_ts;
        context.last_sent_rtp_marker = current_marker;
        context.last_sent_ip_id_full = current_ip_id;

        // Handle compressor mode transition FO -> SO (RFC 3095, Sec 5.3.2.1)
        if context.mode == Profile1CompressorMode::FirstOrder {
            context.consecutive_fo_packets_sent =
                context.consecutive_fo_packets_sent.saturating_add(1);
            if context.consecutive_fo_packets_sent >= P1_COMPRESSOR_FO_TO_SO_THRESHOLD {
                context.mode = Profile1CompressorMode::SecondOrder;
                context.consecutive_fo_packets_sent = 0; // Reset after transition
            }
        }
        context.fo_packets_sent_since_ir = context.fo_packets_sent_since_ir.saturating_add(1);

        Ok(final_rohc_packet_bytes)
    }

    /// Builds a ROHC Profile 1 UO-0 packet's byte representation.
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
            marker: false, // UO-1-TS implies M=0 in type, actual marker from context for CRC
            ts_lsb: Some(ts_lsb_val),
            num_ts_lsb_bits: Some(P1_UO1_TS_LSB_WIDTH_DEFAULT),
            crc8: calculated_crc8,
            ..Default::default()
        };
        context.current_lsb_ts_width = P1_UO1_TS_LSB_WIDTH_DEFAULT;
        build_profile1_uo1_ts_packet(&uo1_ts_packet_data).map_err(RohcError::Building)
    }

    /// Builds a ROHC Profile 1 UO-1-SN packet's byte representation.
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
            context.last_sent_rtp_ts_full, // TS from context for CRC
            current_marker,                // Marker from current packet
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

    /// Parses an IR packet and updates decompressor context.
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
        context.initialize_from_ir_packet(&parsed_ir);
        Ok(self.reconstruct_full_headers(
            context,
            parsed_ir.dyn_rtp_sn,
            parsed_ir.dyn_rtp_timestamp,
            parsed_ir.dyn_rtp_marker,
            context.last_reconstructed_ip_id_full, // IP-ID not in IR dynamic chain for P1
        ))
    }

    /// Parses a UO-0 packet and updates decompressor context.
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
        let crc_input_bytes = self.build_uo_crc_input(
            context.rtp_ssrc,
            decoded_sn,
            context.last_reconstructed_rtp_ts_full,
            context.last_reconstructed_rtp_marker,
        );
        if crc::calculate_rohc_crc3(&crc_input_bytes) != parsed_uo0.crc3 {
            return Err(RohcError::Parsing(RohcParsingError::CrcMismatch {
                expected: parsed_uo0.crc3,
                calculated: crc::calculate_rohc_crc3(&crc_input_bytes),
                crc_type: "ROHC-CRC3".to_string(),
            }));
        }
        context.last_reconstructed_rtp_sn_full = decoded_sn;
        Ok(self.reconstruct_full_headers(
            context,
            decoded_sn,
            context.last_reconstructed_rtp_ts_full,
            context.last_reconstructed_rtp_marker,
            context.last_reconstructed_ip_id_full,
        ))
    }

    /// Parses a UO-1-SN packet and updates decompressor context.
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
        let crc_input_bytes = self.build_uo_crc_input(
            context.rtp_ssrc,
            decoded_sn,
            context.last_reconstructed_rtp_ts_full, // TS from context for UO-1-SN
            parsed_uo1.marker,                      // Marker from packet
        );
        if crc::calculate_rohc_crc8(&crc_input_bytes) != parsed_uo1.crc8 {
            return Err(RohcError::Parsing(RohcParsingError::CrcMismatch {
                expected: parsed_uo1.crc8,
                calculated: crc::calculate_rohc_crc8(&crc_input_bytes),
                crc_type: "ROHC-CRC8".to_string(),
            }));
        }
        context.last_reconstructed_rtp_sn_full = decoded_sn;
        context.last_reconstructed_rtp_marker = parsed_uo1.marker;
        Ok(self.reconstruct_full_headers(
            context,
            decoded_sn,
            context.last_reconstructed_rtp_ts_full,
            parsed_uo1.marker,
            context.last_reconstructed_ip_id_full,
        ))
    }

    /// Parses a UO-1-TS packet and updates decompressor context.
    fn _parse_and_reconstruct_uo1_ts(
        &self,
        context: &mut Profile1DecompressorContext,
        packet_bytes: &[u8],
    ) -> Result<RtpUdpIpv4Headers, RohcError> {
        let parsed_uo1_ts = parse_profile1_uo1_ts_packet(packet_bytes)?;
        let reconstructed_sn = context.last_reconstructed_rtp_sn_full.wrapping_add(1); // SN is implicit +1
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
            context.last_reconstructed_rtp_marker, // Marker from context
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
            context.last_reconstructed_rtp_marker,
            context.last_reconstructed_ip_id_full,
        ))
    }

    /// Parses a UO-1-ID packet and updates decompressor context.
    fn _parse_and_reconstruct_uo1_id(
        &self,
        context: &mut Profile1DecompressorContext,
        packet_bytes: &[u8],
    ) -> Result<RtpUdpIpv4Headers, RohcError> {
        let parsed_uo1_id = parse_profile1_uo1_id_packet(packet_bytes)?;
        let reconstructed_sn = context.last_reconstructed_rtp_sn_full.wrapping_add(1); // SN is implicit +1
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
            context.last_reconstructed_rtp_ts_full, // TS from context
            context.last_reconstructed_rtp_marker,  // Marker from context
            received_ip_id_lsb_val as u8,           // Use received LSB for CRC
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
            context.last_reconstructed_rtp_ts_full,
            context.last_reconstructed_rtp_marker,
            decoded_ip_id,
        ))
    }

    /// Handles FC state updates after UO packet processing.
    /// Centralizes FC->SO and FC->SC transition logic.
    /// (RFC 3095, Sec 5.3.2.2.2, 5.3.2.2.3)
    fn handle_fc_uo_packet_outcome(
        &self,
        context: &mut Profile1DecompressorContext,
        parse_outcome: Result<RtpUdpIpv4Headers, RohcError>,
    ) -> Result<RtpUdpIpv4Headers, RohcError> {
        debug_assert_eq!(context.mode, Profile1DecompressorMode::FullContext);
        match parse_outcome {
            Ok(reconstructed_headers) => {
                context.consecutive_crc_failures_in_fc = 0;
                context.fc_packets_successful_streak =
                    context.fc_packets_successful_streak.saturating_add(1);
                // Check for FC -> SO transition (RFC 3095, Sec 5.3.2.2.2)
                if context.fc_packets_successful_streak >= P1_DECOMPRESSOR_FC_TO_SO_THRESHOLD_STREAK
                {
                    context.mode = Profile1DecompressorMode::SecondOrder;
                    // Initialize SO confidence values (RFC 3095, Sec 5.3.2.3)
                    context.so_static_confidence = P1_SO_INITIAL_STATIC_CONFIDENCE;
                    context.so_dynamic_confidence = P1_SO_INITIAL_DYNAMIC_CONFIDENCE;
                    context.so_packets_received_in_so = 0;
                    context.so_consecutive_failures = 0;
                    context.fc_packets_successful_streak = 0; // Reset after transition
                }
                Ok(reconstructed_headers)
            }
            Err(e) => {
                context.consecutive_crc_failures_in_fc =
                    context.consecutive_crc_failures_in_fc.saturating_add(1);
                context.fc_packets_successful_streak = 0;
                // Check for FC -> SC transition (RFC 3095, Sec 5.3.2.2.3)
                if context.consecutive_crc_failures_in_fc
                    >= P1_DECOMPRESSOR_FC_TO_SC_CRC_FAILURE_THRESHOLD
                {
                    context.mode = Profile1DecompressorMode::StaticContext;
                    context.sc_to_nc_k_failures = 0; // Reset SC counters upon entering SC
                    context.sc_to_nc_n_window_count = 0;
                }
                Err(e)
            }
        }
    }

    /// Decompresses an IR packet, updates context, and transitions to FullContext.
    /// (RFC 3095, Sec 5.3.2.2)
    fn decompress_as_ir(
        &self,
        context: &mut Profile1DecompressorContext,
        packet_bytes: &[u8],
    ) -> Result<GenericUncompressedHeaders, RohcError> {
        match self._parse_and_reconstruct_ir(context, packet_bytes) {
            Ok(reconstructed_rtp_headers) => {
                context.mode = Profile1DecompressorMode::FullContext;
                // Reset all relevant state transition counters as IR provides a fresh baseline
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

    /// Decompresses UO-0 in FC mode, handling state transitions.
    fn decompress_as_uo0(
        &self,
        context: &mut Profile1DecompressorContext,
        packet_bytes: &[u8],
    ) -> Result<GenericUncompressedHeaders, RohcError> {
        let outcome = self._parse_and_reconstruct_uo0(context, packet_bytes);
        self.handle_fc_uo_packet_outcome(context, outcome)
            .map(GenericUncompressedHeaders::RtpUdpIpv4)
    }

    /// Decompresses UO-1-SN in FC mode, handling state transitions.
    fn decompress_as_uo1_sn(
        &self,
        context: &mut Profile1DecompressorContext,
        packet_bytes: &[u8],
    ) -> Result<GenericUncompressedHeaders, RohcError> {
        let outcome = self._parse_and_reconstruct_uo1_sn(context, packet_bytes);
        self.handle_fc_uo_packet_outcome(context, outcome)
            .map(GenericUncompressedHeaders::RtpUdpIpv4)
    }

    /// Decompresses UO-1-TS in FC mode, handling state transitions.
    fn decompress_as_uo1_ts(
        &self,
        context: &mut Profile1DecompressorContext,
        packet_bytes: &[u8],
    ) -> Result<GenericUncompressedHeaders, RohcError> {
        let outcome = self._parse_and_reconstruct_uo1_ts(context, packet_bytes);
        self.handle_fc_uo_packet_outcome(context, outcome)
            .map(GenericUncompressedHeaders::RtpUdpIpv4)
    }

    /// Decompresses UO-1-ID in FC mode, handling state transitions.
    fn decompress_as_uo1_id(
        &self,
        context: &mut Profile1DecompressorContext,
        packet_bytes: &[u8],
    ) -> Result<GenericUncompressedHeaders, RohcError> {
        let outcome = self._parse_and_reconstruct_uo1_id(context, packet_bytes);
        self.handle_fc_uo_packet_outcome(context, outcome)
            .map(GenericUncompressedHeaders::RtpUdpIpv4)
    }

    /// Checks if decompressor should transition from SO to NC.
    /// (RFC 3095, Sec 5.3.2.3.1)
    fn should_transition_so_to_nc(&self, context: &Profile1DecompressorContext) -> bool {
        if context.so_consecutive_failures >= P1_SO_MAX_CONSECUTIVE_FAILURES {
            return true;
        }
        if context.so_dynamic_confidence < P1_SO_TO_NC_CONFIDENCE_THRESHOLD {
            return true;
        }
        false
    }

    /// Checks if decompressor should transition from SC to NC.
    /// (RFC 3095, Sec 5.3.2.2.3)
    fn should_transition_sc_to_nc(&self, context: &Profile1DecompressorContext) -> bool {
        context.sc_to_nc_k_failures >= P1_DECOMPRESSOR_SC_TO_NC_K2
    }

    /// Handles decompression in Static Context (SC) state.
    /// (RFC 3095, Sec 5.3.2.2.3)
    fn decompress_in_sc_state(
        &self,
        context: &mut Profile1DecompressorContext,
        packet_bytes: &[u8],
        discriminated_type: Profile1PacketType,
    ) -> Result<GenericUncompressedHeaders, RohcError> {
        debug_assert_eq!(context.mode, Profile1DecompressorMode::StaticContext);
        let mut is_failure_of_dynamic_updater_parse = false;
        // In SC mode, decompressor expects IR or UO-1 to potentially resynchronize dynamic context.
        // UO-0 cannot be processed as it relies on fully synchronized dynamic state.
        let parse_reconstruct_result: Result<GenericUncompressedHeaders, RohcError> =
            match discriminated_type {
                Profile1PacketType::Uo1Ts => {
                    let res = self._parse_and_reconstruct_uo1_ts(context, packet_bytes);
                    if res.is_err() {
                        is_failure_of_dynamic_updater_parse = true;
                    }
                    res.map(GenericUncompressedHeaders::RtpUdpIpv4)
                }
                Profile1PacketType::Uo1Id => {
                    let res = self._parse_and_reconstruct_uo1_id(context, packet_bytes);
                    if res.is_err() {
                        is_failure_of_dynamic_updater_parse = true;
                    }
                    res.map(GenericUncompressedHeaders::RtpUdpIpv4)
                }
                Profile1PacketType::Uo1Sn { .. } => {
                    let res = self._parse_and_reconstruct_uo1_sn(context, packet_bytes);
                    if res.is_err() {
                        is_failure_of_dynamic_updater_parse = true;
                    }
                    res.map(GenericUncompressedHeaders::RtpUdpIpv4)
                }
                Profile1PacketType::Uo0 => {
                    // UO-0 received in SC is an error; no dynamic update possible.
                    // This does not count as a K2 failure for SC->NC.
                    is_failure_of_dynamic_updater_parse = false;
                    Err(RohcError::InvalidState(
                    "UO-0 packet received in StaticContext mode; cannot establish dynamic context.".to_string()
                ))
                }
                Profile1PacketType::Unknown(val) => {
                    // An unknown packet type is treated as a failure of a potential updater.
                    is_failure_of_dynamic_updater_parse = true;
                    Err(RohcError::Parsing(RohcParsingError::InvalidPacketType {
                        discriminator: val,
                        profile_id: Some(self.profile_id().into()),
                    }))
                }
                Profile1PacketType::IrStatic | Profile1PacketType::IrDynamic => {
                    // IRs should have been handled by the main `decompress` dispatcher.
                    return Err(RohcError::Internal(
                        "IR packet unexpectedly routed to decompress_in_sc_state.".to_string(),
                    ));
                }
            };

        match parse_reconstruct_result {
            Ok(headers) => {
                // Successfully processed a UO-1 in SC. Reset SC->NC counters.
                // Per RFC, MAY transition to FC. For MVP, conservatively stay SC, await IR for FC.
                context.sc_to_nc_k_failures = 0;
                context.sc_to_nc_n_window_count = 0;
                Ok(headers)
            }
            Err(ref e) => {
                // Any packet processing attempt in SC increments the N2 window counter.
                context.sc_to_nc_n_window_count = context.sc_to_nc_n_window_count.saturating_add(1);
                // Increment K2 failure count only if it was a parse/CRC error of a
                // packet type that *could* have updated dynamic context.
                if is_failure_of_dynamic_updater_parse && !matches!(e, RohcError::InvalidState(_)) {
                    context.sc_to_nc_k_failures = context.sc_to_nc_k_failures.saturating_add(1);
                }
                // Check for SC->NC transition or N2 window reset
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

    /// Handles decompression in Second Order (SO) state.
    /// (RFC 3095, Sec 5.3.2.3)
    fn decompress_in_so_state(
        &self,
        context: &mut Profile1DecompressorContext,
        packet_bytes: &[u8],
        discriminated_type: Profile1PacketType,
    ) -> Result<GenericUncompressedHeaders, RohcError> {
        debug_assert_eq!(context.mode, Profile1DecompressorMode::SecondOrder);
        // In SO mode, decompressor processes UO-0/UO-1 and updates confidence.
        let parse_reconstruct_result: Result<GenericUncompressedHeaders, RohcError> =
            match discriminated_type {
                Profile1PacketType::Uo1Ts => self
                    ._parse_and_reconstruct_uo1_ts(context, packet_bytes)
                    .map(GenericUncompressedHeaders::RtpUdpIpv4),
                Profile1PacketType::Uo1Id => self
                    ._parse_and_reconstruct_uo1_id(context, packet_bytes)
                    .map(GenericUncompressedHeaders::RtpUdpIpv4),
                Profile1PacketType::Uo1Sn { .. } => self
                    ._parse_and_reconstruct_uo1_sn(context, packet_bytes)
                    .map(GenericUncompressedHeaders::RtpUdpIpv4),
                Profile1PacketType::Uo0 => self
                    ._parse_and_reconstruct_uo0(context, packet_bytes)
                    .map(GenericUncompressedHeaders::RtpUdpIpv4),
                Profile1PacketType::Unknown(val) => {
                    Err(RohcError::Parsing(RohcParsingError::InvalidPacketType {
                        discriminator: val,
                        profile_id: Some(self.profile_id().into()),
                    }))
                }
                Profile1PacketType::IrStatic | Profile1PacketType::IrDynamic => {
                    // IRs should have been handled by the main `decompress` dispatcher.
                    return Err(RohcError::Internal(
                        "IR packet unexpectedly routed to decompress_in_so_state.".to_string(),
                    ));
                }
            };

        match parse_reconstruct_result {
            Ok(headers) => {
                // Successful UO in SO: boost dynamic confidence, reset consecutive failures.
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
                // Failed UO in SO: penalize dynamic confidence, increment consecutive failures.
                debug_assert_eq!(context.mode, Profile1DecompressorMode::SecondOrder);
                context.so_dynamic_confidence = context
                    .so_dynamic_confidence
                    .saturating_sub(P1_SO_FAILURE_CONFIDENCE_PENALTY);
                context.so_consecutive_failures = context.so_consecutive_failures.saturating_add(1);
                // Check for SO -> NC transition (RFC 3095, Sec 5.3.2.3.1)
                if self.should_transition_so_to_nc(context) {
                    context.mode = Profile1DecompressorMode::NoContext;
                    context.reset_for_nc_transition();
                }
                Err(e)
            }
        }
    }

    /// Reconstructs full headers from context and decoded dynamic fields.
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
            ip_total_length: 0, // To be filled by upper layers if needed
            ip_identification: ip_id,
            ip_dont_fragment: true, // Common for RTP
            ip_more_fragments: false,
            ip_fragment_offset: 0,
            ip_ttl: DEFAULT_IPV4_TTL,
            ip_protocol: IP_PROTOCOL_UDP,
            ip_checksum: 0,  // To be calculated by sender if needed
            udp_length: 0,   // To be filled by upper layers
            udp_checksum: 0, // Optional
            rtp_version: RTP_VERSION,
            rtp_padding: false,
            rtp_extension: false,
            rtp_csrc_count: 0,
            rtp_payload_type: 0, // Not explicitly carried in most ROHC packets
            rtp_csrc_list: Vec::new(),
        }
    }

    /// Creates byte slice input for UO packet CRC calculation.
    /// Format: SSRC(4), SN(2), TS(4), Marker(1 byte: 0x00 or 0x01).
    fn build_uo_crc_input(&self, context_ssrc: u32, sn: u16, ts: u32, marker: bool) -> Vec<u8> {
        let mut crc_input = Vec::with_capacity(P1_UO_CRC_INPUT_LENGTH_BYTES);
        crc_input.extend_from_slice(&context_ssrc.to_be_bytes());
        crc_input.extend_from_slice(&sn.to_be_bytes());
        crc_input.extend_from_slice(&ts.to_be_bytes());
        crc_input.push(if marker { 0x01 } else { 0x00 });
        crc_input
    }

    /// Creates byte slice input for UO-1-ID packet CRC calculation.
    /// Format: SSRC(4), SN(2), TS(4), Marker(1), IP-ID LSB(1 for 8-bit width).
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
}

impl ProfileHandler for Profile1Handler {
    fn profile_id(&self) -> RohcProfile {
        RohcProfile::RtpUdpIp
    }

    fn create_compressor_context(
        &self,
        cid: u16,
        ir_refresh_interval: u32,
    ) -> Box<dyn RohcCompressorContext> {
        Box::new(Profile1CompressorContext::new(cid, ir_refresh_interval))
    }

    fn create_decompressor_context(&self, cid: u16) -> Box<dyn RohcDecompressorContext> {
        Box::new(Profile1DecompressorContext::new(cid))
    }

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

        // If SSRC changes, force context re-initialization which sets mode to IR
        if context.rtp_ssrc != 0 && context.rtp_ssrc != uncompressed_headers.rtp_ssrc {
            context.initialize_context_from_uncompressed_headers(uncompressed_headers);
        }

        // Determine if an IR packet is needed based on mode, SSRC, refresh, or LSB issues
        if self.should_force_ir(context, uncompressed_headers) {
            self.compress_as_ir(context, uncompressed_headers)
        } else {
            self.compress_as_uo(context, uncompressed_headers)
        }
    }

    /// Decompresses a ROHC Profile 1 packet.
    /// (Main dispatch logic based on RFC 3095, Sec 5.3.2.2)
    ///
    /// # Parameters
    /// - `context_dyn`: Mutable reference to a `RohcDecompressorContext`.
    /// - `packet_bytes`: Slice containing the core ROHC Profile 1 packet data.
    ///
    /// # Returns
    /// `Result<GenericUncompressedHeaders, RohcError>`.
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

        // State: NoContext (NC) - RFC 3095, 5.3.2.2.1
        // Only IR packets are accepted in NoContext mode.
        if context.mode == Profile1DecompressorMode::NoContext {
            return if discriminated_type.is_ir() {
                self.decompress_as_ir(context, packet_bytes)
            } else {
                Err(RohcError::InvalidState(
                    "Non-IR packet received but decompressor is in NoContext mode.".to_string(),
                ))
            };
        }

        // If an IR packet is received in SC, FC, or SO mode, it refreshes the context to FC.
        // (RFC 3095, 5.3.2.2.2 for FC/SC, 5.3.2.3 for SO)
        if discriminated_type.is_ir() {
            return self.decompress_as_ir(context, packet_bytes);
        }

        // Dispatch to mode-specific handlers for non-IR packets
        match context.mode {
            Profile1DecompressorMode::FullContext => {
                // RFC 3095, 5.3.2.2.2
                match discriminated_type {
                    Profile1PacketType::Uo0 => self.decompress_as_uo0(context, packet_bytes),
                    Profile1PacketType::Uo1Sn { .. } => {
                        self.decompress_as_uo1_sn(context, packet_bytes)
                    }
                    Profile1PacketType::Uo1Ts => self.decompress_as_uo1_ts(context, packet_bytes),
                    Profile1PacketType::Uo1Id => self.decompress_as_uo1_id(context, packet_bytes),
                    Profile1PacketType::Unknown(val) => {
                        Err(RohcError::Parsing(RohcParsingError::InvalidPacketType {
                            discriminator: val,
                            profile_id: Some(self.profile_id().into()),
                        }))
                    }
                    // IRStatic and IrDynamic are already handled by the `is_ir()` check above.
                    // This arm should ideally be unreachable for IR types.
                    _ => unreachable!(
                        "IR types should have been handled before FC mode dispatch for non-IR packets"
                    ),
                }
            }
            Profile1DecompressorMode::StaticContext => {
                // RFC 3095, 5.3.2.2.3
                self.decompress_in_sc_state(context, packet_bytes, discriminated_type)
            }
            Profile1DecompressorMode::SecondOrder => {
                // RFC 3095, 5.3.2.3
                // SO mode primarily processes UO-0 and UO-1 packets.
                if discriminated_type.is_uo0() || discriminated_type.is_uo1() {
                    self.decompress_in_so_state(context, packet_bytes, discriminated_type)
                } else {
                    // An unknown packet type in SO state is unexpected. Route to SO handler which will treat as error.
                    self.decompress_in_so_state(context, packet_bytes, discriminated_type)
                }
            }
            Profile1DecompressorMode::NoContext => {
                // This case should have been handled by the initial check.
                unreachable!(
                    "NoContext state should have been handled at the beginning of the function"
                )
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crc;
    use crate::encodings::encode_lsb;
    use crate::profiles::profile1::packet_processor::build_profile1_uo0_packet;
    use crate::profiles::profile1::packet_types::Uo0Packet;

    fn create_test_rtp_headers(sn: u16, ts: u32, marker: bool) -> RtpUdpIpv4Headers {
        RtpUdpIpv4Headers {
            ip_src: "192.168.0.1".parse().unwrap(),
            ip_dst: "192.168.0.2".parse().unwrap(),
            udp_src_port: 10000,
            udp_dst_port: 20000,
            rtp_ssrc: 0x12345678,
            rtp_sequence_number: sn,
            rtp_timestamp: ts,
            rtp_marker: marker,
            ip_identification: sn % 256,
            ..Default::default()
        }
    }

    #[allow(dead_code)] // Allowed for test helper not used in all test configs
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

    #[allow(dead_code)] // Allowed for test helper not used in all test configs
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
    fn ir_compression_and_decompression_flow() {
        let handler = Profile1Handler::new();
        let mut comp_ctx_dyn = handler.create_compressor_context(0, 5);
        let mut decomp_ctx_dyn = handler.create_decompressor_context(0);
        let headers1 = create_test_rtp_headers(100, 1000, false);
        let generic_headers1 = GenericUncompressedHeaders::RtpUdpIpv4(headers1.clone());
        let compressed_ir = handler
            .compress(comp_ctx_dyn.as_mut(), &generic_headers1)
            .unwrap();
        assert!(!compressed_ir.is_empty());
        assert_eq!(compressed_ir[0], P1_ROHC_IR_PACKET_TYPE_WITH_DYN);
        let decompressed_generic1 = handler
            .decompress(decomp_ctx_dyn.as_mut(), &compressed_ir)
            .unwrap();
        let decomp_headers1 = match decompressed_generic1 {
            GenericUncompressedHeaders::RtpUdpIpv4(h) => h,
            _ => panic!("Wrong enum variant"),
        };
        assert_eq!(decomp_headers1.rtp_ssrc, headers1.rtp_ssrc);
        assert_eq!(
            decomp_headers1.rtp_sequence_number,
            headers1.rtp_sequence_number
        );
        let comp_ctx = comp_ctx_dyn
            .as_any()
            .downcast_ref::<Profile1CompressorContext>()
            .unwrap();
        assert_eq!(comp_ctx.mode, Profile1CompressorMode::FirstOrder);
        let decomp_ctx = decomp_ctx_dyn
            .as_any()
            .downcast_ref::<Profile1DecompressorContext>()
            .unwrap();
        assert_eq!(decomp_ctx.mode, Profile1DecompressorMode::FullContext);
    }

    #[test]
    fn uo0_compression_and_decompression_flow_in_fc() {
        let handler = Profile1Handler::new();
        let mut comp_ctx_dyn = handler.create_compressor_context(0, 5);
        let mut decomp_ctx_dyn = handler.create_decompressor_context(0);
        let headers_ir = create_test_rtp_headers(100, 1000, false);
        let generic_headers_ir = GenericUncompressedHeaders::RtpUdpIpv4(headers_ir.clone());
        let compressed_ir = handler
            .compress(comp_ctx_dyn.as_mut(), &generic_headers_ir)
            .unwrap();
        handler
            .decompress(decomp_ctx_dyn.as_mut(), &compressed_ir)
            .unwrap(); // Establish FC
        let mut headers_uo0 = create_test_rtp_headers(101, 1000, false);
        headers_uo0.ip_identification = headers_ir.ip_identification; // For UO-0, IP-ID must be same
        let generic_headers_uo0 = GenericUncompressedHeaders::RtpUdpIpv4(headers_uo0.clone());
        let compressed_uo0 = handler
            .compress(comp_ctx_dyn.as_mut(), &generic_headers_uo0)
            .unwrap();
        let decompressed_generic_uo0 = handler
            .decompress(decomp_ctx_dyn.as_mut(), &compressed_uo0)
            .unwrap();
        match decompressed_generic_uo0 {
            GenericUncompressedHeaders::RtpUdpIpv4(h) => {
                assert_eq!(h.rtp_sequence_number, 101);
                assert_eq!(h.rtp_timestamp, 1000); // From context
            }
            _ => panic!("Wrong enum variant"),
        }
    }

    #[test]
    fn fc_to_so_transition_on_successful_uo_streak() {
        let handler = Profile1Handler::new();
        let mut ctx = Profile1DecompressorContext::new(0);
        ctx.mode = Profile1DecompressorMode::FullContext; // Start in FC
        ctx.rtp_ssrc = 0x12345678;
        ctx.last_reconstructed_rtp_ts_full = 1000;
        ctx.last_reconstructed_rtp_marker = false;
        ctx.expected_lsb_sn_width = P1_UO0_SN_LSB_WIDTH_DEFAULT;
        let mut current_sn = 100u16;
        ctx.last_reconstructed_rtp_sn_full = current_sn;
        let mut ctx_dyn: Box<dyn RohcDecompressorContext> = Box::new(ctx);

        for i in 0..P1_DECOMPRESSOR_FC_TO_SO_THRESHOLD_STREAK {
            current_sn = current_sn.wrapping_add(1);
            let sn_lsb = encode_lsb(current_sn as u64, P1_UO0_SN_LSB_WIDTH_DEFAULT).unwrap() as u8;
            let crc_input = handler.build_uo_crc_input(
                ctx_dyn
                    .as_any()
                    .downcast_ref::<Profile1DecompressorContext>()
                    .unwrap()
                    .rtp_ssrc,
                current_sn,
                ctx_dyn
                    .as_any()
                    .downcast_ref::<Profile1DecompressorContext>()
                    .unwrap()
                    .last_reconstructed_rtp_ts_full,
                ctx_dyn
                    .as_any()
                    .downcast_ref::<Profile1DecompressorContext>()
                    .unwrap()
                    .last_reconstructed_rtp_marker,
            );
            let crc3 = crc::calculate_rohc_crc3(&crc_input);
            let uo0_data = Uo0Packet {
                cid: None,
                sn_lsb,
                crc3,
            };
            let uo0_bytes = build_profile1_uo0_packet(&uo0_data).unwrap();

            // Use main decompress for stateful testing
            let result = handler.decompress(ctx_dyn.as_mut(), &uo0_bytes);
            assert!(
                result.is_ok(),
                "UO-0 decompression in FC failed at iter {}",
                i
            );

            let current_ctx = ctx_dyn
                .as_any()
                .downcast_ref::<Profile1DecompressorContext>()
                .unwrap();
            if i < P1_DECOMPRESSOR_FC_TO_SO_THRESHOLD_STREAK - 1 {
                assert_eq!(current_ctx.mode, Profile1DecompressorMode::FullContext);
                assert_eq!(current_ctx.fc_packets_successful_streak, i + 1);
            }
        }
        let final_ctx = ctx_dyn
            .as_any()
            .downcast_ref::<Profile1DecompressorContext>()
            .unwrap();
        assert_eq!(final_ctx.mode, Profile1DecompressorMode::SecondOrder);
        assert_eq!(
            final_ctx.so_static_confidence,
            P1_SO_INITIAL_STATIC_CONFIDENCE
        );
        assert_eq!(
            final_ctx.so_dynamic_confidence,
            P1_SO_INITIAL_DYNAMIC_CONFIDENCE
        );
        assert_eq!(final_ctx.fc_packets_successful_streak, 0);
    }
}
