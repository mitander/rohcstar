//! ROHC (Robust Header Compression) Profile 1 (RTP/UDP/IP) handler implementation.
//!
//! This module provides the concrete implementation of the `ProfileHandler` trait
//! for ROHC Profile 1. It orchestrates the compression and decompression of
//! RTP/UDP/IPv4 packet headers according to the rules specified in RFC 3095.

use std::time::Instant;

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
use super::protocol_types::{RtpUdpIpv4Headers, Timestamp};
use crate::constants::{DEFAULT_IPV4_TTL, IP_PROTOCOL_UDP, IPV4_STANDARD_IHL, RTP_VERSION};
use crate::crc::CrcCalculators;
use crate::encodings::{decode_lsb, encode_lsb};
use crate::error::{RohcError, RohcParsingError};
use crate::packet_defs::{GenericUncompressedHeaders, RohcProfile};
use crate::traits::{ProfileHandler, RohcCompressorContext, RohcDecompressorContext};

/// Implements the ROHC Profile 1 (RTP/UDP/IP) compression and decompression logic.
#[derive(Debug, Default)]
pub struct Profile1Handler {
    /// Reusable CRC calculator instances to optimize performance.
    crc_calculators: CrcCalculators,
}

impl Profile1Handler {
    /// Creates a new instance of the `Profile1Handler`.
    pub fn new() -> Self {
        Profile1Handler {
            crc_calculators: CrcCalculators::new(),
        }
    }

    /// Determines if an IR packet must be sent by the compressor.
    ///
    /// An IR packet is forced if:
    /// - Compressor is in `InitializationAndRefresh` mode.
    /// - IR refresh interval is met.
    /// - SSRC change is detected.
    /// - Significant SN, TS, or IP-ID jump occurs that might exceed UO LSB encoding capabilities.
    ///
    /// # Parameters
    /// * `context` - Reference to the current `Profile1CompressorContext`.
    /// * `uncompressed_headers` - Reference to the current uncompressed headers.
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

        let sn_k = P1_UO1_SN_LSB_WIDTH_DEFAULT; // Assumes UO-1 is the general case for LSB limits
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
            // Max bits for u32 timestamp
            let max_safe_ts_delta: u32 = 1 << (ts_k.saturating_sub(1));
            let current_ts_val = uncompressed_headers.rtp_timestamp.value();
            let last_ts_val = context.last_sent_rtp_ts_full.value();
            let diff_ts_abs = current_ts_val.wrapping_sub(last_ts_val);
            let diff_ts_abs_alt = last_ts_val.wrapping_sub(current_ts_val);
            if core::cmp::min(diff_ts_abs, diff_ts_abs_alt) > max_safe_ts_delta {
                return true;
            }
        }

        if uncompressed_headers.ip_identification != context.last_sent_ip_id_full {
            let ipid_k = P1_UO1_IPID_LSB_WIDTH_DEFAULT;
            if ipid_k > 0 && ipid_k < 16 {
                // Max bits for u16 IP-ID
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
    /// Updates the compressor context with the current packet's dynamic fields
    /// and transitions the mode to `FirstOrder`.
    ///
    /// # Parameters
    /// * `context` - Mutable reference to the `Profile1CompressorContext`.
    /// * `uncompressed_headers` - The uncompressed headers for the current packet.
    ///
    /// # Returns
    /// `Result<Vec<u8>, RohcError>` containing the built IR packet bytes.
    fn compress_as_ir(
        &self,
        context: &mut Profile1CompressorContext,
        uncompressed_headers: &RtpUdpIpv4Headers,
    ) -> Result<Vec<u8>, RohcError> {
        // If SSRC changed or context is new, reinitialize static parts from current headers
        if context.mode == Profile1CompressorMode::InitializationAndRefresh
            || context.rtp_ssrc == 0 // Indicates context not yet fully initialized
            || context.rtp_ssrc != uncompressed_headers.rtp_ssrc
        {
            context.initialize_context_from_uncompressed_headers(uncompressed_headers);
        }
        // For other IR triggers (refresh, LSB issues), use existing static context, update dynamic.

        let ir_data = IrPacket {
            cid: context.cid,
            profile_id: self.profile_id(),
            crc8: 0,                          // Will be calculated by builder
            static_ip_src: context.ip_source, // Use established static context
            static_ip_dst: context.ip_destination,
            static_udp_src_port: context.udp_source_port,
            static_udp_dst_port: context.udp_destination_port,
            static_rtp_ssrc: context.rtp_ssrc,
            dyn_rtp_sn: uncompressed_headers.rtp_sequence_number,
            dyn_rtp_timestamp: uncompressed_headers.rtp_timestamp,
            dyn_rtp_marker: uncompressed_headers.rtp_marker,
            // ts_stride field will be added in Commit 5 for IR-DYN extension.
        };

        let rohc_packet_bytes = build_profile1_ir_packet(&ir_data, &self.crc_calculators)
            .map_err(RohcError::Building)?;

        // Update context with dynamic fields of the sent IR packet
        context.last_sent_rtp_sn_full = uncompressed_headers.rtp_sequence_number;
        context.last_sent_rtp_ts_full = uncompressed_headers.rtp_timestamp;
        context.last_sent_rtp_marker = uncompressed_headers.rtp_marker;
        context.last_sent_ip_id_full = uncompressed_headers.ip_identification;

        context.mode = Profile1CompressorMode::FirstOrder;
        context.fo_packets_sent_since_ir = 0;
        context.consecutive_fo_packets_sent = 0;

        // TS Stride detection state should be reset by initialize_context or after sending IR,
        // as IR implies a full context refresh which might change stride behavior.
        // This is handled by initialize_context_from_uncompressed_headers if SSRC changes,
        // or should be done explicitly here if IR is for other reasons.
        // For now, initialize_context covers the main reset case.
        // If an IR is sent just for refresh, existing stride detection state *could* persist if desired,
        // but resetting is safer.
        context.ts_stride = None;
        context.ts_offset = Timestamp::new(0);
        context.ts_stride_packets = 0;
        context.ts_scaled_mode = false;

        Ok(rohc_packet_bytes)
    }

    /// Handles compressor logic for sending UO (Unidirectional Optimistic) packets.
    ///
    /// Selects the most appropriate UO packet type (UO-0, UO-1-SN, UO-1-TS, UO-1-ID,
    /// or future UO-1-RTP) based on changes in header fields relative to the context.
    /// Updates TS stride detection and relevant context fields after packet selection.
    ///
    /// # Parameters
    /// * `context` - Mutable reference to the `Profile1CompressorContext`.
    /// * `uncompressed_headers` - The uncompressed headers for the current packet.
    ///
    /// # Returns
    /// `Result<Vec<u8>, RohcError>` containing the built UO packet bytes.
    fn compress_as_uo(
        &self,
        context: &mut Profile1CompressorContext,
        uncompressed_headers: &RtpUdpIpv4Headers,
    ) -> Result<Vec<u8>, RohcError> {
        let current_sn = uncompressed_headers.rtp_sequence_number;
        let current_ts = uncompressed_headers.rtp_timestamp; // Is Timestamp type
        let current_marker = uncompressed_headers.rtp_marker;
        let current_ip_id = uncompressed_headers.ip_identification;

        // Update TS stride detection state based on the current packet's timestamp.
        // This must be done *before* `last_sent_rtp_ts_full` is updated with `current_ts`.
        context.update_ts_stride_detection(current_ts);

        let marker_unchanged = current_marker == context.last_sent_rtp_marker;
        let sn_diff = current_sn.wrapping_sub(context.last_sent_rtp_sn_full);
        let sn_encodable_for_uo0 = sn_diff > 0 && sn_diff < 16; // For UO-0 (4-bit LSB for SN)
        let ts_changed_significantly = current_ts != context.last_sent_rtp_ts_full;
        let sn_incremented_by_one = current_sn == context.last_sent_rtp_sn_full.wrapping_add(1);
        let ip_id_changed = current_ip_id != context.last_sent_ip_id_full;
        // UO-1-ID is chosen if IP-ID changes and it's not a large jump (already handled by should_force_ir).
        // Here, simple change detection suffices for selection among UO types.
        let ip_id_conditions_for_uo1_id = ip_id_changed; // Width check is implicit in LSB encoding

        // Attempt to calculate TS_SCALED if conditions are met
        // (UO-1-RTP needs SN+1, IP-ID unchanged, Marker can change)
        let maybe_ts_scaled = if context.ts_scaled_mode && sn_incremented_by_one && !ip_id_changed {
            context.calculate_ts_scaled(current_ts)
        } else {
            None
        };

        let final_rohc_packet_bytes = if marker_unchanged
            && sn_encodable_for_uo0
            && !ts_changed_significantly
            && !ip_id_changed
        {
            // UO-0: Minimal changes (SN fits, TS same, Marker same, IP-ID same)
            self.build_compress_uo0(context, current_sn)?
        } else if let Some(_ts_scaled_val) = maybe_ts_scaled {
            // UO-1-RTP: (Logic for building UO-1-RTP will be added in Commit 4)
            // For Commit 1, this branch is not fully utilized yet. Fall through.
            // Placeholder: Fallback to UO-1-TS or UO-1-SN if TS_SCALED is intended but not built.
            // This fallback logic will be refined when UO-1-RTP builder is added.
            // If it falls through here, it means UO-1-RTP was possible but not chosen yet.
            // The existing UO-1-TS / UO-1-ID / UO-1-SN selection will take precedence.
            // This is fine for now as TS_STRIDE isn't fully integrated.
            // Once UO-1-RTP is available, it will be the preferred option here.
            // For now, simulate fallback for type consistency in return.
            if marker_unchanged
                && ts_changed_significantly
                && sn_incremented_by_one
                && !ip_id_changed
            {
                self.build_compress_uo1_ts(context, current_sn, current_ts)?
            } else {
                self.build_compress_uo1_sn(context, current_sn, current_marker)?
            }
        } else if marker_unchanged
            && ts_changed_significantly
            && sn_incremented_by_one
            && !ip_id_changed
        {
            // UO-1-TS: Marker same, IP-ID same; SN is +1; TS changed significantly.
            self.build_compress_uo1_ts(context, current_sn, current_ts)?
        } else if marker_unchanged
            && ip_id_conditions_for_uo1_id // IP-ID changed
            && sn_incremented_by_one
            && !ts_changed_significantly
        // TS must be same for UO-1-ID
        {
            // UO-1-ID: Marker same, TS same; SN is +1; IP-ID changed.
            self.build_compress_uo1_id(context, current_sn, current_ip_id)?
        } else {
            // UO-1-SN: Fallback for other cases like marker changes, larger SN jumps,
            // or combined changes not fitting specific UO-1 variants.
            self.build_compress_uo1_sn(context, current_sn, current_marker)?
        };

        // Update context with dynamic fields of the sent packet
        context.last_sent_rtp_sn_full = current_sn;
        context.last_sent_rtp_ts_full = current_ts;
        context.last_sent_rtp_marker = current_marker;
        context.last_sent_ip_id_full = current_ip_id;

        // Handle compressor mode transition FO -> SO
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
            context.last_sent_rtp_ts_full, // TS for CRC is from context (unchanged for UO-0)
            context.last_sent_rtp_marker,  // Marker for CRC is from context (unchanged for UO-0)
        );
        let crc3_val = self.crc_calculators.calculate_rohc_crc3(&crc_input_bytes);
        let uo0_data = Uo0Packet {
            cid: context.get_small_cid_for_packet(),
            sn_lsb: sn_lsb_val,
            crc3: crc3_val,
        };
        context.current_lsb_sn_width = P1_UO0_SN_LSB_WIDTH_DEFAULT; // Update LSB width context
        build_profile1_uo0_packet(&uo0_data).map_err(RohcError::Building)
    }

    /// Builds a ROHC Profile 1 UO-1-TS packet's byte representation.
    fn build_compress_uo1_ts(
        &self,
        context: &mut Profile1CompressorContext,
        current_sn: u16,
        current_ts: Timestamp, // Expects Timestamp directly
    ) -> Result<Vec<u8>, RohcError> {
        let ts_lsb_val = encode_lsb(current_ts.value() as u64, P1_UO1_TS_LSB_WIDTH_DEFAULT)? as u16;
        let crc_input_bytes = self.build_uo_crc_input(
            context.rtp_ssrc,
            current_sn,                   // SN for CRC uses current SN
            current_ts,                   // TS for CRC uses current TS
            context.last_sent_rtp_marker, // Marker for CRC uses context (unchanged for UO-1-TS)
        );
        let calculated_crc8 = self.crc_calculators.calculate_rohc_crc8(&crc_input_bytes);
        let uo1_ts_packet_data = Uo1Packet {
            cid: context.get_small_cid_for_packet(),
            marker: false, // UO-1-TS type octet implies M=0, marker bit for CRC is from context
            ts_lsb: Some(ts_lsb_val),
            num_ts_lsb_bits: Some(P1_UO1_TS_LSB_WIDTH_DEFAULT),
            crc8: calculated_crc8,
            ..Default::default() // Other fields like sn_lsb are not for UO-1-TS
        };
        context.current_lsb_ts_width = P1_UO1_TS_LSB_WIDTH_DEFAULT; // Update LSB width context
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
            current_sn,                    // SN for CRC uses current SN
            context.last_sent_rtp_ts_full, // TS for CRC uses context (unchanged for UO-1-SN)
            current_marker,                // Marker for CRC uses current marker
        );
        let calculated_crc8 = self.crc_calculators.calculate_rohc_crc8(&crc_input_bytes);
        let uo1_sn_data = Uo1Packet {
            cid: context.get_small_cid_for_packet(),
            sn_lsb: sn_lsb_val,
            num_sn_lsb_bits: P1_UO1_SN_LSB_WIDTH_DEFAULT,
            marker: current_marker,
            crc8: calculated_crc8,
            ..Default::default() // Other fields not for UO-1-SN
        };
        context.current_lsb_sn_width = P1_UO1_SN_LSB_WIDTH_DEFAULT; // Update LSB width context
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
            current_sn, // SN for CRC uses current SN (which is SN_ref + 1)
            context.last_sent_rtp_ts_full, // TS for CRC uses context (unchanged for UO-1-ID)
            context.last_sent_rtp_marker, // Marker for CRC uses context (unchanged for UO-1-ID)
            ip_id_lsb_for_packet_field, // Use the LSB of IP-ID to be sent for CRC
        );
        let calculated_crc8 = self.crc_calculators.calculate_rohc_crc8(&crc_input_bytes);
        let uo1_id_packet_data = Uo1Packet {
            cid: context.get_small_cid_for_packet(),
            ip_id_lsb: Some(ip_id_lsb_for_packet_field as u16),
            num_ip_id_lsb_bits: Some(P1_UO1_IPID_LSB_WIDTH_DEFAULT),
            crc8: calculated_crc8,
            ..Default::default() // Other fields not for UO-1-ID
        };
        // context.current_lsb_ip_id_width is already P1_UO1_IPID_LSB_WIDTH_DEFAULT by default.
        build_profile1_uo1_id_packet(&uo1_id_packet_data).map_err(RohcError::Building)
    }

    /// Parses an IR packet, updates decompressor context. Used internally.
    fn _parse_and_reconstruct_ir(
        &self,
        context: &mut Profile1DecompressorContext,
        packet_bytes: &[u8],
    ) -> Result<RtpUdpIpv4Headers, RohcError> {
        let parsed_ir =
            parse_profile1_ir_packet(packet_bytes, context.cid(), &self.crc_calculators)?;
        if parsed_ir.profile_id != self.profile_id() {
            return Err(RohcError::Parsing(RohcParsingError::InvalidProfileId(
                parsed_ir.profile_id.into(),
            )));
        }
        context.initialize_from_ir_packet(&parsed_ir);
        // For IR, IP-ID context is reset/defaulted as it's not in P1 IR dynamic chain.
        // The `last_reconstructed_ip_id_full` in context is used here.
        Ok(self.reconstruct_full_headers(
            context,
            parsed_ir.dyn_rtp_sn,
            parsed_ir.dyn_rtp_timestamp, // Is Timestamp from IrPacket
            parsed_ir.dyn_rtp_marker,
            context.last_reconstructed_ip_id_full,
        ))
    }

    /// Parses a UO-0 packet, updates decompressor context. Used internally.
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
            context.expected_lsb_sn_width, // Should be P1_UO0_SN_LSB_WIDTH_DEFAULT after IR/FC
            context.p_sn,
        )? as u16;

        let crc_input_bytes = self.build_uo_crc_input(
            context.rtp_ssrc,
            decoded_sn,
            context.last_reconstructed_rtp_ts_full, // Pass Timestamp
            context.last_reconstructed_rtp_marker,
        );
        let calculated_crc3 = self.crc_calculators.calculate_rohc_crc3(&crc_input_bytes);
        if calculated_crc3 != parsed_uo0.crc3 {
            return Err(RohcError::Parsing(RohcParsingError::CrcMismatch {
                expected: parsed_uo0.crc3,
                calculated: calculated_crc3,
                crc_type: "ROHC-CRC3".to_string(),
            }));
        }
        context.last_reconstructed_rtp_sn_full = decoded_sn;
        // For UO-0, TS and Marker are unchanged from context.
        // Infer stride based on unchanged TS (effectively diff = 0 if called).
        context.infer_ts_stride_from_decompressed_ts(context.last_reconstructed_rtp_ts_full);

        Ok(self.reconstruct_full_headers(
            context,
            decoded_sn,
            context.last_reconstructed_rtp_ts_full, // Pass Timestamp
            context.last_reconstructed_rtp_marker,
            context.last_reconstructed_ip_id_full, // IP-ID from context for UO-0
        ))
    }

    /// Parses a UO-1-SN packet, updates decompressor context. Used internally.
    fn _parse_and_reconstruct_uo1_sn(
        &self,
        context: &mut Profile1DecompressorContext,
        packet_bytes: &[u8],
    ) -> Result<RtpUdpIpv4Headers, RohcError> {
        let parsed_uo1 = parse_profile1_uo1_sn_packet(packet_bytes)?;
        let decoded_sn = decode_lsb(
            parsed_uo1.sn_lsb as u64,
            context.last_reconstructed_rtp_sn_full as u64,
            parsed_uo1.num_sn_lsb_bits, // UO-1-SN uses 8-bit LSB width by default
            context.p_sn,
        )? as u16;

        let crc_input_bytes = self.build_uo_crc_input(
            context.rtp_ssrc,
            decoded_sn,
            context.last_reconstructed_rtp_ts_full, // TS for CRC is from context
            parsed_uo1.marker,                      // Marker for CRC is from packet
        );
        let calculated_crc8 = self.crc_calculators.calculate_rohc_crc8(&crc_input_bytes);
        if calculated_crc8 != parsed_uo1.crc8 {
            return Err(RohcError::Parsing(RohcParsingError::CrcMismatch {
                expected: parsed_uo1.crc8,
                calculated: calculated_crc8,
                crc_type: "ROHC-CRC8".to_string(),
            }));
        }
        context.last_reconstructed_rtp_sn_full = decoded_sn;
        context.last_reconstructed_rtp_marker = parsed_uo1.marker;
        // For UO-1-SN, TS is unchanged from context.
        context.infer_ts_stride_from_decompressed_ts(context.last_reconstructed_rtp_ts_full);

        Ok(self.reconstruct_full_headers(
            context,
            decoded_sn,
            context.last_reconstructed_rtp_ts_full, // Pass Timestamp
            parsed_uo1.marker,
            context.last_reconstructed_ip_id_full, // IP-ID from context for UO-1-SN
        ))
    }

    /// Parses a UO-1-TS packet, updates decompressor context. Used internally.
    fn _parse_and_reconstruct_uo1_ts(
        &self,
        context: &mut Profile1DecompressorContext,
        packet_bytes: &[u8],
    ) -> Result<RtpUdpIpv4Headers, RohcError> {
        let parsed_uo1_ts = parse_profile1_uo1_ts_packet(packet_bytes)?;
        let reconstructed_sn = context.last_reconstructed_rtp_sn_full.wrapping_add(1); // SN is implicit +1
        let decoded_ts_val = decode_lsb(
            parsed_uo1_ts.ts_lsb.unwrap_or(0) as u64, // UO-1-TS carries TS LSBs
            context.last_reconstructed_rtp_ts_full.value() as u64, // Use .value()
            parsed_uo1_ts
                .num_ts_lsb_bits
                .unwrap_or(P1_UO1_TS_LSB_WIDTH_DEFAULT),
            context.p_ts,
        )? as u32;
        let decoded_ts = Timestamp::new(decoded_ts_val); // Convert to Timestamp

        let crc_input_bytes = self.build_uo_crc_input(
            context.rtp_ssrc,
            reconstructed_sn,
            decoded_ts,                            // TS for CRC is the newly decoded TS
            context.last_reconstructed_rtp_marker, // Marker for CRC is from context
        );
        let calculated_crc8 = self.crc_calculators.calculate_rohc_crc8(&crc_input_bytes);
        if calculated_crc8 != parsed_uo1_ts.crc8 {
            return Err(RohcError::Parsing(RohcParsingError::CrcMismatch {
                expected: parsed_uo1_ts.crc8,
                calculated: calculated_crc8,
                crc_type: "ROHC-CRC8".to_string(),
            }));
        }
        context.last_reconstructed_rtp_sn_full = reconstructed_sn;
        context.last_reconstructed_rtp_ts_full = decoded_ts; // Update context TS
        // Marker is unchanged from context.
        context.infer_ts_stride_from_decompressed_ts(decoded_ts);

        Ok(self.reconstruct_full_headers(
            context,
            reconstructed_sn,
            decoded_ts, // Pass Timestamp
            context.last_reconstructed_rtp_marker,
            context.last_reconstructed_ip_id_full, // IP-ID from context for UO-1-TS
        ))
    }

    /// Parses a UO-1-ID packet, updates decompressor context. Used internally.
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
            context.last_reconstructed_rtp_ts_full, // TS for CRC is from context
            context.last_reconstructed_rtp_marker,  // Marker for CRC is from context
            received_ip_id_lsb_val as u8,           // Use received LSB for CRC calculation
        );
        let calculated_crc8 = self.crc_calculators.calculate_rohc_crc8(&crc_input_bytes);
        if calculated_crc8 != parsed_uo1_id.crc8 {
            return Err(RohcError::Parsing(RohcParsingError::CrcMismatch {
                expected: parsed_uo1_id.crc8,
                calculated: calculated_crc8,
                crc_type: "ROHC-CRC8".to_string(),
            }));
        }
        context.last_reconstructed_rtp_sn_full = reconstructed_sn;
        context.last_reconstructed_ip_id_full = decoded_ip_id; // Update context IP-ID
        // For UO-1-ID, TS is unchanged from context.
        context.infer_ts_stride_from_decompressed_ts(context.last_reconstructed_rtp_ts_full);

        Ok(self.reconstruct_full_headers(
            context,
            reconstructed_sn,
            context.last_reconstructed_rtp_ts_full, // Pass Timestamp
            context.last_reconstructed_rtp_marker,
            decoded_ip_id, // Use newly decoded IP-ID
        ))
    }

    /// Handles decompressor state transitions for FC mode after UO packet processing.
    /// Centralizes FC->SO and FC->SC transition logic.
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
                if context.fc_packets_successful_streak >= P1_DECOMPRESSOR_FC_TO_SO_THRESHOLD_STREAK
                {
                    context.mode = Profile1DecompressorMode::SecondOrder;
                    context.so_static_confidence = P1_SO_INITIAL_STATIC_CONFIDENCE;
                    context.so_dynamic_confidence = P1_SO_INITIAL_DYNAMIC_CONFIDENCE;
                    context.so_packets_received_in_so = 0;
                    context.so_consecutive_failures = 0;
                    context.fc_packets_successful_streak = 0;
                }
                Ok(reconstructed_headers)
            }
            Err(e) => {
                context.consecutive_crc_failures_in_fc =
                    context.consecutive_crc_failures_in_fc.saturating_add(1);
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

    /// Decompresses an IR packet, updates context, and transitions to FullContext.
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
    fn should_transition_sc_to_nc(&self, context: &Profile1DecompressorContext) -> bool {
        context.sc_to_nc_k_failures >= P1_DECOMPRESSOR_SC_TO_NC_K2
    }

    /// Handles decompression in Static Context (SC) state.
    fn decompress_in_sc_state(
        &self,
        context: &mut Profile1DecompressorContext,
        packet_bytes: &[u8],
        discriminated_type: Profile1PacketType,
    ) -> Result<GenericUncompressedHeaders, RohcError> {
        debug_assert_eq!(context.mode, Profile1DecompressorMode::StaticContext);
        let mut is_failure_of_dynamic_updater_parse = false;

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
                // UO-1-RTP case will be added here later
                Profile1PacketType::Uo0 => {
                    is_failure_of_dynamic_updater_parse = false; // UO-0 is not an updater in SC
                    Err(RohcError::InvalidState(
                    "UO-0 packet received in StaticContext mode; cannot establish dynamic context.".to_string()
                ))
                }
                Profile1PacketType::Unknown(val) => {
                    is_failure_of_dynamic_updater_parse = true;
                    Err(RohcError::Parsing(RohcParsingError::InvalidPacketType {
                        discriminator: val,
                        profile_id: Some(self.profile_id().into()),
                    }))
                }
                Profile1PacketType::IrStatic | Profile1PacketType::IrDynamic => {
                    unreachable!("IR packet routed to decompress_in_sc_state.");
                }
            };

        match parse_reconstruct_result {
            Ok(headers) => {
                context.sc_to_nc_k_failures = 0;
                context.sc_to_nc_n_window_count = 0;
                // Optionally transition to FC here, or require another IR.
                // Staying in SC is a conservative approach after a UO-1 update.
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

    /// Handles decompression in Second Order (SO) state.
    fn decompress_in_so_state(
        &self,
        context: &mut Profile1DecompressorContext,
        packet_bytes: &[u8],
        discriminated_type: Profile1PacketType,
    ) -> Result<GenericUncompressedHeaders, RohcError> {
        debug_assert_eq!(context.mode, Profile1DecompressorMode::SecondOrder);

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
                // UO-1-RTP will be added here later
                Profile1PacketType::Unknown(val) => {
                    Err(RohcError::Parsing(RohcParsingError::InvalidPacketType {
                        discriminator: val,
                        profile_id: Some(self.profile_id().into()),
                    }))
                }
                Profile1PacketType::IrStatic | Profile1PacketType::IrDynamic => {
                    unreachable!("IR packet routed to decompress_in_so_state.");
                }
            };

        match parse_reconstruct_result {
            Ok(headers) => {
                context.so_dynamic_confidence = context
                    .so_dynamic_confidence
                    .saturating_add(P1_SO_SUCCESS_CONFIDENCE_BOOST);
                context.so_consecutive_failures = 0;
                context.so_packets_received_in_so =
                    context.so_packets_received_in_so.saturating_add(1);
                Ok(headers)
            }
            Err(e) => {
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

    /// Reconstructs full `RtpUdpIpv4Headers` from context and decoded dynamic fields.
    ///
    /// This helper function assembles the full uncompressed header structure using
    /// static fields from the decompressor context and the dynamic fields that were
    /// just decoded or inferred from the incoming ROHC packet.
    ///
    /// # Parameters
    /// * `context` - The decompressor context holding static chain information.
    /// * `sn` - The reconstructed RTP Sequence Number.
    /// * `ts` - The reconstructed RTP Timestamp.
    /// * `marker` - The reconstructed RTP Marker bit.
    /// * `ip_id` - The reconstructed IP Identification.
    ///
    /// # Returns
    /// The fully reconstructed `RtpUdpIpv4Headers`.
    fn reconstruct_full_headers(
        &self,
        context: &Profile1DecompressorContext,
        sn: u16,
        ts: Timestamp, // Takes Timestamp
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
            rtp_timestamp: ts, // Assigns Timestamp
            rtp_marker: marker,
            ip_ihl: IPV4_STANDARD_IHL,
            ip_dscp: 0,         // Assuming defaults, not typically compressed by P1
            ip_ecn: 0,          // Assuming defaults
            ip_total_length: 0, // To be filled by upper layers if needed
            ip_identification: ip_id,
            ip_dont_fragment: true, // Common default for RTP
            ip_more_fragments: false,
            ip_fragment_offset: 0,
            ip_ttl: DEFAULT_IPV4_TTL, // Common default
            ip_protocol: IP_PROTOCOL_UDP,
            ip_checksum: 0,  // To be calculated by sender if needed
            udp_length: 0,   // To be filled by upper layers
            udp_checksum: 0, // Optional
            rtp_version: RTP_VERSION,
            rtp_padding: false,
            rtp_extension: false,
            rtp_csrc_count: 0,
            rtp_payload_type: 0, // Not explicitly carried in most ROHC P1 packets
            rtp_csrc_list: Vec::new(),
        }
    }

    /// Creates byte slice input for UO packet CRC calculation.
    /// Format: SSRC(4), SN(2), TS(4), Marker(1 byte: 0x00 or 0x01).
    ///
    /// # Parameters
    /// * `context_ssrc` - The SSRC from the context.
    /// * `sn` - The sequence number for CRC calculation.
    /// * `ts` - The timestamp for CRC calculation.
    /// * `marker` - The marker bit value for CRC calculation.
    ///
    /// # Returns
    /// `Vec<u8>` containing the bytes for CRC input.
    fn build_uo_crc_input(
        &self,
        context_ssrc: u32,
        sn: u16,
        ts: Timestamp,
        marker: bool,
    ) -> Vec<u8> {
        let mut crc_input = Vec::with_capacity(P1_UO_CRC_INPUT_LENGTH_BYTES);
        crc_input.extend_from_slice(&context_ssrc.to_be_bytes());
        crc_input.extend_from_slice(&sn.to_be_bytes());
        crc_input.extend_from_slice(&ts.to_be_bytes()); // Timestamp's to_be_bytes
        crc_input.push(if marker { 0x01 } else { 0x00 });
        crc_input
    }

    /// Creates byte slice input for UO-1-ID packet CRC calculation.
    /// Format: SSRC(4), SN(2), TS(4), Marker(1), IP-ID LSB(1 for 8-bit width).
    ///
    /// # Parameters
    /// * `context_ssrc` - The SSRC from the context.
    /// * `sn` - The sequence number (typically SN_ref + 1).
    /// * `ts` - The timestamp (from context).
    /// * `marker` - The marker bit (from context).
    /// * `ip_id_lsb` - The LSB of the IP-ID being transmitted.
    ///
    /// # Returns
    /// `Vec<u8>` for CRC input.
    fn build_uo1_id_crc_input(
        &self,
        context_ssrc: u32,
        sn: u16,
        ts: Timestamp, // Takes Timestamp
        marker: bool,
        ip_id_lsb: u8,
    ) -> Vec<u8> {
        let mut crc_input = Vec::with_capacity(P1_UO_CRC_INPUT_LENGTH_BYTES + 1); // +1 for IP-ID LSB
        crc_input.extend_from_slice(&context_ssrc.to_be_bytes());
        crc_input.extend_from_slice(&sn.to_be_bytes());
        crc_input.extend_from_slice(&ts.to_be_bytes()); // Timestamp's to_be_bytes
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
        creation_time: Instant,
    ) -> Box<dyn RohcCompressorContext> {
        Box::new(Profile1CompressorContext::new(
            cid,
            ir_refresh_interval,
            creation_time,
        ))
    }

    fn create_decompressor_context(
        &self,
        cid: u16,
        creation_time: Instant,
    ) -> Box<dyn RohcDecompressorContext> {
        let mut ctx = Profile1DecompressorContext::new(cid);
        ctx.last_accessed = creation_time; // Ensure last_accessed is set from creation_time
        Box::new(ctx)
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

        // If SSRC changes, or if context is fresh, initialize/re-initialize.
        // initialize_context_from_uncompressed_headers forces IR mode.
        if context.rtp_ssrc == 0 || context.rtp_ssrc != uncompressed_headers.rtp_ssrc {
            context.initialize_context_from_uncompressed_headers(uncompressed_headers);
        }

        let result = if self.should_force_ir(context, uncompressed_headers) {
            self.compress_as_ir(context, uncompressed_headers)
        } else {
            self.compress_as_uo(context, uncompressed_headers)
        };

        // Update last_accessed time only on successful operation.
        if result.is_ok() {
            // In a real system, this Instant::now() would come from an abstracted clock.
            // For now, assuming direct Instant::now() is acceptable per existing code.
            context.set_last_accessed(Instant::now());
        }
        result
    }

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

        let result = match context.mode {
            Profile1DecompressorMode::NoContext => {
                if discriminated_type.is_ir() {
                    self.decompress_as_ir(context, packet_bytes)
                } else {
                    Err(RohcError::InvalidState(
                        "Non-IR packet received but decompressor is in NoContext mode.".to_string(),
                    ))
                }
            }
            _ => {
                // Covers FullContext, StaticContext, SecondOrder
                if discriminated_type.is_ir() {
                    // IR packets refresh context regardless of current FC/SC/SO state.
                    return self.decompress_as_ir(context, packet_bytes);
                }
                // Dispatch to mode-specific handlers for non-IR packets
                match context.mode {
                    Profile1DecompressorMode::FullContext => {
                        match discriminated_type {
                            Profile1PacketType::Uo0 => {
                                self.decompress_as_uo0(context, packet_bytes)
                            }
                            Profile1PacketType::Uo1Sn { .. } => {
                                self.decompress_as_uo1_sn(context, packet_bytes)
                            }
                            Profile1PacketType::Uo1Ts => {
                                self.decompress_as_uo1_ts(context, packet_bytes)
                            }
                            Profile1PacketType::Uo1Id => {
                                self.decompress_as_uo1_id(context, packet_bytes)
                            }
                            // UO-1-RTP case for TS Stride will be added in Commit 4/5.
                            Profile1PacketType::Unknown(val) => {
                                Err(RohcError::Parsing(RohcParsingError::InvalidPacketType {
                                    discriminator: val,
                                    profile_id: Some(self.profile_id().into()),
                                }))
                            }
                            _ => unreachable!(
                                "IR types should have been handled before FC mode non-IR dispatch"
                            ),
                        }
                    }
                    Profile1DecompressorMode::StaticContext => {
                        self.decompress_in_sc_state(context, packet_bytes, discriminated_type)
                    }
                    Profile1DecompressorMode::SecondOrder => {
                        // SO mode processes UO-0 and UO-1 type packets.
                        if discriminated_type.is_uo0() || discriminated_type.is_uo1() {
                            self.decompress_in_so_state(context, packet_bytes, discriminated_type)
                        } else {
                            // Other packet types in SO are unexpected, treat as error by routing to SO handler
                            self.decompress_in_so_state(context, packet_bytes, discriminated_type)
                        }
                    }
                    Profile1DecompressorMode::NoContext => {
                        unreachable!("NoContext handled earlier")
                    }
                }
            }
        };

        if result.is_ok() {
            context.set_last_accessed(Instant::now()); // Update on success
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Test helper to create RTP headers with specific SN, TS, and Marker
    fn create_test_rtp_headers(sn: u16, ts: Timestamp, marker: bool) -> RtpUdpIpv4Headers {
        RtpUdpIpv4Headers {
            ip_src: "192.168.0.1".parse().unwrap(),
            ip_dst: "192.168.0.2".parse().unwrap(),
            udp_src_port: 10000,
            udp_dst_port: 20000,
            rtp_ssrc: 0x12345678, // Fixed SSRC for simplicity in these handler tests
            rtp_sequence_number: sn,
            rtp_timestamp: ts,
            rtp_marker: marker,
            ip_identification: sn.wrapping_add(0xAA), // Make IP-ID vary but predictably
            ..Default::default()
        }
    }

    #[test]
    fn ir_compression_and_decompression_flow() {
        let handler = Profile1Handler::new();
        let mut comp_ctx_dyn = handler.create_compressor_context(0, 5, Instant::now());
        let mut decomp_ctx_dyn = handler.create_decompressor_context(0, Instant::now());

        let headers1 = create_test_rtp_headers(100, Timestamp::new(1000), false);
        let generic_headers1 = GenericUncompressedHeaders::RtpUdpIpv4(headers1.clone());

        let compressed_ir = handler
            .compress(comp_ctx_dyn.as_mut(), &generic_headers1)
            .unwrap();
        assert!(!compressed_ir.is_empty());
        assert_eq!(compressed_ir[0], P1_ROHC_IR_PACKET_TYPE_WITH_DYN); // Expect IR-DYN

        let decompressed_generic1 = handler
            .decompress(decomp_ctx_dyn.as_mut(), &compressed_ir) // Pass core packet bytes
            .unwrap();
        let decomp_headers1 = match decompressed_generic1 {
            GenericUncompressedHeaders::RtpUdpIpv4(h) => h,
            _ => panic!("Wrong enum variant for decompressed IR"),
        };

        assert_eq!(decomp_headers1.rtp_ssrc, headers1.rtp_ssrc);
        assert_eq!(
            decomp_headers1.rtp_sequence_number,
            headers1.rtp_sequence_number
        );
        assert_eq!(decomp_headers1.rtp_timestamp, headers1.rtp_timestamp);

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
        let mut comp_ctx_dyn = handler.create_compressor_context(0, 5, Instant::now());
        let mut decomp_ctx_dyn = handler.create_decompressor_context(0, Instant::now());

        // Establish IR context
        let headers_ir = create_test_rtp_headers(100, Timestamp::new(1000), false);
        let generic_headers_ir = GenericUncompressedHeaders::RtpUdpIpv4(headers_ir.clone());
        let compressed_ir = handler
            .compress(comp_ctx_dyn.as_mut(), &generic_headers_ir)
            .unwrap();
        handler
            .decompress(decomp_ctx_dyn.as_mut(), &compressed_ir)
            .unwrap();

        // Prepare UO-0: SN+ (encodable), TS same, Marker same, IP-ID same
        let comp_ctx_snapshot = comp_ctx_dyn
            .as_any()
            .downcast_ref::<Profile1CompressorContext>()
            .unwrap();
        let mut headers_uo0 = create_test_rtp_headers(101, Timestamp::new(1000), false);
        headers_uo0.ip_identification = comp_ctx_snapshot.last_sent_ip_id_full; // Crucial for UO-0
        let generic_headers_uo0 = GenericUncompressedHeaders::RtpUdpIpv4(headers_uo0.clone());

        let compressed_uo0 = handler
            .compress(comp_ctx_dyn.as_mut(), &generic_headers_uo0)
            .unwrap();
        assert_eq!(compressed_uo0.len(), 1); // UO-0 for CID 0

        let decompressed_generic_uo0 = handler
            .decompress(decomp_ctx_dyn.as_mut(), &compressed_uo0)
            .unwrap();
        match decompressed_generic_uo0 {
            GenericUncompressedHeaders::RtpUdpIpv4(h) => {
                assert_eq!(h.rtp_sequence_number, 101);
                assert_eq!(h.rtp_timestamp, Timestamp::new(1000)); // From context
                assert!(!h.rtp_marker); // From context
            }
            _ => panic!("Wrong enum variant for decompressed UO-0"),
        }
    }

    #[test]
    fn fc_to_so_transition_on_successful_uo_streak() {
        let handler = Profile1Handler::new();
        let mut ctx = Profile1DecompressorContext::new(0);
        ctx.mode = Profile1DecompressorMode::FullContext;
        ctx.rtp_ssrc = 0x12345678;
        ctx.last_reconstructed_rtp_ts_full = Timestamp::new(1000);
        ctx.last_reconstructed_rtp_marker = false;
        ctx.expected_lsb_sn_width = P1_UO0_SN_LSB_WIDTH_DEFAULT;
        let mut current_sn = 100u16;
        ctx.last_reconstructed_rtp_sn_full = current_sn;
        // Simulate IP-ID for context reconstruction, though not directly used by UO-0 CRC
        ctx.ip_source = "1.1.1.1".parse().unwrap();
        ctx.ip_destination = "2.2.2.2".parse().unwrap();
        ctx.udp_source_port = 1000;
        ctx.udp_destination_port = 2000;

        let mut ctx_dyn: Box<dyn RohcDecompressorContext> = Box::new(ctx);

        for i in 0..P1_DECOMPRESSOR_FC_TO_SO_THRESHOLD_STREAK {
            current_sn = current_sn.wrapping_add(1);
            let sn_lsb = encode_lsb(current_sn as u64, P1_UO0_SN_LSB_WIDTH_DEFAULT).unwrap() as u8;

            let decomp_ctx_snapshot = ctx_dyn
                .as_any()
                .downcast_ref::<Profile1DecompressorContext>()
                .unwrap();
            let crc_input = handler.build_uo_crc_input(
                decomp_ctx_snapshot.rtp_ssrc,
                current_sn,
                decomp_ctx_snapshot.last_reconstructed_rtp_ts_full,
                decomp_ctx_snapshot.last_reconstructed_rtp_marker,
            );
            let crc3 = handler.crc_calculators.calculate_rohc_crc3(&crc_input);
            let uo0_data = Uo0Packet {
                cid: None, // CID 0
                sn_lsb,
                crc3,
            };
            let uo0_bytes = build_profile1_uo0_packet(&uo0_data).unwrap();

            let result = handler.decompress(ctx_dyn.as_mut(), &uo0_bytes);
            assert!(
                result.is_ok(),
                "UO-0 decompression in FC failed at iter {}: {:?}",
                i,
                result.err()
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
        assert_eq!(final_ctx.fc_packets_successful_streak, 0); // Reset after transition
    }
}
