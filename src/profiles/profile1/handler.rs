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
    build_profile1_uo1_rtp_packet, build_profile1_uo1_sn_packet, build_profile1_uo1_ts_packet,
    parse_profile1_ir_packet, parse_profile1_uo0_packet, parse_profile1_uo1_id_packet,
    parse_profile1_uo1_rtp_packet, parse_profile1_uo1_sn_packet, parse_profile1_uo1_ts_packet,
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
            static_ip_src: context.ip_source,
            static_ip_dst: context.ip_destination,
            static_udp_src_port: context.udp_source_port,
            static_udp_dst_port: context.udp_destination_port,
            static_rtp_ssrc: context.rtp_ssrc,
            dyn_rtp_sn: uncompressed_headers.rtp_sequence_number,
            dyn_rtp_timestamp: uncompressed_headers.rtp_timestamp,
            dyn_rtp_marker: uncompressed_headers.rtp_marker,
        };

        let rohc_packet_bytes = build_profile1_ir_packet(&ir_data, &self.crc_calculators)
            .map_err(RohcError::Building)?;

        context.last_sent_rtp_sn_full = uncompressed_headers.rtp_sequence_number;
        context.last_sent_rtp_ts_full = uncompressed_headers.rtp_timestamp;
        context.last_sent_rtp_marker = uncompressed_headers.rtp_marker;
        context.last_sent_ip_id_full = uncompressed_headers.ip_identification;
        context.mode = Profile1CompressorMode::FirstOrder;
        context.fo_packets_sent_since_ir = 0;
        context.consecutive_fo_packets_sent = 0;

        context.ts_stride = None;
        context.ts_offset = Timestamp::new(0);
        context.ts_stride_packets = 0;
        context.ts_scaled_mode = false;

        Ok(rohc_packet_bytes)
    }

    /// Handles compressor logic for sending UO (Unidirectional Optimistic) packets.
    fn compress_as_uo(
        &self,
        context: &mut Profile1CompressorContext,
        uncompressed_headers: &RtpUdpIpv4Headers,
    ) -> Result<Vec<u8>, RohcError> {
        let current_sn = uncompressed_headers.rtp_sequence_number;
        let current_ts = uncompressed_headers.rtp_timestamp;
        let current_marker = uncompressed_headers.rtp_marker;
        let current_ip_id = uncompressed_headers.ip_identification;

        context.update_ts_stride_detection(current_ts);

        let marker_unchanged = current_marker == context.last_sent_rtp_marker;
        let sn_diff = current_sn.wrapping_sub(context.last_sent_rtp_sn_full);
        let sn_encodable_for_uo0 = sn_diff > 0 && sn_diff < 16;
        let ts_changed_significantly = current_ts != context.last_sent_rtp_ts_full;
        let sn_incremented_by_one = current_sn == context.last_sent_rtp_sn_full.wrapping_add(1);
        let ip_id_changed = current_ip_id != context.last_sent_ip_id_full;
        let ip_id_conditions_for_uo1_id = ip_id_changed;

        // Packet selection logic, prioritizing UO-1-RTP if possible
        let final_rohc_packet_bytes =
            if context.ts_scaled_mode && sn_incremented_by_one && !ip_id_changed {
                if let Some(ts_scaled_val) = context.calculate_ts_scaled(current_ts) {
                    // Attempt to build UO-1-RTP
                    self.build_compress_uo1_rtp(context, current_sn, ts_scaled_val, current_marker)?
                } else {
                    // TS_SCALED not possible (e.g., overflow, non-alignment), fall back
                    // The most likely fallback if TS has changed (implied by active stride usually)
                    // and other UO-0 conditions are not met, would be UO-1-TS.
                    if marker_unchanged && ts_changed_significantly && !ip_id_changed {
                        self.build_compress_uo1_ts(context, current_sn, current_ts)?
                    } else {
                        // Broader fallback to UO-1-SN if UO-1-TS isn't appropriate
                        self.build_compress_uo1_sn(context, current_sn, current_marker)?
                    }
                }
            } else if marker_unchanged
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
            context.consecutive_fo_packets_sent =
                context.consecutive_fo_packets_sent.saturating_add(1);
            if context.consecutive_fo_packets_sent >= P1_COMPRESSOR_FO_TO_SO_THRESHOLD {
                context.mode = Profile1CompressorMode::SecondOrder;
                context.consecutive_fo_packets_sent = 0;
            }
        }
        context.fo_packets_sent_since_ir = context.fo_packets_sent_since_ir.saturating_add(1);

        Ok(final_rohc_packet_bytes)
    }

    /// Builds a ROHC Profile 1 UO-0 packet.
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
        let crc3_val = self.crc_calculators.calculate_rohc_crc3(&crc_input_bytes);
        let uo0_data = Uo0Packet {
            cid: context.get_small_cid_for_packet(),
            sn_lsb: sn_lsb_val,
            crc3: crc3_val,
        };
        context.current_lsb_sn_width = P1_UO0_SN_LSB_WIDTH_DEFAULT;
        build_profile1_uo0_packet(&uo0_data).map_err(RohcError::Building)
    }

    /// Builds a ROHC Profile 1 UO-1-TS packet.
    fn build_compress_uo1_ts(
        &self,
        context: &mut Profile1CompressorContext,
        current_sn: u16,
        current_ts: Timestamp,
    ) -> Result<Vec<u8>, RohcError> {
        let ts_lsb_val = encode_lsb(current_ts.value() as u64, P1_UO1_TS_LSB_WIDTH_DEFAULT)? as u16;
        let crc_input_bytes = self.build_uo_crc_input(
            context.rtp_ssrc,
            current_sn,
            current_ts,
            context.last_sent_rtp_marker,
        );
        let calculated_crc8 = self.crc_calculators.calculate_rohc_crc8(&crc_input_bytes);
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

    /// Builds a ROHC Profile 1 UO-1-SN packet.
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
        let calculated_crc8 = self.crc_calculators.calculate_rohc_crc8(&crc_input_bytes);
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

    /// Builds a ROHC Profile 1 UO-1-ID packet.
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
        let calculated_crc8 = self.crc_calculators.calculate_rohc_crc8(&crc_input_bytes);
        let uo1_id_packet_data = Uo1Packet {
            cid: context.get_small_cid_for_packet(),
            ip_id_lsb: Some(ip_id_lsb_for_packet_field as u16),
            num_ip_id_lsb_bits: Some(P1_UO1_IPID_LSB_WIDTH_DEFAULT),
            crc8: calculated_crc8,
            ..Default::default()
        };
        build_profile1_uo1_id_packet(&uo1_id_packet_data).map_err(RohcError::Building)
    }

    /// Builds a ROHC Profile 1 UO-1-RTP packet.
    fn build_compress_uo1_rtp(
        &self,
        context: &Profile1CompressorContext, // context can be & for read-only access during build
        current_sn: u16,
        ts_scaled_val: u8,
        current_marker: bool,
    ) -> Result<Vec<u8>, RohcError> {
        let stride = context.ts_stride.ok_or_else(|| {
            RohcError::Internal(
                "TS stride missing in scaled mode during UO-1-RTP build.".to_string(),
            )
        })?;
        let full_ts_for_crc = context
            .ts_offset
            .wrapping_add(ts_scaled_val as u32 * stride);

        let crc_input_bytes = self.build_uo_crc_input(
            context.rtp_ssrc,
            current_sn,
            full_ts_for_crc,
            current_marker,
        );
        let calculated_crc8 = self.crc_calculators.calculate_rohc_crc8(&crc_input_bytes);

        let uo1_rtp_data = Uo1Packet {
            cid: context.get_small_cid_for_packet(),
            marker: current_marker,
            ts_scaled: Some(ts_scaled_val),
            crc8: calculated_crc8,
            ..Default::default()
        };
        build_profile1_uo1_rtp_packet(&uo1_rtp_data).map_err(RohcError::Building)
    }

    /// Parses an IR packet and updates decompressor context.
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
        Ok(self.reconstruct_full_headers(
            context,
            parsed_ir.dyn_rtp_sn,
            parsed_ir.dyn_rtp_timestamp,
            parsed_ir.dyn_rtp_marker,
            context.last_reconstructed_ip_id_full,
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
        let calculated_crc3 = self.crc_calculators.calculate_rohc_crc3(&crc_input_bytes);
        if calculated_crc3 != parsed_uo0.crc3 {
            return Err(RohcError::Parsing(RohcParsingError::CrcMismatch {
                expected: parsed_uo0.crc3,
                calculated: calculated_crc3,
                crc_type: "ROHC-CRC3".to_string(),
            }));
        }
        context.last_reconstructed_rtp_sn_full = decoded_sn;
        context.infer_ts_stride_from_decompressed_ts(context.last_reconstructed_rtp_ts_full);

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
            context.last_reconstructed_rtp_ts_full,
            parsed_uo1.marker,
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
        context.infer_ts_stride_from_decompressed_ts(context.last_reconstructed_rtp_ts_full);

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
        let reconstructed_sn = context.last_reconstructed_rtp_sn_full.wrapping_add(1);
        let decoded_ts_val = decode_lsb(
            parsed_uo1_ts.ts_lsb.unwrap_or(0) as u64,
            context.last_reconstructed_rtp_ts_full.value() as u64,
            parsed_uo1_ts
                .num_ts_lsb_bits
                .unwrap_or(P1_UO1_TS_LSB_WIDTH_DEFAULT),
            context.p_ts,
        )? as u32;
        let decoded_ts = Timestamp::new(decoded_ts_val);

        let crc_input_bytes = self.build_uo_crc_input(
            context.rtp_ssrc,
            reconstructed_sn,
            decoded_ts,
            context.last_reconstructed_rtp_marker,
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
        context.last_reconstructed_rtp_ts_full = decoded_ts;
        context.infer_ts_stride_from_decompressed_ts(decoded_ts);

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
        let reconstructed_sn = context.last_reconstructed_rtp_sn_full.wrapping_add(1);
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
            context.last_reconstructed_rtp_ts_full,
            context.last_reconstructed_rtp_marker,
            received_ip_id_lsb_val as u8,
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
        context.last_reconstructed_ip_id_full = decoded_ip_id;
        context.infer_ts_stride_from_decompressed_ts(context.last_reconstructed_rtp_ts_full);

        Ok(self.reconstruct_full_headers(
            context,
            reconstructed_sn,
            context.last_reconstructed_rtp_ts_full,
            context.last_reconstructed_rtp_marker,
            decoded_ip_id,
        ))
    }

    /// Parses a UO-1-RTP packet and updates decompressor context.
    fn _parse_and_reconstruct_uo1_rtp(
        &self,
        context: &mut Profile1DecompressorContext,
        packet_bytes: &[u8],
    ) -> Result<RtpUdpIpv4Headers, RohcError> {
        let parsed_uo1_rtp = parse_profile1_uo1_rtp_packet(packet_bytes)?;

        let reconstructed_sn = context.last_reconstructed_rtp_sn_full.wrapping_add(1);

        let ts_scaled_received =
            parsed_uo1_rtp
                .ts_scaled
                .ok_or_else(|| RohcParsingError::MandatoryFieldMissing {
                    field_name: "ts_scaled".to_string(),
                    structure_name: "UO-1-RTP (parsed)".to_string(),
                })?;

        let reconstructed_ts = context
            .reconstruct_ts_from_scaled(ts_scaled_received)
            .ok_or_else(|| {
                RohcError::InvalidState(
                    "Cannot reconstruct TS from TS_SCALED: TS_STRIDE not established in context."
                        .to_string(),
                )
            })?;

        if context.ts_stride.is_some() && !context.ts_scaled_mode {
            context.ts_scaled_mode = true;
        }
        context.infer_ts_stride_from_decompressed_ts(reconstructed_ts);

        let crc_input_bytes = self.build_uo_crc_input(
            context.rtp_ssrc,
            reconstructed_sn,
            reconstructed_ts,
            parsed_uo1_rtp.marker,
        );
        let calculated_crc8 = self.crc_calculators.calculate_rohc_crc8(&crc_input_bytes);
        if calculated_crc8 != parsed_uo1_rtp.crc8 {
            return Err(RohcError::Parsing(RohcParsingError::CrcMismatch {
                expected: parsed_uo1_rtp.crc8,
                calculated: calculated_crc8,
                crc_type: "ROHC-CRC8 (UO-1-RTP)".to_string(),
            }));
        }

        context.last_reconstructed_rtp_sn_full = reconstructed_sn;
        context.last_reconstructed_rtp_ts_full = reconstructed_ts;
        context.last_reconstructed_rtp_marker = parsed_uo1_rtp.marker;

        Ok(self.reconstruct_full_headers(
            context,
            reconstructed_sn,
            reconstructed_ts,
            parsed_uo1_rtp.marker,
            context.last_reconstructed_ip_id_full,
        ))
    }

    /// Handles decompressor state transitions for FC mode after UO packet processing.
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

    /// Decompresses UO-1-RTP in FC mode, handling state transitions.
    fn decompress_as_uo1_rtp(
        &self,
        context: &mut Profile1DecompressorContext,
        packet_bytes: &[u8],
    ) -> Result<GenericUncompressedHeaders, RohcError> {
        let outcome = self._parse_and_reconstruct_uo1_rtp(context, packet_bytes);
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
                Profile1PacketType::Uo1Rtp { .. } => {
                    let res = self._parse_and_reconstruct_uo1_rtp(context, packet_bytes);
                    if res.is_err() {
                        is_failure_of_dynamic_updater_parse = true;
                    }
                    res.map(GenericUncompressedHeaders::RtpUdpIpv4)
                }
                Profile1PacketType::Uo0 => {
                    is_failure_of_dynamic_updater_parse = false;
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
                if discriminated_type.is_dynamically_updating_type()
                    && (discriminated_type.is_uo1() || context.ts_scaled_mode)
                {
                    context.mode = Profile1DecompressorMode::FullContext;
                    context.fc_packets_successful_streak = 1;
                }
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
                Profile1PacketType::Uo1Rtp { .. } => self
                    ._parse_and_reconstruct_uo1_rtp(context, packet_bytes)
                    .map(GenericUncompressedHeaders::RtpUdpIpv4),
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
    fn reconstruct_full_headers(
        &self,
        context: &Profile1DecompressorContext,
        sn: u16,
        ts: Timestamp,
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

    /// Creates byte slice input for UO packet CRC calculation.
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
        crc_input.extend_from_slice(&ts.to_be_bytes());
        crc_input.push(if marker { 0x01 } else { 0x00 });
        crc_input
    }

    /// Creates byte slice input for UO-1-ID packet CRC calculation.
    fn build_uo1_id_crc_input(
        &self,
        context_ssrc: u32,
        sn: u16,
        ts: Timestamp,
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
        ctx.last_accessed = creation_time;
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

        if context.rtp_ssrc == 0 || context.rtp_ssrc != uncompressed_headers.rtp_ssrc {
            context.initialize_context_from_uncompressed_headers(uncompressed_headers);
        }

        let result = if self.should_force_ir(context, uncompressed_headers) {
            self.compress_as_ir(context, uncompressed_headers)
        } else {
            self.compress_as_uo(context, uncompressed_headers)
        };

        if result.is_ok() {
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
                if discriminated_type.is_ir() {
                    return self.decompress_as_ir(context, packet_bytes);
                }
                match context.mode {
                    Profile1DecompressorMode::FullContext => match discriminated_type {
                        Profile1PacketType::Uo0 => self.decompress_as_uo0(context, packet_bytes),
                        Profile1PacketType::Uo1Sn { .. } => {
                            self.decompress_as_uo1_sn(context, packet_bytes)
                        }
                        Profile1PacketType::Uo1Ts => {
                            self.decompress_as_uo1_ts(context, packet_bytes)
                        }
                        Profile1PacketType::Uo1Id => {
                            self.decompress_as_uo1_id(context, packet_bytes)
                        }
                        Profile1PacketType::Uo1Rtp { .. } => {
                            self.decompress_as_uo1_rtp(context, packet_bytes)
                        }
                        Profile1PacketType::Unknown(val) => {
                            Err(RohcError::Parsing(RohcParsingError::InvalidPacketType {
                                discriminator: val,
                                profile_id: Some(self.profile_id().into()),
                            }))
                        }
                        Profile1PacketType::IrStatic | Profile1PacketType::IrDynamic => {
                            unreachable!("IR types handled")
                        }
                    },
                    Profile1DecompressorMode::StaticContext => {
                        self.decompress_in_sc_state(context, packet_bytes, discriminated_type)
                    }
                    Profile1DecompressorMode::SecondOrder => {
                        self.decompress_in_so_state(context, packet_bytes, discriminated_type)
                    }
                    Profile1DecompressorMode::NoContext => unreachable!(),
                }
            }
        };

        if result.is_ok() {
            context.set_last_accessed(Instant::now());
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_rtp_headers(sn: u16, ts: Timestamp, marker: bool) -> RtpUdpIpv4Headers {
        RtpUdpIpv4Headers {
            ip_src: "192.168.0.1".parse().unwrap(),
            ip_dst: "192.168.0.2".parse().unwrap(),
            udp_src_port: 10000,
            udp_dst_port: 20000,
            rtp_ssrc: 0x12345678,
            rtp_sequence_number: sn,
            rtp_timestamp: ts,
            rtp_marker: marker,
            ip_identification: sn.wrapping_add(0xAA),
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
        assert_eq!(compressed_ir[0], P1_ROHC_IR_PACKET_TYPE_WITH_DYN);

        let decompressed_generic1 = handler
            .decompress(decomp_ctx_dyn.as_mut(), &compressed_ir)
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

        let headers_ir = create_test_rtp_headers(100, Timestamp::new(1000), false);
        let generic_headers_ir = GenericUncompressedHeaders::RtpUdpIpv4(headers_ir.clone());
        let compressed_ir = handler
            .compress(comp_ctx_dyn.as_mut(), &generic_headers_ir)
            .unwrap();
        handler
            .decompress(decomp_ctx_dyn.as_mut(), &compressed_ir)
            .unwrap();

        let comp_ctx_snapshot = comp_ctx_dyn
            .as_any()
            .downcast_ref::<Profile1CompressorContext>()
            .unwrap();
        let mut headers_uo0 = create_test_rtp_headers(101, Timestamp::new(1000), false);
        headers_uo0.ip_identification = comp_ctx_snapshot.last_sent_ip_id_full;
        let generic_headers_uo0 = GenericUncompressedHeaders::RtpUdpIpv4(headers_uo0.clone());

        let compressed_uo0 = handler
            .compress(comp_ctx_dyn.as_mut(), &generic_headers_uo0)
            .unwrap();
        assert_eq!(compressed_uo0.len(), 1);

        let decompressed_generic_uo0 = handler
            .decompress(decomp_ctx_dyn.as_mut(), &compressed_uo0)
            .unwrap();
        match decompressed_generic_uo0 {
            GenericUncompressedHeaders::RtpUdpIpv4(h) => {
                assert_eq!(h.rtp_sequence_number, 101);
                assert_eq!(h.rtp_timestamp, Timestamp::new(1000));
                assert!(!h.rtp_marker);
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
                cid: None,
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
        assert_eq!(final_ctx.fc_packets_successful_streak, 0);
    }
}
