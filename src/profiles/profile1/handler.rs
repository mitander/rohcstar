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
use super::packet_processor::{
    build_profile1_ir_packet, build_profile1_uo0_packet, build_profile1_uo1_sn_packet,
    build_profile1_uo1_ts_packet, parse_profile1_ir_packet, parse_profile1_uo0_packet,
    parse_profile1_uo1_sn_packet, parse_profile1_uo1_ts_packet,
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
/// - Managing state transitions within the Profile 1 contexts.
#[derive(Debug, Default)]
pub struct Profile1Handler;

impl Profile1Handler {
    /// Creates a new instance of the `Profile1Handler`.
    pub fn new() -> Self {
        Profile1Handler
    }

    /// Determines if an IR packet must be sent based on context and current headers.
    ///
    /// This function checks several conditions that necessitate sending an IR packet:
    /// - The compressor is in `InitializationAndRefresh` mode.
    /// - The IR refresh interval has been met.
    /// - The SSRC of the current packet differs from the SSRC in the context.
    ///
    /// # Parameters
    /// - `context`: A reference to the current compressor context.
    /// - `uncompressed_headers`: A reference to the current uncompressed headers being processed.
    ///
    /// # Returns
    /// `true` if an IR packet should be forced, `false` otherwise.
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
        // SSRC change always forces IR for Profile 1 context re-initialization.
        if context.rtp_ssrc != 0 && context.rtp_ssrc != uncompressed_headers.rtp_ssrc {
            return true;
        }
        // TODO: FO->IR transition on LSB encoding insufficient for SN/TS/IP-ID.
        false
    }

    /// Handles the compression logic when an IR packet is to be sent.
    ///
    /// This involves initializing or re-initializing the context if necessary,
    /// populating an `IrPacket` structure, building the ROHC IR packet bytes,
    /// and updating the compressor context state.
    ///
    /// # Parameters
    /// - `context`: A mutable reference to the compressor context.
    /// - `uncompressed_headers`: The uncompressed headers to be encapsulated in the IR packet.
    ///
    /// # Returns
    /// A `Result` containing the built IR packet as `Vec<u8>`, or a `RohcError`.
    fn compress_as_ir(
        &self,
        context: &mut Profile1CompressorContext,
        uncompressed_headers: &RtpUdpIpv4Headers,
    ) -> Result<Vec<u8>, RohcError> {
        // Ensure context is initialized or re-initialized if SSRC changed or it's the very first packet.
        if context.mode == Profile1CompressorMode::InitializationAndRefresh
            || context.rtp_ssrc == 0
            || context.rtp_ssrc != uncompressed_headers.rtp_ssrc
        {
            context.initialize_context_from_uncompressed_headers(uncompressed_headers);
        }

        let ir_data = IrPacket {
            cid: context.cid,
            profile_id: self.profile_id(),
            crc8: 0, // Calculated by build_profile1_ir_packet
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

        // Update context state after sending IR
        context.last_sent_rtp_sn_full = uncompressed_headers.rtp_sequence_number;
        context.last_sent_rtp_ts_full = uncompressed_headers.rtp_timestamp;
        context.last_sent_rtp_marker = uncompressed_headers.rtp_marker;
        context.mode = Profile1CompressorMode::FirstOrder;
        context.fo_packets_sent_since_ir = 0;

        Ok(rohc_packet_bytes)
    }

    /// Handles the compression logic for UO (Unidirectional Optimistic) packets.
    ///
    /// This function orchestrates the selection and building of the appropriate
    /// UO packet type (UO-0, UO-1-TS, or UO-1-SN) based on changes in SN, TS,
    /// and Marker bit relative to the compressor context. It then updates the context.
    ///
    /// # Parameters
    /// - `context`: A mutable reference to the compressor context.
    /// - `uncompressed_headers`: The current uncompressed headers to be compressed.
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

        // Determine changed fields relative to context
        let marker_unchanged = current_marker == context.last_sent_rtp_marker;
        let sn_diff = current_sn.wrapping_sub(context.last_sent_rtp_sn_full);
        let sn_encodable_for_uo0 = sn_diff > 0 && sn_diff < 16; // UO-0 implies SN has advanced

        // TODO: TS_STRIDE: Replace simple equality check with stride-based logic.
        let ts_changed_significantly = current_ts != context.last_sent_rtp_ts_full;
        let sn_incremented_by_one = current_sn == context.last_sent_rtp_sn_full.wrapping_add(1);

        let final_rohc_packet_bytes =
            if marker_unchanged && sn_encodable_for_uo0 && !ts_changed_significantly {
                self.build_compress_uo0(context, current_sn)?
            } else if marker_unchanged && ts_changed_significantly && sn_incremented_by_one {
                self.build_compress_uo1_ts(context, current_sn, current_ts)?
            } else {
                // TODO: UO-1-ID: Add logic to select UO-1-ID if IP-ID changed significantly
                // and other conditions for UO-1-ID are met.
                self.build_compress_uo1_sn(context, current_sn, current_marker)?
            };

        // Update context state after sending any UO packet
        context.last_sent_rtp_sn_full = current_sn;
        context.last_sent_rtp_ts_full = current_ts; // Always update to actual current TS for next decision
        context.last_sent_rtp_marker = current_marker;
        context.fo_packets_sent_since_ir += 1;

        Ok(final_rohc_packet_bytes)
    }

    /// Builds and compresses a UO-0 packet.
    ///
    /// This helper prepares data for a UO-0 packet and calls the respective
    /// packet builder from `packet_processor`.
    ///
    /// # Parameters
    /// - `context`: A mutable reference to the compressor context.
    /// - `current_sn`: The current RTP sequence number.
    ///
    /// # Returns
    /// A `Result` containing the built UO-0 packet as `Vec<u8>`, or a `RohcError`.
    fn build_compress_uo0(
        &self,
        context: &mut Profile1CompressorContext,
        current_sn: u16,
    ) -> Result<Vec<u8>, RohcError> {
        let sn_lsb_val = encode_lsb(current_sn as u64, P1_UO0_SN_LSB_WIDTH_DEFAULT)? as u8;
        // UO-0 CRC uses current SN, but TS and Marker from context.
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

    /// Builds and compresses a UO-1-TS packet.
    ///
    /// Prepares data for a UO-1-TS packet, which conveys timestamp LSBs.
    /// The sequence number is implicitly incremented by one.
    ///
    /// # Parameters
    /// - `context`: A mutable reference to the compressor context.
    /// - `current_sn`: The current RTP sequence number (expected to be `last_sn + 1`).
    /// - `current_ts`: The current RTP timestamp to be encoded.
    ///
    /// # Returns
    /// A `Result` containing the built UO-1-TS packet as `Vec<u8>`, or a `RohcError`.
    fn build_compress_uo1_ts(
        &self,
        context: &mut Profile1CompressorContext,
        current_sn: u16,
        current_ts: u32,
    ) -> Result<Vec<u8>, RohcError> {
        let ts_lsb_val = encode_lsb(current_ts as u64, P1_UO1_TS_LSB_WIDTH_DEFAULT)? as u16;
        // UO-1-TS CRC uses current SN (implicitly last_sn + 1), current TS, and marker from context.
        let crc_input_bytes = self.build_uo_crc_input(
            context.rtp_ssrc,
            current_sn,
            current_ts,
            context.last_sent_rtp_marker, // Marker from context
        );
        let calculated_crc8 = crc::calculate_rohc_crc8(&crc_input_bytes);
        let uo1_ts_packet_data = Uo1Packet {
            cid: context.get_small_cid_for_packet(),
            sn_lsb: 0, // Not transmitted in UO-1-TS itself
            num_sn_lsb_bits: 0,
            marker: false, // Not transmitted; UO-1-TS type implies M=0, context M used for CRC.
            ts_lsb: Some(ts_lsb_val),
            num_ts_lsb_bits: Some(P1_UO1_TS_LSB_WIDTH_DEFAULT),
            crc8: calculated_crc8,
        };
        context.current_lsb_ts_width = P1_UO1_TS_LSB_WIDTH_DEFAULT;
        build_profile1_uo1_ts_packet(&uo1_ts_packet_data).map_err(RohcError::Building)
    }

    /// Builds and compresses a UO-1-SN packet.
    ///
    /// Prepares data for a UO-1-SN packet, which conveys sequence number LSBs
    /// and the marker bit.
    ///
    /// # Parameters
    /// - `context`: A mutable reference to the compressor context.
    /// - `current_sn`: The current RTP sequence number.
    /// - `current_marker`: The current RTP marker bit.
    ///
    /// # Returns
    /// A `Result` containing the built UO-1-SN packet as `Vec<u8>`, or a `RohcError`.
    fn build_compress_uo1_sn(
        &self,
        context: &mut Profile1CompressorContext,
        current_sn: u16,
        current_marker: bool,
    ) -> Result<Vec<u8>, RohcError> {
        let sn_lsb_val = encode_lsb(current_sn as u64, P1_UO1_SN_LSB_WIDTH_DEFAULT)? as u16;
        // UO-1-SN CRC uses current SN, current Marker, and TS from context.
        let crc_input_bytes = self.build_uo_crc_input(
            context.rtp_ssrc,
            current_sn,
            context.last_sent_rtp_ts_full, // TS from context
            current_marker,                // Marker from current packet
        );
        let calculated_crc8 = crc::calculate_rohc_crc8(&crc_input_bytes);
        let uo1_sn_data = Uo1Packet {
            cid: context.get_small_cid_for_packet(),
            sn_lsb: sn_lsb_val,
            num_sn_lsb_bits: P1_UO1_SN_LSB_WIDTH_DEFAULT,
            marker: current_marker,
            ts_lsb: None,
            num_ts_lsb_bits: None,
            crc8: calculated_crc8,
        };
        context.current_lsb_sn_width = P1_UO1_SN_LSB_WIDTH_DEFAULT;
        build_profile1_uo1_sn_packet(&uo1_sn_data).map_err(RohcError::Building)
    }

    /// Handles decompression of an IR packet.
    ///
    /// Parses an IR packet, validates its profile and CRC, initializes the
    /// decompressor context, and reconstructs the uncompressed headers.
    ///
    /// # Parameters
    /// - `context`: A mutable reference to the decompressor context.
    /// - `packet_bytes`: The byte slice of the core IR packet.
    ///
    /// # Returns
    /// A `Result` containing the reconstructed `GenericUncompressedHeaders` or a `RohcError`.
    fn decompress_as_ir(
        &self,
        context: &mut Profile1DecompressorContext,
        packet_bytes: &[u8],
    ) -> Result<GenericUncompressedHeaders, RohcError> {
        let parsed_ir = parse_profile1_ir_packet(packet_bytes, context.cid())?;
        if parsed_ir.profile_id != self.profile_id() {
            return Err(RohcError::Parsing(RohcParsingError::InvalidProfileId(
                parsed_ir.profile_id.into(),
            )));
        }
        context.initialize_from_ir_packet(&parsed_ir);
        let reconstructed_headers = self.reconstruct_full_headers(
            context,
            parsed_ir.dyn_rtp_sn,
            parsed_ir.dyn_rtp_timestamp,
            parsed_ir.dyn_rtp_marker,
        );
        Ok(GenericUncompressedHeaders::RtpUdpIpv4(
            reconstructed_headers,
        ))
    }

    /// Handles decompression of a UO-0 packet.
    ///
    /// Parses a UO-0 packet, decodes the sequence number, validates the CRC,
    /// updates the decompressor context, and reconstructs headers.
    /// Assumes decompressor is in `FullContext` mode.
    ///
    /// # Parameters
    /// - `context`: A mutable reference to the decompressor context.
    /// - `packet_bytes`: The byte slice of the core UO-0 packet.
    ///
    /// # Returns
    /// A `Result` containing the reconstructed `GenericUncompressedHeaders` or a `RohcError`.
    fn decompress_as_uo0(
        &self,
        context: &mut Profile1DecompressorContext,
        packet_bytes: &[u8],
    ) -> Result<GenericUncompressedHeaders, RohcError> {
        if context.mode != Profile1DecompressorMode::FullContext {
            return Err(RohcError::InvalidState(
                "Received UO-0 packet but decompressor not in Full Context mode.".to_string(),
            ));
        }
        let cid_for_parse: Option<u8> = if context.cid() == 0 {
            None
        } else if context.cid() <= 15 {
            // Ensure it's a small CID, as UO-0 builder expects this
            Some(context.cid() as u8)
        } else {
            return Err(RohcError::Internal(format!(
                "UO-0 decompression for unexpected large CID {}",
                context.cid()
            )));
        };
        let parsed_uo0 = parse_profile1_uo0_packet(packet_bytes, cid_for_parse)?;

        let decoded_sn = decode_lsb(
            parsed_uo0.sn_lsb as u64,
            context.last_reconstructed_rtp_sn_full as u64,
            context.expected_lsb_sn_width, // UO-0 uses context's expected width
            context.p_sn,
        )? as u16;

        // For UO-0, marker and timestamp are from context
        let marker_for_header = context.last_reconstructed_rtp_marker;
        let ts_for_header = context.last_reconstructed_rtp_ts_full;

        let crc_input_bytes = self.build_uo_crc_input(
            context.rtp_ssrc,
            decoded_sn,        // Use decoded SN for CRC
            ts_for_header,     // TS from context
            marker_for_header, // Marker from context
        );
        let calculated_crc3 = crc::calculate_rohc_crc3(&crc_input_bytes);

        if calculated_crc3 == parsed_uo0.crc3 {
            context.last_reconstructed_rtp_sn_full = decoded_sn;
            // Marker & TS not updated by UO-0 from packet content
            context.consecutive_crc_failures_in_fc = 0;
            let reconstructed_headers = self.reconstruct_full_headers(
                context,
                decoded_sn,
                ts_for_header,
                marker_for_header,
            );
            Ok(GenericUncompressedHeaders::RtpUdpIpv4(
                reconstructed_headers,
            ))
        } else {
            context.consecutive_crc_failures_in_fc += 1;
            if context.consecutive_crc_failures_in_fc
                >= P1_DECOMPRESSOR_FC_TO_SC_CRC_FAILURE_THRESHOLD
            {
                context.mode = Profile1DecompressorMode::StaticContext;
            }
            Err(RohcError::Parsing(RohcParsingError::CrcMismatch {
                expected: parsed_uo0.crc3,
                calculated: calculated_crc3,
                crc_type: "ROHC-CRC3".to_string(),
            }))
        }
    }

    /// Handles decompression of a UO-1-TS packet.
    ///
    /// Parses a UO-1-TS packet, decodes the timestamp, implicitly updates the
    /// sequence number, validates the CRC, updates context, and reconstructs headers.
    /// Assumes decompressor is in `FullContext` mode.
    ///
    /// # Parameters
    /// - `context`: A mutable reference to the decompressor context.
    /// - `packet_bytes`: The byte slice of the core UO-1-TS packet.
    ///
    /// # Returns
    /// A `Result` containing the reconstructed `GenericUncompressedHeaders` or a `RohcError`.
    fn decompress_as_uo1_ts(
        &self,
        context: &mut Profile1DecompressorContext,
        packet_bytes: &[u8],
    ) -> Result<GenericUncompressedHeaders, RohcError> {
        let parsed_uo1_ts = parse_profile1_uo1_ts_packet(packet_bytes)?;

        // UO-1-TS implicitly updates SN by 1. Marker is from context. TS from packet.
        let reconstructed_sn = context.last_reconstructed_rtp_sn_full.wrapping_add(1);
        let marker_from_context = context.last_reconstructed_rtp_marker;

        let decoded_ts = decode_lsb(
            parsed_uo1_ts
                .ts_lsb
                .ok_or_else(|| RohcParsingError::MandatoryFieldMissing {
                    field_name: "ts_lsb".to_string(),
                    structure_name: "Parsed UO-1-TS".to_string(),
                })? as u64,
            context.last_reconstructed_rtp_ts_full as u64,
            parsed_uo1_ts.num_ts_lsb_bits.ok_or_else(|| {
                RohcParsingError::MandatoryFieldMissing {
                    field_name: "num_ts_lsb_bits".to_string(),
                    structure_name: "Parsed UO-1-TS".to_string(),
                }
            })?,
            context.p_ts,
        )? as u32;

        let crc_input_bytes = self.build_uo_crc_input(
            context.rtp_ssrc,
            reconstructed_sn,
            decoded_ts,
            marker_from_context,
        );
        let calculated_crc8 = crc::calculate_rohc_crc8(&crc_input_bytes);

        if calculated_crc8 == parsed_uo1_ts.crc8 {
            context.last_reconstructed_rtp_sn_full = reconstructed_sn; // Update SN
            context.last_reconstructed_rtp_ts_full = decoded_ts; // Update TS
            // context.last_reconstructed_rtp_marker remains unchanged from context.
            context.consecutive_crc_failures_in_fc = 0;

            let reconstructed_headers = self.reconstruct_full_headers(
                context,
                reconstructed_sn,
                decoded_ts,
                marker_from_context,
            );
            Ok(GenericUncompressedHeaders::RtpUdpIpv4(
                reconstructed_headers,
            ))
        } else {
            context.consecutive_crc_failures_in_fc += 1;
            if context.consecutive_crc_failures_in_fc
                >= P1_DECOMPRESSOR_FC_TO_SC_CRC_FAILURE_THRESHOLD
            {
                context.mode = Profile1DecompressorMode::StaticContext;
            }
            Err(RohcError::Parsing(RohcParsingError::CrcMismatch {
                expected: parsed_uo1_ts.crc8,
                calculated: calculated_crc8,
                crc_type: "ROHC-CRC8".to_string(),
            }))
        }
    }

    /// Handles decompression of a UO-1-SN packet.
    ///
    /// Parses a UO-1-SN packet, decodes sequence number and marker bit,
    /// validates CRC, updates context, and reconstructs headers.
    /// Assumes decompressor is in `FullContext` mode.
    ///
    /// # Parameters
    /// - `context`: A mutable reference to the decompressor context.
    /// - `packet_bytes`: The byte slice of the core UO-1-SN packet.
    ///
    /// # Returns
    /// A `Result` containing the reconstructed `GenericUncompressedHeaders` or a `RohcError`.
    fn decompress_as_uo1_sn(
        &self,
        context: &mut Profile1DecompressorContext,
        packet_bytes: &[u8],
    ) -> Result<GenericUncompressedHeaders, RohcError> {
        let parsed_uo1 = parse_profile1_uo1_sn_packet(packet_bytes)?;
        let marker = parsed_uo1.marker;

        let decoded_sn = decode_lsb(
            parsed_uo1.sn_lsb as u64,
            context.last_reconstructed_rtp_sn_full as u64,
            parsed_uo1.num_sn_lsb_bits,
            context.p_sn,
        )? as u16;

        // For UO-1-SN, timestamp is from context
        let ts_for_header = context.last_reconstructed_rtp_ts_full;

        let crc_input_bytes =
            self.build_uo_crc_input(context.rtp_ssrc, decoded_sn, ts_for_header, marker);
        let calculated_crc8 = crc::calculate_rohc_crc8(&crc_input_bytes);

        if calculated_crc8 == parsed_uo1.crc8 {
            context.last_reconstructed_rtp_sn_full = decoded_sn;
            context.last_reconstructed_rtp_marker = marker;
            // UO-1-SN does not update TS from packet content.
            context.consecutive_crc_failures_in_fc = 0;
            let reconstructed_headers =
                self.reconstruct_full_headers(context, decoded_sn, ts_for_header, marker);
            Ok(GenericUncompressedHeaders::RtpUdpIpv4(
                reconstructed_headers,
            ))
        } else {
            context.consecutive_crc_failures_in_fc += 1;
            if context.consecutive_crc_failures_in_fc
                >= P1_DECOMPRESSOR_FC_TO_SC_CRC_FAILURE_THRESHOLD
            {
                context.mode = Profile1DecompressorMode::StaticContext;
            }
            Err(RohcError::Parsing(RohcParsingError::CrcMismatch {
                expected: parsed_uo1.crc8,
                calculated: calculated_crc8,
                crc_type: "ROHC-CRC8".to_string(),
            }))
        }
    }

    /// Reconstructs full `RtpUdpIpv4Headers` from the decompressor context and
    /// newly decoded dynamic fields.
    fn reconstruct_full_headers(
        &self,
        context: &Profile1DecompressorContext,
        sn: u16,
        ts: u32,
        marker: bool,
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
            ip_total_length: 0,     // Would need payload size
            ip_identification: 0,   // ROHC P1 can compress this, but base UOs don't always carry
            ip_dont_fragment: true, // Often true for RTP
            ip_more_fragments: false,
            ip_fragment_offset: 0,
            ip_ttl: DEFAULT_IPV4_TTL,
            ip_protocol: IP_PROTOCOL_UDP,
            ip_checksum: 0,  // Needs recalculation if sent
            udp_length: 0,   // UDP header + RTP header + payload
            udp_checksum: 0, // Optional
            rtp_version: RTP_VERSION,
            rtp_padding: false,
            rtp_extension: false,
            rtp_csrc_count: 0,
            rtp_payload_type: 0, // Not signaled by ROHC IR/UO; must be known otherwise
            rtp_csrc_list: Vec::new(),
        }
    }

    /// Creates the byte slice input required for calculating the CRC for UO-0 and UO-1 packets
    /// in ROHC Profile 1. Input format: SSRC(4), SN(2), TS(4), Marker(1).
    fn build_uo_crc_input(&self, context_ssrc: u32, sn: u16, ts: u32, marker: bool) -> Vec<u8> {
        let mut crc_input = Vec::with_capacity(P1_UO_CRC_INPUT_LENGTH_BYTES);
        crc_input.extend_from_slice(&context_ssrc.to_be_bytes());
        crc_input.extend_from_slice(&sn.to_be_bytes());
        crc_input.extend_from_slice(&ts.to_be_bytes());
        crc_input.push(if marker { 0x01 } else { 0x00 });
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

        // Handle SSRC change: forces re-initialization before IR decision logic.
        // This ensures initialize_context_from_uncompressed_headers (which sets mode to IR)
        // is called if SSRC changed.
        if context.rtp_ssrc != 0 && context.rtp_ssrc != uncompressed_headers.rtp_ssrc {
            context.initialize_context_from_uncompressed_headers(uncompressed_headers);
            // Context mode is now InitializationAndRefresh, so should_force_ir will be true.
        }

        if self.should_force_ir(context, uncompressed_headers) {
            self.compress_as_ir(context, uncompressed_headers)
        } else {
            self.compress_as_uo(context, uncompressed_headers)
        }
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

        // Dispatch based on packet type discriminator
        if (first_byte & !P1_ROHC_IR_PACKET_TYPE_D_BIT_MASK) == P1_ROHC_IR_PACKET_TYPE_BASE {
            // IR or IR-DYN Packet (0xFC or 0xFD)
            self.decompress_as_ir(context, packet_bytes)
        } else if (first_byte & P1_UO_1_TS_PACKET_TYPE_PREFIX) == P1_UO_1_TS_PACKET_TYPE_PREFIX {
            // UO-1 Packet (prefix 101xxxxx)
            // This includes UO-1-SN, UO-1-TS, (and future UO-1-ID)
            if context.mode != Profile1DecompressorMode::FullContext {
                return Err(RohcError::InvalidState(
                    "Received UO-1 packet but decompressor not in Full Context mode.".to_string(),
                ));
            }
            // Further discriminate UO-1 types
            if (first_byte & P1_UO_1_TS_TYPE_MASK)
                == (P1_UO_1_TS_DISCRIMINATOR & P1_UO_1_TS_TYPE_MASK)
            {
                self.decompress_as_uo1_ts(context, packet_bytes)
            } else {
                // Assuming UO-1-SN for now if not UO-1-TS and matches UO-1 prefix
                // Future: Add check for UO-1-ID here based on remaining bits of type octet.
                self.decompress_as_uo1_sn(context, packet_bytes)
            }
        } else if (first_byte & 0x80) == 0x00 {
            // UO-0 Packet (MSB is 0)
            self.decompress_as_uo0(context, packet_bytes)
        } else {
            Err(RohcError::Parsing(RohcParsingError::InvalidPacketType {
                discriminator: first_byte,
                profile_id: Some(self.profile_id().into()),
            }))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
            ..Default::default()
        }
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
        assert_eq!(decomp_headers1.rtp_timestamp, headers1.rtp_timestamp);
        assert_eq!(decomp_headers1.rtp_marker, headers1.rtp_marker);

        let comp_ctx = comp_ctx_dyn
            .as_any()
            .downcast_ref::<Profile1CompressorContext>()
            .unwrap();
        assert_eq!(comp_ctx.mode, Profile1CompressorMode::FirstOrder);
        assert_eq!(comp_ctx.last_sent_rtp_sn_full, 100);
        assert_eq!(comp_ctx.fo_packets_sent_since_ir, 0);

        let decomp_ctx = decomp_ctx_dyn
            .as_any()
            .downcast_ref::<Profile1DecompressorContext>()
            .unwrap();
        assert_eq!(decomp_ctx.mode, Profile1DecompressorMode::FullContext);
        assert_eq!(decomp_ctx.last_reconstructed_rtp_sn_full, 100);
    }

    #[test]
    fn uo0_compression_and_decompression_flow() {
        let handler = Profile1Handler::new();
        let mut comp_ctx_dyn = handler.create_compressor_context(0, 5);
        let mut decomp_ctx_dyn = handler.create_decompressor_context(0);

        let headers_ir = create_test_rtp_headers(100, 1000, false);
        let generic_headers_ir = GenericUncompressedHeaders::RtpUdpIpv4(headers_ir.clone());
        let compressed_ir = handler
            .compress(comp_ctx_dyn.as_mut(), &generic_headers_ir)
            .unwrap();
        let _ = handler
            .decompress(decomp_ctx_dyn.as_mut(), &compressed_ir)
            .unwrap();

        let headers_uo0 = create_test_rtp_headers(101, 1000, false); // TS same, marker same for UO-0
        let generic_headers_uo0 = GenericUncompressedHeaders::RtpUdpIpv4(headers_uo0.clone());
        let compressed_uo0 = handler
            .compress(comp_ctx_dyn.as_mut(), &generic_headers_uo0)
            .unwrap();

        assert_eq!(compressed_uo0.len(), 1);
        assert_eq!(compressed_uo0[0] & 0x80, 0x00);

        let decompressed_generic_uo0 = handler
            .decompress(decomp_ctx_dyn.as_mut(), &compressed_uo0)
            .unwrap();
        let decomp_headers_uo0 = match decompressed_generic_uo0 {
            GenericUncompressedHeaders::RtpUdpIpv4(h) => h,
            _ => panic!("Wrong enum variant"),
        };

        assert_eq!(decomp_headers_uo0.rtp_sequence_number, 101);
        assert_eq!(decomp_headers_uo0.rtp_marker, headers_ir.rtp_marker);
        assert_eq!(decomp_headers_uo0.rtp_timestamp, headers_ir.rtp_timestamp);
    }

    #[test]
    fn uo1_sn_compression_and_decompression_on_marker_change() {
        let handler = Profile1Handler::new();
        let mut comp_ctx_dyn = handler.create_compressor_context(0, 5);
        let mut decomp_ctx_dyn = handler.create_decompressor_context(0);

        let headers_ir = create_test_rtp_headers(200, 2000, false);
        let generic_headers_ir = GenericUncompressedHeaders::RtpUdpIpv4(headers_ir.clone());
        let compressed_ir = handler
            .compress(comp_ctx_dyn.as_mut(), &generic_headers_ir)
            .unwrap();
        let _ = handler
            .decompress(decomp_ctx_dyn.as_mut(), &compressed_ir)
            .unwrap();

        let headers_uo1 = create_test_rtp_headers(201, 2000, true); // TS same, marker changed for UO-1
        let generic_headers_uo1 = GenericUncompressedHeaders::RtpUdpIpv4(headers_uo1.clone());
        let compressed_uo1 = handler
            .compress(comp_ctx_dyn.as_mut(), &generic_headers_uo1)
            .unwrap();

        assert_eq!(compressed_uo1.len(), 3);
        assert_eq!(
            compressed_uo1[0] & P1_UO_1_SN_PACKET_TYPE_PREFIX,
            P1_UO_1_SN_PACKET_TYPE_PREFIX
        );
        assert_ne!(compressed_uo1[0] & P1_UO_1_SN_MARKER_BIT_MASK, 0);

        let decompressed_generic_uo1 = handler
            .decompress(decomp_ctx_dyn.as_mut(), &compressed_uo1)
            .unwrap();
        let decomp_headers_uo1 = match decompressed_generic_uo1 {
            GenericUncompressedHeaders::RtpUdpIpv4(h) => h,
            _ => panic!("Wrong enum variant"),
        };

        assert_eq!(decomp_headers_uo1.rtp_sequence_number, 201);
        assert!(decomp_headers_uo1.rtp_marker);
        assert_eq!(decomp_headers_uo1.rtp_timestamp, headers_ir.rtp_timestamp);
    }

    #[test]
    fn ir_refresh_triggered_by_interval() {
        let handler = Profile1Handler::new();
        let refresh_interval = 3; // IR, UO, UO, then next should be IR
        let mut comp_ctx_dyn = handler.create_compressor_context(0, refresh_interval);

        // Packet 1: IR
        let headers1 = create_test_rtp_headers(10, 100, false); // TS = 100
        let generic1 = GenericUncompressedHeaders::RtpUdpIpv4(headers1.clone());
        let compressed1 = handler.compress(comp_ctx_dyn.as_mut(), &generic1).unwrap();
        assert_eq!(compressed1[0], P1_ROHC_IR_PACKET_TYPE_WITH_DYN);
        let comp_ctx_after_p1 = comp_ctx_dyn
            .as_any()
            .downcast_ref::<Profile1CompressorContext>()
            .unwrap();
        assert_eq!(comp_ctx_after_p1.fo_packets_sent_since_ir, 0);
        assert_eq!(comp_ctx_after_p1.last_sent_rtp_ts_full, 100);

        // Packet 2: UO-0
        // For UO-0, TS must not change from context (100), marker same (false), SN increments.
        let headers2 = create_test_rtp_headers(11, 100, false); // TS = 100
        let generic2 = GenericUncompressedHeaders::RtpUdpIpv4(headers2.clone());
        let compressed2 = handler.compress(comp_ctx_dyn.as_mut(), &generic2).unwrap();
        assert_eq!(
            compressed2.len(),
            1,
            "Packet 2 (UO-0) length failure. Generated: {:?}",
            compressed2
        ); // UO-0
        let comp_ctx_after_p2 = comp_ctx_dyn
            .as_any()
            .downcast_ref::<Profile1CompressorContext>()
            .unwrap();
        assert_eq!(comp_ctx_after_p2.fo_packets_sent_since_ir, 1);
        assert_eq!(comp_ctx_after_p2.last_sent_rtp_ts_full, 100);

        // Packet 3: UO-0
        let headers3 = create_test_rtp_headers(12, 100, false);
        let generic3 = GenericUncompressedHeaders::RtpUdpIpv4(headers3.clone());
        let compressed3 = handler.compress(comp_ctx_dyn.as_mut(), &generic3).unwrap();
        assert_eq!(
            compressed3.len(),
            1,
            "Packet 3 (UO-0) length failure. Generated: {:?}",
            compressed3
        ); // UO-0
        let comp_ctx_after_p3 = comp_ctx_dyn
            .as_any()
            .downcast_ref::<Profile1CompressorContext>()
            .unwrap();
        assert_eq!(comp_ctx_after_p3.fo_packets_sent_since_ir, 2);
        assert_eq!(comp_ctx_after_p3.last_sent_rtp_ts_full, 100);

        // Packet 4: Should be IR due to refresh
        // TS can change for IR packet.
        let headers4 = create_test_rtp_headers(13, 130, false);
        let generic4 = GenericUncompressedHeaders::RtpUdpIpv4(headers4.clone());
        let compressed4 = handler.compress(comp_ctx_dyn.as_mut(), &generic4).unwrap();
        assert_eq!(
            compressed4[0], P1_ROHC_IR_PACKET_TYPE_WITH_DYN,
            "Packet 4 should be an IR due to refresh"
        );
        let comp_ctx_after_p4 = comp_ctx_dyn
            .as_any()
            .downcast_ref::<Profile1CompressorContext>()
            .unwrap();
        assert_eq!(comp_ctx_after_p4.fo_packets_sent_since_ir, 0);
        assert_eq!(comp_ctx_after_p4.last_sent_rtp_ts_full, 130);
    }

    #[test]
    fn should_force_ir_when_in_initial_mode() {
        let handler = Profile1Handler::new();
        let mut ctx = Profile1CompressorContext::new(0, 5);
        ctx.mode = Profile1CompressorMode::InitializationAndRefresh;
        let headers = create_test_rtp_headers(1, 10, false);
        assert!(handler.should_force_ir(&ctx, &headers));
    }

    #[test]
    fn should_force_ir_when_refresh_interval_met() {
        let handler = Profile1Handler::new();
        let mut ctx = Profile1CompressorContext::new(0, 3);
        ctx.mode = Profile1CompressorMode::FirstOrder;
        ctx.fo_packets_sent_since_ir = 2; // Interval is 3, so refresh after 2 FOs
        let headers = create_test_rtp_headers(1, 10, false);
        assert!(handler.should_force_ir(&ctx, &headers));

        ctx.fo_packets_sent_since_ir = 1; // Not met yet
        assert!(!handler.should_force_ir(&ctx, &headers));
    }

    #[test]
    fn should_force_ir_on_ssrc_change() {
        let handler = Profile1Handler::new();
        let mut ctx = Profile1CompressorContext::new(0, 5);
        ctx.mode = Profile1CompressorMode::FirstOrder;
        ctx.rtp_ssrc = 0x12345678;

        // SSRC is 0x12345678
        let headers_fixture = create_test_rtp_headers(1, 10, false);

        let headers_diff_ssrc = RtpUdpIpv4Headers {
            rtp_ssrc: 0xAAAAAAAA, // Different SSRC
            ..headers_fixture.clone()
        };
        assert!(handler.should_force_ir(&ctx, &headers_diff_ssrc));

        // Test with same SSRC
        assert!(!handler.should_force_ir(&ctx, &headers_fixture));
    }

    #[test]
    fn compress_as_ir_initializes_and_updates_context() {
        let handler = Profile1Handler::new();
        let mut ctx = Profile1CompressorContext::new(0, 5);
        ctx.mode = Profile1CompressorMode::InitializationAndRefresh; // Force IR mode
        let headers = create_test_rtp_headers(10, 1000, true);

        let result = handler.compress_as_ir(&mut ctx, &headers);
        assert!(result.is_ok());
        let packet = result.unwrap();
        assert!(!packet.is_empty());
        assert_eq!(packet[0], P1_ROHC_IR_PACKET_TYPE_WITH_DYN); // Assuming CID 0

        // Check context updates
        assert_eq!(ctx.mode, Profile1CompressorMode::FirstOrder);
        assert_eq!(ctx.last_sent_rtp_sn_full, 10);
        assert_eq!(ctx.last_sent_rtp_ts_full, 1000);
        assert!(ctx.last_sent_rtp_marker);
        assert_eq!(ctx.fo_packets_sent_since_ir, 0);
        assert_eq!(ctx.rtp_ssrc, headers.rtp_ssrc); // Verify context SSRC was initialized
        assert_eq!(ctx.ip_source, headers.ip_src); // Verify other static parts
    }

    #[test]
    fn build_compress_uo0_creates_valid_packet_data() {
        let handler = Profile1Handler::new();
        let mut ctx = Profile1CompressorContext::new(0, 5);
        ctx.rtp_ssrc = 0x12345678; // SSRC must be set for CRC calculation
        ctx.last_sent_rtp_ts_full = 1000;
        ctx.last_sent_rtp_marker = false;

        let current_sn = 101;
        let result = handler.build_compress_uo0(&mut ctx, current_sn);
        assert!(result.is_ok());
        let packet = result.unwrap();
        assert_eq!(packet.len(), 1); // UO-0 for CID 0 is 1 byte
        assert_eq!(ctx.current_lsb_sn_width, P1_UO0_SN_LSB_WIDTH_DEFAULT);
    }

    #[test]
    fn build_compress_uo1_ts_creates_valid_packet_data() {
        let handler = Profile1Handler::new();
        let mut ctx = Profile1CompressorContext::new(0, 5);
        ctx.rtp_ssrc = 0x12345678;
        ctx.last_sent_rtp_sn_full = 200;
        ctx.last_sent_rtp_marker = false; // UO-1-TS uses context marker for CRC

        let current_sn = 201;
        let current_ts = 2500;
        let result = handler.build_compress_uo1_ts(&mut ctx, current_sn, current_ts);
        assert!(result.is_ok());
        let packet = result.unwrap();
        assert_eq!(packet.len(), 4); // UO-1-TS for CID 0 is 4 bytes
        assert_eq!(packet[0], P1_UO_1_TS_DISCRIMINATOR);
        assert_eq!(ctx.current_lsb_ts_width, P1_UO1_TS_LSB_WIDTH_DEFAULT);
    }

    #[test]
    fn build_compress_uo1_sn_creates_valid_packet_data() {
        let handler = Profile1Handler::new();
        let mut ctx = Profile1CompressorContext::new(0, 5);
        ctx.rtp_ssrc = 0x12345678;
        ctx.last_sent_rtp_ts_full = 3000; // UO-1-SN uses context TS for CRC

        let current_sn = 305;
        let current_marker = true; // Marker bit being sent
        let result = handler.build_compress_uo1_sn(&mut ctx, current_sn, current_marker);
        assert!(result.is_ok());
        let packet = result.unwrap();
        assert_eq!(packet.len(), 3); // UO-1-SN for CID 0 is 3 bytes
        assert_eq!(
            packet[0],
            P1_UO_1_SN_PACKET_TYPE_PREFIX | P1_UO_1_SN_MARKER_BIT_MASK
        ); // Type with M bit set
        assert_eq!(ctx.current_lsb_sn_width, P1_UO1_SN_LSB_WIDTH_DEFAULT);
    }

    #[test]
    fn decompress_as_ir_initializes_context_and_reconstructs() {
        let handler = Profile1Handler::new();
        let mut decomp_ctx = Profile1DecompressorContext::new(0);
        let ir_data_orig = IrPacket {
            cid: 0,
            profile_id: RohcProfile::RtpUdpIp,
            static_ip_src: "1.2.3.4".parse().unwrap(),
            static_ip_dst: "5.6.7.8".parse().unwrap(),
            static_udp_src_port: 111,
            static_udp_dst_port: 222,
            static_rtp_ssrc: 0xABCDEF,
            dyn_rtp_sn: 50,
            dyn_rtp_timestamp: 5000,
            dyn_rtp_marker: false,
            crc8: 0, // Will be auto-calculated
        };
        let ir_bytes = build_profile1_ir_packet(&ir_data_orig).unwrap();

        let result = handler.decompress_as_ir(&mut decomp_ctx, &ir_bytes);
        assert!(
            result.is_ok(),
            "decompress_as_ir failed: {:?}",
            result.err()
        );
        let headers = result.unwrap().as_rtp_udp_ipv4().unwrap().clone();

        assert_eq!(decomp_ctx.mode, Profile1DecompressorMode::FullContext);
        assert_eq!(decomp_ctx.rtp_ssrc, ir_data_orig.static_rtp_ssrc);
        assert_eq!(decomp_ctx.ip_source, ir_data_orig.static_ip_src);
        assert_eq!(headers.rtp_sequence_number, ir_data_orig.dyn_rtp_sn);
        assert_eq!(headers.rtp_timestamp, ir_data_orig.dyn_rtp_timestamp);
        assert_eq!(headers.rtp_marker, ir_data_orig.dyn_rtp_marker);
    }

    #[test]
    fn decompress_as_uo0_in_full_context_valid_packet() {
        let handler = Profile1Handler::new();
        let mut decomp_ctx = Profile1DecompressorContext::new(0);

        // Manually set up context as if an IR was received
        decomp_ctx.mode = Profile1DecompressorMode::FullContext;
        decomp_ctx.rtp_ssrc = 0x12345678;
        decomp_ctx.last_reconstructed_rtp_sn_full = 100;
        decomp_ctx.last_reconstructed_rtp_ts_full = 1000;
        decomp_ctx.last_reconstructed_rtp_marker = false;
        decomp_ctx.expected_lsb_sn_width = P1_UO0_SN_LSB_WIDTH_DEFAULT;

        // Create a valid UO-0 packet for SN=101
        let current_sn_val = 101;
        let sn_lsb = encode_lsb(current_sn_val as u64, P1_UO0_SN_LSB_WIDTH_DEFAULT).unwrap() as u8;
        let crc_input = handler.build_uo_crc_input(
            decomp_ctx.rtp_ssrc,
            current_sn_val, // Use the full SN for CRC calculation base
            decomp_ctx.last_reconstructed_rtp_ts_full,
            decomp_ctx.last_reconstructed_rtp_marker,
        );
        let crc3 = crc::calculate_rohc_crc3(&crc_input);
        let uo0_packet_data = Uo0Packet {
            cid: None,
            sn_lsb,
            crc3,
        };
        let uo0_bytes = build_profile1_uo0_packet(&uo0_packet_data).unwrap();

        let result = handler.decompress_as_uo0(&mut decomp_ctx, &uo0_bytes);
        assert!(
            result.is_ok(),
            "UO-0 decompression failed: {:?}",
            result.err()
        );
        let headers = result.unwrap().as_rtp_udp_ipv4().unwrap().clone();

        assert_eq!(headers.rtp_sequence_number, current_sn_val);
        assert_eq!(headers.rtp_timestamp, 1000); // From context
        assert!(!headers.rtp_marker); // From context
        assert_eq!(decomp_ctx.last_reconstructed_rtp_sn_full, current_sn_val);
        assert_eq!(decomp_ctx.consecutive_crc_failures_in_fc, 0);
    }

    #[test]
    fn decompress_as_uo0_returns_invalid_state_if_not_fc() {
        let handler = Profile1Handler::new();
        let mut decomp_ctx = Profile1DecompressorContext::new(0); // Default is NoContext
        let uo0_bytes = vec![0x08]; // Dummy UO-0 (SN=1, CRC=0 assuming 4-bit SN)

        let result = handler.decompress_as_uo0(&mut decomp_ctx, &uo0_bytes);
        assert!(matches!(result, Err(RohcError::InvalidState(_))));

        decomp_ctx.mode = Profile1DecompressorMode::StaticContext;
        let result_sc = handler.decompress_as_uo0(&mut decomp_ctx, &uo0_bytes);
        assert!(matches!(result_sc, Err(RohcError::InvalidState(_))));
    }

    #[test]
    fn decompress_as_uo1_ts_in_full_context_valid_packet() {
        let handler = Profile1Handler::new();
        let mut decomp_ctx = Profile1DecompressorContext::new(0);
        // Setup context
        decomp_ctx.mode = Profile1DecompressorMode::FullContext;
        decomp_ctx.rtp_ssrc = 0xABCDEF01;
        decomp_ctx.last_reconstructed_rtp_sn_full = 50;
        decomp_ctx.last_reconstructed_rtp_ts_full = 5000;
        decomp_ctx.last_reconstructed_rtp_marker = true; // Context marker value
        decomp_ctx.expected_lsb_ts_width = P1_UO1_TS_LSB_WIDTH_DEFAULT; // Ensure this matches build

        let expected_reconstructed_sn = 51; // UO-1-TS implies SN+1
        let new_ts_value = 5500;
        let ts_lsb = encode_lsb(new_ts_value as u64, P1_UO1_TS_LSB_WIDTH_DEFAULT).unwrap() as u16;

        // CRC uses implicitly updated SN, new TS, and context marker
        let crc_input = handler.build_uo_crc_input(
            decomp_ctx.rtp_ssrc,
            expected_reconstructed_sn,
            new_ts_value,
            decomp_ctx.last_reconstructed_rtp_marker,
        );
        let crc8 = crc::calculate_rohc_crc8(&crc_input);
        let uo1_ts_packet_data = Uo1Packet {
            cid: None,
            ts_lsb: Some(ts_lsb),
            num_ts_lsb_bits: Some(P1_UO1_TS_LSB_WIDTH_DEFAULT),
            crc8,
            ..Default::default()
        };
        let uo1_ts_bytes = build_profile1_uo1_ts_packet(&uo1_ts_packet_data).unwrap();

        let result = handler.decompress_as_uo1_ts(&mut decomp_ctx, &uo1_ts_bytes);
        assert!(
            result.is_ok(),
            "UO-1-TS decompression failed: {:?}",
            result.err()
        );
        let headers = result.unwrap().as_rtp_udp_ipv4().unwrap().clone();

        assert_eq!(headers.rtp_sequence_number, expected_reconstructed_sn);
        assert_eq!(headers.rtp_timestamp, new_ts_value);
        assert!(headers.rtp_marker); // From context
        assert_eq!(
            decomp_ctx.last_reconstructed_rtp_sn_full,
            expected_reconstructed_sn
        );
        assert_eq!(decomp_ctx.last_reconstructed_rtp_ts_full, new_ts_value);
        assert!(decomp_ctx.last_reconstructed_rtp_marker); // Context marker unchanged
    }

    #[test]
    fn decompress_as_uo1_sn_in_full_context_valid_packet() {
        let handler = Profile1Handler::new();
        let mut decomp_ctx = Profile1DecompressorContext::new(0);

        // Setup context
        decomp_ctx.mode = Profile1DecompressorMode::FullContext;
        decomp_ctx.rtp_ssrc = 0xFEDCBA98;
        decomp_ctx.last_reconstructed_rtp_sn_full = 70;
        decomp_ctx.last_reconstructed_rtp_ts_full = 7000; // This TS will be used for reconstruction
        decomp_ctx.last_reconstructed_rtp_marker = false; // Initial context marker

        let sn_in_packet = 75; // Represents a jump, not necessarily +1
        let marker_in_packet = true;
        let sn_lsb = encode_lsb(sn_in_packet as u64, P1_UO1_SN_LSB_WIDTH_DEFAULT).unwrap() as u16;

        // CRC uses SN from packet, TS from context, marker from packet
        let crc_input = handler.build_uo_crc_input(
            decomp_ctx.rtp_ssrc,
            sn_in_packet,
            decomp_ctx.last_reconstructed_rtp_ts_full,
            marker_in_packet,
        );
        let crc8 = crc::calculate_rohc_crc8(&crc_input);
        let uo1_sn_packet_data = Uo1Packet {
            cid: None,
            sn_lsb,
            num_sn_lsb_bits: P1_UO1_SN_LSB_WIDTH_DEFAULT,
            marker: marker_in_packet,
            crc8,
            ..Default::default()
        };
        let uo1_sn_bytes = build_profile1_uo1_sn_packet(&uo1_sn_packet_data).unwrap();

        let result = handler.decompress_as_uo1_sn(&mut decomp_ctx, &uo1_sn_bytes);
        assert!(
            result.is_ok(),
            "UO-1-SN decompression failed: {:?}",
            result.err()
        );
        let headers = result.unwrap().as_rtp_udp_ipv4().unwrap().clone();

        assert_eq!(headers.rtp_sequence_number, sn_in_packet);
        assert_eq!(headers.rtp_timestamp, 7000); // From context, UO-1-SN does not carry TS
        assert_eq!(headers.rtp_marker, marker_in_packet);
        assert_eq!(decomp_ctx.last_reconstructed_rtp_sn_full, sn_in_packet);
        assert_eq!(decomp_ctx.last_reconstructed_rtp_marker, marker_in_packet);
        assert_eq!(decomp_ctx.last_reconstructed_rtp_ts_full, 7000); // Context TS unchanged by UO-1-SN
    }
}
