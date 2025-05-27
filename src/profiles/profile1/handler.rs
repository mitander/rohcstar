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
        let ts_changed_significantly = current_ts != context.last_sent_rtp_ts_full; // TODO: TS_STRIDE
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
    /// This function prepares data for a UO-0 packet by encoding the sequence number's LSBs
    /// and calculating the 3-bit CRC. It then uses `build_profile1_uo0_packet` from
    /// `packet_processor` to assemble the final byte sequence, potentially including an
    /// Add-CID octet if `context.cid` is small and non-zero.
    ///
    /// # Parameters
    /// - `context`: Mutable reference to `Profile1CompressorContext` (used for SSRC, last TS, last Marker for CRC calculation, and CID).
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
            context.last_sent_rtp_ts_full, // UO-0 uses context TS for CRC
            context.last_sent_rtp_marker,  // UO-0 uses context Marker for CRC
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
    /// This function prepares data for a UO-1-TS packet, encoding the current timestamp's LSBs.
    /// The sequence number is assumed to have incremented by one. The 8-bit CRC is calculated
    /// based on SSRC, implicit SN+1, current TS, and the context's last marker bit.
    /// It uses `build_profile1_uo1_ts_packet` for final assembly.
    ///
    /// # Parameters
    /// - `context`: Mutable reference to `Profile1CompressorContext`.
    /// - `current_sn`: The full sequence number (expected to be `last_sent_rtp_sn_full + 1`).
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
            current_sn,                   // SN is current_sn (implicitly last_sn + 1)
            current_ts,                   // TS is current_ts
            context.last_sent_rtp_marker, // Marker from context for CRC calculation
        );
        let calculated_crc8 = crc::calculate_rohc_crc8(&crc_input_bytes);
        let uo1_ts_packet_data = Uo1Packet {
            cid: context.get_small_cid_for_packet(),
            marker: false, // UO-1-TS packet type implies M=0, actual marker for CRC from context
            ts_lsb: Some(ts_lsb_val),
            num_ts_lsb_bits: Some(P1_UO1_TS_LSB_WIDTH_DEFAULT),
            crc8: calculated_crc8,
            ..Default::default() // Other fields like sn_lsb are not relevant for UO-1-TS packet
        };
        context.current_lsb_ts_width = P1_UO1_TS_LSB_WIDTH_DEFAULT;
        build_profile1_uo1_ts_packet(&uo1_ts_packet_data).map_err(RohcError::Building)
    }

    /// Builds a ROHC Profile 1 UO-1-SN packet's byte representation.
    ///
    /// This function prepares data for a UO-1-SN packet, encoding the current sequence number's LSBs
    /// and the current marker bit. The 8-bit CRC is calculated using SSRC, current SN, current Marker,
    /// and the context's last timestamp. Uses `build_profile1_uo1_sn_packet` for assembly.
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
            context.last_sent_rtp_ts_full, // TS from context for CRC
            current_marker,                // Marker from current packet for CRC & packet field
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
    /// Prepares data for a UO-1-ID packet, encoding the current IP-ID's LSBs.
    /// The sequence number is assumed to have incremented by one. The 8-bit CRC is calculated
    /// using SSRC, implicit SN+1, context TS, context Marker, and the transmitted IP-ID LSBs.
    /// Uses `build_profile1_uo1_id_packet` for assembly.
    ///
    /// # Parameters
    /// - `context`: Mutable reference to `Profile1CompressorContext`.
    /// - `current_sn`: The full sequence number (expected to be `last_sent_rtp_sn_full + 1`).
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
            current_sn,                    // SN is current_sn (implicitly last_sn + 1)
            context.last_sent_rtp_ts_full, // TS from context
            context.last_sent_rtp_marker,  // Marker from context
            ip_id_lsb_for_packet_field,    // Use the 8-bit LSB that will go into the packet
        );
        let calculated_crc8 = crc::calculate_rohc_crc8(&crc_input_bytes);

        let uo1_id_packet_data = Uo1Packet {
            cid: context.get_small_cid_for_packet(),
            // Store the LSB that was actually used for the packet field and CRC
            ip_id_lsb: Some(ip_id_lsb_for_packet_field as u16),
            num_ip_id_lsb_bits: Some(P1_UO1_IPID_LSB_WIDTH_DEFAULT),
            crc8: calculated_crc8,
            ..Default::default()
        };
        // context.current_lsb_ip_id_width is used for W-LSB interpretation window,
        // but the packet itself has a fixed-size field for IP-ID LSB in UO-1-ID.
        build_profile1_uo1_id_packet(&uo1_id_packet_data).map_err(RohcError::Building)
    }

    /// Internal helper: Parses an IR packet, validates its profile ID, and updates
    /// the static and dynamic fields of the decompressor context based on the IR content.
    /// It does NOT change `context.mode`; mode management is handled by the caller (`decompress_as_ir`).
    ///
    /// # Parameters
    /// - `context`: A mutable reference to the `Profile1DecompressorContext` to be updated.
    /// - `packet_bytes`: Slice containing the core IR packet data.
    ///
    /// # Returns
    /// `Result<RtpUdpIpv4Headers, RohcError>`: The fully reconstructed headers from the IR packet.
    /// Errors if parsing fails or the profile ID in the packet doesn't match Profile 1.
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

    /// Internal helper: Parses a UO-0 packet, decodes the sequence number, validates the CRC,
    /// and updates `context.last_reconstructed_rtp_sn_full`.
    /// Does NOT change `context.mode` or manage transition counters.
    ///
    /// # Parameters
    /// - `context`: Mutable reference to `Profile1DecompressorContext`.
    /// - `packet_bytes`: Slice containing the core UO-0 packet data.
    ///
    /// # Returns
    /// `Result<RtpUdpIpv4Headers, RohcError>` containing reconstructed headers if successful.
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

    /// Decompresses an IR packet and transitions decompressor context to FullContext.
    ///
    /// This method calls the internal `_parse_and_reconstruct_ir` helper.
    /// On success, it sets the context mode to `FullContext` and resets
    /// counters related to FC->SC, FC->SO, and SO state management, ensuring
    /// a clean state after IR processing.
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
                // Reset SO counters as IR establishes a new FC baseline
                context.so_static_confidence = 0;
                context.so_dynamic_confidence = 0;
                context.so_packets_received_in_so = 0;
                context.so_consecutive_failures = 0;
                // Reset SC counters as well
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
    /// Calls `_parse_and_reconstruct_uo0`. On success, manages FC->SO transition
    /// based on `fc_packets_successful_streak`. On failure, manages FC->SC transition
    /// based on `consecutive_crc_failures_in_fc`.
    ///
    /// # Parameters
    /// - `context`: Mutable reference to `Profile1DecompressorContext`.
    /// - `packet_bytes`: Slice containing the core UO-0 packet data.
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
    /// Manages FC->SO and FC->SC transitions similarly to `decompress_as_uo0`.
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
    /// Manages FC->SO and FC->SC transitions.
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
    /// Manages FC->SO and FC->SC transitions.
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

    /// Determines if the decompressor should transition from Second Order (SO) to No Context (NC).
    ///
    /// According to ROHC Profile 1 (RFC 3095) recommendations, this transition typically occurs if:
    /// 1. A certain number of consecutive packet processing failures happen while in SO mode
    ///    (violating `P1_SO_MAX_CONSECUTIVE_FAILURES`).
    /// 2. The decompressor's confidence in the dynamic part of the context drops below a
    ///    predefined threshold (`P1_SO_TO_NC_CONFIDENCE_THRESHOLD`).
    ///
    /// This function encapsulates that logic.
    ///
    /// # Parameters
    /// - `context`: An immutable reference to the `Profile1DecompressorContext` currently in SO state.
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

    /// Handles decompression of packets when the decompressor is in Second Order (SO) state.
    ///
    /// In SO mode, the decompressor has high confidence in its context. This method attempts
    /// to decompress incoming UO-0, UO-1 (non-IR) packets using the respective private parsing helpers.
    /// IR packets are handled by the main `decompress` dispatcher and will transition out of SO.
    ///
    /// # Parameters
    /// - `context`: A mutable reference to the `Profile1DecompressorContext` (expected to be in SO mode).
    /// - `packet_bytes`: A byte slice containing the core ROHC packet data.
    ///
    /// # Returns
    /// `Result<GenericUncompressedHeaders, RohcError>`. Context mode might change to `NoContext`.
    fn decompress_in_so_state(
        &self,
        context: &mut Profile1DecompressorContext,
        packet_bytes: &[u8],
    ) -> Result<GenericUncompressedHeaders, RohcError> {
        debug_assert_eq!(context.mode, Profile1DecompressorMode::SecondOrder);
        let first_byte = packet_bytes[0]; // Assumes packet_bytes is not empty (checked by caller)

        // IR packets are handled by the main decompress dispatcher which will transition to FC.
        // This function will therefore only process UO packets.
        let parse_reconstruct_result =
            if (first_byte & P1_UO_1_TS_PACKET_TYPE_PREFIX) == P1_UO_1_TS_PACKET_TYPE_PREFIX {
                if (first_byte & P1_UO_1_TS_TYPE_MASK)
                    == (P1_UO_1_TS_DISCRIMINATOR & P1_UO_1_TS_TYPE_MASK)
                {
                    self._parse_and_reconstruct_uo1_ts(context, packet_bytes)
                        .map(GenericUncompressedHeaders::RtpUdpIpv4)
                } else if first_byte == P1_UO_1_ID_DISCRIMINATOR {
                    self._parse_and_reconstruct_uo1_id(context, packet_bytes)
                        .map(GenericUncompressedHeaders::RtpUdpIpv4)
                } else {
                    // UO-1-SN
                    self._parse_and_reconstruct_uo1_sn(context, packet_bytes)
                        .map(GenericUncompressedHeaders::RtpUdpIpv4)
                }
            } else if (first_byte & 0x80) == 0x00 {
                // UO-0
                self._parse_and_reconstruct_uo0(context, packet_bytes)
                    .map(GenericUncompressedHeaders::RtpUdpIpv4)
            } else {
                // Not an IR (handled by caller), not UO-1, not UO-0. Invalid packet for SO processing.
                Err(RohcError::Parsing(RohcParsingError::InvalidPacketType {
                    discriminator: first_byte,
                    profile_id: Some(self.profile_id().into()),
                }))
            };

        match parse_reconstruct_result {
            Ok(headers) => {
                // Successful UO packet processing in SO state.
                // An IR would have transitioned context.mode to FullContext already.
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

    /// Determines if the decompressor should transition from Static Context (SC) to No Context (NC).
    ///
    /// According to ROHC Profile 1 (RFC 3095, Section 5.3.2.2.3), this transition
    /// occurs if `K2` (`P1_DECOMPRESSOR_SC_TO_NC_K2`) out of `N2` (`P1_DECOMPRESSOR_SC_TO_NC_N2`)
    /// "updating" packets (typically UO-1 or IR-DYN) fail to be decompressed correctly
    /// while in SC mode.
    ///
    /// # Parameters
    /// - `context`: An immutable reference to the `Profile1DecompressorContext` currently in SC state.
    ///
    /// # Returns
    /// `true` if a transition from SC to No Context (NC) is warranted, `false` otherwise.
    fn should_transition_sc_to_nc(&self, context: &Profile1DecompressorContext) -> bool {
        // Transition if k_failures (sc_to_nc_k_failures) >= K2.
        // The windowing logic (N2) is managed by the caller (decompress_in_sc_state)
        // by resetting counters after N2 packets if transition hasn't occurred.
        context.sc_to_nc_k_failures >= P1_DECOMPRESSOR_SC_TO_NC_K2
    }

    /// Handles decompression of packets when the decompressor is in Static Context (SC) state.
    ///
    /// In SC mode, the decompressor has a valid static context (IPs, ports, SSRC from an IR packet)
    /// but may have lost synchronization of dynamic fields (SN, TS, etc.). It primarily expects
    /// IR packets (to re-establish Full Context, handled by the main `decompress` dispatcher)
    /// or UO-1 packets that might allow it to re-synchronize and potentially move to Full Context.
    /// UO-0 packets are generally not processable in SC mode.
    ///
    /// - **Successful Decompression (UO-1 packet):** If a UO-1 packet is successfully decompressed,
    ///   the dynamic context fields are updated. The SC->NC transition counters are reset.
    ///   The context typically remains in SC, awaiting an IR for a robust transition to FC.
    /// - **Decompression Failure (for UO-1 or other relevant "updating" packets):**
    ///     - The `sc_to_nc_n_window_count` is incremented.
    ///     - If the failure is a CRC mismatch or parsing error (not an `InvalidState` from UO-0),
    ///       `sc_to_nc_k_failures` is incremented.
    ///     - It checks if conditions for transitioning to No Context (NC) are met
    ///       (via `should_transition_sc_to_nc`). If so, mode is set to `NoContext` and
    ///       dynamic fields are reset using `context.reset_for_nc_transition()`.
    ///     - If the N2 window (`P1_DECOMPRESSOR_SC_TO_NC_N2`) is completed without triggering NC,
    ///       the SC->NC window counters are reset.
    ///       The original error causing the failure is returned.
    ///
    /// # Parameters
    /// - `context`: A mutable reference to the `Profile1DecompressorContext` (expected to be in SC mode).
    /// - `packet_bytes`: A byte slice containing the core ROHC packet data.
    ///
    /// # Returns
    /// `Result<GenericUncompressedHeaders, RohcError>`. Context mode might change to `FullContext` (if an IR was somehow routed here, though unlikely) or `NoContext`.
    fn decompress_in_sc_state(
        &self,
        context: &mut Profile1DecompressorContext,
        packet_bytes: &[u8],
    ) -> Result<GenericUncompressedHeaders, RohcError> {
        debug_assert_eq!(context.mode, Profile1DecompressorMode::StaticContext);
        let first_byte = packet_bytes[0];

        #[allow(unused_assignments)]
        let mut is_considered_updating_packet_for_sc = false;

        let parse_reconstruct_result =
            if (first_byte & P1_UO_1_TS_PACKET_TYPE_PREFIX) == P1_UO_1_TS_PACKET_TYPE_PREFIX {
                is_considered_updating_packet_for_sc = true;
                if (first_byte & P1_UO_1_TS_TYPE_MASK)
                    == (P1_UO_1_TS_DISCRIMINATOR & P1_UO_1_TS_TYPE_MASK)
                {
                    self._parse_and_reconstruct_uo1_ts(context, packet_bytes)
                        .map(GenericUncompressedHeaders::RtpUdpIpv4)
                } else if first_byte == P1_UO_1_ID_DISCRIMINATOR {
                    self._parse_and_reconstruct_uo1_id(context, packet_bytes)
                        .map(GenericUncompressedHeaders::RtpUdpIpv4)
                } else {
                    // UO-1-SN
                    self._parse_and_reconstruct_uo1_sn(context, packet_bytes)
                        .map(GenericUncompressedHeaders::RtpUdpIpv4)
                }
            } else if (first_byte & 0x80) == 0x00 {
                // UO-0 packet
                is_considered_updating_packet_for_sc = true; // Counts towards N2 window, but not K2 failures
                Err(RohcError::InvalidState(
                    "UO-0 packet received in StaticContext mode; cannot be processed.".to_string(),
                ))
            } else {
                // Not IR (handled by main dispatch), not UO-1, not UO-0.
                is_considered_updating_packet_for_sc = true;
                Err(RohcError::Parsing(RohcParsingError::InvalidPacketType {
                    discriminator: first_byte,
                    profile_id: Some(self.profile_id().into()),
                }))
            };

        match parse_reconstruct_result {
            Ok(headers) => {
                // Successfully processed an UO-1 in SC
                context.sc_to_nc_k_failures = 0;
                context.sc_to_nc_n_window_count = 0;
                Ok(headers)
            }
            Err(e) => {
                if is_considered_updating_packet_for_sc {
                    context.sc_to_nc_n_window_count =
                        context.sc_to_nc_n_window_count.saturating_add(1);
                    if !matches!(e, RohcError::InvalidState(_)) {
                        // Don't count UO-0 InvalidState as a 'k' failure
                        context.sc_to_nc_k_failures = context.sc_to_nc_k_failures.saturating_add(1);
                    }

                    if self.should_transition_sc_to_nc(context) {
                        context.mode = Profile1DecompressorMode::NoContext;
                        context.reset_for_nc_transition();
                    } else if context.sc_to_nc_n_window_count >= P1_DECOMPRESSOR_SC_TO_NC_N2 {
                        context.sc_to_nc_k_failures = 0;
                        context.sc_to_nc_n_window_count = 0;
                    }
                }
                Err(e)
            }
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
            ip_total_length: 0, // Would need payload size
            ip_identification: ip_id,
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

    /// Creates the byte slice input required for calculating the CRC for UO-1-ID packets.
    /// Input format: SSRC(4), SN(2), TS(4), Marker(1), IP-ID LSBs(1 for 8-bit width).
    fn build_uo1_id_crc_input(
        &self,
        context_ssrc: u32,
        sn: u16,
        ts: u32,
        marker: bool,
        ip_id_lsb: u8,
    ) -> Vec<u8> {
        let mut crc_input = Vec::with_capacity(P1_UO_CRC_INPUT_LENGTH_BYTES + 1); // +1 for IP-ID LSB
        crc_input.extend_from_slice(&context_ssrc.to_be_bytes());
        crc_input.extend_from_slice(&sn.to_be_bytes());
        crc_input.extend_from_slice(&ts.to_be_bytes());
        crc_input.push(if marker { 0x01 } else { 0x00 });
        crc_input.push(ip_id_lsb);
        crc_input
    }
}

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
    /// It determines whether to send an IR or UO packet based on the compressor context state
    /// (e.g., SSRC changes, refresh intervals, current mode IR/FO/SO) and changes in
    /// header fields.
    ///
    /// # Parameters
    /// - `context_dyn`: A mutable reference to a `RohcCompressorContext` (downcast to `Profile1CompressorContext`).
    /// - `headers_generic`: The `GenericUncompressedHeaders` to be compressed (expected to be `RtpUdpIpv4`).
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
    /// This is the main entry point for decompressing Profile 1 packets. It dispatches
    /// to specific handlers based on the current decompressor context mode (NoContext,
    /// StaticContext, FullContext, SecondOrder) and the packet type discriminator.
    ///
    /// **Dispatch Logic:**
    /// 1.  Handles empty packets.
    /// 2.  If in `NoContext` mode: Only IR packets are accepted (calls `decompress_as_ir`); others error.
    /// 3.  If the packet is an IR packet (regardless of current mode): Calls `decompress_as_ir`.
    ///     Successful IR processing transitions the context to `FullContext`.
    /// 4.  If in `StaticContext` mode (and not an IR packet): Returns an error indicating
    ///     SC processing for UO packets is not yet fully implemented (intended for Commit 4).
    /// 5.  If in `SecondOrder` mode (and not an IR packet): Calls `decompress_in_so_state`.
    /// 6.  If in `FullContext` mode (and not an IR packet): Dispatches to `decompress_as_uo0` or
    ///     `decompress_as_uo1_*` based on UO packet type.
    ///
    /// # Parameters
    /// - `context_dyn`: A mutable reference to a `RohcDecompressorContext` (downcast to `Profile1DecompressorContext`).
    /// - `packet_bytes`: A slice containing the core ROHC Profile 1 packet data (after Add-CID stripping).
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

        // 1. Handle NoContext Mode first
        if context.mode == Profile1DecompressorMode::NoContext {
            if (first_byte & !P1_ROHC_IR_PACKET_TYPE_D_BIT_MASK) == P1_ROHC_IR_PACKET_TYPE_BASE {
                return self.decompress_as_ir(context, packet_bytes);
            } else {
                return Err(RohcError::InvalidState(
                    "Non-IR packet received but decompressor is in NoContext mode.".to_string(),
                ));
            }
        }

        // 2. Handle IR packets (can be received in any mode other than NoContext)
        // An IR packet will always attempt to (re)initialize to FullContext.
        if (first_byte & !P1_ROHC_IR_PACKET_TYPE_D_BIT_MASK) == P1_ROHC_IR_PACKET_TYPE_BASE {
            return self.decompress_as_ir(context, packet_bytes);
        }

        // 3. Dispatch based on current mode for non-IR packets
        match context.mode {
            Profile1DecompressorMode::StaticContext => {
                // This method will call appropriate _parse_and_reconstruct_* helpers
                // and manage SC->NC or potential SC->FC transitions.
                self.decompress_in_sc_state(context, packet_bytes)
            }
            Profile1DecompressorMode::SecondOrder => {
                self.decompress_in_so_state(context, packet_bytes)
            }
            Profile1DecompressorMode::FullContext => {
                if (first_byte & P1_UO_1_TS_PACKET_TYPE_PREFIX) == P1_UO_1_TS_PACKET_TYPE_PREFIX {
                    // UO-1
                    if (first_byte & P1_UO_1_TS_TYPE_MASK)
                        == (P1_UO_1_TS_DISCRIMINATOR & P1_UO_1_TS_TYPE_MASK)
                    {
                        self.decompress_as_uo1_ts(context, packet_bytes)
                    } else if first_byte == P1_UO_1_ID_DISCRIMINATOR {
                        self.decompress_as_uo1_id(context, packet_bytes)
                    } else {
                        // UO-1-SN
                        self.decompress_as_uo1_sn(context, packet_bytes)
                    }
                } else if (first_byte & 0x80) == 0x00 {
                    // UO-0
                    self.decompress_as_uo0(context, packet_bytes)
                } else {
                    Err(RohcError::Parsing(RohcParsingError::InvalidPacketType {
                        discriminator: first_byte,
                        profile_id: Some(self.profile_id().into()),
                    }))
                }
            }
            Profile1DecompressorMode::NoContext => {
                // Should be caught by the initial NoContext check above. This is a safeguard.
                Err(RohcError::Internal(
                    "Decompress dispatch reached NoContext unexpectedly after initial check."
                        .to_string(),
                ))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    // Use common test utils if they define create_rtp_headers (adjust path if needed)
    // For simplicity here, re-defining a local version or ensuring it's accessible.
    fn create_test_rtp_headers(sn: u16, ts: u32, marker: bool) -> RtpUdpIpv4Headers {
        RtpUdpIpv4Headers {
            ip_src: "192.168.0.1".parse().unwrap(),
            ip_dst: "192.168.0.2".parse().unwrap(),
            udp_src_port: 10000,
            udp_dst_port: 20000,
            rtp_ssrc: 0x12345678, // Default SSRC for these tests
            rtp_sequence_number: sn,
            rtp_timestamp: ts,
            rtp_marker: marker,
            ip_identification: sn % 256, // Simple IP-ID for testing
            ..Default::default()
        }
    }

    // Helper to setup a context in SO mode for testing decompress_in_so_state
    fn setup_context_in_so_mode(cid: u16) -> Profile1DecompressorContext {
        let mut ctx = Profile1DecompressorContext::new(cid);
        // Manually set to SO state with initial confidence for testing
        ctx.mode = Profile1DecompressorMode::SecondOrder;
        ctx.rtp_ssrc = 0x12345678; // Needs to match create_test_rtp_headers default or be consistent
        ctx.last_reconstructed_rtp_sn_full = 100;
        ctx.last_reconstructed_rtp_ts_full = 1000;
        ctx.last_reconstructed_rtp_marker = false;
        ctx.last_reconstructed_ip_id_full = 100; // Consistent with SN if test packets use SN for IP-ID
        ctx.expected_lsb_sn_width = P1_UO0_SN_LSB_WIDTH_DEFAULT;
        ctx.so_static_confidence = P1_SO_INITIAL_STATIC_CONFIDENCE;
        ctx.so_dynamic_confidence = P1_SO_INITIAL_DYNAMIC_CONFIDENCE;
        ctx.so_packets_received_in_so = 0;
        ctx.so_consecutive_failures = 0;
        ctx.fc_packets_successful_streak = 0;
        ctx
    }

    // Helper to create a default context and then force it into SC mode
    // by simulating P1_DECOMPRESSOR_FC_TO_SC_CRC_FAILURE_THRESHOLD CRC failures on UO-0 packets in FC mode.
    fn setup_context_in_sc_mode_via_fc_failures(cid: u16) -> Profile1DecompressorContext {
        let handler = Profile1Handler::new();
        let mut ctx = Profile1DecompressorContext::new(cid);

        // Simulate initial IR reception to get to FC
        ctx.mode = Profile1DecompressorMode::FullContext;
        ctx.rtp_ssrc = 0x12345678; // Consistent SSRC
        ctx.last_reconstructed_rtp_sn_full = 50;
        ctx.last_reconstructed_rtp_ts_full = 500;
        ctx.last_reconstructed_rtp_marker = false;
        ctx.last_reconstructed_ip_id_full = 50;
        ctx.expected_lsb_sn_width = P1_UO0_SN_LSB_WIDTH_DEFAULT;
        ctx.fc_packets_successful_streak = 0;
        ctx.consecutive_crc_failures_in_fc = 0;
        // Ensure SC counters are initially 0 as if coming from IR/FC setup
        ctx.sc_to_nc_k_failures = 0;
        ctx.sc_to_nc_n_window_count = 0;

        // For SN_LSB=1 (decoded SN typically last_sn+X), assume some CRC for a valid packet.
        // We need a packet that _would_ be valid if not for the CRC.
        // The actual sn_lsb used doesn't matter as much as ensuring a CRC mismatch happens.
        // Create a UO-0 packet that will definitely cause a CRC mismatch.
        // SN LSB from (50+1)%16 = 3 (0b0011), use sn_lsb=3 for consistency with typical next SN
        // Let's say the good CRC for SN=51, SSRC=0x12345678, TS=500, M=false is `good_crc_val`.
        // We'll use `(good_crc_val + 1) % 8` for the bad CRC.
        let decoded_sn_for_fc_fail = ctx.last_reconstructed_rtp_sn_full.wrapping_add(1);
        let good_crc_val = crc::calculate_rohc_crc3(&handler.build_uo_crc_input(
            ctx.rtp_ssrc,
            decoded_sn_for_fc_fail,
            ctx.last_reconstructed_rtp_ts_full,
            ctx.last_reconstructed_rtp_marker,
        ));
        let bad_crc = (good_crc_val + 1) & 0x07;

        let uo0_bad_crc_data = Uo0Packet {
            cid: None,
            sn_lsb: encode_lsb(decoded_sn_for_fc_fail as u64, P1_UO0_SN_LSB_WIDTH_DEFAULT).unwrap()
                as u8,
            crc3: bad_crc,
        };
        let uo0_bad_crc_bytes = build_profile1_uo0_packet(&uo0_bad_crc_data).unwrap();

        for i in 0..P1_DECOMPRESSOR_FC_TO_SC_CRC_FAILURE_THRESHOLD {
            // Call the FC-specific decompressor directly for this setup
            let res = handler.decompress_as_uo0(&mut ctx, &uo0_bad_crc_bytes);
            assert!(
                res.is_err(),
                "UO-0 decompression in FC setup loop iter {} should fail",
                i
            );
        }
        assert_eq!(
            ctx.mode,
            Profile1DecompressorMode::StaticContext,
            "Context should transition to SC mode"
        );
        assert_eq!(
            ctx.sc_to_nc_k_failures, 0,
            "SC k_failures should be 0 upon entering SC"
        );
        assert_eq!(
            ctx.sc_to_nc_n_window_count, 0,
            "SC n_window_count should be 0 upon entering SC"
        );
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

        let mut headers_uo0 = create_test_rtp_headers(101, 1000, false); // TS same, marker same for UO-0
        headers_uo0.ip_identification = headers_ir.ip_identification; // Keep IP-ID same as IR context for UO-0

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
        let mut headers2 = create_test_rtp_headers(11, 100, false); // TS = 100
        headers2.ip_identification = headers1.ip_identification; // Keep IP-ID same for UO-0
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
        let mut headers3 = create_test_rtp_headers(12, 100, false);
        headers3.ip_identification = headers1.ip_identification; // Keep IP-ID same for UO-0
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
    fn decompress_as_uo0_returns_invalid_state_if_not_fc_or_nc_or_sc() {
        let handler = Profile1Handler::new();
        let uo0_bytes = vec![0x08]; // Dummy UO-0 (SN LSB=1, CRC3=0)

        // Test NoContext
        let nc_ctx = Profile1DecompressorContext::new(0);
        // nc_ctx.mode is NoContext by default
        let mut nc_ctx_dyn: Box<dyn RohcDecompressorContext> = Box::new(nc_ctx);
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

        // Test StaticContext
        let mut sc_ctx = Profile1DecompressorContext::new(0);
        sc_ctx.mode = Profile1DecompressorMode::StaticContext;
        sc_ctx.rtp_ssrc = 0x12345678;
        sc_ctx.ip_source = "1.1.1.1".parse().unwrap();

        let mut sc_ctx_dyn: Box<dyn RohcDecompressorContext> = Box::new(sc_ctx);
        let result_sc = handler.decompress(sc_ctx_dyn.as_mut(), &uo0_bytes);

        assert!(
            matches!(result_sc, Err(RohcError::InvalidState(_))),
            "Test failed for SC mode: Expected InvalidState, got {:?}",
            result_sc
        );
        if let Err(RohcError::InvalidState(msg)) = result_sc {
            assert!(
                msg.contains("UO-0 packet received in StaticContext mode"),
                "Error message mismatch for UO-0 in SC. Got: {}",
                msg
            );
        }
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

    #[test]
    fn test_fc_to_sc_transition_and_sc_counter_reset() {
        // This test primarily verifies the end state of the setup helper
        let ctx = setup_context_in_sc_mode_via_fc_failures(0);
        assert_eq!(ctx.mode, Profile1DecompressorMode::StaticContext);
        assert_eq!(ctx.sc_to_nc_k_failures, 0);
        assert_eq!(ctx.sc_to_nc_n_window_count, 0);
        assert_eq!(
            ctx.consecutive_crc_failures_in_fc,
            P1_DECOMPRESSOR_FC_TO_SC_CRC_FAILURE_THRESHOLD
        );
        assert_eq!(ctx.fc_packets_successful_streak, 0); // Should have been reset by failures in FC
    }

    #[test]
    fn test_decompress_in_sc_state_successful_uo1_sn_resets_sc_counters() {
        let handler = Profile1Handler::new();
        let mut ctx = setup_context_in_sc_mode_via_fc_failures(0);
        // Simulate some prior SC activity that might have incremented counters
        ctx.sc_to_nc_k_failures = 1;
        ctx.sc_to_nc_n_window_count = 2;

        // Context values from setup_context_in_sc_mode_via_fc_failures
        let ssrc = ctx.rtp_ssrc; // Should be 0x12345678
        let last_sn = ctx.last_reconstructed_rtp_sn_full; // Should be 50 (or 50 + FC_THRESHOLD)
        let last_ts = ctx.last_reconstructed_rtp_ts_full; // Should be 500

        // Create a valid UO-1-SN packet for SN = last_sn + 1, Marker true
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
            "Decompression in SC should succeed for valid UO-1-SN: {:?}",
            result.err()
        );

        let final_ctx = ctx_dyn
            .as_any()
            .downcast_ref::<Profile1DecompressorContext>()
            .unwrap();
        assert_eq!(
            final_ctx.mode,
            Profile1DecompressorMode::StaticContext,
            "Should remain in SC after UO-1 (conservative approach)"
        );
        assert_eq!(final_ctx.last_reconstructed_rtp_sn_full, next_sn);
        assert_eq!(final_ctx.last_reconstructed_rtp_marker, new_marker);
        assert_eq!(
            final_ctx.sc_to_nc_k_failures, 0,
            "SC k_failures should be reset on success in SC"
        );
        assert_eq!(
            final_ctx.sc_to_nc_n_window_count, 0,
            "SC n_window_count should be reset on success in SC"
        );
    }

    #[test]
    fn test_decompress_in_sc_state_uo0_packet_is_invalid_state() {
        let handler = Profile1Handler::new();
        let mut ctx = setup_context_in_sc_mode_via_fc_failures(0);
        ctx.sc_to_nc_k_failures = 0; // Ensure clean state for this test
        ctx.sc_to_nc_n_window_count = 0;

        let uo0_data = Uo0Packet {
            cid: None,
            sn_lsb: 1,
            crc3: 0,
        };
        let packet_bytes = build_profile1_uo0_packet(&uo0_data).unwrap();

        let mut ctx_dyn: Box<dyn RohcDecompressorContext> = Box::new(ctx);
        let result = handler.decompress(ctx_dyn.as_mut(), &packet_bytes);

        assert!(
            matches!(result, Err(RohcError::InvalidState(ref msg)) if msg.contains("UO-0 packet received in StaticContext mode")),
            "Expected InvalidState for UO-0 in SC, got {:?}",
            result
        );

        let final_ctx = ctx_dyn
            .as_any()
            .downcast_ref::<Profile1DecompressorContext>()
            .unwrap();
        assert_eq!(final_ctx.mode, Profile1DecompressorMode::StaticContext);
        assert_eq!(
            final_ctx.sc_to_nc_n_window_count, 1,
            "N_window count should increment for UO-0 attempt in SC"
        );
        assert_eq!(
            final_ctx.sc_to_nc_k_failures, 0,
            "K_failures should NOT increment for UO-0 InvalidState in SC"
        );
    }

    #[test]
    fn test_decompress_in_sc_state_transitions_to_nc_on_k2_n2_failures() {
        let handler = Profile1Handler::new();
        // Use constants directly for K2/N2, ensure they are small for testing
        const TEST_K2: u8 = P1_DECOMPRESSOR_SC_TO_NC_K2;

        let ctx = setup_context_in_sc_mode_via_fc_failures(0);
        // Static fields are set by setup_context_in_sc_mode_via_fc_failures
        // Dynamic fields would be unreliable in SC, so we are testing failure to update them.

        let uo1_bad_crc_data = Uo1Packet {
            cid: None,
            sn_lsb: 1, // Arbitrary LSBs
            num_sn_lsb_bits: P1_UO1_SN_LSB_WIDTH_DEFAULT,
            marker: false,
            crc8: 0, // Intentionally bad CRC
            ..Default::default()
        };
        let packet_bytes_bad_crc = build_profile1_uo1_sn_packet(&uo1_bad_crc_data).unwrap();

        let mut ctx_dyn: Box<dyn RohcDecompressorContext> = Box::new(ctx);

        // Cause exactly K2 failures within N2 packets
        for i in 0..TEST_K2 {
            let result = handler.decompress(ctx_dyn.as_mut(), &packet_bytes_bad_crc);
            assert!(
                result.is_err(),
                "Decompression of bad UO-1-SN in SC should fail on iter {}",
                i
            );
        }

        let final_ctx_after_k2_fails = ctx_dyn
            .as_any()
            .downcast_ref::<Profile1DecompressorContext>()
            .unwrap();
        assert_eq!(
            final_ctx_after_k2_fails.mode,
            Profile1DecompressorMode::NoContext,
            "Should transition to NC after K2 failures"
        );
        assert_eq!(
            final_ctx_after_k2_fails.sc_to_nc_k_failures, 0,
            "K_failures reset by NC transition"
        );
        assert_eq!(
            final_ctx_after_k2_fails.sc_to_nc_n_window_count, 0,
            "N_window count reset by NC transition"
        );
    }

    #[test]
    fn test_decompress_in_sc_state_n2_window_resets_without_nc_if_k2_not_met() {
        let handler = Profile1Handler::new();
        const TEST_K2: u8 = P1_DECOMPRESSOR_SC_TO_NC_K2;
        const TEST_N2: u8 = P1_DECOMPRESSOR_SC_TO_NC_N2;

        let ctx = setup_context_in_sc_mode_via_fc_failures(0);

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
                (ctx.last_reconstructed_rtp_sn_full + 10) as u64,
                P1_UO1_SN_LSB_WIDTH_DEFAULT,
            )
            .unwrap() as u16,
            num_sn_lsb_bits: P1_UO1_SN_LSB_WIDTH_DEFAULT,
            marker: true,
            crc8: crc::calculate_rohc_crc8(&handler.build_uo_crc_input(
                ctx.rtp_ssrc,
                ctx.last_reconstructed_rtp_sn_full + 10,
                ctx.last_reconstructed_rtp_ts_full,
                true,
            )),
            ..Default::default()
        };
        let packet_bytes_good = build_profile1_uo1_sn_packet(&good_uo1_sn_data).unwrap();

        let mut ctx_dyn: Box<dyn RohcDecompressorContext> = Box::new(ctx);

        // Cause K2-1 failures
        for _ in 0..(TEST_K2 - 1) {
            assert!(
                handler
                    .decompress(ctx_dyn.as_mut(), &packet_bytes_bad_crc)
                    .is_err()
            );
        }

        let ctx_snapshot1 = ctx_dyn
            .as_any()
            .downcast_ref::<Profile1DecompressorContext>()
            .unwrap();
        assert_eq!(ctx_snapshot1.sc_to_nc_k_failures, TEST_K2 - 1);
        assert_eq!(ctx_snapshot1.sc_to_nc_n_window_count, TEST_K2 - 1);
        assert_eq!(ctx_snapshot1.mode, Profile1DecompressorMode::StaticContext);

        // Send successful packets until N2 window is full, ensuring we don't hit K2 failures
        for _ in (TEST_K2 - 1)..TEST_N2 {
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
            "Should remain SC as K2 threshold not hit in window"
        );
        assert_eq!(
            final_ctx.sc_to_nc_k_failures, 0,
            "K_failures should reset after N2 window without NC transition"
        );
        assert_eq!(
            final_ctx.sc_to_nc_n_window_count, 0,
            "N_window_count should reset after N2 window without NC transition"
        );
    }

    #[test]
    fn test_ir_reception_in_sc_transitions_to_fc() {
        let handler = Profile1Handler::new();
        let ctx = setup_context_in_sc_mode_via_fc_failures(0); // ctx is now in SC

        // Values to be updated by IR
        let new_ssrc = ctx.rtp_ssrc.wrapping_add(1); // Ensure IR updates SSRC
        let new_sn = ctx.last_reconstructed_rtp_sn_full.wrapping_add(100);
        let new_ts = ctx.last_reconstructed_rtp_ts_full.wrapping_add(1000);

        let ir_data = IrPacket {
            cid: ctx.cid,
            profile_id: RohcProfile::RtpUdpIp,
            static_ip_src: ctx.ip_source, // Keep static part same for simplicity of test focus
            static_ip_dst: ctx.ip_destination,
            static_udp_src_port: ctx.udp_source_port,
            static_udp_dst_port: ctx.udp_destination_port,
            static_rtp_ssrc: new_ssrc,
            dyn_rtp_sn: new_sn,
            dyn_rtp_timestamp: new_ts,
            dyn_rtp_marker: true,
            crc8: 0, // Will be calculated
        };
        let ir_packet_bytes = build_profile1_ir_packet(&ir_data).unwrap();

        let mut ctx_dyn: Box<dyn RohcDecompressorContext> = Box::new(ctx);
        let result = handler.decompress(ctx_dyn.as_mut(), &ir_packet_bytes);
        assert!(
            result.is_ok(),
            "IR decompression failed: {:?}",
            result.err()
        );

        let final_ctx = ctx_dyn
            .as_any()
            .downcast_ref::<Profile1DecompressorContext>()
            .unwrap();
        assert_eq!(
            final_ctx.mode,
            Profile1DecompressorMode::FullContext,
            "Receiving IR in SC should transition to FC"
        );
        assert_eq!(final_ctx.rtp_ssrc, new_ssrc);
        assert_eq!(final_ctx.last_reconstructed_rtp_sn_full, new_sn);
        assert_eq!(final_ctx.fc_packets_successful_streak, 0);
        assert_eq!(final_ctx.so_dynamic_confidence, 0);
        assert_eq!(final_ctx.sc_to_nc_k_failures, 0);
        assert_eq!(final_ctx.sc_to_nc_n_window_count, 0);
    }

    #[test]
    fn test_decompress_in_so_state_successful_uo0_updates_confidence() {
        let handler = Profile1Handler::new();
        let mut ctx = setup_context_in_so_mode(0);
        let initial_dynamic_confidence = ctx.so_dynamic_confidence;
        let initial_packets_in_so = ctx.so_packets_received_in_so;

        // For SN_LSB=1 (decoded SN=113 in this context), calculated CRC3 is 7.
        let uo0_data = Uo0Packet {
            cid: None,
            sn_lsb: 1,
            crc3: 7, // Correct CRC for SN_LSB=1 -> SN=113
        };
        let packet_bytes = build_profile1_uo0_packet(&uo0_data).unwrap();

        let result = handler.decompress_in_so_state(&mut ctx, &packet_bytes);
        assert!(
            result.is_ok(),
            "Decompression in SO failed for valid UO-0: {:?}",
            result.err()
        );

        let headers = result.unwrap().as_rtp_udp_ipv4().unwrap().clone();
        assert_eq!(headers.rtp_sequence_number, 113); // Check based on setup_context_in_so_mode's last_sn and LSB decoding

        assert_eq!(
            ctx.mode,
            Profile1DecompressorMode::SecondOrder,
            "Should remain in SO mode"
        );
        assert_eq!(
            ctx.so_dynamic_confidence,
            initial_dynamic_confidence + P1_SO_SUCCESS_CONFIDENCE_BOOST
        );
        assert_eq!(ctx.so_consecutive_failures, 0);
        assert_eq!(ctx.so_packets_received_in_so, initial_packets_in_so + 1);
    }

    #[test]
    fn test_decompress_in_so_state_failure_crc_mismatch_uo0_penalizes_confidence() {
        let handler = Profile1Handler::new();
        let mut ctx = setup_context_in_so_mode(0);
        let initial_dynamic_confidence = ctx.so_dynamic_confidence;

        // For SN_LSB=1 (decoded SN=113), calculated CRC3 is 7. We set packet CRC3 to 0 for mismatch.
        let uo0_data_bad_crc = Uo0Packet {
            cid: None,
            sn_lsb: 1,
            crc3: 0,
        };
        let packet_bytes_bad_crc = build_profile1_uo0_packet(&uo0_data_bad_crc).unwrap();

        let result = handler.decompress_in_so_state(&mut ctx, &packet_bytes_bad_crc);
        assert!(result.is_err(), "Decompression should fail due to CRC");
        assert!(
            matches!(result.unwrap_err(), RohcError::Parsing(RohcParsingError::CrcMismatch { calculated, expected, .. }) if calculated == 7 && expected == 0 )
        );

        assert_eq!(
            ctx.mode,
            Profile1DecompressorMode::SecondOrder,
            "Should remain in SO (unless threshold for NC hit)"
        );
        assert_eq!(
            ctx.so_dynamic_confidence,
            initial_dynamic_confidence.saturating_sub(P1_SO_FAILURE_CONFIDENCE_PENALTY)
        );
        assert_eq!(ctx.so_consecutive_failures, 1);
    }

    #[test]
    fn test_decompress_in_so_state_transitions_to_nc_on_max_failures() {
        let handler = Profile1Handler::new();
        let mut ctx = setup_context_in_so_mode(0);
        ctx.so_dynamic_confidence = (P1_SO_MAX_CONSECUTIVE_FAILURES
            * P1_SO_FAILURE_CONFIDENCE_PENALTY)
            + P1_SO_TO_NC_CONFIDENCE_THRESHOLD;

        let uo0_data_bad_crc = Uo0Packet {
            cid: None,
            sn_lsb: 1,
            crc3: 0,
        }; // Bad CRC (calc is 7)
        let packet_bytes_bad_crc = build_profile1_uo0_packet(&uo0_data_bad_crc).unwrap();

        for i in 0..P1_SO_MAX_CONSECUTIVE_FAILURES {
            let mode_before_this_iteration = ctx.mode.clone();
            let result = handler.decompress_in_so_state(&mut ctx, &packet_bytes_bad_crc);
            assert!(
                result.is_err(),
                "Decompression should fail on iteration {}. Mode before: {:?}",
                i,
                mode_before_this_iteration
            );

            if i < P1_SO_MAX_CONSECUTIVE_FAILURES - 1
                && mode_before_this_iteration == Profile1DecompressorMode::SecondOrder
            {
                assert_eq!(
                    ctx.mode,
                    Profile1DecompressorMode::SecondOrder,
                    "Should stay SO. Iter: {}, Fails: {}, Conf: {}",
                    i,
                    ctx.so_consecutive_failures,
                    ctx.so_dynamic_confidence
                );
            }
        }
        assert_eq!(
            ctx.mode,
            Profile1DecompressorMode::NoContext,
            "Should transition to NC. Final Fails: {}, Final Conf (before reset): {}",
            ctx.so_consecutive_failures,
            ctx.so_dynamic_confidence
        );
        assert_eq!(ctx.so_consecutive_failures, 0);
        assert_eq!(ctx.so_dynamic_confidence, 0);
        assert_eq!(ctx.last_reconstructed_rtp_sn_full, 0);
    }

    #[test]
    fn test_decompress_in_so_state_transitions_to_nc_on_low_confidence() {
        let handler = Profile1Handler::new();
        let mut ctx = setup_context_in_so_mode(0);
        ctx.so_dynamic_confidence =
            P1_SO_TO_NC_CONFIDENCE_THRESHOLD + P1_SO_FAILURE_CONFIDENCE_PENALTY - 1;
        let confidence_before_failure_trigger = ctx.so_dynamic_confidence;
        ctx.so_consecutive_failures = 0;

        let uo0_data_bad_crc = Uo0Packet {
            cid: None,
            sn_lsb: 1,
            crc3: 0,
        }; // Bad CRC (calc is 7)
        let packet_bytes_bad_crc = build_profile1_uo0_packet(&uo0_data_bad_crc).unwrap();

        let result = handler.decompress_in_so_state(&mut ctx, &packet_bytes_bad_crc);
        assert!(
            result.is_err(),
            "Decompression expected to fail. Result: {:?}",
            result
        );

        assert_eq!(
            ctx.mode,
            Profile1DecompressorMode::NoContext,
            "Should transition to NC. Conf before fail: {}, after fail (then reset): {}, threshold: {}",
            confidence_before_failure_trigger,
            ctx.so_dynamic_confidence, // This will be 0 due to reset
            P1_SO_TO_NC_CONFIDENCE_THRESHOLD
        );
        assert_eq!(ctx.so_dynamic_confidence, 0);
        assert_eq!(ctx.so_consecutive_failures, 0);
    }

    #[test]
    fn test_decompress_in_so_state_ir_packet_reception_via_main_decompress() {
        let handler = Profile1Handler::new();
        let ctx_so = setup_context_in_so_mode(0);

        let ir_data = IrPacket {
            cid: 0,
            profile_id: RohcProfile::RtpUdpIp,
            static_rtp_ssrc: 0xABCDEFFF,
            dyn_rtp_sn: 500,
            dyn_rtp_timestamp: 50000,
            dyn_rtp_marker: false,
            static_ip_src: "10.0.0.10".parse().unwrap(),
            ..Default::default()
        };
        let ir_packet_bytes = build_profile1_ir_packet(&ir_data).unwrap();

        let mut ctx_dyn: Box<dyn RohcDecompressorContext> = Box::new(ctx_so);
        let result = handler.decompress(ctx_dyn.as_mut(), &ir_packet_bytes);
        assert!(
            result.is_ok(),
            "IR decompression failed: {:?}",
            result.err()
        );

        let final_ctx = ctx_dyn
            .as_any()
            .downcast_ref::<Profile1DecompressorContext>()
            .unwrap();
        assert_eq!(final_ctx.mode, Profile1DecompressorMode::FullContext);
        assert_eq!(final_ctx.rtp_ssrc, 0xABCDEFFF);
        assert_eq!(final_ctx.fc_packets_successful_streak, 0);
        assert_eq!(final_ctx.so_dynamic_confidence, 0);
    }
}
