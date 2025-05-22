//! Handler for ROHC Profile 1 (RTP/UDP/IP - RFC 3095, RFC 3843) specific logic.
//!
//! This module encapsulates the compression and decompression algorithms,
//! context management specifics, and packet processing rules tailored for
//! ROHC Profile 0x0001.
use crate::RtpUdpIpv4Headers;
use crate::constants::*;
use crate::context::{
    CompressorMode as P1CompressorMode, DecompressorMode as P1DecompressorMode,
    RtpUdpIpP1CompressorContext, RtpUdpIpP1DecompressorContext,
};
use crate::crc;
use crate::encodings::{decode_lsb, encode_lsb, value_in_lsb_interval};
use crate::error::{RohcError, RohcParsingError};
use crate::packet_defs::{GenericUncompressedHeaders, RohcIrProfile1Packet, RohcProfile};
use crate::packet_processor::{
    build_ir_profile1_packet, build_uo0_profile1_cid0_packet, build_uo1_sn_profile1_packet,
    parse_ir_profile1_packet, parse_uo0_profile1_cid0_packet, parse_uo1_sn_profile1_packet,
};
use crate::traits::{ProfileHandler, RohcCompressorContext, RohcDecompressorContext};

/// Implements the `ProfileHandler` trait for ROHC Profile 0x0001 (RTP/UDP/IP).
///
/// This struct is stateless itself; all state is managed within the
/// `RtpUdpIpP1CompressorContext` and `RtpUdpIpP1DecompressorContext` instances
/// passed to its methods.
#[derive(Debug, Default)]
pub struct Profile1Handler;

impl Profile1Handler {
    /// Creates a new instance of the Profile 1 handler.
    pub fn new() -> Self {
        Profile1Handler
    }

    /// Reconstructs uncompressed RTP/UDP/IPv4 headers from a parsed Profile 1 IR packet.
    fn reconstruct_headers_from_p1_ir(
        &self,
        ir_packet: &RohcIrProfile1Packet,
    ) -> RtpUdpIpv4Headers {
        RtpUdpIpv4Headers {
            ip_src: ir_packet.static_ip_src,
            ip_dst: ir_packet.static_ip_dst,
            udp_src_port: ir_packet.static_udp_src_port,
            udp_dst_port: ir_packet.static_udp_dst_port,
            rtp_ssrc: ir_packet.static_rtp_ssrc,
            rtp_sequence_number: ir_packet.dyn_rtp_sn,
            rtp_timestamp: ir_packet.dyn_rtp_timestamp,
            rtp_marker: ir_packet.dyn_rtp_marker,
            ip_protocol: IP_PROTOCOL_UDP,
            rtp_version: RTP_VERSION,
            ip_ihl: 5,
            ip_ttl: 64, // Default, not conveyed by P1 IR for this field
            ..Default::default()
        }
    }

    /// Processes a parsed IR packet for Profile 1.
    fn handle_p1_ir_packet(
        &self,
        context: &mut RtpUdpIpP1DecompressorContext, // Concrete context type
        parsed_ir: RohcIrProfile1Packet, // CID within parsed_ir is from parser (0 if no Add-CID)
                                         // context.cid() is the true CID for this context instance
    ) -> Result<RtpUdpIpv4Headers, RohcError> {
        // The dispatcher should have already set context.cid correctly.
        // initialize_from_ir_packet will use the fields from parsed_ir.
        // We need to ensure the parsed_ir's profile matches if we check it here.
        debug_assert_eq!(
            parsed_ir.profile,
            RohcProfile::RtpUdpIp,
            "IR packet profile mismatch for P1Handler"
        );

        context.initialize_from_ir_packet(&parsed_ir);
        context.consecutive_crc_failures_in_fc = 0;
        Ok(self.reconstruct_headers_from_p1_ir(&parsed_ir))
    }

    /// Creates the byte sequence from reconstructed header fields for UO-packet CRC verification.
    fn create_crc_input_for_p1_uo_verification(
        &self,
        context: &RtpUdpIpP1DecompressorContext,
        reconstructed_sn: u16,
        reconstructed_ts: u32,
        reconstructed_marker: bool,
    ) -> Vec<u8> {
        let mut crc_input = Vec::with_capacity(11);
        crc_input.extend_from_slice(&context.rtp_ssrc.to_be_bytes());
        crc_input.extend_from_slice(&reconstructed_sn.to_be_bytes());
        crc_input.extend_from_slice(&reconstructed_ts.to_be_bytes());
        crc_input.push(if reconstructed_marker { 0x01 } else { 0x00 });
        crc_input
    }

    /// Processes a parsed UO-0 packet for Profile 1.
    fn handle_p1_uo0_packet(
        &self,
        context: &mut RtpUdpIpP1DecompressorContext, // Concrete context type
        core_packet_slice: &[u8],
    ) -> Result<RtpUdpIpv4Headers, RohcError> {
        if context.mode != P1DecompressorMode::FullContext {
            return Err(RohcError::InvalidState(
                "P1: Received UO-0 packet but decompressor is not in Full Context mode."
                    .to_string(),
            ));
        }

        let parsed_uo0 =
            parse_uo0_profile1_cid0_packet(core_packet_slice).map_err(RohcError::Parsing)?;

        let reconstructed_sn = decode_lsb(
            parsed_uo0.sn_lsb as u64,
            context.last_reconstructed_rtp_sn_full as u64,
            context.expected_lsb_sn_width,
            context.p_sn,
        )
        .map_err(RohcError::Parsing)? as u16;

        let reconstructed_ts_for_header = context.last_reconstructed_rtp_ts_full;
        let reconstructed_marker_for_header = context.last_reconstructed_rtp_marker;

        let reconstructed_headers = RtpUdpIpv4Headers {
            ip_src: context.ip_source,
            ip_dst: context.ip_destination,
            udp_src_port: context.udp_source_port,
            udp_dst_port: context.udp_destination_port,
            rtp_ssrc: context.rtp_ssrc,
            rtp_sequence_number: reconstructed_sn,
            rtp_timestamp: reconstructed_ts_for_header,
            rtp_marker: reconstructed_marker_for_header,
            ip_protocol: IP_PROTOCOL_UDP,
            rtp_version: RTP_VERSION,
            ip_ihl: 5,
            ip_ttl: 64,
            ..Default::default()
        };

        let crc_payload_bytes = self.create_crc_input_for_p1_uo_verification(
            context,
            reconstructed_sn,
            context.last_reconstructed_rtp_ts_full, // TS for CRC from context
            context.last_reconstructed_rtp_marker,  // Marker for CRC from context
        );
        let calculated_crc3 = crc::calculate_rohc_crc3(&crc_payload_bytes);

        if calculated_crc3 == parsed_uo0.crc3 {
            context.last_reconstructed_rtp_sn_full = reconstructed_sn;
            context.consecutive_crc_failures_in_fc = 0;
            Ok(reconstructed_headers)
        } else {
            context.consecutive_crc_failures_in_fc += 1;
            if context.consecutive_crc_failures_in_fc >= DECOMPRESSOR_FC_TO_SC_CRC_FAILURE_THRESHOLD
            {
                context.mode = P1DecompressorMode::StaticContext;
            }
            Err(RohcError::Parsing(RohcParsingError::CrcMismatch {
                expected: parsed_uo0.crc3,
                calculated: calculated_crc3,
            }))
        }
    }

    /// Processes a parsed UO-1-SN packet for Profile 1.
    fn handle_p1_uo1_sn_packet(
        &self,
        context: &mut RtpUdpIpP1DecompressorContext, // Concrete context type
        core_packet_slice: &[u8],
    ) -> Result<RtpUdpIpv4Headers, RohcError> {
        if context.mode != P1DecompressorMode::FullContext {
            return Err(RohcError::InvalidState(
                "P1: Received UO-1 packet but decompressor is not in Full Context mode."
                    .to_string(),
            ));
        }

        let parsed_uo1 =
            parse_uo1_sn_profile1_packet(core_packet_slice).map_err(RohcError::Parsing)?;

        let reconstructed_sn = decode_lsb(
            parsed_uo1.sn_lsb as u64,
            context.last_reconstructed_rtp_sn_full as u64,
            parsed_uo1.num_sn_lsb_bits,
            context.p_sn,
        )
        .map_err(RohcError::Parsing)? as u16;

        let reconstructed_marker_for_header = parsed_uo1.rtp_marker_bit_value.ok_or_else(|| {
            RohcError::Parsing(RohcParsingError::MandatoryFieldMissing {
                field_name: "P1: UO-1-SN Marker bit".to_string(),
            })
        })?;
        let reconstructed_ts_for_header = context.last_reconstructed_rtp_ts_full;

        let reconstructed_headers = RtpUdpIpv4Headers {
            ip_src: context.ip_source,
            ip_dst: context.ip_destination,
            udp_src_port: context.udp_source_port,
            udp_dst_port: context.udp_destination_port,
            rtp_ssrc: context.rtp_ssrc,
            rtp_sequence_number: reconstructed_sn,
            rtp_timestamp: reconstructed_ts_for_header,
            rtp_marker: reconstructed_marker_for_header,
            ip_protocol: IP_PROTOCOL_UDP,
            rtp_version: RTP_VERSION,
            ip_ihl: 5,
            ip_ttl: 64,
            ..Default::default()
        };

        let crc_payload_bytes = self.create_crc_input_for_p1_uo_verification(
            context,
            reconstructed_sn,
            context.last_reconstructed_rtp_ts_full, // TS for CRC from context
            reconstructed_marker_for_header,        // Marker for CRC from packet
        );
        let calculated_crc8 = crc::calculate_rohc_crc8(&crc_payload_bytes);

        if calculated_crc8 == parsed_uo1.crc8 {
            context.last_reconstructed_rtp_sn_full = reconstructed_sn;
            context.last_reconstructed_rtp_marker = reconstructed_marker_for_header;
            context.consecutive_crc_failures_in_fc = 0;
            Ok(reconstructed_headers)
        } else {
            context.consecutive_crc_failures_in_fc += 1;
            if context.consecutive_crc_failures_in_fc >= DECOMPRESSOR_FC_TO_SC_CRC_FAILURE_THRESHOLD
            {
                context.mode = P1DecompressorMode::StaticContext;
            }
            Err(RohcError::Parsing(RohcParsingError::CrcMismatch {
                expected: parsed_uo1.crc8,
                calculated: calculated_crc8,
            }))
        }
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
        Box::new(RtpUdpIpP1CompressorContext::new(
            cid,
            self.profile_id(),
            ir_refresh_interval,
        ))
    }

    fn create_decompressor_context(&self, cid: u16) -> Box<dyn RohcDecompressorContext> {
        Box::new(RtpUdpIpP1DecompressorContext::new(cid, self.profile_id()))
    }

    fn compress(
        &self,
        context_dyn: &mut dyn RohcCompressorContext,
        headers_generic: &GenericUncompressedHeaders,
    ) -> Result<Vec<u8>, RohcError> {
        let context = context_dyn
            .as_any_mut()
            .downcast_mut::<RtpUdpIpP1CompressorContext>()
            .ok_or_else(|| {
                RohcError::Internal("P1Handler::compress: incorrect context type".to_string())
            })?;

        debug_assert_eq!(
            context.profile_id(),
            self.profile_id(),
            "Context profile mismatch"
        );

        let GenericUncompressedHeaders::RtpUdpIpv4(uncompressed_headers) = headers_generic;

        let mut force_ir_due_to_refresh = false;
        if context.mode == P1CompressorMode::FirstOrder
            && context.ir_refresh_interval > 0
            && context.fo_packets_sent_since_ir >= (context.ir_refresh_interval.saturating_sub(1))
        {
            force_ir_due_to_refresh = true;
        }

        let should_send_ir_packet =
            context.mode == P1CompressorMode::InitializationAndRefresh || force_ir_due_to_refresh;

        if should_send_ir_packet {
            let ir_data = RohcIrProfile1Packet {
                cid: context.cid,
                profile: self.profile_id(),
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

            if context.mode == P1CompressorMode::InitializationAndRefresh {
                // Initialize static part if context appears "new"
                if context.rtp_ssrc == 0 && context.ip_source.is_unspecified() {
                    context.ip_source = uncompressed_headers.ip_src;
                    context.ip_destination = uncompressed_headers.ip_dst;
                    context.udp_source_port = uncompressed_headers.udp_src_port;
                    context.udp_destination_port = uncompressed_headers.udp_dst_port;
                    context.rtp_ssrc = uncompressed_headers.rtp_ssrc;
                }
            }

            let rohc_packet_bytes = build_ir_profile1_packet(&ir_data)?;

            context.last_sent_rtp_sn_full = uncompressed_headers.rtp_sequence_number;
            context.last_sent_rtp_ts_full = uncompressed_headers.rtp_timestamp;
            context.last_sent_rtp_marker = uncompressed_headers.rtp_marker;
            context.mode = P1CompressorMode::FirstOrder;
            context.fo_packets_sent_since_ir = 0;

            Ok(rohc_packet_bytes)
        } else {
            // UO packet logic
            let current_sn = uncompressed_headers.rtp_sequence_number;
            let current_marker = uncompressed_headers.rtp_marker;

            let marker_changed = current_marker != context.last_sent_rtp_marker;
            let uo0_can_represent_sn = value_in_lsb_interval(
                current_sn as u64,
                context.last_sent_rtp_sn_full as u64,
                DEFAULT_PROFILE1_UO0_SN_LSB_WIDTH,
                0,
            );

            let core_rohc_packet_bytes: Vec<u8>; // Holds UO-0 or UO-1-SN *without* Add-CID

            if !marker_changed && uo0_can_represent_sn {
                // Build UO-0 packet (core)
                context.current_lsb_sn_width = DEFAULT_PROFILE1_UO0_SN_LSB_WIDTH;
                let sn_lsb_for_uo0 = encode_lsb(current_sn as u64, context.current_lsb_sn_width)
                    .map_err(|e| {
                        RohcError::Internal(format!("P1: SN LSB encoding for UO-0 failed: {}", e))
                    })? as u8;

                let mut crc_input_for_uo0 = Vec::with_capacity(11);
                crc_input_for_uo0.extend_from_slice(&context.rtp_ssrc.to_be_bytes());
                crc_input_for_uo0.extend_from_slice(&current_sn.to_be_bytes());
                crc_input_for_uo0.extend_from_slice(&context.last_sent_rtp_ts_full.to_be_bytes());
                crc_input_for_uo0.push(if context.last_sent_rtp_marker {
                    0x01
                } else {
                    0x00
                });

                let crc3_value = crc::calculate_rohc_crc3(&crc_input_for_uo0);
                core_rohc_packet_bytes =
                    build_uo0_profile1_cid0_packet(sn_lsb_for_uo0, crc3_value)?;
            } else {
                // Build UO-1-SN packet (core)
                let uo1_sn_lsb_width = DEFAULT_PROFILE1_UO1_SN_LSB_WIDTH;
                let sn_8_lsb = encode_lsb(current_sn as u64, uo1_sn_lsb_width).map_err(|e| {
                    RohcError::Internal(format!("P1: SN LSB encoding for UO-1 failed: {}", e))
                })? as u8;

                let mut crc_input_for_uo1_sn = Vec::with_capacity(11);
                crc_input_for_uo1_sn.extend_from_slice(&context.rtp_ssrc.to_be_bytes());
                crc_input_for_uo1_sn.extend_from_slice(&current_sn.to_be_bytes());
                crc_input_for_uo1_sn
                    .extend_from_slice(&context.last_sent_rtp_ts_full.to_be_bytes());
                crc_input_for_uo1_sn.push(if current_marker { 0x01 } else { 0x00 });

                let crc8_value = crc::calculate_rohc_crc8(&crc_input_for_uo1_sn);
                core_rohc_packet_bytes =
                    build_uo1_sn_profile1_packet(sn_8_lsb, current_marker, crc8_value)?;
                context.current_lsb_sn_width = uo1_sn_lsb_width;
            }

            // --- Prepend Add-CID octet if necessary for UO packets ---
            let final_rohc_packet_bytes = if context.cid > 0 && context.cid <= 15 {
                let mut framed_packet = Vec::with_capacity(core_rohc_packet_bytes.len() + 1);
                framed_packet.push(
                    ADD_CID_OCTET_PREFIX_VALUE | (context.cid as u8 & ADD_CID_OCTET_CID_MASK),
                );
                framed_packet.extend_from_slice(&core_rohc_packet_bytes);
                framed_packet
            } else if context.cid > 15 {
                // Large CIDs for UO packets are not handled by simple Add-CID octet
                // and require different packet formats (e.g., UO-2 or IR-DYN with large CID).
                // This indicates an issue if we try to send UO-0/UO-1 for large CID here.
                // For now, error or send IR. Let's assume IR would have been forced earlier or this is an error state.
                return Err(RohcError::Internal(format!(
                    "P1: UO packet compression attempted for large CID {}",
                    context.cid
                )));
            } else {
                // CID == 0
                core_rohc_packet_bytes
            };

            // Update compressor context state
            context.last_sent_rtp_sn_full = current_sn;
            context.last_sent_rtp_marker = current_marker;
            // context.last_sent_rtp_ts_full is NOT updated for UO-0/UO-1-SN
            context.fo_packets_sent_since_ir += 1;

            Ok(final_rohc_packet_bytes)
        }
    }

    fn decompress(
        &self,
        context_dyn: &mut dyn RohcDecompressorContext,
        rohc_packet_core_bytes: &[u8],
    ) -> Result<GenericUncompressedHeaders, RohcError> {
        let context = context_dyn
            .as_any_mut()
            .downcast_mut::<RtpUdpIpP1DecompressorContext>()
            .ok_or_else(|| {
                RohcError::Internal("P1Handler::decompress: incorrect context type".to_string())
            })?;

        debug_assert_eq!(
            context.profile_id(),
            self.profile_id(),
            "Context profile mismatch"
        );
        // Caller (engine/manager) must ensure context.cid() is correct before calling.

        if rohc_packet_core_bytes.is_empty() {
            return Err(RohcError::Parsing(RohcParsingError::NotEnoughData {
                needed: 1,
                got: 0,
            }));
        }

        let first_byte = rohc_packet_core_bytes[0];
        // The RohcPacketDiscriminator can be used here, but the original dispatcher logic
        // was already quite specific to P1 packet types. We can translate that directly.
        // This internal dispatch within P1 handler is fine. A generic engine might use
        // RohcPacketDiscriminator before calling the profile handler.

        if (first_byte & !ROHC_IR_PACKET_TYPE_D_BIT_MASK) == ROHC_IR_PACKET_TYPE_BASE {
            let parsed_ir =
                parse_ir_profile1_packet(rohc_packet_core_bytes).map_err(RohcError::Parsing)?;
            // The parsed_ir.cid from parser might be 0. The context.cid() is the authoritative one.
            // We pass the parsed_ir and the context's current CID to handle_p1_ir_packet
            // if handle_p1_ir_packet was designed to take an explicit CID to set.
            // However, our current RtpUdpIpP1DecompressorContext::initialize_from_ir_packet
            // uses fields from parsed_ir, and context.cid is already set by the manager.
            // We must ensure parsed_ir.profile matches this handler.
            if parsed_ir.profile != self.profile_id() {
                return Err(RohcError::Parsing(RohcParsingError::InvalidProfileId(
                    parsed_ir.profile.into(),
                )));
            }
            self.handle_p1_ir_packet(context, parsed_ir)
                .map(GenericUncompressedHeaders::RtpUdpIpv4)
        } else if (first_byte & 0xF0) == UO_1_SN_P1_PACKET_TYPE_BASE {
            // UO-1-SN
            self.handle_p1_uo1_sn_packet(context, rohc_packet_core_bytes)
                .map(GenericUncompressedHeaders::RtpUdpIpv4)
        } else if (first_byte & 0x80) == 0x00 {
            // UO-0 for CID 0 (or after Add-CID stripped)
            self.handle_p1_uo0_packet(context, rohc_packet_core_bytes)
                .map(GenericUncompressedHeaders::RtpUdpIpv4)
        } else {
            Err(RohcError::Parsing(RohcParsingError::InvalidPacketType(
                first_byte,
            )))
        }
    }
}
