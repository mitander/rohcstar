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
    parse_profile1_ir_packet, parse_profile1_uo0_packet, parse_profile1_uo1_sn_packet,
};
use super::packet_types::{IrPacket, Uo0Packet, Uo1Packet};
use super::protocol_types::RtpUdpIpv4Headers;
use crate::constants::{DEFAULT_IPV4_TTL, IP_PROTOCOL_UDP, IPV4_STANDARD_IHL, RTP_VERSION};
use crate::crc;
use crate::encodings::{decode_lsb, encode_lsb};
use crate::error::{RohcBuildingError, RohcError, RohcParsingError};
use crate::packet_defs::{GenericUncompressedHeaders, RohcProfile};
use crate::traits::{ProfileHandler, RohcCompressorContext, RohcDecompressorContext};

/// Implements the ROHC Profile 1 (RTP/UDP/IP) compression and decompression logic.
///
/// This handler is responsible for:
/// - Creating and managing Profile 1 specific compressor and decompressor contexts.
/// - Processing uncompressed RTP/UDP/IPv4 headers and generating corresponding
///   ROHC Profile 1 packets (IR, UO-0, UO-1-SN, etc.).
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

    /// Reconstructs full `RtpUdpIpv4Headers` from the decompressor context and
    /// newly decoded dynamic fields.
    ///
    /// # Parameters
    /// - `context`: The Profile 1 decompressor context holding static fields.
    /// - `sn`: The decoded RTP Sequence Number.
    /// - `ts`: The decoded/inferred RTP Timestamp.
    /// - `marker`: The decoded/inferred RTP Marker bit.
    ///
    /// # Returns
    /// Fully reconstructed `RtpUdpIpv4Headers`.
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

            // Fill in other fields with context-derived or default values
            ip_ihl: IPV4_STANDARD_IHL, // Assuming standard IHL
            ip_dscp: 0, // ROHC P1 typically doesn't compress/signal DSCP changes robustly without extensions
            ip_ecn: 0,  // Same for ECN
            ip_total_length: 0, // This would need payload size, which ROHC doesn't know
            ip_identification: 0, // ROHC P1 can compress IP-ID, but base UO packets don't always carry it
            ip_dont_fragment: true, // Often true for RTP
            ip_more_fragments: false,
            ip_fragment_offset: 0,
            ip_ttl: DEFAULT_IPV4_TTL, // Common default
            ip_protocol: IP_PROTOCOL_UDP,
            ip_checksum: 0,  // Needs recalculation if packet is actually sent
            udp_length: 0,   // Similar to ip_total_length
            udp_checksum: 0, // Optional, often 0 if not used
            rtp_version: RTP_VERSION,
            rtp_padding: false, // Not typically signaled by base ROHC P1 packets
            rtp_extension: false,
            rtp_csrc_count: 0,
            rtp_payload_type: 0, // Not signaled by ROHC IR/UO packets; must be known by other means
            rtp_csrc_list: Vec::new(),
        }
    }

    /// Creates the byte slice input required for calculating the CRC for UO-0 and UO-1 packets
    /// in ROHC Profile 1. The input format is SSRC (4 bytes), SN (2 bytes), TS (4 bytes),
    /// and Marker (1 byte).
    ///
    /// # Parameters
    /// - `context_ssrc`: The SSRC from the context.
    /// - `sn`: The sequence number to include in the CRC input.
    /// - `ts`: The timestamp to include in the CRC input.
    /// - `marker`: The marker bit value to include.
    ///
    /// # Returns
    /// A `Vec<u8>` of length `P1_UO_CRC_INPUT_LENGTH_BYTES` (11 bytes).
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
            _ => {
                return Err(RohcError::UnsupportedProfile(u8::from(context.profile_id)));
            }
        };

        // Determine if an IR packet needs to be sent (initial, refresh, or significant change)
        let mut force_ir = context.mode == Profile1CompressorMode::InitializationAndRefresh;
        if !force_ir && context.ir_refresh_interval > 0 {
            // Refresh interval is number of FO packets between IRs.
            // So, if interval is 5, IR is sent, then 4 FOs, then next packet is IR.
            if context.fo_packets_sent_since_ir >= context.ir_refresh_interval.saturating_sub(1) {
                force_ir = true;
            }
        }

        // Additional checks that might force IR (Profile 1 specific logic):
        // - SSRC change (though typically a new CID would be used)
        // - Major jump in TS if TS stride cannot be maintained (not implemented here yet)
        // - Significant IP address or port changes (again, new CID often preferred)
        if context.rtp_ssrc != 0 && context.rtp_ssrc != uncompressed_headers.rtp_ssrc {
            // Re-initialize context for new SSRC.
            context.initialize_context_from_uncompressed_headers(uncompressed_headers);
            force_ir = true;
        }

        if force_ir {
            // If mode was IR, ensure context static parts are initialized
            if context.mode == Profile1CompressorMode::InitializationAndRefresh {
                context.initialize_context_from_uncompressed_headers(uncompressed_headers);
            }

            let ir_data = IrPacket {
                cid: context.cid,
                profile: self.profile_id(),
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

            let rohc_packet_bytes =
                build_profile1_ir_packet(&ir_data).map_err(RohcError::Building)?;

            context.last_sent_rtp_sn_full = uncompressed_headers.rtp_sequence_number;
            context.last_sent_rtp_ts_full = uncompressed_headers.rtp_timestamp;
            context.last_sent_rtp_marker = uncompressed_headers.rtp_marker;
            context.mode = Profile1CompressorMode::FirstOrder;
            context.fo_packets_sent_since_ir = 0;

            Ok(rohc_packet_bytes)
        } else {
            // Attempt to send a UO (Unidirectional Optimistic) packet
            let current_sn = uncompressed_headers.rtp_sequence_number;
            let current_marker = uncompressed_headers.rtp_marker;

            // For UO-0 and UO-1-SN, timestamp is typically not sent if it follows a linear progression.
            // We use the last sent TS for CRC calculation for these packets.
            // A more advanced implementation would track TS stride and send UO-1-TS if needed.
            let ts_for_crc = context.last_sent_rtp_ts_full;

            // Check if UO-0 can be used:
            // - Marker bit must not have changed from context.
            // - SN must be compressible with UO-0's LSB encoding (e.g., within +0 to +15 of last SN).
            // - Other fields (IP-ID, TS stride) must also be compressible by UO-0 (not fully modeled here).
            let marker_unchanged = current_marker == context.last_sent_rtp_marker;
            let diff_sn = current_sn.wrapping_sub(context.last_sent_rtp_sn_full);
            let sn_encodable_for_uo0 = diff_sn < 16;

            let final_rohc_packet_bytes = if marker_unchanged && sn_encodable_for_uo0 {
                let sn_lsb_val = encode_lsb(current_sn as u64, P1_UO0_SN_LSB_WIDTH_DEFAULT)? as u8;

                let crc_input_bytes = self.build_uo_crc_input(
                    context.rtp_ssrc,
                    current_sn,                   // CRC uses the current SN
                    ts_for_crc,                   // TS from context for UO-0
                    context.last_sent_rtp_marker, // Marker from context for UO-0
                );
                let crc3_val = crc::calculate_rohc_crc3(&crc_input_bytes);

                let uo0_packet_data = Uo0Packet {
                    cid: if context.cid > 0 && context.cid <= 15 {
                        Some(context.cid as u8)
                    } else {
                        None
                    },
                    sn_lsb: sn_lsb_val,
                    crc3: crc3_val,
                };
                context.current_lsb_sn_width = P1_UO0_SN_LSB_WIDTH_DEFAULT;
                build_profile1_uo0_packet(&uo0_packet_data).map_err(RohcError::Building)?
            } else {
                let sn_lsb_val = encode_lsb(current_sn as u64, P1_UO1_SN_LSB_WIDTH_DEFAULT)? as u16;

                let crc_input_bytes = self.build_uo_crc_input(
                    context.rtp_ssrc,
                    current_sn,     // Current SN for CRC
                    ts_for_crc,     // TS from context
                    current_marker, // Current Marker for CRC (UO-1-SN sends this)
                );
                let crc8_val = crc::calculate_rohc_crc8(&crc_input_bytes);

                let cid = if context.cid > 0 && context.cid <= 15 {
                    Some(context.cid as u8)
                } else if context.cid == 0 {
                    None
                } else {
                    return Err(RohcError::Building(
                        RohcBuildingError::ContextInsufficient {
                            reason: format!(
                                "UO-1 compression with Add-CID not supported for large CID {}",
                                context.cid
                            ),
                        },
                    ));
                };
                let uo1_packet_data = Uo1Packet {
                    cid,
                    sn_lsb: sn_lsb_val,
                    num_sn_lsb_bits: P1_UO1_SN_LSB_WIDTH_DEFAULT,
                    rtp_marker_bit_value: Some(current_marker),
                    ts_lsb: None,
                    num_ts_lsb_bits: None,
                    crc8: crc8_val,
                };
                context.current_lsb_sn_width = P1_UO1_SN_LSB_WIDTH_DEFAULT;

                build_profile1_uo1_sn_packet(&uo1_packet_data).map_err(RohcError::Building)?
            };

            // Update compressor context state for FO packet
            context.last_sent_rtp_sn_full = current_sn;
            context.last_sent_rtp_marker = current_marker;
            context.fo_packets_sent_since_ir += 1;

            Ok(final_rohc_packet_bytes)
        }
    }

    fn decompress(
        &self,
        context_dyn: &mut dyn RohcDecompressorContext,
        rohc_packet_data: &[u8],
    ) -> Result<GenericUncompressedHeaders, RohcError> {
        let context = context_dyn
            .as_any_mut()
            .downcast_mut::<Profile1DecompressorContext>()
            .ok_or_else(|| {
                RohcError::Internal("P1Handler::decompress: Incorrect context type.".to_string())
            })?;

        if rohc_packet_data.is_empty() {
            return Err(RohcError::Parsing(RohcParsingError::NotEnoughData {
                needed: 1,
                got: 0,
                context: "ROHC packet".to_string(),
            }));
        }

        // The ROHC engine should have handled Add-CID octet and passed the core packet here.
        // The context.cid should be correctly set by the engine.
        let first_byte = rohc_packet_data[0];

        // Discriminate packet type based on Profile 1 rules
        if (first_byte & !P1_ROHC_IR_PACKET_TYPE_D_BIT_MASK) == P1_ROHC_IR_PACKET_TYPE_BASE {
            let parsed_ir = parse_profile1_ir_packet(rohc_packet_data, context.cid())?;
            if parsed_ir.profile != self.profile_id() {
                return Err(RohcError::Parsing(RohcParsingError::InvalidProfileId(
                    parsed_ir.profile.into(),
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
        } else if (first_byte & P1_UO_1_SN_PACKET_TYPE_PREFIX) == P1_UO_1_SN_PACKET_TYPE_PREFIX {
            if context.mode != Profile1DecompressorMode::FullContext {
                return Err(RohcError::InvalidState(
                    "Received UO-1 packet but decompressor not in Full Context mode.".to_string(),
                ));
            }
            let parsed_uo1 = parse_profile1_uo1_sn_packet(rohc_packet_data)?;
            let marker = parsed_uo1.rtp_marker_bit_value.ok_or_else(|| {
                RohcError::Parsing(RohcParsingError::MandatoryFieldMissing {
                    field_name: "RTP Marker".to_string(),
                    structure_name: "UO-1-SN Packet".to_string(),
                })
            })?;

            let decoded_sn = decode_lsb(
                parsed_uo1.sn_lsb as u64,
                context.last_reconstructed_rtp_sn_full as u64,
                parsed_uo1.num_sn_lsb_bits,
                context.p_sn,
            )? as u16;

            // For UO-1-SN, timestamp is from context
            let ts_for_header = context.last_reconstructed_rtp_ts_full;

            let crc_input_bytes = self.build_uo_crc_input(
                context.rtp_ssrc,
                decoded_sn,    // Use decoded SN for CRC
                ts_for_header, // TS from context
                marker,        // Marker from packet
            );
            let calculated_crc8 = crc::calculate_rohc_crc8(&crc_input_bytes);

            if calculated_crc8 == parsed_uo1.crc8 {
                context.last_reconstructed_rtp_sn_full = decoded_sn;
                context.last_reconstructed_rtp_marker = marker;
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
        } else if (first_byte & 0x80) == 0x00 {
            if context.mode != Profile1DecompressorMode::FullContext {
                return Err(RohcError::InvalidState(
                    "Received UO-0 packet but decompressor not in Full Context mode.".to_string(),
                ));
            }

            let cid_for_uo0_parse: Option<u8> = if context.cid() == 0 {
                None
            } else if context.cid() <= 15 {
                Some(context.cid() as u8)
            } else {
                return Err(RohcError::Internal(format!(
                    "UO-0 packet processing for unexpected large CID {}",
                    context.cid()
                )));
            };

            let parsed_uo0 = parse_profile1_uo0_packet(rohc_packet_data, cid_for_uo0_parse)?;

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
                // Marker & TS not updated by UO-0
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
    use crate::packet_defs::GenericUncompressedHeaders;
    use crate::profiles::profile1::protocol_types::RtpUdpIpv4Headers;

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
    fn profile1_handler_ir_compression_decompression() {
        let handler = Profile1Handler::new();
        let mut comp_ctx_dyn = handler.create_compressor_context(0, 5);
        let mut decomp_ctx_dyn = handler.create_decompressor_context(0);

        let headers1 = create_test_rtp_headers(100, 1000, false);
        let generic_headers1 = GenericUncompressedHeaders::RtpUdpIpv4(headers1.clone());

        // Compress IR
        let compressed_ir = handler
            .compress(comp_ctx_dyn.as_mut(), &generic_headers1)
            .unwrap();
        assert!(!compressed_ir.is_empty());
        assert_eq!(compressed_ir[0], P1_ROHC_IR_PACKET_TYPE_WITH_DYN); // Assuming CID 0, no Add-CID

        // Decompress IR
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

        // Check compressor context state
        let comp_ctx = comp_ctx_dyn
            .as_any()
            .downcast_ref::<Profile1CompressorContext>()
            .unwrap();
        assert_eq!(comp_ctx.mode, Profile1CompressorMode::FirstOrder);
        assert_eq!(comp_ctx.last_sent_rtp_sn_full, 100);
        assert_eq!(comp_ctx.fo_packets_sent_since_ir, 0);

        // Check decompressor context state
        let decomp_ctx = decomp_ctx_dyn
            .as_any()
            .downcast_ref::<Profile1DecompressorContext>()
            .unwrap();
        assert_eq!(decomp_ctx.mode, Profile1DecompressorMode::FullContext);
        assert_eq!(decomp_ctx.last_reconstructed_rtp_sn_full, 100);
    }

    #[test]
    fn profile1_handler_uo0_compression_decompression() {
        let handler = Profile1Handler::new();
        let mut comp_ctx_dyn = handler.create_compressor_context(0, 5);
        let mut decomp_ctx_dyn = handler.create_decompressor_context(0);

        // Send IR first to establish context
        let headers_ir = create_test_rtp_headers(100, 1000, false);
        let generic_headers_ir = GenericUncompressedHeaders::RtpUdpIpv4(headers_ir.clone());
        let compressed_ir = handler
            .compress(comp_ctx_dyn.as_mut(), &generic_headers_ir)
            .unwrap();
        let _ = handler
            .decompress(decomp_ctx_dyn.as_mut(), &compressed_ir)
            .unwrap();

        // Now send UO-0 (SN=101, M=false)
        let headers_uo0 = create_test_rtp_headers(101, 1160, false); // TS changes, marker same
        let generic_headers_uo0 = GenericUncompressedHeaders::RtpUdpIpv4(headers_uo0.clone());
        let compressed_uo0 = handler
            .compress(comp_ctx_dyn.as_mut(), &generic_headers_uo0)
            .unwrap();

        assert_eq!(compressed_uo0.len(), 1); // UO-0 for CID 0 is 1 byte
        assert_eq!(compressed_uo0[0] & 0x80, 0x00); // MSB is 0 for UO-0

        let decompressed_generic_uo0 = handler
            .decompress(decomp_ctx_dyn.as_mut(), &compressed_uo0)
            .unwrap();
        let decomp_headers_uo0 = match decompressed_generic_uo0 {
            GenericUncompressedHeaders::RtpUdpIpv4(h) => h,
            _ => panic!("Wrong enum variant"),
        };

        assert_eq!(decomp_headers_uo0.rtp_sequence_number, 101);
        assert_eq!(decomp_headers_uo0.rtp_marker, headers_ir.rtp_marker); // Marker from context for UO-0
        assert_eq!(decomp_headers_uo0.rtp_timestamp, headers_ir.rtp_timestamp); // TS from context for UO-0
    }

    #[test]
    fn profile1_handler_uo1_sn_compression_decompression() {
        let handler = Profile1Handler::new();
        let mut comp_ctx_dyn = handler.create_compressor_context(0, 5);
        let mut decomp_ctx_dyn = handler.create_decompressor_context(0);

        // Send IR first
        let headers_ir = create_test_rtp_headers(200, 2000, false);
        let generic_headers_ir = GenericUncompressedHeaders::RtpUdpIpv4(headers_ir.clone());
        let compressed_ir = handler
            .compress(comp_ctx_dyn.as_mut(), &generic_headers_ir)
            .unwrap();
        let _ = handler
            .decompress(decomp_ctx_dyn.as_mut(), &compressed_ir)
            .unwrap();

        // Now send UO-1-SN because marker changes (SN=201, M=true)
        let headers_uo1 = create_test_rtp_headers(201, 2160, true);
        let generic_headers_uo1 = GenericUncompressedHeaders::RtpUdpIpv4(headers_uo1.clone());
        let compressed_uo1 = handler
            .compress(comp_ctx_dyn.as_mut(), &generic_headers_uo1)
            .unwrap();

        assert_eq!(compressed_uo1.len(), 3); // UO-1-SN for CID 0 is 3 bytes
        assert_eq!(
            compressed_uo1[0] & P1_UO_1_SN_PACKET_TYPE_PREFIX,
            P1_UO_1_SN_PACKET_TYPE_PREFIX
        );
        assert_ne!(compressed_uo1[0] & P1_UO_1_SN_MARKER_BIT_MASK, 0); // Marker bit is set

        let decompressed_generic_uo1 = handler
            .decompress(decomp_ctx_dyn.as_mut(), &compressed_uo1)
            .unwrap();
        let decomp_headers_uo1 = match decompressed_generic_uo1 {
            GenericUncompressedHeaders::RtpUdpIpv4(h) => h,
            _ => panic!("Wrong enum variant"),
        };

        assert_eq!(decomp_headers_uo1.rtp_sequence_number, 201);
        assert!(decomp_headers_uo1.rtp_marker); // Marker from packet
        assert_eq!(decomp_headers_uo1.rtp_timestamp, headers_ir.rtp_timestamp); // TS from context
    }

    #[test]
    fn profile1_handler_ir_refresh() {
        let handler = Profile1Handler::new();
        let refresh_interval = 3; // IR, UO, UO, then next should be IR
        let mut comp_ctx_dyn = handler.create_compressor_context(0, refresh_interval);

        // Packet 1: IR
        let headers1 = create_test_rtp_headers(10, 100, false);
        let generic1 = GenericUncompressedHeaders::RtpUdpIpv4(headers1);
        let compressed1 = handler.compress(comp_ctx_dyn.as_mut(), &generic1).unwrap();
        assert_eq!(compressed1[0], P1_ROHC_IR_PACKET_TYPE_WITH_DYN);
        let comp_ctx_after_p1 = comp_ctx_dyn
            .as_any()
            .downcast_ref::<Profile1CompressorContext>()
            .unwrap();
        assert_eq!(comp_ctx_after_p1.fo_packets_sent_since_ir, 0);

        // Packet 2: UO-0
        let headers2 = create_test_rtp_headers(11, 110, false);
        let generic2 = GenericUncompressedHeaders::RtpUdpIpv4(headers2);
        let compressed2 = handler.compress(comp_ctx_dyn.as_mut(), &generic2).unwrap();
        assert_eq!(compressed2.len(), 1); // UO-0
        let comp_ctx_after_p2 = comp_ctx_dyn
            .as_any()
            .downcast_ref::<Profile1CompressorContext>()
            .unwrap();
        assert_eq!(comp_ctx_after_p2.fo_packets_sent_since_ir, 1);

        // Packet 3: UO-0
        let headers3 = create_test_rtp_headers(12, 120, false);
        let generic3 = GenericUncompressedHeaders::RtpUdpIpv4(headers3);
        let compressed3 = handler.compress(comp_ctx_dyn.as_mut(), &generic3).unwrap();
        assert_eq!(compressed3.len(), 1); // UO-0
        let comp_ctx_after_p3 = comp_ctx_dyn
            .as_any()
            .downcast_ref::<Profile1CompressorContext>()
            .unwrap();
        assert_eq!(comp_ctx_after_p3.fo_packets_sent_since_ir, 2); // Sent 2 FOs, next is IR because interval = 3

        // Packet 4: Should be IR due to refresh
        let headers4 = create_test_rtp_headers(13, 130, false);
        let generic4 = GenericUncompressedHeaders::RtpUdpIpv4(headers4);
        let compressed4 = handler.compress(comp_ctx_dyn.as_mut(), &generic4).unwrap();
        assert_eq!(
            compressed4[0], P1_ROHC_IR_PACKET_TYPE_WITH_DYN,
            "Packet 4 should be an IR due to refresh"
        );
        let comp_ctx_after_p4 = comp_ctx_dyn
            .as_any()
            .downcast_ref::<Profile1CompressorContext>()
            .unwrap();
        assert_eq!(comp_ctx_after_p4.fo_packets_sent_since_ir, 0); // Reset after IR
    }
}
