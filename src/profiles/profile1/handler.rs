//! ROHC (Robust Header Compression) Profile 1 (RTP/UDP/IP) handler implementation.
//!
//! This module provides the concrete implementation of the `ProfileHandler` trait
//! for ROHC Profile 1. It orchestrates the compression and decompression of
//! RTP/UDP/IPv4 packet headers according to the rules specified in RFC 3095,
//! delegating specific logic to submodules like `compression_logic`,
//! `decompression_logic`, and `state_machine`.

use std::time::Instant;

use super::compression_logic;
use super::context::{
    Profile1CompressorContext, Profile1DecompressorContext, Profile1DecompressorMode,
};
use super::discriminator::Profile1PacketType;
use super::state_machine;

use crate::crc::CrcCalculators;
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
}

impl ProfileHandler for Profile1Handler {
    /// Returns the ROHC Profile Identifier that this handler implements.
    fn profile_id(&self) -> RohcProfile {
        RohcProfile::RtpUdpIp
    }

    /// Creates a new, profile-specific compressor context.
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

    /// Creates a new, profile-specific decompressor context.
    fn create_decompressor_context(
        &self,
        cid: u16,
        creation_time: Instant,
    ) -> Box<dyn RohcDecompressorContext> {
        let mut ctx = Profile1DecompressorContext::new(cid);
        ctx.last_accessed = creation_time;
        Box::new(ctx)
    }

    /// Compresses a set of uncompressed headers using this profile's logic.
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
        debug_assert_ne!(
            context.rtp_ssrc, 0,
            "Context SSRC should be initialized at this point."
        );

        let result = if compression_logic::should_force_ir(context, uncompressed_headers) {
            compression_logic::compress_as_ir(context, uncompressed_headers, &self.crc_calculators)
        } else {
            compression_logic::compress_as_uo(context, uncompressed_headers, &self.crc_calculators)
        };

        if result.is_ok() {
            context.set_last_accessed(Instant::now());
        }
        result
    }

    /// Decompresses a ROHC packet using this profile's logic, managed by the state machine.
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
                    state_machine::process_ir_packet(
                        context,
                        packet_bytes,
                        &self.crc_calculators,
                        self.profile_id(),
                    )
                } else {
                    Err(RohcError::InvalidState(
                        "Non-IR packet received but decompressor is in NoContext mode.".to_string(),
                    ))
                }
            }
            _ => {
                // Covers FC, SC, SO
                if discriminated_type.is_ir() {
                    return state_machine::process_ir_packet(
                        context,
                        packet_bytes,
                        &self.crc_calculators,
                        self.profile_id(),
                    );
                }
                // Delegate to mode-specific UO/other packet processing in state_machine
                match context.mode {
                    Profile1DecompressorMode::FullContext => {
                        state_machine::process_uo_packet_in_fc_mode(
                            context,
                            packet_bytes,
                            discriminated_type,
                            &self.crc_calculators,
                        )
                    }
                    Profile1DecompressorMode::StaticContext => {
                        state_machine::process_packet_in_sc_mode(
                            context,
                            packet_bytes,
                            discriminated_type,
                            &self.crc_calculators,
                        )
                    }
                    Profile1DecompressorMode::SecondOrder => {
                        state_machine::process_packet_in_so_mode(
                            context,
                            packet_bytes,
                            discriminated_type,
                            &self.crc_calculators,
                        )
                    }
                    Profile1DecompressorMode::NoContext => {
                        unreachable!("NoContext handled by the outer match")
                    }
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
    use crate::packet_defs::GenericUncompressedHeaders;
    use crate::profiles::profile1::constants::P1_ROHC_IR_PACKET_TYPE_WITH_DYN;
    use crate::profiles::profile1::context::Profile1CompressorMode;
    use crate::profiles::profile1::protocol_types::{RtpUdpIpv4Headers, Timestamp};

    #[test]
    fn handler_calls_compression_logic_for_ir() {
        let handler = Profile1Handler::new();
        let mut comp_ctx_dyn = handler.create_compressor_context(0, 5, Instant::now());
        let comp_ctx = comp_ctx_dyn
            .as_any_mut()
            .downcast_mut::<Profile1CompressorContext>()
            .unwrap();

        let headers1 = RtpUdpIpv4Headers {
            rtp_ssrc: 0x12345678, // Set a specific SSRC for the packet
            rtp_sequence_number: 100,
            rtp_timestamp: Timestamp::new(1000),
            ..Default::default()
        };
        // Initialize context with this SSRC and force IR mode
        comp_ctx.initialize_context_from_uncompressed_headers(&headers1);
        comp_ctx.mode = Profile1CompressorMode::InitializationAndRefresh;

        let generic_headers1 = GenericUncompressedHeaders::RtpUdpIpv4(headers1.clone());

        let compressed_ir = handler
            .compress(comp_ctx_dyn.as_mut(), &generic_headers1)
            .unwrap();
        assert!(!compressed_ir.is_empty());
        assert_eq!(compressed_ir[0], P1_ROHC_IR_PACKET_TYPE_WITH_DYN);
    }

    #[test]
    fn handler_calls_state_machine_for_ir_decompression() {
        let handler = Profile1Handler::new();
        let mut decomp_ctx_dyn = handler.create_decompressor_context(0, Instant::now());

        let ir_data_content = super::super::packet_types::IrPacket {
            cid: 0,
            profile_id: RohcProfile::RtpUdpIp,
            static_ip_src: "1.1.1.1".parse().unwrap(),
            static_ip_dst: "2.2.2.2".parse().unwrap(),
            static_udp_src_port: 100,
            static_udp_dst_port: 200,
            static_rtp_ssrc: 0xABCDE,
            dyn_rtp_sn: 10,
            dyn_rtp_timestamp: Timestamp::new(1000),
            dyn_rtp_marker: false,
            ts_stride: None,
            crc8: 0,
        };
        let ir_packet_bytes = super::super::packet_processor::build_profile1_ir_packet(
            &ir_data_content,
            &handler.crc_calculators,
        )
        .expect("Test IR packet build failed");

        let result = handler.decompress(decomp_ctx_dyn.as_mut(), &ir_packet_bytes);
        assert!(
            result.is_ok(),
            "Decompressing IR failed: {:?}",
            result.err()
        );

        let decomp_ctx = decomp_ctx_dyn
            .as_any()
            .downcast_ref::<Profile1DecompressorContext>()
            .unwrap();
        assert_eq!(decomp_ctx.mode, Profile1DecompressorMode::FullContext); // State machine sets this
    }
}
