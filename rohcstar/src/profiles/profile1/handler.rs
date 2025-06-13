//! ROHC (Robust Header Compression) Profile 1 (RTP/UDP/IP) handler implementation.
//!
//! This module provides the concrete implementation of the `ProfileHandler` trait
//! for ROHC Profile 1. It orchestrates the compression and decompression of
//! RTP/UDP/IPv4 packet headers according to the rules specified in RFC 3095,
//! delegating specific logic to submodules like `compressor`,
//! `decompressor`, and `state_machine`.

use std::time::Instant;

use super::compression::{compress_as_ir, compress_as_uo, should_force_ir};
use super::context::{
    Profile1CompressorContext, Profile1DecompressorContext, Profile1DecompressorMode,
};
use super::discriminator::Profile1PacketType;
use super::state_machine;

use crate::crc::CrcCalculators;
use crate::error::{
    CompressionError, DecompressionError, EngineError, Field, ParseContext, RohcError,
    RohcParsingError,
};
use crate::packet_defs::{GenericUncompressedHeaders, RohcProfile};
use crate::traits::{ProfileHandler, RohcCompressorContext, RohcDecompressorContext};
use crate::types::ContextId;

/// ROHC Profile 1 handler for RTP/UDP/IP packet compression.
///
/// Implements the [`ProfileHandler`] trait to provide compression and decompression
/// logic for RTP over UDP over IPv4 packets according to RFC 3095. This handler
/// manages the Profile 1 state machine, packet discrimination, and context creation.
///
/// ## Supported Packet Types
/// - IR (Initialization and Refresh)
/// - UO-0 (Unidirectional Optimistic, no sequence number)
/// - UO-1 (Unidirectional Optimistic, with sequence number/timestamp)
/// - UOR-2 (Unidirectional/Bidirectional Optimistic/Reliable)
#[derive(Debug, Default)]
pub struct Profile1Handler {
    /// Reusable CRC calculator instances to optimize performance.
    crc_calculators: CrcCalculators,
}

impl Profile1Handler {
    /// Creates a new Profile 1 handler instance.
    ///
    /// Initializes the handler with pre-configured CRC calculators for performance
    /// optimization during packet processing.
    ///
    /// # Returns
    /// A new `Profile1Handler` ready for registration with a ROHC engine.
    pub fn new() -> Self {
        Profile1Handler {
            crc_calculators: CrcCalculators::new(),
        }
    }
}

impl ProfileHandler for Profile1Handler {
    /// Returns the ROHC Profile Identifier for Profile 1.
    ///
    /// # Returns
    /// [`RohcProfile::RtpUdpIp`] indicating this handler supports Profile 1.
    fn profile_id(&self) -> RohcProfile {
        RohcProfile::RtpUdpIp
    }

    /// Creates a new Profile 1 compressor context.
    ///
    /// Initializes a context in the Initialization and Refresh (IR) state with
    /// the specified configuration parameters.
    ///
    /// # Parameters
    /// - `cid`: Context ID for the new compression flow
    /// - `ir_refresh_interval`: Number of packets between IR refreshes
    /// - `creation_time`: Timestamp for context creation and initial access time
    ///
    /// # Returns
    /// A boxed Profile 1 compressor context ready for packet compression.
    fn create_compressor_context(
        &self,
        cid: ContextId,
        ir_refresh_interval: u32,
        creation_time: Instant,
    ) -> Box<dyn RohcCompressorContext> {
        Box::new(Profile1CompressorContext::new(
            cid,
            ir_refresh_interval,
            creation_time,
        ))
    }

    /// Creates a new Profile 1 decompressor context.
    ///
    /// Initializes a context in the No Context state, ready to receive the first
    /// IR packet for the decompression flow.
    ///
    /// # Parameters
    /// - `cid`: Context ID for the new decompression flow
    /// - `creation_time`: Timestamp for context creation and initial access time
    ///
    /// # Returns
    /// A boxed Profile 1 decompressor context ready for packet decompression.
    fn create_decompressor_context(
        &self,
        cid: ContextId,
        creation_time: Instant,
    ) -> Box<dyn RohcDecompressorContext> {
        let mut ctx = Profile1DecompressorContext::new(cid);
        ctx.last_accessed = creation_time;
        Box::new(ctx)
    }

    /// Compresses uncompressed RTP/UDP/IP headers into provided buffer.
    ///
    /// Analyzes the uncompressed headers and context state to determine the optimal
    /// packet type (IR, UO-0, UO-1, etc.) and generates the corresponding ROHC packet.
    /// Updates the compressor context state and statistics.
    ///
    /// # Parameters
    /// - `context_dyn`: Mutable reference to the Profile 1 compressor context
    /// - `headers_generic`: Uncompressed headers to compress (must be RTP/UDP/IPv4)
    /// - `out`: Output buffer to write the compressed packet into
    ///
    /// # Returns
    /// The number of bytes written to the output buffer.
    ///
    /// # Errors
    /// - [`RohcError::Internal`] - Context downcast failed
    /// - [`RohcError::UnsupportedProfile`] - Headers not compatible with Profile 1
    /// - [`RohcError::Building`] - Packet construction failed
    fn compress(
        &self,
        context_dyn: &mut dyn RohcCompressorContext,
        headers_generic: &GenericUncompressedHeaders,
        out: &mut [u8],
    ) -> Result<usize, RohcError> {
        let context = context_dyn
            .as_any_mut()
            .downcast_mut::<Profile1CompressorContext>()
            .ok_or({
                RohcError::Engine(EngineError::Internal {
                    reason: "P1Handler::compress: Incorrect context type",
                })
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

        let len = if should_force_ir(context, uncompressed_headers) {
            compress_as_ir(context, uncompressed_headers, &self.crc_calculators, out)?
        } else {
            match compress_as_uo(context, uncompressed_headers, &self.crc_calculators, out) {
                Ok(len) => len,
                Err(RohcError::Compression(CompressionError::ContextInsufficient {
                    field: Field::TsScaled,
                    ..
                })) => {
                    // ts_scaled_mode was newly activated, retry with IR packet
                    compress_as_ir(context, uncompressed_headers, &self.crc_calculators, out)?
                }
                Err(e) => return Err(e),
            }
        };

        if len > 0 {
            context.update_access_time(Instant::now());
        }
        Ok(len)
    }

    /// Decompresses a ROHC packet into uncompressed RTP/UDP/IP headers.
    ///
    /// Processes the ROHC packet according to the Profile 1 state machine, updating
    /// the decompressor context and reconstructing the original headers. Handles
    /// packet type discrimination and CRC validation.
    ///
    /// # Parameters
    /// - `context_dyn`: Mutable reference to the Profile 1 decompressor context
    /// - `packet`: ROHC packet data to decompress
    ///
    /// # Returns
    /// The reconstructed uncompressed headers.
    ///
    /// # Errors
    /// - [`RohcError::Internal`] - Context downcast failed
    /// - [`RohcError::Parsing`] - Invalid packet format or CRC mismatch
    /// - [`RohcError::Decompression`] - Context state inconsistent with packet type
    fn decompress(
        &self,
        context_dyn: &mut dyn RohcDecompressorContext,
        packet: &[u8],
    ) -> Result<GenericUncompressedHeaders, RohcError> {
        let context = context_dyn
            .as_any_mut()
            .downcast_mut::<Profile1DecompressorContext>()
            .ok_or({
                RohcError::Engine(EngineError::Internal {
                    reason: "P1Handler::decompress: Incorrect context type",
                })
            })?;

        if packet.is_empty() {
            return Err(RohcError::Parsing(RohcParsingError::NotEnoughData {
                needed: 1,
                got: 0,
                context: ParseContext::RohcPacketInput,
            }));
        }

        let first_byte = packet[0];
        let discriminated_type = Profile1PacketType::from_first_byte(first_byte);

        let result = match context.mode {
            Profile1DecompressorMode::NoContext => {
                if discriminated_type.is_ir() {
                    state_machine::process_ir_packet(
                        context,
                        packet,
                        &self.crc_calculators,
                        self.profile_id(),
                    )
                } else {
                    Err(RohcError::Decompression(
                        DecompressionError::InvalidPacketType {
                            cid: context.cid(),
                            packet_type: packet[0],
                        },
                    ))
                }
            }
            _ => {
                // Covers FC, SC, SO
                if discriminated_type.is_ir() {
                    return state_machine::process_ir_packet(
                        context,
                        packet,
                        &self.crc_calculators,
                        self.profile_id(),
                    );
                }
                // Delegate to mode-specific UO/other packet processing in state_machine
                match context.mode {
                    Profile1DecompressorMode::FullContext => {
                        state_machine::process_packet_in_fc_mode(
                            context,
                            packet,
                            discriminated_type,
                            &self.crc_calculators,
                        )
                    }
                    Profile1DecompressorMode::StaticContext => {
                        state_machine::process_packet_in_sc_mode(
                            context,
                            packet,
                            discriminated_type,
                            &self.crc_calculators,
                        )
                    }
                    Profile1DecompressorMode::SecondOrder => {
                        state_machine::process_packet_in_so_mode(
                            context,
                            packet,
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
            context.update_access_time(Instant::now());
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
    use crate::profiles::profile1::packet_types::IrPacket;
    use crate::profiles::profile1::protocol_types::RtpUdpIpv4Headers;
    use crate::profiles::profile1::serialization::ir_packets::serialize_ir;

    #[test]
    fn handler_calls_compressor_for_ir() {
        let handler = Profile1Handler::new();
        let mut comp_ctx_dyn = handler.create_compressor_context(0.into(), 5, Instant::now());
        let comp_ctx = comp_ctx_dyn
            .as_any_mut()
            .downcast_mut::<Profile1CompressorContext>()
            .unwrap();

        let headers1 = RtpUdpIpv4Headers {
            rtp_ssrc: 0x12345678.into(), // Set a specific SSRC for the packet
            rtp_sequence_number: 100.into(),
            rtp_timestamp: 1000.into(),
            ..Default::default()
        };
        // Initialize context with this SSRC and force IR mode
        comp_ctx.initialize_context_from_uncompressed_headers(&headers1);
        comp_ctx.mode = Profile1CompressorMode::InitializationAndRefresh;

        let generic_headers1 = GenericUncompressedHeaders::RtpUdpIpv4(headers1.clone());

        let mut compress_buf = [0u8; 64];
        let compressed_ir_len = handler
            .compress(comp_ctx_dyn.as_mut(), &generic_headers1, &mut compress_buf)
            .unwrap();
        assert!(compressed_ir_len > 0);
        assert_eq!(compress_buf[0], P1_ROHC_IR_PACKET_TYPE_WITH_DYN);
    }

    #[test]
    fn handler_calls_state_machine_for_ir_decompression() {
        let handler = Profile1Handler::new();
        let mut decomp_ctx_dyn = handler.create_decompressor_context(0.into(), Instant::now());

        let ir_data_content = IrPacket {
            cid: 0.into(),
            profile_id: RohcProfile::RtpUdpIp,
            static_ip_src: "1.1.1.1".parse().unwrap(),
            static_ip_dst: "2.2.2.2".parse().unwrap(),
            static_udp_src_port: 100,
            static_udp_dst_port: 200,
            static_rtp_ssrc: 0xABCDE.into(),
            static_rtp_payload_type: 0,
            static_rtp_extension: false,
            static_rtp_padding: false,
            dyn_rtp_sn: 10.into(),
            dyn_rtp_timestamp: 1000.into(),
            dyn_rtp_marker: false,
            dyn_ip_ttl: 64,
            dyn_ip_id: 0.into(),
            ts_stride: None,
            crc8: 0,
        };
        let mut ir_buf = [0u8; 64];
        let ir_len = serialize_ir(&ir_data_content, &handler.crc_calculators, &mut ir_buf)
            .expect("Test IR packet build failed");
        let ir_packet_bytes = &ir_buf[..ir_len];

        let result = handler.decompress(decomp_ctx_dyn.as_mut(), ir_packet_bytes);
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
