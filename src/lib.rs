//! `rohcstar`: a modern, memory-safe, and performant Rust implementation of the Robust Header Compression (ROHC) framework.
//!
//! This crate provides implementations for ROHC profiles, context management,
//! packet processing, and core ROHC logic like LSB encoding and CRC calculation.
//!
//! The primary focus of the MVP is ROHC Profile 1 (RTP/UDP/IP) in Unidirectional mode.
//!
//!
//! ## Example: Basic Profile 1 U-mode Compression and Decompression
//!
//! ```rust
//! use rohcstar::{
//!     RtpUdpIpv4Headers,
//!     RtpUdpIpP1CompressorContext,
//!     RtpUdpIpP1DecompressorContext,
//!     compress_rtp_udp_ip_umode,
//!     decompress_rtp_udp_ip_umode,
//!     constants::PROFILE_ID_RTP_UDP_IP,
//!     RohcError,
//! };
//! use std::net::Ipv4Addr;
//!
//! fn main() -> Result<(), RohcError> {
//!     // 1. Create initial uncompressed headers
//!     let original_headers = RtpUdpIpv4Headers {
//!         ip_src: "192.168.1.10".parse().unwrap(),
//!         ip_dst: "192.168.1.20".parse().unwrap(),
//!         udp_src_port: 12345,
//!         udp_dst_port: 54321,
//!         rtp_ssrc: 0x11223344,
//!         rtp_sequence_number: 100,
//!         rtp_timestamp: 1000,
//!         rtp_marker: false,
//!         ..Default::default()
//!     };
//!
//!     // 2. Initialize compressor and decompressor contexts (CID 0 for simplicity)
//!     let cid = 0;
//!     let ir_refresh_interval = 20; // Example refresh interval
//!     let mut compressor_context = RtpUdpIpP1CompressorContext::new(
//!         cid,
//!         PROFILE_ID_RTP_UDP_IP,
//!         ir_refresh_interval
//!     );
//!     let mut decompressor_context = RtpUdpIpP1DecompressorContext::new(
//!         cid,
//!         PROFILE_ID_RTP_UDP_IP
//!     );
//!
//!     // 3. Compress the headers (first packet will be an IR packet)
//!     // The compressor context's static part is initialized internally on the first call
//!     // when its mode is InitializationAndRefresh.
//!     let compressed_packet_ir = compress_rtp_udp_ip_umode(
//!         &mut compressor_context,
//!         &original_headers
//!     )?;
//!     println!("Sent IR packet ({} bytes)", compressed_packet_ir.len());
//!
//!     // 4. Decompress the IR packet
//!     let decompressed_headers_ir = decompress_rtp_udp_ip_umode(
//!         &mut decompressor_context,
//!         &compressed_packet_ir
//!     )?;
//!
//!     assert_eq!(decompressed_headers_ir.rtp_sequence_number, original_headers.rtp_sequence_number);
//!     assert_eq!(decompressed_headers_ir.rtp_ssrc, original_headers.rtp_ssrc);
//!     println!("Decompressed IR packet successfully.");
//!
//!     // 5. Create a subsequent packet (e.g., SN increment)
//!     let mut next_headers = original_headers.clone();
//!     next_headers.rtp_sequence_number += 1;
//!     next_headers.rtp_timestamp += 160; // Example timestamp increment
//!
//!     // 6. Compress the subsequent packet (should be a UO packet)
//!     let compressed_packet_uo = compress_rtp_udp_ip_umode(
//!         &mut compressor_context,
//!         &next_headers
//!     )?;
//!     println!("Sent UO packet ({} bytes)", compressed_packet_uo.len());
//!
//!     // 7. Decompress the UO packet
//!     let decompressed_headers_uo = decompress_rtp_udp_ip_umode(
//!         &mut decompressor_context,
//!         &compressed_packet_uo
//!     )?;
//!
//!     assert_eq!(decompressed_headers_uo.rtp_sequence_number, next_headers.rtp_sequence_number);
//!     println!("Decompressed UO packet successfully.");
//!
//!     Ok(())
//! }
//! ```
pub mod constants;
pub mod context;
pub mod context_manager;
pub mod crc;
pub mod encodings;
pub mod error;
pub mod fuzz_harnesses;
pub mod packet_processor;
pub mod profiles;
pub mod protocol_types;

pub use context::{
    CompressorMode, DecompressorMode, RtpUdpIpP1CompressorContext, RtpUdpIpP1DecompressorContext,
};
pub use context_manager::SimpleContextManager;
pub use error::RohcError;
pub use profiles::profile1_compressor::compress_rtp_udp_ip_umode;
pub use profiles::profile1_decompressor::decompress_rtp_udp_ip_umode;
pub use protocol_types::RtpUdpIpv4Headers;
