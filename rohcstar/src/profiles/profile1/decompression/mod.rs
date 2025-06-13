//! ROHC Profile 1 decompression modules.
//!
//! This module organizes decompression functionality into focused submodules:
//! - IR packet decompression
//! - UO-0 packet decompression
//! - UO-1 packet variants decompression
//! - Recovery utilities and helper functions

use crate::crc::CrcCalculators;
use crate::error::{RohcError, RohcParsingError};
use crate::packet_defs::RohcProfile;

use super::context::Profile1DecompressorContext;
use super::discriminator::Profile1PacketType;
use super::protocol_types::RtpUdpIpv4Headers;

pub mod ir_decompression;
pub mod recovery;
pub mod uo0_decompression;
pub mod uo1_decompression;

#[cfg(test)]
mod tests;

// Re-export main functions for backward compatibility
pub use self::ir_decompression::decompress_as_ir;
pub use self::uo0_decompression::decompress_as_uo0;
pub use self::uo1_decompression::{
    decompress_as_uo1_id, decompress_as_uo1_rtp, decompress_as_uo1_sn, decompress_as_uo1_ts,
};

/// Decompresses a UO (Unidirectional Optimistic) packet by auto-dispatching to the appropriate variant.
///
/// This function provides a unified entry point for decompressing any UO packet type.
/// It automatically determines the packet type from the first byte and dispatches to the
/// corresponding specific decompression function. This matches the abstraction level of
/// the compressor's `compress_as_uo()` function.
///
/// # Parameters
/// - `context`: Mutable decompressor context with established state.
/// - `packet`: Core UO packet data (after Add-CID processing, if any).
/// - `crc_calculators`: CRC calculator instances for verification.
///
/// # Returns
/// The reconstructed RTP/UDP/IPv4 headers.
///
/// # Errors
/// - [`RohcError::Parsing`] - Unknown packet type or decompression failure from specific function
pub fn decompress_as_uo(
    context: &mut Profile1DecompressorContext,
    packet: &[u8],
    crc_calculators: &CrcCalculators,
) -> Result<RtpUdpIpv4Headers, RohcError> {
    if packet.is_empty() {
        return Err(RohcError::Parsing(RohcParsingError::NotEnoughData {
            needed: 1,
            got: 0,
            context: crate::ParseContext::UoPacketTypeDiscriminator,
        }));
    }

    let packet_type = Profile1PacketType::from_first_byte(packet[0]);

    match packet_type {
        Profile1PacketType::Uo0 => decompress_as_uo0(context, packet, crc_calculators),
        Profile1PacketType::Uo1Sn { .. } => decompress_as_uo1_sn(context, packet, crc_calculators),
        Profile1PacketType::Uo1Ts => decompress_as_uo1_ts(context, packet, crc_calculators),
        Profile1PacketType::Uo1Id => decompress_as_uo1_id(context, packet, crc_calculators),
        Profile1PacketType::Uo1Rtp { .. } => {
            decompress_as_uo1_rtp(context, packet, crc_calculators)
        }
        Profile1PacketType::IrStatic | Profile1PacketType::IrDynamic => {
            Err(RohcError::Parsing(RohcParsingError::InvalidPacketType {
                discriminator: packet[0],
                profile_id: Some(RohcProfile::RtpUdpIp.into()),
            }))
        }
        Profile1PacketType::Unknown(discriminator) => {
            Err(RohcError::Parsing(RohcParsingError::InvalidPacketType {
                discriminator,
                profile_id: Some(RohcProfile::RtpUdpIp.into()),
            }))
        }
    }
}
