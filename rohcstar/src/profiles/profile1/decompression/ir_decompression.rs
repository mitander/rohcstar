//! IR packet decompression for ROHC Profile 1.
//!
//! This module handles the decompression of IR (Initialization and Refresh) packets,
//! which establish and refresh compression contexts with static and dynamic chain information.

use crate::crc::CrcCalculators;
use crate::error::{RohcError, RohcParsingError};
use crate::packet_defs::RohcProfile;
use crate::traits::RohcDecompressorContext;

use super::super::context::Profile1DecompressorContext;
use super::super::protocol_types::RtpUdpIpv4Headers;
use super::super::serialization::ir_packets::deserialize_ir;
use super::recovery::reconstruct_headers_from_context;

/// Decompresses IR packet and reconstructs headers from static chain information (IP addresses, ports, SSRC) and dynamic chain elements
/// (SN, TS, Marker, optional TS_STRIDE). It initializes the decompressor context
/// based on the received IR packet and validates the profile ID.
///
/// # Parameters
/// - `context`: Mutable decompressor context to be updated with information from the IR packet.
/// - `packet`: Byte slice of the core IR packet (after Add-CID octet processing, if any).
/// - `crc_calculators`: CRC calculator instances for verifying packet integrity.
/// - `handler_profile_id`: Expected ROHC profile ID for this handler, used for validation.
///
/// # Returns
/// The reconstructed RTP/UDP/IPv4 headers.
///
/// # Errors
/// - [`RohcError::Parsing`] - CRC mismatch, invalid profile ID, or decompression failure
pub fn decompress_as_ir(
    context: &mut Profile1DecompressorContext,
    packet: &[u8],
    crc_calculators: &CrcCalculators,
    handler_profile_id: RohcProfile,
) -> Result<RtpUdpIpv4Headers, RohcError> {
    let parsed_ir = deserialize_ir(packet, context.cid(), crc_calculators)?;

    if parsed_ir.profile_id != handler_profile_id {
        return Err(RohcError::Parsing(RohcParsingError::InvalidProfileId(
            parsed_ir.profile_id.into(),
        )));
    }

    context.initialize_from_ir_packet(&parsed_ir);

    Ok(reconstruct_headers_from_context(
        context,
        parsed_ir.dyn_rtp_sn,
        parsed_ir.dyn_rtp_timestamp,
        parsed_ir.dyn_rtp_marker,
        context.last_reconstructed_ip_id_full,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crc::CrcCalculators;
    use crate::packet_defs::RohcProfile;
    use crate::profiles::profile1::context::Profile1DecompressorContext;
    use crate::profiles::profile1::packet_types::IrPacket;
    use crate::profiles::profile1::serialization::ir_packets::serialize_ir;
    use crate::types::{ContextId, SequenceNumber, Timestamp};

    #[test]
    fn ir_decompression_profile_validation() {
        let crc_calculators = CrcCalculators::new();
        let mut context = Profile1DecompressorContext::new(ContextId::new(0));

        let ir_packet = IrPacket {
            cid: ContextId::new(0),
            profile_id: RohcProfile::RtpUdpIp,
            static_rtp_ssrc: 0x12345678.into(),
            dyn_rtp_sn: SequenceNumber::new(100),
            dyn_rtp_timestamp: Timestamp::new(16000),
            ..Default::default()
        };

        let mut packet_buffer = [0u8; 64];
        let packet_length = serialize_ir(&ir_packet, &crc_calculators, &mut packet_buffer).unwrap();

        // Test with correct profile
        let result = decompress_as_ir(
            &mut context,
            &packet_buffer[..packet_length],
            &crc_calculators,
            RohcProfile::RtpUdpIp,
        );
        assert!(
            result.is_ok(),
            "IR decompression should succeed with matching profile"
        );

        // Test with wrong profile
        let result_wrong = decompress_as_ir(
            &mut context,
            &packet_buffer[..packet_length],
            &crc_calculators,
            RohcProfile::Uncompressed,
        );
        assert!(
            result_wrong.is_err(),
            "IR decompression should fail with mismatched profile"
        );
    }

    #[test]
    fn ir_decompression_context_initialization() {
        let crc_calculators = CrcCalculators::new();
        let mut context = Profile1DecompressorContext::new(ContextId::new(5));

        let ssrc = 0x87654321u32;
        let sequence_number = SequenceNumber::new(200);
        let timestamp = Timestamp::new(32000);

        let ir_packet = IrPacket {
            cid: ContextId::new(5),
            profile_id: RohcProfile::RtpUdpIp,
            static_rtp_ssrc: ssrc.into(),
            dyn_rtp_sn: sequence_number,
            dyn_rtp_timestamp: timestamp,
            ..Default::default()
        };

        let mut packet_buffer = [0u8; 64];
        let packet_length = serialize_ir(&ir_packet, &crc_calculators, &mut packet_buffer).unwrap();

        // Skip Add-CID byte if present (CID=5, so first byte is 0xE5)
        let core_packet = if packet_buffer[0] == 0xE5 {
            &packet_buffer[1..packet_length]
        } else {
            &packet_buffer[..packet_length]
        };

        let result = decompress_as_ir(
            &mut context,
            core_packet,
            &crc_calculators,
            RohcProfile::RtpUdpIp,
        );
        assert!(
            result.is_ok(),
            "IR decompression should initialize context correctly"
        );

        let headers = result.unwrap();
        assert_eq!(
            headers.rtp_ssrc.value(),
            ssrc,
            "SSRC should be initialized from IR"
        );
        assert_eq!(
            headers.rtp_sequence_number, sequence_number,
            "SN should be initialized from IR"
        );
        assert_eq!(
            headers.rtp_timestamp, timestamp,
            "TS should be initialized from IR"
        );

        // Verify context was updated
        assert_eq!(
            context.rtp_ssrc.value(),
            ssrc,
            "Context SSRC should be updated"
        );
        assert_eq!(
            context.last_reconstructed_rtp_sn_full, sequence_number,
            "Context SN should be updated"
        );
        assert_eq!(
            context.last_reconstructed_rtp_ts_full, timestamp,
            "Context TS should be updated"
        );
    }

    #[test]
    fn ir_decompression_static_dynamic_chain_handling() {
        let crc_calculators = CrcCalculators::new();
        let mut context = Profile1DecompressorContext::new(ContextId::new(0));

        let ir_packet = IrPacket {
            cid: ContextId::new(0),
            profile_id: RohcProfile::RtpUdpIp,
            static_ip_src: [192, 168, 1, 1].into(),
            static_ip_dst: [192, 168, 1, 2].into(),
            static_udp_src_port: 5004,
            static_udp_dst_port: 5006,
            static_rtp_ssrc: 0xAABBCCDD.into(),
            dyn_rtp_sn: SequenceNumber::new(300),
            dyn_rtp_timestamp: Timestamp::new(48000),
            dyn_rtp_marker: true,
            ..Default::default()
        };

        let mut packet_buffer = [0u8; 64];
        let packet_length = serialize_ir(&ir_packet, &crc_calculators, &mut packet_buffer).unwrap();

        let result = decompress_as_ir(
            &mut context,
            &packet_buffer[..packet_length],
            &crc_calculators,
            RohcProfile::RtpUdpIp,
        );
        assert!(
            result.is_ok(),
            "IR with full static/dynamic chains should decompress"
        );

        let headers = result.unwrap();
        assert_eq!(
            headers.ip_src.octets(),
            [192, 168, 1, 1],
            "Source IP should match static chain"
        );
        assert_eq!(
            headers.ip_dst.octets(),
            [192, 168, 1, 2],
            "Dest IP should match static chain"
        );
        assert_eq!(
            headers.udp_src_port, 5004,
            "Source port should match static chain"
        );
        assert_eq!(
            headers.udp_dst_port, 5006,
            "Dest port should match static chain"
        );
        assert!(headers.rtp_marker, "Marker bit should match dynamic chain");
    }

    #[test]
    fn ir_decompression_crc_validation() {
        let crc_calculators = CrcCalculators::new();
        let mut context = Profile1DecompressorContext::new(ContextId::new(0));

        let ir_packet = IrPacket {
            cid: ContextId::new(0),
            profile_id: RohcProfile::RtpUdpIp,
            static_rtp_ssrc: 0x55667788.into(),
            dyn_rtp_sn: SequenceNumber::new(400),
            dyn_rtp_timestamp: Timestamp::new(64000),
            ..Default::default()
        };

        let mut packet_buffer = [0u8; 64];
        let packet_length = serialize_ir(&ir_packet, &crc_calculators, &mut packet_buffer).unwrap();

        // Corrupt the CRC by modifying the packet
        let mut corrupted_buffer = packet_buffer;
        corrupted_buffer[2] ^= 0x01; // Flip a bit to corrupt CRC

        let result = decompress_as_ir(
            &mut context,
            &corrupted_buffer[..packet_length],
            &crc_calculators,
            RohcProfile::RtpUdpIp,
        );
        assert!(
            result.is_err(),
            "IR decompression should fail with corrupted CRC"
        );
    }
}
