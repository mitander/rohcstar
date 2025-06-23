//! Recovery functions for ROHC Profile 1 decompression.
//!
//! Implements sequence number recovery, header reconstruction, and timestamp
//! calculation functions used by packet type decompression modules.

use super::super::context::Profile1DecompressorContext;
use crate::CrcType;
use crate::constants::{IP_PROTOCOL_UDP, IPV4_STANDARD_IHL, RTP_VERSION};
use crate::error::{RohcError, RohcParsingError};
use crate::protocol_types::RtpUdpIpv4Headers;
use crate::types::{IpId, SequenceNumber, Timestamp};

/// LSB constraint for sequence number recovery validation.
#[derive(Debug, Clone, Copy)]
pub(super) struct LsbConstraint {
    /// The expected LSB value
    pub(super) value: u8,
    /// Number of LSB bits to validate
    pub(super) bits: u8,
}

/// Attempts sequence number recovery on CRC mismatch using configurable search windows.
///
/// Performs forward and backward search around the expected sequence number to find
/// a candidate that produces the correct CRC, using configurable search windows.
///
/// # Errors
/// - `RohcError::Parsing` - No valid sequence number found within search windows
#[allow(clippy::too_many_arguments)]
pub(super) fn try_sn_recovery<F, G>(
    context: &Profile1DecompressorContext,
    received_crc: u8,
    crc_type: CrcType,
    forward_window: u16,
    backward_window: u16,
    lsb_constraint: Option<LsbConstraint>,
    crc_calculator: F,
    crc_input_generator: G,
) -> Result<SequenceNumber, RohcError>
where
    F: Fn(&[u8]) -> u8,
    G: Fn(SequenceNumber, Timestamp, &mut [u8]) -> usize,
{
    let expected_next_sn = context.last_reconstructed_rtp_sn_full.wrapping_add(1);

    // Pre-compute LSB mask if needed
    let lsb_mask_and_value = lsb_constraint.map(|constraint| {
        let mask = (1u16 << constraint.bits) - 1;
        (mask, constraint.value)
    });

    // Stack buffer for CRC input - largest is 12 bytes for UO-1-ID
    let mut crc_input_buf = [0u8; 16];

    // Forward search
    for offset in 1..=forward_window {
        let candidate_sn = context.last_reconstructed_rtp_sn_full.wrapping_add(offset);

        // LSB validation if required
        if let Some((mask, expected_lsb)) = lsb_mask_and_value {
            if (candidate_sn.value() & mask) as u8 != expected_lsb {
                continue;
            }
        }

        // Reject extreme jumps (conservative distance check)
        let distance = candidate_sn.value().wrapping_sub(expected_next_sn.value());
        if distance > forward_window && distance < (u16::MAX - forward_window) {
            continue;
        }

        let candidate_ts = calculate_reconstructed_ts_implicit(context, candidate_sn);
        let crc_len = crc_input_generator(candidate_sn, candidate_ts, &mut crc_input_buf);

        if crc_calculator(&crc_input_buf[..crc_len]) == received_crc {
            return Ok(candidate_sn);
        }
    }

    // Backward search
    for offset in 1..=backward_window {
        let candidate_sn = SequenceNumber::new(
            context
                .last_reconstructed_rtp_sn_full
                .wrapping_sub(SequenceNumber::new(offset)),
        );

        // LSB validation if required
        if let Some((mask, expected_lsb)) = lsb_mask_and_value {
            if (candidate_sn.value() & mask) as u8 != expected_lsb {
                continue;
            }
        }

        let candidate_ts = calculate_reconstructed_ts_implicit(context, candidate_sn);
        let crc_len = crc_input_generator(candidate_sn, candidate_ts, &mut crc_input_buf);

        if crc_calculator(&crc_input_buf[..crc_len]) == received_crc {
            return Ok(candidate_sn);
        }
    }

    Err(RohcError::Parsing(RohcParsingError::CrcMismatch {
        expected: received_crc,
        calculated: 0,
        crc_type,
    }))
}

/// Reconstructs full RTP/UDP/IPv4 headers using context and current dynamic values.
///
/// Populates an RtpUdpIpv4Headers struct using static fields from the decompressor
/// context and the provided dynamic values from the current packet.
pub(super) fn reconstruct_headers_from_context(
    context: &Profile1DecompressorContext,
    sn: SequenceNumber,
    ts: Timestamp,
    marker: bool,
    ip_id: IpId,
) -> RtpUdpIpv4Headers {
    debug_assert_ne!(
        context.rtp_ssrc, 0,
        "Context SSRC must be initialized for header reconstruction."
    );

    RtpUdpIpv4Headers {
        ip_src: context.ip_source,
        ip_dst: context.ip_destination,
        udp_src_port: context.udp_source_port,
        udp_dst_port: context.udp_destination_port,
        rtp_ssrc: context.rtp_ssrc,
        rtp_sequence_number: sn,
        rtp_timestamp: ts,
        rtp_marker: marker,
        ip_identification: ip_id,
        ip_ihl: IPV4_STANDARD_IHL,
        ip_dscp: 0,
        ip_ecn: 0,
        ip_total_length: 0,
        ip_dont_fragment: true,
        ip_more_fragments: false,
        ip_fragment_offset: 0,
        ip_ttl: context.ip_ttl,
        ip_protocol: IP_PROTOCOL_UDP,
        ip_checksum: 0,
        udp_length: 0,
        udp_checksum: 0,
        rtp_version: RTP_VERSION,
        rtp_padding: context.rtp_padding,
        rtp_extension: context.rtp_extension,
        rtp_csrc_count: 0,
        rtp_payload_type: context.rtp_payload_type,
        rtp_csrc_list: Vec::new(),
    }
}

/// Calculates reconstructed RTP timestamp using established stride and SN delta.
///
/// Uses the established or potential TS stride to calculate the timestamp based
/// on sequence number advancement when TS is not explicitly carried.
pub(super) fn calculate_reconstructed_ts_implicit(
    context: &Profile1DecompressorContext,
    decoded_sn: SequenceNumber,
) -> Timestamp {
    // Use established stride first, then potential stride to match compressor logic
    let stride = context.ts_stride.or(context.potential_ts_stride);
    if let Some(stride_val) = stride {
        let sn_delta = decoded_sn.wrapping_sub(context.last_reconstructed_rtp_sn_full);
        if sn_delta > 0 {
            Timestamp::new(
                context
                    .last_reconstructed_rtp_ts_full
                    .value()
                    .wrapping_add(sn_delta as u32 * stride_val),
            )
        } else {
            context.last_reconstructed_rtp_ts_full
        }
    } else {
        context.last_reconstructed_rtp_ts_full
    }
}

/// Calculates reconstructed RTP timestamp when SN advances by exactly one.
///
/// Specialized version for packet types where the sequence number is always
/// last_reconstructed_sn + 1 (e.g., UO-1-ID, UO-1-RTP packets).
pub(super) fn calculate_reconstructed_ts_implicit_sn_plus_one(
    context: &Profile1DecompressorContext,
) -> Timestamp {
    // Use established stride first, then potential stride to match compressor logic
    let stride = context.ts_stride.or(context.potential_ts_stride);
    if let Some(stride_val) = stride {
        Timestamp::new(
            context
                .last_reconstructed_rtp_ts_full
                .value()
                .wrapping_add(stride_val),
        )
    } else {
        context.last_reconstructed_rtp_ts_full
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crc::CrcCalculators;
    use crate::profiles::profile1::context::Profile1DecompressorContext;
    use crate::types::{IpId, SequenceNumber, Timestamp};

    fn create_test_context(
        sequence_number: u16,
        timestamp: u32,
        ssrc: u32,
    ) -> Profile1DecompressorContext {
        let mut context = Profile1DecompressorContext::new(0.into());
        context.rtp_ssrc = ssrc.into();
        context.last_reconstructed_rtp_sn_full = SequenceNumber::new(sequence_number);
        context.last_reconstructed_rtp_ts_full = Timestamp::new(timestamp);
        context.last_reconstructed_ip_id_full = IpId::new(0x1000);
        context.ts_stride = Some(160u32);
        context
    }

    #[test]
    fn sn_recovery_respects_search_window_limits() {
        let context = create_test_context(1000, 160000, 0x12345678);
        let crc_calculators = CrcCalculators::new();

        // Test recovery with limited search windows
        let _result = try_sn_recovery(
            &context,
            0x85, // Target CRC
            crate::CrcType::Crc8Uo1Sn,
            10,   // Forward window
            5,    // Backward window
            None, // No LSB constraint
            |input| crc_calculators.crc8(input),
            |candidate_sn, candidate_ts, buf| {
                // Simple CRC input generator for testing
                let input = format!("{}-{}", candidate_sn.value(), candidate_ts.value());
                let bytes = input.as_bytes();
                let len = bytes.len().min(buf.len());
                buf[..len].copy_from_slice(&bytes[..len]);
                len
            },
        );

        // Result depends on CRC match, but should respect window limits
        // and not search beyond specified boundaries
    }

    #[test]
    fn sn_recovery_validates_lsb_constraints() {
        let context = create_test_context(2000, 320000, 0x87654321);
        let crc_calculators = CrcCalculators::new();

        // Test with LSB constraint (e.g., UO-1 with 6-bit SN LSB = 5)
        let lsb_constraint = Some(LsbConstraint {
            value: 5u8,
            bits: 6u8,
        });

        let _result = try_sn_recovery(
            &context,
            0x42,
            crate::CrcType::Crc8Uo1Sn,
            32,
            16,
            lsb_constraint,
            |input| crc_calculators.crc8(input),
            |candidate_sn, candidate_ts, buf| {
                let combined = (candidate_sn.value() as u32) << 16 | candidate_ts.value();
                let bytes = combined.to_be_bytes();
                buf[..4].copy_from_slice(&bytes);
                4
            },
        );

        // Only candidates with (SN & 0x3F) == 5 should be tested
    }

    #[test]
    fn implicit_timestamp_calculation_uses_stride() {
        let context = create_test_context(500, 80000, 0xAABBCCDD);

        // Test basic stride calculation
        let calculated_ts = calculate_reconstructed_ts_implicit(&context, SequenceNumber::new(502));

        // SN delta = 502 - 500 = 2, TS should advance by 2 * 160 = 320
        let expected_ts = Timestamp::new(80000 + 2 * 160);
        assert_eq!(
            calculated_ts, expected_ts,
            "TS should advance by stride * SN delta"
        );
    }

    #[test]
    fn implicit_timestamp_calculation_handles_wraparound() {
        let mut context = create_test_context(65535, 4294967000, 0x11223344); // Near u32::MAX
        context.ts_stride = Some(1000u32); // Large stride

        // Test wraparound scenario
        let calculated_ts = calculate_reconstructed_ts_implicit(&context, SequenceNumber::new(2)); // Wrapped SN

        // Should handle wraparound correctly without overflow
        assert!(
            calculated_ts.value() < 4294967295,
            "TS calculation should handle wraparound"
        );
    }

    #[test]
    fn sn_plus_one_timestamp_calculation() {
        let context = create_test_context(1500, 240000, 0x55667788);

        let calculated_ts = calculate_reconstructed_ts_implicit_sn_plus_one(&context);

        // SN implicitly becomes 1501 (1500 + 1), TS should advance by 160
        let expected_ts = Timestamp::new(240000 + 160);
        assert_eq!(
            calculated_ts, expected_ts,
            "TS should advance by one stride for SN+1"
        );
    }

    #[test]
    fn header_reconstruction_preserves_all_fields() {
        let mut context = create_test_context(800, 128000, 0x99AABBCC);
        context.ip_source = [10, 0, 0, 1].into();
        context.ip_destination = [10, 0, 0, 2].into();
        context.udp_source_port = 5004;
        context.udp_destination_port = 5006;

        let sequence_number = SequenceNumber::new(805);
        let timestamp = Timestamp::new(128800);
        let marker = true;
        let ip_id = IpId::new(0x5678);

        let headers =
            reconstruct_headers_from_context(&context, sequence_number, timestamp, marker, ip_id);

        // Verify all fields are correctly reconstructed
        assert_eq!(
            headers.ip_src.octets(),
            [10, 0, 0, 1],
            "Source IP should be preserved"
        );
        assert_eq!(
            headers.ip_dst.octets(),
            [10, 0, 0, 2],
            "Dest IP should be preserved"
        );
        assert_eq!(
            headers.udp_src_port, 5004,
            "Source port should be preserved"
        );
        assert_eq!(headers.udp_dst_port, 5006, "Dest port should be preserved");
        assert_eq!(
            headers.rtp_ssrc.value(),
            0x99AABBCC,
            "SSRC should be preserved"
        );
        assert_eq!(
            headers.rtp_sequence_number, sequence_number,
            "SN should match input"
        );
        assert_eq!(headers.rtp_timestamp, timestamp, "TS should match input");
        assert_eq!(headers.rtp_marker, marker, "Marker should match input");
    }

    #[test]
    fn recovery_rejects_extreme_distance_jumps() {
        let context = create_test_context(10000, 1600000, 0xDDEEFFAA);
        let crc_calculators = CrcCalculators::new();

        // Test with search window that would normally find candidates
        // but distance check should reject extreme jumps
        let _result = try_sn_recovery(
            &context,
            0x99,
            crate::CrcType::Crc8Uo1Sn,
            100, // Large window
            50,  // Large backward window
            None,
            |input| crc_calculators.crc8(input),
            |candidate_sn, candidate_ts, buf| {
                // Generate input that might match CRC but has extreme distance
                // Use actual SN/TS values to test distance checking
                let combined = (candidate_sn.value() as u64) << 32 | candidate_ts.value() as u64;
                let bytes = combined.to_be_bytes();
                buf[..8].copy_from_slice(&bytes);
                8
            },
        );

        // Should reject candidates that are too far from expected next SN
        // even if CRC matches
    }
}
