//! ROHC (Robust Header Compression) Profile 1 (RTP/UDP/IP) decompression logic.
//!
//! This module handles the decompression-side processing of ROHC Profile 1 packets.
//! It parses specific ROHC packet types (IR, UO-0, UO-1-* variants) and reconstructs
//! the original uncompressed headers. State transition logic is handled by the calling
//! handler or dedicated state machine module.

use super::context::Profile1DecompressorContext;
use super::packet_processor::{
    parse_profile1_ir_packet, parse_profile1_uo0_packet, parse_profile1_uo1_id_packet,
    parse_profile1_uo1_rtp_packet, parse_profile1_uo1_sn_packet, parse_profile1_uo1_ts_packet,
    prepare_generic_uo_crc_input_payload, prepare_uo1_id_specific_crc_input_payload,
};
use super::protocol_types::{RtpUdpIpv4Headers, Timestamp};

use crate::constants::{DEFAULT_IPV4_TTL, IP_PROTOCOL_UDP, IPV4_STANDARD_IHL, RTP_VERSION};
use crate::crc::CrcCalculators;
use crate::encodings::decode_lsb;
use crate::error::{RohcError, RohcParsingError};
use crate::packet_defs::RohcProfile;
use crate::traits::RohcDecompressorContext;

/// Parses an IR packet, updates decompressor context, and reconstructs headers.
///
/// This function handles the core parsing of IR/IR-DYN packet fields and updates
/// the decompressor's context with static and dynamic information. Profile ID
/// validation ensures packet compatibility with the handler.
///
/// # Parameters
/// - `context`: The mutable decompressor context.
/// - `packet_bytes`: The byte slice of the core IR packet (after Add-CID removal).
/// - `crc_calculators`: Reference to `CrcCalculators` for CRC verification.
/// - `handler_profile_id`: The `RohcProfile` ID of the calling handler, for validation.
///
/// # Returns
/// - `Ok(RtpUdpIpv4Headers)` containing the reconstructed headers.
/// - `Err(RohcError)` if parsing the IR packet fails.
pub(super) fn parse_and_reconstruct_ir(
    context: &mut Profile1DecompressorContext,
    packet_bytes: &[u8],
    crc_calculators: &CrcCalculators,
    handler_profile_id: RohcProfile,
) -> Result<RtpUdpIpv4Headers, RohcError> {
    debug_assert!(
        !packet_bytes.is_empty(),
        "IR packet_bytes should not be empty."
    );
    let parsed_ir = parse_profile1_ir_packet(packet_bytes, context.cid(), crc_calculators)?;

    if parsed_ir.profile_id != handler_profile_id {
        return Err(RohcError::Parsing(RohcParsingError::InvalidProfileId(
            parsed_ir.profile_id.into(),
        )));
    }
    context.initialize_from_ir_packet(&parsed_ir);

    Ok(reconstruct_full_headers_from_context_and_dynamic(
        context,
        parsed_ir.dyn_rtp_sn,
        parsed_ir.dyn_rtp_timestamp,
        parsed_ir.dyn_rtp_marker,
        context.last_reconstructed_ip_id_full, // Profile 1 IR doesn't carry IP-ID in dynamic part
    ))
}

/// Parses a UO-0 packet, validates CRC, updates decompressor context, and reconstructs headers.
///
/// UO-0 packets maintain the same timestamp and marker bit, only updating the sequence number.
/// Timestamp is reconstructed using stride inference when available.
///
/// # Parameters
/// - `context`: The mutable decompressor context.
/// - `packet_bytes`: The byte slice of the core UO-0 packet.
/// - `crc_calculators`: Reference to `CrcCalculators` for CRC verification.
///
/// # Returns
/// - `Ok(RtpUdpIpv4Headers)` containing the reconstructed headers.
/// - `Err(RohcError)` if parsing, LSB decoding, or CRC validation fails.
pub(super) fn parse_and_reconstruct_uo0(
    context: &mut Profile1DecompressorContext,
    packet_bytes: &[u8],
    crc_calculators: &CrcCalculators,
) -> Result<RtpUdpIpv4Headers, RohcError> {
    debug_assert_eq!(
        packet_bytes.len(),
        1,
        "UO-0 core packet must be 1 byte long."
    );
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

    // Reconstruct timestamp using stride if available
    let sn_delta = decoded_sn.wrapping_sub(context.last_reconstructed_rtp_sn_full);
    let new_timestamp = if let Some(ts_stride) = context.ts_stride {
        let ts_delta = sn_delta as u32 * ts_stride;
        Timestamp::new(
            context
                .last_reconstructed_rtp_ts_full
                .value()
                .wrapping_add(ts_delta),
        )
    } else {
        context.last_reconstructed_rtp_ts_full
    };

    let crc_input_bytes = prepare_generic_uo_crc_input_payload(
        context.rtp_ssrc,
        decoded_sn,
        new_timestamp,
        context.last_reconstructed_rtp_marker,
    );
    let calculated_crc3 = crc_calculators.calculate_rohc_crc3(&crc_input_bytes);

    if calculated_crc3 != parsed_uo0.crc3 {
        return Err(RohcError::Parsing(RohcParsingError::CrcMismatch {
            expected: parsed_uo0.crc3,
            calculated: calculated_crc3,
            crc_type: "ROHC-CRC3 (UO-0)".to_string(),
        }));
    }

    // Infer stride before updating context state
    context.infer_ts_stride_from_decompressed_ts(new_timestamp);

    context.last_reconstructed_rtp_sn_full = decoded_sn;
    context.last_reconstructed_rtp_ts_full = new_timestamp;

    Ok(reconstruct_full_headers_from_context_and_dynamic(
        context,
        decoded_sn,
        new_timestamp,
        context.last_reconstructed_rtp_marker,
        context.last_reconstructed_ip_id_full,
    ))
}

/// Parses a UO-1-SN packet, validates CRC, updates decompressor context, and reconstructs headers.
///
/// UO-1-SN packets carry both sequence number changes and marker bit updates. Timestamp
/// is reconstructed implicitly using stride inference.
///
/// # Parameters
/// - `context`: The mutable decompressor context.
/// - `packet_bytes`: The byte slice of the core UO-1-SN packet.
/// - `crc_calculators`: Reference to `CrcCalculators` for CRC verification.
///
/// # Returns
/// - `Ok(RtpUdpIpv4Headers)` containing the reconstructed headers.
/// - `Err(RohcError)` if parsing, LSB decoding, or CRC validation fails.
pub(super) fn parse_and_reconstruct_uo1_sn(
    context: &mut Profile1DecompressorContext,
    packet_bytes: &[u8],
    crc_calculators: &CrcCalculators,
) -> Result<RtpUdpIpv4Headers, RohcError> {
    debug_assert_eq!(
        packet_bytes.len(),
        3,
        "UO-1-SN core packet must be 3 bytes long."
    );
    let parsed_uo1 = parse_profile1_uo1_sn_packet(packet_bytes)?;

    let decoded_sn = decode_lsb(
        parsed_uo1.sn_lsb as u64,
        context.last_reconstructed_rtp_sn_full as u64,
        parsed_uo1.num_sn_lsb_bits,
        context.p_sn,
    )? as u16;

    // Reconstruct implicit timestamp using stride
    let sn_delta = decoded_sn.wrapping_sub(context.last_reconstructed_rtp_sn_full);
    let new_timestamp = if let Some(ts_stride) = context.ts_stride {
        let ts_delta = sn_delta as u32 * ts_stride;
        Timestamp::new(
            context
                .last_reconstructed_rtp_ts_full
                .value()
                .wrapping_add(ts_delta),
        )
    } else {
        context.last_reconstructed_rtp_ts_full
    };

    let crc_input_bytes = prepare_generic_uo_crc_input_payload(
        context.rtp_ssrc,
        decoded_sn,
        new_timestamp,
        parsed_uo1.marker,
    );
    let calculated_crc8 = crc_calculators.calculate_rohc_crc8(&crc_input_bytes);

    if calculated_crc8 != parsed_uo1.crc8 {
        return Err(RohcError::Parsing(RohcParsingError::CrcMismatch {
            expected: parsed_uo1.crc8,
            calculated: calculated_crc8,
            crc_type: "ROHC-CRC8 (UO-1-SN)".to_string(),
        }));
    }

    context.infer_ts_stride_from_decompressed_ts(new_timestamp);

    context.last_reconstructed_rtp_sn_full = decoded_sn;
    context.last_reconstructed_rtp_ts_full = new_timestamp;
    context.last_reconstructed_rtp_marker = parsed_uo1.marker;

    Ok(reconstruct_full_headers_from_context_and_dynamic(
        context,
        decoded_sn,
        new_timestamp,
        parsed_uo1.marker,
        context.last_reconstructed_ip_id_full,
    ))
}

/// Parses a UO-1-TS packet, validates CRC, updates decompressor context, and reconstructs headers.
///
/// UO-1-TS packets carry explicit timestamp changes with implicit sequence number increment.
/// This is used when timestamp changes but sequence number increments by exactly 1.
///
/// # Parameters
/// - `context`: The mutable decompressor context.
/// - `packet_bytes`: The byte slice of the core UO-1-TS packet.
/// - `crc_calculators`: Reference to `CrcCalculators` for CRC verification.
///
/// # Returns
/// - `Ok(RtpUdpIpv4Headers)` containing the reconstructed headers.
/// - `Err(RohcError)` if parsing, LSB decoding, or CRC validation fails.
pub(super) fn parse_and_reconstruct_uo1_ts(
    context: &mut Profile1DecompressorContext,
    packet_bytes: &[u8],
    crc_calculators: &CrcCalculators,
) -> Result<RtpUdpIpv4Headers, RohcError> {
    debug_assert_eq!(
        packet_bytes.len(),
        4,
        "UO-1-TS core packet must be 4 bytes long."
    );
    let parsed_uo1_ts = parse_profile1_uo1_ts_packet(packet_bytes)?;

    // UO-1-TS has implicit SN increment of 1
    let reconstructed_sn = context.last_reconstructed_rtp_sn_full.wrapping_add(1);

    let ts_lsb_from_packet = parsed_uo1_ts.ts_lsb.ok_or_else(|| {
        RohcError::Parsing(RohcParsingError::MandatoryFieldMissing {
            field_name: "ts_lsb".to_string(),
            structure_name: "Parsed UO-1-TS".to_string(),
        })
    })?;
    let num_ts_lsb_bits_from_packet = parsed_uo1_ts.num_ts_lsb_bits.ok_or_else(|| {
        RohcError::Parsing(RohcParsingError::MandatoryFieldMissing {
            field_name: "num_ts_lsb_bits".to_string(),
            structure_name: "Parsed UO-1-TS".to_string(),
        })
    })?;

    let decoded_ts_val = decode_lsb(
        ts_lsb_from_packet as u64,
        context.last_reconstructed_rtp_ts_full.value() as u64,
        num_ts_lsb_bits_from_packet,
        context.p_ts,
    )? as u32;
    let decoded_ts = Timestamp::new(decoded_ts_val);

    let crc_input_bytes = prepare_generic_uo_crc_input_payload(
        context.rtp_ssrc,
        reconstructed_sn,
        decoded_ts,
        context.last_reconstructed_rtp_marker, // UO-1-TS uses marker from context
    );
    let calculated_crc8 = crc_calculators.calculate_rohc_crc8(&crc_input_bytes);

    if calculated_crc8 != parsed_uo1_ts.crc8 {
        return Err(RohcError::Parsing(RohcParsingError::CrcMismatch {
            expected: parsed_uo1_ts.crc8,
            calculated: calculated_crc8,
            crc_type: "ROHC-CRC8 (UO-1-TS)".to_string(),
        }));
    }

    context.infer_ts_stride_from_decompressed_ts(decoded_ts);
    context.last_reconstructed_rtp_sn_full = reconstructed_sn;
    context.last_reconstructed_rtp_ts_full = decoded_ts;

    Ok(reconstruct_full_headers_from_context_and_dynamic(
        context,
        reconstructed_sn,
        decoded_ts,
        context.last_reconstructed_rtp_marker,
        context.last_reconstructed_ip_id_full, // IP-ID not in UO-1-TS
    ))
}

/// Parses a UO-1-ID packet, validates CRC, updates decompressor context, and reconstructs headers.
///
/// UO-1-ID packets carry IP identification changes with implicit sequence number increment.
/// Timestamp is reconstructed using stride inference.
///
/// # Parameters
/// - `context`: The mutable decompressor context.
/// - `packet_bytes`: The byte slice of the core UO-1-ID packet.
/// - `crc_calculators`: Reference to `CrcCalculators` for CRC verification.
///
/// # Returns
/// - `Ok(RtpUdpIpv4Headers)` containing the reconstructed headers.
/// - `Err(RohcError)` if parsing, LSB decoding, or CRC validation fails.
pub(super) fn parse_and_reconstruct_uo1_id(
    context: &mut Profile1DecompressorContext,
    packet_bytes: &[u8],
    crc_calculators: &CrcCalculators,
) -> Result<RtpUdpIpv4Headers, RohcError> {
    debug_assert_eq!(
        packet_bytes.len(),
        3,
        "UO-1-ID core packet must be 3 bytes long."
    );
    let parsed_uo1_id = parse_profile1_uo1_id_packet(packet_bytes)?;

    // UO-1-ID has implicit SN increment of 1
    let reconstructed_sn = context.last_reconstructed_rtp_sn_full.wrapping_add(1);

    // Reconstruct timestamp using stride (SN delta is always 1)
    let sn_delta = 1;
    let new_timestamp = if let Some(ts_stride) = context.ts_stride {
        let ts_delta = sn_delta * ts_stride;
        Timestamp::new(
            context
                .last_reconstructed_rtp_ts_full
                .value()
                .wrapping_add(ts_delta),
        )
    } else {
        context.last_reconstructed_rtp_ts_full
    };

    let ip_id_lsb_from_packet = parsed_uo1_id.ip_id_lsb.ok_or_else(|| {
        RohcError::Parsing(RohcParsingError::MandatoryFieldMissing {
            field_name: "ip_id_lsb".to_string(),
            structure_name: "Parsed UO-1-ID".to_string(),
        })
    })?;
    let num_ip_id_lsb_bits_from_packet = parsed_uo1_id.num_ip_id_lsb_bits.ok_or_else(|| {
        RohcError::Parsing(RohcParsingError::MandatoryFieldMissing {
            field_name: "num_ip_id_lsb_bits".to_string(),
            structure_name: "Parsed UO-1-ID".to_string(),
        })
    })?;

    let decoded_ip_id = decode_lsb(
        ip_id_lsb_from_packet as u64,
        context.last_reconstructed_ip_id_full as u64,
        num_ip_id_lsb_bits_from_packet,
        context.p_ip_id,
    )? as u16;

    let crc_input_bytes = prepare_uo1_id_specific_crc_input_payload(
        context.rtp_ssrc,
        reconstructed_sn,
        new_timestamp,
        context.last_reconstructed_rtp_marker,
        ip_id_lsb_from_packet as u8,
    );
    let calculated_crc8 = crc_calculators.calculate_rohc_crc8(&crc_input_bytes);

    if calculated_crc8 != parsed_uo1_id.crc8 {
        return Err(RohcError::Parsing(RohcParsingError::CrcMismatch {
            expected: parsed_uo1_id.crc8,
            calculated: calculated_crc8,
            crc_type: "ROHC-CRC8 (UO-1-ID)".to_string(),
        }));
    }

    context.infer_ts_stride_from_decompressed_ts(new_timestamp);

    context.last_reconstructed_rtp_sn_full = reconstructed_sn;
    context.last_reconstructed_rtp_ts_full = new_timestamp;
    context.last_reconstructed_ip_id_full = decoded_ip_id;

    Ok(reconstruct_full_headers_from_context_and_dynamic(
        context,
        reconstructed_sn,
        new_timestamp,
        context.last_reconstructed_rtp_marker,
        decoded_ip_id,
    ))
}

/// Parses a UO-1-RTP packet, validates CRC, updates decompressor context, and reconstructs headers.
///
/// UO-1-RTP packets use TS_SCALED encoding for timestamp compression, requiring established
/// stride for proper reconstruction. This packet type is only used when the compressor
/// is in scaled mode.
///
/// # Parameters
/// - `context`: The mutable decompressor context.
/// - `packet_bytes`: The byte slice of the core UO-1-RTP packet.
/// - `crc_calculators`: Reference to `CrcCalculators` for CRC verification.
///
/// # Returns
/// - `Ok(RtpUdpIpv4Headers)` containing the reconstructed headers.
/// - `Err(RohcError)` if parsing, TS reconstruction, or CRC validation fails.
pub(super) fn parse_and_reconstruct_uo1_rtp(
    context: &mut Profile1DecompressorContext,
    packet_bytes: &[u8],
    crc_calculators: &CrcCalculators,
) -> Result<RtpUdpIpv4Headers, RohcError> {
    debug_assert_eq!(
        packet_bytes.len(),
        3,
        "UO-1-RTP core packet must be 3 bytes long."
    );
    let parsed_uo1_rtp = parse_profile1_uo1_rtp_packet(packet_bytes)?;

    // UO-1-RTP has implicit SN increment of 1
    let reconstructed_sn = context.last_reconstructed_rtp_sn_full.wrapping_add(1);

    let ts_scaled_received =
        parsed_uo1_rtp
            .ts_scaled
            .ok_or_else(|| RohcParsingError::MandatoryFieldMissing {
                field_name: "ts_scaled".to_string(),
                structure_name: "Parsed UO-1-RTP".to_string(),
            })?;

    // Reconstruct full TS from TS_SCALED value
    let reconstructed_ts = context
        .reconstruct_ts_from_scaled(ts_scaled_received)
        .ok_or_else(|| {
            RohcError::InvalidState(
                "Cannot reconstruct TS from TS_SCALED for UO-1-RTP: Decompressor TS_STRIDE not established."
                    .to_string(),
            )
        })?;

    let crc_input_bytes = prepare_generic_uo_crc_input_payload(
        context.rtp_ssrc,
        reconstructed_sn,
        reconstructed_ts,
        parsed_uo1_rtp.marker, // UO-1-RTP carries the marker
    );
    let calculated_crc8 = crc_calculators.calculate_rohc_crc8(&crc_input_bytes);

    if calculated_crc8 != parsed_uo1_rtp.crc8 {
        return Err(RohcError::Parsing(RohcParsingError::CrcMismatch {
            expected: parsed_uo1_rtp.crc8,
            calculated: calculated_crc8,
            crc_type: "ROHC-CRC8 (UO-1-RTP)".to_string(),
        }));
    }

    // Successful UO-1-RTP decode implies scaled mode should be active
    if context.ts_stride.is_some() && !context.ts_scaled_mode {
        context.ts_scaled_mode = true;
    }

    context.infer_ts_stride_from_decompressed_ts(reconstructed_ts);
    context.last_reconstructed_rtp_sn_full = reconstructed_sn;
    context.last_reconstructed_rtp_ts_full = reconstructed_ts;
    context.last_reconstructed_rtp_marker = parsed_uo1_rtp.marker;

    Ok(reconstruct_full_headers_from_context_and_dynamic(
        context,
        reconstructed_sn,
        reconstructed_ts,
        parsed_uo1_rtp.marker,
        context.last_reconstructed_ip_id_full, // IP-ID not in UO-1-RTP
    ))
}

/// Reconstructs full `RtpUdpIpv4Headers` from decompressor context and current dynamic fields.
///
/// Combines static fields from context with dynamic fields from parameters. Uses standard
/// defaults for fields not directly conveyed by ROHC Profile 1 packets (TTL, DSCP, etc.).
///
/// # Parameters
/// - `context`: The decompressor context holding static chain information.
/// - `sn`: The current RTP sequence number.
/// - `ts`: The current RTP timestamp.
/// - `marker`: The current RTP marker bit.
/// - `ip_id`: The current IP Identification value.
///
/// # Returns
/// Fully reconstructed `RtpUdpIpv4Headers`.
fn reconstruct_full_headers_from_context_and_dynamic(
    context: &Profile1DecompressorContext,
    sn: u16,
    ts: Timestamp,
    marker: bool,
    ip_id: u16,
) -> RtpUdpIpv4Headers {
    debug_assert_ne!(
        context.rtp_ssrc, 0,
        "Context SSRC must be non-zero for header reconstruction."
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
        ip_ihl: IPV4_STANDARD_IHL,
        ip_dscp: 0,
        ip_ecn: 0,
        ip_total_length: 0, // Set by caller or network stack
        ip_identification: ip_id,
        ip_dont_fragment: true,
        ip_more_fragments: false,
        ip_fragment_offset: 0,
        ip_ttl: DEFAULT_IPV4_TTL,
        ip_protocol: IP_PROTOCOL_UDP,
        ip_checksum: 0, // Set by caller or network stack
        udp_length: 0,  // Set by caller or network stack
        udp_checksum: 0,
        rtp_version: RTP_VERSION,
        rtp_padding: false,
        rtp_extension: false,
        rtp_csrc_count: 0,
        rtp_payload_type: 0, // Application-specific, not in ROHC context
        rtp_csrc_list: Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crc::CrcCalculators;
    use crate::encodings::encode_lsb;
    use crate::profiles::profile1::context::{
        Profile1DecompressorContext, Profile1DecompressorMode,
    };
    use crate::profiles::profile1::packet_processor::{
        build_profile1_uo0_packet, build_profile1_uo1_id_packet, build_profile1_uo1_sn_packet,
    };
    use crate::profiles::profile1::packet_types::{Uo0Packet, Uo1Packet};
    use crate::profiles::profile1::*;

    // Helper to create a basic decompressor context, common for UO tests
    fn setup_decomp_context_for_uo(
        sn: u16,
        ts: u32,
        marker: bool,
        ip_id: u16,
        ssrc: u32,
    ) -> Profile1DecompressorContext {
        let mut context = Profile1DecompressorContext::new(0);
        context.rtp_ssrc = ssrc;
        context.last_reconstructed_rtp_sn_full = sn;
        context.last_reconstructed_rtp_ts_full = Timestamp::new(ts);
        context.last_reconstructed_rtp_marker = marker;
        context.last_reconstructed_ip_id_full = ip_id;
        context.expected_lsb_sn_width = P1_UO0_SN_LSB_WIDTH_DEFAULT;
        context.mode = Profile1DecompressorMode::FullContext;
        context
    }

    /// Helper to create a context with established TS_STRIDE for testing implicit updates
    fn setup_context_with_stride(
        initial_sn: u16,
        initial_ts: u32,
        ts_stride: u32,
        ssrc: u32,
    ) -> Profile1DecompressorContext {
        let mut context = Profile1DecompressorContext::new(0);
        context.rtp_ssrc = ssrc;
        context.last_reconstructed_rtp_sn_full = initial_sn;
        context.last_reconstructed_rtp_ts_full = Timestamp::new(initial_ts);
        context.last_reconstructed_rtp_marker = false;
        context.last_reconstructed_ip_id_full = 100;
        context.ts_stride = Some(ts_stride); // Key: establish stride
        context.ts_offset = Timestamp::new(initial_ts); // Set offset
        context.expected_lsb_sn_width = P1_UO0_SN_LSB_WIDTH_DEFAULT;
        context.mode = Profile1DecompressorMode::FullContext;
        context
    }

    /// Build a UO-0 packet with correct CRC for given parameters
    fn build_uo0_with_correct_crc(
        target_sn: u16,
        expected_ts: Timestamp,
        marker: bool,
        ssrc: u32,
        crc_calculators: &CrcCalculators,
    ) -> Vec<u8> {
        let sn_lsb = encode_lsb(target_sn as u64, P1_UO0_SN_LSB_WIDTH_DEFAULT).unwrap() as u8;
        let crc_input = prepare_generic_uo_crc_input_payload(ssrc, target_sn, expected_ts, marker);
        let crc3 = crc_calculators.calculate_rohc_crc3(&crc_input);

        let uo0_packet = Uo0Packet {
            cid: None,
            sn_lsb,
            crc3,
        };
        build_profile1_uo0_packet(&uo0_packet).unwrap()
    }

    #[test]
    fn rfc4815_uo0_implicit_timestamp_update_single_packet() {
        let crc_calculators = CrcCalculators::new();
        let ssrc = 0x12345678;
        let ts_stride = 160;
        let mut context = setup_context_with_stride(100, 1000, ts_stride, ssrc);

        // UO-0 packet: SN 100 → 101, TS should become 1000 + (1 * 160) = 1160
        let target_sn = 101;
        let expected_ts = Timestamp::new(1000 + ts_stride);
        let uo0_bytes =
            build_uo0_with_correct_crc(target_sn, expected_ts, false, ssrc, &crc_calculators);

        let result = parse_and_reconstruct_uo0(&mut context, &uo0_bytes, &crc_calculators);
        assert!(result.is_ok(), "UO-0 parsing failed: {:?}", result.err());

        let headers = result.unwrap();
        assert_eq!(headers.rtp_sequence_number, target_sn);
        assert_eq!(
            headers.rtp_timestamp, expected_ts,
            "RFC 4815 Section 6.1: UO-0 must implicitly update timestamp"
        );

        // Verify context was updated
        assert_eq!(context.last_reconstructed_rtp_sn_full, target_sn);
        assert_eq!(context.last_reconstructed_rtp_ts_full, expected_ts);
    }

    #[test]
    fn rfc4815_uo0_implicit_timestamp_update_sequence() {
        let crc_calculators = CrcCalculators::new();
        let ssrc = 0x87654321;
        let ts_stride = 160;
        let mut context = setup_context_with_stride(50, 2000, ts_stride, ssrc);

        // First UO-0: SN 50 → 51, TS 2000 → 2160
        let sn1 = 51;
        let ts1 = Timestamp::new(2000 + ts_stride);
        let uo0_bytes1 = build_uo0_with_correct_crc(sn1, ts1, false, ssrc, &crc_calculators);

        let result1 =
            parse_and_reconstruct_uo0(&mut context, &uo0_bytes1, &crc_calculators).unwrap();
        assert_eq!(result1.rtp_timestamp, ts1);

        // Second UO-0: SN 51 → 52, TS 2160 → 2320
        let sn2 = 52;
        let ts2 = Timestamp::new(ts1.value() + ts_stride);
        let uo0_bytes2 = build_uo0_with_correct_crc(sn2, ts2, false, ssrc, &crc_calculators);

        let result2 =
            parse_and_reconstruct_uo0(&mut context, &uo0_bytes2, &crc_calculators).unwrap();
        assert_eq!(result2.rtp_timestamp, ts2);

        // Third UO-0: SN 52 → 53, TS 2320 → 2480
        let sn3 = 53;
        let ts3 = Timestamp::new(ts2.value() + ts_stride);
        let uo0_bytes3 = build_uo0_with_correct_crc(sn3, ts3, false, ssrc, &crc_calculators);

        let result3 =
            parse_and_reconstruct_uo0(&mut context, &uo0_bytes3, &crc_calculators).unwrap();
        assert_eq!(result3.rtp_timestamp, ts3);
    }

    #[test]
    fn rfc4815_uo0_no_stride_no_timestamp_update() {
        let crc_calculators = CrcCalculators::new();
        let ssrc = 0xABCDEF00;
        let mut context = setup_decomp_context_for_uo(100, 1000, false, 10, ssrc);
        // Intentionally NO ts_stride set

        let target_sn = 101;
        let expected_ts = Timestamp::new(1000); // Should stay same without stride
        let uo0_bytes =
            build_uo0_with_correct_crc(target_sn, expected_ts, false, ssrc, &crc_calculators);

        let result = parse_and_reconstruct_uo0(&mut context, &uo0_bytes, &crc_calculators).unwrap();
        assert_eq!(
            result.rtp_timestamp, expected_ts,
            "Without TS_STRIDE, timestamp should remain unchanged"
        );
    }

    #[test]
    fn rfc4815_uo0_wraparound_handling() {
        let crc_calculators = CrcCalculators::new();
        let ssrc = 0x11111111;
        let ts_stride = 160;
        let mut context = setup_context_with_stride(65535, u32::MAX - 80, ts_stride, ssrc);

        // SN wraps: 65535 → 0, TS wraps: (MAX - 80) → (MAX - 80) + 160 = MAX + 80 (wraps)
        let target_sn = 0;
        let expected_ts_val = (u32::MAX - 80).wrapping_add(ts_stride);
        let expected_ts = Timestamp::new(expected_ts_val);

        let uo0_bytes =
            build_uo0_with_correct_crc(target_sn, expected_ts, false, ssrc, &crc_calculators);
        let result = parse_and_reconstruct_uo0(&mut context, &uo0_bytes, &crc_calculators).unwrap();

        assert_eq!(
            result.rtp_timestamp, expected_ts,
            "UO-0 should handle SN and TS wraparound correctly"
        );
    }

    #[test]
    fn rfc4815_uo1_sn_implicit_timestamp_update() {
        let crc_calculators = CrcCalculators::new();
        let ssrc = 0x22222222;
        let ts_stride = 160;
        let mut context = setup_context_with_stride(200, 3000, ts_stride, ssrc);
        context.expected_lsb_sn_width = P1_UO1_SN_LSB_WIDTH_DEFAULT;

        // UO-1-SN: SN 200 → 205 (delta=5), TS should become 3000 + (5 * 160) = 3800
        let target_sn = 205;
        let expected_ts = Timestamp::new(3000 + (5 * ts_stride));
        let target_marker = true;

        let sn_lsb = encode_lsb(target_sn as u64, P1_UO1_SN_LSB_WIDTH_DEFAULT).unwrap() as u16;
        let crc_input =
            prepare_generic_uo_crc_input_payload(ssrc, target_sn, expected_ts, target_marker);
        let crc8 = crc_calculators.calculate_rohc_crc8(&crc_input);

        let uo1_packet = Uo1Packet {
            sn_lsb,
            num_sn_lsb_bits: P1_UO1_SN_LSB_WIDTH_DEFAULT,
            marker: target_marker,
            crc8,
            ..Default::default()
        };
        let uo1_bytes = build_profile1_uo1_sn_packet(&uo1_packet).unwrap();

        let result = parse_and_reconstruct_uo1_sn(&mut context, &uo1_bytes, &crc_calculators);
        assert!(result.is_ok(), "UO-1-SN parsing failed: {:?}", result.err());

        let headers = result.unwrap();
        assert_eq!(
            headers.rtp_timestamp, expected_ts,
            "RFC 4815 Section 6.1: UO-1-SN must implicitly update timestamp"
        );
    }

    #[test]
    fn rfc4815_uo1_id_implicit_timestamp_update() {
        let crc_calculators = CrcCalculators::new();
        let ssrc = 0x33333333;
        let ts_stride = 160;
        let mut context = setup_context_with_stride(300, 4000, ts_stride, ssrc);
        context.expected_lsb_ip_id_width = P1_UO1_IPID_LSB_WIDTH_DEFAULT;

        // UO-1-ID: SN 300 → 301 (delta=1), TS should become 4000 + (1 * 160) = 4160
        let target_sn = 301;
        let expected_ts = Timestamp::new(4000 + ts_stride);
        let target_ip_id = 35;
        let ip_id_lsb =
            encode_lsb(target_ip_id as u64, P1_UO1_IPID_LSB_WIDTH_DEFAULT).unwrap() as u8;

        let crc_input = prepare_uo1_id_specific_crc_input_payload(
            ssrc,
            target_sn,
            expected_ts,
            false,
            ip_id_lsb,
        );
        let crc8 = crc_calculators.calculate_rohc_crc8(&crc_input);

        let uo1_packet = Uo1Packet {
            ip_id_lsb: Some(ip_id_lsb as u16),
            num_ip_id_lsb_bits: Some(P1_UO1_IPID_LSB_WIDTH_DEFAULT),
            crc8,
            ..Default::default()
        };
        let uo1_bytes = build_profile1_uo1_id_packet(&uo1_packet).unwrap();

        let result = parse_and_reconstruct_uo1_id(&mut context, &uo1_bytes, &crc_calculators);
        assert!(result.is_ok(), "UO-1-ID parsing failed: {:?}", result.err());

        let headers = result.unwrap();
        assert_eq!(
            headers.rtp_timestamp, expected_ts,
            "RFC 4815 Section 6.1: UO-1-ID must implicitly update timestamp"
        );
    }

    #[test]
    fn rfc4815_mixed_packet_sequence_timestamp_consistency() {
        let crc_calculators = CrcCalculators::new();
        let ssrc = 0x44444444;
        let ts_stride = 160;
        let mut context = setup_context_with_stride(400, 5000, ts_stride, ssrc);
        // context.expected_lsb_sn_width = P1_UO1_SN_LSB_WIDTH_DEFAULT;

        // Packet 1: UO-0, SN 400 → 401, TS 5000 → 5160
        let sn1 = 401;
        let ts1 = Timestamp::new(5000 + ts_stride);
        let uo0_bytes = build_uo0_with_correct_crc(sn1, ts1, false, ssrc, &crc_calculators);
        let result1 =
            parse_and_reconstruct_uo0(&mut context, &uo0_bytes, &crc_calculators).unwrap();
        assert_eq!(result1.rtp_timestamp, ts1);

        // Packet 2: UO-1-SN, SN 401 → 402, TS 5160 → 5320
        let sn2 = 402;
        let ts2 = Timestamp::new(ts1.value() + ts_stride);
        let sn_lsb = encode_lsb(sn2 as u64, P1_UO1_SN_LSB_WIDTH_DEFAULT).unwrap() as u16;
        let crc_input = prepare_generic_uo_crc_input_payload(ssrc, sn2, ts2, true);
        let crc8 = crc_calculators.calculate_rohc_crc8(&crc_input);

        let uo1_packet = Uo1Packet {
            sn_lsb,
            num_sn_lsb_bits: P1_UO1_SN_LSB_WIDTH_DEFAULT,
            marker: true,
            crc8,
            ..Default::default()
        };
        let uo1_bytes = build_profile1_uo1_sn_packet(&uo1_packet).unwrap();
        let result2 =
            parse_and_reconstruct_uo1_sn(&mut context, &uo1_bytes, &crc_calculators).unwrap();
        assert_eq!(result2.rtp_timestamp, ts2);
    }

    #[test]
    fn large_sn_delta_timestamp_calculation() {
        let crc_calculators = CrcCalculators::new();
        let ssrc = 0x55555555;
        let ts_stride = 160;
        let mut context = setup_context_with_stride(1000, 10000, ts_stride, ssrc);

        // Large SN jump: 1000 → 1010 (delta=10), TS should be 10000 + (10 * 160) = 11600
        let target_sn = 1010;
        let expected_ts = Timestamp::new(10000 + (10 * ts_stride));
        let uo0_bytes =
            build_uo0_with_correct_crc(target_sn, expected_ts, false, ssrc, &crc_calculators);

        let result = parse_and_reconstruct_uo0(&mut context, &uo0_bytes, &crc_calculators).unwrap();
        assert_eq!(
            result.rtp_timestamp, expected_ts,
            "Should handle large SN deltas correctly"
        );
    }

    #[test]
    fn different_ts_stride_values() {
        let crc_calculators = CrcCalculators::new();
        let ssrc = 0x66666666;

        // Test various common TS_STRIDE values
        for &stride in &[160, 240, 320, 480, 960] {
            let mut context = setup_context_with_stride(100, 1000, stride, ssrc);

            let target_sn = 102; // delta = 2
            let expected_ts = Timestamp::new(1000 + (2 * stride));
            let uo0_bytes =
                build_uo0_with_correct_crc(target_sn, expected_ts, false, ssrc, &crc_calculators);

            let result =
                parse_and_reconstruct_uo0(&mut context, &uo0_bytes, &crc_calculators).unwrap();
            assert_eq!(
                result.rtp_timestamp, expected_ts,
                "Should work with TS_STRIDE = {}",
                stride
            );
        }
    }

    #[test]
    fn parse_uo0_and_reconstruct_with_timestamp_update() {
        let crc_calculators = CrcCalculators::new();
        let ssrc = 0xABCD;
        let ts_stride = 160;
        let mut context = setup_context_with_stride(100, 1000, ts_stride, ssrc);

        let target_sn: u16 = 101;
        let expected_ts = Timestamp::new(1000 + ts_stride);

        let sn_lsb = encode_lsb(target_sn as u64, P1_UO0_SN_LSB_WIDTH_DEFAULT).unwrap() as u8;
        let crc_input = prepare_generic_uo_crc_input_payload(ssrc, target_sn, expected_ts, false);
        let crc3 = crc_calculators.calculate_rohc_crc3(&crc_input);

        let uo0_packet_data = Uo0Packet {
            cid: None,
            sn_lsb,
            crc3,
        };
        let uo0_bytes = build_profile1_uo0_packet(&uo0_packet_data).unwrap();

        let result = parse_and_reconstruct_uo0(&mut context, &uo0_bytes, &crc_calculators);
        assert!(result.is_ok(), "UO-0 parsing failed: {:?}", result.err());

        let headers = result.unwrap();
        assert_eq!(headers.rtp_sequence_number, target_sn);
        assert_eq!(headers.rtp_timestamp, expected_ts);
        assert_eq!(context.last_reconstructed_rtp_sn_full, target_sn);
        assert_eq!(context.last_reconstructed_rtp_ts_full, expected_ts);
    }

    #[test]
    fn parse_uo1_sn_and_reconstruct_with_timestamp_update() {
        let crc_calculators = CrcCalculators::new();
        let ssrc = 0x1122;
        let ts_stride = 160;
        let mut context = setup_context_with_stride(50, 500, ts_stride, ssrc);
        context.expected_lsb_sn_width = P1_UO1_SN_LSB_WIDTH_DEFAULT;

        let target_sn: u16 = 55; // delta = 5
        let expected_ts = Timestamp::new(500 + (5 * ts_stride));
        let target_marker = true;

        let sn_lsb_val = encode_lsb(target_sn as u64, P1_UO1_SN_LSB_WIDTH_DEFAULT).unwrap() as u16;
        let crc_input =
            prepare_generic_uo_crc_input_payload(ssrc, target_sn, expected_ts, target_marker);
        let crc8 = crc_calculators.calculate_rohc_crc8(&crc_input);

        let uo1_packet_data = Uo1Packet {
            sn_lsb: sn_lsb_val,
            num_sn_lsb_bits: P1_UO1_SN_LSB_WIDTH_DEFAULT,
            marker: target_marker,
            crc8,
            ..Default::default()
        };
        let uo1_bytes = build_profile1_uo1_sn_packet(&uo1_packet_data).unwrap();

        let result = parse_and_reconstruct_uo1_sn(&mut context, &uo1_bytes, &crc_calculators);
        assert!(result.is_ok(), "UO-1-SN parsing failed: {:?}", result.err());

        let headers = result.unwrap();
        assert_eq!(headers.rtp_sequence_number, target_sn);
        assert_eq!(headers.rtp_timestamp, expected_ts);
        assert_eq!(headers.rtp_marker, target_marker);
    }
}
