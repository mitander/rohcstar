//! ROHC (Robust Header Compression) Profile 1 (RTP/UDP/IP) decompression logic.
//!
//! This module contains functions responsible for the decompression-side
//! processing of ROHC Profile 1 packets. It includes logic for parsing
//! specific ROHC packet types (IR, UO-0, UO-1-* variants) and reconstructing
//! the original uncompressed headers. State transition logic is primarily handled
//! by the calling handler or a dedicated state machine module.

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
/// This function is responsible for the core parsing of IR/IR-DYN packet fields
/// and updating the decompressor's context with the static and dynamic information
/// contained within the IR packet.
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

    context.last_reconstructed_rtp_sn_full = decoded_sn;
    context.last_reconstructed_rtp_ts_full = new_timestamp;
    context.infer_ts_stride_from_decompressed_ts(new_timestamp);

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
        parsed_uo1.num_sn_lsb_bits, // Should be P1_UO1_SN_LSB_WIDTH_DEFAULT
        context.p_sn,
    )? as u16;

    let crc_input_bytes = prepare_generic_uo_crc_input_payload(
        context.rtp_ssrc,
        decoded_sn,
        context.last_reconstructed_rtp_ts_full, // UO-1-SN uses TS from context
        parsed_uo1.marker,                      // UO-1-SN carries the marker
    );
    let calculated_crc8 = crc_calculators.calculate_rohc_crc8(&crc_input_bytes);

    if calculated_crc8 != parsed_uo1.crc8 {
        return Err(RohcError::Parsing(RohcParsingError::CrcMismatch {
            expected: parsed_uo1.crc8,
            calculated: calculated_crc8,
            crc_type: "ROHC-CRC8 (UO-1-SN)".to_string(),
        }));
    }

    context.infer_ts_stride_from_decompressed_ts(context.last_reconstructed_rtp_ts_full);
    context.last_reconstructed_rtp_sn_full = decoded_sn;
    context.last_reconstructed_rtp_marker = parsed_uo1.marker;

    Ok(reconstruct_full_headers_from_context_and_dynamic(
        context,
        decoded_sn,
        context.last_reconstructed_rtp_ts_full,
        parsed_uo1.marker,
        context.last_reconstructed_ip_id_full, // IP-ID not in UO-1-SN
    ))
}

/// Parses a UO-1-TS packet, validates CRC, updates decompressor context, and reconstructs headers.
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

    // For UO-1-TS, SN is implicitly last_reconstructed_sn + 1
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
        decoded_ts,                            // Current (decoded) TS for CRC
        context.last_reconstructed_rtp_marker, // UO-1-TS uses Marker from context
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

    // For UO-1-ID, SN is implicitly last_reconstructed_sn + 1
    let reconstructed_sn = context.last_reconstructed_rtp_sn_full.wrapping_add(1);

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
        context.last_reconstructed_rtp_ts_full, // UO-1-ID uses TS from context
        context.last_reconstructed_rtp_marker,  // UO-1-ID uses Marker from context
        ip_id_lsb_from_packet as u8,            // LSB of IP-ID from packet used in CRC
    );
    let calculated_crc8 = crc_calculators.calculate_rohc_crc8(&crc_input_bytes);

    if calculated_crc8 != parsed_uo1_id.crc8 {
        return Err(RohcError::Parsing(RohcParsingError::CrcMismatch {
            expected: parsed_uo1_id.crc8,
            calculated: calculated_crc8,
            crc_type: "ROHC-CRC8 (UO-1-ID)".to_string(),
        }));
    }

    context.infer_ts_stride_from_decompressed_ts(context.last_reconstructed_rtp_ts_full);
    context.last_reconstructed_rtp_sn_full = reconstructed_sn;
    context.last_reconstructed_ip_id_full = decoded_ip_id;

    Ok(reconstruct_full_headers_from_context_and_dynamic(
        context,
        reconstructed_sn,
        context.last_reconstructed_rtp_ts_full,
        context.last_reconstructed_rtp_marker,
        decoded_ip_id,
    ))
}

/// Parses a UO-1-RTP packet, validates CRC, updates decompressor context, and reconstructs headers.
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

    // For UO-1-RTP, SN is implicitly last_reconstructed_sn + 1
    let reconstructed_sn = context.last_reconstructed_rtp_sn_full.wrapping_add(1);

    let ts_scaled_received =
        parsed_uo1_rtp
            .ts_scaled
            .ok_or_else(|| RohcParsingError::MandatoryFieldMissing {
                field_name: "ts_scaled".to_string(),
                structure_name: "Parsed UO-1-RTP".to_string(),
            })?;

    // Reconstruct full TS from TS_SCALED
    let reconstructed_ts = context
        .reconstruct_ts_from_scaled(ts_scaled_received)
        .ok_or_else(|| {
            RohcError::InvalidState(
                "Cannot reconstruct TS from TS_SCALED for UO-1-RTP: Decompressor TS_STRIDE not established."
                    .to_string(),
            )
        })?;

    // If we successfully decode a UO-1-RTP, it implies the decompressor should
    // now be in scaled mode if it wasn't already (e.g., if stride was only inferred).
    if context.ts_stride.is_some() && !context.ts_scaled_mode {
        context.ts_scaled_mode = true;
        // The ts_offset should align with compressor if this UO-1-RTP is valid.
        // An IR-DYN with TS_STRIDE sets ts_offset explicitly. Here, we trust compressor
        // signaled correctly.
    }
    context.infer_ts_stride_from_decompressed_ts(reconstructed_ts);

    let crc_input_bytes = prepare_generic_uo_crc_input_payload(
        context.rtp_ssrc,
        reconstructed_sn,
        reconstructed_ts,      // Current (reconstructed) TS for CRC
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

    // If we successfully decode a UO-1-RTP, it implies the decompressor should
    // now be in scaled mode if it wasn't already.
    if context.ts_stride.is_some() && !context.ts_scaled_mode {
        // Check before inference might change stride
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
/// Fills in static fields from the context and dynamic fields from parameters.
/// Default values are used for fields not directly conveyed by ROHC P1 common packet types.
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
        ip_total_length: 0, // To be set by caller or network stack
        ip_identification: ip_id,
        ip_dont_fragment: true, // Common default
        ip_more_fragments: false,
        ip_fragment_offset: 0,
        ip_ttl: DEFAULT_IPV4_TTL,
        ip_protocol: IP_PROTOCOL_UDP,
        ip_checksum: 0, // To be set by caller or network stack
        udp_length: 0,  // To be set by caller or network stack
        udp_checksum: 0,
        rtp_version: RTP_VERSION,
        rtp_padding: false,
        rtp_extension: false,
        rtp_csrc_count: 0,
        rtp_payload_type: 0, // Often part of application signaling, not context directly
        rtp_csrc_list: Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crc::CrcCalculators;
    use crate::encodings::encode_lsb;
    use crate::profiles::profile1::compression_logic::build_generic_uo_crc_input;
    use crate::profiles::profile1::context::{
        Profile1DecompressorContext, Profile1DecompressorMode,
    };
    use crate::profiles::profile1::packet_processor::{
        build_profile1_ir_packet, build_profile1_uo0_packet, build_profile1_uo1_id_packet,
        build_profile1_uo1_rtp_packet, build_profile1_uo1_sn_packet, build_profile1_uo1_ts_packet,
    };
    use crate::profiles::profile1::packet_types::{IrPacket, Uo0Packet, Uo1Packet};
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

    #[test]
    fn parse_ir_and_reconstruct_basic() {
        let crc_calculators = CrcCalculators::new();
        let mut context = Profile1DecompressorContext::new(0);
        let ir_content = IrPacket {
            cid: 0,
            profile_id: RohcProfile::RtpUdpIp,
            static_rtp_ssrc: 0x1234,
            dyn_rtp_sn: 100,
            dyn_rtp_timestamp: Timestamp::new(1000),
            dyn_rtp_marker: true,
            ts_stride: None,
            ..Default::default()
        };
        let ir_bytes = build_profile1_ir_packet(&ir_content, &crc_calculators).unwrap();

        let result = parse_and_reconstruct_ir(
            &mut context,
            &ir_bytes,
            &crc_calculators,
            RohcProfile::RtpUdpIp,
        );
        assert!(result.is_ok());
        let headers = result.unwrap();
        assert_eq!(headers.rtp_ssrc, 0x1234);
        assert_eq!(headers.rtp_sequence_number, 100);
        assert_eq!(headers.rtp_timestamp, Timestamp::new(1000));
        assert!(headers.rtp_marker);
        assert_eq!(context.rtp_ssrc, 0x1234); // Context updated
        assert_eq!(context.ts_stride, None);
        assert_eq!(context.ts_offset, Timestamp::new(1000)); // Offset set to IR's TS
    }

    #[test]
    fn parse_ir_with_ts_stride_correctly_updates_context() {
        let crc_calculators = CrcCalculators::new();
        let mut context = Profile1DecompressorContext::new(0);
        let ir_content = IrPacket {
            cid: 0,
            profile_id: RohcProfile::RtpUdpIp,
            static_rtp_ssrc: 0x5678,
            dyn_rtp_sn: 200,
            dyn_rtp_timestamp: Timestamp::new(2000),
            dyn_rtp_marker: false,
            ts_stride: Some(160), // IR signals stride
            ..Default::default()
        };
        let ir_bytes = build_profile1_ir_packet(&ir_content, &crc_calculators).unwrap();

        let _ = parse_and_reconstruct_ir(
            &mut context,
            &ir_bytes,
            &crc_calculators,
            RohcProfile::RtpUdpIp,
        )
        .unwrap();
        assert_eq!(context.ts_stride, Some(160));
        assert_eq!(context.ts_offset, Timestamp::new(2000));
        assert!(context.ts_scaled_mode); // Scaled mode should activate
    }

    #[test]
    fn parse_uo0_and_reconstruct_success() {
        let crc_calculators = CrcCalculators::new();
        let ssrc = 0xABCD;
        let mut context = setup_decomp_context_for_uo(100, 1000, false, 10, ssrc);
        context.expected_lsb_sn_width = P1_UO0_SN_LSB_WIDTH_DEFAULT;

        let target_sn: u16 = 101;
        let sn_lsb = encode_lsb(target_sn as u64, P1_UO0_SN_LSB_WIDTH_DEFAULT).unwrap() as u8;

        let crc_input = build_generic_uo_crc_input(ssrc, target_sn, Timestamp::new(1000), false);
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
        assert_eq!(headers.rtp_timestamp, Timestamp::new(1000)); // From context
        assert_eq!(context.last_reconstructed_rtp_sn_full, target_sn);
    }

    #[test]
    fn parse_uo0_crc_mismatch() {
        let crc_calculators = CrcCalculators::new();
        let mut context = setup_decomp_context_for_uo(100, 1000, false, 10, 0xABCD);
        let uo0_packet_data = Uo0Packet {
            cid: None,
            sn_lsb: 1,
            crc3: 7,
        }; // Assume CRC 7 is wrong
        let uo0_bytes = build_profile1_uo0_packet(&uo0_packet_data).unwrap();

        let result = parse_and_reconstruct_uo0(&mut context, &uo0_bytes, &crc_calculators);
        assert!(matches!(
            result,
            Err(RohcError::Parsing(RohcParsingError::CrcMismatch { .. }))
        ));
    }

    #[test]
    fn parse_uo1_sn_and_reconstruct_success() {
        let crc_calculators = CrcCalculators::new();
        let ssrc = 0x1122;
        let mut context = setup_decomp_context_for_uo(50, 500, false, 5, ssrc);
        context.expected_lsb_sn_width = P1_UO1_SN_LSB_WIDTH_DEFAULT;

        let target_sn: u16 = 55;
        let target_marker = true;
        let sn_lsb_val = encode_lsb(target_sn as u64, P1_UO1_SN_LSB_WIDTH_DEFAULT).unwrap() as u16;

        let crc_input =
            build_generic_uo_crc_input(ssrc, target_sn, Timestamp::new(500), target_marker);
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
        assert_eq!(headers.rtp_marker, target_marker);
        assert_eq!(headers.rtp_timestamp, Timestamp::new(500)); // From context
    }

    #[test]
    fn parse_uo1_ts_and_reconstruct_success() {
        let crc_calculators = CrcCalculators::new();
        let ssrc = 0x3344;
        let mut context = setup_decomp_context_for_uo(200, 2000, false, 20, ssrc);
        context.expected_lsb_ts_width = P1_UO1_TS_LSB_WIDTH_DEFAULT;

        let target_sn: u16 = 201; // SN = last_sn + 1 for UO-1-TS
        let target_ts_val: u32 = 2000 + 160; // TS changes
        let ts_lsb_val =
            encode_lsb(target_ts_val as u64, P1_UO1_TS_LSB_WIDTH_DEFAULT).unwrap() as u16;

        let crc_input =
            build_generic_uo_crc_input(ssrc, target_sn, Timestamp::new(target_ts_val), false);
        let crc8 = crc_calculators.calculate_rohc_crc8(&crc_input);

        let uo1_packet_data = Uo1Packet {
            ts_lsb: Some(ts_lsb_val),
            num_ts_lsb_bits: Some(P1_UO1_TS_LSB_WIDTH_DEFAULT),
            crc8,
            ..Default::default()
        };
        let uo1_bytes = build_profile1_uo1_ts_packet(&uo1_packet_data).unwrap();

        let result = parse_and_reconstruct_uo1_ts(&mut context, &uo1_bytes, &crc_calculators);
        assert!(result.is_ok(), "UO-1-TS parsing failed: {:?}", result.err());
        let headers = result.unwrap();
        assert_eq!(headers.rtp_sequence_number, target_sn);
        assert_eq!(headers.rtp_timestamp, Timestamp::new(target_ts_val));
    }

    #[test]
    fn parse_uo1_id_and_reconstruct_success() {
        let crc_calculators = CrcCalculators::new();
        let ssrc = 0x5566;
        let mut context = setup_decomp_context_for_uo(300, 3000, true, 30, ssrc);
        context.expected_lsb_ip_id_width = P1_UO1_IPID_LSB_WIDTH_DEFAULT;

        let target_sn: u16 = 301; // SN = last_sn + 1
        let target_ip_id: u16 = 30 + 5;
        let ip_id_lsb_val =
            encode_lsb(target_ip_id as u64, P1_UO1_IPID_LSB_WIDTH_DEFAULT).unwrap() as u8;

        let crc_input = prepare_uo1_id_specific_crc_input_payload(
            ssrc,
            target_sn,
            Timestamp::new(3000),
            true,
            ip_id_lsb_val,
        );
        let crc8 = crc_calculators.calculate_rohc_crc8(&crc_input);

        let uo1_packet_data = Uo1Packet {
            ip_id_lsb: Some(ip_id_lsb_val as u16),
            num_ip_id_lsb_bits: Some(P1_UO1_IPID_LSB_WIDTH_DEFAULT),
            crc8,
            ..Default::default()
        };
        let uo1_bytes = build_profile1_uo1_id_packet(&uo1_packet_data).unwrap();

        let result = parse_and_reconstruct_uo1_id(&mut context, &uo1_bytes, &crc_calculators);
        assert!(result.is_ok(), "UO-1-ID parsing failed: {:?}", result.err());
        let headers = result.unwrap();
        assert_eq!(headers.rtp_sequence_number, target_sn);
        assert_eq!(headers.ip_identification, target_ip_id);
    }

    #[test]
    fn parse_uo1_rtp_and_reconstruct_success() {
        let crc_calculators = CrcCalculators::new();
        let ssrc = 0x7788;
        let mut context = setup_decomp_context_for_uo(400, 4000, false, 40, ssrc);
        context.ts_stride = Some(160); // Decompressor has stride
        context.ts_offset = Timestamp::new(4000); // And offset
        context.ts_scaled_mode = true; // And is in scaled mode

        let target_sn: u16 = 401;
        let ts_scaled_val: u8 = 2; // Implies target_ts = 4000 + 2 * 160 = 4320
        let target_ts_val: u32 =
            context.ts_offset.value() + (ts_scaled_val as u32 * context.ts_stride.unwrap());
        let target_marker = true;

        let crc_input = prepare_generic_uo_crc_input_payload(
            ssrc,
            target_sn,
            Timestamp::new(target_ts_val),
            target_marker,
        );
        let crc8 = crc_calculators.calculate_rohc_crc8(&crc_input);

        let uo1_packet_data = Uo1Packet {
            ts_scaled: Some(ts_scaled_val),
            marker: target_marker,
            crc8,
            ..Default::default()
        };
        let uo1_bytes = build_profile1_uo1_rtp_packet(&uo1_packet_data).unwrap();

        let result = parse_and_reconstruct_uo1_rtp(&mut context, &uo1_bytes, &crc_calculators);
        assert!(
            result.is_ok(),
            "UO-1-RTP parsing failed: {:?}",
            result.err()
        );
        let headers = result.unwrap();
        assert_eq!(headers.rtp_sequence_number, target_sn);
        assert_eq!(headers.rtp_timestamp, Timestamp::new(target_ts_val));
        assert_eq!(headers.rtp_marker, target_marker);
    }

    #[test]
    fn parse_uo1_rtp_missing_stride_in_context() {
        let crc_calculators = CrcCalculators::new();
        let mut context = setup_decomp_context_for_uo(400, 4000, false, 40, 0x7788);
        context.ts_stride = None; // No stride established

        let uo1_packet_data = Uo1Packet {
            ts_scaled: Some(1),
            crc8: 0,
            ..Default::default()
        };
        let uo1_bytes = build_profile1_uo1_rtp_packet(&uo1_packet_data).unwrap();

        let result = parse_and_reconstruct_uo1_rtp(&mut context, &uo1_bytes, &crc_calculators);
        assert!(matches!(result, Err(RohcError::InvalidState(_))));
    }
}
