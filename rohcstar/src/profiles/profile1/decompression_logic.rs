//! ROHC Profile 1 decompression logic for RTP/UDP/IP packets.
//!
//! This module implements the decompression-side packet processing for ROHC Profile 1,
//! parsing compressed packet types (IR, UO-0, UO-1 variants) and reconstructing original
//! headers. The decompressor maintains context state to handle LSB-encoded fields and
//! implements timestamp stride inference for efficient RTP stream decompression.

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

/// Parses an IR packet, updates decompressor context, and reconstructs full headers.
///
/// This function handles the core parsing of IR/IR-DYN packet fields, including
/// static chain information (IP addresses, ports, SSRC) and dynamic chain elements
/// (SN, TS, Marker, optional TS_STRIDE). It initializes the decompressor context
/// based on the received IR packet and validates the profile ID.
///
/// # Parameters
/// - `context`: Mutable decompressor context to be updated with information from the IR packet.
/// - `packet_bytes`: Byte slice of the core IR packet (after Add-CID octet processing, if any).
/// - `crc_calculators`: CRC calculator instances for verifying packet integrity.
/// - `handler_profile_id`: Expected ROHC profile ID for this handler, used for validation.
///
/// # Returns
/// - `Ok(RtpUdpIpv4Headers)`: Reconstructed RTP/UDP/IPv4 headers.
/// - `Err(RohcError)`: If parsing fails (e.g., CRC mismatch, invalid profile ID).
pub(super) fn parse_and_reconstruct_ir(
    context: &mut Profile1DecompressorContext,
    packet_bytes: &[u8],
    crc_calculators: &CrcCalculators,
    handler_profile_id: RohcProfile,
) -> Result<RtpUdpIpv4Headers, RohcError> {
    let parsed_ir = parse_profile1_ir_packet(packet_bytes, context.cid(), crc_calculators)?;

    if parsed_ir.profile_id != handler_profile_id {
        return Err(RohcError::Parsing(RohcParsingError::InvalidProfileId(
            parsed_ir.profile_id.into(),
        )));
    }

    context.initialize_from_ir_packet(&parsed_ir);

    // IR packets for Profile 1 do not explicitly carry IP-ID in the dynamic part.
    // The decompressor's context IP-ID will be used (initialized to 0 or from previous state).
    Ok(reconstruct_headers_from_context(
        context,
        parsed_ir.dyn_rtp_sn,
        parsed_ir.dyn_rtp_timestamp,
        parsed_ir.dyn_rtp_marker,
        context.last_reconstructed_ip_id_full,
    ))
}

/// Parses a UO-0 packet, validates CRC, updates decompressor context, and reconstructs headers.
///
/// UO-0 packets carry an LSB-encoded RTP Sequence Number and a 3-bit CRC.
/// The RTP Timestamp is implicitly reconstructed based on the context's TS stride, if established.
/// The RTP Marker bit is assumed to be unchanged from the context.
///
/// # Parameters
/// - `context`: Mutable decompressor context with established state.
/// - `packet_bytes`: Single-byte UO-0 packet (core part, after Add-CID if any).
/// - `crc_calculators`: CRC calculator instances for verification.
///
/// # Returns
/// - `Ok(RtpUdpIpv4Headers)`: Reconstructed RTP/UDP/IPv4 headers.
/// - `Err(RohcError)`: If parsing, CRC validation, or LSB decoding fails.
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

    let new_timestamp = calculate_reconstructed_ts_implicit(context, decoded_sn);

    let crc_input_bytes = prepare_generic_uo_crc_input_payload(
        context.rtp_ssrc,
        decoded_sn,
        new_timestamp,
        context.last_reconstructed_rtp_marker, // UO-0 implies marker is unchanged from context
    );
    let calculated_crc3 = crc_calculators.calculate_rohc_crc3(&crc_input_bytes);

    if calculated_crc3 != parsed_uo0.crc3 {
        return Err(RohcError::Parsing(RohcParsingError::CrcMismatch {
            expected: parsed_uo0.crc3,
            calculated: calculated_crc3,
            crc_type: "CRC3-UO0".to_string(),
        }));
    }

    // Update context after successful CRC validation.
    context.infer_ts_stride_from_decompressed_ts(new_timestamp, decoded_sn);
    context.last_reconstructed_rtp_sn_full = decoded_sn;
    context.last_reconstructed_rtp_ts_full = new_timestamp;
    // Marker and IP-ID remain from context for UO-0.

    Ok(reconstruct_headers_from_context(
        context,
        decoded_sn,
        new_timestamp,
        context.last_reconstructed_rtp_marker,
        context.last_reconstructed_ip_id_full,
    ))
}

/// Parses a UO-1-SN packet, validates CRC, updates context, and reconstructs headers.
///
/// UO-1-SN packets carry LSB-encoded RTP Sequence Number and the current RTP Marker bit.
/// The RTP Timestamp is implicitly reconstructed using the context's TS stride.
///
/// # Parameters
/// - `context`: Mutable decompressor context.
/// - `packet_bytes`: Core UO-1-SN packet data (typically 3 bytes).
/// - `crc_calculators`: CRC calculator instances.
///
/// # Returns
/// - `Ok(RtpUdpIpv4Headers)`: Reconstructed headers.
/// - `Err(RohcError)`: If parsing, CRC validation, or LSB decoding fails.
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

    let new_timestamp = calculate_reconstructed_ts_implicit(context, decoded_sn);

    let crc_input_bytes = prepare_generic_uo_crc_input_payload(
        context.rtp_ssrc,
        decoded_sn,
        new_timestamp,
        parsed_uo1.marker, // UO-1-SN carries the marker bit.
    );
    let calculated_crc8 = crc_calculators.calculate_rohc_crc8(&crc_input_bytes);

    if calculated_crc8 != parsed_uo1.crc8 {
        return Err(RohcError::Parsing(RohcParsingError::CrcMismatch {
            expected: parsed_uo1.crc8,
            calculated: calculated_crc8,
            crc_type: "CRC8-UO1SN".to_string(),
        }));
    }

    context.infer_ts_stride_from_decompressed_ts(new_timestamp, decoded_sn);
    context.last_reconstructed_rtp_sn_full = decoded_sn;
    context.last_reconstructed_rtp_ts_full = new_timestamp;
    context.last_reconstructed_rtp_marker = parsed_uo1.marker;
    // IP-ID remains from context for UO-1-SN.

    Ok(reconstruct_headers_from_context(
        context,
        decoded_sn,
        new_timestamp,
        parsed_uo1.marker,
        context.last_reconstructed_ip_id_full,
    ))
}

/// Parses a UO-1-TS packet, validates CRC, updates context, and reconstructs headers.
///
/// UO-1-TS packets carry an LSB-encoded RTP Timestamp. The RTP Sequence Number is
/// implicitly reconstructed as `last_reconstructed_sn + 1`.
/// The RTP Marker bit is assumed to be unchanged from the context.
///
/// # Parameters
/// - `context`: Mutable decompressor context.
/// - `packet_bytes`: Core UO-1-TS packet data (typically 4 bytes).
/// - `crc_calculators`: CRC calculator instances.
///
/// # Returns
/// - `Ok(RtpUdpIpv4Headers)`: Reconstructed headers.
/// - `Err(RohcError)`: If parsing, CRC, or LSB decoding fails.
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

    // UO-1-TS implies SN increments by 1.
    let reconstructed_sn = context.last_reconstructed_rtp_sn_full.wrapping_add(1);

    let ts_lsb_from_packet = parsed_uo1_ts.ts_lsb.ok_or_else(|| {
        RohcError::Parsing(RohcParsingError::MandatoryFieldMissing {
            field_name: "ts_lsb".to_string(),
            structure_name: "UO1TS".to_string(),
        })
    })?;
    let num_ts_lsb_bits = parsed_uo1_ts.num_ts_lsb_bits.ok_or_else(|| {
        RohcError::Parsing(RohcParsingError::MandatoryFieldMissing {
            field_name: "num_ts_lsb_bits".to_string(),
            structure_name: "UO1TS".to_string(),
        })
    })?;

    let decoded_ts_val = decode_lsb(
        ts_lsb_from_packet as u64,
        context.last_reconstructed_rtp_ts_full.value() as u64,
        num_ts_lsb_bits,
        context.p_ts,
    )? as u32;
    let decoded_ts = Timestamp::new(decoded_ts_val);

    let crc_input_bytes = prepare_generic_uo_crc_input_payload(
        context.rtp_ssrc,
        reconstructed_sn,
        decoded_ts,
        context.last_reconstructed_rtp_marker, // UO-1-TS implies marker is unchanged.
    );
    let calculated_crc8 = crc_calculators.calculate_rohc_crc8(&crc_input_bytes);

    if calculated_crc8 != parsed_uo1_ts.crc8 {
        return Err(RohcError::Parsing(RohcParsingError::CrcMismatch {
            expected: parsed_uo1_ts.crc8,
            calculated: calculated_crc8,
            crc_type: "CRC8-UO1TS".to_string(),
        }));
    }

    context.infer_ts_stride_from_decompressed_ts(decoded_ts, reconstructed_sn);
    context.last_reconstructed_rtp_sn_full = reconstructed_sn;
    context.last_reconstructed_rtp_ts_full = decoded_ts;
    // Marker and IP-ID remain from context for UO-1-TS.

    Ok(reconstruct_headers_from_context(
        context,
        reconstructed_sn,
        decoded_ts,
        context.last_reconstructed_rtp_marker,
        context.last_reconstructed_ip_id_full,
    ))
}

/// Parses a UO-1-ID packet, validates CRC, updates context, and reconstructs headers.
///
/// UO-1-ID packets carry an LSB-encoded IP Identification. The RTP Sequence Number
/// is implicitly reconstructed as `last_reconstructed_sn + 1`.
/// The RTP Timestamp is implicitly reconstructed using the context's TS stride (SN delta is 1).
/// The RTP Marker bit is assumed to be unchanged from the context.
///
/// # Parameters
/// - `context`: Mutable decompressor context.
/// - `packet_bytes`: Core UO-1-ID packet data (typically 3 bytes).
/// - `crc_calculators`: CRC calculator instances.
///
/// # Returns
/// - `Ok(RtpUdpIpv4Headers)`: Reconstructed headers.
/// - `Err(RohcError)`: If parsing, CRC, or LSB decoding fails.
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

    // UO-1-ID implies SN increments by 1.
    let reconstructed_sn = context.last_reconstructed_rtp_sn_full.wrapping_add(1);
    let new_timestamp = calculate_reconstructed_ts_implicit_sn_plus_one(context);

    let ip_id_lsb_from_packet = parsed_uo1_id.ip_id_lsb.ok_or_else(|| {
        RohcError::Parsing(RohcParsingError::MandatoryFieldMissing {
            field_name: "ip_id_lsb".to_string(),
            structure_name: "UO1ID".to_string(),
        })
    })?;
    let num_ip_id_lsb_bits = parsed_uo1_id.num_ip_id_lsb_bits.ok_or_else(|| {
        RohcError::Parsing(RohcParsingError::MandatoryFieldMissing {
            field_name: "num_ip_id_lsb_bits".to_string(),
            structure_name: "UO1ID".to_string(),
        })
    })?;

    let decoded_ip_id = decode_lsb(
        ip_id_lsb_from_packet as u64,
        context.last_reconstructed_ip_id_full as u64,
        num_ip_id_lsb_bits,
        context.p_ip_id,
    )? as u16;

    // UO-1-ID uses a specific CRC input format.
    let crc_input_bytes = prepare_uo1_id_specific_crc_input_payload(
        context.rtp_ssrc,
        reconstructed_sn,
        new_timestamp,                         // Use the implicitly reconstructed TS.
        context.last_reconstructed_rtp_marker, // UO-1-ID implies marker is unchanged.
        ip_id_lsb_from_packet as u8,           // CRC is over the LSBs, not the decoded value.
    );
    let calculated_crc8 = crc_calculators.calculate_rohc_crc8(&crc_input_bytes);

    if calculated_crc8 != parsed_uo1_id.crc8 {
        return Err(RohcError::Parsing(RohcParsingError::CrcMismatch {
            expected: parsed_uo1_id.crc8,
            calculated: calculated_crc8,
            crc_type: "CRC8-UO1ID".to_string(),
        }));
    }

    context.infer_ts_stride_from_decompressed_ts(new_timestamp, reconstructed_sn);
    context.last_reconstructed_rtp_sn_full = reconstructed_sn;
    context.last_reconstructed_rtp_ts_full = new_timestamp;
    context.last_reconstructed_ip_id_full = decoded_ip_id;
    // Marker remains from context for UO-1-ID.

    Ok(reconstruct_headers_from_context(
        context,
        reconstructed_sn,
        new_timestamp,
        context.last_reconstructed_rtp_marker,
        decoded_ip_id,
    ))
}

/// Parses a UO-1-RTP packet, validates CRC, updates context, and reconstructs headers.
///
/// UO-1-RTP packets carry a TS_SCALED value for the RTP Timestamp and the current Marker bit.
/// The RTP Sequence Number is implicitly reconstructed as `last_reconstructed_sn + 1`.
/// Successful decoding requires an established TS stride and offset in the context.
///
/// # Parameters
/// - `context`: Mutable decompressor context (must have TS stride/offset).
/// - `packet_bytes`: Core UO-1-RTP packet data (typically 3 bytes).
/// - `crc_calculators`: CRC calculator instances.
///
/// # Returns
/// - `Ok(RtpUdpIpv4Headers)`: Reconstructed headers.
/// - `Err(RohcError)`: If parsing, TS reconstruction, or CRC validation fails.
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

    // UO-1-RTP implies SN increments by 1.
    let reconstructed_sn = context.last_reconstructed_rtp_sn_full.wrapping_add(1);

    let ts_scaled_received = parsed_uo1_rtp.ts_scaled.ok_or_else(|| {
        RohcError::Parsing(RohcParsingError::MandatoryFieldMissing {
            field_name: "ts_scaled".to_string(),
            structure_name: "UO1RTP".to_string(),
        })
    })?;

    let reconstructed_ts = context
        .reconstruct_ts_from_scaled(ts_scaled_received)
        .ok_or_else(|| {
            RohcError::InvalidState("Cannot reconstruct TS: stride not established".to_string())
        })?;

    let crc_input_bytes = prepare_generic_uo_crc_input_payload(
        context.rtp_ssrc,
        reconstructed_sn,
        reconstructed_ts,
        parsed_uo1_rtp.marker, // UO-1-RTP carries the marker.
    );
    let calculated_crc8 = crc_calculators.calculate_rohc_crc8(&crc_input_bytes);

    if calculated_crc8 != parsed_uo1_rtp.crc8 {
        return Err(RohcError::Parsing(RohcParsingError::CrcMismatch {
            expected: parsed_uo1_rtp.crc8,
            calculated: calculated_crc8,
            crc_type: "CRC8-UO1RTP".to_string(),
        }));
    }

    // Successful UO-1-RTP implies decompressor should be in (or enter) scaled mode if stride is known.
    if context.ts_stride.is_some() && !context.ts_scaled_mode {
        context.ts_scaled_mode = true;
    }

    context.infer_ts_stride_from_decompressed_ts(reconstructed_ts, reconstructed_sn);
    context.last_reconstructed_rtp_sn_full = reconstructed_sn;
    context.last_reconstructed_rtp_ts_full = reconstructed_ts;
    context.last_reconstructed_rtp_marker = parsed_uo1_rtp.marker;
    // IP-ID remains from context for UO-1-RTP.

    Ok(reconstruct_headers_from_context(
        context,
        reconstructed_sn,
        reconstructed_ts,
        parsed_uo1_rtp.marker,
        context.last_reconstructed_ip_id_full,
    ))
}

/// Reconstructs full `RtpUdpIpv4Headers` from decompressor context and current dynamic fields.
///
/// Combines static fields from the context (IP addresses, ports, SSRC) with the provided
/// dynamic fields (SN, TS, Marker, IP-ID). Uses standard defaults for fields not directly
/// conveyed by ROHC Profile 1 packets (e.g., TTL, DSCP).
///
/// # Parameters
/// - `context`: Decompressor context holding static chain information.
/// - `sn`: Current RTP sequence number.
/// - `ts`: Current RTP timestamp.
/// - `marker`: Current RTP marker bit.
/// - `ip_id`: Current IP Identification value.
///
/// # Returns
/// Fully reconstructed `RtpUdpIpv4Headers`.
fn reconstruct_headers_from_context(
    context: &Profile1DecompressorContext,
    sn: u16,
    ts: Timestamp,
    marker: bool,
    ip_id: u16,
) -> RtpUdpIpv4Headers {
    debug_assert_ne!(
        context.rtp_ssrc, 0,
        "Context SSRC must be initialized for header reconstruction."
    );

    RtpUdpIpv4Headers {
        // Static fields from context
        ip_src: context.ip_source,
        ip_dst: context.ip_destination,
        udp_src_port: context.udp_source_port,
        udp_dst_port: context.udp_destination_port,
        rtp_ssrc: context.rtp_ssrc,

        // Dynamic fields from current packet
        rtp_sequence_number: sn,
        rtp_timestamp: ts,
        rtp_marker: marker,
        ip_identification: ip_id,

        // Fixed or default values for Profile 1 reconstruction
        ip_ihl: IPV4_STANDARD_IHL,
        ip_dscp: 0,
        ip_ecn: 0,
        ip_total_length: 0,     // Typically set by higher layers or network stack
        ip_dont_fragment: true, // Common assumption for ROHC Profile 1
        ip_more_fragments: false,
        ip_fragment_offset: 0,
        ip_ttl: DEFAULT_IPV4_TTL,
        ip_protocol: IP_PROTOCOL_UDP,
        ip_checksum: 0,  // Recalculated by network stack
        udp_length: 0,   // Recalculated by higher layers
        udp_checksum: 0, // May be 0 if not used, or recalculated
        rtp_version: RTP_VERSION,
        rtp_padding: false,   // Assumed false unless payload indicates otherwise
        rtp_extension: false, // Assumed false
        rtp_csrc_count: 0,    // Assumed 0
        rtp_payload_type: 0,  // Application-specific, not typically in ROHC context
        rtp_csrc_list: Vec::new(),
    }
}

/// Calculates reconstructed RTP timestamp based on SN delta and context stride.
/// If no stride, returns context's last TS.
fn calculate_reconstructed_ts_implicit(
    context: &Profile1DecompressorContext,
    decoded_sn: u16,
) -> Timestamp {
    if let Some(stride) = context.ts_stride {
        let sn_delta = decoded_sn.wrapping_sub(context.last_reconstructed_rtp_sn_full);
        if sn_delta > 0 {
            Timestamp::new(
                context
                    .last_reconstructed_rtp_ts_full
                    .value()
                    .wrapping_add(sn_delta as u32 * stride),
            )
        } else {
            context.last_reconstructed_rtp_ts_full
        }
    } else {
        context.last_reconstructed_rtp_ts_full
    }
}

/// Calculates reconstructed RTP timestamp assuming SN increments by 1 and context has a stride.
/// If no stride, returns context's last TS.
fn calculate_reconstructed_ts_implicit_sn_plus_one(
    context: &Profile1DecompressorContext,
) -> Timestamp {
    if let Some(stride) = context.ts_stride {
        Timestamp::new(
            context
                .last_reconstructed_rtp_ts_full
                .value()
                .wrapping_add(stride), // SN delta is 1
        )
    } else {
        context.last_reconstructed_rtp_ts_full
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
        build_profile1_ir_packet, build_profile1_uo0_packet, build_profile1_uo1_id_packet,
        build_profile1_uo1_sn_packet,
    };
    use crate::profiles::profile1::packet_types::{IrPacket, Uo0Packet, Uo1Packet};
    use crate::profiles::profile1::*; // For constants like P1_ROHC_IR_PACKET_TYPE_STATIC_ONLY

    fn create_test_context(
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

    fn create_context_with_stride(
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
        context.ts_stride = Some(ts_stride);
        context.ts_offset = Timestamp::new(initial_ts);
        context.expected_lsb_sn_width = P1_UO0_SN_LSB_WIDTH_DEFAULT;
        context.mode = Profile1DecompressorMode::FullContext;
        context
    }

    fn build_uo0_with_crc(
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
    fn p1_uo0_implicit_ts_update_single_packet() {
        let crc_calculators = CrcCalculators::new();
        let ssrc = 0x12345678;
        let ts_stride = 160;
        let mut context = create_context_with_stride(100, 1000, ts_stride, ssrc);

        // SN 100 → 101, TS should be 1000 + 160 = 1160
        let target_sn = 101;
        let expected_ts = Timestamp::new(1160);
        let uo0_bytes = build_uo0_with_crc(target_sn, expected_ts, false, ssrc, &crc_calculators);

        let result = parse_and_reconstruct_uo0(&mut context, &uo0_bytes, &crc_calculators);
        assert!(result.is_ok());

        let headers = result.unwrap();
        assert_eq!(headers.rtp_sequence_number, target_sn);
        assert_eq!(headers.rtp_timestamp, expected_ts);
        assert_eq!(context.last_reconstructed_rtp_sn_full, target_sn);
        assert_eq!(context.last_reconstructed_rtp_ts_full, expected_ts);
    }

    #[test]
    fn p1_uo0_implicit_ts_update_sequence() {
        let crc_calculators = CrcCalculators::new();
        let ssrc = 0x87654321;
        let ts_stride = 160;
        let mut context = create_context_with_stride(50, 2000, ts_stride, ssrc);

        // Packet 1: SN 50 → 51, TS 2000 → 2160
        let uo0_1 = build_uo0_with_crc(51, Timestamp::new(2160), false, ssrc, &crc_calculators);
        let result1 = parse_and_reconstruct_uo0(&mut context, &uo0_1, &crc_calculators).unwrap();
        assert_eq!(result1.rtp_timestamp, Timestamp::new(2160));

        // Packet 2: SN 51 → 52, TS 2160 → 2320
        let uo0_2 = build_uo0_with_crc(52, Timestamp::new(2320), false, ssrc, &crc_calculators);
        let result2 = parse_and_reconstruct_uo0(&mut context, &uo0_2, &crc_calculators).unwrap();
        assert_eq!(result2.rtp_timestamp, Timestamp::new(2320));

        // Packet 3: SN 52 → 53, TS 2320 → 2480
        let uo0_3 = build_uo0_with_crc(53, Timestamp::new(2480), false, ssrc, &crc_calculators);
        let result3 = parse_and_reconstruct_uo0(&mut context, &uo0_3, &crc_calculators).unwrap();
        assert_eq!(result3.rtp_timestamp, Timestamp::new(2480));
    }

    #[test]
    fn p1_uo0_no_stride_no_ts_update() {
        let crc_calculators = CrcCalculators::new();
        let ssrc = 0xABCDEF00;
        let mut context = create_test_context(100, 1000, false, 10, ssrc);
        // No stride set in create_test_context by default

        let target_sn = 101;
        let expected_ts = Timestamp::new(1000); // Should remain unchanged
        let uo0_bytes = build_uo0_with_crc(target_sn, expected_ts, false, ssrc, &crc_calculators);

        let result = parse_and_reconstruct_uo0(&mut context, &uo0_bytes, &crc_calculators).unwrap();
        assert_eq!(result.rtp_timestamp, expected_ts);
    }

    #[test]
    fn p1_uo0_wraparound_handling() {
        let crc_calculators = CrcCalculators::new();
        let ssrc = 0x11111111;
        let ts_stride = 160;
        let mut context = create_context_with_stride(65535, u32::MAX - 80, ts_stride, ssrc);

        // SN wraps: 65535 → 0, TS wraps
        let target_sn = 0;
        let expected_ts = Timestamp::new((u32::MAX - 80).wrapping_add(ts_stride));
        let uo0_bytes = build_uo0_with_crc(target_sn, expected_ts, false, ssrc, &crc_calculators);

        let result = parse_and_reconstruct_uo0(&mut context, &uo0_bytes, &crc_calculators).unwrap();
        assert_eq!(result.rtp_timestamp, expected_ts);
    }

    #[test]
    fn p1_uo1_sn_implicit_ts_update() {
        let crc_calculators = CrcCalculators::new();
        let ssrc = 0x22222222;
        let ts_stride = 160;
        let mut context = create_context_with_stride(200, 3000, ts_stride, ssrc);
        context.expected_lsb_sn_width = P1_UO1_SN_LSB_WIDTH_DEFAULT;

        // SN 200 → 205 (delta=5), TS should be 3000 + (5 * 160) = 3800
        let target_sn = 205;
        let expected_ts = Timestamp::new(3800);
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
        assert!(result.is_ok());

        let headers = result.unwrap();
        assert_eq!(headers.rtp_timestamp, expected_ts);
    }

    #[test]
    fn p1_uo1_id_implicit_ts_update() {
        let crc_calculators = CrcCalculators::new();
        let ssrc = 0x33333333;
        let ts_stride = 160;
        let mut context = create_context_with_stride(300, 4000, ts_stride, ssrc);
        context.expected_lsb_ip_id_width = P1_UO1_IPID_LSB_WIDTH_DEFAULT;

        // SN 300 → 301 (delta=1), TS should be 4000 + 160 = 4160
        let target_sn = 301;
        let expected_ts = Timestamp::new(4160);
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
        assert!(result.is_ok());

        let headers = result.unwrap();
        assert_eq!(headers.rtp_timestamp, expected_ts);
    }

    #[test]
    fn p1_mixed_packet_sequence() {
        let crc_calculators = CrcCalculators::new();
        let ssrc = 0x44444444;
        let ts_stride = 160;
        let mut context = create_context_with_stride(400, 5000, ts_stride, ssrc);

        // Packet 1: UO-0, SN 400 → 401, TS 5000 → 5160
        let uo0_bytes =
            build_uo0_with_crc(401, Timestamp::new(5160), false, ssrc, &crc_calculators);
        let result1 =
            parse_and_reconstruct_uo0(&mut context, &uo0_bytes, &crc_calculators).unwrap();
        assert_eq!(result1.rtp_timestamp, Timestamp::new(5160));

        // Packet 2: UO-1-SN, SN 401 → 402, TS 5160 → 5320
        let sn_lsb = encode_lsb(402u64, P1_UO1_SN_LSB_WIDTH_DEFAULT).unwrap() as u16;
        let crc_input = prepare_generic_uo_crc_input_payload(ssrc, 402, Timestamp::new(5320), true);
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
        assert_eq!(result2.rtp_timestamp, Timestamp::new(5320));
    }

    #[test]
    fn p1_large_sn_delta_ts_calculation() {
        let crc_calculators = CrcCalculators::new();
        let ssrc = 0x55555555;
        let ts_stride = 160;
        let mut context = create_context_with_stride(1000, 10000, ts_stride, ssrc);

        // Large SN jump: 1000 → 1010 (delta=10), TS should be 10000 + (10 * 160) = 11600
        let target_sn = 1010;
        let expected_ts = Timestamp::new(11600);
        let uo0_bytes = build_uo0_with_crc(target_sn, expected_ts, false, ssrc, &crc_calculators);

        let result = parse_and_reconstruct_uo0(&mut context, &uo0_bytes, &crc_calculators).unwrap();
        assert_eq!(result.rtp_timestamp, expected_ts);
    }

    #[test]
    fn p1_different_stride_values() {
        let crc_calculators = CrcCalculators::new();
        let ssrc = 0x66666666;

        for &stride in &[160, 240, 320, 480, 960] {
            let mut context = create_context_with_stride(100, 1000, stride, ssrc);

            let target_sn = 102; // delta = 2
            let expected_ts = Timestamp::new(1000 + (2 * stride));
            let uo0_bytes =
                build_uo0_with_crc(target_sn, expected_ts, false, ssrc, &crc_calculators);

            let result =
                parse_and_reconstruct_uo0(&mut context, &uo0_bytes, &crc_calculators).unwrap();
            assert_eq!(result.rtp_timestamp, expected_ts);
        }
    }

    #[test]
    fn p1_crc_mismatch_detection() {
        let crc_calculators = CrcCalculators::new();
        let ssrc = 0x77777777;
        let mut context = create_test_context(100, 1000, false, 10, ssrc);

        let target_sn = 101u16;
        let sn_lsb = encode_lsb(target_sn as u64, P1_UO0_SN_LSB_WIDTH_DEFAULT).unwrap() as u8;

        // Determine the TS the decompressor will use for CRC calculation
        let ts_for_crc_calc = if let Some(stride) = context.ts_stride {
            Timestamp::new(context.last_reconstructed_rtp_ts_full.value().wrapping_add(
                target_sn.wrapping_sub(context.last_reconstructed_rtp_sn_full) as u32 * stride,
            ))
        } else {
            context.last_reconstructed_rtp_ts_full
        };

        // Calculate the correct CRC for this SN and context state
        let correct_crc_input = prepare_generic_uo_crc_input_payload(
            ssrc,
            target_sn,
            ts_for_crc_calc,
            context.last_reconstructed_rtp_marker,
        );
        let correct_crc3 = crc_calculators.calculate_rohc_crc3(&correct_crc_input);

        // Ensure wrong_crc3 is actually different
        let wrong_crc3 = (correct_crc3 + 1) & 0x07; // Guarantees it's different and still 3-bit

        let uo0_packet_with_bad_crc = Uo0Packet {
            cid: None,
            sn_lsb,
            crc3: wrong_crc3,
        };
        let uo0_bytes_bad_crc = build_profile1_uo0_packet(&uo0_packet_with_bad_crc).unwrap();

        let result = parse_and_reconstruct_uo0(&mut context, &uo0_bytes_bad_crc, &crc_calculators);
        assert!(
            result.is_err(),
            "Decompression should fail due to CRC mismatch"
        );

        if let Err(RohcError::Parsing(RohcParsingError::CrcMismatch {
            expected,
            calculated,
            crc_type,
        })) = result
        {
            assert_eq!(expected, wrong_crc3);
            assert_eq!(calculated, correct_crc3);
            assert_eq!(crc_type, "CRC3-UO0");
        } else {
            panic!("Expected CrcMismatch error, got {:?}", result);
        }
    }

    #[test]
    fn p1_uo1_ts_explicit_ts_update() {
        let crc_calculators = CrcCalculators::new();
        let ssrc = 0x88888888;
        let mut context = create_test_context(100, 1000, false, 10, ssrc);
        context.expected_lsb_ts_width = P1_UO1_TS_LSB_WIDTH_DEFAULT;

        // Build UO-1-TS packet
        let new_ts = Timestamp::new(1500);
        let ts_lsb = encode_lsb(new_ts.value() as u64, P1_UO1_TS_LSB_WIDTH_DEFAULT).unwrap() as u16;

        // SN increments implicitly
        let expected_sn = 101;
        let crc_input = prepare_generic_uo_crc_input_payload(ssrc, expected_sn, new_ts, false);
        let crc8 = crc_calculators.calculate_rohc_crc8(&crc_input);

        // Build packet manually to ensure proper format
        let packet_bytes = vec![
            P1_UO_1_TS_DISCRIMINATOR,
            (ts_lsb >> 8) as u8,
            ts_lsb as u8,
            crc8,
        ];

        let result = parse_and_reconstruct_uo1_ts(&mut context, &packet_bytes, &crc_calculators);
        assert!(result.is_ok());

        let headers = result.unwrap();
        assert_eq!(headers.rtp_sequence_number, expected_sn);
        assert_eq!(headers.rtp_timestamp, new_ts);
    }

    #[test]
    fn p1_uo1_rtp_scaled_mode() {
        let crc_calculators = CrcCalculators::new();
        let ssrc = 0x99999999;
        let ts_stride = 160;
        let mut context = create_context_with_stride(100, 1000, ts_stride, ssrc);
        context.ts_scaled_mode = true;

        // Build UO-1-RTP packet with TS_SCALED = 2
        let ts_scaled = 2u8;
        let expected_sn = 101;
        let expected_ts = Timestamp::new(1000 + (2 * ts_stride)); // 1320
        let marker = true;

        let crc_input =
            prepare_generic_uo_crc_input_payload(ssrc, expected_sn, expected_ts, marker);
        let crc8 = crc_calculators.calculate_rohc_crc8(&crc_input);

        // Build packet manually
        let packet_bytes = vec![
            P1_UO_1_RTP_DISCRIMINATOR_BASE
                | (if marker {
                    P1_UO_1_RTP_MARKER_BIT_MASK
                } else {
                    0
                }),
            ts_scaled,
            crc8,
        ];

        let result = parse_and_reconstruct_uo1_rtp(&mut context, &packet_bytes, &crc_calculators);
        assert!(result.is_ok());

        let headers = result.unwrap();
        assert_eq!(headers.rtp_sequence_number, expected_sn);
        assert_eq!(headers.rtp_timestamp, expected_ts);
        assert_eq!(headers.rtp_marker, marker);
    }

    #[test]
    fn p1_uo1_rtp_no_stride_fails() {
        let crc_calculators = CrcCalculators::new();
        let ssrc = 0xAAAAAAAA;
        let mut context = create_test_context(100, 1000, false, 10, ssrc);
        // No stride set (ts_stride = None by default from create_test_context)

        let packet_bytes = vec![P1_UO_1_RTP_DISCRIMINATOR_BASE, 1, 0xFF]; // Example UO-1-RTP

        let result = parse_and_reconstruct_uo1_rtp(&mut context, &packet_bytes, &crc_calculators);
        assert!(result.is_err());

        if let Err(RohcError::InvalidState(msg)) = result {
            assert!(
                msg.contains("stride not established"),
                "Error message was: {}",
                msg
            );
        } else {
            panic!(
                "Expected InvalidState error for UO-1-RTP without stride, got {:?}",
                result
            );
        }
    }

    #[test]
    fn p1_ir_packet_profile_mismatch() {
        let crc_calculators = CrcCalculators::new();
        let mut context = Profile1DecompressorContext::new(0);

        let wrong_profile = RohcProfile::Uncompressed; // 0x00

        let mut ir_payload_content = Vec::new();
        ir_payload_content.push(u8::from(wrong_profile));
        ir_payload_content.extend_from_slice(&[0u8; P1_STATIC_CHAIN_LENGTH_BYTES]);
        // For IR-STATIC, CRC is over Profile ID + Static Chain only.
        let crc = crc_calculators.calculate_rohc_crc8(&ir_payload_content);

        let mut full_ir_static_packet_bytes = Vec::new();
        full_ir_static_packet_bytes.push(P1_ROHC_IR_PACKET_TYPE_STATIC_ONLY); // Type
        full_ir_static_packet_bytes.extend_from_slice(&ir_payload_content); // Profile + Static
        full_ir_static_packet_bytes.push(crc); // CRC

        assert_eq!(
            full_ir_static_packet_bytes.len(),
            1 + 1 + P1_STATIC_CHAIN_LENGTH_BYTES + 1,
            "Constructed IR-STATIC packet length is incorrect."
        );

        let result = parse_and_reconstruct_ir(
            &mut context,
            &full_ir_static_packet_bytes,
            &crc_calculators,
            RohcProfile::RtpUdpIp, // Handler expects RtpUdpIp
        );

        assert!(
            result.is_err(),
            "Expected error due to profile mismatch, got Ok: {:?}",
            result.ok()
        );
        if let Err(RohcError::Parsing(RohcParsingError::InvalidProfileId(id))) = result {
            assert_eq!(
                id,
                u8::from(wrong_profile),
                "Mismatch in reported wrong profile ID"
            );
        } else {
            panic!(
                "Expected InvalidProfileId error, got {:?}. Packet: {:02X?}",
                result, full_ir_static_packet_bytes
            );
        }
    }

    #[test]
    fn p1_context_update_after_successful_decompress() {
        let crc_calculators = CrcCalculators::new();
        let ssrc = 0xBBBBBBBB;
        let mut context = create_test_context(100, 1000, false, 10, ssrc);

        let target_sn = 101;
        let expected_ts = Timestamp::new(1000); // UO-0 implies TS unchanged if no stride
        let uo0_bytes = build_uo0_with_crc(target_sn, expected_ts, false, ssrc, &crc_calculators);

        let _ = parse_and_reconstruct_uo0(&mut context, &uo0_bytes, &crc_calculators).unwrap();

        // Verify context was updated
        assert_eq!(context.last_reconstructed_rtp_sn_full, target_sn);
        assert_eq!(context.last_reconstructed_rtp_ts_full, expected_ts);
        assert_eq!(context.last_reconstructed_rtp_marker, false);
    }

    #[test]
    fn p1_stride_inference_updates() {
        let mut context = create_test_context(100, 1000, false, 10, 0xCCCCCCCC);
        // Initially no stride
        assert!(context.ts_stride.is_none());

        context.last_reconstructed_rtp_sn_full = 100;
        context.last_reconstructed_rtp_ts_full = Timestamp::new(1000);

        context.infer_ts_stride_from_decompressed_ts(Timestamp::new(1200), 101);

        assert_eq!(context.ts_stride, Some(200));
        assert_eq!(context.ts_offset, Timestamp::new(1000));
    }

    #[test]
    fn p1_reconstruct_headers_values() {
        let mut context = Profile1DecompressorContext::new(0);
        context.rtp_ssrc = 0xDEADBEEF;
        context.ip_source = "10.0.0.1".parse().unwrap();
        context.ip_destination = "10.0.0.2".parse().unwrap();
        context.udp_source_port = 5000;
        context.udp_destination_port = 6000;

        let headers =
            reconstruct_headers_from_context(&context, 12345, Timestamp::new(98765), true, 54321);

        // Verify static chain
        assert_eq!(headers.rtp_ssrc, 0xDEADBEEF);
        assert_eq!(headers.ip_src.to_string(), "10.0.0.1");
        assert_eq!(headers.ip_dst.to_string(), "10.0.0.2");
        assert_eq!(headers.udp_src_port, 5000);
        assert_eq!(headers.udp_dst_port, 6000);

        // Verify dynamic fields
        assert_eq!(headers.rtp_sequence_number, 12345);
        assert_eq!(headers.rtp_timestamp, Timestamp::new(98765));
        assert!(headers.rtp_marker);
        assert_eq!(headers.ip_identification, 54321);

        // Verify defaults
        assert_eq!(headers.ip_ttl, DEFAULT_IPV4_TTL);
        assert_eq!(headers.ip_protocol, IP_PROTOCOL_UDP);
        assert_eq!(headers.rtp_version, RTP_VERSION);
    }

    #[test]
    fn p1_lsb_decoding_edge_cases() {
        let crc_calculators = CrcCalculators::new();
        let ssrc = 0xEEEEEEEE;
        let mut context = create_test_context(65530, 1000, false, 10, ssrc);
        context.expected_lsb_sn_width = P1_UO0_SN_LSB_WIDTH_DEFAULT; // e.g., 4 bits

        // Test wraparound: 65530 → 2 (SN_LSB should be 2)
        // Ref is 65530, LSB width is 4, p_offset is 0 for SN.
        // decode_lsb(2, 65530, 4, 0) should yield 2.
        let target_sn = 2;
        let uo0_bytes = build_uo0_with_crc(
            target_sn,
            Timestamp::new(1000),
            false,
            ssrc,
            &crc_calculators,
        );

        let result = parse_and_reconstruct_uo0(&mut context, &uo0_bytes, &crc_calculators);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().rtp_sequence_number, target_sn);
    }

    #[test]
    fn p1_marker_bit_transitions() {
        let crc_calculators = CrcCalculators::new();
        let ssrc = 0xFFFFFFFF;
        let mut context = create_test_context(100, 1000, false, 10, ssrc); // Marker is false in context
        context.expected_lsb_sn_width = P1_UO1_SN_LSB_WIDTH_DEFAULT; // Assume UO-1-SN for marker bit encoding
        context.ts_stride = Some(160); // UO-1-SN needs stride for TS reconstruction.

        // UO-1-SN with marker bit set
        let target_sn = 101;
        let target_marker = true;
        let sn_lsb = encode_lsb(target_sn as u64, P1_UO1_SN_LSB_WIDTH_DEFAULT).unwrap() as u16;
        let expected_ts_for_crc = calculate_reconstructed_ts_implicit(&context, target_sn);

        let crc_input = prepare_generic_uo_crc_input_payload(
            ssrc,
            target_sn,
            expected_ts_for_crc, // Use implicitly calculated TS for CRC
            target_marker,
        );
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
        assert!(
            result.is_ok(),
            "Parsing UO-1-SN for marker transition failed: {:?}",
            result.err()
        );

        let headers = result.unwrap();
        assert!(
            headers.rtp_marker,
            "Reconstructed marker bit should be true"
        );
        assert!(
            context.last_reconstructed_rtp_marker,
            "Context marker should be updated to true"
        );
    }
}
