//! UO-1 packet decompression for ROHC Profile 1.
//!
//! Handles decompression of UO-1 packet variants (UO-1-SN, UO-1-TS, UO-1-ID, UO-1-RTP)
//! which carry different combinations of sequence number, timestamp, and IP-ID information.

use crate::CrcType;
use crate::Field;
use crate::StructureType;
use crate::crc::CrcCalculators;
use crate::encodings::decode_lsb;
use crate::error::{DecompressionError, RohcError, RohcParsingError};
use crate::traits::RohcDecompressorContext;
use crate::types::{IpId, Timestamp};

use super::super::constants::P1_MAX_REASONABLE_SN_JUMP;
use super::super::context::Profile1DecompressorContext;
use super::super::serialization::uo1_packets::{
    deserialize_uo1_id, deserialize_uo1_rtp, deserialize_uo1_sn, deserialize_uo1_ts,
    prepare_generic_uo_crc_input_into_buf, prepare_generic_uo_crc_input_payload,
    prepare_uo1_id_specific_crc_input_into_buf, prepare_uo1_id_specific_crc_input_payload,
};
use super::recovery::{
    LsbConstraint, calculate_reconstructed_ts_implicit,
    calculate_reconstructed_ts_implicit_sn_plus_one, reconstruct_headers_from_context,
    try_sn_recovery,
};
use crate::protocol_types::RtpUdpIpv4Headers;

/// Decompresses a UO-1-SN packet, validates CRC, updates context, and reconstructs headers.
///
/// UO-1-SN packets carry LSB-encoded RTP Sequence Number and the current RTP Marker bit.
/// The RTP Timestamp is implicitly reconstructed using the context's TS stride.
///
/// # Parameters
/// - `context`: Mutable decompressor context to update with new state
/// - `packet`: Core UO-1-SN packet data (after Add-CID processing, if any)
/// - `crc_calculators`: CRC calculator instances for verification
///
/// # Returns
/// The reconstructed RTP/UDP/IPv4 headers.
///
/// # Errors
/// - [`RohcError::Parsing`] - CRC mismatch or unreasonable sequence number jump
pub fn decompress_as_uo1_sn(
    context: &mut Profile1DecompressorContext,
    packet: &[u8],
    crc_calculators: &CrcCalculators,
) -> Result<RtpUdpIpv4Headers, RohcError> {
    debug_assert_eq!(packet.len(), 3, "UO-1-SN core packet must be 3 bytes long.");

    let parsed_uo1 = deserialize_uo1_sn(packet)?;

    let decoded_sn = decode_lsb(
        parsed_uo1.sn_lsb as u64,
        context.last_reconstructed_rtp_sn_full.as_u64(),
        parsed_uo1.num_sn_lsb_bits,
        context.p_sn,
    )? as u16;

    let decoded_ts = calculate_reconstructed_ts_implicit(context, decoded_sn.into());

    let crc_input_bytes = prepare_generic_uo_crc_input_payload(
        context.rtp_ssrc,
        decoded_sn.into(),
        decoded_ts,
        parsed_uo1.marker,
    );
    let calculated_crc8 = crc_calculators.crc8(&crc_input_bytes);

    if calculated_crc8 != parsed_uo1.crc8 {
        match try_sn_recovery(
            context,
            parsed_uo1.crc8,
            CrcType::Crc8Uo1Sn,
            32,
            8,
            Some(LsbConstraint {
                value: parsed_uo1.sn_lsb as u8,
                bits: parsed_uo1.num_sn_lsb_bits,
            }),
            |input| crc_calculators.crc8(input),
            |candidate_sn, candidate_ts, buf| {
                prepare_generic_uo_crc_input_into_buf(
                    context.rtp_ssrc,
                    candidate_sn,
                    candidate_ts,
                    parsed_uo1.marker,
                    buf,
                )
            },
        ) {
            Ok(recovery_sn) => {
                let decoded_ts = calculate_reconstructed_ts_implicit(context, recovery_sn);

                context.infer_ts_stride_from_decompressed_ts(decoded_ts, recovery_sn);
                context.last_reconstructed_rtp_sn_full = recovery_sn;
                context.last_reconstructed_rtp_ts_full = decoded_ts;
                context.last_reconstructed_rtp_marker = parsed_uo1.marker;

                return Ok(reconstruct_headers_from_context(
                    context,
                    recovery_sn,
                    decoded_ts,
                    parsed_uo1.marker,
                    context.last_reconstructed_ip_id_full,
                ));
            }
            Err(_) => {
                return Err(RohcError::Parsing(RohcParsingError::CrcMismatch {
                    expected: parsed_uo1.crc8,
                    calculated: calculated_crc8,
                    crc_type: CrcType::Crc8Uo1Sn,
                }));
            }
        }
    }

    // Sanity check: Only validate after CRC passes to avoid penalizing hot path
    let expected_sn_range_start = context.last_reconstructed_rtp_sn_full.wrapping_add(1);
    let sn_diff_forward = decoded_sn.wrapping_sub(expected_sn_range_start.value());
    let sn_diff_backward = expected_sn_range_start.value().wrapping_sub(decoded_sn);

    if sn_diff_forward > P1_MAX_REASONABLE_SN_JUMP && sn_diff_backward > P1_MAX_REASONABLE_SN_JUMP {
        if let Ok(recovery_sn) = try_sn_recovery(
            context,
            parsed_uo1.crc8,
            CrcType::Crc8Uo1Sn,
            32,
            8,
            Some(LsbConstraint {
                value: parsed_uo1.sn_lsb as u8,
                bits: parsed_uo1.num_sn_lsb_bits,
            }),
            |input| crc_calculators.crc8(input),
            |candidate_sn, candidate_ts, buf| {
                prepare_generic_uo_crc_input_into_buf(
                    context.rtp_ssrc,
                    candidate_sn,
                    candidate_ts,
                    parsed_uo1.marker,
                    buf,
                )
            },
        ) {
            let decoded_ts = calculate_reconstructed_ts_implicit(context, recovery_sn);

            context.infer_ts_stride_from_decompressed_ts(decoded_ts, recovery_sn);
            context.last_reconstructed_rtp_sn_full = recovery_sn;
            context.last_reconstructed_rtp_ts_full = decoded_ts;
            context.last_reconstructed_rtp_marker = parsed_uo1.marker;

            return Ok(reconstruct_headers_from_context(
                context,
                recovery_sn,
                decoded_ts,
                parsed_uo1.marker,
                context.last_reconstructed_ip_id_full,
            ));
        }
    }

    let final_sn = decoded_sn.into();

    context.infer_ts_stride_from_decompressed_ts(decoded_ts, final_sn);
    context.last_reconstructed_rtp_sn_full = final_sn;
    context.last_reconstructed_rtp_ts_full = decoded_ts;
    context.last_reconstructed_rtp_marker = parsed_uo1.marker;

    Ok(reconstruct_headers_from_context(
        context,
        final_sn,
        decoded_ts,
        parsed_uo1.marker,
        context.last_reconstructed_ip_id_full,
    ))
}

/// Decompresses a UO-1-TS packet, validates CRC, updates context, and reconstructs headers.
///
/// UO-1-TS packets carry an LSB-encoded RTP Timestamp. The RTP Sequence Number is
/// implicitly reconstructed as `last_reconstructed_sn + 1`.
/// The RTP Marker bit is assumed to be unchanged from the context.
///
/// # Parameters
/// - `context`: Mutable decompressor context to update with new state
/// - `packet`: Core UO-1-TS packet data (after Add-CID processing, if any)
/// - `crc_calculators`: CRC calculator instances for verification
///
/// # Returns
/// The reconstructed RTP/UDP/IPv4 headers.
///
/// # Errors
/// - [`RohcError::Parsing`] - Missing mandatory fields or CRC mismatch
pub fn decompress_as_uo1_ts(
    context: &mut Profile1DecompressorContext,
    packet: &[u8],
    crc_calculators: &CrcCalculators,
) -> Result<RtpUdpIpv4Headers, RohcError> {
    debug_assert_eq!(packet.len(), 4, "UO-1-TS core packet must be 4 bytes long.");

    let parsed_uo1_ts = deserialize_uo1_ts(packet)?;

    let ts_lsb = parsed_uo1_ts.ts_lsb.ok_or({
        RohcError::Parsing(RohcParsingError::MandatoryFieldMissing {
            field: Field::TsLsb,
            structure: StructureType::Uo1TsPacket,
        })
    })?;
    let ts_lsb_bits = parsed_uo1_ts.num_ts_lsb_bits.ok_or({
        RohcError::Parsing(RohcParsingError::MandatoryFieldMissing {
            field: Field::NumTsLsbBits,
            structure: StructureType::Uo1TsPacket,
        })
    })?;

    let decoded_ts_value = decode_lsb(
        ts_lsb as u64,
        context.last_reconstructed_rtp_ts_full.value() as u64,
        ts_lsb_bits,
        context.p_ts,
    )? as u32;
    let decoded_ts = Timestamp::new(decoded_ts_value);
    let expected_sn = context.last_reconstructed_rtp_sn_full.wrapping_add(1);
    let crc_input_bytes = prepare_generic_uo_crc_input_payload(
        context.rtp_ssrc,
        expected_sn,
        decoded_ts,
        context.last_reconstructed_rtp_marker,
    );
    let calculated_crc8 = crc_calculators.crc8(&crc_input_bytes);

    let final_sn = if calculated_crc8 == parsed_uo1_ts.crc8 {
        expected_sn
    } else {
        try_sn_recovery(
            context,
            parsed_uo1_ts.crc8,
            CrcType::Crc8Uo1Sn,
            32,
            8,
            None,
            |input| crc_calculators.crc8(input),
            |candidate_sn, _, buf| {
                prepare_generic_uo_crc_input_into_buf(
                    context.rtp_ssrc,
                    candidate_sn,
                    decoded_ts,
                    context.last_reconstructed_rtp_marker,
                    buf,
                )
            },
        )?
    };

    context.infer_ts_stride_from_decompressed_ts(decoded_ts, final_sn);
    context.last_reconstructed_rtp_sn_full = final_sn;
    context.last_reconstructed_rtp_ts_full = decoded_ts;

    Ok(reconstruct_headers_from_context(
        context,
        final_sn,
        decoded_ts,
        context.last_reconstructed_rtp_marker,
        context.last_reconstructed_ip_id_full,
    ))
}

/// Decompresses a UO-1-ID packet, validates CRC, updates context, and reconstructs headers.
///
/// UO-1-ID packets carry an LSB-encoded IP Identification. The RTP Sequence Number
/// is implicitly reconstructed as `last_reconstructed_sn + 1`.
/// The RTP Timestamp is implicitly reconstructed using the context's TS stride (SN delta is 1).
/// The RTP Marker bit is assumed to be unchanged from the context.
///
/// # Parameters
/// - `context`: Mutable decompressor context to update with new state
/// - `packet`: Core UO-1-ID packet data (after Add-CID processing, if any)
/// - `crc_calculators`: CRC calculator instances for verification
///
/// # Returns
/// The reconstructed RTP/UDP/IPv4 headers.
///
/// # Errors
/// - [`RohcError::Parsing`] - Missing mandatory fields or CRC mismatch
pub fn decompress_as_uo1_id(
    context: &mut Profile1DecompressorContext,
    packet: &[u8],
    crc_calculators: &CrcCalculators,
) -> Result<RtpUdpIpv4Headers, RohcError> {
    debug_assert_eq!(packet.len(), 3, "UO-1-ID core packet must be 3 bytes long.");

    let parsed_uo1_id = deserialize_uo1_id(packet)?;

    let ip_id_lsb = parsed_uo1_id.ip_id_lsb.ok_or({
        RohcError::Parsing(RohcParsingError::MandatoryFieldMissing {
            field: Field::IpIdLsb,
            structure: StructureType::Uo1IdPacket,
        })
    })?;
    let ip_id_lsb_bits = parsed_uo1_id.num_ip_id_lsb_bits.ok_or({
        RohcError::Parsing(RohcParsingError::MandatoryFieldMissing {
            field: Field::NumIpIdLsbBits,
            structure: StructureType::Uo1IdPacket,
        })
    })?;

    let _decoded_ip_id = decode_lsb(
        ip_id_lsb as u64,
        context.last_reconstructed_ip_id_full.as_u64(),
        ip_id_lsb_bits,
        context.p_ip_id,
    )? as u16;
    let expected_sn = context.last_reconstructed_rtp_sn_full.wrapping_add(1);
    let expected_ts = calculate_reconstructed_ts_implicit_sn_plus_one(context);
    let crc_input_bytes = prepare_uo1_id_specific_crc_input_payload(
        context.rtp_ssrc,
        expected_sn,
        expected_ts,
        context.last_reconstructed_rtp_marker,
        ip_id_lsb as u8,
    );
    let calculated_crc8 = crc_calculators.crc8(&crc_input_bytes);

    let final_sn = if calculated_crc8 == parsed_uo1_id.crc8 {
        expected_sn
    } else {
        let ts_for_sn_plus_one = calculate_reconstructed_ts_implicit_sn_plus_one(context);
        let ip_id_lsb = parsed_uo1_id.ip_id_lsb.unwrap_or(0) as u8;

        try_sn_recovery(
            context,
            parsed_uo1_id.crc8,
            CrcType::Crc8Uo1Sn,
            32,
            8,
            None,
            |input| crc_calculators.crc8(input),
            |candidate_sn, _, buf| {
                prepare_uo1_id_specific_crc_input_into_buf(
                    context.rtp_ssrc,
                    candidate_sn,
                    ts_for_sn_plus_one,
                    context.last_reconstructed_rtp_marker,
                    ip_id_lsb,
                    buf,
                )
            },
        )?
    };
    let decoded_ts = expected_ts;
    let decoded_ip_id_full = IpId::new(decode_lsb(
        ip_id_lsb as u64,
        context.last_reconstructed_ip_id_full.as_u64(),
        ip_id_lsb_bits,
        context.p_ip_id,
    )? as u16);

    context.infer_ts_stride_from_decompressed_ts(decoded_ts, final_sn);
    context.last_reconstructed_rtp_sn_full = final_sn;
    context.last_reconstructed_rtp_ts_full = decoded_ts;
    context.last_reconstructed_ip_id_full = decoded_ip_id_full;

    Ok(reconstruct_headers_from_context(
        context,
        final_sn,
        decoded_ts,
        context.last_reconstructed_rtp_marker,
        decoded_ip_id_full,
    ))
}

/// Decompresses a UO-1-RTP packet, validates CRC, updates context, and reconstructs headers.
///
/// UO-1-RTP packets carry a TS_SCALED value for the RTP Timestamp and the current Marker bit.
/// The RTP Sequence Number is implicitly reconstructed as `last_reconstructed_sn + 1`.
/// Successful decompression requires an established TS stride and offset in the context.
///
/// # Parameters
/// - `context`: Mutable decompressor context to update with new state
/// - `packet`: Core UO-1-RTP packet data (after Add-CID processing, if any)
/// - `crc_calculators`: CRC calculator instances for verification
///
/// # Returns
/// The reconstructed RTP/UDP/IPv4 headers.
///
/// # Errors
/// - [`RohcError::Parsing`] - Missing mandatory fields or CRC mismatch
/// - [`RohcError::Decompression`] - LSB decoding failed for TS_SCALED
pub fn decompress_as_uo1_rtp(
    context: &mut Profile1DecompressorContext,
    packet: &[u8],
    crc_calculators: &CrcCalculators,
) -> Result<RtpUdpIpv4Headers, RohcError> {
    debug_assert_eq!(
        packet.len(),
        3,
        "UO-1-RTP core packet must be 3 bytes long."
    );

    let parsed_uo1_rtp = deserialize_uo1_rtp(packet)?;

    let ts_scaled_received = parsed_uo1_rtp.ts_scaled.ok_or({
        RohcError::Parsing(RohcParsingError::MandatoryFieldMissing {
            field: Field::TsScaled,
            structure: StructureType::Uo1RtpPacket,
        })
    })?;

    let expected_ts_from_scaled = context
        .reconstruct_ts_from_scaled(ts_scaled_received)
        .ok_or_else(|| {
            RohcError::Decompression(DecompressionError::LsbDecodingFailed {
                cid: context.cid(),
                field: Field::TsScaled,
            })
        })?;

    let expected_sn = context.last_reconstructed_rtp_sn_full.wrapping_add(1);
    let crc_input_bytes = prepare_generic_uo_crc_input_payload(
        context.rtp_ssrc,
        expected_sn,
        expected_ts_from_scaled,
        parsed_uo1_rtp.marker,
    );
    let calculated_crc8 = crc_calculators.crc8(&crc_input_bytes);

    let decoded_sn = if calculated_crc8 == parsed_uo1_rtp.crc8 {
        expected_sn
    } else {
        try_sn_recovery(
            context,
            parsed_uo1_rtp.crc8,
            CrcType::Crc8Uo1Sn,
            32,
            8,
            None,
            |input| crc_calculators.crc8(input),
            |candidate_sn, _, buf| {
                prepare_generic_uo_crc_input_into_buf(
                    context.rtp_ssrc,
                    candidate_sn,
                    expected_ts_from_scaled,
                    parsed_uo1_rtp.marker,
                    buf,
                )
            },
        )?
    };
    let decoded_ts = expected_ts_from_scaled;

    if context.ts_stride.is_some() && !context.ts_scaled_mode {
        context.ts_scaled_mode = true;
    }

    context.infer_ts_stride_from_decompressed_ts(decoded_ts, decoded_sn);
    context.last_reconstructed_rtp_sn_full = decoded_sn;
    context.last_reconstructed_rtp_ts_full = decoded_ts;
    context.last_reconstructed_rtp_marker = parsed_uo1_rtp.marker;

    Ok(reconstruct_headers_from_context(
        context,
        decoded_sn,
        decoded_ts,
        parsed_uo1_rtp.marker,
        context.last_reconstructed_ip_id_full,
    ))
}
