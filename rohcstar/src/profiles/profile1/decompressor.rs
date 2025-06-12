//! ROHC Profile 1 decompression for RTP/UDP/IP packets.
//!
//! Implements RFC 3095 profile 0x0001 decompression with robust CRC recovery
//! and conservative false positive prevention.

use super::constants::{P1_MAX_REASONABLE_SN_JUMP, P1_MAX_REASONABLE_UO0_SN_JUMP};
use super::context::Profile1DecompressorContext;
use super::discriminator::Profile1PacketType;
use super::packet_processor::{
    deserialize_ir, deserialize_uo0, deserialize_uo1_id, deserialize_uo1_rtp, deserialize_uo1_sn,
    deserialize_uo1_ts, prepare_generic_uo_crc_input_into_buf,
    prepare_generic_uo_crc_input_payload, prepare_uo1_id_specific_crc_input_into_buf,
    prepare_uo1_id_specific_crc_input_payload,
};
use super::protocol_types::RtpUdpIpv4Headers;

use crate::CrcType::{self, Crc3Uo0, Crc8Uo1Sn};
use crate::Field::{self, IpIdLsb, NumIpIdLsbBits, NumTsLsbBits, TsLsb, TsScaled};
use crate::ParseContext::UoPacketTypeDiscriminator;
use crate::StructureType::{Uo1IdPacket, Uo1RtpPacket, Uo1TsPacket};
use crate::constants::{IP_PROTOCOL_UDP, IPV4_STANDARD_IHL, RTP_VERSION};
use crate::crc::CrcCalculators;
use crate::encodings::decode_lsb;
use crate::error::{DecompressionError, RohcError, RohcParsingError};
use crate::packet_defs::RohcProfile;

use crate::traits::RohcDecompressorContext;
use crate::types::{IpId, SequenceNumber, Timestamp};

/// Decompresses IR packet and reconstructs headers.
/// static chain information (IP addresses, ports, SSRC) and dynamic chain elements
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
pub(super) fn decompress_as_ir(
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
pub(super) fn decompress_as_uo(
    context: &mut Profile1DecompressorContext,
    packet: &[u8],
    crc_calculators: &CrcCalculators,
) -> Result<RtpUdpIpv4Headers, RohcError> {
    if packet.is_empty() {
        return Err(RohcError::Parsing(RohcParsingError::NotEnoughData {
            needed: 1,
            got: 0,
            context: UoPacketTypeDiscriminator,
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

/// Decompresses a UO-0 packet, validates CRC, updates decompressor context, and reconstructs headers.
///
/// UO-0 packets carry an LSB-encoded RTP Sequence Number and a 3-bit CRC.
/// The RTP Timestamp is implicitly reconstructed based on the context's TS stride, if established.
/// The RTP Marker bit is assumed to be unchanged from the context.
fn decompress_as_uo0(
    context: &mut Profile1DecompressorContext,
    packet: &[u8],
    crc_calculators: &CrcCalculators,
) -> Result<RtpUdpIpv4Headers, RohcError> {
    debug_assert_eq!(packet.len(), 1, "UO-0 core packet must be 1 byte long.");

    let cid_for_parse = if context.cid() == 0 {
        None
    } else {
        Some(context.cid())
    };
    let parsed_uo0 = deserialize_uo0(packet, cid_for_parse)?;

    let decoded_sn = crate::encodings::decode_lsb_uo0_sn(
        parsed_uo0.sn_lsb,
        *context.last_reconstructed_rtp_sn_full,
    );
    let forward_jump = decoded_sn.wrapping_sub(*context.last_reconstructed_rtp_sn_full);
    let backward_jump = (*context.last_reconstructed_rtp_sn_full).wrapping_sub(decoded_sn);

    if forward_jump > 50 && backward_jump > 50 {
        context.counters.so_consecutive_failures =
            context.counters.so_consecutive_failures.saturating_add(3);
    }
    debug_assert!(
        forward_jump <= 15 || forward_jump >= (u16::MAX - 15),
        "UO-0 SN decode produced unreasonable jump: {} -> {} (delta={})",
        context.last_reconstructed_rtp_sn_full,
        decoded_sn,
        decoded_sn.wrapping_sub(*context.last_reconstructed_rtp_sn_full)
    );

    let decoded_ts = calculate_reconstructed_ts_implicit(context, decoded_sn.into());

    let crc_input_bytes = prepare_generic_uo_crc_input_payload(
        context.rtp_ssrc,
        decoded_sn.into(),
        decoded_ts,
        context.last_reconstructed_rtp_marker,
    );
    let calculated_crc3 = crc_calculators.crc3(&crc_input_bytes);

    if calculated_crc3 != parsed_uo0.crc3 {
        let (forward_window, backward_window) = if context.counters.so_consecutive_failures > 2 {
            (256u16, 128u16)
        } else {
            (8u16, 4u16)
        };
        context.counters.had_recent_crc_failure = true;

        match try_sn_recovery(
            context,
            parsed_uo0.crc3,
            Crc3Uo0,
            forward_window,
            backward_window,
            None,
            |input| crc_calculators.crc3(input),
            |candidate_sn, candidate_ts, buf| {
                prepare_generic_uo_crc_input_into_buf(
                    context.rtp_ssrc,
                    candidate_sn,
                    candidate_ts,
                    context.last_reconstructed_rtp_marker,
                    buf,
                )
            },
        ) {
            Ok(recovery_sn) => {
                let decoded_ts = calculate_reconstructed_ts_implicit(context, recovery_sn);

                context.infer_ts_stride_from_decompressed_ts(decoded_ts, recovery_sn);
                context.last_reconstructed_rtp_sn_full = recovery_sn;
                context.last_reconstructed_rtp_ts_full = decoded_ts;

                return Ok(reconstruct_headers_from_context(
                    context,
                    recovery_sn,
                    decoded_ts,
                    context.last_reconstructed_rtp_marker,
                    context.last_reconstructed_ip_id_full,
                ));
            }
            Err(_) => {
                return Err(RohcError::Parsing(RohcParsingError::CrcMismatch {
                    expected: parsed_uo0.crc3,
                    calculated: calculated_crc3,
                    crc_type: Crc3Uo0,
                }));
            }
        }
    }

    // Sanity check: Only validate after CRC passes to avoid penalizing hot path
    let expected_sn_range_start = context.last_reconstructed_rtp_sn_full.wrapping_add(1);
    let sn_diff_forward = decoded_sn.wrapping_sub(expected_sn_range_start.value());
    let sn_diff_backward = expected_sn_range_start.value().wrapping_sub(decoded_sn);

    if sn_diff_forward > P1_MAX_REASONABLE_UO0_SN_JUMP
        && sn_diff_backward > P1_MAX_REASONABLE_UO0_SN_JUMP
    {
        context.counters.had_recent_crc_failure = true;

        let recovery_sn = try_sn_recovery(
            context,
            parsed_uo0.crc3,
            Crc3Uo0,
            8,
            4,
            None,
            |input| crc_calculators.crc3(input),
            |candidate_sn, candidate_ts, buf| {
                prepare_generic_uo_crc_input_into_buf(
                    context.rtp_ssrc,
                    candidate_sn,
                    candidate_ts,
                    context.last_reconstructed_rtp_marker,
                    buf,
                )
            },
        )?;

        let decoded_ts = calculate_reconstructed_ts_implicit(context, recovery_sn);

        context.infer_ts_stride_from_decompressed_ts(decoded_ts, recovery_sn);
        context.last_reconstructed_rtp_sn_full = recovery_sn;
        context.last_reconstructed_rtp_ts_full = decoded_ts;

        return Ok(reconstruct_headers_from_context(
            context,
            recovery_sn,
            decoded_ts,
            context.last_reconstructed_rtp_marker,
            context.last_reconstructed_ip_id_full,
        ));
    }

    context.infer_ts_stride_from_decompressed_ts(decoded_ts, SequenceNumber::new(decoded_sn));
    context.last_reconstructed_rtp_sn_full = decoded_sn.into();
    context.last_reconstructed_rtp_ts_full = decoded_ts;

    Ok(reconstruct_headers_from_context(
        context,
        decoded_sn.into(),
        decoded_ts,
        context.last_reconstructed_rtp_marker,
        context.last_reconstructed_ip_id_full,
    ))
}

/// Decompresses a UO-1-SN packet, validates CRC, updates context, and reconstructs headers.
///
/// UO-1-SN packets carry LSB-encoded RTP Sequence Number and the current RTP Marker bit.
/// The RTP Timestamp is implicitly reconstructed using the context's TS stride.
fn decompress_as_uo1_sn(
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
            Crc8Uo1Sn,
            32,
            8,
            Some((parsed_uo1.sn_lsb as u8, parsed_uo1.num_sn_lsb_bits)),
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
                    crc_type: Crc8Uo1Sn,
                }));
            }
        }
    }

    // Sanity check: Only validate after CRC passes to avoid penalizing hot path
    let expected_sn_range_start = context.last_reconstructed_rtp_sn_full.wrapping_add(1);
    let sn_diff_forward = decoded_sn.wrapping_sub(expected_sn_range_start.value());
    let sn_diff_backward = expected_sn_range_start.value().wrapping_sub(decoded_sn);

    if sn_diff_forward > P1_MAX_REASONABLE_SN_JUMP && sn_diff_backward > P1_MAX_REASONABLE_SN_JUMP {
        match try_sn_recovery(
            context,
            parsed_uo1.crc8,
            Crc8Uo1Sn,
            32,
            8,
            Some((parsed_uo1.sn_lsb as u8, parsed_uo1.num_sn_lsb_bits)),
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
            Err(_) => {}
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
fn decompress_as_uo1_ts(
    context: &mut Profile1DecompressorContext,
    packet: &[u8],
    crc_calculators: &CrcCalculators,
) -> Result<RtpUdpIpv4Headers, RohcError> {
    debug_assert_eq!(packet.len(), 4, "UO-1-TS core packet must be 4 bytes long.");

    let parsed_uo1_ts = deserialize_uo1_ts(packet)?;

    let ts_lsb = parsed_uo1_ts.ts_lsb.ok_or({
        RohcError::Parsing(RohcParsingError::MandatoryFieldMissing {
            field: TsLsb,
            structure: Uo1TsPacket,
        })
    })?;
    let ts_lsb_bits = parsed_uo1_ts.num_ts_lsb_bits.ok_or({
        RohcError::Parsing(RohcParsingError::MandatoryFieldMissing {
            field: NumTsLsbBits,
            structure: Uo1TsPacket,
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
            Crc8Uo1Sn,
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
fn decompress_as_uo1_id(
    context: &mut Profile1DecompressorContext,
    packet: &[u8],
    crc_calculators: &CrcCalculators,
) -> Result<RtpUdpIpv4Headers, RohcError> {
    debug_assert_eq!(packet.len(), 3, "UO-1-ID core packet must be 3 bytes long.");

    let parsed_uo1_id = deserialize_uo1_id(packet)?;

    let ip_id_lsb = parsed_uo1_id.ip_id_lsb.ok_or({
        RohcError::Parsing(RohcParsingError::MandatoryFieldMissing {
            field: IpIdLsb,
            structure: Uo1IdPacket,
        })
    })?;
    let ip_id_lsb_bits = parsed_uo1_id.num_ip_id_lsb_bits.ok_or({
        RohcError::Parsing(RohcParsingError::MandatoryFieldMissing {
            field: NumIpIdLsbBits,
            structure: Uo1IdPacket,
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
            Crc8Uo1Sn,
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
fn decompress_as_uo1_rtp(
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
            field: TsScaled,
            structure: Uo1RtpPacket,
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
            Crc8Uo1Sn,
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

/// Attempts sequence number recovery on CRC mismatch.
///
/// Unified recovery function that handles all packet types with configurable
/// search windows and optional LSB validation. Uses minimal generics for
/// performance while maintaining flexibility.
///
/// # Parameters
/// - `forward_window`: Maximum packets to search forward from current SN
/// - `backward_window`: Maximum packets to search backward from current SN
/// - `lsb_constraint`: Optional (lsb_value, num_bits) for LSB validation
/// - `crc_calculator`: Closure for CRC calculation
/// - `crc_input_generator`: Closure to generate CRC input
#[allow(clippy::too_many_arguments)]
fn try_sn_recovery<F, G>(
    context: &Profile1DecompressorContext,
    received_crc: u8,
    crc_type: CrcType,
    forward_window: u16,
    backward_window: u16,
    lsb_constraint: Option<(u8, u8)>,
    crc_calculator: F,
    crc_input_generator: G,
) -> Result<SequenceNumber, RohcError>
where
    F: Fn(&[u8]) -> u8,
    G: Fn(SequenceNumber, Timestamp, &mut [u8]) -> usize,
{
    let expected_next_sn = context.last_reconstructed_rtp_sn_full.wrapping_add(1);

    // Pre-compute LSB mask if needed
    let lsb_mask_and_value = lsb_constraint.map(|(lsb_value, num_bits)| {
        let mask = (1u16 << num_bits) - 1;
        (mask, lsb_value)
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
/// Populates an `RtpUdpIpv4Headers` struct using static fields from the
/// decompressor context and the provided dynamic values (SN, TS, Marker, IP-ID)
/// from the currently processed packet. Fields not directly carried or inferred
/// by ROHC Profile 1 are set to default or common values.
fn reconstruct_headers_from_context(
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
        ip_total_length: 0,     // Typically set by higher layers or network stack
        ip_dont_fragment: true, // Common assumption for ROHC Profile 1
        ip_more_fragments: false,
        ip_fragment_offset: 0,
        ip_ttl: context.ip_ttl,
        ip_protocol: IP_PROTOCOL_UDP,
        ip_checksum: 0,  // Recalculated by network stack
        udp_length: 0,   // Recalculated by higher layers
        udp_checksum: 0, // May be 0 if not used, or recalculated
        rtp_version: RTP_VERSION,
        rtp_padding: context.rtp_padding, // Assumed false unless payload indicates otherwise
        rtp_extension: context.rtp_extension, // Assumed false
        rtp_csrc_count: 0,                // Assumed 0
        rtp_payload_type: context.rtp_payload_type,
        rtp_csrc_list: Vec::new(),
    }
}

/// Calculates the reconstructed RTP Timestamp for packets where TS is implicit.
///
/// If a TS stride is established in the context, the timestamp is calculated based
/// on the last reconstructed timestamp, the sequence number delta, and the stride.
/// If no stride is established, or if the SN delta is not positive, the last
/// reconstructed timestamp is returned (as per RFC 3095 UO-0 behavior when TS is static).
fn calculate_reconstructed_ts_implicit(
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

/// Calculates the reconstructed RTP Timestamp for packets where SN advances by exactly one.
///
/// This is a specialized version of `calculate_reconstructed_ts_implicit`
/// used by packet types (like UO-1-ID, UO-1-RTP) where the SN is always
/// `last_reconstructed_sn + 1`.
fn calculate_reconstructed_ts_implicit_sn_plus_one(
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
    use crate::encodings::encode_lsb;
    use crate::error::DecompressionError;
    use crate::profiles::profile1::context::{
        Profile1DecompressorContext, Profile1DecompressorMode,
    };
    use crate::profiles::profile1::packet_processor::{
        serialize_uo0, serialize_uo1_id, serialize_uo1_sn,
    };
    use crate::profiles::profile1::packet_types::{Uo0Packet, Uo1Packet};
    use crate::profiles::profile1::*;

    fn create_test_context(
        sn: u16,
        ts: u32,
        marker: bool,
        ip_id: u16,
        ssrc: u32,
    ) -> Profile1DecompressorContext {
        let mut context = Profile1DecompressorContext::new(0.into());
        context.rtp_ssrc = ssrc.into();
        context.last_reconstructed_rtp_sn_full = sn.into();
        context.last_reconstructed_rtp_ts_full = ts.into();
        context.last_reconstructed_rtp_marker = marker;
        context.last_reconstructed_ip_id_full = ip_id.into();
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
        let mut context = Profile1DecompressorContext::new(0.into());
        context.rtp_ssrc = ssrc.into();
        context.last_reconstructed_rtp_sn_full = initial_sn.into();
        context.last_reconstructed_rtp_ts_full = initial_ts.into();
        context.last_reconstructed_rtp_marker = false;
        context.last_reconstructed_ip_id_full = 100.into();
        context.ts_stride = Some(ts_stride);
        context.ts_offset = initial_ts.into();
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
        let crc_input = prepare_generic_uo_crc_input_payload(
            ssrc.into(),
            target_sn.into(),
            expected_ts,
            marker,
        );
        let crc3 = crc_calculators.crc3(&crc_input);

        let uo0_packet = Uo0Packet {
            cid: None,
            sn_lsb,
            crc3,
        };
        let mut buf = [0u8; 8];
        let len = serialize_uo0(&uo0_packet, &mut buf).unwrap();
        buf[..len].to_vec()
    }

    #[test]
    fn p1_uo0_implicit_ts_update_single_packet() {
        let crc_calculators = CrcCalculators::new();
        let ssrc = 0x12345678;
        let ts_stride = 160;
        let mut context = create_context_with_stride(100, 1000, ts_stride, ssrc);

        // SN 100 → 101, TS should be 1000 + 160 = 1160
        let target_sn = 101;
        let expected_ts: Timestamp = 1160.into();
        let uo0_bytes = build_uo0_with_crc(target_sn, expected_ts, false, ssrc, &crc_calculators);

        let result = decompress_as_uo0(&mut context, &uo0_bytes, &crc_calculators);
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
        let first_packet = build_uo0_with_crc(51, 2160.into(), false, ssrc, &crc_calculators);
        let first_headers =
            decompress_as_uo0(&mut context, &first_packet, &crc_calculators).unwrap();
        assert_eq!(first_headers.rtp_timestamp, 2160);
        // Packet 2: SN 51 → 52, TS 2160 → 2320
        let second_packet = build_uo0_with_crc(52, 2320.into(), false, ssrc, &crc_calculators);
        let second_headers =
            decompress_as_uo0(&mut context, &second_packet, &crc_calculators).unwrap();
        assert_eq!(second_headers.rtp_timestamp, 2320);

        // Packet 3: SN 52 → 53, TS 2320 → 2480
        let third_packet = build_uo0_with_crc(53, 2480.into(), false, ssrc, &crc_calculators);
        let third_headers =
            decompress_as_uo0(&mut context, &third_packet, &crc_calculators).unwrap();
        assert_eq!(third_headers.rtp_timestamp, 2480);
    }

    #[test]
    fn p1_uo0_no_stride_no_ts_update() {
        let crc_calculators = CrcCalculators::new();
        let ssrc = 0xABCDEF00;
        let mut context = create_test_context(100, 1000, false, 10, ssrc);
        // No stride set in create_test_context by default

        let target_sn = 101;
        let expected_ts: Timestamp = 1000.into();
        let uo0_bytes = build_uo0_with_crc(target_sn, expected_ts, false, ssrc, &crc_calculators);

        let result = decompress_as_uo0(&mut context, &uo0_bytes, &crc_calculators).unwrap();
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
        let expected_ts_val = (u32::MAX - 80).wrapping_add(ts_stride);
        let expected_ts: Timestamp = expected_ts_val.into();
        let uo0_bytes = build_uo0_with_crc(target_sn, expected_ts, false, ssrc, &crc_calculators);

        let result = decompress_as_uo0(&mut context, &uo0_bytes, &crc_calculators).unwrap();
        assert_eq!(result.rtp_timestamp, expected_ts_val);
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
        let expected_ts_val = 3800;
        let expected_ts: Timestamp = expected_ts_val.into();
        let target_marker = true;

        let sn_lsb = encode_lsb(target_sn as u64, P1_UO1_SN_LSB_WIDTH_DEFAULT).unwrap() as u16;
        let crc_input = prepare_generic_uo_crc_input_payload(
            ssrc.into(),
            target_sn.into(),
            expected_ts,
            target_marker,
        );
        let crc8 = crc_calculators.crc8(&crc_input);

        let uo1_packet = Uo1Packet {
            sn_lsb,
            num_sn_lsb_bits: P1_UO1_SN_LSB_WIDTH_DEFAULT,
            marker: target_marker,
            crc8,
            ..Default::default()
        };
        let mut uo1_buf = [0u8; 8];
        let uo1_len = serialize_uo1_sn(&uo1_packet, &mut uo1_buf).unwrap();
        let uo1_bytes = &uo1_buf[..uo1_len];

        let result = decompress_as_uo1_sn(&mut context, uo1_bytes, &crc_calculators);
        assert!(result.is_ok());

        let headers = result.unwrap();
        assert_eq!(headers.rtp_timestamp, expected_ts_val);
    }

    #[test]
    fn p1_uo1_id_implicit_ts_update() {
        let crc_calculators = CrcCalculators::new();
        let ssrc = 0x33333333;
        let ts_stride = 160;
        let mut context = create_context_with_stride(300, 4000, ts_stride, ssrc);
        context.expected_lsb_ip_id_width = P1_UO1_IP_ID_LSB_WIDTH_DEFAULT;

        // SN 300 → 301 (delta=1), TS should be 4000 + 160 = 4160
        let target_sn = 301;
        let expected_ts_val = 4160;
        let expected_ts: Timestamp = expected_ts_val.into();
        let target_ip_id = 35;
        let ip_id_lsb =
            encode_lsb(target_ip_id as u64, P1_UO1_IP_ID_LSB_WIDTH_DEFAULT).unwrap() as u8;

        let crc_input = prepare_uo1_id_specific_crc_input_payload(
            ssrc.into(),
            target_sn.into(),
            expected_ts,
            false,
            ip_id_lsb,
        );
        let crc8 = crc_calculators.crc8(&crc_input);

        let uo1_packet = Uo1Packet {
            ip_id_lsb: Some(ip_id_lsb as u16),
            num_ip_id_lsb_bits: Some(P1_UO1_IP_ID_LSB_WIDTH_DEFAULT),
            crc8,
            ..Default::default()
        };
        let mut uo1_buf = [0u8; 8];
        let uo1_len = serialize_uo1_id(&uo1_packet, &mut uo1_buf).unwrap();
        let uo1_bytes = &uo1_buf[..uo1_len];

        let result = decompress_as_uo1_id(&mut context, uo1_bytes, &crc_calculators);
        assert!(result.is_ok());

        let headers = result.unwrap();
        assert_eq!(headers.rtp_timestamp, expected_ts_val);
    }

    #[test]
    fn p1_mixed_packet_sequence() {
        let crc_calculators = CrcCalculators::new();
        let ssrc = 0x44444444;
        let ts_stride = 160;
        let mut context = create_context_with_stride(400, 5000, ts_stride, ssrc);

        // Packet 1: UO-0, SN 400 → 401, TS 5000 → 5160
        let uo0_packet = build_uo0_with_crc(401, 5160.into(), false, ssrc, &crc_calculators);
        let uo0_headers = decompress_as_uo0(&mut context, &uo0_packet, &crc_calculators).unwrap();
        assert_eq!(uo0_headers.rtp_timestamp, 5160);

        // Packet 2: UO-1-SN, SN 401 → 402, TS 5160 → 5320
        let sn_lsb = encode_lsb(402u64, P1_UO1_SN_LSB_WIDTH_DEFAULT).unwrap() as u16;
        let crc_input =
            prepare_generic_uo_crc_input_payload(ssrc.into(), 402.into(), 5320.into(), true);
        let crc8 = crc_calculators.crc8(&crc_input);

        let uo1_packet = Uo1Packet {
            sn_lsb,
            num_sn_lsb_bits: P1_UO1_SN_LSB_WIDTH_DEFAULT,
            marker: true,
            crc8,
            ..Default::default()
        };
        let mut uo1_buf = [0u8; 8];
        let uo1_len = serialize_uo1_sn(&uo1_packet, &mut uo1_buf).unwrap();
        let uo1_bytes = &uo1_buf[..uo1_len];
        let uo1_headers = decompress_as_uo1_sn(&mut context, uo1_bytes, &crc_calculators).unwrap();
        assert_eq!(uo1_headers.rtp_timestamp, 5320);
    }

    #[test]
    fn p1_large_sn_delta_ts_calculation() {
        let crc_calculators = CrcCalculators::new();
        let ssrc = 0x55555555;
        let ts_stride = 160;
        let mut context = create_context_with_stride(1000, 10000, ts_stride, ssrc);

        // Large SN jump: 1000 → 1010 (delta=10), TS should be 10000 + (10 * 160) = 11600
        let target_sn = 1010;
        let expected_ts_val = 11600;
        let expected_ts: Timestamp = expected_ts_val.into();
        let uo0_bytes = build_uo0_with_crc(target_sn, expected_ts, false, ssrc, &crc_calculators);

        let result = decompress_as_uo0(&mut context, &uo0_bytes, &crc_calculators).unwrap();
        assert_eq!(result.rtp_timestamp, expected_ts_val);
    }

    #[test]
    fn p1_different_stride_values() {
        let crc_calculators = CrcCalculators::new();
        let ssrc = 0x66666666;

        for &stride in &[160, 240, 320, 480, 960] {
            let mut context = create_context_with_stride(100, 1000, stride, ssrc);

            let target_sn = 102; // delta = 2
            let expected_ts_val = 1000 + (2 * stride);
            let expected_ts: Timestamp = expected_ts_val.into();
            let uo0_bytes =
                build_uo0_with_crc(target_sn, expected_ts, false, ssrc, &crc_calculators);

            let result = decompress_as_uo0(&mut context, &uo0_bytes, &crc_calculators).unwrap();
            assert_eq!(result.rtp_timestamp, expected_ts_val);
        }
    }
    #[test]
    fn p1_crc_mismatch_detection() {
        let crc_calculators = CrcCalculators::new();
        let ssrc = 0x77777777;
        let mut context = create_test_context(100, 1000, false, 10, ssrc);
        context.expected_lsb_sn_width = P1_UO0_SN_LSB_WIDTH_DEFAULT;

        let target_sn = 101u16;
        let sn_lsb = encode_lsb(target_sn as u64, context.expected_lsb_sn_width).unwrap() as u8;

        let ts_decompressor_will_use =
            calculate_reconstructed_ts_implicit(&context, target_sn.into());

        let correct_crc_input = prepare_generic_uo_crc_input_payload(
            ssrc.into(),
            target_sn.into(),
            ts_decompressor_will_use,
            context.last_reconstructed_rtp_marker,
        );
        let correct_crc3 = crc_calculators.crc3(&correct_crc_input);

        let wrong_crc3_in_packet = (correct_crc3 + 1) & 0x07;

        let uo0_packet_with_bad_crc = Uo0Packet {
            cid: None,
            sn_lsb,
            crc3: wrong_crc3_in_packet,
        };
        let mut uo0_buf_bad = [0u8; 8];
        let uo0_len_bad = serialize_uo0(&uo0_packet_with_bad_crc, &mut uo0_buf_bad).unwrap();
        let uo0_bytes_bad_crc = &uo0_buf_bad[..uo0_len_bad];

        let result = decompress_as_uo0(&mut context, uo0_bytes_bad_crc, &crc_calculators);

        // CRC3 collision rate ~12.5% - recovery may find false positives
        match &result {
            Ok(recovered_headers) => {
                let recovered_sn = recovered_headers.rtp_sequence_number;
                let distance_from_last = recovered_sn
                    .value()
                    .wrapping_sub(context.last_reconstructed_rtp_sn_full.value());

                assert!(
                    distance_from_last <= 8 || distance_from_last >= (u16::MAX - 8),
                    "Recovered SN {} should be within 8 packets of last SN {}, got distance {}",
                    recovered_sn,
                    context.last_reconstructed_rtp_sn_full,
                    distance_from_last
                );

                // CRC3 recovery found alternative SN
            }
            Err(RohcError::Parsing(RohcParsingError::CrcMismatch {
                expected,
                calculated,
                crc_type,
            })) => {
                assert_eq!(expected, &wrong_crc3_in_packet);
                assert_eq!(calculated, &correct_crc3);
                assert_eq!(crc_type, &Crc3Uo0);
                // CRC3 recovery correctly failed - no valid alternatives found
            }
            _ => {
                panic!(
                    "Expected either successful recovery or CrcMismatch error, got {:?}",
                    result
                );
            }
        }
    }

    #[test]
    fn p1_uo1_ts_explicit_ts_update() {
        let crc_calculators = CrcCalculators::new();
        let ssrc = 0x88888888;
        let mut context = create_test_context(100, 1000, false, 10, ssrc);
        context.expected_lsb_ts_width = P1_UO1_TS_LSB_WIDTH_DEFAULT;

        let new_ts_val = 1500;
        let new_ts: Timestamp = new_ts_val.into();
        let ts_lsb = encode_lsb(new_ts.value() as u64, P1_UO1_TS_LSB_WIDTH_DEFAULT).unwrap() as u16;

        let expected_sn = 101;
        let crc_input =
            prepare_generic_uo_crc_input_payload(ssrc.into(), expected_sn.into(), new_ts, false);
        let crc8 = crc_calculators.crc8(&crc_input);

        let packet = vec![
            P1_UO_1_TS_DISCRIMINATOR,
            (ts_lsb >> 8) as u8,
            ts_lsb as u8,
            crc8,
        ];

        let result = decompress_as_uo1_ts(&mut context, &packet, &crc_calculators);
        assert!(result.is_ok());

        let headers = result.unwrap();
        assert_eq!(headers.rtp_sequence_number, expected_sn);
        assert_eq!(headers.rtp_timestamp, new_ts_val);
    }

    #[test]
    fn p1_uo1_rtp_scaled_mode() {
        let crc_calculators = CrcCalculators::new();
        let ssrc = 0x99999999;
        let ts_stride = 160;
        let mut context = create_context_with_stride(100, 1000, ts_stride, ssrc);
        context.ts_scaled_mode = true;

        let ts_scaled = 2u8;
        let expected_sn = 101;
        let expected_ts_val = 1000 + (2 * ts_stride); // 1320
        let expected_ts: Timestamp = expected_ts_val.into();
        let marker = true;

        let crc_input = prepare_generic_uo_crc_input_payload(
            ssrc.into(),
            expected_sn.into(),
            expected_ts,
            marker,
        );
        let crc8 = crc_calculators.crc8(&crc_input);

        let packet = vec![
            P1_UO_1_RTP_DISCRIMINATOR_BASE
                | (if marker {
                    P1_UO_1_RTP_MARKER_BIT_MASK
                } else {
                    0
                }),
            ts_scaled,
            crc8,
        ];

        let result = decompress_as_uo1_rtp(&mut context, &packet, &crc_calculators);
        assert!(result.is_ok());

        let headers = result.unwrap();
        assert_eq!(headers.rtp_sequence_number, expected_sn);
        assert_eq!(headers.rtp_timestamp, expected_ts_val);
        assert_eq!(headers.rtp_marker, marker);
    }

    #[test]
    fn p1_uo1_rtp_no_stride_fails() {
        let crc_calculators = CrcCalculators::new();
        let ssrc = 0xAAAAAAAA;
        let mut context = create_test_context(100, 1000, false, 10, ssrc);

        let packet = vec![P1_UO_1_RTP_DISCRIMINATOR_BASE, 1, 0xFF];

        let result = decompress_as_uo1_rtp(&mut context, &packet, &crc_calculators);
        assert!(result.is_err());

        if let Err(RohcError::Decompression(DecompressionError::LsbDecodingFailed { cid, field })) =
            result
        {
            assert_eq!(cid, context.cid);
            assert_eq!(field, TsScaled);
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
        let mut context = Profile1DecompressorContext::new(0.into());
        let wrong_profile_id = RohcProfile::UdpIp;

        let mut ir_packet_payload_for_crc = Vec::new();
        ir_packet_payload_for_crc.push(u8::from(wrong_profile_id));
        ir_packet_payload_for_crc.extend_from_slice(&[0u8; P1_STATIC_CHAIN_LENGTH_BYTES]);

        let crc_over_payload = crc_calculators.crc8(&ir_packet_payload_for_crc);

        let mut full_ir_static_packet_bytes = Vec::new();
        full_ir_static_packet_bytes.push(P1_ROHC_IR_PACKET_TYPE_STATIC_ONLY);
        full_ir_static_packet_bytes.extend_from_slice(&ir_packet_payload_for_crc);
        full_ir_static_packet_bytes.push(crc_over_payload);

        let result = decompress_as_ir(
            &mut context,
            &full_ir_static_packet_bytes,
            &crc_calculators,
            RohcProfile::RtpUdpIp,
        );

        assert!(
            result.is_err(),
            "Expected error for profile mismatch, got Ok: {:?}",
            result.ok()
        );
        if let Err(RohcError::Parsing(RohcParsingError::InvalidProfileId(id))) = result {
            assert_eq!(
                id,
                u8::from(wrong_profile_id),
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
        let expected_ts_val = 1000; // UO-0 implies TS unchanged if no stride
        let expected_ts: Timestamp = expected_ts_val.into();
        let uo0_bytes = build_uo0_with_crc(target_sn, expected_ts, false, ssrc, &crc_calculators);

        let _ = decompress_as_uo0(&mut context, &uo0_bytes, &crc_calculators).unwrap();

        assert_eq!(context.last_reconstructed_rtp_sn_full, target_sn);
        assert_eq!(context.last_reconstructed_rtp_ts_full, expected_ts_val);
        assert!(!context.last_reconstructed_rtp_marker);
    }

    #[test]
    fn p1_stride_inference_updates() {
        let mut context = create_test_context(100, 1000, false, 10, 0xCCCCCCCC);
        assert!(context.ts_stride.is_none());

        context.last_reconstructed_rtp_sn_full = 100.into();
        context.last_reconstructed_rtp_ts_full = 1000.into();
        context.infer_ts_stride_from_decompressed_ts(1200.into(), 101.into());
        assert_eq!(context.ts_stride, None); // Stride not immediately established
        assert_eq!(context.potential_ts_stride, Some(200)); // Potential stride detected
        assert_eq!(context.ts_offset, 1000); // Offset updated when potential stride detected
    }

    #[test]
    fn p1_reconstruct_headers_values() {
        let mut context = Profile1DecompressorContext::new(0.into());
        context.rtp_ssrc = 0xDEADBEEF.into();
        context.ip_source = "10.0.0.1".parse().unwrap();
        context.ip_destination = "10.0.0.2".parse().unwrap();
        context.udp_source_port = 5000;
        context.udp_destination_port = 6000;

        let headers = reconstruct_headers_from_context(
            &context,
            12345.into(),
            98765.into(),
            true,
            54321.into(),
        );

        assert_eq!(headers.rtp_ssrc, 0xDEADBEEF);
        assert_eq!(headers.ip_src.to_string(), "10.0.0.1");
        assert_eq!(headers.ip_dst.to_string(), "10.0.0.2");
        assert_eq!(headers.udp_src_port, 5000);
        assert_eq!(headers.udp_dst_port, 6000);

        assert_eq!(headers.rtp_sequence_number, 12345);
        assert_eq!(headers.rtp_timestamp, 98765);
        assert!(headers.rtp_marker);
        assert_eq!(headers.ip_identification, 54321);

        assert_eq!(headers.ip_ttl, 64);
        assert_eq!(headers.ip_protocol, IP_PROTOCOL_UDP);
        assert_eq!(headers.rtp_version, RTP_VERSION);
    }

    #[test]
    fn p1_lsb_decoding_edge_cases() {
        let crc_calculators = CrcCalculators::new();
        let ssrc = 0xEEEEEEEE;
        let mut context = create_test_context(65530, 1000, false, 10, ssrc);
        context.expected_lsb_sn_width = P1_UO0_SN_LSB_WIDTH_DEFAULT;

        let target_sn = 2;
        let uo0_bytes = build_uo0_with_crc(target_sn, 1000.into(), false, ssrc, &crc_calculators);

        let result = decompress_as_uo0(&mut context, &uo0_bytes, &crc_calculators);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().rtp_sequence_number, target_sn);
    }

    #[test]
    fn p1_marker_bit_transitions() {
        let crc_calculators = CrcCalculators::new();
        let ssrc = 0xFFFFFFFF;
        let mut context = create_test_context(100, 1000, false, 10, ssrc);
        context.expected_lsb_sn_width = P1_UO1_SN_LSB_WIDTH_DEFAULT;
        context.ts_stride = Some(160);

        let target_sn = 101;
        let target_marker = true;
        let sn_lsb = encode_lsb(target_sn as u64, P1_UO1_SN_LSB_WIDTH_DEFAULT).unwrap() as u16;
        let expected_ts_for_crc = calculate_reconstructed_ts_implicit(&context, target_sn.into());

        let crc_input = prepare_generic_uo_crc_input_payload(
            ssrc.into(),
            target_sn.into(),
            expected_ts_for_crc,
            target_marker,
        );
        let crc8 = crc_calculators.crc8(&crc_input);

        let uo1_packet = Uo1Packet {
            sn_lsb,
            num_sn_lsb_bits: P1_UO1_SN_LSB_WIDTH_DEFAULT,
            marker: target_marker,
            crc8,
            ..Default::default()
        };
        let mut uo1_buf = [0u8; 8];
        let uo1_len = serialize_uo1_sn(&uo1_packet, &mut uo1_buf).unwrap();
        let uo1_bytes = &uo1_buf[..uo1_len];

        let result = decompress_as_uo1_sn(&mut context, uo1_bytes, &crc_calculators);
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

    #[test]
    fn p1_decompress_as_uo_dispatches_to_uo0() {
        let crc_calculators = CrcCalculators::new();
        let ssrc = 0x12345678;
        let ts_stride = 160;
        let mut context = create_context_with_stride(100, 1000, ts_stride, ssrc);

        let target_sn = 101;
        let expected_ts_val = 1160;
        let expected_ts: Timestamp = expected_ts_val.into();
        let uo0_bytes = build_uo0_with_crc(target_sn, expected_ts, false, ssrc, &crc_calculators);

        let result = decompress_as_uo(&mut context, &uo0_bytes, &crc_calculators);
        assert!(result.is_ok());

        let headers = result.unwrap();
        assert_eq!(headers.rtp_sequence_number, target_sn);
        assert_eq!(headers.rtp_timestamp, expected_ts_val);
    }

    #[test]
    fn p1_decompress_as_uo_dispatches_to_uo1_sn() {
        let crc_calculators = CrcCalculators::new();
        let ssrc = 0x87654321;
        let ts_stride = 160;
        let mut context = create_context_with_stride(200, 3000, ts_stride, ssrc);
        context.expected_lsb_sn_width = P1_UO1_SN_LSB_WIDTH_DEFAULT;

        let target_sn = 205;
        let expected_ts_val = 3800;
        let expected_ts: Timestamp = expected_ts_val.into();
        let target_marker = true;

        let sn_lsb = encode_lsb(target_sn as u64, P1_UO1_SN_LSB_WIDTH_DEFAULT).unwrap() as u16;
        let crc_input = prepare_generic_uo_crc_input_payload(
            ssrc.into(),
            target_sn.into(),
            expected_ts,
            target_marker,
        );
        let crc8 = crc_calculators.crc8(&crc_input);

        let uo1_packet = Uo1Packet {
            sn_lsb,
            num_sn_lsb_bits: P1_UO1_SN_LSB_WIDTH_DEFAULT,
            marker: target_marker,
            crc8,
            ..Default::default()
        };
        let mut uo1_buf = [0u8; 8];
        let uo1_len = serialize_uo1_sn(&uo1_packet, &mut uo1_buf).unwrap();
        let uo1_bytes = &uo1_buf[..uo1_len];

        let result = decompress_as_uo(&mut context, uo1_bytes, &crc_calculators);
        assert!(result.is_ok());

        let headers = result.unwrap();
        assert_eq!(headers.rtp_timestamp, expected_ts_val);
        assert_eq!(headers.rtp_marker, target_marker);
    }

    #[test]
    fn p1_decompress_as_uo_dispatches_to_uo1_ts() {
        let crc_calculators = CrcCalculators::new();
        let ssrc = 0xAABBCCDD;
        let mut context = create_test_context(100, 1000, false, 10, ssrc);
        context.expected_lsb_ts_width = P1_UO1_TS_LSB_WIDTH_DEFAULT;

        let new_ts_val = 1500;
        let new_ts: Timestamp = new_ts_val.into();
        let ts_lsb = encode_lsb(new_ts.value() as u64, P1_UO1_TS_LSB_WIDTH_DEFAULT).unwrap() as u16;

        let expected_sn = 101;
        let crc_input =
            prepare_generic_uo_crc_input_payload(ssrc.into(), expected_sn.into(), new_ts, false);
        let crc8 = crc_calculators.crc8(&crc_input);

        let packet = vec![
            P1_UO_1_TS_DISCRIMINATOR,
            (ts_lsb >> 8) as u8,
            ts_lsb as u8,
            crc8,
        ];

        let result = decompress_as_uo(&mut context, &packet, &crc_calculators);
        assert!(result.is_ok());

        let headers = result.unwrap();
        assert_eq!(headers.rtp_sequence_number, expected_sn);
        assert_eq!(headers.rtp_timestamp, new_ts_val);
    }

    #[test]
    fn p1_decompress_as_uo_dispatches_to_uo1_id() {
        let crc_calculators = CrcCalculators::new();
        let ssrc = 0x11223344;
        let ts_stride = 160;
        let mut context = create_context_with_stride(300, 4000, ts_stride, ssrc);
        context.expected_lsb_ip_id_width = P1_UO1_IP_ID_LSB_WIDTH_DEFAULT;

        let target_ip_id = 300;
        context.last_reconstructed_ip_id_full = 291.into();
        let target_sn = 301;
        let expected_ts_val = 4160;
        let expected_ts: Timestamp = expected_ts_val.into();
        let ip_id_lsb =
            encode_lsb(target_ip_id as u64, P1_UO1_IP_ID_LSB_WIDTH_DEFAULT).unwrap() as u8;

        let crc_input = prepare_uo1_id_specific_crc_input_payload(
            ssrc.into(),
            target_sn.into(),
            expected_ts,
            false,
            ip_id_lsb,
        );
        let crc8 = crc_calculators.crc8(&crc_input);

        let uo1_packet = Uo1Packet {
            ip_id_lsb: Some(ip_id_lsb as u16),
            num_ip_id_lsb_bits: Some(P1_UO1_IP_ID_LSB_WIDTH_DEFAULT),
            crc8,
            ..Default::default()
        };
        let mut uo1_buf = [0u8; 8];
        let uo1_len = serialize_uo1_id(&uo1_packet, &mut uo1_buf).unwrap();
        let uo1_bytes = &uo1_buf[..uo1_len];

        let result = decompress_as_uo(&mut context, uo1_bytes, &crc_calculators);
        assert!(result.is_ok());

        let headers = result.unwrap();
        assert_eq!(headers.rtp_timestamp, expected_ts_val);
        assert_eq!(headers.ip_identification, target_ip_id);
    }

    #[test]
    fn p1_decompress_as_uo_dispatches_to_uo1_rtp() {
        let crc_calculators = CrcCalculators::new();
        let ssrc = 0x55667788;
        let ts_stride = 160;
        let mut context = create_context_with_stride(100, 1000, ts_stride, ssrc);
        context.ts_scaled_mode = true;

        let ts_scaled = 2u8;
        let expected_sn = 101;
        let expected_ts_val = 1000 + (2 * ts_stride);
        let expected_ts: Timestamp = expected_ts_val.into();
        let marker = true;

        let crc_input = prepare_generic_uo_crc_input_payload(
            ssrc.into(),
            expected_sn.into(),
            expected_ts,
            marker,
        );
        let crc8 = crc_calculators.crc8(&crc_input);

        let packet = vec![
            P1_UO_1_RTP_DISCRIMINATOR_BASE
                | (if marker {
                    P1_UO_1_RTP_MARKER_BIT_MASK
                } else {
                    0
                }),
            ts_scaled,
            crc8,
        ];

        let result = decompress_as_uo(&mut context, &packet, &crc_calculators);
        assert!(result.is_ok());

        let headers = result.unwrap();
        assert_eq!(headers.rtp_sequence_number, expected_sn);
        assert_eq!(headers.rtp_timestamp, expected_ts_val);
        assert_eq!(headers.rtp_marker, marker);
    }

    #[test]
    fn p1_decompress_as_uo_rejects_ir_packet() {
        let crc_calculators = CrcCalculators::new();
        let mut context = create_test_context(100, 1000, false, 10, 0x12345678);

        let ir_packet = vec![P1_ROHC_IR_PACKET_TYPE_WITH_DYN, 0x01];

        let result = decompress_as_uo(&mut context, &ir_packet, &crc_calculators);
        assert!(result.is_err());

        if let Err(RohcError::Parsing(RohcParsingError::InvalidPacketType {
            discriminator, ..
        })) = &result
        {
            assert_eq!(discriminator, &P1_ROHC_IR_PACKET_TYPE_WITH_DYN);
        } else {
            panic!(
                "Expected InvalidPacketType error for IR packet, got {:?}",
                result
            );
        }
    }

    #[test]
    fn p1_decompress_as_uo_rejects_unknown_packet() {
        let crc_calculators = CrcCalculators::new();
        let mut context = create_test_context(100, 1000, false, 10, 0x12345678);

        let unknown_packet = vec![0xFF];

        let result = decompress_as_uo(&mut context, &unknown_packet, &crc_calculators);
        assert!(result.is_err());

        if let Err(RohcError::Parsing(RohcParsingError::InvalidPacketType {
            discriminator, ..
        })) = &result
        {
            assert_eq!(discriminator, &0xFF);
        } else {
            panic!(
                "Expected InvalidPacketType error for unknown packet, got {:?}",
                result
            );
        }
    }

    #[test]
    fn p1_decompress_as_uo_rejects_empty_packet() {
        let crc_calculators = CrcCalculators::new();
        let mut context = create_test_context(100, 1000, false, 10, 0x12345678);

        let empty_packet = vec![];

        let result = decompress_as_uo(&mut context, &empty_packet, &crc_calculators);
        assert!(result.is_err());

        if let Err(RohcError::Parsing(RohcParsingError::NotEnoughData {
            needed: 1, got: 0, ..
        })) = &result
        {
            // Expected behavior
        } else {
            panic!(
                "Expected NotEnoughData error for empty packet, got {:?}",
                result
            );
        }
    }

    #[test]
    fn p1_uo1_sn_recovery_rejects_extreme_jumps() {
        let crc_calculators = CrcCalculators::new();
        let ssrc = 0x12345678;
        let mut context = create_test_context(795, 10000, false, 100, ssrc);
        context.expected_lsb_sn_width = P1_UO1_SN_LSB_WIDTH_DEFAULT;

        // Simulate the problematic scenario: expected SN=796, candidate=1071 (distance=275)
        let target_sn = 1071u16;
        let target_marker = true;
        let sn_lsb = encode_lsb(target_sn as u64, P1_UO1_SN_LSB_WIDTH_DEFAULT).unwrap() as u16;

        // Calculate what TS the decompressor will expect for an extreme SN jump
        let expected_ts = calculate_reconstructed_ts_implicit(&context, target_sn.into());

        // Create CRC input that matches - this simulates a CRC collision scenario
        let crc_input = prepare_generic_uo_crc_input_payload(
            ssrc.into(),
            target_sn.into(),
            expected_ts,
            target_marker,
        );
        let crc8 = crc_calculators.crc8(&crc_input);

        let uo1_packet = Uo1Packet {
            sn_lsb,
            num_sn_lsb_bits: P1_UO1_SN_LSB_WIDTH_DEFAULT,
            marker: target_marker,
            crc8,
            ..Default::default()
        };
        let mut uo1_buf = [0u8; 8];
        let uo1_len = serialize_uo1_sn(&uo1_packet, &mut uo1_buf).unwrap();
        let uo1_bytes = &uo1_buf[..uo1_len];

        // Before the fix, this would succeed with the extreme jump
        // After the fix, it should fail because 276-packet jump exceeds reasonable limits
        let result = decompress_as_uo1_sn(&mut context, uo1_bytes, &crc_calculators);

        // Should reject the extreme jump (distance=275 > 64)
        assert!(
            result.is_err(),
            "Decompressor should reject 276-packet jump (SN 795->1071)"
        );

        // Verify the rejection is due to CRC mismatch (no valid recovery found)
        if let Err(RohcError::Parsing(RohcParsingError::CrcMismatch { .. })) = result {
            // Expected: No valid SN candidate found within reasonable distance
        } else {
            panic!(
                "Expected CrcMismatch error for extreme jump rejection, got {:?}",
                result
            );
        }
    }
}
