//! UO (Unidirectional Optimistic) packet compression logic.
//!
//! This module handles the compression logic for UO packets, including packet type
//! selection and building according to RFC 3095. It supports UO-0, UO-1-SN, UO-1-TS,
//! UO-1-ID, and UO-1-RTP packet variants.

use crate::crc::CrcCalculators;
use crate::encodings::encode_lsb;
use crate::error::{CompressionError, Field, RohcError};
use crate::types::{IpId, SequenceNumber, Timestamp};

use super::super::constants::*;
use super::super::context::{Profile1CompressorContext, Profile1CompressorMode};
use super::super::packet_types::{Uo0Packet, Uo1Packet};
use super::super::serialization::uo0_packets::serialize_uo0;
use super::super::serialization::uo1_packets::{
    prepare_generic_uo_crc_input_payload, prepare_uo1_id_specific_crc_input_payload,
};
use super::super::serialization::uo1_packets::{
    serialize_uo1_id, serialize_uo1_rtp, serialize_uo1_sn, serialize_uo1_ts,
};
use super::compute_implicit_ts;
use crate::protocol_types::RtpUdpIpv4Headers;
use crate::traits::RohcCompressorContext;

/// Compresses headers as a UO (Unidirectional Optimistic) packet into provided buffer.
///
/// Analyzes header changes and selects the optimal UO packet type (UO-0, UO-1-SN, UO-1-TS,
/// UO-1-ID, or UO-1-RTP) based on RFC 3095 compression rules. Updates compressor context
/// state including timestamp stride detection and scaled mode transitions.
///
/// # Parameters
/// - `context`: Mutable compressor context containing state and configuration.
/// - `headers`: Uncompressed headers of the current packet to compress.
/// - `crc_calculators`: CRC calculator instances for packet integrity checks.
/// - `out`: Output buffer to write the compressed packet into.
///
/// # Returns
/// The number of bytes written to the output buffer.
///
/// # Errors
/// - [`RohcError::Building`] - No suitable UO packet type available or construction failed
/// - [`RohcError::Internal`] - Internal logic error
pub fn compress_as_uo(
    context: &mut Profile1CompressorContext,
    headers: &RtpUdpIpv4Headers,
    crc_calculators: &CrcCalculators,
    out: &mut [u8],
) -> Result<usize, RohcError> {
    debug_assert_eq!(
        context.rtp_ssrc, headers.rtp_ssrc,
        "SSRC mismatch in compress_as_uo; context should align with packet SSRC."
    );

    let current_sn = headers.rtp_sequence_number;
    let current_ts = headers.rtp_timestamp;
    let current_marker = headers.rtp_marker;
    let current_ip_id = headers.ip_identification;

    let sn_delta = current_sn.wrapping_sub(context.last_sent_rtp_sn_full);
    let marker_changed = current_marker != context.last_sent_rtp_marker;
    let ts_changed = current_ts != context.last_sent_rtp_ts_full;
    let ip_id_changed = current_ip_id != context.last_sent_ip_id_full;

    // Run stride detection early to ensure stride is established before packet type selection
    if ts_changed && sn_delta == 1 {
        context.detect_ts_stride(current_ts, current_sn);
    }

    let implicit_ts = compute_implicit_ts(context, sn_delta);

    let (len, actual_ts_for_context_update) = select_and_build_uo_packet(
        context,
        current_sn,
        current_ts,
        current_marker,
        current_ip_id,
        sn_delta,
        marker_changed,
        ts_changed,
        ip_id_changed,
        implicit_ts,
        crc_calculators,
        out,
    )?;

    context.last_sent_rtp_sn_full = current_sn;
    context.last_sent_rtp_ts_full = actual_ts_for_context_update;
    context.last_sent_rtp_marker = current_marker;
    context.last_sent_ip_id_full = current_ip_id;

    advance_compressor_mode(context);
    context.fo_packets_sent_since_ir = context.fo_packets_sent_since_ir.saturating_add(1);

    Ok(len)
}

#[allow(clippy::too_many_arguments)]
fn select_and_build_uo_packet(
    context: &mut Profile1CompressorContext,
    current_sn: SequenceNumber,
    current_ts: Timestamp,
    current_marker: bool,
    current_ip_id: IpId,
    sn_delta: u16,
    marker_changed: bool,
    ts_changed: bool,
    ip_id_changed: bool,
    implicit_ts: Option<Timestamp>,
    crc_calculators: &CrcCalculators,
    out: &mut [u8],
) -> Result<(usize, Timestamp), RohcError> {
    if let Some(ts_scaled_val) = can_use_uo1_rtp(context, sn_delta, ip_id_changed, current_ts) {
        let len = build_uo1_rtp_packet(
            context,
            current_sn,
            ts_scaled_val,
            current_marker,
            crc_calculators,
            out,
        )?;
        return Ok((len, current_ts));
    } else if context.ts_scaled_mode {
        if context.ts_stride.is_none() {
            context.ts_scaled_mode = false;
        } else {
            let implicit_ts_for_fallback = implicit_ts
                .expect("Stride exists with positive sn_delta, implicit_ts should be Some.");
            let len =
                build_uo1_sn_packet(context, current_sn, current_marker, crc_calculators, out)?;
            return Ok((len, implicit_ts_for_fallback));
        }
    }

    if can_use_uo0(marker_changed, sn_delta, ip_id_changed, ts_changed) {
        let len = build_uo0_packet(context, current_sn, current_ts, crc_calculators, out)?;
        return Ok((len, current_ts));
    }

    if !marker_changed && ts_changed && sn_delta == 1 && !ip_id_changed {
        let len = build_uo1_ts_packet(context, current_sn, current_ts, crc_calculators, out)?;
        return Ok((len, current_ts));
    }

    let ts_for_uo1_id_check = implicit_ts.unwrap_or(context.last_sent_rtp_ts_full);

    if can_use_uo1_id(
        marker_changed,
        ip_id_changed,
        sn_delta,
        current_ts,
        ts_for_uo1_id_check,
    ) {
        let len = build_uo1_id_packet(context, current_sn, current_ip_id, crc_calculators, out)?;
        return Ok((len, ts_for_uo1_id_check));
    }

    if can_use_uo1_sn(context) {
        let implicit_ts_for_sn_fallback = match implicit_ts {
            Some(ts) => ts,
            None => {
                let current_sn_delta_for_fallback =
                    current_sn.wrapping_sub(context.last_sent_rtp_sn_full);
                let stride = context
                    .ts_stride
                    .or(context.potential_ts_stride)
                    .unwrap_or(0);
                context
                    .last_sent_rtp_ts_full
                    .value()
                    .wrapping_add(current_sn_delta_for_fallback as u32 * stride)
                    .into()
            }
        };
        let len = build_uo1_sn_packet(context, current_sn, current_marker, crc_calculators, out)?;
        return Ok((len, implicit_ts_for_sn_fallback));
    }

    Err(RohcError::Compression(
        CompressionError::ContextInsufficient {
            cid: context.cid(),
            field: Field::TsScaled,
        },
    ))
}

fn can_use_uo1_rtp(
    context: &Profile1CompressorContext,
    sn_delta: u16,
    ip_id_changed: bool,
    current_ts: Timestamp,
) -> Option<u8> {
    if context.ts_scaled_mode && sn_delta == 1 && !ip_id_changed {
        context.calculate_ts_scaled(current_ts)
    } else {
        None
    }
}

fn can_use_uo0(marker_changed: bool, sn_delta: u16, ip_id_changed: bool, ts_changed: bool) -> bool {
    !marker_changed && sn_delta > 0 && sn_delta < 16 && !ip_id_changed && !ts_changed
}

fn can_use_uo1_id(
    marker_changed: bool,
    ip_id_changed: bool,
    sn_delta: u16,
    current_ts: Timestamp,
    expected_ts: Timestamp,
) -> bool {
    !marker_changed && ip_id_changed && sn_delta == 1 && current_ts == expected_ts
}

fn can_use_uo1_sn(context: &Profile1CompressorContext) -> bool {
    // UO-1-SN can be used with established or potential stride
    // This enables early usage during stride detection phase
    context.ts_stride.is_some() || context.potential_ts_stride.is_some()
}

fn advance_compressor_mode(context: &mut Profile1CompressorContext) {
    if context.mode == Profile1CompressorMode::FirstOrder {
        context.consecutive_fo_packets_sent = context.consecutive_fo_packets_sent.saturating_add(1);
        if context.consecutive_fo_packets_sent >= P1_COMPRESSOR_FO_TO_SO_THRESHOLD {
            context.mode = Profile1CompressorMode::SecondOrder;
            context.consecutive_fo_packets_sent = 0;
        }
    }
}

fn build_uo0_packet(
    context: &Profile1CompressorContext,
    current_sn: SequenceNumber,
    ts_for_crc: Timestamp, // This is the TS value used in CRC calculation.
    crc_calculators: &CrcCalculators,
    out: &mut [u8],
) -> Result<usize, RohcError> {
    let sn_lsb = encode_lsb(current_sn.as_u64(), P1_UO0_SN_LSB_WIDTH_DEFAULT)? as u8;
    let crc_input_bytes = prepare_generic_uo_crc_input_payload(
        context.rtp_ssrc,
        current_sn,
        ts_for_crc,
        context.last_sent_rtp_marker,
    );
    let crc3 = crc_calculators.crc3(&crc_input_bytes);

    let uo0_data = Uo0Packet {
        cid: context.get_small_cid_for_packet(),
        sn_lsb,
        crc3,
    };
    serialize_uo0(&uo0_data, out).map_err(RohcError::Building)
}

// UO-1 Packet Builders
// Note: The following build helpers have different signatures to reflect
// the specific fields carried by each UO-1 packet variant:
// - UO-1-SN: Explicitly carries the marker bit
// - UO-1-TS: Carries the full timestamp; infers marker from context
// - UO-1-ID: Carries the IP-ID LSBs; infers marker from context
// - UO-1-RTP: Explicitly carries the marker bit along with TS_SCALED

fn build_uo1_ts_packet(
    context: &mut Profile1CompressorContext,
    current_sn: SequenceNumber,
    current_ts: Timestamp,
    crc_calculators: &CrcCalculators,
    out: &mut [u8],
) -> Result<usize, RohcError> {
    let ts_lsb = encode_lsb(current_ts.as_u64(), P1_UO1_TS_LSB_WIDTH_DEFAULT)? as u16;
    let crc_input_bytes = prepare_generic_uo_crc_input_payload(
        context.rtp_ssrc,
        current_sn, // UO-1-TS implies SN+1, so current_sn should be context.last_sn + 1.
        current_ts,
        context.last_sent_rtp_marker, // UO-1-TS implies marker is unchanged from context.
    );
    let crc8 = crc_calculators.crc8(&crc_input_bytes);

    let uo1_packet_data = Uo1Packet {
        cid: context.get_small_cid_for_packet(),
        marker: false, // UO-1-TS specific: M bit in type is 0. Actual marker is from context.
        ts_lsb: Some(ts_lsb),
        num_ts_lsb_bits: Some(P1_UO1_TS_LSB_WIDTH_DEFAULT),
        crc8,
        ..Default::default()
    };
    serialize_uo1_ts(&uo1_packet_data, out).map_err(RohcError::Building)
}

fn build_uo1_sn_packet(
    context: &Profile1CompressorContext,
    current_sn: SequenceNumber,
    current_marker: bool,
    crc_calculators: &CrcCalculators,
    out: &mut [u8],
) -> Result<usize, RohcError> {
    debug_assert!(
        context.ts_stride.is_some() || context.potential_ts_stride.is_some(),
        "State violation: UO-1-SN requires stride"
    );

    let sn_lsb_val = encode_lsb(current_sn.as_u64(), P1_UO1_SN_LSB_WIDTH_DEFAULT)? as u16;

    let sn_delta_for_ts = current_sn.wrapping_sub(context.last_sent_rtp_sn_full);
    let stride_val = context.ts_stride.or(context.potential_ts_stride);
    let implicit_ts_for_crc = if let Some(stride) = stride_val {
        context
            .last_sent_rtp_ts_full
            .value()
            .wrapping_add(sn_delta_for_ts as u32 * stride)
            .into()
    } else {
        // Should not happen due to debug_assert, but fallback.
        context.last_sent_rtp_ts_full
    };

    let crc_input_bytes = prepare_generic_uo_crc_input_payload(
        context.rtp_ssrc,
        current_sn,
        implicit_ts_for_crc,
        current_marker, // UO-1-SN carries the current marker.
    );
    let calculated_crc8 = crc_calculators.crc8(&crc_input_bytes);

    let uo1_sn_data = Uo1Packet {
        cid: context.get_small_cid_for_packet(),
        sn_lsb: sn_lsb_val,
        num_sn_lsb_bits: P1_UO1_SN_LSB_WIDTH_DEFAULT,
        marker: current_marker, // This is the marker bit set in the UO-1-SN type octet.
        crc8: calculated_crc8,
        ..Default::default()
    };
    serialize_uo1_sn(&uo1_sn_data, out).map_err(RohcError::Building)
}

// Builds a UO-1-ID packet when IP identification changes but SN increments by 1.
fn build_uo1_id_packet(
    context: &Profile1CompressorContext,
    current_sn: SequenceNumber,
    current_ip_id: IpId,
    crc_calculators: &CrcCalculators,
    out: &mut [u8],
) -> Result<usize, RohcError> {
    let ip_id_lsb_for_packet =
        encode_lsb(current_ip_id.as_u64(), P1_UO1_IP_ID_LSB_WIDTH_DEFAULT)? as u8;

    // UO-1-ID implies SN+1 and unchanged TS (or TS follows stride for implicit update if stride known).
    // For CRC, it specifically uses the *last sent TS* from context if no stride,
    // or implicit TS if stride is present.
    // This function's caller (`select_and_build_uo_packet`) already filters for `!ts_changed`
    // or ensures `implicit_ts_if_stride_set` is compatible before choosing UO-1-ID.
    // For CRC, we need the effective TS based on these rules.
    let ts_for_crc = if let Some(stride_val) = context.ts_stride {
        // SN delta is implicitly 1 for UO-1-ID
        context
            .last_sent_rtp_ts_full
            .value()
            .wrapping_add(stride_val)
            .into()
    } else {
        context.last_sent_rtp_ts_full // If no stride, TS must be unchanged from context.
    };

    let crc_input_bytes = prepare_uo1_id_specific_crc_input_payload(
        context.rtp_ssrc,
        current_sn, // UO-1-ID implies SN+1, so current_sn is context.last_sn + 1.
        ts_for_crc,
        context.last_sent_rtp_marker, // UO-1-ID implies marker is unchanged from context.
        ip_id_lsb_for_packet,
    );
    let calculated_crc8 = crc_calculators.crc8(&crc_input_bytes);

    let uo1_id_packet_data = Uo1Packet {
        cid: context.get_small_cid_for_packet(),
        ip_id_lsb: Some(ip_id_lsb_for_packet as u16),
        num_ip_id_lsb_bits: Some(P1_UO1_IP_ID_LSB_WIDTH_DEFAULT),
        crc8: calculated_crc8,
        ..Default::default() // Marker is false in type byte, other LSBs None
    };
    serialize_uo1_id(&uo1_id_packet_data, out).map_err(RohcError::Building)
}

// Builds a UO-1-RTP packet using TS_SCALED mode when TS follows the established stride.
fn build_uo1_rtp_packet(
    context: &Profile1CompressorContext,
    current_sn: SequenceNumber,
    ts_scaled_val: u8, // The calculated TS_SCALED value.
    current_marker: bool,
    crc_calculators: &CrcCalculators,
    out: &mut [u8],
) -> Result<usize, RohcError> {
    let stride = context.ts_stride.ok_or_else(|| {
        RohcError::Compression(CompressionError::ContextInsufficient {
            cid: context.cid(),
            field: Field::TsScaled,
        })
    })?;
    debug_assert!(stride > 0, "Invalid stride: {} must be positive", stride);

    // Reconstruct the full TS value from TS_Offset and TS_SCALED for CRC calculation.
    // current_sn for CRC is the SN of the packet (context.last_sn + 1).
    let full_ts_for_crc = context
        .ts_offset
        .wrapping_add(ts_scaled_val as u32 * stride);

    let crc_input_bytes = prepare_generic_uo_crc_input_payload(
        context.rtp_ssrc,
        current_sn, // UO-1-RTP implies SN+1.
        full_ts_for_crc,
        current_marker, // UO-1-RTP carries the current marker bit.
    );
    let calculated_crc8 = crc_calculators.crc8(&crc_input_bytes);

    let uo1_rtp_data = Uo1Packet {
        cid: context.get_small_cid_for_packet(),
        marker: current_marker, // This is the marker bit set in the UO-1-RTP type octet.
        ts_scaled: Some(ts_scaled_val),
        crc8: calculated_crc8,
        ..Default::default() // Other LSB fields are not used by UO-1-RTP.
    };
    serialize_uo1_rtp(&uo1_rtp_data, out).map_err(RohcError::Building)
}
