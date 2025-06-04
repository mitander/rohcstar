//! ROHC (Robust Header Compression) Profile 1 decompressor state machine logic.
//!
//! This module implements the state transitions (NoContext, StaticContext, FullContext, SecondOrder)
//! for the ROHC Profile 1 decompressor, as defined in RFC 3095, Section 5.3.
//! It works in conjunction with `decompressor.rs` which handles packet parsing
//! and header reconstruction.

use super::constants::*;
use super::context::{Profile1DecompressorContext, Profile1DecompressorMode};
use super::decompressor;
use super::discriminator::Profile1PacketType;
use super::protocol_types::RtpUdpIpv4Headers;

use crate::crc::CrcCalculators;
use crate::error::{RohcError, RohcParsingError};
use crate::packet_defs::{GenericUncompressedHeaders, RohcProfile};

/// Processes a received IR packet.
///
/// This function always transitions the decompressor to `FullContext` mode and
/// resets relevant state counters after successful IR packet parsing.
///
/// # Parameters
/// - `context`: Mutable reference to the `Profile1DecompressorContext`.
/// - `packet_bytes`: The ROHC packet data for the IR packet (core packet, after Add-CID if any).
/// - `crc_calculators`: For CRC verification.
/// - `handler_profile_id`: The `RohcProfile` ID of the calling handler, used for profile validation.
///
/// # Returns
/// The reconstructed `GenericUncompressedHeaders` on success.
///
/// # Errors
/// - [`RohcError::Parsing`]: If IR packet parsing, CRC validation, or profile validation fails.
pub(super) fn process_ir_packet(
    context: &mut Profile1DecompressorContext,
    packet_bytes: &[u8],
    crc_calculators: &CrcCalculators,
    handler_profile_id: RohcProfile,
) -> Result<GenericUncompressedHeaders, RohcError> {
    let reconstructed_rtp_headers =
        decompressor::decompress_as_ir(context, packet_bytes, crc_calculators, handler_profile_id)?;

    context.mode = Profile1DecompressorMode::FullContext;
    context.consecutive_crc_failures_in_fc = 0;
    context.fc_packets_successful_streak = 0;
    context.so_static_confidence = 0; // Reset SO confidence if previously in SO
    context.so_dynamic_confidence = 0;
    context.so_packets_received_in_so = 0;
    context.so_consecutive_failures = 0;
    context.sc_to_nc_k_failures = 0; // Reset SC counters
    context.sc_to_nc_n_window_count = 0;

    Ok(GenericUncompressedHeaders::RtpUdpIpv4(
        reconstructed_rtp_headers,
    ))
}

/// Processes a received UO packet when the decompressor is in Full Context (FC) mode.
///
/// Handles state transitions to SO or SC mode based on the outcome of UO packet processing.
///
/// # Parameters
/// - `context`: Mutable reference to the `Profile1DecompressorContext`.
/// - `packet_bytes`: The ROHC packet data (core packet, after Add-CID if any).
/// - `discriminated_type`: The `Profile1PacketType` (unused as `decompress_as_uo` re-discriminates).
/// - `crc_calculators`: For CRC verification.
///
/// # Returns
/// The reconstructed `GenericUncompressedHeaders` on successful UO packet processing.
///
/// # Errors
/// - [`RohcError`]: Propagated from `decompress_as_uo` or state transition logic.
pub(super) fn process_packet_in_fc_mode(
    context: &mut Profile1DecompressorContext,
    packet_bytes: &[u8],
    discriminated_type: Profile1PacketType,
    crc_calculators: &CrcCalculators,
) -> Result<GenericUncompressedHeaders, RohcError> {
    debug_assert_eq!(
        context.mode,
        Profile1DecompressorMode::FullContext,
        "process_packet_in_fc_mode called outside of FullContext mode"
    );
    debug_assert!(
        !discriminated_type.is_ir(),
        "IR packet routed to UO processing in FC mode"
    );

    let outcome = decompressor::decompress_as_uo(context, packet_bytes, crc_calculators);
    handle_fc_uo_packet_outcome(context, outcome).map(GenericUncompressedHeaders::RtpUdpIpv4)
}

/// Processes a received ROHC packet when the decompressor is in Static Context (SC) mode.
///
/// UO-0 packets are invalid in this state as they cannot update dynamic context.
/// Successful processing of UO-1 packets transitions to FC mode. Repeated failures
/// can lead to a transition to NC mode.
///
/// # Parameters
/// - `context`: Mutable reference to the `Profile1DecompressorContext`.
/// - `packet_bytes`: The ROHC packet data (core packet, after Add-CID if any).
/// - `discriminated_type`: The `Profile1PacketType` determined by the caller.
/// - `crc_calculators`: For CRC verification.
///
/// # Returns
/// The reconstructed `GenericUncompressedHeaders` on successful decompression and context update.
///
/// # Errors
/// - [`RohcError::InvalidState`]: If a UO-0 packet is received.
/// - [`RohcError::Parsing`]: If packet type is unknown or decompression fails.
/// - Other `RohcError` variants from underlying operations.
pub(super) fn process_packet_in_sc_mode(
    context: &mut Profile1DecompressorContext,
    packet_bytes: &[u8],
    discriminated_type: Profile1PacketType,
    crc_calculators: &CrcCalculators,
) -> Result<GenericUncompressedHeaders, RohcError> {
    debug_assert_eq!(
        context.mode,
        Profile1DecompressorMode::StaticContext,
        "process_packet_in_sc_mode called outside of StaticContext mode"
    );
    debug_assert!(
        !discriminated_type.is_ir(),
        "IR packet routed to process_packet_in_sc_mode"
    );

    let decompress_result = match discriminated_type {
        Profile1PacketType::Uo0 => {
            return Err(RohcError::InvalidState(
                "UO-0 packet received in StaticContext mode; cannot establish dynamic context."
                    .to_string(),
            ));
        }
        Profile1PacketType::Unknown(val) => {
            return Err(RohcError::Parsing(RohcParsingError::InvalidPacketType {
                discriminator: val,
                profile_id: Some(context.profile_id.into()),
            }));
        }
        Profile1PacketType::IrStatic | Profile1PacketType::IrDynamic => {
            unreachable!("IR packets should be handled by process_ir_packet directly.");
        }
        _ => {
            // All UO-1 variants are suitable for dynamic updates
            decompressor::decompress_as_uo(context, packet_bytes, crc_calculators)
        }
    };

    match decompress_result {
        Ok(headers) => {
            debug_assert!(
                discriminated_type.is_dynamic_updating(),
                "Packet processed in SC mode that was not a dynamic updater (and not UO-0): {:?}",
                discriminated_type
            );

            // Dynamic packet success transitions to FC.
            context.sc_to_nc_k_failures = 0;
            context.sc_to_nc_n_window_count = 0;
            context.mode = Profile1DecompressorMode::FullContext;
            context.fc_packets_successful_streak = 1;
            Ok(GenericUncompressedHeaders::RtpUdpIpv4(headers))
        }
        Err(e) => {
            // Only dynamic updating packets (UO-1 types) count for SC->NC N2 window logic.
            if discriminated_type.is_dynamic_updating() {
                context.sc_to_nc_n_window_count = context.sc_to_nc_n_window_count.saturating_add(1);

                if matches!(e, RohcError::Parsing(RohcParsingError::CrcMismatch { .. })) {
                    context.sc_to_nc_k_failures = context.sc_to_nc_k_failures.saturating_add(1);
                }

                let should_reset_counters =
                    context.sc_to_nc_n_window_count >= P1_DECOMPRESSOR_SC_TO_NC_N2;

                if should_transition_sc_to_nc(context) {
                    context.mode = Profile1DecompressorMode::NoContext;
                    context.reset_for_nc_transition();
                } else if should_reset_counters {
                    context.sc_to_nc_k_failures = 0;
                    context.sc_to_nc_n_window_count = 0;
                }
            }
            Err(e)
        }
    }
}

/// Processes a received ROHC packet when the decompressor is in Second Order (SO) mode.
///
/// Updates confidence levels based on packet processing success or failure.
/// Transitions to NC mode if confidence drops too low or too many consecutive failures occur.
///
/// # Parameters
/// - `context`: Mutable reference to the `Profile1DecompressorContext`.
/// - `packet_bytes`: The ROHC packet data (core packet, after Add-CID if any).
/// - `discriminated_type`: The `Profile1PacketType` (unused as `decompress_as_uo` re-discriminates).
/// - `crc_calculators`: For CRC verification.
///
/// # Returns
/// The reconstructed `GenericUncompressedHeaders` on successful UO packet processing.
///
/// # Errors
/// - [`RohcError`]: Propagated from `decompress_as_uo` or state transition logic.
pub(super) fn process_packet_in_so_mode(
    context: &mut Profile1DecompressorContext,
    packet_bytes: &[u8],
    discriminated_type: Profile1PacketType,
    crc_calculators: &CrcCalculators,
) -> Result<GenericUncompressedHeaders, RohcError> {
    debug_assert_eq!(
        context.mode,
        Profile1DecompressorMode::SecondOrder,
        "process_packet_in_so_mode called outside of SecondOrder mode"
    );
    debug_assert!(
        !discriminated_type.is_ir(),
        "IR packet routed to UO processing in SO mode"
    );

    let parse_reconstruct_result =
        decompressor::decompress_as_uo(context, packet_bytes, crc_calculators);

    match parse_reconstruct_result {
        Ok(headers) => {
            context.so_dynamic_confidence = context
                .so_dynamic_confidence
                .saturating_add(P1_SO_SUCCESS_CONFIDENCE_BOOST);
            context.so_consecutive_failures = 0;
            context.so_packets_received_in_so = context.so_packets_received_in_so.saturating_add(1);
            Ok(GenericUncompressedHeaders::RtpUdpIpv4(headers))
        }
        Err(e) => {
            context.so_dynamic_confidence = context
                .so_dynamic_confidence
                .saturating_sub(P1_SO_FAILURE_CONFIDENCE_PENALTY);
            context.so_consecutive_failures = context.so_consecutive_failures.saturating_add(1);

            if should_transition_so_to_nc(context) {
                context.mode = Profile1DecompressorMode::NoContext;
                context.reset_for_nc_transition();
            }
            Err(e)
        }
    }
}

/// Handles the outcome of UO packet processing in Full Context mode.
fn handle_fc_uo_packet_outcome(
    context: &mut Profile1DecompressorContext,
    parse_outcome: Result<RtpUdpIpv4Headers, RohcError>,
) -> Result<RtpUdpIpv4Headers, RohcError> {
    debug_assert_eq!(
        context.mode,
        Profile1DecompressorMode::FullContext,
        "handle_fc_uo_packet_outcome called outside of FullContext mode"
    );

    match parse_outcome {
        Ok(reconstructed_headers) => {
            context.consecutive_crc_failures_in_fc = 0;
            context.fc_packets_successful_streak =
                context.fc_packets_successful_streak.saturating_add(1);

            if context.fc_packets_successful_streak >= P1_DECOMPRESSOR_FC_TO_SO_THRESHOLD_STREAK {
                context.mode = Profile1DecompressorMode::SecondOrder;
                context.so_static_confidence = P1_SO_INITIAL_STATIC_CONFIDENCE;
                context.so_dynamic_confidence = P1_SO_INITIAL_DYNAMIC_CONFIDENCE;
                context.so_packets_received_in_so = 0;
                context.so_consecutive_failures = 0;
                context.fc_packets_successful_streak = 0; // Reset streak after transition
            }
            Ok(reconstructed_headers)
        }
        Err(e) => {
            // Only CRC mismatches count towards FC->SC transition threshold.
            if matches!(e, RohcError::Parsing(RohcParsingError::CrcMismatch { .. })) {
                context.consecutive_crc_failures_in_fc =
                    context.consecutive_crc_failures_in_fc.saturating_add(1);
            }
            context.fc_packets_successful_streak = 0;

            if context.consecutive_crc_failures_in_fc
                >= P1_DECOMPRESSOR_FC_TO_SC_CRC_FAILURE_THRESHOLD
            {
                context.mode = Profile1DecompressorMode::StaticContext;
                context.sc_to_nc_k_failures = 0;
                context.sc_to_nc_n_window_count = 0;
                context.consecutive_crc_failures_in_fc = 0;
            }
            Err(e)
        }
    }
}

/// Checks if the decompressor should transition from Second Order to NoContext mode.
fn should_transition_so_to_nc(context: &Profile1DecompressorContext) -> bool {
    debug_assert_eq!(
        context.mode,
        Profile1DecompressorMode::SecondOrder,
        "should_transition_so_to_nc called outside of SecondOrder mode"
    );
    if context.so_consecutive_failures >= P1_SO_MAX_CONSECUTIVE_FAILURES {
        return true;
    }
    if context.so_dynamic_confidence < P1_SO_TO_NC_CONFIDENCE_THRESHOLD {
        return true;
    }
    false
}

/// Checks if the decompressor should transition from Static Context to NoContext mode.
fn should_transition_sc_to_nc(context: &Profile1DecompressorContext) -> bool {
    debug_assert_eq!(
        context.mode,
        Profile1DecompressorMode::StaticContext,
        "should_transition_sc_to_nc called outside of StaticContext mode"
    );
    context.sc_to_nc_k_failures >= P1_DECOMPRESSOR_SC_TO_NC_K2
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crc::CrcCalculators;
    use crate::packet_defs::RohcProfile;
    use crate::profiles::profile1::context::{
        Profile1DecompressorContext, Profile1DecompressorMode,
    };
    use crate::profiles::profile1::packet_processor::{
        prepare_generic_uo_crc_input_payload, serialize_ir, serialize_uo0, serialize_uo1_sn,
    };
    use crate::profiles::profile1::packet_types::{IrPacket, Uo0Packet, Uo1Packet};
    use crate::profiles::profile1::protocol_types::{RtpUdpIpv4Headers, Timestamp};

    // Helper for dummy headers in state machine tests where content doesn't matter
    fn create_dummy_rtp_headers() -> RtpUdpIpv4Headers {
        RtpUdpIpv4Headers {
            rtp_ssrc: 1,
            ..Default::default()
        }
    }

    // Helper to create a basic decompressor context in a given mode
    fn setup_context_in_mode(mode: Profile1DecompressorMode) -> Profile1DecompressorContext {
        let mut ctx = Profile1DecompressorContext::new(0);
        ctx.mode = mode;
        ctx.rtp_ssrc = 0x12345678; // Needed for CRC calculations
        ctx.last_reconstructed_rtp_sn_full = 100;
        ctx.last_reconstructed_rtp_ts_full = Timestamp::new(1000);
        ctx
    }

    #[test]
    fn fc_uo_outcome_success_leads_to_so() {
        let mut context = setup_context_in_mode(Profile1DecompressorMode::FullContext);
        let headers = create_dummy_rtp_headers();

        for i in 0..P1_DECOMPRESSOR_FC_TO_SO_THRESHOLD_STREAK {
            let outcome = Ok(headers.clone());
            let _ = handle_fc_uo_packet_outcome(&mut context, outcome);
            if i < P1_DECOMPRESSOR_FC_TO_SO_THRESHOLD_STREAK - 1 {
                assert_eq!(context.mode, Profile1DecompressorMode::FullContext);
                assert_eq!(context.fc_packets_successful_streak, i + 1);
            }
        }
        assert_eq!(context.mode, Profile1DecompressorMode::SecondOrder);
        assert_eq!(
            context.so_static_confidence,
            P1_SO_INITIAL_STATIC_CONFIDENCE
        );
        assert_eq!(context.fc_packets_successful_streak, 0); // Check reset
    }

    #[test]
    fn fc_uo_outcome_crc_failure_leads_to_sc() {
        let mut context = setup_context_in_mode(Profile1DecompressorMode::FullContext);
        let crc_error = Err(RohcError::Parsing(RohcParsingError::CrcMismatch {
            expected: 0,
            calculated: 1,
            crc_type: "test".to_string(),
        }));

        for i in 0..P1_DECOMPRESSOR_FC_TO_SC_CRC_FAILURE_THRESHOLD {
            let _ = handle_fc_uo_packet_outcome(&mut context, crc_error.clone());
            if i < P1_DECOMPRESSOR_FC_TO_SC_CRC_FAILURE_THRESHOLD - 1 {
                assert_eq!(context.mode, Profile1DecompressorMode::FullContext);
                assert_eq!(context.consecutive_crc_failures_in_fc, i + 1);
            }
        }
        assert_eq!(context.mode, Profile1DecompressorMode::StaticContext);
        assert_eq!(context.consecutive_crc_failures_in_fc, 0); // Check reset
    }

    #[test]
    fn fc_uo_outcome_non_crc_failure_no_sc_transition() {
        let mut context = setup_context_in_mode(Profile1DecompressorMode::FullContext);
        let non_crc_error = Err(RohcError::Internal("some other error".to_string()));

        for _i in 0..P1_DECOMPRESSOR_FC_TO_SC_CRC_FAILURE_THRESHOLD {
            let _ = handle_fc_uo_packet_outcome(&mut context, non_crc_error.clone());
            assert_eq!(context.mode, Profile1DecompressorMode::FullContext);
            assert_eq!(context.consecutive_crc_failures_in_fc, 0); // Non-CRC errors don't increment
        }
        assert_eq!(context.mode, Profile1DecompressorMode::FullContext); // Stays FC
    }

    #[test]
    fn sc_to_nc_transition_on_failures() {
        let crc_calculators = CrcCalculators::new();
        let mut context = setup_context_in_mode(Profile1DecompressorMode::StaticContext);

        let uo1_sn_data_bad_crc = Uo1Packet {
            sn_lsb: 1,
            num_sn_lsb_bits: P1_UO1_SN_LSB_WIDTH_DEFAULT,
            marker: false,
            crc8: 0xFF,
            ..Default::default()
        };
        let uo1_sn_bytes_bad = serialize_uo1_sn(&uo1_sn_data_bad_crc).unwrap();

        for _ in 0..P1_DECOMPRESSOR_SC_TO_NC_K2 {
            let _ = process_packet_in_sc_mode(
                &mut context,
                &uo1_sn_bytes_bad,
                Profile1PacketType::Uo1Sn { marker: false },
                &crc_calculators,
            );
        }
        assert_eq!(context.mode, Profile1DecompressorMode::NoContext);
    }

    #[test]
    fn sc_stays_sc_if_failures_not_met_and_window_resets() {
        let crc_calculators = CrcCalculators::new();
        let mut context = setup_context_in_mode(Profile1DecompressorMode::StaticContext);

        let uo1_sn_data_bad_crc = Uo1Packet {
            sn_lsb: 1,
            num_sn_lsb_bits: P1_UO1_SN_LSB_WIDTH_DEFAULT,
            marker: false,
            crc8: 0xFF,
            cid: None,
            ..Default::default()
        };
        let uo1_sn_bytes_bad = serialize_uo1_sn(&uo1_sn_data_bad_crc).unwrap();

        for _ in 0..(P1_DECOMPRESSOR_SC_TO_NC_K2 - 1) {
            let current_marker_for_type = context.last_reconstructed_rtp_marker;
            let _ = process_packet_in_sc_mode(
                &mut context,
                &uo1_sn_bytes_bad,
                Profile1PacketType::Uo1Sn {
                    marker: current_marker_for_type,
                },
                &crc_calculators,
            );
        }
        assert_eq!(context.mode, Profile1DecompressorMode::StaticContext);
        assert_eq!(context.sc_to_nc_k_failures, P1_DECOMPRESSOR_SC_TO_NC_K2 - 1);
        assert_eq!(
            context.sc_to_nc_n_window_count,
            P1_DECOMPRESSOR_SC_TO_NC_K2 - 1
        );

        // Simulate N2-(K2-1) more failed UO-1s to fill N2 window but NOT exceed K2 overall
        let remaining_packets_in_window =
            P1_DECOMPRESSOR_SC_TO_NC_N2 - (P1_DECOMPRESSOR_SC_TO_NC_K2 - 1);
        for _ in 0..remaining_packets_in_window {
            if context.mode != Profile1DecompressorMode::StaticContext {
                break;
            } // e.g. if it went to FC early
            let current_marker_for_type = context.last_reconstructed_rtp_marker;
            // Simulating a different kind of error, not CRC, to not increment k_failures
            let _ = process_packet_in_sc_mode(
                &mut context,
                &[0b10100000, 0x02, 0x03], // UO-1-SN structure, probably bad CRC against context
                Profile1PacketType::Uo1Sn {
                    marker: current_marker_for_type,
                },
                &crc_calculators,
            );
        }
        if context.mode == Profile1DecompressorMode::StaticContext {
            // Only if it hasn't transitioned
            assert_eq!(
                context.sc_to_nc_k_failures, 0,
                "K failures should reset after N2 window without K2 threshold"
            );
            assert_eq!(context.sc_to_nc_n_window_count, 0, "N window should reset");
        }
    }

    #[test]
    fn sc_to_fc_on_dynamic_update_success() {
        let crc_calculators = CrcCalculators::new();
        let mut context = setup_context_in_mode(Profile1DecompressorMode::StaticContext);

        let target_sn = context.last_reconstructed_rtp_sn_full.wrapping_add(1);
        let uo1_sn_data_good = Uo1Packet {
            sn_lsb: crate::encodings::encode_lsb(target_sn as u64, P1_UO1_SN_LSB_WIDTH_DEFAULT)
                .unwrap() as u16,
            num_sn_lsb_bits: P1_UO1_SN_LSB_WIDTH_DEFAULT,
            marker: false,
            ..Default::default()
        };
        let crc_input_good = prepare_generic_uo_crc_input_payload(
            context.rtp_ssrc,
            target_sn,
            context.last_reconstructed_rtp_ts_full,
            false,
        );
        let uo1_sn_data_good_crc = Uo1Packet {
            crc8: crc_calculators.crc8(&crc_input_good),
            ..uo1_sn_data_good
        };
        let uo1_sn_bytes_good = serialize_uo1_sn(&uo1_sn_data_good_crc).unwrap();

        let result = process_packet_in_sc_mode(
            &mut context,
            &uo1_sn_bytes_good,
            Profile1PacketType::Uo1Sn { marker: false },
            &crc_calculators,
        );
        assert!(
            result.is_ok(),
            "SC->FC transition packet failed: {:?}",
            result.err()
        );
        assert_eq!(context.mode, Profile1DecompressorMode::FullContext);
        assert_eq!(context.fc_packets_successful_streak, 1);
    }

    #[test]
    fn so_to_nc_transition_on_consecutive_failures() {
        let crc_calculators = CrcCalculators::new();
        let mut context = setup_context_in_mode(Profile1DecompressorMode::SecondOrder);
        context.so_dynamic_confidence = P1_SO_FAILURE_CONFIDENCE_PENALTY
            * P1_SO_MAX_CONSECUTIVE_FAILURES
            + P1_SO_TO_NC_CONFIDENCE_THRESHOLD;

        let uo0_data_bad_crc = Uo0Packet {
            crc3: 0x07, // Likely bad CRC for most contexts
            sn_lsb: 0x0F,
            cid: None,
        };
        let uo0_bytes_bad = serialize_uo0(&uo0_data_bad_crc).unwrap();

        for i in 0..P1_SO_MAX_CONSECUTIVE_FAILURES {
            if i == P1_SO_MAX_CONSECUTIVE_FAILURES - 1 {
                assert_eq!(
                    context.mode,
                    Profile1DecompressorMode::SecondOrder,
                    "Should be SO before the failure that causes transition"
                );
            }
            let result = process_packet_in_so_mode(
                &mut context,
                &uo0_bytes_bad,
                Profile1PacketType::Uo0,
                &crc_calculators,
            );
            assert!(result.is_err());
        }
        assert_eq!(
            context.mode,
            Profile1DecompressorMode::NoContext,
            "Should be NoContext after max consecutive failures"
        );
        assert_eq!(context.so_consecutive_failures, 0); // Reset by reset_for_nc_transition
    }

    #[test]
    fn so_to_nc_transition_on_low_confidence() {
        let crc_calculators = CrcCalculators::new();
        let mut context = setup_context_in_mode(Profile1DecompressorMode::SecondOrder);
        context.so_dynamic_confidence = P1_SO_TO_NC_CONFIDENCE_THRESHOLD; // Start just at threshold

        let uo0_data_bad_crc = Uo0Packet {
            crc3: 0x07,
            sn_lsb: 0x0F,
            cid: None,
        };
        let uo0_bytes_bad = serialize_uo0(&uo0_data_bad_crc).unwrap();

        let _ = process_packet_in_so_mode(
            &mut context,
            &uo0_bytes_bad,
            Profile1PacketType::Uo0,
            &crc_calculators,
        );
        assert_eq!(context.mode, Profile1DecompressorMode::NoContext);
    }

    #[test]
    fn so_confidence_management() {
        let crc_calculators = CrcCalculators::new();
        let mut context = setup_context_in_mode(Profile1DecompressorMode::SecondOrder);
        context.so_dynamic_confidence = P1_SO_INITIAL_DYNAMIC_CONFIDENCE;

        let next_sn = context.last_reconstructed_rtp_sn_full.wrapping_add(1);
        let sn_lsb_good = crate::encodings::encode_lsb(next_sn as u64, P1_UO0_SN_LSB_WIDTH_DEFAULT)
            .unwrap() as u8;
        let crc_input_good = prepare_generic_uo_crc_input_payload(
            context.rtp_ssrc,
            next_sn,
            context.last_reconstructed_rtp_ts_full,
            context.last_reconstructed_rtp_marker,
        );
        let uo0_data_good_crc = Uo0Packet {
            crc3: crc_calculators.crc3(&crc_input_good),
            sn_lsb: sn_lsb_good,
            ..Default::default()
        };
        let uo0_bytes_good = serialize_uo0(&uo0_data_good_crc).unwrap();

        let _ = process_packet_in_so_mode(
            &mut context,
            &uo0_bytes_good,
            Profile1PacketType::Uo0,
            &crc_calculators,
        );
        assert_eq!(
            context.so_dynamic_confidence,
            P1_SO_INITIAL_DYNAMIC_CONFIDENCE + P1_SO_SUCCESS_CONFIDENCE_BOOST
        );
        assert_eq!(context.so_consecutive_failures, 0);

        let uo0_data_bad_crc = Uo0Packet {
            crc3: 0x07,
            sn_lsb: 0x0F,
            cid: None,
        };
        let uo0_bytes_bad = serialize_uo0(&uo0_data_bad_crc).unwrap();
        let _ = process_packet_in_so_mode(
            &mut context,
            &uo0_bytes_bad,
            Profile1PacketType::Uo0,
            &crc_calculators,
        );
        assert_eq!(
            context.so_dynamic_confidence,
            P1_SO_INITIAL_DYNAMIC_CONFIDENCE + P1_SO_SUCCESS_CONFIDENCE_BOOST
                - P1_SO_FAILURE_CONFIDENCE_PENALTY
        );
        assert_eq!(context.so_consecutive_failures, 1);
    }

    #[test]
    fn process_ir_packet_resets_to_fc_and_counters() {
        let crc_calculators = CrcCalculators::new();
        let mut context = setup_context_in_mode(Profile1DecompressorMode::SecondOrder);
        context.so_consecutive_failures = 2;
        context.consecutive_crc_failures_in_fc = 1; // Should be reset by IR
        context.sc_to_nc_k_failures = 1; // Should be reset

        let ir_content = IrPacket {
            cid: 0,
            profile_id: RohcProfile::RtpUdpIp,
            static_rtp_ssrc: 0x1A2B3C4D,
            dyn_rtp_sn: 150,
            dyn_rtp_timestamp: Timestamp::new(15000),
            ..Default::default()
        };
        let ir_bytes = serialize_ir(&ir_content, &crc_calculators).unwrap();

        let result = process_ir_packet(
            &mut context,
            &ir_bytes,
            &crc_calculators,
            RohcProfile::RtpUdpIp,
        );
        assert!(result.is_ok());

        assert_eq!(context.mode, Profile1DecompressorMode::FullContext);
        assert_eq!(context.consecutive_crc_failures_in_fc, 0);
        assert_eq!(context.fc_packets_successful_streak, 0);
        assert_eq!(context.so_static_confidence, 0);
        assert_eq!(context.so_dynamic_confidence, 0);
        assert_eq!(context.so_packets_received_in_so, 0);
        assert_eq!(context.so_consecutive_failures, 0);
        assert_eq!(context.sc_to_nc_k_failures, 0);
        assert_eq!(context.sc_to_nc_n_window_count, 0);
    }
}
