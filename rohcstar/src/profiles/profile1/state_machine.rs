//! ROHC (Robust Header Compression) Profile 1 decompressor state machine logic.
//!
//! This module implements the state transitions (NoContext, StaticContext, FullContext, SecondOrder)
//! for the ROHC Profile 1 decompressor, as defined in RFC 3095, Section 5.3.
//! It works in conjunction with `decompression_logic.rs` which handles packet parsing
//! and header reconstruction.

use super::constants::*;
use super::context::{Profile1DecompressorContext, Profile1DecompressorMode};
use super::decompression_logic;
use super::discriminator::Profile1PacketType;
use super::protocol_types::RtpUdpIpv4Headers;

use crate::crc::CrcCalculators;
use crate::error::{RohcError, RohcParsingError};
use crate::packet_defs::{GenericUncompressedHeaders, RohcProfile};

// Handles UO packet outcome in FC mode, transitioning to SO on success or SC on failures.
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
            // Only count CRC mismatches for FC->SC transition based on consecutive failures.
            // Other parsing errors might not indicate context desync.
            if matches!(&e, RohcError::Parsing(RohcParsingError::CrcMismatch { .. })) {
                context.consecutive_crc_failures_in_fc =
                    context.consecutive_crc_failures_in_fc.saturating_add(1);
            }
            context.fc_packets_successful_streak = 0; // Reset streak on any failure

            if context.consecutive_crc_failures_in_fc
                >= P1_DECOMPRESSOR_FC_TO_SC_CRC_FAILURE_THRESHOLD
            {
                context.mode = Profile1DecompressorMode::StaticContext;
                context.sc_to_nc_k_failures = 0;
                context.sc_to_nc_n_window_count = 0;
            }
            Err(e)
        }
    }
}

// Checks if SO mode should transition to NC due to consecutive failures or low confidence.
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

// Checks if SC mode should transition to NC due to repeated failures.
fn should_transition_sc_to_nc(context: &Profile1DecompressorContext) -> bool {
    debug_assert_eq!(
        context.mode,
        Profile1DecompressorMode::StaticContext,
        "should_transition_sc_to_nc called outside of StaticContext mode"
    );
    context.sc_to_nc_k_failures >= P1_DECOMPRESSOR_SC_TO_NC_K2
}

/// Processes a received IR packet.
///
/// This function always transitions the decompressor to `FullContext` mode and
/// resets relevant state counters.
///
/// # Parameters
/// - `context`: Mutable reference to the `Profile1DecompressorContext`.
/// - `packet_bytes`: The ROHC packet data for the IR packet.
/// - `crc_calculators`: For CRC verification.
/// - `handler_profile_id`: The `RohcProfile` ID of the calling handler.
///
/// # Returns
/// Result of header reconstruction.
pub(super) fn process_ir_packet(
    context: &mut Profile1DecompressorContext,
    packet_bytes: &[u8],
    crc_calculators: &CrcCalculators,
    handler_profile_id: RohcProfile,
) -> Result<GenericUncompressedHeaders, RohcError> {
    match decompression_logic::parse_and_reconstruct_ir(
        context,
        packet_bytes,
        crc_calculators,
        handler_profile_id,
    ) {
        Ok(reconstructed_rtp_headers) => {
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
        Err(e) => {
            // If IR parsing itself fails (e.g. CRC, bad profile ID), context mode might not change,
            // or could even go to NC if it was previously unstable.
            // For now, if IR parsing fails, the context state (mode) remains as it was before this call.
            // The caller (handler) might decide to nuke the context or signal severe error.
            Err(e)
        }
    }
}

/// Processes a received UO packet when the decompressor is in Full Context (FC) mode.
///
/// # Parameters
/// - `context`: Mutable reference to the `Profile1DecompressorContext`.
/// - `packet_bytes`: The ROHC packet data.
/// - `discriminated_type`: The already determined `Profile1PacketType`.
/// - `crc_calculators`: For CRC verification.
///
/// # Returns
/// Result of header reconstruction, after state transitions are applied.
pub(super) fn process_uo_packet_in_fc_mode(
    context: &mut Profile1DecompressorContext,
    packet_bytes: &[u8],
    discriminated_type: Profile1PacketType,
    crc_calculators: &CrcCalculators,
) -> Result<GenericUncompressedHeaders, RohcError> {
    debug_assert_eq!(
        context.mode,
        Profile1DecompressorMode::FullContext,
        "process_uo_packet_in_fc_mode called outside of FullContext mode"
    );
    debug_assert!(
        !discriminated_type.is_ir(),
        "IR packet routed to process_uo_packet_in_fc_mode"
    );

    let outcome: Result<RtpUdpIpv4Headers, RohcError> = match discriminated_type {
        Profile1PacketType::Uo0 => {
            decompression_logic::parse_and_reconstruct_uo0(context, packet_bytes, crc_calculators)
        }
        Profile1PacketType::Uo1Sn { .. } => decompression_logic::parse_and_reconstruct_uo1_sn(
            context,
            packet_bytes,
            crc_calculators,
        ),
        Profile1PacketType::Uo1Ts => decompression_logic::parse_and_reconstruct_uo1_ts(
            context,
            packet_bytes,
            crc_calculators,
        ),
        Profile1PacketType::Uo1Id => decompression_logic::parse_and_reconstruct_uo1_id(
            context,
            packet_bytes,
            crc_calculators,
        ),
        Profile1PacketType::Uo1Rtp { .. } => decompression_logic::parse_and_reconstruct_uo1_rtp(
            context,
            packet_bytes,
            crc_calculators,
        ),
        Profile1PacketType::Unknown(val) => {
            return Err(RohcError::Parsing(RohcParsingError::InvalidPacketType {
                discriminator: val,
                profile_id: Some(context.profile_id.into()),
            }));
        }
        Profile1PacketType::IrStatic | Profile1PacketType::IrDynamic => unreachable!(),
    };

    handle_fc_uo_packet_outcome(context, outcome).map(GenericUncompressedHeaders::RtpUdpIpv4)
}

/// Processes a received ROHC packet when the decompressor is in Static Context (SC) mode.
///
/// If a UO-1 packet successfully updates dynamic fields, transitions to FC mode.
/// If UO-0 is received, it's an error as it cannot update dynamic state.
/// If parsing fails repeatedly, transitions to NC mode.
///
/// # Parameters
/// - `context`, `packet_bytes`, `discriminated_type`, `crc_calculators`: As per other process functions.
///
/// # Returns
/// Result of header reconstruction.
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

    let parse_reconstruct_result: Result<RtpUdpIpv4Headers, RohcError> = match discriminated_type {
        Profile1PacketType::Uo1Ts => decompression_logic::parse_and_reconstruct_uo1_ts(
            context,
            packet_bytes,
            crc_calculators,
        ),
        Profile1PacketType::Uo1Id => decompression_logic::parse_and_reconstruct_uo1_id(
            context,
            packet_bytes,
            crc_calculators,
        ),
        Profile1PacketType::Uo1Sn { .. } => decompression_logic::parse_and_reconstruct_uo1_sn(
            context,
            packet_bytes,
            crc_calculators,
        ),
        Profile1PacketType::Uo1Rtp { .. } => decompression_logic::parse_and_reconstruct_uo1_rtp(
            context,
            packet_bytes,
            crc_calculators,
        ),
        Profile1PacketType::Uo0 => {
            // UO-0 is not a dynamic updater. Receiving it in SC is an invalid sequence.
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
        Profile1PacketType::IrStatic | Profile1PacketType::IrDynamic => unreachable!(),
    };

    match parse_reconstruct_result {
        Ok(headers) => {
            context.sc_to_nc_k_failures = 0;
            context.sc_to_nc_n_window_count = 0;
            // If a dynamically updating packet was successfully processed, transition to FC.
            // All UO-1 types handled above are dynamic updaters.
            debug_assert!(discriminated_type.is_dynamically_updating_type());
            context.mode = Profile1DecompressorMode::FullContext;
            context.fc_packets_successful_streak = 1; // Start FC streak
            Ok(GenericUncompressedHeaders::RtpUdpIpv4(headers))
        }
        Err(ref e) => {
            // Only consider dynamically updating packets for the SC->NC N2 window.
            if discriminated_type.is_dynamically_updating_type() {
                context.sc_to_nc_n_window_count = context.sc_to_nc_n_window_count.saturating_add(1);

                if matches!(e, RohcError::Parsing(RohcParsingError::CrcMismatch { .. })) {
                    context.sc_to_nc_k_failures = context.sc_to_nc_k_failures.saturating_add(1);
                }

                if should_transition_sc_to_nc(context) {
                    context.mode = Profile1DecompressorMode::NoContext;
                    context.reset_for_nc_transition();
                } else if context.sc_to_nc_n_window_count >= P1_DECOMPRESSOR_SC_TO_NC_N2 {
                    context.sc_to_nc_k_failures = 0;
                    context.sc_to_nc_n_window_count = 0;
                }
            }
            Err(e.clone())
        }
    }
}

/// Processes a received ROHC packet when the decompressor is in Second Order (SO) mode.
///
/// Updates confidence levels based on success/failure.
/// Transitions to NC mode if confidence drops too low or too many consecutive failures occur.
///
/// # Parameters
/// - `context`, `packet_bytes`, `discriminated_type`, `crc_calculators`: As per other process functions.
///
/// # Returns
/// Result of header reconstruction.
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
        "IR packet routed to process_packet_in_so_mode"
    );

    let parse_reconstruct_result: Result<RtpUdpIpv4Headers, RohcError> = match discriminated_type {
        Profile1PacketType::Uo0 => {
            decompression_logic::parse_and_reconstruct_uo0(context, packet_bytes, crc_calculators)
        }
        Profile1PacketType::Uo1Sn { .. } => decompression_logic::parse_and_reconstruct_uo1_sn(
            context,
            packet_bytes,
            crc_calculators,
        ),
        Profile1PacketType::Uo1Ts => decompression_logic::parse_and_reconstruct_uo1_ts(
            context,
            packet_bytes,
            crc_calculators,
        ),
        Profile1PacketType::Uo1Id => decompression_logic::parse_and_reconstruct_uo1_id(
            context,
            packet_bytes,
            crc_calculators,
        ),
        Profile1PacketType::Uo1Rtp { .. } => decompression_logic::parse_and_reconstruct_uo1_rtp(
            context,
            packet_bytes,
            crc_calculators,
        ),
        Profile1PacketType::Unknown(val) => {
            return Err(RohcError::Parsing(RohcParsingError::InvalidPacketType {
                discriminator: val,
                profile_id: Some(context.profile_id.into()),
            }));
        }
        Profile1PacketType::IrStatic | Profile1PacketType::IrDynamic => unreachable!(),
    };

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crc::CrcCalculators;
    use crate::encodings::encode_lsb;
    use crate::packet_defs::RohcProfile;
    use crate::profiles::profile1::context::{
        Profile1DecompressorContext, Profile1DecompressorMode,
    };
    use crate::profiles::profile1::packet_processor::{
        build_profile1_ir_packet, build_profile1_uo0_packet, build_profile1_uo1_sn_packet,
        prepare_generic_uo_crc_input_payload,
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
    }

    #[test]
    fn fc_uo_outcome_non_crc_failure_no_sc_transition() {
        let mut context = setup_context_in_mode(Profile1DecompressorMode::FullContext);
        let non_crc_error = Err(RohcError::Internal("some other error".to_string()));

        for _i in 0..P1_DECOMPRESSOR_FC_TO_SC_CRC_FAILURE_THRESHOLD {
            let _ = handle_fc_uo_packet_outcome(&mut context, non_crc_error.clone());
            assert_eq!(context.mode, Profile1DecompressorMode::FullContext);
            assert_eq!(context.consecutive_crc_failures_in_fc, 0); // Non-CRC errors don't increment this counter
        }
        assert_eq!(context.mode, Profile1DecompressorMode::FullContext); // Stays FC
    }

    #[test]
    fn sc_to_nc_transition_on_failures() {
        let crc_calculators = CrcCalculators::new();
        let mut context = setup_context_in_mode(Profile1DecompressorMode::StaticContext);

        // Simulate UO-1-SN packet that will cause CRC error
        // Need to make sure the UO-1-SN itself is well-formed except for its content / CRC against context.
        // The parsing of the packet structure should succeed.
        let uo1_sn_data_bad_crc = Uo1Packet {
            sn_lsb: 1,
            num_sn_lsb_bits: P1_UO1_SN_LSB_WIDTH_DEFAULT,
            marker: false,
            crc8: 0xFF, // Likely wrong CRC against actual context values
            ..Default::default()
        };
        let uo1_sn_bytes_bad = build_profile1_uo1_sn_packet(&uo1_sn_data_bad_crc).unwrap();

        for _ in 0..P1_DECOMPRESSOR_SC_TO_NC_K2 {
            let _ = process_packet_in_sc_mode(
                &mut context,
                &uo1_sn_bytes_bad,
                Profile1PacketType::Uo1Sn { marker: false }, // type that is dynamic updater
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
            /* ... as before ... */
            sn_lsb: 1,
            num_sn_lsb_bits: P1_UO1_SN_LSB_WIDTH_DEFAULT,
            marker: false,
            crc8: 0xFF,
            cid: None,
            ..Default::default()
        };
        let uo1_sn_bytes_bad = build_profile1_uo1_sn_packet(&uo1_sn_data_bad_crc).unwrap();

        // Cause K2-1 CRC failures
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
        let k_failures_before_good_packets = context.sc_to_nc_k_failures;
        let n_window_before_good_packets = context.sc_to_nc_n_window_count;

        assert_eq!(
            k_failures_before_good_packets,
            P1_DECOMPRESSOR_SC_TO_NC_K2 - 1
        );
        assert_eq!(
            n_window_before_good_packets,
            P1_DECOMPRESSOR_SC_TO_NC_K2 - 1
        );

        // Fill rest of N2 window with successful dynamic updaters
        // This loop will likely only run once or a few times before transition to FC.
        let packets_to_test_window_reset =
            P1_DECOMPRESSOR_SC_TO_NC_N2.saturating_sub(n_window_before_good_packets);

        for _iteration in 0..packets_to_test_window_reset {
            if context.mode != Profile1DecompressorMode::StaticContext {
                break; // Mode changed, usually to FC, stop processing in SC logic
            }
            let next_sn_good = context.last_reconstructed_rtp_sn_full.wrapping_add(1);
            let current_marker_for_type = context.last_reconstructed_rtp_marker;
            let uo1_sn_data_good = Uo1Packet {
                sn_lsb: encode_lsb(next_sn_good as u64, P1_UO1_SN_LSB_WIDTH_DEFAULT).unwrap()
                    as u16,
                num_sn_lsb_bits: P1_UO1_SN_LSB_WIDTH_DEFAULT,
                marker: current_marker_for_type,
                cid: None,
                ..Default::default()
            };
            let crc_input_good = prepare_generic_uo_crc_input_payload(
                context.rtp_ssrc,
                next_sn_good,
                context.last_reconstructed_rtp_ts_full,
                current_marker_for_type,
            );
            let uo1_sn_data_good_crc = Uo1Packet {
                crc8: crc_calculators.calculate_rohc_crc8(&crc_input_good),
                ..uo1_sn_data_good
            };
            let uo1_sn_bytes_good = build_profile1_uo1_sn_packet(&uo1_sn_data_good_crc).unwrap();

            let result = process_packet_in_sc_mode(
                &mut context,
                &uo1_sn_bytes_good,
                Profile1PacketType::Uo1Sn {
                    marker: current_marker_for_type,
                },
                &crc_calculators,
            );
            // First successful dynamic update in SC should transition to FC
            assert!(
                result.is_ok(),
                "Processing good UO-1-SN in SC failed: {:?}",
                result.err()
            );
            assert_eq!(
                context.mode,
                Profile1DecompressorMode::FullContext,
                "Should transition to FC on first good UO-1-SN in SC"
            );
        }

        // If the loop completed (meaning it transitioned to FC), the SC counters are reset then.
        assert_ne!(
            context.mode,
            Profile1DecompressorMode::NoContext,
            "Should not have transitioned to NC"
        );
        assert_eq!(
            context.sc_to_nc_k_failures, 0,
            "SC k_failures should be reset after moving to FC or completing N2 window without NC"
        );
        assert_eq!(
            context.sc_to_nc_n_window_count, 0,
            "SC n_window_count should be reset"
        );
    }

    #[test]
    fn sc_to_fc_on_dynamic_update_success() {
        let crc_calculators = CrcCalculators::new();
        let mut context = setup_context_in_mode(Profile1DecompressorMode::StaticContext);

        // Create a valid UO-1-SN packet that will parse correctly
        let target_sn = context.last_reconstructed_rtp_sn_full.wrapping_add(1);
        let uo1_sn_data_good = Uo1Packet {
            sn_lsb: crate::encodings::encode_lsb(target_sn as u64, P1_UO1_SN_LSB_WIDTH_DEFAULT)
                .unwrap() as u16,
            num_sn_lsb_bits: P1_UO1_SN_LSB_WIDTH_DEFAULT,
            marker: false,
            ..Default::default()
        };
        let crc_input = prepare_generic_uo_crc_input_payload(
            // Use function from module
            context.rtp_ssrc,
            target_sn,
            context.last_reconstructed_rtp_ts_full,
            false,
        );
        let uo1_sn_data_good_crc = Uo1Packet {
            crc8: crc_calculators.calculate_rohc_crc8(&crc_input),
            ..uo1_sn_data_good
        };
        let uo1_sn_bytes_good = build_profile1_uo1_sn_packet(&uo1_sn_data_good_crc).unwrap();

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
    }

    #[test]
    fn so_to_nc_transition_on_consecutive_failures() {
        let crc_calculators = CrcCalculators::new();
        let mut context = setup_context_in_mode(Profile1DecompressorMode::SecondOrder);
        // Ensure confidence is high enough so only consecutive failures trigger transition
        context.so_dynamic_confidence = P1_SO_FAILURE_CONFIDENCE_PENALTY
            * P1_SO_MAX_CONSECUTIVE_FAILURES
            + P1_SO_TO_NC_CONFIDENCE_THRESHOLD;

        let uo0_data_bad_crc = Uo0Packet {
            crc3: 0x07,
            sn_lsb: 0x0F,
            cid: None,
        };
        let uo0_bytes_bad = build_profile1_uo0_packet(&uo0_data_bad_crc).unwrap();

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
        // After transitioning to NoContext, so_consecutive_failures is reset by reset_for_nc_transition()
        assert_eq!(
            context.so_consecutive_failures, 0,
            "so_consecutive_failures should be reset after NC transition"
        );
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
        let uo0_bytes_bad = build_profile1_uo0_packet(&uo0_data_bad_crc).unwrap();

        // One failure should push it below
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

        // Good UO-0 packet
        let next_sn = context.last_reconstructed_rtp_sn_full.wrapping_add(1);
        let sn_lsb_good = crate::encodings::encode_lsb(next_sn as u64, P1_UO0_SN_LSB_WIDTH_DEFAULT)
            .unwrap() as u8;
        let crc_input = prepare_generic_uo_crc_input_payload(
            // Use function from module
            context.rtp_ssrc,
            next_sn,
            context.last_reconstructed_rtp_ts_full,
            context.last_reconstructed_rtp_marker,
        );
        let uo0_data_good_crc = Uo0Packet {
            crc3: crc_calculators.calculate_rohc_crc3(&crc_input),
            sn_lsb: sn_lsb_good,
            ..Default::default()
        };
        let uo0_bytes_good = build_profile1_uo0_packet(&uo0_data_good_crc).unwrap();

        // Success
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

        // Failure
        let uo0_data_bad_crc = Uo0Packet {
            crc3: 0x07,
            sn_lsb: 0x0F,
            cid: None,
        }; // Likely invalid combination
        let uo0_bytes_bad = build_profile1_uo0_packet(&uo0_data_bad_crc).unwrap();
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
    fn process_ir_packet_resets_to_fc() {
        let crc_calculators = CrcCalculators::new();
        let mut context = setup_context_in_mode(Profile1DecompressorMode::SecondOrder); // Start in SO
        context.so_consecutive_failures = 2;
        context.consecutive_crc_failures_in_fc = 1;

        let ir_content = IrPacket {
            cid: 0,
            profile_id: RohcProfile::RtpUdpIp,
            static_rtp_ssrc: 0x1A2B3C4D,
            ..Default::default()
        };
        let ir_bytes = build_profile1_ir_packet(&ir_content, &crc_calculators).unwrap();

        let _ = process_ir_packet(
            &mut context,
            &ir_bytes,
            &crc_calculators,
            RohcProfile::RtpUdpIp,
        );

        assert_eq!(context.mode, Profile1DecompressorMode::FullContext);
        assert_eq!(context.consecutive_crc_failures_in_fc, 0);
        assert_eq!(context.so_consecutive_failures, 0); // SO counters reset
    }
}
