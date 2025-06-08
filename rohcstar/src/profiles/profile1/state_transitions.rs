//! State transition logic for Profile 1 decompressor.

use super::constants::*;
use super::context::Profile1DecompressorMode;
use super::state_types::StateCounters;

/// Events that trigger state transitions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransitionEvent {
    IrReceived,
    UoSuccess { is_dynamic_updating: bool },
    CrcFailure,
    ParseError,
}

/// Processes state transitions based on current mode and event.
///
/// # Returns
/// - `Some(mode)`: New mode if transition occurred
/// - `None`: No transition, mode unchanged
pub fn process_transition(
    current_mode: &mut Profile1DecompressorMode,
    counters: &mut StateCounters,
    event: TransitionEvent,
) -> Option<Profile1DecompressorMode> {
    use Profile1DecompressorMode::*;

    let new_mode = match (&current_mode, event) {
        (NoContext, TransitionEvent::IrReceived) => {
            counters.reset_for_nc();
            Some(FullContext)
        }

        (StaticContext, TransitionEvent::IrReceived) => {
            counters.reset_for_nc();
            Some(FullContext)
        }
        (
            StaticContext,
            TransitionEvent::UoSuccess {
                is_dynamic_updating: true,
            },
        ) => {
            counters.reset_for_fc();
            counters.fc_success_streak = 1;
            Some(FullContext)
        }
        (StaticContext, TransitionEvent::CrcFailure) => {
            counters.sc_n_window = counters.sc_n_window.saturating_add(1);
            counters.sc_k_failures = counters.sc_k_failures.saturating_add(1);

            if counters.sc_k_failures >= P1_DECOMPRESSOR_SC_TO_NC_K2
                || counters.sc_n_window >= P1_DECOMPRESSOR_SC_TO_NC_N2
            {
                if counters.sc_k_failures >= P1_DECOMPRESSOR_SC_TO_NC_K2 {
                    counters.reset_for_nc();
                    Some(NoContext)
                } else {
                    counters.sc_k_failures = 0;
                    counters.sc_n_window = 0;
                    None
                }
            } else {
                None
            }
        }
        (StaticContext, TransitionEvent::ParseError) => {
            counters.sc_n_window = counters.sc_n_window.saturating_add(1);

            if counters.sc_n_window >= P1_DECOMPRESSOR_SC_TO_NC_N2 {
                counters.sc_k_failures = 0;
                counters.sc_n_window = 0;
            }
            None
        }

        (FullContext, TransitionEvent::IrReceived) => {
            counters.reset_for_nc();
            Some(FullContext)
        }
        (FullContext, TransitionEvent::UoSuccess { .. }) => {
            counters.fc_crc_failures = 0;
            counters.fc_success_streak = counters.fc_success_streak.saturating_add(1);

            if counters.fc_success_streak >= P1_DECOMPRESSOR_FC_TO_SO_THRESHOLD_STREAK {
                counters.init_for_so();
                Some(SecondOrder)
            } else {
                None
            }
        }
        (FullContext, TransitionEvent::CrcFailure) => {
            counters.fc_crc_failures = counters.fc_crc_failures.saturating_add(1);
            counters.fc_success_streak = 0;

            if counters.fc_crc_failures >= P1_DECOMPRESSOR_FC_TO_SC_CRC_FAILURE_THRESHOLD {
                counters.fc_crc_failures = 0;
                counters.sc_k_failures = 0;
                counters.sc_n_window = 0;
                Some(StaticContext)
            } else {
                None
            }
        }
        (FullContext, TransitionEvent::ParseError) => {
            counters.fc_success_streak = 0;
            None
        }

        (SecondOrder, TransitionEvent::IrReceived) => {
            counters.reset_for_nc();
            Some(FullContext)
        }
        (SecondOrder, TransitionEvent::UoSuccess { .. }) => {
            counters.so_dynamic_confidence = counters
                .so_dynamic_confidence
                .saturating_add(P1_SO_SUCCESS_CONFIDENCE_BOOST);
            counters.so_consecutive_failures = 0;
            counters.so_packets_in_so = counters.so_packets_in_so.saturating_add(1);
            None
        }
        (SecondOrder, TransitionEvent::CrcFailure | TransitionEvent::ParseError) => {
            counters.so_dynamic_confidence = counters
                .so_dynamic_confidence
                .saturating_sub(P1_SO_FAILURE_CONFIDENCE_PENALTY);
            counters.so_consecutive_failures = counters.so_consecutive_failures.saturating_add(1);

            if counters.so_consecutive_failures >= P1_SO_MAX_CONSECUTIVE_FAILURES
                || counters.so_dynamic_confidence < P1_SO_TO_NC_CONFIDENCE_THRESHOLD
            {
                counters.reset_for_nc();
                Some(NoContext)
            } else {
                None
            }
        }

        _ => None,
    };

    if let Some(new) = new_mode {
        debug_assert!(
            new != *current_mode || matches!(new, FullContext),
            "Invalid self-transition from {:?} to {:?}",
            current_mode,
            new
        );
        *current_mode = new;
    }

    new_mode
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn p1_transition_nc_to_fc_on_ir() {
        let mut mode = Profile1DecompressorMode::NoContext;
        let mut counters = StateCounters::default();

        let new_mode = process_transition(&mut mode, &mut counters, TransitionEvent::IrReceived);

        assert_eq!(new_mode, Some(Profile1DecompressorMode::FullContext));
        assert_eq!(mode, Profile1DecompressorMode::FullContext);
        assert_eq!(counters.fc_success_streak, 0);
        assert_eq!(counters.fc_crc_failures, 0);
    }

    #[test]
    fn p1_transition_fc_to_so_after_threshold() {
        let mut mode = Profile1DecompressorMode::FullContext;
        let mut counters = StateCounters::default();

        // Simulate success streak
        for i in 0..P1_DECOMPRESSOR_FC_TO_SO_THRESHOLD_STREAK {
            let result = process_transition(
                &mut mode,
                &mut counters,
                TransitionEvent::UoSuccess {
                    is_dynamic_updating: true,
                },
            );

            if i < P1_DECOMPRESSOR_FC_TO_SO_THRESHOLD_STREAK - 1 {
                assert_eq!(result, None);
                assert_eq!(mode, Profile1DecompressorMode::FullContext);
                assert_eq!(counters.fc_success_streak, i + 1);
            } else {
                assert_eq!(result, Some(Profile1DecompressorMode::SecondOrder));
                assert_eq!(mode, Profile1DecompressorMode::SecondOrder);
            }
        }

        assert_eq!(
            counters.so_static_confidence,
            P1_SO_INITIAL_STATIC_CONFIDENCE
        );
        assert_eq!(
            counters.so_dynamic_confidence,
            P1_SO_INITIAL_DYNAMIC_CONFIDENCE
        );
    }

    #[test]
    fn p1_transition_fc_to_sc_on_crc_failures() {
        let mut mode = Profile1DecompressorMode::FullContext;
        let mut counters = StateCounters::default();

        for i in 0..P1_DECOMPRESSOR_FC_TO_SC_CRC_FAILURE_THRESHOLD {
            let result = process_transition(&mut mode, &mut counters, TransitionEvent::CrcFailure);

            if i < P1_DECOMPRESSOR_FC_TO_SC_CRC_FAILURE_THRESHOLD - 1 {
                assert_eq!(result, None);
                assert_eq!(mode, Profile1DecompressorMode::FullContext);
                assert_eq!(counters.fc_crc_failures, i + 1);
                assert_eq!(counters.fc_success_streak, 0);
            } else {
                assert_eq!(result, Some(Profile1DecompressorMode::StaticContext));
                assert_eq!(mode, Profile1DecompressorMode::StaticContext);
                assert_eq!(counters.sc_k_failures, 0);
                assert_eq!(counters.sc_n_window, 0);
            }
        }
    }

    #[test]
    fn p1_transition_sc_to_fc_on_dynamic_success() {
        let mut mode = Profile1DecompressorMode::StaticContext;
        let mut counters = StateCounters::default();

        let result = process_transition(
            &mut mode,
            &mut counters,
            TransitionEvent::UoSuccess {
                is_dynamic_updating: true,
            },
        );

        assert_eq!(result, Some(Profile1DecompressorMode::FullContext));
        assert_eq!(mode, Profile1DecompressorMode::FullContext);
        assert_eq!(counters.fc_success_streak, 1);
    }

    #[test]
    fn p1_transition_sc_to_nc_on_k_failures() {
        let mut mode = Profile1DecompressorMode::StaticContext;
        let mut counters = StateCounters::default();

        for i in 0..P1_DECOMPRESSOR_SC_TO_NC_K2 {
            let result = process_transition(&mut mode, &mut counters, TransitionEvent::CrcFailure);

            if i < P1_DECOMPRESSOR_SC_TO_NC_K2 - 1 {
                assert_eq!(result, None);
                assert_eq!(mode, Profile1DecompressorMode::StaticContext);
                assert_eq!(counters.sc_k_failures, i + 1);
            } else {
                assert_eq!(result, Some(Profile1DecompressorMode::NoContext));
                assert_eq!(mode, Profile1DecompressorMode::NoContext);
                assert_eq!(counters.sc_k_failures, 0); // Reset
            }
        }
    }

    #[test]
    fn p1_transition_so_to_nc_on_consecutive_failures() {
        let mut mode = Profile1DecompressorMode::SecondOrder;
        let mut counters = StateCounters {
            so_dynamic_confidence: 100, // High confidence to test consecutive failures only
            ..Default::default()
        };

        for i in 0..P1_SO_MAX_CONSECUTIVE_FAILURES {
            let result = process_transition(&mut mode, &mut counters, TransitionEvent::ParseError);

            if i < P1_SO_MAX_CONSECUTIVE_FAILURES - 1 {
                assert_eq!(result, None);
                assert_eq!(mode, Profile1DecompressorMode::SecondOrder);
                assert_eq!(counters.so_consecutive_failures, i + 1);
            } else {
                assert_eq!(result, Some(Profile1DecompressorMode::NoContext));
                assert_eq!(mode, Profile1DecompressorMode::NoContext);
                assert_eq!(counters.so_consecutive_failures, 0); // Reset
            }
        }
    }

    #[test]
    fn p1_transition_so_to_nc_on_low_confidence() {
        let mut mode = Profile1DecompressorMode::SecondOrder;
        let mut counters = StateCounters {
            so_dynamic_confidence: P1_SO_TO_NC_CONFIDENCE_THRESHOLD,
            ..Default::default()
        };

        let result = process_transition(&mut mode, &mut counters, TransitionEvent::ParseError);

        assert_eq!(result, Some(Profile1DecompressorMode::NoContext));
        assert_eq!(mode, Profile1DecompressorMode::NoContext);
        assert_eq!(counters.fc_success_streak, 0); // All counters reset
    }

    #[test]
    fn p1_transition_so_success_updates_confidence() {
        let mut mode = Profile1DecompressorMode::SecondOrder;
        let mut counters = StateCounters::default();
        counters.init_for_so();
        let initial_confidence = counters.so_dynamic_confidence;

        let result = process_transition(
            &mut mode,
            &mut counters,
            TransitionEvent::UoSuccess {
                is_dynamic_updating: false,
            },
        );

        assert_eq!(result, None); // No transition
        assert_eq!(mode, Profile1DecompressorMode::SecondOrder);
        assert_eq!(
            counters.so_dynamic_confidence,
            initial_confidence + P1_SO_SUCCESS_CONFIDENCE_BOOST
        );
        assert_eq!(counters.so_consecutive_failures, 0);
        assert_eq!(counters.so_packets_in_so, 1);
    }
}
