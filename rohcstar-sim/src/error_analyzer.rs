//! Error classification and analysis tools for ROHC simulation.
//!
//! Helps distinguish real implementation bugs from expected network behavior
//! by analyzing error patterns and simulation context.

use rohcstar::error::{EngineError, RohcError, RohcParsingError};

use crate::{SimConfig, SimError};

/// Classification of simulation errors for better debugging.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ErrorCategory {
    /// Expected behavior due to network conditions  
    NetworkRelated,
    /// Likely implementation bug that needs investigation
    ImplementationBug,
    /// Ambiguous - needs manual review
    RequiresReview,
}

/// Error analysis result with reasoning.
#[derive(Debug)]
pub struct ErrorAnalysis {
    pub category: ErrorCategory,
    pub confidence: f32, // 0.0 to 1.0
    pub reason: &'static str,
    pub should_log: bool,
}

/// Analyzes simulation errors to classify them as network vs implementation issues.
pub struct ErrorAnalyzer;

impl ErrorAnalyzer {
    /// Analyzes a simulation error in context to determine if it's likely a real bug.
    pub fn analyze_error(error: &SimError, config: &SimConfig) -> ErrorAnalysis {
        match error {
            SimError::PacketGenerationExhausted => ErrorAnalysis {
                category: ErrorCategory::ImplementationBug,
                confidence: 1.0,
                reason: "Packet generator should not exhaust unexpectedly",
                should_log: true,
            },

            SimError::CompressionError {
                error: rohc_error, ..
            } => Self::analyze_rohc_error_context(rohc_error, config, "compression"),

            SimError::DecompressionError {
                error: rohc_error, ..
            } => Self::analyze_rohc_error_context(rohc_error, config, "decompression"),

            SimError::VerificationError { message, .. } => {
                Self::analyze_verification_error(message, config)
            }

            SimError::CrcRecoveryLimitExceeded {
                packet_loss_rate,
                distance,
                limit,
                ..
            } => {
                // High packet loss with large recovery distance is expected
                if *packet_loss_rate > 0.1 && *distance > *limit / 2 {
                    ErrorAnalysis {
                        category: ErrorCategory::NetworkRelated,
                        confidence: 0.9,
                        reason: "CRC recovery limit exceeded under high packet loss",
                        should_log: false,
                    }
                } else {
                    ErrorAnalysis {
                        category: ErrorCategory::RequiresReview,
                        confidence: 0.6,
                        reason: "CRC recovery failed under low packet loss - investigate",
                        should_log: true,
                    }
                }
            }
        }
    }

    fn analyze_rohc_error_context(
        rohc_error: &RohcError,
        config: &SimConfig,
        _operation: &'static str,
    ) -> ErrorAnalysis {
        match rohc_error {
            RohcError::Engine(EngineError::PacketLoss { .. }) => {
                if config.channel_packet_loss_probability > 0.0 {
                    ErrorAnalysis {
                        category: ErrorCategory::NetworkRelated,
                        confidence: 1.0,
                        reason: "PacketLoss error with configured packet loss",
                        should_log: false,
                    }
                } else {
                    ErrorAnalysis {
                        category: ErrorCategory::ImplementationBug,
                        confidence: 0.8,
                        reason: "PacketLoss error on perfect channel",
                        should_log: true,
                    }
                }
            }

            RohcError::Parsing(RohcParsingError::CrcMismatch { .. }) => {
                if config.channel_packet_loss_probability > 0.05 {
                    ErrorAnalysis {
                        category: ErrorCategory::NetworkRelated,
                        confidence: 0.8,
                        reason: "CRC mismatch under significant packet loss",
                        should_log: false,
                    }
                } else {
                    ErrorAnalysis {
                        category: ErrorCategory::ImplementationBug,
                        confidence: 0.9,
                        reason: "CRC mismatch on reliable channel",
                        should_log: true,
                    }
                }
            }

            RohcError::Parsing(RohcParsingError::NotEnoughData { .. }) => ErrorAnalysis {
                category: ErrorCategory::ImplementationBug,
                confidence: 0.95,
                reason: "Packet truncation indicates serialization bug",
                should_log: true,
            },

            RohcError::Parsing(RohcParsingError::InvalidPacketType { .. }) => ErrorAnalysis {
                category: ErrorCategory::ImplementationBug,
                confidence: 0.95,
                reason: "Invalid packet type suggests compression bug",
                should_log: true,
            },

            RohcError::Building(_) => ErrorAnalysis {
                category: ErrorCategory::ImplementationBug,
                confidence: 1.0,
                reason: "Building errors are always implementation bugs",
                should_log: true,
            },

            _ => ErrorAnalysis {
                category: ErrorCategory::RequiresReview,
                confidence: 0.5,
                reason: "Unknown error type needs manual classification",
                should_log: true,
            },
        }
    }

    fn analyze_verification_error(message: &str, config: &SimConfig) -> ErrorAnalysis {
        if message.contains("Timestamp mismatch") {
            if config.channel_packet_loss_probability > 0.0 || config.marker_probability > 0.0 {
                ErrorAnalysis {
                    category: ErrorCategory::NetworkRelated,
                    confidence: 0.7,
                    reason: "Timestamp mismatch with packet loss/marker changes",
                    should_log: false,
                }
            } else {
                ErrorAnalysis {
                    category: ErrorCategory::ImplementationBug,
                    confidence: 0.8,
                    reason: "Timestamp mismatch on perfect channel",
                    should_log: true,
                }
            }
        } else if message.contains("SN mismatch") {
            if config.channel_packet_loss_probability > 0.1 {
                ErrorAnalysis {
                    category: ErrorCategory::NetworkRelated,
                    confidence: 0.6,
                    reason: "SN mismatch under high packet loss",
                    should_log: false,
                }
            } else {
                ErrorAnalysis {
                    category: ErrorCategory::ImplementationBug,
                    confidence: 0.9,
                    reason: "SN mismatch on reliable channel",
                    should_log: true,
                }
            }
        } else if message.contains("Marker mismatch") {
            if config.channel_packet_loss_probability > 0.0 && config.marker_probability > 0.0 {
                ErrorAnalysis {
                    category: ErrorCategory::NetworkRelated,
                    confidence: 0.8,
                    reason: "Marker mismatch with packet loss + marker changes",
                    should_log: false,
                }
            } else {
                ErrorAnalysis {
                    category: ErrorCategory::ImplementationBug,
                    confidence: 0.9,
                    reason: "Marker mismatch without expected causes",
                    should_log: true,
                }
            }
        } else if message.contains("SSRC mismatch") {
            ErrorAnalysis {
                category: ErrorCategory::ImplementationBug,
                confidence: 1.0,
                reason: "SSRC should never change in single flow",
                should_log: true,
            }
        } else {
            ErrorAnalysis {
                category: ErrorCategory::RequiresReview,
                confidence: 0.5,
                reason: "Unknown verification error",
                should_log: true,
            }
        }
    }

    /// Provides a summary of error analysis results.
    pub fn summarize_errors(analyses: &[(SimError, ErrorAnalysis)]) -> ErrorSummary {
        let total = analyses.len();
        let network_related = analyses
            .iter()
            .filter(|(_, analysis)| analysis.category == ErrorCategory::NetworkRelated)
            .count();
        let implementation_bugs = analyses
            .iter()
            .filter(|(_, analysis)| analysis.category == ErrorCategory::ImplementationBug)
            .count();
        let requires_review = analyses
            .iter()
            .filter(|(_, analysis)| analysis.category == ErrorCategory::RequiresReview)
            .count();

        let high_confidence_bugs = analyses
            .iter()
            .filter(|(_, analysis)| {
                analysis.category == ErrorCategory::ImplementationBug && analysis.confidence > 0.8
            })
            .count();

        ErrorSummary {
            total_errors: total,
            network_related,
            implementation_bugs,
            requires_review,
            high_confidence_bugs,
        }
    }
}

/// Summary of error analysis results.
#[derive(Debug)]
pub struct ErrorSummary {
    pub total_errors: usize,
    pub network_related: usize,
    pub implementation_bugs: usize,
    pub requires_review: usize,
    pub high_confidence_bugs: usize,
}

impl ErrorSummary {
    pub fn bug_rate(&self) -> f32 {
        if self.total_errors > 0 {
            self.implementation_bugs as f32 / self.total_errors as f32
        } else {
            0.0
        }
    }

    pub fn has_critical_issues(&self) -> bool {
        self.high_confidence_bugs > 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn analyze_network_related_errors() {
        let config = SimConfig {
            channel_packet_loss_probability: 0.2,
            marker_probability: 0.1,
            ..Default::default()
        };

        // Timestamp mismatch with packet loss should be network-related
        let error = SimError::VerificationError {
            sn: 100,
            message: "Timestamp mismatch: expected 1000, got 1160".to_string(),
        };

        let analysis = ErrorAnalyzer::analyze_error(&error, &config);
        assert_eq!(analysis.category, ErrorCategory::NetworkRelated);
        assert!(!analysis.should_log);
    }

    #[test]
    fn analyze_implementation_bugs() {
        let config = SimConfig {
            channel_packet_loss_probability: 0.0, // Perfect channel
            ..Default::default()
        };

        // SSRC mismatch is always a bug
        let error = SimError::VerificationError {
            sn: 100,
            message: "SSRC mismatch: expected 123, got 456".to_string(),
        };

        let analysis = ErrorAnalyzer::analyze_error(&error, &config);
        assert_eq!(analysis.category, ErrorCategory::ImplementationBug);
        assert!(analysis.should_log);
        assert!(analysis.confidence > 0.9);
    }

    #[test]
    fn error_summary_calculation() {
        let analyses = vec![
            (
                SimError::VerificationError {
                    sn: 1,
                    message: "SSRC mismatch".to_string(),
                },
                ErrorAnalysis {
                    category: ErrorCategory::ImplementationBug,
                    confidence: 1.0,
                    reason: "",
                    should_log: true,
                },
            ),
            (
                SimError::VerificationError {
                    sn: 2,
                    message: "Timestamp mismatch".to_string(),
                },
                ErrorAnalysis {
                    category: ErrorCategory::NetworkRelated,
                    confidence: 0.8,
                    reason: "",
                    should_log: false,
                },
            ),
            (
                SimError::VerificationError {
                    sn: 3,
                    message: "Unknown error".to_string(),
                },
                ErrorAnalysis {
                    category: ErrorCategory::RequiresReview,
                    confidence: 0.5,
                    reason: "",
                    should_log: true,
                },
            ),
        ];

        let summary = ErrorAnalyzer::summarize_errors(&analyses);
        assert_eq!(summary.total_errors, 3);
        assert_eq!(summary.implementation_bugs, 1);
        assert_eq!(summary.network_related, 1);
        assert_eq!(summary.requires_review, 1);
        assert_eq!(summary.high_confidence_bugs, 1);
        assert!(summary.has_critical_issues());
    }
}
