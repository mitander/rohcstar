//! Smart ROHC fuzzer with error classification and focused bug detection.
//!
//! This module provides an improved fuzzing interface that uses error analysis
//! to distinguish real bugs from expected network behavior, providing cleaner
//! output and better signal-to-noise ratio for bug detection.

use crate::{
    RohcSimulator, SimConfig,
    error_analyzer::{ErrorAnalyzer, ErrorCategory},
};
use rand::prelude::*;
use rand::rngs::StdRng;
use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Configuration for smart fuzzing campaigns.
#[derive(Debug, Clone)]
pub struct SmartFuzzConfig {
    pub iterations: usize,
    pub packets_per_iteration: usize,
    pub max_packet_loss: f64,
    pub workers: usize,
    pub focus_on_bugs: bool, // If true, only report implementation bugs
    pub master_seed: Option<u64>,
}

impl Default for SmartFuzzConfig {
    fn default() -> Self {
        Self {
            iterations: 1000,
            packets_per_iteration: 100,
            max_packet_loss: 0.1,
            workers: 1,
            focus_on_bugs: true,
            master_seed: None,
        }
    }
}

/// Results from a smart fuzzing campaign.
#[derive(Debug, Default)]
pub struct SmartFuzzResults {
    pub total_simulations: usize,
    pub successful_simulations: usize,
    pub total_errors: usize,
    pub network_related_errors: usize,
    pub implementation_bugs: usize,
    pub high_confidence_bugs: usize,
    pub duration: Duration,
    pub simulation_rate: f64, // simulations per second
}

impl SmartFuzzResults {
    pub fn success_rate(&self) -> f64 {
        if self.total_simulations > 0 {
            self.successful_simulations as f64 / self.total_simulations as f64
        } else {
            0.0
        }
    }

    pub fn bug_rate(&self) -> f64 {
        if self.total_errors > 0 {
            self.implementation_bugs as f64 / self.total_errors as f64
        } else {
            0.0
        }
    }

    pub fn has_critical_issues(&self) -> bool {
        self.high_confidence_bugs > 0
    }
}

/// Smart fuzzer that focuses on finding real implementation bugs.
pub struct SmartFuzzer {
    config: SmartFuzzConfig,
}

impl SmartFuzzer {
    pub fn new(config: SmartFuzzConfig) -> Self {
        Self { config }
    }

    /// Runs a smart fuzzing campaign with error classification.
    pub fn run(&self) -> SmartFuzzResults {
        let start_time = Instant::now();
        let mut results = SmartFuzzResults::default();

        let master_seed = self.config.master_seed.unwrap_or_else(rand::random);
        let mut seed_rng = StdRng::seed_from_u64(master_seed);

        println!("Smart ROHC Fuzzer");
        println!("================");
        println!("Iterations: {}", self.config.iterations);
        println!(
            "Packets per iteration: {}",
            self.config.packets_per_iteration
        );
        println!(
            "Max packet loss: {:.1}%",
            self.config.max_packet_loss * 100.0
        );
        println!(
            "Focus mode: {}",
            if self.config.focus_on_bugs {
                "bugs only"
            } else {
                "all errors"
            }
        );
        println!("Master seed: {}\n", master_seed);

        let mut bug_types: HashMap<String, usize> = HashMap::new();

        for iteration in 0..self.config.iterations {
            let iteration_seed: u64 = seed_rng.random();
            let sim_config = self.generate_simulation_config(iteration_seed);

            let mut simulator = RohcSimulator::new(sim_config.clone());
            results.total_simulations += 1;

            match simulator.run() {
                Ok(_) => {
                    results.successful_simulations += 1;
                }
                Err(error) => {
                    results.total_errors += 1;
                    let analysis = ErrorAnalyzer::analyze_error(&error, &sim_config);

                    match analysis.category {
                        ErrorCategory::NetworkRelated => {
                            results.network_related_errors += 1;
                            if !self.config.focus_on_bugs {
                                println!("Network error (iter {}): {}", iteration, analysis.reason);
                            }
                        }
                        ErrorCategory::ImplementationBug => {
                            results.implementation_bugs += 1;
                            if analysis.confidence > 0.8 {
                                results.high_confidence_bugs += 1;
                            }

                            // Track bug types
                            *bug_types.entry(analysis.reason.to_string()).or_insert(0) += 1;

                            println!(
                                "🐛 BUG (iter {}, seed {}, confidence {:.0}%): {}",
                                iteration,
                                iteration_seed,
                                analysis.confidence * 100.0,
                                analysis.reason
                            );

                            if analysis.confidence > 0.9 {
                                println!("   Critical bug details: {:?}", error);
                            }
                        }
                        ErrorCategory::RequiresReview => {
                            println!(
                                "❓ REVIEW (iter {}, seed {}): {}",
                                iteration, iteration_seed, analysis.reason
                            );
                            println!("   Error: {:?}", error);
                        }
                    }
                }
            }

            // Progress update every 100 iterations
            if (iteration + 1) % 100 == 0 {
                let elapsed = start_time.elapsed();
                let rate = results.total_simulations as f64 / elapsed.as_secs_f64();
                println!(
                    "Progress: {}/{} ({:.0} sim/sec)",
                    iteration + 1,
                    self.config.iterations,
                    rate
                );
            }
        }

        results.duration = start_time.elapsed();
        results.simulation_rate = results.total_simulations as f64 / results.duration.as_secs_f64();

        // Summary
        println!("\n📊 Smart Fuzzing Results");
        println!("========================");
        println!(
            "Simulations: {} ({:.0}/sec)",
            results.total_simulations, results.simulation_rate
        );
        println!("Success rate: {:.1}%", results.success_rate() * 100.0);
        println!("Total errors: {}", results.total_errors);
        println!(
            "├─ Network-related: {} ({:.1}%)",
            results.network_related_errors,
            if results.total_errors > 0 {
                100.0 * results.network_related_errors as f64 / results.total_errors as f64
            } else {
                0.0
            }
        );
        println!(
            "├─ Implementation bugs: {} ({:.1}%)",
            results.implementation_bugs,
            if results.total_errors > 0 {
                100.0 * results.implementation_bugs as f64 / results.total_errors as f64
            } else {
                0.0
            }
        );
        println!("└─ High-confidence bugs: {}", results.high_confidence_bugs);

        if !bug_types.is_empty() {
            println!("\n🔍 Bug Type Breakdown:");
            let mut sorted_bugs: Vec<_> = bug_types.iter().collect();
            sorted_bugs.sort_by_key(|(_, count)| std::cmp::Reverse(**count));
            for (bug_type, count) in sorted_bugs {
                println!("  {} × {}", count, bug_type);
            }
        }

        if results.has_critical_issues() {
            println!(
                "\n⚠️  CRITICAL: {} high-confidence bugs found!",
                results.high_confidence_bugs
            );
            println!("These should be investigated immediately.");
        } else if results.implementation_bugs > 0 {
            println!(
                "\n⚡ {} potential bugs found (lower confidence)",
                results.implementation_bugs
            );
            println!("Review recommended but not critical.");
        } else {
            println!("\n✅ No implementation bugs detected!");
            println!("ROHC implementation appears robust under tested conditions.");
        }

        results
    }

    fn generate_simulation_config(&self, seed: u64) -> SimConfig {
        let mut rng = StdRng::seed_from_u64(seed);

        SimConfig {
            seed: rng.random(),
            num_packets: self.config.packets_per_iteration,
            start_sn: rng.random_range(0..u16::MAX / 4),
            start_ts_val: rng.random_range(0..u32::MAX / 4),
            ts_stride: if rng.random_bool(0.8) {
                160
            } else {
                rng.random_range(1..1000)
            },
            ssrc: rng.random(),
            cid: if rng.random_bool(0.5) {
                0
            } else {
                rng.random_range(1..=15)
            },
            marker_probability: if rng.random_bool(0.7) {
                0.0
            } else {
                rng.random_range(0.01..=0.5)
            },
            channel_packet_loss_probability: if rng.random_bool(0.7) {
                0.0
            } else {
                rng.random_range(0.0..=self.config.max_packet_loss)
            },
            stable_phase_count: rng.random_range(1..=10),
            uo0_phase_count: rng.random_range(1..=10),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn smart_fuzzer_basic_run() {
        let config = SmartFuzzConfig {
            iterations: 10,
            packets_per_iteration: 20,
            ..Default::default()
        };

        let fuzzer = SmartFuzzer::new(config);
        let results = fuzzer.run();

        assert_eq!(results.total_simulations, 10);
        assert!(results.simulation_rate > 0.0);
        // Should complete without panics
    }
}
