//! Demonstrates error analysis capabilities to distinguish real bugs from network effects.

use rohcstar_sim::error_analyzer::{ErrorAnalyzer, ErrorCategory};
use rohcstar_sim::{RohcSimulator, SimConfig};

fn main() {
    println!("ROHC Simulator Error Analysis Demo");
    println!("==================================\n");

    // Test 1: Perfect channel - all errors should be implementation bugs
    println!("Test 1: Perfect Channel (no packet loss)");
    let perfect_config = SimConfig {
        seed: 42,
        num_packets: 100,
        channel_packet_loss_probability: 0.0,
        marker_probability: 0.0,
        ..Default::default()
    };

    let mut sim = RohcSimulator::new(perfect_config.clone());
    match sim.run() {
        Ok(_) => println!("✓ Perfect channel completed successfully"),
        Err(error) => {
            let analysis = ErrorAnalyzer::analyze_error(&error, &perfect_config);
            println!("✗ Error on perfect channel: {:?}", analysis.category);
            println!("  Reason: {}", analysis.reason);
            println!("  Confidence: {:.1}%", analysis.confidence * 100.0);
            if analysis.should_log {
                println!("  → This should be investigated as a potential bug");
            }
        }
    }

    println!();

    // Test 2: High packet loss - many errors should be network-related
    println!("Test 2: Lossy Channel (20% packet loss)");
    let lossy_config = SimConfig {
        seed: 123,
        num_packets: 50,
        channel_packet_loss_probability: 0.2,
        marker_probability: 0.1,
        ..Default::default()
    };

    let mut errors_analyzed = Vec::new();

    // Run multiple simulations to collect error patterns
    for seed in 100..110 {
        let mut config = lossy_config.clone();
        config.seed = seed;
        let mut sim = RohcSimulator::new(config.clone());

        match sim.run() {
            Ok(_) => continue,
            Err(error) => {
                let analysis = ErrorAnalyzer::analyze_error(&error, &config);
                errors_analyzed.push((error, analysis));
            }
        }
    }

    if !errors_analyzed.is_empty() {
        let summary = ErrorAnalyzer::summarize_errors(&errors_analyzed);

        println!(
            "Analyzed {} errors from lossy channel simulations:",
            summary.total_errors
        );
        println!(
            "  Network-related: {} ({:.1}%)",
            summary.network_related,
            100.0 * summary.network_related as f32 / summary.total_errors as f32
        );
        println!(
            "  Implementation bugs: {} ({:.1}%)",
            summary.implementation_bugs,
            100.0 * summary.implementation_bugs as f32 / summary.total_errors as f32
        );
        println!(
            "  Requires review: {} ({:.1}%)",
            summary.requires_review,
            100.0 * summary.requires_review as f32 / summary.total_errors as f32
        );

        println!(
            "\nHigh-confidence bugs found: {}",
            summary.high_confidence_bugs
        );

        if summary.has_critical_issues() {
            println!("⚠️  Critical issues detected that need investigation:");
            for (_error, analysis) in &errors_analyzed {
                if analysis.category == ErrorCategory::ImplementationBug
                    && analysis.confidence > 0.8
                {
                    println!(
                        "  - {} (confidence: {:.1}%)",
                        analysis.reason,
                        analysis.confidence * 100.0
                    );
                }
            }
        } else {
            println!("✓ No critical implementation bugs detected in lossy channel");
        }
    } else {
        println!("✓ No errors encountered in lossy channel simulations");
    }

    println!("\nSummary:");
    println!("========");
    println!("The error analyzer helps distinguish between:");
    println!("• Network-related errors (expected with packet loss)");
    println!("• Implementation bugs (unexpected on any channel)");
    println!("• Ambiguous cases requiring manual review");
    println!("\nThis reduces noise and helps focus on real bugs.");
}
