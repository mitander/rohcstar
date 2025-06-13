//! Demo of smart fuzzer with error classification.

use rohcstar_sim::smart_fuzzer::{SmartFuzzConfig, SmartFuzzer};

fn main() {
    // Quick demonstration run
    let config = SmartFuzzConfig {
        iterations: 100,
        packets_per_iteration: 50,
        max_packet_loss: 0.15,
        focus_on_bugs: true,   // Only show real bugs, not network noise
        master_seed: Some(42), // Reproducible
        ..Default::default()
    };

    let fuzzer = SmartFuzzer::new(config);
    let results = fuzzer.run();

    println!("\n🎯 Demonstration Complete!");
    println!("This smart fuzzer:");
    println!(
        "• Ran {} simulations in {:.2}s",
        results.total_simulations,
        results.duration.as_secs_f64()
    );
    println!(
        "• Achieved {:.0} simulations/second",
        results.simulation_rate
    );
    println!(
        "• Found {} implementation bugs vs {} network errors",
        results.implementation_bugs, results.network_related_errors
    );
    println!("• Filtered out network noise, focusing on real issues");

    if results.has_critical_issues() {
        println!("\n🚨 Use these bug reports to fix the implementation!");
    } else {
        println!("\n✅ Implementation looks solid under these test conditions.");
    }
}
