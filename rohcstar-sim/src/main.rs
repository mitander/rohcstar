//! ROHCStar Deterministic Simulator CLI.
//!
//! This binary provides command-line interface to run various ROHC simulations:
//! - Fuzzing: Run many simulations with randomized configurations.
//! - Replay: Re-run a simulation with a specific seed and configuration.
//! - Stress: (Placeholder) Long-duration stress testing.

use clap::Parser;
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use rohcstar::RohcError;
use rohcstar_sim::{RohcSimulator, SimConfig, SimError};
use std::fs::File;
use std::io::Write;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::thread;
use std::time::Duration;
use std::time::Instant;

#[derive(Parser, Debug)]
#[command(author, version, about = "ROHCStar Deterministic Simulator", long_about = None)]
struct CliArgs {
    /// Run mode: fuzz, replay, or stress.
    #[arg(value_enum)]
    mode: RunMode,

    /// Seed for the simulation. Required for 'replay', used as master seed for 'fuzz' loop if provided.
    #[arg(short, long)]
    seed: Option<u64>,

    /// Number of iterations (distinct SimConfig seeds) for 'fuzz' mode.
    #[arg(short = 'i', long, default_value_t = 1000)]
    iterations: usize,

    /// Number of packets to generate and process per simulation run.
    #[arg(short = 'p', long, default_value_t = 200)]
    packets: usize,

    /// Maximum packet loss probability (0.0 to 1.0) for fuzz mode.
    #[arg(long, default_value_t = 0.1)]
    max_loss: f64,

    /// Output file for logging failures and interesting cases.
    #[arg(short = 'o', long, default_value = "rohc_sim_failures.log")]
    output_file: PathBuf,

    /// Number of parallel workers for fuzzing. Defaults to number of logical CPUs.
    #[arg(short = 'w', long, default_value_t = num_cpus::get())]
    workers: usize,
}

#[derive(clap::ValueEnum, Clone, Debug)]
enum RunMode {
    /// Fuzz with many random configurations.
    Fuzz,
    /// Replay a simulation with a specific seed and default configuration.
    Replay,
    /// (Placeholder) Long-running stress test.
    Stress,
}

fn main() {
    let args = CliArgs::parse();

    match args.mode {
        RunMode::Fuzz => run_fuzz_mode(args),
        RunMode::Replay => run_replay_mode(args),
        RunMode::Stress => run_stress_mode(args),
    }
}

/// Generates a randomized `SimConfig` for a fuzzing iteration.
///
/// Creates a deterministic but varied simulation configuration using the provided seed.
/// The generated configuration includes randomized parameters for packet generation,
/// network conditions, and ROHC compression behavior to stress-test different scenarios.
///
/// # Parameters
/// - `iteration_seed`: Random seed for deterministic configuration generation
/// - `num_packets_per_run`: Number of packets to generate in this simulation run
/// - `max_channel_loss`: Maximum packet loss probability (0.0 to 1.0) to randomly select from
///
/// # Returns
/// A `SimConfig` with randomized parameters suitable for fuzzing
///
/// # Configuration Randomization
/// - **SSRC**: Fully randomized for context isolation
/// - **Starting values**: Random but reasonable ranges for SN, timestamp, IP ID
/// - **Timestamp stride**: Usually 160 (RTP default) but occasionally randomized
/// - **CID**: 50% chance of using 0, otherwise random 1-15
/// - **Marker probability**: 70% chance of 0.0, otherwise 1-50%
/// - **Packet loss**: 70% chance of 0.0, otherwise up to `max_channel_loss`
/// - **Phase counts**: Random but ensure at least 1 packet per phase
fn generate_fuzz_config(
    iteration_seed: u64,
    num_packets_per_run: usize,
    max_channel_loss: f64,
) -> SimConfig {
    let mut rng = rand::rngs::StdRng::seed_from_u64(iteration_seed);

    SimConfig {
        seed: rng.random(), // Each SimConfig gets its own truly random seed for its internal RNGs
        num_packets: num_packets_per_run,
        start_sn: rng.random_range(0..(u16::MAX / 4)),
        start_ts_val: rng.random_range(0..(u32::MAX / 4)),
        ts_stride: if rng.random_bool(0.8) {
            160
        } else {
            rng.random_range(1..1000u32)
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
            rng.random_range(0.0..=max_channel_loss.clamp(0.0, 1.0))
        },
        stable_phase_count: rng.random_range(1..=10),
        uo0_phase_count: rng.random_range(1..=10),
    }
}

/// Runs the fuzzing mode with parallel workers to test many randomized configurations.
///
/// This function orchestrates a large-scale fuzzing campaign by:
/// 1. Creating multiple worker threads for parallel execution
/// 2. Generating unique simulation configurations for each iteration
/// 3. Running simulations and collecting failure statistics
/// 4. Logging critical failures and tolerated errors
/// 5. Providing progress updates and final summary
///
/// # Parameters
/// - `args`: Command-line arguments containing fuzzing parameters
///
/// # Worker Distribution
/// Each worker gets roughly `iterations / workers` configurations to test.
/// Workers use deterministic seeds derived from the master seed to ensure
/// reproducible failure sequences even in parallel execution.
///
/// # Error Classification
/// - **Critical Failures**: Unexpected errors that indicate real bugs
/// - **Tolerated Errors**: Expected errors due to configuration (e.g., timestamp
///   mismatches with packet loss, parsing errors with high loss rates)
///
/// # Exit Behavior
/// - Returns 0 (success) if no critical failures found
/// - Returns 1 (failure) if any critical failures detected
/// - Supports graceful shutdown via Ctrl+C
fn run_fuzz_mode(args: CliArgs) {
    println!(
        "Starting Fuzz mode: {} iterations, {} packets/iter, up to {}% loss, {} workers.",
        args.iterations,
        args.packets,
        (args.max_loss * 100.0) as u32,
        args.workers
    );
    let fuzz_run_start_time = Instant::now();

    let total_iterations = Arc::new(AtomicUsize::new(0));
    let critical_failures = Arc::new(AtomicUsize::new(0));
    let tolerated_errors = Arc::new(AtomicUsize::new(0));
    let gracefully_stopped = Arc::new(AtomicBool::new(false));

    let output_file_handle = Arc::new(std::sync::Mutex::new(
        File::create(&args.output_file).unwrap_or_else(|e| {
            panic!("Failed to create output file {:?}: {}", args.output_file, e)
        }),
    ));

    let running_main_thread = Arc::new(AtomicBool::new(true));
    let running_ctrlc = running_main_thread.clone();
    ctrlc::set_handler(move || {
        println!("\nCtrl+C detected. Signalling workers to stop...");
        running_ctrlc.store(false, Ordering::SeqCst);
    })
    .expect("Error setting Ctrl-C handler");

    let master_fuzz_seed = args.seed.unwrap_or_else(rand::random);
    let mut scenario_seed_rng = StdRng::seed_from_u64(master_fuzz_seed);
    println!(
        "Master seed for generating SimConfig seeds: {}",
        master_fuzz_seed
    );

    let iterations_per_worker = args.iterations.div_ceil(args.workers);

    (0..args.workers).for_each(|_worker_id| {
        let completed_by_worker = Arc::clone(&total_iterations);
        let crit_fail_by_worker = Arc::clone(&critical_failures);
        let tol_err_by_worker = Arc::clone(&tolerated_errors);
        let running_worker = Arc::clone(&running_main_thread);
        let output_file_worker = Arc::clone(&output_file_handle);
        let gracefully_stopped_clone = gracefully_stopped.clone();

        // Deterministic seed generator per worker for reproducible failure sequences
        let mut worker_scenario_seed_rng = StdRng::seed_from_u64(scenario_seed_rng.random());

        thread::spawn(move || {
            for _i in 0..iterations_per_worker {
                if !running_worker.load(Ordering::Relaxed) {
                    gracefully_stopped_clone.store(true, Ordering::Relaxed);
                    break;
                }
                let current_config_seed = worker_scenario_seed_rng.random();
                let config = generate_fuzz_config(current_config_seed, args.packets, args.max_loss);
                let mut sim = RohcSimulator::new(config.clone());

                match sim.run() {
                    Ok(_) => {}
                    Err(sim_error) => {
                        let is_critical = match &sim_error {
                            SimError::VerificationError { message, .. } => {
                                !(message.contains("Timestamp mismatch")
                                    && (config.marker_probability > 0.0
                                        || config.channel_packet_loss_probability > 0.0))
                            }
                            SimError::DecompressionError { error, .. } => {
                                !((config.channel_packet_loss_probability > 0.0)
                                    && (matches!(error, RohcError::Parsing(_))
                                        || matches!(error, RohcError::InvalidState(_))))
                            }
                            _ => true,
                        };

                        let log_message = format!(
                            "{} - Seed {}: Error: {:?}\nConfig: {:#?}\n\n",
                            if is_critical {
                                "CRITICAL FAILURE"
                            } else {
                                "Tolerated Error"
                            },
                            current_config_seed,
                            sim_error,
                            config
                        );

                        eprint!("{}", log_message);
                        if let Ok(mut file) = output_file_worker.lock() {
                            let _ = file.write_all(log_message.as_bytes());
                            let _ = file.flush();
                        }

                        if is_critical {
                            crit_fail_by_worker.fetch_add(1, Ordering::Relaxed);
                            // running_worker.store(false, Ordering::Relaxed); // Uncomment to stop all on first critical
                        } else {
                            tol_err_by_worker.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                }
                let total_done = completed_by_worker.fetch_add(1, Ordering::Relaxed) + 1;
                if total_done % (100 * args.workers).max(1) == 0 || total_done == args.iterations {
                    println!(
                        "Progress: ~{}/{} iterations completed ({} critical, {} tolerated)",
                        total_done,
                        args.iterations,
                        crit_fail_by_worker.load(Ordering::Relaxed),
                        tol_err_by_worker.load(Ordering::Relaxed)
                    );
                }
                if total_done >= args.iterations && args.workers == 1 {
                    break;
                }
            }
        });
    });

    // Wait for threads in pool scope; this is implicit with rayon's top-level scope,
    // but if using std::thread, you'd join. For rayon, it blocks until all spawned tasks are done.
    // The main thread continues after scope exits or all tasks complete.
    while running_main_thread.load(Ordering::Relaxed)
        && total_iterations.load(Ordering::Relaxed) < args.iterations
    {
        // Poll for completion if workers are still running
        thread::sleep(Duration::from_millis(100));
    }

    let final_completed = total_iterations.load(Ordering::SeqCst);
    let final_critical_failures = critical_failures.load(Ordering::SeqCst);
    let final_tolerated_errors = tolerated_errors.load(Ordering::SeqCst);

    println!("\n--- Fuzzing Run Summary ---");
    println!(
        "Total iterations attempted/completed: {} / {}",
        args.iterations, final_completed
    );
    println!("Duration: {:.2?}", fuzz_run_start_time.elapsed());
    println!("Critical Failures: {}", final_critical_failures);
    println!("Tolerated Errors: {}", final_tolerated_errors);
    if gracefully_stopped.load(Ordering::SeqCst) {
        println!("Fuzzing was gracefully interrupted.");
    }
    if final_critical_failures > 0 {
        println!(
            "FAIL: Critical failures found. Check '{}'.",
            args.output_file.display()
        );
        std::process::exit(1);
    } else {
        println!("PASS: No critical failures detected.");
    }
}
/// Runs replay mode to reproduce a specific simulation scenario.
///
/// This mode allows debugging specific failures found during fuzzing by
/// recreating the exact same simulation conditions using a known seed.
/// The simulation uses the same configuration generation logic as fuzzing
/// but runs only a single deterministic scenario.
///
/// # Parameters
/// - `args`: Command-line arguments containing the seed and replay parameters
///
/// # Requirements
/// - `args.seed` must be provided (the function will panic if missing)
/// - The seed should typically come from a previous fuzzing run's failure log
///
/// # Exit Behavior
/// - Returns 0 (success) if replay completes without errors
/// - Returns 1 (failure) if replay encounters any simulation error
/// - Prints the full configuration being replayed for debugging
fn run_replay_mode(args: CliArgs) {
    let seed_to_replay = args
        .seed
        .expect("Seed (--seed <VALUE>) is required for replay mode.");
    println!(
        "Replaying simulation with specific SimConfig seed: {}",
        seed_to_replay
    );

    let config_to_replay = generate_fuzz_config(seed_to_replay, args.packets, args.max_loss);
    println!("Replaying with Config: {:#?}", config_to_replay);

    let mut simulator = RohcSimulator::new(config_to_replay);
    match simulator.run() {
        Ok(_) => println!(
            "SUCCESS: Replay of seed {} completed without errors.",
            seed_to_replay
        ),
        Err(e) => {
            eprintln!(
                "FAILURE: Replay of seed {} resulted in error: {:?}",
                seed_to_replay, e
            );
            std::process::exit(1);
        }
    }
}

/// Runs stress test mode for long-duration stability testing.
///
/// This mode is designed to test system stability under sustained load by
/// running a single simulation with a large number of packets and moderate
/// network conditions. Unlike fuzzing, this focuses on endurance rather
/// than configuration variety.
///
/// # Parameters
/// - `args`: Command-line arguments containing stress test parameters
///
/// # Configuration
/// - Uses 1,000,000 packets per iteration (overriding CLI packet count)
/// - Applies 1% packet loss and 5% marker probability for realistic stress
/// - Phase counts are tied to the iterations parameter for duration control
/// - Single-threaded execution to focus on individual run stability
///
/// # Use Cases
/// - Memory leak detection over long runs
/// - Performance profiling under sustained load
/// - Stability testing for production-like scenarios
///
/// # Exit Behavior
/// - Returns 0 (success) if stress test completes successfully
/// - Returns 1 (failure) if any error occurs during execution
/// - Reports timing information for performance analysis
fn run_stress_mode(args: CliArgs) {
    println!(
        "Stress Test Mode ({} packets per iteration, {} workers, interrupt with Ctrl+C):",
        args.packets, args.workers
    );

    let seed = args.seed.unwrap_or_else(rand::random);
    let config = SimConfig {
        seed,
        num_packets: 1_000_000,                // Large number of packets
        channel_packet_loss_probability: 0.01, // Some loss
        marker_probability: 0.05,              // Some marker changes
        stable_phase_count: args.iterations.max(100), // Can tie this to CLI arg for stress duration control
        uo0_phase_count: args.iterations.max(100),
        ..Default::default()
    };

    println!("Running stress iteration with config: {:#?}", config);
    let mut simulator = RohcSimulator::new(config.clone());
    let start_time = Instant::now();
    match simulator.run() {
        Ok(_) => {
            println!(
                "Stress iteration completed successfully in {:.2?}.",
                start_time.elapsed()
            );
        }
        Err(e) => {
            eprintln!(
                "Stress iteration FAILED after {:.2?} with error: {:?}",
                start_time.elapsed(),
                e
            );
            eprintln!("Failing Config: {:#?}", config);
            std::process::exit(1);
        }
    }
}
