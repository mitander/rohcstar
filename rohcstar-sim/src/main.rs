//! Rohcstar Deterministic Simulator CLI.
//!
//! This binary provides command-line interface to run various ROHC simulations:
//! - Fuzzing: Run many simulations with randomized configurations.
//! - Replay: Re-run a simulation with a specific seed and configuration.
//! - Stress: (Placeholder) Long-duration stress testing.

use clap::Parser;
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng, random};
use rohcstar_sim::{RohcSimulator, SimConfig, SimError};
use std::collections::HashSet;
use std::fs::File;
use std::hash::{DefaultHasher, Hash, Hasher};
use std::io::Write;
use std::path::PathBuf;
use std::process::Command;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::thread;
use std::time::Duration;
use std::time::Instant;

#[derive(Parser, Debug)]
#[command(author, version, about = "Rohcstar Deterministic Simulator", long_about = None)]
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

    /// Only log critical failures (skip tolerated errors)
    #[arg(long)]
    critical_only: bool,

    /// Run forever (fuzz mode only)
    #[arg(long)]
    infinite: bool,

    /// Enable periodic 'git pull' checks and exit if updates are found (infinite mode only)
    #[arg(long, requires = "infinite")]
    enable_git_update_check: bool,

    /// Interval in seconds for 'git pull' checks (infinite mode only)
    #[arg(long, default_value_t = 600, requires = "infinite")]
    git_update_check_interval_secs: u64,

    /// ntfy.sh topic or full URL for critical failure notifications
    #[arg(long)]
    ntfy_topic: Option<String>,
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
        // Ensure phases are not trivially small, especially for larger packet counts
        stable_phase_count: rng.random_range(1..=(10.max(num_packets_per_run / 20))),
        uo0_phase_count: rng.random_range(1..=(10.max(num_packets_per_run / 20))),
    }
}

fn send_ntfy_notification_sync(
    topic_or_url: &str,
    title: &str,
    error_details: &str,
    seed: u64,
    config_details: &str,
) {
    let ntfy_url = if topic_or_url.starts_with("http://") || topic_or_url.starts_with("https://") {
        topic_or_url.to_string()
    } else {
        format!("https://ntfy.sh/{}", topic_or_url)
    };

    let full_message = format!("Seed={}\n{}\n{}", seed, error_details, config_details);

    let output = Command::new("curl")
        .arg("-X")
        .arg("POST")
        .arg("-H")
        .arg(format!("Title: {}", title))
        .arg("-H")
        .arg("Tags: rotating_light,bug")
        .arg("-d")
        .arg(&full_message)
        .arg(&ntfy_url)
        .arg("--connect-timeout")
        .arg("15")
        .arg("--max-time")
        .arg("15")
        .output();

    match output {
        Ok(output) => {
            if output.status.success() {
                println!("[NTFY] Notification sent successfully for seed {}.", seed);
            } else {
                eprintln!(
                    "[NTFY] Failed to send notification for seed {}: {}",
                    seed,
                    String::from_utf8_lossy(&output.stderr)
                );
            }
        }
        Err(e) => {
            eprintln!("[NTFY] Error executing curl for seed {}: {}", seed, e);
        }
    }
}

fn check_for_git_updates() -> Result<bool, String> {
    println!("[GIT CHECK] Running 'git pull'...");
    let output = Command::new("git")
        .arg("pull")
        .output()
        .map_err(|e| format!("Failed to execute 'git pull': {}", e))?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    if !output.status.success() {
        return Err(format!(
            "'git pull' command failed with status {}. Stderr: {}",
            output.status, stderr
        ));
    }

    // A more robust check might involve `git rev-parse HEAD` before and after `git pull`
    // and comparing the commit hashes. For simplicity, this common string check is used.
    // It's important to note that `git pull` output can be localized.
    let no_updates_messages = ["Already up to date.", "Bereits aktuell."]; // Add other localizations if needed
    let updates_pulled = !no_updates_messages.iter().any(|msg| stdout.contains(msg));

    if updates_pulled {
        println!("[GIT CHECK] 'git pull' fetched updates:\n{}", stdout);
    }

    Ok(updates_pulled)
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
/// - Returns 1 (failure) if any critical failures detected (Note: this CLI doesn't exit with 1, relies on logs/notifications)
/// - Supports graceful shutdown via Ctrl+C
fn run_fuzz_mode(args: CliArgs) {
    let mode_desc = if args.infinite {
        format!("infinite mode, {} packets/iter", args.packets)
    } else {
        format!(
            "{} iterations, {} packets/iter",
            args.iterations, args.packets
        )
    };

    println!(
        "Starting Fuzz mode: {}, up to {}% loss, {} workers{}{}{}.",
        mode_desc,
        (args.max_loss * 100.0) as u32,
        args.workers,
        if args.critical_only {
            " (critical only)"
        } else {
            ""
        },
        if args.infinite && args.enable_git_update_check {
            format!(
                ", git checks every {}s",
                args.git_update_check_interval_secs
            )
        } else {
            "".to_string()
        },
        if args.ntfy_topic.is_some() {
            " (ntfy enabled)"
        } else {
            ""
        }
    );
    let fuzz_run_start_time = Instant::now();

    let total_iterations = Arc::new(AtomicUsize::new(0));
    let critical_failures = Arc::new(AtomicUsize::new(0));
    let tolerated_errors = Arc::new(AtomicUsize::new(0));
    let gracefully_stopped = Arc::new(AtomicBool::new(false));

    // Track seen errors to avoid duplicate logging
    let seen_errors = Arc::new(std::sync::Mutex::new(HashSet::new()));

    // Progress tracking
    let last_progress_time = Arc::new(std::sync::Mutex::new(Instant::now()));
    let progress_interval = Duration::from_secs(60); // Report every minute

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

    let iterations_per_worker = if args.infinite {
        usize::MAX / args.workers.max(1) // Effectively infinite, ensure workers > 0
    } else {
        args.iterations.div_ceil(args.workers.max(1))
    };
    let critical_only = args.critical_only;
    // Clone Option<String> once for all workers to use as a template
    let ntfy_topic_template = args.ntfy_topic.clone();

    // Store args fields that will be moved into threads by copying them first
    let packets_per_run_arg = args.packets;
    let max_loss_arg = args.max_loss;
    let infinite_arg = args.infinite;
    let iterations_arg = args.iterations;

    let mut handles = Vec::new();

    for _worker_id in 0..args.workers {
        let completed_by_worker = Arc::clone(&total_iterations);
        let crit_fail_by_worker = Arc::clone(&critical_failures);
        let tol_err_by_worker = Arc::clone(&tolerated_errors);
        let running_worker = Arc::clone(&running_main_thread);
        let output_file_worker = Arc::clone(&output_file_handle);
        let gracefully_stopped_clone = gracefully_stopped.clone();
        let seen_errors_worker = Arc::clone(&seen_errors);
        let last_progress_worker = Arc::clone(&last_progress_time);
        let ntfy_topic_worker = ntfy_topic_template.clone(); // Clone the Option for this specific worker

        // Deterministic seed generator per worker for reproducible failure sequences
        let mut worker_scenario_seed_rng = StdRng::seed_from_u64(scenario_seed_rng.random());

        let handle = thread::spawn(move || {
            for _i in 0..iterations_per_worker {
                if !running_worker.load(Ordering::Relaxed) {
                    gracefully_stopped_clone.store(true, Ordering::Relaxed);
                    break;
                }
                let current_config_seed = worker_scenario_seed_rng.random();
                let config =
                    generate_fuzz_config(current_config_seed, packets_per_run_arg, max_loss_arg);
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
                            SimError::DecompressionError { error, .. } => !matches!(
                                error,
                                rohcstar::RohcError::Engine(
                                    rohcstar::error::EngineError::PacketLoss { .. }
                                )
                            ),
                            _ => true,
                        };

                        // Calculate error hash based on error type and key details
                        let error_hash = {
                            let mut hasher = DefaultHasher::new();
                            match &sim_error {
                                SimError::VerificationError { message, .. } => {
                                    format!("VerificationError:{}", message).hash(&mut hasher);
                                }
                                SimError::DecompressionError { error, .. } => {
                                    format!("DecompressionError:{:?}", error).hash(&mut hasher);
                                }
                                _ => format!("{:?}", sim_error).hash(&mut hasher),
                            }
                            hasher.finish()
                        };

                        if is_critical {
                            let is_new = seen_errors_worker.lock().unwrap().insert(error_hash);
                            if is_new {
                                crit_fail_by_worker.fetch_add(1, Ordering::Relaxed);

                                let log_message = format!(
                                    "\n[CRITICAL FAILURE]\nSeed={}\n{:#?}\n{:#?}\n\n",
                                    current_config_seed, sim_error, config
                                );

                                eprint!("{}", log_message);
                                if let Ok(mut file) = output_file_worker.lock() {
                                    let _ = file.write_all(log_message.as_bytes());
                                    let _ = file.flush();
                                }

                                // Log progress immediately on new critical failure
                                let total_done_snap = completed_by_worker.load(Ordering::Relaxed); // Use a snapshot for consistency
                                let elapsed_snap = fuzz_run_start_time.elapsed();
                                let rate_snap = if elapsed_snap.as_secs_f64() > 0.0 {
                                    total_done_snap as f64 / elapsed_snap.as_secs_f64()
                                } else {
                                    0.0
                                };
                                println!(
                                    "[{:>7.1}s] {} iters @ {:.0}/sec | {} critical, {} tolerated (New Critical!)",
                                    elapsed_snap.as_secs_f64(),
                                    total_done_snap,
                                    rate_snap,
                                    crit_fail_by_worker.load(Ordering::Relaxed), // Use current counts for summary
                                    tol_err_by_worker.load(Ordering::Relaxed)
                                );

                                // Send ntfy notification if configured
                                if let Some(topic) = &ntfy_topic_worker {
                                    // Create a concise summary for notification
                                    let error_summary_for_ntfy = match &sim_error {
                                        SimError::VerificationError { message, .. } => {
                                            message.chars().take(100).collect::<String>() + "..."
                                        }
                                        SimError::DecompressionError { error, .. } => {
                                            format!("{:?}", error)
                                                .chars()
                                                .take(100)
                                                .collect::<String>()
                                                + "..."
                                        }
                                        _ => {
                                            format!("{:?}", sim_error)
                                                .chars()
                                                .take(100)
                                                .collect::<String>()
                                                + "..."
                                        }
                                    };
                                    let config_summary_for_ntfy = format!("{:#?}", config); // Or a more summarized version
                                    send_ntfy_notification_sync(
                                        topic,
                                        "ROHCStar Fuzzer: CRITICAL FAILURE",
                                        &error_summary_for_ntfy,
                                        current_config_seed,
                                        &config_summary_for_ntfy,
                                    );
                                }
                            }
                            // Don't exit - keep fuzzing to find more bugs
                        } else {
                            tol_err_by_worker.fetch_add(1, Ordering::Relaxed);

                            // Only log tolerated errors if not in critical_only mode
                            if !critical_only {
                                let log_message = format!(
                                    "\n[Tolerated Error]\nSeed={}\n{:#?}\n{:#?}\n\n",
                                    current_config_seed, sim_error, config
                                );
                                eprint!("{}", log_message);
                            }
                        }
                    }
                }

                let total_done_this_worker =
                    completed_by_worker.fetch_add(1, Ordering::Relaxed) + 1;

                // For finite runs, signal main thread if global iteration count is met.
                // The worker continues its `iterations_per_worker` unless main thread stops it.
                if !infinite_arg
                    && total_done_this_worker >= iterations_arg
                    && running_worker.load(Ordering::Relaxed)
                {
                    // Check if not already stopping
                    // This condition might be hit by multiple workers if iterations_per_worker is not perfectly aligned
                    // but running_main_thread store is atomic.
                    println!(
                        "Worker {} reached target iterations {}. Signaling main thread if not already done.",
                        _i, iterations_arg
                    );
                    // running_worker.store(false, Ordering::Relaxed); // Let main loop detect via total_iterations
                }

                // Periodic progress updates (try_lock to avoid contention)
                let should_log_progress = if let Ok(mut last_time) = last_progress_worker.try_lock()
                {
                    let now = Instant::now();
                    if now.duration_since(*last_time) >= progress_interval {
                        *last_time = now;
                        true
                    } else {
                        false
                    }
                } else {
                    false // Another thread is logging progress, or lock is busy
                };

                if should_log_progress {
                    let total_done_snap = completed_by_worker.load(Ordering::Relaxed); // Use current global total
                    let elapsed = fuzz_run_start_time.elapsed();
                    let rate = if elapsed.as_secs_f64() > 0.0 {
                        total_done_snap as f64 / elapsed.as_secs_f64()
                    } else {
                        0.0
                    };
                    println!(
                        "[{:>7.1}s] {} iters @ {:.0}/sec | {} critical, {} tolerated",
                        elapsed.as_secs_f64(),
                        total_done_snap,
                        rate,
                        crit_fail_by_worker.load(Ordering::Relaxed),
                        tol_err_by_worker.load(Ordering::Relaxed)
                    );
                }
            }
            // Worker finished its assigned iterations or was stopped
            if running_worker.load(Ordering::Relaxed)
                && !infinite_arg
                && completed_by_worker.load(Ordering::Relaxed) < iterations_arg
            {
                // This case should ideally not be hit if iterations_per_worker is calculated correctly
                // and the main loop condition works.
                // println!("Worker finished its loop but global iterations not met. This might indicate an issue or end of worker's share.");
            }
        });

        handles.push(handle);
    }

    // --- Main thread loop for waiting and git checks ---
    let mut last_git_check_time = Instant::now();
    let git_check_interval = Duration::from_secs(args.git_update_check_interval_secs);

    while running_main_thread.load(Ordering::Relaxed)
        && (args.infinite || total_iterations.load(Ordering::Relaxed) < args.iterations)
    {
        if args.infinite
            && args.enable_git_update_check
            && last_git_check_time.elapsed() >= git_check_interval
        {
            match check_for_git_updates() {
                Ok(true) => {
                    // Updates found
                    println!(
                        "[GIT CHECK] Updates found via 'git pull'. Signaling shutdown to allow restart."
                    );
                    running_main_thread.store(false, Ordering::Relaxed); // Signal workers
                    gracefully_stopped.store(true, Ordering::Relaxed); // Mark as graceful stop for summary
                    // The loop will terminate as running_main_thread is now false.
                }
                Ok(false) => {
                    // No updates
                    println!("[GIT CHECK] No new git updates found.");
                }
                Err(e) => {
                    // Error executing git pull itself
                    eprintln!(
                        "[GIT CHECK] Error during 'git pull' check: {}. Continuing fuzzing.",
                        e
                    );
                }
            }
            last_git_check_time = Instant::now(); // Reset timer regardless of outcome
        }
        thread::sleep(Duration::from_millis(500)); // Poll less frequently in main thread
    }

    // Ensure all worker tasks are signaled to stop if not already
    running_main_thread.store(false, Ordering::Relaxed);

    println!("Main loop finished. Waiting for workers to complete current tasks...");

    // Wait for all worker threads to complete
    for handle in handles {
        if let Err(e) = handle.join() {
            eprintln!("Worker thread panicked: {:?}", e);
        }
    }

    let final_completed = total_iterations.load(Ordering::SeqCst);
    let final_critical_failures = critical_failures.load(Ordering::SeqCst);
    let final_tolerated_errors = tolerated_errors.load(Ordering::SeqCst);

    println!("\n--- Fuzzing Run Summary ---");

    let iterations_display_str = if args.infinite {
        "N/A (infinite)".to_string()
    } else {
        args.iterations.to_string()
    };
    println!(
        "Total iterations attempted/completed: {} / {}",
        iterations_display_str, final_completed
    );

    println!("Duration: {:.2?}", fuzz_run_start_time.elapsed());
    println!("Critical Failures (unique): {}", final_critical_failures);
    println!("Tolerated Errors: {}", final_tolerated_errors);
    if gracefully_stopped.load(Ordering::SeqCst) {
        println!("Fuzzing was gracefully interrupted (Ctrl+C or git update).");
    }
    if final_critical_failures > 0 {
        println!(
            "Found {} unique critical failures. Check '{}'.",
            final_critical_failures,
            args.output_file.display()
        );
        // Don't exit with 1 - let the fuzzer complete its run / allow wrapper script to handle
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
        "Stress Test Mode (fixed 1,000,000 packets, {} iterations for phase counts, interrupt with Ctrl+C):",
        args.iterations // iterations arg used for phase count here
    );

    let seed = args.seed.unwrap_or_else(rand::random);
    let config = SimConfig {
        seed,
        num_packets: 1_000_000,                // Large number of packets
        channel_packet_loss_probability: 0.01, // Some loss
        marker_probability: 0.05,              // Some marker changes
        stable_phase_count: args.iterations.max(100), // Can tie this to CLI arg for stress duration control
        uo0_phase_count: args.iterations.max(100),
        // Default other SimConfig fields reasonable for stress:
        start_sn: 0,
        start_ts_val: 0,
        ts_stride: 160, // Common RTP stride
        ssrc: random(),
        cid: 0, // Common CID
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
