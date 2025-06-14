use clap::{Arg, Command};
use rohcstar_sim::{RohcSimulator, SimConfig, error_analyzer::{ErrorAnalyzer, ErrorAnalysis, ErrorCategory}};
use std::collections::HashMap;
use std::io::{self, Write};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

struct FuzzStats {
    runs_completed: AtomicU64,
    total_packets: AtomicU64,
    network_errors: AtomicU64,
    implementation_bugs: AtomicU64,
    review_required: AtomicU64,
    packets_per_second: AtomicU64,
    start_time: Instant,
}

impl FuzzStats {
    fn new() -> Self {
        Self {
            runs_completed: AtomicU64::new(0),
            total_packets: AtomicU64::new(0),
            network_errors: AtomicU64::new(0),
            implementation_bugs: AtomicU64::new(0),
            review_required: AtomicU64::new(0),
            packets_per_second: AtomicU64::new(0),
            start_time: Instant::now(),
        }
    }

    fn record_run(&self, packets: u64, analysis: &[ErrorAnalysis]) {
        self.runs_completed.fetch_add(1, Ordering::Relaxed);
        self.total_packets.fetch_add(packets, Ordering::Relaxed);

        for error_analysis in analysis {
            match error_analysis.category {
                ErrorCategory::NetworkRelated => {
                    self.network_errors.fetch_add(1, Ordering::Relaxed);
                }
                ErrorCategory::ImplementationBug => {
                    self.implementation_bugs.fetch_add(1, Ordering::Relaxed);
                }
                ErrorCategory::RequiresReview => {
                    self.review_required.fetch_add(1, Ordering::Relaxed);
                }
            }
        }

        let elapsed = self.start_time.elapsed().as_secs();
        if elapsed > 0 {
            let pps = self.total_packets.load(Ordering::Relaxed) / elapsed;
            self.packets_per_second.store(pps, Ordering::Relaxed);
        }
    }

    fn print_summary(&self) {
        let runs = self.runs_completed.load(Ordering::Relaxed);
        let packets = self.total_packets.load(Ordering::Relaxed);
        let network = self.network_errors.load(Ordering::Relaxed);
        let bugs = self.implementation_bugs.load(Ordering::Relaxed);
        let review = self.review_required.load(Ordering::Relaxed);
        let pps = self.packets_per_second.load(Ordering::Relaxed);
        let uptime = self.start_time.elapsed();

        println!("\n=== FUZZ MONITOR SUMMARY ===");
        println!("Uptime: {:.1}h", uptime.as_secs_f64() / 3600.0);
        println!("Runs completed: {}", runs);
        println!("Total packets: {} ({}/sec)", packets, pps);
        println!("Network errors: {} ({:.1}%)", network, 
                 if packets > 0 { (network as f64 / packets as f64) * 100.0 } else { 0.0 });
        println!("Implementation bugs: {} ({:.1}%)", bugs,
                 if packets > 0 { (bugs as f64 / packets as f64) * 100.0 } else { 0.0 });
        println!("Requires review: {} ({:.1}%)", review,
                 if packets > 0 { (review as f64 / packets as f64) * 100.0 } else { 0.0 });
    }
}

struct BugTracker {
    bug_counts: Mutex<HashMap<String, u64>>,
}

impl BugTracker {
    fn new() -> Self {
        Self {
            bug_counts: Mutex::new(HashMap::new()),
        }
    }

    fn record_bug(&self, bug_type: &str) {
        let mut counts = self.bug_counts.lock().unwrap();
        *counts.entry(bug_type.to_string()).or_insert(0) += 1;
    }

    fn print_top_bugs(&self, limit: usize) {
        let counts = self.bug_counts.lock().unwrap();
        if counts.is_empty() {
            return;
        }

        let mut bugs: Vec<_> = counts.iter().collect();
        bugs.sort_by(|a, b| b.1.cmp(a.1));

        println!("\n=== TOP {} IMPLEMENTATION BUGS ===", limit);
        for (i, (bug_type, count)) in bugs.iter().take(limit).enumerate() {
            println!("{}. {} ({}x)", i + 1, bug_type, count);
        }
    }
}

fn run_continuous_fuzz(
    config: SimConfig,
    stats: Arc<FuzzStats>,
    bug_tracker: Arc<BugTracker>,
    stop_flag: Arc<AtomicBool>,
) {
    let mut simulator = RohcSimulator::new(config.clone());
    let mut _run_counter = 0u64;

    while !stop_flag.load(Ordering::Relaxed) {
        _run_counter += 1;
        
        match simulator.run() {
            Ok(()) => {
                // Successful run - no errors to analyze
                let packets = config.num_packets as u64;
                stats.record_run(packets, &[]);
            }
            Err(sim_error) => {
                let packets = config.num_packets as u64;
                let analysis = ErrorAnalyzer::analyze_error(&sim_error, &config);
                
                // Record implementation bugs for tracking
                if let ErrorCategory::ImplementationBug = analysis.category {
                    bug_tracker.record_bug(&format!("{:?}", sim_error));
                }
                
                stats.record_run(packets, &[analysis]);
            }
        }
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let matches = Command::new("ROHC Fuzz Monitor")
        .version("1.0")
        .about("Continuous ROHC fuzzing with real-time monitoring")
        .arg(Arg::new("packets")
            .long("packets")
            .value_name("NUM")
            .help("Packets per simulation run")
            .default_value("1000"))
        .arg(Arg::new("loss-rate")
            .long("loss-rate")
            .value_name("RATE")
            .help("Packet loss rate (0.0-1.0)")
            .default_value("0.01"))
        .arg(Arg::new("error-rate")
            .long("error-rate")
            .value_name("RATE")
            .help("Bit error rate (0.0-1.0)")
            .default_value("0.001"))
        .arg(Arg::new("threads")
            .long("threads")
            .value_name("NUM")
            .help("Number of fuzzing threads")
            .default_value("4"))
        .arg(Arg::new("update-interval")
            .long("update-interval")
            .value_name("SECONDS")
            .help("Stats update interval")
            .default_value("10"))
        .get_matches();

    let packets: usize = matches.get_one::<String>("packets").unwrap().parse()?;
    let loss_rate: f64 = matches.get_one::<String>("loss-rate").unwrap().parse()?;
    let _error_rate: f64 = matches.get_one::<String>("error-rate").unwrap().parse()?;
    let threads: usize = matches.get_one::<String>("threads").unwrap().parse()?;
    let update_interval: u64 = matches.get_one::<String>("update-interval").unwrap().parse()?;

    let config = SimConfig {
        num_packets: packets,
        channel_packet_loss_probability: loss_rate,
        ..Default::default()
    };

    let stats = Arc::new(FuzzStats::new());
    let bug_tracker = Arc::new(BugTracker::new());
    let stop_flag = Arc::new(AtomicBool::new(false));

    // Set up signal handler for graceful shutdown
    let stop_flag_signal = stop_flag.clone();
    ctrlc::set_handler(move || {
        println!("\nShutdown requested...");
        stop_flag_signal.store(true, Ordering::Relaxed);
    })?;

    println!("Starting ROHC continuous fuzzing:");
    println!("  Packets per run: {}", packets);
    println!("  Loss rate: {:.3}%", loss_rate * 100.0);
    println!("  Threads: {}", threads);
    println!("  Update interval: {}s", update_interval);
    println!("\nPress Ctrl+C to stop gracefully.\n");

    // Start fuzzing threads
    let mut handles = Vec::new();
    for i in 0..threads {
        let config = config.clone();
        let stats = stats.clone();
        let bug_tracker = bug_tracker.clone();
        let stop_flag = stop_flag.clone();
        
        let handle = thread::spawn(move || {
            println!("Fuzzing thread {} started", i);
            run_continuous_fuzz(config, stats, bug_tracker, stop_flag);
            println!("Fuzzing thread {} stopped", i);
        });
        
        handles.push(handle);
    }

    // Stats display loop
    let stats_display = stats.clone();
    let bug_tracker_display = bug_tracker.clone();
    let stop_flag_display = stop_flag.clone();
    
    let stats_handle = thread::spawn(move || {
        while !stop_flag_display.load(Ordering::Relaxed) {
            thread::sleep(Duration::from_secs(update_interval));
            
            print!("\x1B[2J\x1B[1;1H"); // Clear screen
            io::stdout().flush().unwrap();
            
            stats_display.print_summary();
            bug_tracker_display.print_top_bugs(10);
            
            println!("\nPress Ctrl+C to stop gracefully.");
        }
    });

    // Wait for all threads to finish
    for handle in handles {
        handle.join().unwrap();
    }
    
    stats_handle.join().unwrap();
    
    // Final summary
    print!("\x1B[2J\x1B[1;1H"); // Clear screen
    stats.print_summary();
    bug_tracker.print_top_bugs(20);
    
    println!("\nFuzzing completed.");
    Ok(())
}