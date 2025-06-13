use criterion::{Criterion, black_box, criterion_group, criterion_main};
use rohcstar_sim::{RohcSimulator, SimConfig};

fn benchmark_original_simulator(c: &mut Criterion) {
    c.bench_function("original_simulator_100_packets", |b| {
        b.iter(|| {
            let config = SimConfig {
                seed: black_box(42),
                num_packets: 100,
                channel_packet_loss_probability: 0.0,
                marker_probability: 0.0,
                ..Default::default()
            };
            let mut simulator = RohcSimulator::new(config);
            simulator.run().expect("Simulation should succeed");
            black_box(());
        });
    });
}

fn benchmark_optimized_simulator(c: &mut Criterion) {
    c.bench_function("optimized_simulator_100_packets", |b| {
        b.iter(|| {
            let config = SimConfig {
                seed: black_box(42),
                num_packets: 100,
                channel_packet_loss_probability: 0.0,
                ..Default::default()
            };
            let mut simulator = RohcSimulator::new(config);
            simulator
                .run()
                .expect("Optimized simulation should succeed");
            black_box(());
        });
    });
}

fn benchmark_simulation_throughput(c: &mut Criterion) {
    c.bench_function("high_throughput_1000_packets", |b| {
        b.iter(|| {
            let config = SimConfig {
                seed: black_box(999),
                num_packets: 1000,
                channel_packet_loss_probability: 0.0,
                ..Default::default()
            };
            let mut simulator = RohcSimulator::new(config);
            simulator
                .run()
                .expect("High-throughput simulation should succeed");
            black_box(());
        });
    });
}

criterion_group!(
    benches,
    benchmark_original_simulator,
    benchmark_optimized_simulator,
    benchmark_simulation_throughput
);
criterion_main!(benches);
