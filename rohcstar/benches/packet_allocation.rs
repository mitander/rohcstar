//! Benchmark packet allocation patterns.

use criterion::{Criterion, black_box, criterion_group, criterion_main};
use rohcstar::profiles::profile1::Uo0Packet;
use rohcstar::profiles::profile1::packet_builder::{UO0_MAX_SIZE, build_uo0_packet};
use rohcstar::profiles::profile1::serialization::serialize_uo0;
use rohcstar::types::ContextId;

fn bench_current_uo0_allocation(c: &mut Criterion) {
    let packet = Uo0Packet {
        cid: Some(ContextId::new(5)),
        sn_lsb: 7,
        crc3: 2,
    };

    c.bench_function("current_uo0_with_buffer", |b| {
        b.iter(|| {
            let mut buf = [0u8; 16];
            let len = serialize_uo0(black_box(&packet), &mut buf).unwrap();
            black_box((buf, len))
        })
    });
}

fn bench_zero_copy_uo0(c: &mut Criterion) {
    let packet = Uo0Packet {
        cid: Some(ContextId::new(5)),
        sn_lsb: 7,
        crc3: 2,
    };

    c.bench_function("zero_copy_uo0_stack_array", |b| {
        b.iter(|| {
            let (buf, len) = build_uo0_packet(black_box(&packet)).unwrap();
            black_box((buf, len))
        })
    });
}

fn bench_heap_allocation_simulation(c: &mut Criterion) {
    let packet = Uo0Packet {
        cid: Some(ContextId::new(5)),
        sn_lsb: 7,
        crc3: 2,
    };

    c.bench_function("heap_allocation_vec", |b| {
        b.iter(|| {
            let mut vec = Vec::with_capacity(UO0_MAX_SIZE);
            let mut buf = [0u8; 16];
            let len = serialize_uo0(black_box(&packet), &mut buf).unwrap();
            vec.extend_from_slice(&buf[..len]);
            black_box(vec)
        })
    });
}

criterion_group!(
    packet_allocation_benches,
    bench_current_uo0_allocation,
    bench_zero_copy_uo0,
    bench_heap_allocation_simulation
);
criterion_main!(packet_allocation_benches);
