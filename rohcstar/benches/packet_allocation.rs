//! Benchmark packet allocation patterns.

use criterion::{Criterion, black_box, criterion_group, criterion_main};
use rohcstar::constants::{ROHC_ADD_CID_FEEDBACK_PREFIX_VALUE, ROHC_SMALL_CID_MASK};
use rohcstar::error::{Field, RohcBuildingError};
use rohcstar::profiles::profile1::serialization::uo0_packets::serialize_uo0;
use rohcstar::profiles::profile1::{P1_UO0_SN_LSB_WIDTH_DEFAULT, Uo0Packet};
use rohcstar::types::ContextId;

/// Maximum size for UO-0 packets (Add-CID + UO-0 byte).
const UO0_MAX_SIZE: usize = 2;

/// Zero-allocation UO-0 packet builder for benchmarking.
///
/// Returns a fixed-size array and actual length to avoid heap allocation.
/// This is experimental code used only for performance comparisons.
fn build_uo0_packet(
    packet_data: &Uo0Packet,
) -> Result<([u8; UO0_MAX_SIZE], usize), RohcBuildingError> {
    debug_assert!(
        packet_data.sn_lsb < (1 << P1_UO0_SN_LSB_WIDTH_DEFAULT),
        "SN LSB value {} too large for {} bits",
        packet_data.sn_lsb,
        P1_UO0_SN_LSB_WIDTH_DEFAULT
    );
    debug_assert!(
        packet_data.crc3 <= 0x07,
        "CRC3 value {} too large",
        packet_data.crc3
    );

    if packet_data.sn_lsb >= (1 << P1_UO0_SN_LSB_WIDTH_DEFAULT) {
        return Err(RohcBuildingError::InvalidFieldValueForBuild {
            field: Field::SnLsb,
            value: packet_data.sn_lsb as u32,
            max_bits: P1_UO0_SN_LSB_WIDTH_DEFAULT,
        });
    }
    if packet_data.crc3 > 0x07 {
        return Err(RohcBuildingError::InvalidFieldValueForBuild {
            field: Field::Crc3,
            value: packet_data.crc3 as u32,
            max_bits: 3,
        });
    }

    let mut buf = [0u8; UO0_MAX_SIZE];
    let mut pos = 0;

    // Add-CID octet if needed
    if let Some(cid_val) = packet_data.cid {
        if cid_val > 0 && cid_val <= 15 {
            buf[pos] = ROHC_ADD_CID_FEEDBACK_PREFIX_VALUE | (*cid_val as u8 & ROHC_SMALL_CID_MASK);
            pos += 1;
        } else if cid_val > 15 {
            return Err(RohcBuildingError::InvalidFieldValueForBuild {
                field: Field::Cid,
                value: *cid_val as u32,
                max_bits: 4,
            });
        }
    }

    // Core UO-0 byte: SN(4 bits) + CRC3(3 bits)
    let core_byte = (packet_data.sn_lsb << 3) | packet_data.crc3;
    buf[pos] = core_byte;
    pos += 1;

    Ok((buf, pos))
}

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
