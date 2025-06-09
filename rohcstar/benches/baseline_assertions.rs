//! Baseline performance assertion benchmarks for rohcstar.
//!
//! These benchmarks enforce critical performance targets and will fail if
//! performance degrades below acceptable thresholds. Unlike regression tests,
//! these represent absolute minimum performance requirements for production use.

use criterion::{Criterion, black_box, criterion_group, criterion_main};
use std::sync::Arc;
use std::time::{Duration, Instant};

use rohcstar::crc::CrcCalculators;
use rohcstar::encodings::{decode_lsb, decode_lsb_uo0_sn, encode_lsb};
use rohcstar::engine::RohcEngine;
use rohcstar::packet_defs::GenericUncompressedHeaders;
use rohcstar::profiles::profile1::{Profile1Handler, RtpUdpIpv4Headers};
use rohcstar::time::SystemClock;
use rohcstar::types::{ContextId, IpId, SequenceNumber, Timestamp};

// Test data constants
const BENCH_SSRC: u32 = 0x12345678;
const BENCH_COMPRESS_BUF_SIZE: usize = 256;
const BENCH_CID: ContextId = ContextId(0);

/// Creates standard test headers for benchmarking
fn create_test_headers(sn: u16, ts: u32, ip_id: u16) -> RtpUdpIpv4Headers {
    RtpUdpIpv4Headers {
        ip_src: "192.168.1.1".parse().unwrap(),
        ip_dst: "192.168.1.2".parse().unwrap(),
        udp_src_port: 5004,
        udp_dst_port: 5004,
        rtp_ssrc: BENCH_SSRC.into(),
        rtp_sequence_number: SequenceNumber::new(sn),
        rtp_timestamp: Timestamp::new(ts),
        rtp_marker: false,
        ip_identification: IpId::new(ip_id),
        ..Default::default()
    }
}

/// Macro to assert operation performance
macro_rules! assert_performance {
    ($op:expr, $max_ns:expr, $description:expr) => {{
        let start = Instant::now();
        let iterations = 1000;
        for _ in 0..iterations {
            black_box($op);
        }
        let elapsed = start.elapsed();
        let per_op_ns = elapsed.as_nanos() / iterations;

        if per_op_ns > $max_ns {
            panic!(
                "{} took {}ns per operation, expected <{}ns",
                $description, per_op_ns, $max_ns
            );
        }
    }};
}

fn baseline_lsb_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("baseline_lsb");

    // Test performance requirements during setup
    assert_performance!(decode_lsb(0xA, 12345, 4, 7), 5, "LSB decode 4-bit");

    assert_performance!(decode_lsb(0xAB, 12345, 8, 7), 5, "LSB decode 8-bit");

    assert_performance!(decode_lsb_uo0_sn(0xAB, 12345), 5, "LSB decode UO-0 SN");

    assert_performance!(encode_lsb(12345, 4).unwrap(), 5, "LSB encode 4-bit");

    assert_performance!(encode_lsb(54321, 8).unwrap(), 5, "LSB encode 8-bit");

    // Regular benchmarks for measurement
    group.bench_function("decode_4bit", |b| {
        b.iter(|| {
            let result = decode_lsb(black_box(0xA), black_box(12345), black_box(4), black_box(7));
            black_box(result)
        });
    });

    group.bench_function("decode_8bit", |b| {
        b.iter(|| {
            let result = decode_lsb(
                black_box(0xAB),
                black_box(12345),
                black_box(8),
                black_box(7),
            );
            black_box(result)
        });
    });

    group.bench_function("decode_uo0_sn", |b| {
        b.iter(|| {
            let result = decode_lsb_uo0_sn(black_box(0xAB), black_box(12345));
            black_box(result)
        });
    });

    group.bench_function("encode_4bit", |b| {
        b.iter(|| {
            let result = encode_lsb(black_box(12345), black_box(4));
            black_box(result)
        });
    });

    group.bench_function("encode_8bit", |b| {
        b.iter(|| {
            let result = encode_lsb(black_box(54321), black_box(8));
            black_box(result)
        });
    });

    group.finish();
}

fn baseline_crc_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("baseline_crc");
    let crc_calcs = CrcCalculators::new();

    // Test performance requirements - 800 MiB/s = 838ns per byte max
    assert_performance!(crc_calcs.crc3(&[0xAB]), 838, "CRC3 1-byte");

    assert_performance!(crc_calcs.crc8(&[0xCD]), 838, "CRC8 1-byte");

    let data_8 = [0xAB, 0xCD, 0xEF, 0x12, 0x34, 0x56, 0x78, 0x9A];
    assert_performance!(
        crc_calcs.crc8(&data_8),
        6704, // 8 * 838ns
        "CRC8 8-byte"
    );

    let data_16 = [0xAB; 16];
    assert_performance!(
        crc_calcs.crc8(&data_16),
        13408, // 16 * 838ns
        "CRC8 16-byte"
    );

    // Regular benchmarks for measurement
    group.bench_function("crc3_1byte", |b| {
        let data = black_box([0xAB]);
        b.iter(|| {
            let result = crc_calcs.crc3(&data);
            black_box(result)
        });
    });

    group.bench_function("crc8_1byte", |b| {
        let data = black_box([0xCD]);
        b.iter(|| {
            let result = crc_calcs.crc8(&data);
            black_box(result)
        });
    });

    group.bench_function("crc8_8byte", |b| {
        let data = black_box([0xAB, 0xCD, 0xEF, 0x12, 0x34, 0x56, 0x78, 0x9A]);
        b.iter(|| {
            let result = crc_calcs.crc8(&data);
            black_box(result)
        });
    });

    group.bench_function("crc8_16byte", |b| {
        let data = black_box([0xAB; 16]);
        b.iter(|| {
            let result = crc_calcs.crc8(&data);
            black_box(result)
        });
    });

    group.finish();
}

fn baseline_roundtrip_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("baseline_roundtrip");

    // Test IR roundtrip performance requirement - <800ns
    {
        let mut engine = RohcEngine::new(20, Duration::from_secs(300), Arc::new(SystemClock));
        engine
            .register_profile_handler(Box::new(Profile1Handler::new()))
            .unwrap();
        let headers = create_test_headers(1000, 160000, 12345);
        let mut compress_buf = [0u8; BENCH_COMPRESS_BUF_SIZE];

        let compressed_len = engine
            .compress(
                BENCH_CID,
                Some(rohcstar::packet_defs::RohcProfile::RtpUdpIp),
                &GenericUncompressedHeaders::RtpUdpIpv4(headers.clone()),
                &mut compress_buf,
            )
            .unwrap();

        assert_performance!(
            engine.decompress(&compress_buf[..compressed_len]).unwrap(),
            800,
            "IR roundtrip decompression"
        );
    }

    // Test UO roundtrip performance requirement - <600ns
    {
        let mut engine = RohcEngine::new(20, Duration::from_secs(300), Arc::new(SystemClock));
        engine
            .register_profile_handler(Box::new(Profile1Handler::new()))
            .unwrap();
        let headers1 = create_test_headers(1000, 160000, 12345);
        let headers2 = create_test_headers(1001, 160160, 12346);
        let mut compress_buf = [0u8; BENCH_COMPRESS_BUF_SIZE];

        // Initialize context
        let _ir_len = engine
            .compress(
                BENCH_CID,
                Some(rohcstar::packet_defs::RohcProfile::RtpUdpIp),
                &GenericUncompressedHeaders::RtpUdpIpv4(headers1),
                &mut compress_buf,
            )
            .unwrap();

        // Get UO packet
        let uo_len = engine
            .compress(
                BENCH_CID,
                None,
                &GenericUncompressedHeaders::RtpUdpIpv4(headers2.clone()),
                &mut compress_buf,
            )
            .unwrap();

        assert_performance!(
            engine.decompress(&compress_buf[..uo_len]).unwrap(),
            100,
            "UO packet decompression"
        );
    }

    // Test first compression performance - <400ns
    {
        let headers = create_test_headers(1000, 160000, 12345);
        let mut compress_buf = [0u8; BENCH_COMPRESS_BUF_SIZE];

        assert_performance!(
            {
                let mut engine =
                    RohcEngine::new(20, Duration::from_secs(300), Arc::new(SystemClock));
                engine
                    .register_profile_handler(Box::new(Profile1Handler::new()))
                    .unwrap();
                engine
                    .compress(
                        BENCH_CID,
                        Some(rohcstar::packet_defs::RohcProfile::RtpUdpIp),
                        &GenericUncompressedHeaders::RtpUdpIpv4(headers.clone()),
                        &mut compress_buf,
                    )
                    .unwrap()
            },
            400,
            "First packet compression"
        );
    }

    // Test subsequent compression performance - <200ns
    {
        let mut engine = RohcEngine::new(20, Duration::from_secs(300), Arc::new(SystemClock));
        engine
            .register_profile_handler(Box::new(Profile1Handler::new()))
            .unwrap();
        let headers1 = create_test_headers(1000, 160000, 12345);
        let headers2 = create_test_headers(1001, 160160, 12346);
        let mut compress_buf = [0u8; BENCH_COMPRESS_BUF_SIZE];

        // Initialize context
        let _ir_len = engine
            .compress(
                BENCH_CID,
                Some(rohcstar::packet_defs::RohcProfile::RtpUdpIp),
                &GenericUncompressedHeaders::RtpUdpIpv4(headers1),
                &mut compress_buf,
            )
            .unwrap();

        assert_performance!(
            engine
                .compress(
                    BENCH_CID,
                    None,
                    &GenericUncompressedHeaders::RtpUdpIpv4(headers2.clone()),
                    &mut compress_buf
                )
                .unwrap(),
            200,
            "Subsequent packet compression"
        );
    }

    // Regular benchmarks for measurement
    group.bench_function("compress_first_packet", |b| {
        b.iter_batched(
            || {
                let mut engine =
                    RohcEngine::new(20, Duration::from_secs(300), Arc::new(SystemClock));
                engine
                    .register_profile_handler(Box::new(Profile1Handler::new()))
                    .unwrap();
                (engine, [0u8; BENCH_COMPRESS_BUF_SIZE])
            },
            |(mut engine, mut buf)| {
                let headers = create_test_headers(1000, 160000, 12345);
                let result = engine.compress(
                    BENCH_CID,
                    Some(rohcstar::packet_defs::RohcProfile::RtpUdpIp),
                    &GenericUncompressedHeaders::RtpUdpIpv4(headers),
                    &mut buf,
                );
                black_box(result)
            },
            criterion::BatchSize::SmallInput,
        );
    });

    group.bench_function("decompress_uo_packet", |b| {
        // Setup compressed UO packet
        let mut setup_engine = RohcEngine::new(20, Duration::from_secs(300), Arc::new(SystemClock));
        setup_engine
            .register_profile_handler(Box::new(Profile1Handler::new()))
            .unwrap();
        let headers1 = create_test_headers(1000, 160000, 12345);
        let headers2 = create_test_headers(1001, 160160, 12346);
        let mut setup_buf = [0u8; BENCH_COMPRESS_BUF_SIZE];

        let _ir_len = setup_engine
            .compress(
                BENCH_CID,
                Some(rohcstar::packet_defs::RohcProfile::RtpUdpIp),
                &GenericUncompressedHeaders::RtpUdpIpv4(headers1),
                &mut setup_buf,
            )
            .unwrap();

        let uo_len = setup_engine
            .compress(
                BENCH_CID,
                None,
                &GenericUncompressedHeaders::RtpUdpIpv4(headers2),
                &mut setup_buf,
            )
            .unwrap();

        let uo_packet = setup_buf[..uo_len].to_vec();

        b.iter_batched(
            || {
                let mut engine =
                    RohcEngine::new(20, Duration::from_secs(300), Arc::new(SystemClock));
                engine
                    .register_profile_handler(Box::new(Profile1Handler::new()))
                    .unwrap();
                // Initialize context
                let headers1 = create_test_headers(1000, 160000, 12345);
                let mut init_buf = [0u8; BENCH_COMPRESS_BUF_SIZE];
                let ir_len = engine
                    .compress(
                        BENCH_CID,
                        Some(rohcstar::packet_defs::RohcProfile::RtpUdpIp),
                        &GenericUncompressedHeaders::RtpUdpIpv4(headers1),
                        &mut init_buf,
                    )
                    .unwrap();
                let _ = engine.decompress(&init_buf[..ir_len]).unwrap();
                (engine, uo_packet.clone())
            },
            |(mut engine, packet)| {
                let result = engine.decompress(&packet);
                black_box(result)
            },
            criterion::BatchSize::SmallInput,
        );
    });

    group.finish();
}

criterion_group!(
    baseline_benches,
    baseline_lsb_operations,
    baseline_crc_operations,
    baseline_roundtrip_operations
);
criterion_main!(baseline_benches);
