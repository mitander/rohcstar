use criterion::{BenchmarkId, Criterion, Throughput, black_box, criterion_group, criterion_main};
use rohcstar::{
    crc::CrcCalculators,
    encodings::{decode_lsb, encode_lsb},
    engine::RohcEngine,
    packet_defs::{GenericUncompressedHeaders, RohcProfile},
    profiles::profile1::{Profile1Handler, RtpUdpIpv4Headers},
    serialization::deserialize_rtp_udp_ipv4_headers,
    time::SystemClock,
    types::{IpId, SequenceNumber, Timestamp},
};
use std::{sync::Arc, time::Duration};

const BENCH_COMPRESS_BUF_SIZE: usize = 256;

// Helper function to create a minimal RTP/UDP/IPv4 packet
fn create_minimal_rtp_packet() -> Vec<u8> {
    let mut packet = Vec::with_capacity(40);

    // IPv4 header (20 bytes)
    packet.extend_from_slice(&[
        0x45, // Version=4, IHL=5
        0x00, // DSCP=0, ECN=0
        0x00, 0x2C, // Total Length = 44 bytes
        0x12, 0x34, // Identification
        0x40, 0x00, // Flags=2 (DF), Fragment Offset=0
        0x40, // TTL=64
        0x11, // Protocol=UDP
        0x00, 0x00, // Checksum (placeholder)
        192, 168, 1, 1, // Source IP
        192, 168, 1, 2, // Dest IP
    ]);

    // UDP header (8 bytes)
    packet.extend_from_slice(&[
        0x27, 0x10, // Source Port = 10000
        0x4E, 0x20, // Dest Port = 20000
        0x00, 0x18, // Length = 24 bytes
        0x00, 0x00, // Checksum (placeholder)
    ]);

    // RTP header (12 bytes)
    packet.extend_from_slice(&[
        0x80, // V=2, P=0, X=0, CC=0
        0x00, // M=0, PT=0
        0x00, 0x64, // Sequence Number = 100
        0x00, 0x00, 0x03, 0xE8, // Timestamp = 1000
        0x12, 0x34, 0x56, 0x78, // SSRC
    ]);

    packet
}

// Helper function to create RTP packet with CSRC list
fn create_rtp_packet_with_csrc(csrc_count: u8) -> Vec<u8> {
    let mut packet = create_minimal_rtp_packet();

    // Update CC field in RTP header
    packet[28] = 0x80 | csrc_count;

    // Add CSRC list
    for i in 0..csrc_count {
        let csrc = 0x11111111u32 + i as u32;
        packet.extend_from_slice(&csrc.to_be_bytes());
    }

    // Update UDP and IP lengths
    let total_rtp_len = 12 + (csrc_count as usize * 4);
    let udp_len = 8 + total_rtp_len;
    let ip_len = 20 + udp_len;

    // Update IP total length
    packet[2..4].copy_from_slice(&(ip_len as u16).to_be_bytes());

    // Update UDP length
    packet[24..26].copy_from_slice(&(udp_len as u16).to_be_bytes());

    packet
}

// Helper function to create test headers
fn create_test_headers() -> RtpUdpIpv4Headers {
    RtpUdpIpv4Headers {
        ip_src: "192.168.1.1".parse().unwrap(),
        ip_dst: "192.168.1.2".parse().unwrap(),
        udp_src_port: 10000,
        udp_dst_port: 20000,
        rtp_ssrc: 0x12345678.into(),
        rtp_sequence_number: SequenceNumber::new(100),
        rtp_timestamp: Timestamp::new(1000),
        rtp_marker: false,
        ip_identification: IpId::new(0x1234),
        ..Default::default()
    }
}

fn bench_packet_parsing(c: &mut Criterion) {
    let mut group = c.benchmark_group("packet_parsing");

    // Benchmark minimal packet parsing
    let minimal_packet = create_minimal_rtp_packet();
    group.throughput(Throughput::Bytes(minimal_packet.len() as u64));
    group.bench_function("minimal_rtp_packet", |b| {
        b.iter(|| deserialize_rtp_udp_ipv4_headers(black_box(&minimal_packet)))
    });

    // Benchmark packets with different CSRC counts
    for csrc_count in [0, 1, 4, 8, 15] {
        let packet = create_rtp_packet_with_csrc(csrc_count);
        group.throughput(Throughput::Bytes(packet.len() as u64));
        group.bench_with_input(
            BenchmarkId::new("csrc_list", csrc_count),
            &packet,
            |b, packet| b.iter(|| deserialize_rtp_udp_ipv4_headers(black_box(packet))),
        );
    }

    group.finish();
}

fn bench_lsb_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("lsb_operations");

    // Test various bit widths for encoding
    for k in [4, 8, 12, 16] {
        group.bench_with_input(BenchmarkId::new("encode", k), &k, |b, &k| {
            b.iter(|| encode_lsb(black_box(12345u64), black_box(k)))
        });
    }

    // Test various bit widths for decoding
    for k in [4, 8, 12, 16] {
        let encoded = encode_lsb(12345u64, k).unwrap();
        group.bench_with_input(
            BenchmarkId::new("decode", k),
            &(encoded, k),
            |b, &(encoded, k)| {
                b.iter(|| {
                    decode_lsb(
                        black_box(encoded),
                        black_box(12000u64),
                        black_box(k),
                        black_box(0i64),
                    )
                })
            },
        );
    }

    // Test wraparound scenarios
    group.bench_function("decode_wraparound_u16", |b| {
        b.iter(|| {
            decode_lsb(
                black_box(5u64),
                black_box(65530u64),
                black_box(8u8),
                black_box(0i64),
            )
        })
    });

    group.finish();
}

fn bench_crc_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("crc_operations");
    let crc_calc = CrcCalculators::new();

    // Test CRC calculation with different payload sizes
    for size in [1, 4, 8, 16, 32, 64, 128] {
        let data = vec![0x42u8; size];

        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::new("crc3", size), &data, |b, data| {
            b.iter(|| crc_calc.crc3(black_box(data)))
        });

        group.bench_with_input(BenchmarkId::new("crc8", size), &data, |b, data| {
            b.iter(|| crc_calc.crc8(black_box(data)))
        });
    }

    group.finish();
}

fn bench_compression_pipeline(c: &mut Criterion) {
    let mut group = c.benchmark_group("compression_pipeline");

    let headers = create_test_headers();
    let generic_headers = GenericUncompressedHeaders::RtpUdpIpv4(headers.clone());

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
            |(mut engine, mut compress_buf)| {
                engine.compress(
                    black_box(0.into()),
                    Some(RohcProfile::RtpUdpIp),
                    black_box(&generic_headers),
                    black_box(&mut compress_buf),
                )
            },
            criterion::BatchSize::SmallInput,
        )
    });

    // Benchmark subsequent compressions (should be faster due to context)
    let mut setup_engine = RohcEngine::new(20, Duration::from_secs(300), Arc::new(SystemClock));
    setup_engine
        .register_profile_handler(Box::new(Profile1Handler::new()))
        .unwrap();
    let mut initial_compress_buf = [0u8; BENCH_COMPRESS_BUF_SIZE];
    let _initial_len = setup_engine
        .compress(
            0.into(),
            Some(RohcProfile::RtpUdpIp),
            &generic_headers,
            &mut initial_compress_buf,
        )
        .unwrap();

    let mut varied_headers = headers.clone();
    group.bench_function("compress_subsequent_packet", |b| {
        let mut iter_compress_buf = [0u8; BENCH_COMPRESS_BUF_SIZE];
        b.iter(|| {
            varied_headers.rtp_sequence_number = varied_headers.rtp_sequence_number.wrapping_add(1);
            varied_headers.rtp_timestamp =
                Timestamp::new(varied_headers.rtp_timestamp.value().wrapping_add(160));
            let generic = GenericUncompressedHeaders::RtpUdpIpv4(varied_headers.clone());
            setup_engine.compress(
                black_box(0.into()),
                None,
                black_box(&generic),
                black_box(&mut iter_compress_buf),
            )
        })
    });

    group.finish();
}

fn bench_decompression_pipeline(c: &mut Criterion) {
    let mut group = c.benchmark_group("decompression_pipeline");

    // Setup compression context first
    let mut compress_engine = RohcEngine::new(20, Duration::from_secs(300), Arc::new(SystemClock));
    compress_engine
        .register_profile_handler(Box::new(Profile1Handler::new()))
        .unwrap();

    let headers = create_test_headers();
    let generic_headers = GenericUncompressedHeaders::RtpUdpIpv4(headers.clone());
    let mut compress_buf = [0u8; BENCH_COMPRESS_BUF_SIZE];

    // Create different packet types
    let ir_packet_len = compress_engine
        .compress(
            0.into(),
            Some(RohcProfile::RtpUdpIp),
            &generic_headers,
            &mut compress_buf,
        )
        .unwrap();
    let ir_packet = compress_buf[..ir_packet_len].to_vec();

    let mut subsequent_headers = headers.clone();
    subsequent_headers.rtp_sequence_number += 1;
    // Use changing timestamp to create UO-1 packet (proper RTP stream)
    subsequent_headers.rtp_timestamp =
        Timestamp::new(subsequent_headers.rtp_timestamp.value() + 160);
    let generic_subsequent = GenericUncompressedHeaders::RtpUdpIpv4(subsequent_headers);
    let uo_packet_len = compress_engine
        .compress(0.into(), None, &generic_subsequent, &mut compress_buf)
        .unwrap();
    let uo_packet = compress_buf[..uo_packet_len].to_vec();

    group.bench_function("decompress_ir_packet", |b| {
        b.iter_batched(
            || {
                let mut engine =
                    RohcEngine::new(20, Duration::from_secs(300), Arc::new(SystemClock));
                engine
                    .register_profile_handler(Box::new(Profile1Handler::new()))
                    .unwrap();
                (engine, ir_packet.clone())
            },
            |(mut engine, packet_data)| engine.decompress(black_box(&packet_data)),
            criterion::BatchSize::SmallInput,
        )
    });

    // Setup decompression context
    let mut decompress_engine =
        RohcEngine::new(20, Duration::from_secs(300), Arc::new(SystemClock));
    decompress_engine
        .register_profile_handler(Box::new(Profile1Handler::new()))
        .unwrap();
    let _setup = decompress_engine.decompress(&ir_packet).unwrap();

    group.bench_function("decompress_uo_packet", |b| {
        b.iter(|| decompress_engine.decompress(black_box(&uo_packet)))
    });

    group.finish();
}

fn bench_full_roundtrip(c: &mut Criterion) {
    let mut group = c.benchmark_group("full_roundtrip");

    let base_headers = create_test_headers();

    group.bench_function("compress_decompress_roundtrip", |b| {
        b.iter_batched(
            || {
                // Setup fresh engines for each iteration
                let mut compress_engine =
                    RohcEngine::new(20, Duration::from_secs(300), Arc::new(SystemClock));
                compress_engine
                    .register_profile_handler(Box::new(Profile1Handler::new()))
                    .unwrap();

                let mut decompress_engine =
                    RohcEngine::new(20, Duration::from_secs(300), Arc::new(SystemClock));
                decompress_engine
                    .register_profile_handler(Box::new(Profile1Handler::new()))
                    .unwrap();

                // Establish context with initial packet
                let initial_headers = GenericUncompressedHeaders::RtpUdpIpv4(base_headers.clone());
                let mut initial_compress_buf = [0u8; BENCH_COMPRESS_BUF_SIZE];
                let initial_compressed_len = compress_engine
                    .compress(
                        0.into(),
                        Some(RohcProfile::RtpUdpIp),
                        &initial_headers,
                        &mut initial_compress_buf,
                    )
                    .unwrap();
                let _initial_decompressed = decompress_engine
                    .decompress(&initial_compress_buf[..initial_compressed_len])
                    .unwrap();

                // Create next packet for benchmarking - use proper RTP stream progression
                let mut next_headers = base_headers.clone();
                next_headers.rtp_sequence_number = next_headers.rtp_sequence_number.wrapping_add(1);
                next_headers.rtp_timestamp =
                    Timestamp::new(next_headers.rtp_timestamp.value().wrapping_add(160)); // Proper 160-sample stride for audio

                (
                    compress_engine,
                    decompress_engine,
                    GenericUncompressedHeaders::RtpUdpIpv4(next_headers),
                    [0u8; BENCH_COMPRESS_BUF_SIZE],
                )
            },
            |(
                mut compress_engine,
                mut decompress_engine,
                generic_headers,
                mut iter_compress_buf,
            )| {
                let compressed_len = compress_engine
                    .compress(
                        black_box(0.into()),
                        None, // No profile hint needed since context exists
                        black_box(&generic_headers),
                        black_box(&mut iter_compress_buf),
                    )
                    .unwrap();

                decompress_engine
                    .decompress(black_box(&iter_compress_buf[..compressed_len]))
                    .unwrap()
            },
            criterion::BatchSize::SmallInput,
        )
    });

    group.finish();
}

fn bench_context_management(c: &mut Criterion) {
    let mut group = c.benchmark_group("context_management");

    let headers = create_test_headers();
    let generic_headers = GenericUncompressedHeaders::RtpUdpIpv4(headers.clone());

    // Benchmark creating many contexts
    group.bench_function("create_multiple_contexts", |b| {
        b.iter_batched(
            || {
                let mut engine =
                    RohcEngine::new(20, Duration::from_secs(300), Arc::new(SystemClock));
                engine
                    .register_profile_handler(Box::new(Profile1Handler::new()))
                    .unwrap();
                (engine, [0u8; BENCH_COMPRESS_BUF_SIZE])
            },
            |(mut engine, mut iter_compress_buf)| {
                for cid in 0..100u16 {
                    let _ = engine.compress(
                        black_box(cid.into()),
                        Some(RohcProfile::RtpUdpIp),
                        black_box(&generic_headers),
                        black_box(&mut iter_compress_buf),
                    );
                }
            },
            criterion::BatchSize::SmallInput,
        )
    });

    // Setup contexts for lookup benchmark
    let mut setup_engine_for_lookup =
        RohcEngine::new(20, Duration::from_secs(300), Arc::new(SystemClock));
    setup_engine_for_lookup
        .register_profile_handler(Box::new(Profile1Handler::new()))
        .unwrap();
    let mut setup_compress_buf = [0u8; BENCH_COMPRESS_BUF_SIZE];
    for cid in 0..100u16 {
        let _ = setup_engine_for_lookup.compress(
            cid.into(),
            Some(RohcProfile::RtpUdpIp),
            &generic_headers,
            &mut setup_compress_buf,
        );
    }

    group.bench_function("context_lookup_existing", |b| {
        let mut iter_compress_buf = [0u8; BENCH_COMPRESS_BUF_SIZE];
        b.iter(|| {
            let cid = black_box(50u16);
            let mut varied_headers = headers.clone();
            varied_headers.rtp_sequence_number = varied_headers.rtp_sequence_number.wrapping_add(1);
            let generic = GenericUncompressedHeaders::RtpUdpIpv4(varied_headers);
            setup_engine_for_lookup.compress(
                cid.into(),
                None,
                black_box(&generic),
                black_box(&mut iter_compress_buf),
            )
        })
    });

    group.finish();
}

fn bench_memory_patterns(c: &mut Criterion) {
    let mut group = c.benchmark_group("memory_patterns");

    let base_headers = create_test_headers();

    // Benchmark memory allocation patterns during compression
    group.bench_function("compression_allocations", |b| {
        b.iter_batched(
            || {
                let mut engine =
                    RohcEngine::new(20, Duration::from_secs(300), Arc::new(SystemClock));
                engine
                    .register_profile_handler(Box::new(Profile1Handler::new()))
                    .unwrap();
                (engine, [0u8; BENCH_COMPRESS_BUF_SIZE])
            },
            |(mut engine, mut iter_compress_buf)| {
                // Measure allocation overhead by compressing many packets
                for i in 0..50 {
                    let mut headers = base_headers.clone();
                    headers.rtp_sequence_number = headers.rtp_sequence_number.wrapping_add(i);
                    headers.rtp_timestamp =
                        Timestamp::new(headers.rtp_timestamp.value().wrapping_add(i as u32 * 160));
                    let generic = GenericUncompressedHeaders::RtpUdpIpv4(headers);

                    let _compressed_len = engine
                        .compress(
                            black_box(0.into()),
                            if i == 0 {
                                Some(RohcProfile::RtpUdpIp)
                            } else {
                                None
                            },
                            black_box(&generic),
                            black_box(&mut iter_compress_buf),
                        )
                        .unwrap();
                }
            },
            criterion::BatchSize::SmallInput,
        )
    });

    // Benchmark buffer reuse patterns
    group.bench_function("buffer_reuse_pattern", |b| {
        b.iter_batched(
            || {
                let mut engine =
                    RohcEngine::new(20, Duration::from_secs(300), Arc::new(SystemClock));
                engine
                    .register_profile_handler(Box::new(Profile1Handler::new()))
                    .unwrap();
                let mut buffers = Vec::with_capacity(10);
                for _ in 0..10 {
                    buffers.push(Vec::with_capacity(100)); // Pre-allocated buffers
                }
                (engine, buffers, [0u8; BENCH_COMPRESS_BUF_SIZE])
            },
            |(mut engine, mut buffers, mut iter_compress_buf)| {
                // Simulate reusing buffers instead of allocating new ones
                for i in 0..10 {
                    let mut headers = base_headers.clone();
                    headers.rtp_sequence_number = headers.rtp_sequence_number.wrapping_add(i);
                    let generic = GenericUncompressedHeaders::RtpUdpIpv4(headers);

                    let compressed_len = engine
                        .compress(
                            black_box(0.into()),
                            if i == 0 {
                                Some(RohcProfile::RtpUdpIp)
                            } else {
                                None
                            },
                            black_box(&generic),
                            black_box(&mut iter_compress_buf),
                        )
                        .unwrap();

                    // Simulate copying to pre-allocated buffer
                    buffers[i as usize].clear();
                    buffers[i as usize].extend_from_slice(&iter_compress_buf[..compressed_len]);
                }
            },
            criterion::BatchSize::SmallInput,
        )
    });

    group.finish();
}

fn bench_burst_processing(c: &mut Criterion) {
    let mut group = c.benchmark_group("burst_processing");

    // Generate burst of test packets with consistent stride for first few packets
    let packet_burst: Vec<RtpUdpIpv4Headers> = (0..1000)
        .map(|i| {
            let mut headers = create_test_headers();
            headers.rtp_sequence_number = headers.rtp_sequence_number.wrapping_add(i);
            // Use consistent 160-sample stride for proper stride establishment
            headers.rtp_timestamp =
                Timestamp::new(headers.rtp_timestamp.value().wrapping_add(i as u32 * 160));
            // Keep marker bit false for first several packets to establish stride
            headers.rtp_marker = i > 10 && (i % 50) == 0;
            headers
        })
        .collect();

    group.throughput(Throughput::Elements(packet_burst.len() as u64));

    // Benchmark burst compression
    group.bench_function("compress_packet_burst", |b| {
        b.iter_batched(
            || {
                let mut engine =
                    RohcEngine::new(20, Duration::from_secs(300), Arc::new(SystemClock));
                engine
                    .register_profile_handler(Box::new(Profile1Handler::new()))
                    .unwrap();
                (engine, [0u8; BENCH_COMPRESS_BUF_SIZE])
            },
            |(mut engine, mut iter_compress_buf)| {
                let mut compressed_packets = Vec::with_capacity(packet_burst.len());

                for (i, headers) in packet_burst.iter().take(100).enumerate() {
                    let generic = GenericUncompressedHeaders::RtpUdpIpv4(headers.clone());
                    // Use profile hint for first packet and periodically for IR refresh
                    let profile_hint = if i == 0 || i % 20 == 0 {
                        Some(RohcProfile::RtpUdpIp)
                    } else {
                        None
                    };
                    let compressed_len = engine
                        .compress(
                            black_box(0.into()),
                            profile_hint,
                            black_box(&generic),
                            black_box(&mut iter_compress_buf),
                        )
                        .unwrap();
                    compressed_packets.push(iter_compress_buf[..compressed_len].to_vec());
                }

                black_box(compressed_packets);
            },
            criterion::BatchSize::SmallInput,
        )
    });

    // Benchmark burst decompression
    group.bench_function("decompress_packet_burst", |b| {
        // Pre-generate compressed packets for decompression
        let (compressed_packets, original_headers): (Vec<Vec<u8>>, Vec<RtpUdpIpv4Headers>) = {
            let mut engine = RohcEngine::new(20, Duration::from_secs(300), Arc::new(SystemClock));
            engine
                .register_profile_handler(Box::new(Profile1Handler::new()))
                .unwrap();

            let mut packets = Vec::with_capacity(packet_burst.len());
            let mut headers = Vec::with_capacity(packet_burst.len());

            for (i, hdrs) in packet_burst.iter().take(100).enumerate() {
                let mut compress_buf = [0u8; BENCH_COMPRESS_BUF_SIZE];
                let generic = GenericUncompressedHeaders::RtpUdpIpv4(hdrs.clone());

                // Use profile hint for first packet and periodically for IR refresh
                let profile_hint = if i == 0 || i % 20 == 0 {
                    Some(RohcProfile::RtpUdpIp)
                } else {
                    None
                };

                let len = engine
                    .compress(0.into(), profile_hint, &generic, &mut compress_buf)
                    .unwrap();

                packets.push(compress_buf[..len].to_vec());
                headers.push(hdrs.clone());
            }

            (packets, headers)
        };

        b.iter_batched(
            || {
                // Create a new engine for this iteration
                let mut engine =
                    RohcEngine::new(20, Duration::from_secs(300), Arc::new(SystemClock));
                engine
                    .register_profile_handler(Box::new(Profile1Handler::new()))
                    .unwrap();

                // Clone the compressed packets for this iteration
                (
                    engine,
                    compressed_packets.clone(),
                    original_headers[0].clone(),
                )
            },
            |(mut engine, compressed_packets, first_header)| {
                // First, process the first packet to establish context
                let first_compressed = &compressed_packets[0];
                let _ = engine.decompress(black_box(first_compressed)).unwrap();

                // Now process all packets
                let mut decompressed_packets = Vec::with_capacity(compressed_packets.len());

                for compressed in compressed_packets {
                    match engine.decompress(black_box(&compressed)) {
                        Ok(GenericUncompressedHeaders::RtpUdpIpv4(headers)) => {
                            decompressed_packets.push(headers);
                        }
                        _ => {
                            // If decompression fails or returns unexpected type, use the original header
                            decompressed_packets.push(first_header.clone());
                        }
                    }
                }

                black_box(decompressed_packets);
            },
            criterion::BatchSize::SmallInput,
        )
    });

    // Benchmark full roundtrip burst
    group.bench_function("roundtrip_packet_burst", |b| {
        b.iter_batched(
            || {
                // Create engines
                let mut comp_engine =
                    RohcEngine::new(20, Duration::from_secs(300), Arc::new(SystemClock));
                comp_engine
                    .register_profile_handler(Box::new(Profile1Handler::new()))
                    .unwrap();
                let mut decomp_engine =
                    RohcEngine::new(20, Duration::from_secs(300), Arc::new(SystemClock));
                decomp_engine
                    .register_profile_handler(Box::new(Profile1Handler::new()))
                    .unwrap();

                // Pre-process first packet to establish context
                let first_headers = &packet_burst[0];
                let first_generic = GenericUncompressedHeaders::RtpUdpIpv4(first_headers.clone());
                let mut compress_buf = [0u8; BENCH_COMPRESS_BUF_SIZE];

                // Compress first packet with IR
                let compressed_len = comp_engine
                    .compress(
                        0.into(),
                        Some(RohcProfile::RtpUdpIp),
                        &first_generic,
                        &mut compress_buf,
                    )
                    .unwrap();

                // Decompress first packet to establish context
                let _ = decomp_engine
                    .decompress(&compress_buf[..compressed_len])
                    .unwrap();

                (comp_engine, decomp_engine, compress_buf)
            },
            |(mut comp_engine, mut decomp_engine, mut compress_buf)| {
                let mut results = Vec::with_capacity(100); // Process first 100 packets for reasonable benchmark time

                // Process packets starting from second packet (first already processed in setup)
                for (i, headers) in packet_burst.iter().skip(1).take(99).enumerate() {
                    let generic = GenericUncompressedHeaders::RtpUdpIpv4(headers.clone());

                    // Use profile hint periodically for IR refresh (first packet already processed)
                    let profile_hint = if (i + 1) % 20 == 0 {
                        Some(RohcProfile::RtpUdpIp)
                    } else {
                        None
                    };

                    // Compress the packet
                    let compressed_len = comp_engine
                        .compress(
                            black_box(0.into()),
                            profile_hint,
                            black_box(&generic),
                            black_box(&mut compress_buf),
                        )
                        .unwrap();

                    // Decompress the packet
                    let decompressed = decomp_engine
                        .decompress(black_box(&compress_buf[..compressed_len]))
                        .unwrap();

                    results.push(decompressed);
                }

                black_box(results);
            },
            criterion::BatchSize::SmallInput,
        )
    });

    group.finish();
}

fn bench_concurrent_contexts(c: &mut Criterion) {
    let mut group = c.benchmark_group("concurrent_contexts");

    let base_headers = create_test_headers();

    // Benchmark context creation overhead with increasing number of contexts (limited to CID 0-15)
    for num_contexts in [1, 5, 10, 15] {
        group.bench_with_input(
            BenchmarkId::new("context_creation_scaling", num_contexts),
            &num_contexts,
            |b, &num_contexts| {
                b.iter_batched(
                    || {
                        let mut engine =
                            RohcEngine::new(20, Duration::from_secs(300), Arc::new(SystemClock));
                        engine
                            .register_profile_handler(Box::new(Profile1Handler::new()))
                            .unwrap();
                        (engine, [0u8; BENCH_COMPRESS_BUF_SIZE])
                    },
                    |(mut engine, mut iter_compress_buf)| {
                        // Create contexts for different CIDs (simulates multiple streams/users)
                        // Note: CIDs must be 0-15 for Add-CID packet format
                        for cid in 0..num_contexts.min(16) {
                            let mut headers = base_headers.clone();
                            headers.rtp_sequence_number =
                                headers.rtp_sequence_number.wrapping_add(cid as u16);
                            headers.rtp_timestamp = Timestamp::new(
                                headers.rtp_timestamp.value().wrapping_add(cid as u32 * 160),
                            );

                            let generic = GenericUncompressedHeaders::RtpUdpIpv4(headers);

                            // First packet for each context - measures context creation overhead
                            let _compressed_len = engine
                                .compress(
                                    black_box((cid as u16).into()),
                                    Some(RohcProfile::RtpUdpIp),
                                    black_box(&generic),
                                    black_box(&mut iter_compress_buf),
                                )
                                .unwrap();
                        }
                    },
                    criterion::BatchSize::SmallInput,
                )
            },
        );
    }

    // Benchmark context lookup performance with pre-existing contexts
    group.bench_function("context_lookup_scaling", |b| {
        b.iter_batched(
            || {
                let mut engine =
                    RohcEngine::new(20, Duration::from_secs(300), Arc::new(SystemClock));
                engine
                    .register_profile_handler(Box::new(Profile1Handler::new()))
                    .unwrap();
                let mut setup_compress_buf = [0u8; BENCH_COMPRESS_BUF_SIZE];

                // Pre-create 16 contexts (CID limit for Add-CID format)
                for cid in 0..16u16 {
                    let mut headers = base_headers.clone();
                    headers.rtp_sequence_number = headers.rtp_sequence_number.wrapping_add(cid);
                    let generic = GenericUncompressedHeaders::RtpUdpIpv4(headers);
                    let _ = engine.compress(
                        cid.into(),
                        Some(RohcProfile::RtpUdpIp),
                        &generic,
                        &mut setup_compress_buf,
                    );
                }
                (engine, [0u8; BENCH_COMPRESS_BUF_SIZE])
            },
            |(mut engine, mut iter_compress_buf)| {
                // Test lookup performance by accessing random contexts
                for i in 0u16..20 {
                    let cid = (i * 7) % 16; // Pseudo-random access pattern within CID limit
                    let mut headers = base_headers.clone();
                    headers.rtp_sequence_number = headers.rtp_sequence_number.wrapping_add(100 + i);
                    headers.rtp_timestamp = Timestamp::new(
                        headers
                            .rtp_timestamp
                            .value()
                            .wrapping_add((100 + i) as u32 * 160),
                    );

                    let generic = GenericUncompressedHeaders::RtpUdpIpv4(headers);

                    // This should use existing context (lookup performance)
                    let _compressed_len = engine.compress(
                        black_box(cid.into()),
                        None, // No profile hint - should use existing context
                        black_box(&generic),
                        black_box(&mut iter_compress_buf),
                    );
                }
            },
            criterion::BatchSize::SmallInput,
        )
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_packet_parsing,
    bench_lsb_operations,
    bench_crc_operations,
    bench_compression_pipeline,
    bench_decompression_pipeline,
    bench_full_roundtrip,
    bench_context_management,
    bench_memory_patterns,
    bench_burst_processing,
    bench_concurrent_contexts
);

criterion_main!(benches);
