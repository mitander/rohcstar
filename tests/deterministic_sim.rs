//! Deterministic Simulation Framework for ROHCStar.
//!
//! This module provides a framework for running deterministic simulations of ROHC
//! compression and decompression, allowing for reproducible testing of packet sequences
//! and, eventually, simulated network conditions.

// Allow dead_code for initial setup, as some components will be expanded later.
#![allow(dead_code)]

use rohcstar::engine::RohcEngine;
use rohcstar::packet_defs::{GenericUncompressedHeaders, RohcProfile};
use rohcstar::profiles::profile1::{Profile1Handler, RtpUdpIpv4Headers, Timestamp};
use rohcstar::time::mock_clock::MockClock;

use rand::prelude::*;
use rand::rngs::StdRng;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Configuration for a simulation scenario.
#[derive(Debug, Clone)]
struct SimConfig {
    /// Seed for all random number generation to ensure determinism.
    seed: u64,
    /// Number of packets to generate and process in the simulation.
    num_packets: usize,
    /// Starting sequence number for the packet generator.
    start_sn: u16,
    /// Starting timestamp value for the packet generator.
    start_ts_val: u32,
    /// Timestamp stride for the packet generator.
    ts_stride: u32,
    /// SSRC to be used for generated packets.
    ssrc: u32,
    /// Context ID to use for compression/decompression.
    cid: u16,
    // Placeholder for future channel model configuration
    // packet_loss_rate: f64,
    // max_reorder_delay_ticks: u64,
}

impl Default for SimConfig {
    fn default() -> Self {
        Self {
            seed: 0, // Default seed, should be varied for different test runs
            num_packets: 100,
            start_sn: 1,
            start_ts_val: 1000,
            ts_stride: 160, // Common RTP stride for 20ms G.711 frames
            ssrc: 0x12345678,
            cid: 0,
            // packet_loss_rate: 0.0,
            // max_reorder_delay_ticks: 0,
        }
    }
}

/// Generates a stream of uncompressed RTP/UDP/IPv4 packets deterministically.
struct PacketGenerator {
    rng: StdRng, // For any randomization in packet field variations (if added later)
    current_sn: u16,
    current_ts_val: u32,
    config: SimConfig, // Uses parts of SimConfig like start_sn, ts_stride, ssrc
}

impl PacketGenerator {
    /// Creates a new `PacketGenerator`.
    ///
    /// # Parameters
    /// - `config`: The simulation configuration containing generation parameters.
    fn new(config: SimConfig) -> Self {
        Self {
            rng: StdRng::seed_from_u64(config.seed), // Seed the generator's RNG
            current_sn: config.start_sn,
            current_ts_val: config.start_ts_val,
            config,
        }
    }

    /// Generates the next packet in the sequence.
    ///
    /// Currently generates simple RTP/UDP/IPv4 packets with incrementing SN
    /// and TS based on a fixed stride. Marker bit and IP-ID are kept simple.
    ///
    /// # Returns
    /// `Some(RtpUdpIpv4Headers)` if more packets are to be generated, `None` otherwise.
    fn next_packet(&mut self) -> Option<RtpUdpIpv4Headers> {
        let ip_id_base = (self.config.start_sn).wrapping_add(self.config.ssrc as u16);
        let mut ip_id_to_use = ip_id_base;
        let mut ts_to_use_val = self.current_ts_val;
        let mut marker_to_use = false; // Default

        // For packets SN=start_sn+1 to start_sn+4 (i.e., packets 2 through 5 if start_sn=1)
        // let's keep IP-ID and Marker stable to encourage UO-1-TS if TS is striding.
        if self.current_sn > self.config.start_sn && self.current_sn <= self.config.start_sn + 4 {
            ip_id_to_use = ip_id_base; // Keep IP-ID same as first packet
        // TS will naturally stride via self.current_ts_val update later
        }
        // For packets after that, let's try to make UO-0 conditions
        else if self.current_sn > self.config.start_sn + 4 {
            ip_id_to_use = ip_id_base; // Keep IP-ID same for UO-0
            // To make TS same as previous for UO-0, use the TS of what would have been SN start_sn+4
            // TS for start_sn + 4 = start_ts_val + 4 * ts_stride
            ts_to_use_val = self.config.start_ts_val + (4 * self.config.ts_stride);
            marker_to_use = false; // Keep marker same for UO-0
        }

        let packet_headers = RtpUdpIpv4Headers {
            ip_src: "192.168.0.1".parse().unwrap(),
            ip_dst: "192.168.0.2".parse().unwrap(),
            udp_src_port: 10000,
            udp_dst_port: 20000,
            rtp_ssrc: self.config.ssrc,
            rtp_sequence_number: self.current_sn,
            rtp_timestamp: Timestamp::new(ts_to_use_val), // Use controlled TS
            rtp_marker: marker_to_use,                    // Use controlled Marker
            ip_identification: ip_id_to_use,              // Use controlled IP-ID
            ..Default::default()
        };

        // Advance state for the next packet's base values
        self.current_sn = self.current_sn.wrapping_add(1);
        // Only advance current_ts_val if we are not intentionally holding it for UO-0
        if self.current_sn <= self.config.start_sn + 5 {
            // After a few UO-0s, let it stride again or do something else
            self.current_ts_val = self.current_ts_val.wrapping_add(self.config.ts_stride);
        }

        Some(packet_headers)
    }
}

/// Represents the simulated network channel between compressor and decompressor.
/// For now, it's a perfect, lossless, zero-delay channel.
struct SimulatedChannel {
    // TODO: Add fields for rng, loss_model, reorder_buffer, clock, etc.
}

impl SimulatedChannel {
    fn new(/* Placeholder: add seed, clock ref later */) -> Self {
        Self {}
    }

    /// "Transmits" a packet through the channel.
    /// Currently a passthrough; will be enhanced for loss, reordering, corruption.
    ///
    /// # Parameters
    /// - `packet_bytes`: The compressed packet from the compressor.
    ///
    /// # Returns
    /// `Some(Vec<u8>)` containing the packet to be delivered to the decompressor,
    /// or `None` if the packet is "lost".
    fn transmit(&mut self, packet_bytes: Vec<u8>) -> Option<Vec<u8>> {
        // TODO: Implement deterministic loss using self.rng and self.loss_model
        // TODO: Implement deterministic reordering using self.rng, self.clock, and a buffer
        // TODO: Implement deterministic corruption using self.rng
        debug_assert!(
            !packet_bytes.is_empty(),
            "Channel received empty packet for transmission."
        );
        Some(packet_bytes) // Perfect transmission for now
    }
}

/// Orchestrates a single deterministic simulation run.
struct RohcSimulator {
    config: SimConfig,
    mock_clock: Arc<MockClock>,
    compressor_engine: RohcEngine,
    decompressor_engine: RohcEngine,
    packet_generator: PacketGenerator,
    channel: SimulatedChannel,
}

impl RohcSimulator {
    /// Creates a new `RohcSimulator` instance.
    ///
    /// # Parameters
    /// - `config`: The simulation configuration.
    ///
    /// # Panics
    /// Panics if `Profile1Handler` cannot be registered (should not happen in normal operation).
    fn new(config: SimConfig) -> Self {
        let initial_time = Instant::now(); // MockClock will use this as its base for 'seed' if seed is low
        let mock_clock = Arc::new(MockClock::new(
            initial_time
                .checked_add(Duration::from_nanos(config.seed))
                .unwrap_or(initial_time),
        ));

        // IR refresh interval and context timeout for the engines can be configured.
        // Using defaults from RohcEngine for now, or could be part of SimConfig.
        let mut compressor_engine =
            RohcEngine::new(20, Duration::from_secs(300), mock_clock.clone());
        compressor_engine
            .register_profile_handler(Box::new(Profile1Handler::new()))
            .expect("Failed to register Profile1Handler for compressor");

        let mut decompressor_engine =
            RohcEngine::new(20, Duration::from_secs(300), mock_clock.clone());
        decompressor_engine
            .register_profile_handler(Box::new(Profile1Handler::new()))
            .expect("Failed to register Profile1Handler for decompressor");

        let packet_generator = PacketGenerator::new(config.clone());
        let channel = SimulatedChannel::new();

        Self {
            config,
            mock_clock,
            compressor_engine,
            decompressor_engine,
            packet_generator,
            channel,
        }
    }

    /// Runs the simulation scenario.
    ///
    /// Processes a configured number of packets, passing them through compression,
    /// the (currently perfect) channel, and decompression. Asserts that the
    /// decompressed headers match the original headers.
    ///
    /// # Panics
    /// Panics if compression, decompression, or header comparison fails.
    fn run(&mut self) {
        for i in 0..self.config.num_packets {
            // 1. Generate original packet
            let original_headers = self.packet_generator.next_packet().unwrap_or_else(|| {
                panic!(
                    "Packet generator exhausted before num_packets reached at iteration {}",
                    i
                )
            });

            let generic_original_headers =
                GenericUncompressedHeaders::RtpUdpIpv4(original_headers.clone());

            // 2. Compress
            let compressed_bytes = self
                .compressor_engine
                .compress(
                    self.config.cid,
                    Some(RohcProfile::RtpUdpIp),
                    &generic_original_headers,
                )
                .unwrap_or_else(|e| {
                    panic!(
                        "Compression failed for packet {} (SN: {}): {:?}",
                        i, original_headers.rtp_sequence_number, e
                    )
                });

            debug_assert!(
                !compressed_bytes.is_empty(),
                "Compressor produced an empty packet for SN {}.",
                original_headers.rtp_sequence_number
            );

            // 3. Simulate clock tick for processing (optional)
            self.mock_clock.advance(Duration::from_millis(1)); // Simulate 1ms processing

            // 4. Transmit through channel
            let maybe_received_bytes = self.channel.transmit(compressed_bytes);

            // 5. Simulate clock tick for network latency (optional, channel will handle this better later)
            self.mock_clock.advance(Duration::from_millis(1)); // Simulate 10ms network latency

            if let Some(received_bytes) = maybe_received_bytes {
                // 6. Decompress
                if original_headers.rtp_sequence_number == 2 {
                    // Check for the failing packet
                    eprintln!(
                        "SIMULATOR: For SN 2, decompressing packet: {:02X?}",
                        received_bytes
                    );
                    // You can also manually parse received_bytes[1] and received_bytes[2] here
                    // if received_bytes[0] is the UO-1-TS discriminator (0xA4 for CID 0)
                    // to see what TS_LSB was actually sent.
                    if received_bytes[0] == 0xA4 {
                        let ts_lsb_in_packet =
                            u16::from_be_bytes([received_bytes[1], received_bytes[2]]);
                        eprintln!(
                            "SIMULATOR: TS_LSB in packet for SN 2: {:#04x} ({})",
                            ts_lsb_in_packet, ts_lsb_in_packet
                        );
                    }
                }

                let decompressed_generic_headers = self
                    .decompressor_engine
                    .decompress(&received_bytes)
                    .unwrap_or_else(|e| {
                        panic!(
                            "Decompression failed for packet {} (SN: {}), original compressed len {}: {:?}",
                            i, original_headers.rtp_sequence_number, received_bytes.len(), e
                        )
                    });

                // 7. Verify
                match decompressed_generic_headers {
                    GenericUncompressedHeaders::RtpUdpIpv4(decompressed_headers) => {
                        // Compare key fields. Note: Not all fields are preserved/reconstructed by ROHC.
                        assert_eq!(
                            decompressed_headers.rtp_ssrc, original_headers.rtp_ssrc,
                            "SSRC mismatch for SN {}",
                            original_headers.rtp_sequence_number
                        );
                        assert_eq!(
                            decompressed_headers.rtp_sequence_number,
                            original_headers.rtp_sequence_number,
                            "SN mismatch for SN {}",
                            original_headers.rtp_sequence_number
                        );
                        assert_eq!(
                            decompressed_headers.rtp_timestamp, original_headers.rtp_timestamp,
                            "Timestamp mismatch for SN {}",
                            original_headers.rtp_sequence_number
                        );
                        assert_eq!(
                            decompressed_headers.rtp_marker, original_headers.rtp_marker,
                            "Marker mismatch for SN {}",
                            original_headers.rtp_sequence_number
                        );

                        // IP-ID might not be perfectly reconstructed by all UO packets, so this assert
                        // might need to be conditional based on the *expected* ROHC packet type.
                        // For IR and UO-1-ID it should match if LSBs are sufficient. UO-0, UO-1-SN/TS/RTP usually don't carry it.
                        // For now, we only check if an IR was likely sent for the first packet.
                        if i == 0 { // First packet is likely an IR, which carries IP-ID implicitly
                            // The IP-ID in context.last_reconstructed_ip_id_full is often 0 after IR for P1 if not sent in dyn chain.
                            // The original_headers.ip_identification is what we compare against.
                            // But the decompressed_headers.ip_identification might be 0 if IR's static IP-ID setup leads to that.
                            // This assertion needs refinement depending on exact IR IP-ID reconstruction.
                            // For simplicity now, let's assume if it's the first packet and an IR, IP-ID in static chain (from original) is the goal.
                            // However, actual IR dynamic chain doesn't include IP-ID for Profile 1. Decompressor context's IP-ID state after IR needs to be defined.
                            // Typically, decompressor's ip_id reference for LSB decoding might be 0 after IR.
                        }
                    }
                    _ => panic!("Decompressed to unexpected header type for packet {}", i),
                }
            } else {
                // Packet was "lost" by the channel
                println!(
                    "Packet {} (SN: {}) lost in channel.",
                    i, original_headers.rtp_sequence_number
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn run_basic_simulation_cid0_perfect_channel() {
        let config = SimConfig {
            seed: 42,        // Ensure deterministic run
            num_packets: 25, // Includes IR, UO-0, UO-1 types potentially
            cid: 0,
            ..Default::default()
        };
        let mut simulator = RohcSimulator::new(config);
        simulator.run();
    }

    #[test]
    fn run_basic_simulation_small_cid_perfect_channel() {
        let config = SimConfig {
            seed: 123,
            num_packets: 30,
            cid: 5, // Use a small CID that requires Add-CID octet
            ..Default::default()
        };
        let mut simulator = RohcSimulator::new(config);
        simulator.run();
    }

    #[test]
    fn packet_generator_produces_sequence() {
        let config = SimConfig {
            seed: 1,
            num_packets: 3,
            start_sn: 10,
            start_ts_val: 100,
            ts_stride: 20,
            ssrc: 111,
            cid: 0,
        };
        let mut generator = PacketGenerator::new(config);

        let p1 = generator.next_packet().unwrap();
        assert_eq!(p1.rtp_ssrc, 111);
        assert_eq!(p1.rtp_sequence_number, 10);
        assert_eq!(p1.rtp_timestamp, Timestamp::new(100));

        let p2 = generator.next_packet().unwrap();
        assert_eq!(p2.rtp_ssrc, 111);
        assert_eq!(p2.rtp_sequence_number, 11);
        assert_eq!(p2.rtp_timestamp, Timestamp::new(120));

        let p3 = generator.next_packet().unwrap();
        assert_eq!(p3.rtp_ssrc, 111);
        assert_eq!(p3.rtp_sequence_number, 12);
        assert_eq!(p3.rtp_timestamp, Timestamp::new(140));
    }
}
