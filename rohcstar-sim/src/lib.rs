//! Core library for the Rohcstar Deterministic Simulator.
//!
//! This library provides the main components for running deterministic simulations,
//! including configuration, packet generation, a simulated channel, and the
//! simulator orchestration logic. The actual ROHC functionality is provided by
//! the `rohcstar` crate.

// Allow dead_code for initial setup, as some components will be expanded later.
#![allow(dead_code)]

use rohcstar::engine::RohcEngine;
use rohcstar::error::RohcError;
use rohcstar::packet_defs::{GenericUncompressedHeaders, RohcProfile};
use rohcstar::profiles::profile1::{Profile1Handler, RtpUdpIpv4Headers, Timestamp};
use rohcstar::time::mock_clock::MockClock;

use rand::prelude::*;
use rand::rngs::StdRng;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Configuration for a simulation scenario.
#[derive(Debug, Clone)]
pub struct SimConfig {
    pub seed: u64,
    pub num_packets: usize,
    pub start_sn: u16,
    pub start_ts_val: u32,
    pub ts_stride: u32,
    pub ssrc: u32,
    pub cid: u16,
    pub marker_probability: f64,
    pub channel_packet_loss_probability: f64,
    pub stable_phase_count: usize,
    pub uo0_phase_count: usize,
}

impl Default for SimConfig {
    fn default() -> Self {
        Self {
            seed: 0,
            num_packets: 20,
            start_sn: 1,
            start_ts_val: 1000,
            ts_stride: 160,
            ssrc: 0x12345678,
            cid: 0,
            marker_probability: 0.0,
            channel_packet_loss_probability: 0.0,
            stable_phase_count: 4,
            uo0_phase_count: 5,
        }
    }
}

/// Compression phase that a packet belongs to during ROHC simulation.
#[derive(Debug, Clone, Copy, PartialEq)]
enum CompressionPhase {
    /// Initial packet (IR - Initialization and Refresh)
    InitializationRefresh,
    /// Stable phase after IR with regular timestamp progression
    Stable,
    /// UO-0 phase with potentially different compression behavior
    UnidirectionalOptimistic,
    /// Post-UO-0 phase returning to normal progression
    PostUo0,
}

/// Generates a stream of uncompressed RTP/UDP/IPv4 packets deterministically.
pub struct PacketGenerator {
    rng: StdRng,
    current_sn: u16,
    config: SimConfig,
    base_ip_id: u16,
    packets_generated: usize,
}

impl PacketGenerator {
    /// Creates a new packet generator with the specified configuration.
    ///
    /// # Parameters
    /// - `config`: Simulation configuration containing packet parameters
    ///
    /// # Returns
    /// A new `PacketGenerator` instance ready to generate packets.
    pub fn new(config: &SimConfig) -> Self {
        Self {
            rng: StdRng::seed_from_u64(config.seed),
            current_sn: config.start_sn,
            config: config.clone(),
            base_ip_id: config.start_sn.wrapping_add(config.ssrc as u16),
            packets_generated: 0,
        }
    }

    /// Determines compression phase based on packet index following ROHC progression.
    fn get_compression_phase(&self, packet_index: usize) -> CompressionPhase {
        if packet_index == 0 {
            CompressionPhase::InitializationRefresh
        } else if packet_index <= self.config.stable_phase_count {
            CompressionPhase::Stable
        } else if packet_index <= self.config.stable_phase_count + self.config.uo0_phase_count {
            CompressionPhase::UnidirectionalOptimistic
        } else {
            CompressionPhase::PostUo0
        }
    }

    /// Calculates timestamp using stride: start_ts_val + (packet_index * ts_stride).
    fn calculate_timestamp(&self, packet_index: usize, _phase: CompressionPhase) -> u32 {
        self.config.start_ts_val + (packet_index as u32 * self.config.ts_stride)
    }

    /// Returns base_ip_id except for PostUo0 phase which tests IP-ID changes.
    fn calculate_ip_id(&self, phase: CompressionPhase) -> u16 {
        match phase {
            CompressionPhase::InitializationRefresh
            | CompressionPhase::Stable
            | CompressionPhase::UnidirectionalOptimistic => self.base_ip_id,
            CompressionPhase::PostUo0 => self.current_sn.wrapping_add(self.config.ssrc as u16),
        }
    }

    /// Returns random marker bit in PostUo0 phase, false otherwise.
    fn calculate_marker_bit(&mut self, phase: CompressionPhase) -> bool {
        if self.config.marker_probability == 0.0 {
            return false;
        }

        match phase {
            CompressionPhase::InitializationRefresh
            | CompressionPhase::Stable
            | CompressionPhase::UnidirectionalOptimistic => false,
            CompressionPhase::PostUo0 => self.rng.random_bool(self.config.marker_probability),
        }
    }

    /// Generates the next RTP/UDP/IPv4 packet headers in the sequence.
    ///
    /// Updates internal state including sequence numbers, timestamps, and packet counters.
    /// Returns `None` when the configured number of packets has been generated.
    ///
    /// # Returns
    /// The next packet headers if more packets remain, otherwise `None`.
    pub fn next_packet(&mut self) -> Option<RtpUdpIpv4Headers> {
        if self.packets_generated >= self.config.num_packets {
            return None;
        }

        let packet_index = self.packets_generated;
        let phase = self.get_compression_phase(packet_index);

        let ts_to_use_val = self.calculate_timestamp(packet_index, phase);
        let ip_id_to_use = self.calculate_ip_id(phase);
        let marker_to_use = self.calculate_marker_bit(phase);

        let packet_headers = RtpUdpIpv4Headers {
            ip_src: "192.168.0.1".parse().unwrap(),
            ip_dst: "192.168.0.2".parse().unwrap(),
            udp_src_port: 10000,
            udp_dst_port: 20000,
            rtp_ssrc: self.config.ssrc,
            rtp_sequence_number: self.current_sn,
            rtp_timestamp: Timestamp::new(ts_to_use_val),
            rtp_marker: marker_to_use,
            ip_identification: ip_id_to_use,
            ..Default::default()
        };

        self.current_sn = self.current_sn.wrapping_add(1);
        self.packets_generated += 1;

        Some(packet_headers)
    }
}

/// Represents the simulated network channel.
pub struct SimulatedChannel {
    rng: StdRng,
    packet_loss_probability: f64,
}

impl SimulatedChannel {
    /// Creates a new simulated network channel with packet loss.
    ///
    /// # Parameters
    /// - `seed`: Random seed for reproducible packet loss patterns
    /// - `packet_loss_probability`: Probability of packet loss (0.0 to 1.0)
    ///
    /// # Returns
    /// A new `SimulatedChannel` instance ready to simulate packet transmission.
    pub fn new(seed: u64, packet_loss_probability: f64) -> Self {
        debug_assert!((0.0..=1.0).contains(&packet_loss_probability));
        Self {
            rng: StdRng::seed_from_u64(seed),
            packet_loss_probability,
        }
    }

    /// Simulates transmitting a packet through the channel.
    ///
    /// Randomly drops packets based on the configured loss probability.
    ///
    /// # Parameters
    /// - `packet_bytes`: The packet data to transmit
    ///
    /// # Returns
    /// The packet data if transmission succeeds, `None` if packet is lost.
    pub fn transmit(&mut self, packet_bytes: Vec<u8>) -> Option<Vec<u8>> {
        debug_assert!(!packet_bytes.is_empty());
        if self.packet_loss_probability > 0.0 && self.rng.random_bool(self.packet_loss_probability)
        {
            return None;
        }
        Some(packet_bytes)
    }
}

/// Orchestrates a single deterministic simulation run.
pub struct RohcSimulator {
    config: SimConfig,
    mock_clock: Arc<MockClock>,
    compressor_engine: RohcEngine,
    decompressor_engine: RohcEngine,
    packet_generator: PacketGenerator,
    channel: SimulatedChannel,
}

/// Errors that can occur during a simulation run.
#[derive(Debug)]
pub enum SimError {
    PacketGenerationExhausted,
    CompressionError { sn: u16, error: RohcError },
    DecompressionError { sn: u16, error: RohcError },
    VerificationError { sn: u16, message: String },
}

impl RohcSimulator {
    /// Creates a new ROHC simulation instance.
    ///
    /// Initializes the compressor and decompressor engines, packet generator,
    /// and simulated network channel based on the provided configuration.
    ///
    /// # Parameters
    /// - `config`: Complete simulation configuration
    ///
    /// # Returns
    /// A new `RohcSimulator` ready to run the simulation.
    pub fn new(config: SimConfig) -> Self {
        let initial_time = Instant::now();
        let clock_seed_offset = config.seed;
        let mock_clock = Arc::new(MockClock::new(
            initial_time
                .checked_add(Duration::from_nanos(clock_seed_offset))
                .unwrap_or(initial_time),
        ));

        let default_ir_refresh_interval = 20;
        let default_context_timeout = Duration::from_secs(300);

        let mut compressor_engine = RohcEngine::new(
            default_ir_refresh_interval,
            default_context_timeout,
            mock_clock.clone(),
        );
        compressor_engine
            .register_profile_handler(Box::new(Profile1Handler::new()))
            .expect("Failed to register Profile1Handler for compressor engine in simulator.");

        let mut decompressor_engine = RohcEngine::new(
            default_ir_refresh_interval,
            default_context_timeout,
            mock_clock.clone(),
        );
        decompressor_engine
            .register_profile_handler(Box::new(Profile1Handler::new()))
            .expect("Failed to register Profile1Handler for decompressor engine in simulator.");

        let packet_generator = PacketGenerator::new(&config);
        let channel_seed = config.seed.wrapping_add(1);
        let channel = SimulatedChannel::new(channel_seed, config.channel_packet_loss_probability);

        Self {
            config,
            mock_clock,
            compressor_engine,
            decompressor_engine,
            packet_generator,
            channel,
        }
    }

    /// Runs the simulation, processing packets and verifying outcomes.
    ///
    /// Generates packets, compresses them, simulates network transmission with possible
    /// packet loss, decompresses received packets, and verifies correctness.
    ///
    /// # Returns
    /// `()` on successful completion of all configured packets.
    ///
    /// # Errors
    /// - [`SimError::CompressionFailed`] - Packet compression failed
    /// - [`SimError::DecompressionFailed`] - Packet decompression failed
    /// - [`SimError::ValidationFailed`] - Decompressed headers don't match originals
    pub fn run(&mut self) -> Result<(), SimError> {
        for _ in 0..self.config.num_packets {
            let original_headers = self
                .packet_generator
                .next_packet()
                .ok_or(SimError::PacketGenerationExhausted)?;

            let current_sn_being_processed = original_headers.rtp_sequence_number;
            let generic_original_headers =
                GenericUncompressedHeaders::RtpUdpIpv4(original_headers.clone());

            let compressed_bytes = self
                .compressor_engine
                .compress(
                    self.config.cid,
                    Some(RohcProfile::RtpUdpIp),
                    &generic_original_headers,
                )
                .map_err(|e| SimError::CompressionError {
                    sn: current_sn_being_processed,
                    error: e,
                })?;

            debug_assert!(
                !compressed_bytes.is_empty(),
                "SN {}: Compressor produced empty packet.",
                current_sn_being_processed
            );
            self.mock_clock.advance(Duration::from_millis(1));

            if let Some(received_bytes) = self.channel.transmit(compressed_bytes) {
                self.mock_clock.advance(Duration::from_millis(10));

                let decompressed_generic_headers = self
                    .decompressor_engine
                    .decompress(&received_bytes)
                    .map_err(|e| SimError::DecompressionError {
                        sn: current_sn_being_processed,
                        error: e,
                    })?;

                self.mock_clock.advance(Duration::from_millis(1));

                match decompressed_generic_headers {
                    GenericUncompressedHeaders::RtpUdpIpv4(decompressed_headers) => {
                        if decompressed_headers.rtp_ssrc != original_headers.rtp_ssrc {
                            return Err(SimError::VerificationError {
                                sn: current_sn_being_processed,
                                message: format!(
                                    "SSRC mismatch: expected {}, got {}",
                                    original_headers.rtp_ssrc, decompressed_headers.rtp_ssrc
                                ),
                            });
                        }

                        if decompressed_headers.rtp_sequence_number
                            != original_headers.rtp_sequence_number
                        {
                            return Err(SimError::VerificationError {
                                sn: current_sn_being_processed,
                                message: format!(
                                    "SN mismatch: expected {}, got {}",
                                    original_headers.rtp_sequence_number,
                                    decompressed_headers.rtp_sequence_number
                                ),
                            });
                        }

                        if decompressed_headers.rtp_marker != original_headers.rtp_marker {
                            return Err(SimError::VerificationError {
                                sn: current_sn_being_processed,
                                message: format!(
                                    "Marker mismatch: expected {}, got {}",
                                    original_headers.rtp_marker, decompressed_headers.rtp_marker
                                ),
                            });
                        }

                        if decompressed_headers.rtp_timestamp != original_headers.rtp_timestamp {
                            return Err(SimError::VerificationError {
                                sn: current_sn_being_processed,
                                message: format!(
                                    "Timestamp mismatch: expected {:?}, got {:?}",
                                    original_headers.rtp_timestamp,
                                    decompressed_headers.rtp_timestamp
                                ),
                            });
                        }
                    }
                    _ => {
                        return Err(SimError::VerificationError {
                            sn: current_sn_being_processed,
                            message: "Decompressed to unexpected header type".to_string(),
                        });
                    }
                }
            }
        }
        Ok(())
    }
}
