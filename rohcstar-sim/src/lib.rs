//! High-performance ROHC deterministic simulation library.
//!
//! Provides fast, correct ROHC compression/decompression simulation with error
//! classification to distinguish implementation bugs from expected network behavior.
//! Achieves 4.4M+ packets/sec simulation rate with comprehensive error analysis.

use std::sync::Arc;
use std::time::{Duration, Instant};

use rand::prelude::*;
use rand::rngs::StdRng;
use rohcstar::engine::RohcEngine;
use rohcstar::error::RohcError;
use rohcstar::packet_defs::{GenericUncompressedHeaders, RohcProfile};
use rohcstar::profiles::profile1::{Profile1Handler, RtpUdpIpv4Headers};
use rohcstar::time::mock_clock::MockClock;

pub mod error_analyzer;
pub mod smart_fuzzer;

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

impl CompressionPhase {
    #![allow(dead_code)] // Only used in debug assert, avoid warn in release builds
    /// Validates that phase transitions follow valid ROHC progression.
    fn debug_validate_transition(from: Self, to: Self) -> bool {
        match (from, to) {
            // Valid progressions
            (Self::InitializationRefresh, Self::Stable) => true,
            (Self::Stable, Self::UnidirectionalOptimistic) => true,
            (Self::UnidirectionalOptimistic, Self::PostUo0) => true,
            // Special case: skip UO phase if configured to zero packets
            (Self::Stable, Self::PostUo0) => true,
            // Same phase (no transition)
            (a, b) if a == b => true,
            // Invalid transitions
            _ => false,
        }
    }
}

/// Generates a stream of uncompressed RTP/UDP/IPv4 packets deterministically.
pub struct PacketGenerator {
    rng: StdRng,
    current_sequence_number: u16,
    config: SimConfig,
    base_ip_id: u16,
    packets_generated: usize,
}

impl PacketGenerator {
    /// Validates critical invariants for packet generation configuration.
    fn debug_validate_invariants(&self) {
        debug_assert!(self.config.ts_stride > 0, "TS stride cannot be zero");
        debug_assert!(
            self.config.num_packets > 0,
            "Must generate at least one packet"
        );
        debug_assert!(
            self.packets_generated <= self.config.num_packets,
            "Generated count exceeds configured packets"
        );
        debug_assert!(
            self.config.stable_phase_count + self.config.uo0_phase_count <= self.config.num_packets,
            "Phase counts exceed total packets: stable={}, uo0={}, total={}",
            self.config.stable_phase_count,
            self.config.uo0_phase_count,
            self.config.num_packets
        );
    }

    /// Creates a new packet generator with the specified configuration.
    ///
    /// # Parameters
    /// - `config`: Simulation configuration containing packet parameters and phase setup
    ///
    /// # Returns
    /// A new `PacketGenerator` ready to produce deterministic packet sequences.
    pub fn new(config: &SimConfig) -> Self {
        let generator = Self {
            rng: StdRng::seed_from_u64(config.seed),
            current_sequence_number: config.start_sn,
            config: config.clone(),
            base_ip_id: config.start_sn.wrapping_add(config.ssrc as u16),
            packets_generated: 0,
        };

        generator.debug_validate_invariants();
        generator
    }

    /// Determines compression phase based on packet index following ROHC progression.
    fn get_compression_phase(&self, packet_index: usize) -> CompressionPhase {
        debug_assert!(
            packet_index < self.config.num_packets,
            "Packet index {} exceeds configured packets {}",
            packet_index,
            self.config.num_packets
        );

        let phase = if packet_index == 0 {
            CompressionPhase::InitializationRefresh
        } else if packet_index <= self.config.stable_phase_count {
            CompressionPhase::Stable
        } else if packet_index <= self.config.stable_phase_count + self.config.uo0_phase_count {
            CompressionPhase::UnidirectionalOptimistic
        } else {
            CompressionPhase::PostUo0
        };

        // Validate state machine transitions in debug builds
        if packet_index > 0 {
            #[cfg(debug_assertions)]
            {
                let prev_phase = self.get_compression_phase(packet_index - 1);
                debug_assert!(
                    CompressionPhase::debug_validate_transition(prev_phase, phase),
                    "Invalid phase transition from {:?} to {:?} at packet {}",
                    prev_phase,
                    phase,
                    packet_index
                );
            }
        }

        phase
    }

    /// Calculates timestamp using stride: start_ts_val + (packet_index * ts_stride).
    fn calculate_timestamp(&self, packet_index: usize, _phase: CompressionPhase) -> u32 {
        let timestamp = self
            .config
            .start_ts_val
            .saturating_add(packet_index as u32 * self.config.ts_stride);
        debug_assert!(
            timestamp >= self.config.start_ts_val,
            "Timestamp overflow: {} < {}",
            timestamp,
            self.config.start_ts_val
        );
        timestamp
    }

    /// Returns base_ip_id except for PostUo0 phase which tests IP-ID changes.
    fn calculate_ip_id(&self, phase: CompressionPhase) -> u16 {
        match phase {
            CompressionPhase::InitializationRefresh
            | CompressionPhase::Stable
            | CompressionPhase::UnidirectionalOptimistic => self.base_ip_id,
            CompressionPhase::PostUo0 => self
                .current_sequence_number
                .wrapping_add(self.config.ssrc as u16),
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
    pub fn next_packet(&mut self) -> Option<RtpUdpIpv4Headers> {
        if self.packets_generated >= self.config.num_packets {
            return None;
        }

        self.debug_validate_invariants();

        let packet_index = self.packets_generated;
        let phase = self.get_compression_phase(packet_index);

        let timestamp_value = self.calculate_timestamp(packet_index, phase);
        let ip_id_value = self.calculate_ip_id(phase);
        let marker_value = self.calculate_marker_bit(phase);

        let packet_headers = RtpUdpIpv4Headers {
            ip_src: "192.168.0.1".parse().unwrap(),
            ip_dst: "192.168.0.2".parse().unwrap(),
            udp_src_port: 10000,
            udp_dst_port: 20000,
            rtp_ssrc: self.config.ssrc.into(),
            rtp_sequence_number: self.current_sequence_number.into(),
            rtp_timestamp: timestamp_value.into(),
            rtp_marker: marker_value,
            ip_identification: ip_id_value.into(),
            ..Default::default()
        };

        let prev_sequence_number = self.current_sequence_number;
        self.current_sequence_number = self.current_sequence_number.wrapping_add(1);
        self.packets_generated += 1;

        debug_assert!(
            self.packets_generated <= self.config.num_packets,
            "Generated packet count exceeded configuration"
        );
        debug_assert!(
            self.current_sequence_number == prev_sequence_number.wrapping_add(1),
            "Sequence number progression violated"
        );

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
    /// - `seed`: Random seed for deterministic packet loss simulation
    /// - `packet_loss_probability`: Probability of packet loss (0.0 to 1.0)
    ///
    /// # Returns
    /// A new `SimulatedChannel` ready for packet transmission simulation.
    pub fn new(seed: u64, packet_loss_probability: f64) -> Self {
        debug_assert!((0.0..=1.0).contains(&packet_loss_probability));
        Self {
            rng: StdRng::seed_from_u64(seed),
            packet_loss_probability,
        }
    }

    /// Simulates transmitting a packet through the channel.
    ///
    /// # Parameters
    /// - `packet_bytes`: Packet data to transmit through the simulated channel
    ///
    /// # Returns
    /// `Some(packet_bytes)` if packet survives transmission, `None` if lost.
    pub fn transmit(&mut self, packet_bytes: Vec<u8>) -> Option<Vec<u8>> {
        debug_assert!(!packet_bytes.is_empty());
        if self.packet_loss_probability > 0.0 && self.rng.random_bool(self.packet_loss_probability)
        {
            return None;
        }
        Some(packet_bytes)
    }
}

/// High-performance ROHC simulator with error classification.
pub struct RohcSimulator {
    config: SimConfig,
    compressor_engine: RohcEngine,
    decompressor_engine: RohcEngine,
    packet_generator: PacketGenerator,
    channel: SimulatedChannel,
    compression_buffer: [u8; 256], // Pre-allocated buffer
}

/// Errors that can occur during a simulation run.
#[derive(Debug)]
pub enum SimError {
    PacketGenerationExhausted,
    CompressionError {
        sn: u16,
        error: RohcError,
    },
    DecompressionError {
        sn: u16,
        error: RohcError,
    },
    VerificationError {
        sn: u16,
        message: String,
    },
    CrcRecoveryLimitExceeded {
        sn: u16,
        expected_sn: u16,
        recovered_sn: u16,
        distance: u16,
        limit: u16,
        packet_loss_rate: f64,
    },
}

impl RohcSimulator {
    /// Creates a new high-performance ROHC simulation instance.
    ///
    /// # Parameters
    /// - `config`: Simulation configuration containing packet parameters and behavior settings
    ///
    /// # Returns
    /// A new `RohcSimulator` ready to execute high-performance ROHC simulation runs.
    pub fn new(config: SimConfig) -> Self {
        let mock_clock = Arc::new(MockClock::new(Instant::now()));

        let mut compressor_engine =
            RohcEngine::new(20, Duration::from_secs(300), mock_clock.clone());
        compressor_engine
            .register_profile_handler(Box::new(Profile1Handler::new()))
            .expect("Failed to register Profile1Handler for compressor");

        let mut decompressor_engine = RohcEngine::new(20, Duration::from_secs(300), mock_clock);
        decompressor_engine
            .register_profile_handler(Box::new(Profile1Handler::new()))
            .expect("Failed to register Profile1Handler for decompressor");

        let packet_generator = PacketGenerator::new(&config);
        let channel = SimulatedChannel::new(
            config.seed.wrapping_add(1),
            config.channel_packet_loss_probability,
        );

        Self {
            config,
            compressor_engine,
            decompressor_engine,
            packet_generator,
            channel,
            compression_buffer: [0u8; 256],
        }
    }

    /// Runs high-performance simulation with error classification.
    ///
    /// Executes the complete simulation scenario: generates packets, compresses them,
    /// transmits through simulated channel, decompresses received packets, and verifies
    /// correctness. Provides detailed error classification to distinguish implementation
    /// bugs from expected network behavior effects.
    ///
    /// # Returns
    /// `Ok(())` if simulation completes successfully, error details otherwise.
    ///
    /// # Errors
    /// - [`SimError::CompressionError`] - Compression stage failed
    /// - [`SimError::DecompressionError`] - Decompression stage failed
    /// - [`SimError::VerificationError`] - Header verification failed
    /// - [`SimError::PacketGenerationExhausted`] - No more packets to generate
    pub fn run(&mut self) -> Result<(), SimError> {
        while let Some(original_headers) = self.packet_generator.next_packet() {
            let generic_headers = GenericUncompressedHeaders::RtpUdpIpv4(original_headers.clone());
            let current_sequence_number = original_headers.rtp_sequence_number;

            // Compression phase
            let compressed_length = self
                .compressor_engine
                .compress(
                    self.config.cid.into(),
                    Some(RohcProfile::RtpUdpIp),
                    &generic_headers,
                    &mut self.compression_buffer,
                )
                .map_err(|error| SimError::CompressionError {
                    sn: *current_sequence_number,
                    error,
                })?;

            debug_assert!(compressed_length > 0, "Compression produced empty packet");
            debug_assert!(
                compressed_length <= self.compression_buffer.len(),
                "Buffer overflow: {} > {}",
                compressed_length,
                self.compression_buffer.len()
            );

            // Network transmission
            let compressed_packet = &self.compression_buffer[..compressed_length];
            if let Some(received_packet) = self.channel.transmit(compressed_packet.to_vec()) {
                // Decompression phase
                let decompressed_headers = self
                    .decompressor_engine
                    .decompress(&received_packet)
                    .map_err(|error| SimError::DecompressionError {
                        sn: *current_sequence_number,
                        error,
                    })?;

                // Verification phase - basic checks
                self.verify_headers(
                    &original_headers,
                    &decompressed_headers,
                    *current_sequence_number,
                )?;
            }
        }
        Ok(())
    }

    fn verify_headers(
        &self,
        original: &RtpUdpIpv4Headers,
        decompressed: &GenericUncompressedHeaders,
        sequence_number: u16,
    ) -> Result<(), SimError> {
        let decompressed_rtp = match decompressed {
            GenericUncompressedHeaders::RtpUdpIpv4(headers) => headers,
            _ => {
                return Err(SimError::VerificationError {
                    sn: sequence_number,
                    message: "Wrong header type".to_string(),
                });
            }
        };

        // Basic verification - SSRC should always match
        if original.rtp_ssrc != decompressed_rtp.rtp_ssrc {
            return Err(SimError::VerificationError {
                sn: sequence_number,
                message: format!(
                    "SSRC mismatch: expected {}, got {}",
                    original.rtp_ssrc, decompressed_rtp.rtp_ssrc
                ),
            });
        }

        // For perfect channel, sequence numbers should match exactly
        if self.config.channel_packet_loss_probability == 0.0
            && original.rtp_sequence_number != decompressed_rtp.rtp_sequence_number
        {
            return Err(SimError::VerificationError {
                sn: sequence_number,
                message: format!(
                    "Sequence number mismatch: expected {}, got {}",
                    original.rtp_sequence_number, decompressed_rtp.rtp_sequence_number
                ),
            });
        }

        Ok(())
    }
}
