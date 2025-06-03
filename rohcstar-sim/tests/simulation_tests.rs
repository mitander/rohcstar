//! Integration tests for the ROHCStar deterministic simulator.
//!
//! Tests end-to-end simulation including packet generation, ROHC compression/decompression,
//! channel simulation, and verification across various scenarios with perfect channels,
//! packet loss, marker variations, and CID handling.

use rohcstar::profiles::profile1::Timestamp;
use rohcstar_sim::{RohcSimulator, SimConfig, SimError};

#[test]
fn packet_generator_produces_sequence() {
    let sim_config = SimConfig {
        num_packets: 3,
        start_sn: 10,
        start_ts_val: 100,
        ts_stride: 20,
        ssrc: 111,
        stable_phase_count: 1,
        uo0_phase_count: 0,
        ..Default::default()
    };
    let mut generator = rohcstar_sim::PacketGenerator::new(&sim_config);

    let p1 = generator.next_packet().unwrap();
    assert_eq!(p1.rtp_ssrc, 111);
    assert_eq!(p1.rtp_sequence_number, 10);
    assert_eq!(p1.rtp_timestamp, Timestamp::new(100));

    let p2 = generator.next_packet().unwrap();
    assert_eq!(p2.rtp_sequence_number, 11);
    assert_eq!(p2.rtp_timestamp, Timestamp::new(120));

    let p3 = generator.next_packet().unwrap();
    assert_eq!(p3.rtp_sequence_number, 12);
    assert_eq!(p3.rtp_timestamp, Timestamp::new(140));

    assert!(generator.next_packet().is_none());
}

#[test]
fn run_basic_simulation_cid0_perfect_channel() {
    let sim_config_params = SimConfig {
        seed: 42,
        num_packets: 11,
        cid: 0,
        ..Default::default()
    };
    let mut simulator = RohcSimulator::new(sim_config_params);
    let result = simulator.run();
    assert!(result.is_ok(), "Basic CID0 sim failed: {:?}", result.err());
}

#[test]
fn run_basic_simulation_small_cid_perfect_channel() {
    let sim_config_params = SimConfig {
        seed: 123,
        num_packets: 11,
        cid: 5,
        ..Default::default()
    };
    let mut simulator = RohcSimulator::new(sim_config_params);
    let result = simulator.run();
    assert!(
        result.is_ok(),
        "Basic small CID sim failed: {:?}",
        result.err()
    );
}

#[test]
fn run_simulation_with_packet_loss() {
    let sim_config_params = SimConfig {
        seed: 888,
        num_packets: 50,
        marker_probability: 0.1,
        channel_packet_loss_probability: 0.25,
        ssrc: 0x987654FE,
        ..Default::default()
    };
    let mut simulator = RohcSimulator::new(sim_config_params);
    let result = simulator.run();
    match result {
        Ok(_) => {}
        Err(SimError::DecompressionError { .. }) => {}
        Err(SimError::VerificationError { sn: _, ref message })
            if message.contains("Timestamp mismatch")
                || message.contains("SN mismatch")
                || message.contains("Marker mismatch") => {}
        Err(other_err) => panic!("Sim with packet loss failed unexpectedly: {:?}", other_err),
    }
}
