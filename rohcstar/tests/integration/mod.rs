//! Integration test suite for the `rohcstar` library.
//!
//! This module contains tests that verify the end-to-end behavior and interaction
//! of various components within `rohcstar`, primarily focusing on Profile 1 (RFC 3095)
//! packet processing, state transitions, and compression/decompression flows.
//! Tests are organized by specific aspects of Profile 1 functionality.

// Common test helpers
pub mod common;

// Profile 1 integration tests
pub mod p1_ir_tests;
pub mod p1_umode_flow_tests;
pub mod p1_uo0_tests;
pub mod p1_uo1_id_tests;
pub mod p1_uo1_rtp_tests;
pub mod p1_uo1_sn_tests;
pub mod p1_uo1_ts_tests;
