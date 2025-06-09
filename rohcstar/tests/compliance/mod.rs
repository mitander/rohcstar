//! RFC 3095 compliance test suite for the `rohcstar` library.
//!
//! This module validates rohcstar's conformance to RFC 3095 packet formats,
//! compression behavior, and state management requirements. Tests are organized
//! by functional area to maintain clarity and enable incremental validation.

// Common test helpers
pub mod common;

// Compliance tests
pub mod context_mgmt;
pub mod ir_packets;
pub mod uo_packets;
