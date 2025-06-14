//! Generic protocol header types for ROHC compression.
//!
//! This module contains protocol header structures that are used by multiple
//! ROHC profiles or need to be referenced from generic containers. Profile-specific
//! types that aren't shared should remain in their respective profile modules.

pub mod rtp_udp_ipv4;

pub use rtp_udp_ipv4::RtpUdpIpv4Headers;
