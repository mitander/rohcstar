//! ROHC (Robust Header Compression) profile implementations.
//!
//! This module acts as a container for the implementations of various ROHC
//! profiles. Each supported profile (e.g., Profile 1 for RTP/UDP/IP,
//! Profile 2 for UDP/IP) will have its own submodule here.
//!
//! The ROHC engine will typically use handlers from these profile modules
//! to perform compression and decompression according to the specific
//! rules of each profile.

pub mod profile1;
