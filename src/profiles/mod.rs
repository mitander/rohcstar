//! ROHC profile implementations.
//!
//! This module contains implementations of different ROHC profiles, each handling
//! compression and decompression for specific protocol stacks:
//!
//! - **Profile 0**: Uncompressed passthrough (planned)
//! - **Profile 1**: RTP/UDP/IP compression (RFC 3095) - Currently implemented
//! - **Profile 2**: UDP/IP compression (planned)
//! - **Profile 3**: IP-only compression (planned)
//! - **Profile 6**: TCP/IP compression (RFC 6846) (planned)
//!
//! Each profile is implemented as a separate handler that implements the
//! [`ProfileHandler`] trait, providing a uniform interface for the ROHC engine.

pub mod p1_handler;
