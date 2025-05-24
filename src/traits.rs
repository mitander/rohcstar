//! Core ROHC (Robust Header Compression) traits.
//!
//! This module defines the essential interfaces for ROHC profile handlers
//! and their associated compressor and decompressor contexts. These traits
//! enable a generic ROHC engine to operate with various compression profiles
//! in a pluggable manner.

use crate::error::RohcError;
use crate::packet_defs::{GenericUncompressedHeaders, RohcProfile};
use std::any::Any;
use std::fmt::Debug;

/// Defines the capabilities of a ROHC compressor context.
///
/// Compressor contexts store the necessary state for a specific ROHC profile
/// to compress a sequence of packets belonging to a single flow.
/// Implementations must be `Send + Sync` to allow for potential concurrent
/// processing of different flows, and `Debug` for easier diagnostics.
pub trait RohcCompressorContext: Send + Sync + Debug {
    /// Returns the ROHC Profile Identifier this context is configured for.
    fn profile_id(&self) -> RohcProfile;

    /// Returns the Context Identifier (CID) uniquely identifying this compression flow.
    fn cid(&self) -> u16;

    /// Provides a reference to the context as `&dyn Any` for downcasting.
    ///
    /// This allows retrieval of the concrete context type when needed,
    /// for example, within a profile-specific handler.
    fn as_any(&self) -> &dyn Any;

    /// Provides a mutable reference to the context as `&mut dyn Any` for downcasting.
    ///
    /// Similar to `as_any`, but allows mutable access to the concrete context type.
    fn as_any_mut(&mut self) -> &mut dyn Any;
}

/// Defines the capabilities of a ROHC decompressor context.
///
/// Decompressor contexts maintain the state required by a specific ROHC profile
/// to decompress a sequence of ROHC packets for a single flow.
/// Implementations must be `Send + Sync` and `Debug`.
pub trait RohcDecompressorContext: Send + Sync + Debug {
    /// Returns the ROHC Profile Identifier this context is configured for.
    fn profile_id(&self) -> RohcProfile;

    /// Returns the Context Identifier (CID) of this decompression flow.
    fn cid(&self) -> u16;

    /// Sets or updates the Context Identifier (CID) for this context.
    ///
    /// This is typically invoked by the ROHC engine when a CID is explicitly
    /// signaled (e.g., via an Add-CID octet) or when associating an existing
    /// context with a new CID if semantics allow.
    fn set_cid(&mut self, cid: u16);

    /// Provides a reference to the context as `&dyn Any` for downcasting.
    fn as_any(&self) -> &dyn Any;

    /// Provides a mutable reference to the context as `&mut dyn Any` for downcasting.
    fn as_any_mut(&mut self) -> &mut dyn Any;
}

/// Defines the interface for a ROHC profile handler.
///
/// Each ROHC profile (e.g., Profile 1 for RTP/UDP/IP, Profile 2 for UDP/IP)
/// implements this trait to provide its specific compression and decompression
/// logic, as well as context management.
/// Implementations must be `Send + Sync` to allow the engine to use them across threads
/// if needed (e.g., one handler instance serving multiple flows of its profile type).
pub trait ProfileHandler: Send + Sync + Debug {
    /// Returns the ROHC Profile Identifier that this handler implements.
    fn profile_id(&self) -> RohcProfile;

    /// Creates a new, profile-specific compressor context.
    ///
    /// The ROHC engine calls this method when a new compression flow is initiated
    /// for this profile.
    ///
    /// # Parameters
    /// - `cid`: The Context Identifier (0-65535) for the new flow.
    /// - `ir_refresh_interval`: The suggested interval (in number of packets)
    ///   between sending IR (Initialization/Refresh) packets. Profiles may
    ///   interpret or use this interval according to their specific needs.
    ///
    /// # Returns
    /// A `Box` containing a new `RohcCompressorContext` for this profile.
    fn create_compressor_context(
        &self,
        cid: u16,
        ir_refresh_interval: u32,
    ) -> Box<dyn RohcCompressorContext>;

    /// Creates a new, profile-specific decompressor context.
    ///
    /// The ROHC engine calls this method when a new decompression flow is
    /// detected (e.g., first packet for a new CID) for this profile.
    ///
    /// # Parameters
    /// - `cid`: The Context Identifier (0-65535) for the new flow.
    ///
    /// # Returns
    /// A `Box` containing a new `RohcDecompressorContext` for this profile.
    fn create_decompressor_context(&self, cid: u16) -> Box<dyn RohcDecompressorContext>;

    /// Compresses a set of uncompressed headers using this profile's logic.
    ///
    /// The provided `context` must be downcastable to the specific context type
    /// expected by this profile handler.
    ///
    /// # Parameters
    /// - `context`: A mutable reference to a `RohcCompressorContext`.
    /// - `headers`: The `GenericUncompressedHeaders` to be compressed. The handler
    ///   is responsible for extracting the relevant header types for its profile.
    ///
    /// # Returns
    /// A `Result` containing the ROHC-compressed packet as a `Vec<u8>`,
    /// or a `RohcError` if compression fails.
    fn compress(
        &self,
        context: &mut dyn RohcCompressorContext,
        headers: &GenericUncompressedHeaders,
    ) -> Result<Vec<u8>, RohcError>;

    /// Decompresses a ROHC packet using this profile's logic.
    ///
    /// The provided `context` must be downcastable to the specific context type
    /// expected by this profile handler. The `rohc_packet_data` is assumed to be
    /// the core ROHC packet, with any system-level framing (like Add-CID octets
    /// used for context lookup by the engine) already processed and removed.
    ///
    /// # Parameters
    /// - `context`: A mutable reference to a `RohcDecompressorContext`.
    /// - `rohc_packet_data`: A slice containing the ROHC packet data to decompress.
    ///
    /// # Returns
    /// A `Result` containing the reconstructed `GenericUncompressedHeaders`,
    /// or a `RohcError` if decompression fails.
    fn decompress(
        &self,
        context: &mut dyn RohcDecompressorContext,
        rohc_packet_data: &[u8],
    ) -> Result<GenericUncompressedHeaders, RohcError>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet_defs::RohcProfile;
    use bytes::Bytes;

    // Mock implementation for RohcCompressorContext
    #[derive(Debug)]
    struct MockCompressorContext {
        cid: u16,
        profile: RohcProfile,
    }

    impl RohcCompressorContext for MockCompressorContext {
        fn profile_id(&self) -> RohcProfile {
            self.profile
        }
        fn cid(&self) -> u16 {
            self.cid
        }
        fn as_any(&self) -> &dyn Any {
            self
        }
        fn as_any_mut(&mut self) -> &mut dyn Any {
            self
        }
    }

    // Mock implementation for RohcDecompressorContext
    #[derive(Debug)]
    struct MockDecompressorContext {
        cid: u16,
        profile: RohcProfile,
    }

    impl RohcDecompressorContext for MockDecompressorContext {
        fn profile_id(&self) -> RohcProfile {
            self.profile
        }
        fn cid(&self) -> u16 {
            self.cid
        }
        fn set_cid(&mut self, cid: u16) {
            self.cid = cid;
        }
        fn as_any(&self) -> &dyn Any {
            self
        }
        fn as_any_mut(&mut self) -> &mut dyn Any {
            self
        }
    }

    // Mock implementation for ProfileHandler
    #[derive(Debug)]
    struct MockProfileHandler {
        profile: RohcProfile,
    }

    impl ProfileHandler for MockProfileHandler {
        fn profile_id(&self) -> RohcProfile {
            self.profile
        }

        fn create_compressor_context(
            &self,
            cid: u16,
            _ir_refresh_interval: u32,
        ) -> Box<dyn RohcCompressorContext> {
            Box::new(MockCompressorContext {
                cid,
                profile: self.profile,
            })
        }

        fn create_decompressor_context(&self, cid: u16) -> Box<dyn RohcDecompressorContext> {
            Box::new(MockDecompressorContext {
                cid,
                profile: self.profile,
            })
        }

        fn compress(
            &self,
            _context: &mut dyn RohcCompressorContext,
            headers: &GenericUncompressedHeaders,
        ) -> Result<Vec<u8>, RohcError> {
            match headers {
                GenericUncompressedHeaders::TestRaw(data) => {
                    // Mock compression: maybe just prepend profile_id and return a few bytes
                    let mut compressed_data = Vec::new();

                    // Example: add profile byte
                    compressed_data.push(self.profile.into());
                    compressed_data.extend_from_slice(&data[0..std::cmp::min(data.len(), 2)]); // take up to 2 bytes
                    Ok(compressed_data)
                }
                _ => Err(RohcError::Internal(
                    "MockProfileHandler only supports TestRaw headers for compress".to_string(),
                )),
            }
        }

        fn decompress(
            &self,
            _context: &mut dyn RohcDecompressorContext,
            rohc_packet_data: &[u8],
        ) -> Result<GenericUncompressedHeaders, RohcError> {
            if rohc_packet_data.is_empty() {
                return Err(RohcError::Parsing(
                    crate::error::RohcParsingError::NotEnoughData {
                        needed: 1,
                        got: 0,
                        context: "mock decompress".to_string(),
                    },
                ));
            }
            // Mock decompression: assume first byte was profile, rest is raw
            let profile_from_packet = RohcProfile::from(rohc_packet_data[0]);
            if profile_from_packet != self.profile {
                return Err(RohcError::Parsing(
                    crate::error::RohcParsingError::InvalidProfileId(rohc_packet_data[0]),
                ));
            }
            Ok(GenericUncompressedHeaders::TestRaw(Bytes::copy_from_slice(
                &rohc_packet_data[1..],
            )))
        }
    }

    #[test]
    fn mock_compressor_context_works() {
        let mut ctx = MockCompressorContext {
            cid: 1,
            profile: RohcProfile::Uncompressed,
        };
        assert_eq!(ctx.cid(), 1);
        assert_eq!(ctx.profile_id(), RohcProfile::Uncompressed);

        let _any_ref = ctx.as_any();
        let _any_mut_ref = ctx.as_any_mut();
    }

    #[test]
    fn mock_decompressor_context_works() {
        let mut ctx = MockDecompressorContext {
            cid: 2,
            profile: RohcProfile::RtpUdpIp,
        };
        assert_eq!(ctx.cid(), 2);
        assert_eq!(ctx.profile_id(), RohcProfile::RtpUdpIp);
        ctx.set_cid(3);
        assert_eq!(ctx.cid(), 3);

        let _any_ref = ctx.as_any();
        let _any_mut_ref = ctx.as_any_mut();
    }

    #[test]
    fn mock_profile_handler_works() {
        let handler = MockProfileHandler {
            profile: RohcProfile::UdpIp,
        };
        assert_eq!(handler.profile_id(), RohcProfile::UdpIp);

        let comp_ctx = handler.create_compressor_context(10, 50);
        assert_eq!(comp_ctx.cid(), 10);
        assert_eq!(comp_ctx.profile_id(), RohcProfile::UdpIp);

        let deomp_ctx = handler.create_decompressor_context(20);
        assert_eq!(deomp_ctx.cid(), 20);
        assert_eq!(deomp_ctx.profile_id(), RohcProfile::UdpIp);
    }

    #[test]
    fn dynamic_dispatch_profile_handler() {
        let handler: Box<dyn ProfileHandler> = Box::new(MockProfileHandler {
            profile: RohcProfile::Ip,
        });
        assert_eq!(handler.profile_id(), RohcProfile::Ip);
        let ctx = handler.create_compressor_context(5, 20);
        assert_eq!(ctx.cid(), 5);
    }

    #[test]
    fn mock_profile_handler_compress_decompress() {
        let handler = MockProfileHandler {
            profile: RohcProfile::UdpIp,
        };
        let mut mock_comp_ctx = MockCompressorContext {
            cid: 1,
            profile: RohcProfile::UdpIp,
        };
        let mut mock_decomp_ctx = MockDecompressorContext {
            cid: 1,
            profile: RohcProfile::UdpIp,
        };

        // Test compress
        let dummy_uncompressed_data = GenericUncompressedHeaders::new_test_raw(vec![0xA, 0xB, 0xC]);
        let compress_result = handler.compress(&mut mock_comp_ctx, &dummy_uncompressed_data);
        assert!(compress_result.is_ok());
        let compressed_bytes = compress_result.unwrap();
        assert_eq!(compressed_bytes, vec![RohcProfile::UdpIp.into(), 0xA, 0xB]); // Based on mock logic

        // Test decompress
        let decompress_result = handler.decompress(&mut mock_decomp_ctx, &compressed_bytes);
        assert!(decompress_result.is_ok());
        match decompress_result.unwrap() {
            GenericUncompressedHeaders::TestRaw(raw_data) => {
                assert_eq!(raw_data, Bytes::from_static(&[0xA, 0xB]));
            }
            _ => panic!("Decompressed to unexpected GenericUncompressedHeaders variant"),
        }
    }
}
