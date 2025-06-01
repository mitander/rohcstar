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
use std::time::Instant;

/// Defines the capabilities of a ROHC compressor context.
pub trait RohcCompressorContext: Send + Sync + Debug {
    /// Returns the ROHC Profile Identifier this context is configured for.
    fn profile_id(&self) -> RohcProfile;
    /// Returns the Context Identifier (CID) uniquely identifying this compression flow.
    fn cid(&self) -> u16;
    /// Provides a reference to the context as `&dyn Any` for downcasting.
    fn as_any(&self) -> &dyn Any;
    /// Provides a mutable reference to the context as `&mut dyn Any` for downcasting.
    fn as_any_mut(&mut self) -> &mut dyn Any;
    /// Returns the `Instant` when this context was last successfully accessed.
    fn last_accessed(&self) -> Instant;
    /// Sets the last accessed time of this context.
    fn set_last_accessed(&mut self, now: Instant);
}

/// Defines the capabilities of a ROHC decompressor context.
pub trait RohcDecompressorContext: Send + Sync + Debug {
    /// Returns the ROHC Profile Identifier this context is configured for.
    fn profile_id(&self) -> RohcProfile;
    /// Returns the Context Identifier (CID) of this decompression flow.
    fn cid(&self) -> u16;
    /// Sets or updates the Context Identifier (CID) for this context.
    fn set_cid(&mut self, cid: u16);
    /// Provides a reference to the context as `&dyn Any` for downcasting.
    fn as_any(&self) -> &dyn Any;
    /// Provides a mutable reference to the context as `&mut dyn Any` for downcasting.
    fn as_any_mut(&mut self) -> &mut dyn Any;
    /// Returns the `Instant` when this context was last successfully accessed.
    fn last_accessed(&self) -> Instant;
    /// Sets the last accessed time of this context.
    fn set_last_accessed(&mut self, now: Instant);
}

/// Defines the interface for a ROHC profile handler.
pub trait ProfileHandler: Send + Sync + Debug {
    /// Returns the ROHC Profile Identifier that this handler implements.
    fn profile_id(&self) -> RohcProfile;

    /// Creates a new, profile-specific compressor context.
    ///
    /// # Parameters
    /// - `cid`: The Context Identifier for the new flow.
    /// - `ir_refresh_interval`: Suggested interval for IR refreshes.
    /// - `creation_time`: The timestamp for the context's creation, used to initialize its `last_accessed` time.
    ///
    /// # Returns
    /// A `Box` containing a new `RohcCompressorContext`.
    fn create_compressor_context(
        &self,
        cid: u16,
        ir_refresh_interval: u32,
        creation_time: Instant,
    ) -> Box<dyn RohcCompressorContext>;

    /// Creates a new, profile-specific decompressor context.
    ///
    /// # Parameters
    /// - `cid`: The Context Identifier for the new flow.
    /// - `creation_time`: The timestamp for the context's creation, used to initialize its `last_accessed` time.
    ///
    /// # Returns
    /// A `Box` containing a new `RohcDecompressorContext`.
    fn create_decompressor_context(
        &self,
        cid: u16,
        creation_time: Instant,
    ) -> Box<dyn RohcDecompressorContext>;

    /// Compresses a set of uncompressed headers using this profile's logic.
    ///
    /// # Parameters
    /// - `context`: A mutable reference to a `RohcCompressorContext`.
    /// - `headers`: The `GenericUncompressedHeaders` to be compressed.
    ///
    /// # Returns
    /// - `Ok(Vec<u8>)` containing the ROHC-compressed packet on success.
    /// - `Err(RohcError)` if compression fails.
    fn compress(
        &self,
        context: &mut dyn RohcCompressorContext,
        headers: &GenericUncompressedHeaders,
    ) -> Result<Vec<u8>, RohcError>;

    /// Decompresses a ROHC packet using this profile's logic.
    ///
    /// # Parameters
    /// - `context`: A mutable reference to a `RohcDecompressorContext`.
    /// - `packet_bytes`: A slice containing the ROHC packet data to decompress.
    ///
    /// # Returns
    /// - `Ok(GenericUncompressedHeaders)` containing the reconstructed headers on success.
    /// - `Err(RohcError)` if decompression fails.
    fn decompress(
        &self,
        context: &mut dyn RohcDecompressorContext,
        packet_bytes: &[u8],
    ) -> Result<GenericUncompressedHeaders, RohcError>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet_defs::RohcProfile;
    use bytes::Bytes;
    use std::time::{Duration, Instant};

    #[derive(Debug)]
    struct MockCompressorContext {
        cid: u16,
        profile: RohcProfile,
        last_accessed: Instant,
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
        fn last_accessed(&self) -> Instant {
            self.last_accessed
        }
        fn set_last_accessed(&mut self, now: Instant) {
            self.last_accessed = now;
        }
    }

    #[derive(Debug)]
    struct MockDecompressorContext {
        cid: u16,
        profile: RohcProfile,
        last_accessed: Instant,
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
        fn last_accessed(&self) -> Instant {
            self.last_accessed
        }
        fn set_last_accessed(&mut self, now: Instant) {
            self.last_accessed = now;
        }
    }

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
            creation_time: Instant,
        ) -> Box<dyn RohcCompressorContext> {
            Box::new(MockCompressorContext {
                cid,
                profile: self.profile,
                last_accessed: creation_time,
            })
        }
        fn create_decompressor_context(
            &self,
            cid: u16,
            creation_time: Instant,
        ) -> Box<dyn RohcDecompressorContext> {
            Box::new(MockDecompressorContext {
                cid,
                profile: self.profile,
                last_accessed: creation_time,
            })
        }
        fn compress(
            &self,
            _context: &mut dyn RohcCompressorContext,
            headers: &GenericUncompressedHeaders,
        ) -> Result<Vec<u8>, RohcError> {
            match headers {
                GenericUncompressedHeaders::TestRaw(data) => {
                    let mut cd = Vec::new();
                    cd.push(self.profile.into());
                    cd.extend_from_slice(&data[0..std::cmp::min(data.len(), 2)]);
                    Ok(cd)
                }
                _ => Err(RohcError::Internal(
                    "MockProfileHandler only supports TestRaw".to_string(),
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
                        context: "mock".to_string(),
                    },
                ));
            }
            let pf = RohcProfile::from(rohc_packet_data[0]);
            if pf != self.profile {
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
    fn mock_context_time_methods_work() {
        let now = Instant::now();
        let mut compressor_ctx = MockCompressorContext {
            cid: 1,
            profile: RohcProfile::Uncompressed,
            last_accessed: now,
        };
        assert_eq!(compressor_ctx.last_accessed(), now);
        let later = now + Duration::from_secs(1);
        compressor_ctx.set_last_accessed(later);
        assert_eq!(compressor_ctx.last_accessed(), later);

        let mut decompressor_ctx = MockDecompressorContext {
            cid: 1,
            profile: RohcProfile::Uncompressed,
            last_accessed: now,
        };
        assert_eq!(decompressor_ctx.last_accessed(), now);
        decompressor_ctx.set_last_accessed(later);
        assert_eq!(decompressor_ctx.last_accessed(), later);
    }

    #[test]
    fn mock_handler_creates_contexts_with_time() {
        let handler = MockProfileHandler {
            profile: RohcProfile::Ip,
        };
        let creation_time = Instant::now();
        let comp_ctx = handler.create_compressor_context(1, 10, creation_time);
        assert_eq!(comp_ctx.last_accessed(), creation_time);
        let decomp_ctx = handler.create_decompressor_context(1, creation_time);
        assert_eq!(decomp_ctx.last_accessed(), creation_time);
    }
}
