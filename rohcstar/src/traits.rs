//! Core ROHC (Robust Header Compression) traits.
//!
//! This module defines the essential interfaces for ROHC profile handlers
//! and their associated compressor and decompressor contexts. These traits
//! enable a generic ROHC engine to operate with various compression profiles
//! in a pluggable manner.

use std::any::Any;
use std::fmt::Debug;
use std::time::Instant;

use crate::error::RohcError;
use crate::packet_defs::{GenericUncompressedHeaders, RohcProfile};
use crate::types::ContextId;

/// Defines the capabilities of a ROHC compressor context.
pub trait RohcCompressorContext: Send + Sync + Debug {
    /// ROHC Profile Identifier this context is configured for.
    fn profile_id(&self) -> RohcProfile;
    /// Context Identifier (CID) uniquely identifying this compression flow.
    fn cid(&self) -> ContextId;
    /// Context as `&dyn Any` for downcasting.
    fn as_any(&self) -> &dyn Any;
    /// Context as `&mut dyn Any` for downcasting.
    fn as_any_mut(&mut self) -> &mut dyn Any;
    /// Last successful access time.
    fn last_accessed(&self) -> Instant;
    /// Updates last accessed time.
    fn update_access_time(&mut self, now: Instant);
}

/// Defines the capabilities of a ROHC decompressor context.
pub trait RohcDecompressorContext: Send + Sync + Debug {
    /// ROHC Profile Identifier this context is configured for.
    fn profile_id(&self) -> RohcProfile;
    /// Context Identifier (CID) of this decompression flow.
    fn cid(&self) -> ContextId;
    /// Assigns new Context Identifier (CID).
    fn assign_cid(&mut self, cid: ContextId);
    /// Context as `&dyn Any` for downcasting.
    fn as_any(&self) -> &dyn Any;
    /// Context as `&mut dyn Any` for downcasting.
    fn as_any_mut(&mut self) -> &mut dyn Any;
    /// Last successful access time.
    fn last_accessed(&self) -> Instant;
    /// Updates last accessed time.
    fn update_access_time(&mut self, now: Instant);
}

/// Defines the interface for a ROHC profile handler.
pub trait ProfileHandler: Send + Sync + Debug {
    /// ROHC Profile Identifier this handler implements.
    fn profile_id(&self) -> RohcProfile;

    /// Creates new profile-specific compressor context.
    fn create_compressor_context(
        &self,
        cid: ContextId,
        ir_refresh_interval: u32,
        creation_time: Instant,
    ) -> Box<dyn RohcCompressorContext>;

    /// Creates new profile-specific decompressor context.
    fn create_decompressor_context(
        &self,
        cid: ContextId,
        creation_time: Instant,
    ) -> Box<dyn RohcDecompressorContext>;

    /// Compresses uncompressed headers into ROHC packet (zero-allocation hot path).
    ///
    /// # Errors
    /// - `RohcError` - Compression fails due to context or profile-specific issues
    fn compress(
        &self,
        context: &mut dyn RohcCompressorContext,
        headers: &GenericUncompressedHeaders,
        out: &mut [u8],
    ) -> Result<usize, RohcError>;

    /// Decompresses a ROHC packet using this profile's logic.
    ///
    /// # Errors
    /// - `RohcError` - Decompression fails due to parsing, CRC, or context issues
    fn decompress(
        &self,
        context: &mut dyn RohcDecompressorContext,
        packet: &[u8],
    ) -> Result<GenericUncompressedHeaders, RohcError>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::{ParseContext, RohcBuildingError, RohcError, RohcParsingError};
    use crate::packet_defs::RohcProfile;
    use bytes::Bytes;
    use std::time::{Duration, Instant};

    #[derive(Debug)]
    struct MockCompressorContext {
        cid: ContextId,
        profile: RohcProfile,
        last_accessed: Instant,
    }

    impl RohcCompressorContext for MockCompressorContext {
        fn profile_id(&self) -> RohcProfile {
            self.profile
        }
        fn cid(&self) -> ContextId {
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
        fn update_access_time(&mut self, now: Instant) {
            self.last_accessed = now;
        }
    }

    #[derive(Debug)]
    struct MockDecompressorContext {
        cid: ContextId,
        profile: RohcProfile,
        last_accessed: Instant,
    }

    impl RohcDecompressorContext for MockDecompressorContext {
        fn profile_id(&self) -> RohcProfile {
            self.profile
        }
        fn cid(&self) -> ContextId {
            self.cid
        }
        fn assign_cid(&mut self, cid: ContextId) {
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
        fn update_access_time(&mut self, now: Instant) {
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
            cid: ContextId,
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
            cid: ContextId,
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
            out: &mut [u8],
        ) -> Result<usize, RohcError> {
            match headers {
                GenericUncompressedHeaders::TestRaw(data) => {
                    let bytes_needed = 1 + std::cmp::min(data.len(), 2);
                    if out.len() < bytes_needed {
                        return Err(RohcError::Building(RohcBuildingError::BufferTooSmall {
                            needed: bytes_needed,
                            available: out.len(),
                            context: ParseContext::RohcPacketInput,
                        }));
                    }
                    out[0] = self.profile.into();
                    let data_len = std::cmp::min(data.len(), 2);
                    out[1..1 + data_len].copy_from_slice(&data[0..data_len]);
                    Ok(1 + data_len)
                }
                _ => Err(RohcError::Internal(
                    "MockProfileHandler only supports TestRaw".to_string(),
                )),
            }
        }

        fn decompress(
            &self,
            _context: &mut dyn RohcDecompressorContext,
            packet: &[u8],
        ) -> Result<GenericUncompressedHeaders, RohcError> {
            if packet.is_empty() {
                return Err(RohcError::Parsing(RohcParsingError::NotEnoughData {
                    needed: 1,
                    got: 0,
                    context: ParseContext::RohcPacketInput,
                }));
            }
            let pf = RohcProfile::from(packet[0]);
            if pf != self.profile {
                return Err(RohcError::Parsing(RohcParsingError::InvalidProfileId(
                    packet[0],
                )));
            }
            Ok(GenericUncompressedHeaders::TestRaw(Bytes::copy_from_slice(
                &packet[1..],
            )))
        }
    }

    #[test]
    fn mock_context_time_methods_work() {
        let now = Instant::now();
        let mut compressor_ctx = MockCompressorContext {
            cid: 1.into(),
            profile: RohcProfile::Uncompressed,
            last_accessed: now,
        };
        assert_eq!(compressor_ctx.last_accessed(), now);
        let later = now + Duration::from_secs(1);
        compressor_ctx.update_access_time(later);
        assert_eq!(compressor_ctx.last_accessed(), later);

        let mut decompressor_ctx = MockDecompressorContext {
            cid: 1.into(),
            profile: RohcProfile::Uncompressed,
            last_accessed: now,
        };
        assert_eq!(decompressor_ctx.last_accessed(), now);
        decompressor_ctx.update_access_time(later);
        assert_eq!(decompressor_ctx.last_accessed(), later);
    }

    #[test]
    fn mock_handler_creates_contexts_with_time() {
        let handler = MockProfileHandler {
            profile: RohcProfile::Ip,
        };
        let creation_time = Instant::now();
        let comp_ctx = handler.create_compressor_context(1.into(), 10, creation_time);
        assert_eq!(comp_ctx.last_accessed(), creation_time);
        let decomp_ctx = handler.create_decompressor_context(1.into(), creation_time);
        assert_eq!(decomp_ctx.last_accessed(), creation_time);
    }
}
