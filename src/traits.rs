//! Core ROHC traits.
//!
//! Defines interfaces for contexts and profile handlers.

use crate::error::RohcError;
use crate::packet_defs::{GenericUncompressedHeaders, RohcProfile};
use std::any::Any;

/// Trait for ROHC compressor contexts.
///
/// Manages compression state and operations for a ROHC profile.
pub trait RohcCompressorContext: Send + Sync {
    /// Returns the ROHC Profile Identifier this context is for.
    fn profile_id(&self) -> RohcProfile;

    /// Returns the Context Identifier (CID) of this context.
    fn cid(&self) -> u16;

    /// Returns a reference to the context as `&dyn Any`.
    ///
    /// # Returns
    /// A reference to the context as `&dyn Any`.
    fn as_any(&self) -> &dyn Any;

    /// Returns a mutable reference to the context as `&mut dyn Any`.
    ///
    /// # Returns
    /// A mutable reference to the context as `&mut dyn Any`.
    fn as_any_mut(&mut self) -> &mut dyn Any;
}

/// Trait for ROHC decompressor contexts.
///
/// Manages state for packet decompression.
pub trait RohcDecompressorContext: Send + Sync {
    /// Returns the ROHC Profile Identifier this context is for.
    fn profile_id(&self) -> RohcProfile;

    /// Returns the Context Identifier (CID) of this context.
    fn cid(&self) -> u16;

    /// Sets the Context Identifier (CID) for this context.
    /// Typically called by the engine/manager when associating a packet stream with this context.
    fn set_cid(&mut self, cid: u16);

    /// Returns a reference to the context as `&dyn Any`.
    ///
    /// # Returns
    /// A reference to the context as `&dyn Any`.
    fn as_any(&self) -> &dyn Any;

    /// Returns a mutable reference to the context as `&mut dyn Any`.
    ///
    /// # Returns
    /// A mutable reference to the context as `&mut dyn Any`.
    fn as_any_mut(&mut self) -> &mut dyn Any;
}

/// Interface for ROHC profile handlers.
///
/// Implemented by each ROHC profile to provide
/// compression/decompression logic.
pub trait ProfileHandler: Send + Sync {
    /// Returns the ROHC profile identifier for this handler.
    fn profile_id(&self) -> RohcProfile;

    /// Creates a new compressor context.
    ///
    /// # Parameters
    /// - `cid`: Context identifier (0-65535)
    /// - `ir_refresh_interval`: Interval between IR refreshes (in packets)
    ///
    /// # Returns
    /// A boxed compressor context for this profile.
    fn create_compressor_context(
        &self,
        cid: u16,
        ir_refresh_interval: u32,
    ) -> Box<dyn RohcCompressorContext>;

    /// Creates a new decompressor context for this profile.
    ///
    /// # Parameters
    /// - `cid`: Context identifier (0-65535)
    ///
    /// # Returns
    /// A boxed decompressor context for this profile.
    fn create_decompressor_context(&self, cid: u16) -> Box<dyn RohcDecompressorContext>;

    /// Compresses headers using this profile.
    ///
    /// # Parameters
    /// - `context`: Mutable reference to the compressor context
    /// - `headers`: Uncompressed headers to process
    ///
    /// # Returns
    /// A `Result` containing the compressed packet as `Vec<u8>` or a `RohcError`.
    fn compress(
        &self,
        context: &mut dyn RohcCompressorContext,
        headers: &GenericUncompressedHeaders,
    ) -> Result<Vec<u8>, RohcError>;

    /// Decompresses a ROHC packet.
    ///
    /// # Parameters
    /// - `context`: Mutable reference to a decompressor context.
    ///   Must be downcast to the profile-specific context type.
    /// - `rohc_packet_data`: Packet data (after any Add-CID octet)
    ///
    /// # Returns
    /// A `Result` containing the reconstructed `GenericUncompressedHeaders` or a `RohcError`.
    fn decompress(
        &self,
        context: &mut dyn RohcDecompressorContext,
        rohc_packet_data: &[u8],
    ) -> Result<GenericUncompressedHeaders, RohcError>;
}
