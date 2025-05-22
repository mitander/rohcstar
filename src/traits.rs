//! Core behavioral traits for the ROHC (Robust Header Compression) library.
//!
//! These traits define the essential interfaces for contexts and profile-specific
//! handlers, enabling a modular and extensible ROHC engine.

use crate::error::RohcError;
use crate::packet_defs::{GenericUncompressedHeaders, RohcProfile};
use std::any::Any;

/// Defines the common interface for a ROHC compressor context.
///
/// Implementations store profile-specific state required for compression.
pub trait RohcCompressorContext: Send + Sync {
    /// Returns the ROHC Profile Identifier this context is for.
    fn profile_id(&self) -> RohcProfile;

    /// Returns the Context Identifier (CID) of this context.
    fn cid(&self) -> u16;

    /// Allows downcasting to a concrete compressor context type.
    fn as_any(&self) -> &dyn Any;

    /// Allows mutable downcasting to a concrete compressor context type.
    fn as_any_mut(&mut self) -> &mut dyn Any;
}

/// Defines the common interface for a ROHC decompressor context.
///
/// Implementations store profile-specific state required for decompression
/// and header reconstruction.
pub trait RohcDecompressorContext: Send + Sync {
    /// Returns the ROHC Profile Identifier this context is for.
    fn profile_id(&self) -> RohcProfile;

    /// Returns the Context Identifier (CID) of this context.
    fn cid(&self) -> u16;

    /// Sets the Context Identifier (CID) for this context.
    /// Typically called by the engine/manager when associating a packet stream with this context.
    fn set_cid(&mut self, cid: u16);

    /// Allows downcasting to a concrete decompressor context type.
    fn as_any(&self) -> &dyn Any;

    /// Allows mutable downcasting to a concrete decompressor context type.
    fn as_any_mut(&mut self) -> &mut dyn Any;
}

/// Defines the interface for a ROHC profile-specific handler.
///
/// Each supported ROHC profile implements this trait to provide its unique
/// compression, decompression, and context management logic.
pub trait ProfileHandler: Send + Sync {
    /// Returns the ROHC Profile Identifier this handler implements.
    fn profile_id(&self) -> RohcProfile;

    /// Compresses an uncompressed packet according to this profile's rules.
    ///
    /// # Arguments
    /// * `context`: A mutable reference to a generic `RohcCompressorContext`.
    ///   The handler must downcast this to its specific context type.
    /// * `headers`: The uncompressed headers to compress.
    ///
    /// # Returns
    /// A `Result` containing the ROHC compressed packet or a `RohcError`.
    fn compress(
        &self,
        context: &mut dyn RohcCompressorContext,
        headers: &GenericUncompressedHeaders,
    ) -> Result<Vec<u8>, RohcError>;

    /// Decompresses a ROHC packet according to this profile's rules.
    ///
    /// # Arguments
    /// * `context`: A mutable reference to a generic `RohcDecompressorContext`.
    ///   The handler must downcast this to its specific context type.
    ///   The context's CID should already be set correctly by the caller.
    ///
    /// * `rohc_packet_core_bytes`: Packet data starting *after* any Add-CID octet,
    ///   beginning with the ROHC packet type discriminator.
    ///
    /// # Returns
    /// A `Result` containing the reconstructed `GenericUncompressedHeaders` or a `RohcError`.
    fn decompress(
        &self,
        context: &mut dyn RohcDecompressorContext,
        rohc_packet_core_bytes: &[u8],
    ) -> Result<GenericUncompressedHeaders, RohcError>;

    /// Creates a new, uninitialized compressor context for this profile.
    fn create_compressor_context(
        &self,
        cid: u16,
        ir_refresh_interval: u32,
    ) -> Box<dyn RohcCompressorContext>;

    /// Creates a new, uninitialized decompressor context for this profile.
    fn create_decompressor_context(&self, cid: u16) -> Box<dyn RohcDecompressorContext>;
}
