//! ROHC (Robust Header Compression) generic context management.
//!
//! This module provides a `ContextManager` responsible for storing, retrieving,
//! and managing the lifecycle of ROHC compressor and decompressor contexts.
//! It operates on trait objects (`Box<dyn RohcCompressorContext>`, etc.)
//! to remain independent of specific ROHC profile implementations.

use std::collections::HashMap;
use std::fmt::Debug;

use crate::error::RohcError;
use crate::traits::{RohcCompressorContext, RohcDecompressorContext};

/// Manages multiple ROHC contexts (both compressor and decompressor) indexed by CID.
///
/// This manager is designed to be generic and can store contexts for any ROHC profile
/// that implements the `RohcCompressorContext` and `RohcDecompressorContext` traits.
/// The actual creation of contexts is delegated to a `ProfileHandler` (managed by the ROHC Engine).
#[derive(Debug, Default)]
pub struct ContextManager {
    /// Stores active compressor contexts, keyed by their Context ID (CID).
    compressor_contexts: HashMap<u16, Box<dyn RohcCompressorContext>>,
    /// Stores active decompressor contexts, keyed by their Context ID (CID).
    decompressor_contexts: HashMap<u16, Box<dyn RohcDecompressorContext>>,
}

impl ContextManager {
    /// Creates a new, empty `ContextManager`.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a new compressor context to the manager.
    ///
    /// If a context with the same CID already exists, it will be overwritten.
    /// This method is typically called by the ROHC engine after a `ProfileHandler`
    /// creates a new context.
    ///
    /// # Parameters
    /// - `cid`: The Context ID for the context being added.
    /// - `context`: The `Box<dyn RohcCompressorContext>` to add.
    pub fn add_compressor_context(&mut self, cid: u16, context: Box<dyn RohcCompressorContext>) {
        self.compressor_contexts.insert(cid, context);
    }

    /// Adds a new decompressor context to the manager.
    ///
    /// If a context with the same CID already exists, it will be overwritten.
    ///
    /// # Parameters
    /// - `cid`: The Context ID for the context being added.
    /// - `context`: The `Box<dyn RohcDecompressorContext>` to add.
    pub fn add_decompressor_context(
        &mut self,
        cid: u16,
        context: Box<dyn RohcDecompressorContext>,
    ) {
        self.decompressor_contexts.insert(cid, context);
    }

    /// Retrieves a mutable reference to a compressor context by its CID.
    ///
    /// # Parameters
    /// - `cid`: The Context ID of the compressor context to retrieve.
    ///
    /// # Returns
    /// - `Ok(&mut Box<dyn RohcCompressorContext>)` if the context is found.
    /// - `Err(RohcError::ContextNotFound(cid))` if no context exists for the given CID.
    pub fn get_compressor_context_mut(
        &mut self,
        cid: u16,
    ) -> Result<&mut Box<dyn RohcCompressorContext>, RohcError> {
        self.compressor_contexts
            .get_mut(&cid)
            .ok_or(RohcError::ContextNotFound(cid))
    }

    /// Retrieves a mutable reference to a decompressor context by its CID.
    ///
    /// # Parameters
    /// - `cid`: The Context ID of the decompressor context to retrieve.
    ///
    /// # Returns
    /// - `Ok(&mut Box<dyn RohcDecompressorContext>)` if the context is found.
    /// - `Err(RohcError::ContextNotFound(cid))` if no context exists for the given CID.
    pub fn get_decompressor_context_mut(
        &mut self,
        cid: u16,
    ) -> Result<&mut Box<dyn RohcDecompressorContext>, RohcError> {
        self.decompressor_contexts
            .get_mut(&cid)
            .ok_or(RohcError::ContextNotFound(cid))
    }

    /// Retrieves a immutable reference to a compressor context by its CID.
    ///
    /// # Parameters
    /// - `cid`: The Context ID of the decompressor context to retrieve.
    ///
    /// # Returns
    /// - `Ok(&dyn RohcCompressorContext)` if the context is found.
    /// - `Err(RohcError::ContextNotFound(cid))` if no context exists for the given CID.
    pub fn get_compressor_context(
        &self,
        cid: u16,
    ) -> Result<&dyn RohcCompressorContext, RohcError> {
        self.compressor_contexts
            .get(&cid)
            .map(|boxed_context_ref| {
                let context_ref: &dyn RohcCompressorContext = &**boxed_context_ref;
                context_ref
            })
            .ok_or(RohcError::ContextNotFound(cid))
    }

    /// Retrieves a immutable reference to a decompressor context by its CID.
    ///
    /// # Parameters
    /// - `cid`: The Context ID of the decompressor context to retrieve.
    ///
    /// # Returns
    /// - `Ok(&dyn RohcDecompressorContext)` if the context is found.
    /// - `Err(RohcError::ContextNotFound(cid))` if no context exists for the given CID.
    pub fn get_decompressor_context(
        &self,
        cid: u16,
    ) -> Result<&dyn RohcDecompressorContext, RohcError> {
        self.decompressor_contexts
            .get(&cid)
            .map(|boxed_context_ref| {
                let context_ref: &dyn RohcDecompressorContext = &**boxed_context_ref;
                context_ref
            })
            .ok_or(RohcError::ContextNotFound(cid))
    }
    /// Removes a compressor context by its CID.
    ///
    /// # Parameters
    /// - `cid`: The Context ID of the compressor context to remove.
    ///
    /// # Returns
    /// The removed `Box<dyn RohcCompressorContext>` if it existed, otherwise `None`.
    pub fn remove_compressor_context(
        &mut self,
        cid: u16,
    ) -> Option<Box<dyn RohcCompressorContext>> {
        self.compressor_contexts.remove(&cid)
    }

    /// Removes a decompressor context by its CID.
    ///
    /// # Parameters
    /// - `cid`: The Context ID of the decompressor context to remove.
    ///
    /// # Returns
    /// The removed `Box<dyn RohcDecompressorContext>` if it existed, otherwise `None`.
    pub fn remove_decompressor_context(
        &mut self,
        cid: u16,
    ) -> Option<Box<dyn RohcDecompressorContext>> {
        self.decompressor_contexts.remove(&cid)
    }

    /// Clears all compressor contexts from the manager.
    pub fn clear_compressor_contexts(&mut self) {
        self.compressor_contexts.clear();
    }

    /// Clears all decompressor contexts from the manager.
    pub fn clear_decompressor_contexts(&mut self) {
        self.decompressor_contexts.clear();
    }

    /// Clears all contexts (both compressor and decompressor) from the manager.
    pub fn clear_all_contexts(&mut self) {
        self.clear_compressor_contexts();
        self.clear_decompressor_contexts();
    }

    /// Returns the number of active compressor contexts.
    pub fn compressor_context_count(&self) -> usize {
        self.compressor_contexts.len()
    }

    /// Returns the number of active decompressor contexts.
    pub fn decompressor_context_count(&self) -> usize {
        self.decompressor_contexts.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet_defs::RohcProfile;
    use crate::traits::{RohcCompressorContext, RohcDecompressorContext};
    use std::any::Any;

    #[derive(Debug)]
    struct MockCompressorCtx {
        cid: u16,
        data: String,
    }
    impl RohcCompressorContext for MockCompressorCtx {
        fn profile_id(&self) -> RohcProfile {
            RohcProfile::Uncompressed
        } // Dummy profile
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

    #[derive(Debug)]
    struct MockDecompressorCtx {
        cid: u16,
        updates: u32,
    }
    impl RohcDecompressorContext for MockDecompressorCtx {
        fn profile_id(&self) -> RohcProfile {
            RohcProfile::RtpUdpIp
        } // Dummy profile
        fn cid(&self) -> u16 {
            self.cid
        }
        fn set_cid(&mut self, new_cid: u16) {
            self.cid = new_cid;
        }
        fn as_any(&self) -> &dyn Any {
            self
        }
        fn as_any_mut(&mut self) -> &mut dyn Any {
            self
        }
    }

    #[test]
    fn context_manager_new_is_empty() {
        let manager = ContextManager::new();
        assert_eq!(manager.compressor_context_count(), 0);
        assert_eq!(manager.decompressor_context_count(), 0);
    }

    #[test]
    fn add_and_get_compressor_context() {
        let mut manager = ContextManager::new();
        let ctx1: Box<dyn RohcCompressorContext> = Box::new(MockCompressorCtx {
            cid: 1,
            data: "flow1".to_string(),
        });
        let cid1 = ctx1.cid();
        manager.add_compressor_context(cid1, ctx1);

        assert_eq!(manager.compressor_context_count(), 1);

        // Get existing context
        let retrieved_ctx1 = manager.get_compressor_context_mut(cid1).unwrap();
        assert_eq!(retrieved_ctx1.cid(), cid1);

        // Downcast to check data
        retrieved_ctx1
            .as_any_mut()
            .downcast_mut::<MockCompressorCtx>()
            .unwrap()
            .data = "flow1_updated".to_string();

        let retrieved_ctx1_again = manager.get_compressor_context_mut(cid1).unwrap();
        assert_eq!(
            retrieved_ctx1_again
                .as_any()
                .downcast_ref::<MockCompressorCtx>()
                .unwrap()
                .data,
            "flow1_updated"
        );

        // Get non-existent context
        let result_non_existent = manager.get_compressor_context_mut(99);
        assert!(matches!(
            result_non_existent,
            Err(RohcError::ContextNotFound(99))
        ));
    }

    #[test]
    fn add_and_get_decompressor_context() {
        let mut manager = ContextManager::new();
        let ctx1: Box<dyn RohcDecompressorContext> =
            Box::new(MockDecompressorCtx { cid: 2, updates: 0 });
        let cid1 = ctx1.cid(); // Get CID before move
        manager.add_decompressor_context(cid1, ctx1);

        assert_eq!(manager.decompressor_context_count(), 1);

        let retrieved_ctx1 = manager.get_decompressor_context_mut(cid1).unwrap();
        assert_eq!(retrieved_ctx1.cid(), cid1);
        retrieved_ctx1
            .as_any_mut()
            .downcast_mut::<MockDecompressorCtx>()
            .unwrap()
            .updates += 1;

        let retrieved_ctx1_again = manager.get_decompressor_context_mut(cid1).unwrap();
        assert_eq!(
            retrieved_ctx1_again
                .as_any()
                .downcast_ref::<MockDecompressorCtx>()
                .unwrap()
                .updates,
            1
        );

        let result_non_existent = manager.get_decompressor_context_mut(100);
        assert!(matches!(
            result_non_existent,
            Err(RohcError::ContextNotFound(100))
        ));
    }

    #[test]
    fn remove_contexts() {
        let mut manager = ContextManager::new();
        manager.add_compressor_context(
            1,
            Box::new(MockCompressorCtx {
                cid: 1,
                data: "".to_string(),
            }),
        );
        manager.add_decompressor_context(2, Box::new(MockDecompressorCtx { cid: 2, updates: 0 }));

        assert_eq!(manager.compressor_context_count(), 1);
        assert_eq!(manager.decompressor_context_count(), 1);

        let removed_comp_ctx = manager.remove_compressor_context(1);
        assert!(removed_comp_ctx.is_some());
        assert_eq!(removed_comp_ctx.unwrap().cid(), 1);
        assert_eq!(manager.compressor_context_count(), 0);
        assert!(manager.remove_compressor_context(1).is_none()); // Already removed

        let removed_decomp_ctx = manager.remove_decompressor_context(2);
        assert!(removed_decomp_ctx.is_some());
        assert_eq!(removed_decomp_ctx.unwrap().cid(), 2);
        assert_eq!(manager.decompressor_context_count(), 0);
    }

    #[test]
    fn clear_contexts() {
        let mut manager = ContextManager::new();
        manager.add_compressor_context(
            1,
            Box::new(MockCompressorCtx {
                cid: 1,
                data: "".to_string(),
            }),
        );
        manager.add_compressor_context(
            2,
            Box::new(MockCompressorCtx {
                cid: 2,
                data: "".to_string(),
            }),
        );
        manager.add_decompressor_context(3, Box::new(MockDecompressorCtx { cid: 3, updates: 0 }));
        manager.add_decompressor_context(4, Box::new(MockDecompressorCtx { cid: 4, updates: 0 }));

        assert_eq!(manager.compressor_context_count(), 2);
        assert_eq!(manager.decompressor_context_count(), 2);

        manager.clear_compressor_contexts();
        assert_eq!(manager.compressor_context_count(), 0);
        assert_eq!(manager.decompressor_context_count(), 2); // Decompressors should remain

        manager.clear_all_contexts();
        assert_eq!(manager.decompressor_context_count(), 0);
    }

    #[test]
    fn overwrite_context() {
        let mut manager = ContextManager::new();
        let ctx_v1: Box<dyn RohcCompressorContext> = Box::new(MockCompressorCtx {
            cid: 1,
            data: "version1".to_string(),
        });
        manager.add_compressor_context(1, ctx_v1);
        assert_eq!(
            manager
                .get_compressor_context_mut(1)
                .unwrap()
                .as_any()
                .downcast_ref::<MockCompressorCtx>()
                .unwrap()
                .data,
            "version1"
        );

        let ctx_v2: Box<dyn RohcCompressorContext> = Box::new(MockCompressorCtx {
            cid: 1,
            data: "version2".to_string(),
        });
        manager.add_compressor_context(1, ctx_v2); // Overwrite
        assert_eq!(manager.compressor_context_count(), 1);
        assert_eq!(
            manager
                .get_compressor_context_mut(1)
                .unwrap()
                .as_any()
                .downcast_ref::<MockCompressorCtx>()
                .unwrap()
                .data,
            "version2"
        );
    }
}
