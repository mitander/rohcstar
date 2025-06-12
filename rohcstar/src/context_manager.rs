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
use crate::types::ContextId;

/// Manages multiple ROHC contexts (both compressor and decompressor) indexed by CID.
///
/// This manager is designed to be generic and can store contexts for any ROHC profile
/// that implements the `RohcCompressorContext` and `RohcDecompressorContext` traits.
/// The actual creation of contexts is delegated to a `ProfileHandler` (managed by the ROHC Engine).
#[derive(Debug, Default)]
pub struct ContextManager {
    /// Stores active compressor contexts, keyed by their Context ID (CID).
    compressor_contexts: HashMap<ContextId, Box<dyn RohcCompressorContext>>,
    /// Stores active decompressor contexts, keyed by their Context ID (CID).
    decompressor_contexts: HashMap<ContextId, Box<dyn RohcDecompressorContext>>,
}

impl ContextManager {
    /// Creates a new, empty `ContextManager`.
    ///
    /// # Returns
    /// A new `ContextManager` instance with no active contexts.
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
    pub fn add_compressor_context(
        &mut self,
        cid: ContextId,
        context: Box<dyn RohcCompressorContext>,
    ) {
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
        cid: ContextId,
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
    /// A mutable reference to the compressor context.
    ///
    /// # Errors
    /// - [`RohcError::ContextNotFound`] - No context exists for the given CID
    pub fn get_compressor_context_mut(
        &mut self,
        cid: ContextId,
    ) -> Result<&mut Box<dyn RohcCompressorContext>, RohcError> {
        self.compressor_contexts
            .get_mut(&cid)
            .ok_or(RohcError::ContextNotFound(cid.into()))
    }

    /// Retrieves a mutable reference to a decompressor context by its CID.
    ///
    /// # Parameters
    /// - `cid`: The Context ID of the decompressor context to retrieve.
    ///
    /// # Returns
    /// A mutable reference to the decompressor context.
    ///
    /// # Errors
    /// - [`RohcError::ContextNotFound`] - No context exists for the given CID
    pub fn get_decompressor_context_mut(
        &mut self,
        cid: ContextId,
    ) -> Result<&mut Box<dyn RohcDecompressorContext>, RohcError> {
        self.decompressor_contexts
            .get_mut(&cid)
            .ok_or(RohcError::ContextNotFound(cid.into()))
    }

    /// Retrieves an immutable reference to a compressor context by its CID.
    ///
    /// # Parameters
    /// - `cid`: The Context ID of the compressor context to retrieve.
    ///
    /// # Returns
    /// An immutable reference to the compressor context.
    ///
    /// # Errors
    /// - [`RohcError::ContextNotFound`] - No context exists for the given CID
    pub fn get_compressor_context(
        &self,
        cid: ContextId,
    ) -> Result<&dyn RohcCompressorContext, RohcError> {
        self.compressor_contexts
            .get(&cid)
            .map(|boxed_context_ref| {
                let context_ref: &dyn RohcCompressorContext = &**boxed_context_ref;
                context_ref
            })
            .ok_or(RohcError::ContextNotFound(cid.into()))
    }

    /// Retrieves an immutable reference to a decompressor context by its CID.
    ///
    /// # Parameters
    /// - `cid`: The Context ID of the decompressor context to retrieve.
    ///
    /// # Returns
    /// An immutable reference to the decompressor context.
    ///
    /// # Errors
    /// - [`RohcError::ContextNotFound`] - No context exists for the given CID
    pub fn get_decompressor_context(
        &self,
        cid: ContextId,
    ) -> Result<&dyn RohcDecompressorContext, RohcError> {
        self.decompressor_contexts
            .get(&cid)
            .map(|boxed_context_ref| {
                let context_ref: &dyn RohcDecompressorContext = &**boxed_context_ref;
                context_ref
            })
            .ok_or(RohcError::ContextNotFound(cid.into()))
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
        cid: ContextId,
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
        cid: ContextId,
    ) -> Option<Box<dyn RohcDecompressorContext>> {
        self.decompressor_contexts.remove(&cid)
    }

    /// Clears all compressor contexts from the manager.
    ///
    /// Removes all active compressor contexts, freeing their resources.
    /// This operation is irreversible.
    pub fn clear_compressor_contexts(&mut self) {
        self.compressor_contexts.clear();
    }

    /// Clears all decompressor contexts from the manager.
    ///
    /// Removes all active decompressor contexts, freeing their resources.
    /// This operation is irreversible.
    pub fn clear_decompressor_contexts(&mut self) {
        self.decompressor_contexts.clear();
    }

    /// Clears all contexts (both compressor and decompressor) from the manager.
    ///
    /// Removes all active contexts of both types, effectively resetting the manager
    /// to an empty state. This operation is irreversible.
    pub fn clear_all_contexts(&mut self) {
        self.clear_compressor_contexts();
        self.clear_decompressor_contexts();
    }

    /// Returns the number of active compressor contexts.
    ///
    /// # Returns
    /// The count of currently managed compressor contexts.
    pub fn compressor_context_count(&self) -> usize {
        self.compressor_contexts.len()
    }

    /// Returns the number of active decompressor contexts.
    ///
    /// # Returns
    /// The count of currently managed decompressor contexts.
    pub fn decompressor_context_count(&self) -> usize {
        self.decompressor_contexts.len()
    }

    /// Returns an immutable iterator over compressor contexts.
    ///
    /// Used by the RohcEngine for operations like pruning stale contexts.
    ///
    /// # Returns
    /// An iterator yielding (CID, context) pairs for all active compressor contexts.
    pub fn compressor_contexts_iter(
        &self,
    ) -> impl Iterator<Item = (&ContextId, &Box<dyn RohcCompressorContext>)> {
        self.compressor_contexts.iter()
    }

    /// Returns an immutable iterator over decompressor contexts.
    ///
    /// Used by the RohcEngine for operations like pruning stale contexts.
    ///
    /// # Returns
    /// An iterator yielding (CID, context) pairs for all active decompressor contexts.
    pub fn decompressor_contexts_iter(
        &self,
    ) -> impl Iterator<Item = (&ContextId, &Box<dyn RohcDecompressorContext>)> {
        self.decompressor_contexts.iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet_defs::RohcProfile;
    use crate::traits::{RohcCompressorContext, RohcDecompressorContext};
    use std::any::Any;
    use std::time::Instant;

    #[derive(Debug)]
    struct MockCompressorCtx {
        cid: ContextId,
        data: String,
        last_accessed: Instant,
    }

    impl RohcCompressorContext for MockCompressorCtx {
        fn profile_id(&self) -> RohcProfile {
            RohcProfile::Uncompressed
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
    struct MockDecompressorCtx {
        cid: ContextId,
        updates: u32,
        last_accessed: Instant,
    }

    impl RohcDecompressorContext for MockDecompressorCtx {
        fn profile_id(&self) -> RohcProfile {
            RohcProfile::RtpUdpIp
        }
        fn cid(&self) -> ContextId {
            self.cid
        }
        fn assign_cid(&mut self, new_cid: ContextId) {
            self.cid = new_cid;
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

    #[test]
    fn context_manager_new_is_empty() {
        let manager = ContextManager::new();
        assert_eq!(manager.compressor_context_count(), 0);
        assert_eq!(manager.decompressor_context_count(), 0);
    }

    #[test]
    fn add_and_get_compressor_context() {
        let mut manager = ContextManager::new();
        let initial_time = Instant::now();
        let ctx1: Box<dyn RohcCompressorContext> = Box::new(MockCompressorCtx {
            cid: 1.into(),
            data: "flow1".to_string(),
            last_accessed: initial_time,
        });
        let cid1 = ctx1.cid();
        manager.add_compressor_context(cid1, ctx1);

        assert_eq!(manager.compressor_context_count(), 1);

        let retrieved_ctx1_mut = manager.get_compressor_context_mut(cid1).unwrap();
        assert_eq!(retrieved_ctx1_mut.cid(), cid1);
        assert_eq!(retrieved_ctx1_mut.last_accessed(), initial_time);

        // Simulate access
        retrieved_ctx1_mut.update_access_time(Instant::now());
        let time_after_update = retrieved_ctx1_mut.last_accessed();
        assert!(time_after_update > initial_time);

        retrieved_ctx1_mut
            .as_any_mut()
            .downcast_mut::<MockCompressorCtx>()
            .unwrap()
            .data = "flow1_updated".to_string();

        let retrieved_ctx1_again = manager.get_compressor_context(cid1).unwrap();
        assert_eq!(
            retrieved_ctx1_again
                .as_any()
                .downcast_ref::<MockCompressorCtx>()
                .unwrap()
                .data,
            "flow1_updated"
        );
        assert_eq!(retrieved_ctx1_again.last_accessed(), time_after_update); // Check time persists

        let result_non_existent = manager.get_compressor_context_mut(99.into());
        assert!(matches!(
            result_non_existent,
            Err(RohcError::ContextNotFound(99))
        ));
    }

    #[test]
    fn add_and_get_decompressor_context() {
        let mut manager = ContextManager::new();
        let initial_time = Instant::now();
        let ctx1: Box<dyn RohcDecompressorContext> = Box::new(MockDecompressorCtx {
            cid: 2.into(),
            updates: 0,
            last_accessed: initial_time,
        });
        let cid1 = ctx1.cid();
        manager.add_decompressor_context(cid1, ctx1);

        assert_eq!(manager.decompressor_context_count(), 1);

        let retrieved_ctx1_mut = manager.get_decompressor_context_mut(cid1).unwrap();
        assert_eq!(retrieved_ctx1_mut.cid(), cid1);
        assert_eq!(retrieved_ctx1_mut.last_accessed(), initial_time);

        retrieved_ctx1_mut.update_access_time(Instant::now());
        let time_after_update = retrieved_ctx1_mut.last_accessed();
        assert!(time_after_update > initial_time);

        retrieved_ctx1_mut
            .as_any_mut()
            .downcast_mut::<MockDecompressorCtx>()
            .unwrap()
            .updates += 1;

        let retrieved_ctx1_again = manager.get_decompressor_context(cid1).unwrap();
        assert_eq!(
            retrieved_ctx1_again
                .as_any()
                .downcast_ref::<MockDecompressorCtx>()
                .unwrap()
                .updates,
            1
        );
        assert_eq!(retrieved_ctx1_again.last_accessed(), time_after_update);

        let result_non_existent = manager.get_decompressor_context_mut(100.into());
        assert!(matches!(
            result_non_existent,
            Err(RohcError::ContextNotFound(100))
        ));
    }

    #[test]
    fn remove_contexts() {
        let mut manager = ContextManager::new();
        manager.add_compressor_context(
            1.into(),
            Box::new(MockCompressorCtx {
                cid: 1.into(),
                data: "".to_string(),
                last_accessed: Instant::now(),
            }),
        );
        manager.add_decompressor_context(
            2.into(),
            Box::new(MockDecompressorCtx {
                cid: 2.into(),
                updates: 0,
                last_accessed: Instant::now(),
            }),
        );

        assert_eq!(manager.compressor_context_count(), 1);
        assert_eq!(manager.decompressor_context_count(), 1);

        let removed_comp_ctx = manager.remove_compressor_context(1.into());
        assert!(removed_comp_ctx.is_some());
        assert_eq!(removed_comp_ctx.unwrap().cid(), 1);
        assert_eq!(manager.compressor_context_count(), 0);
        assert!(manager.remove_compressor_context(1.into()).is_none());

        let removed_decomp_ctx = manager.remove_decompressor_context(2.into());
        assert!(removed_decomp_ctx.is_some());
        assert_eq!(removed_decomp_ctx.unwrap().cid(), 2);
        assert_eq!(manager.decompressor_context_count(), 0);
    }

    #[test]
    fn clear_contexts() {
        let mut manager = ContextManager::new();
        manager.add_compressor_context(
            1.into(),
            Box::new(MockCompressorCtx {
                cid: 1.into(),
                data: "".to_string(),
                last_accessed: Instant::now(),
            }),
        );
        manager.add_compressor_context(
            2.into(),
            Box::new(MockCompressorCtx {
                cid: 2.into(),
                data: "".to_string(),
                last_accessed: Instant::now(),
            }),
        );
        manager.add_decompressor_context(
            3.into(),
            Box::new(MockDecompressorCtx {
                cid: 3.into(),
                updates: 0,
                last_accessed: Instant::now(),
            }),
        );
        manager.add_decompressor_context(
            4.into(),
            Box::new(MockDecompressorCtx {
                cid: 3.into(),
                updates: 0,
                last_accessed: Instant::now(),
            }),
        );

        assert_eq!(manager.compressor_context_count(), 2);
        assert_eq!(manager.decompressor_context_count(), 2);

        manager.clear_compressor_contexts();
        assert_eq!(manager.compressor_context_count(), 0);
        assert_eq!(manager.decompressor_context_count(), 2);

        manager.clear_all_contexts();
        assert_eq!(manager.decompressor_context_count(), 0);
    }

    #[test]
    fn overwrite_context() {
        let mut manager = ContextManager::new();
        let time1 = Instant::now();
        let ctx_v1: Box<dyn RohcCompressorContext> = Box::new(MockCompressorCtx {
            cid: 1.into(),
            data: "version1".to_string(),
            last_accessed: time1,
        });
        manager.add_compressor_context(1.into(), ctx_v1);
        let retrieved_v1 = manager.get_compressor_context(1.into()).unwrap();
        assert_eq!(
            retrieved_v1
                .as_any()
                .downcast_ref::<MockCompressorCtx>()
                .unwrap()
                .data,
            "version1"
        );
        assert_eq!(retrieved_v1.last_accessed(), time1);

        let time2 = Instant::now();
        assert!(time2 > time1); // Ensure time has advanced
        let ctx_v2: Box<dyn RohcCompressorContext> = Box::new(MockCompressorCtx {
            cid: 1.into(), // Same CID
            data: "version2".to_string(),
            last_accessed: time2,
        });
        manager.add_compressor_context(1.into(), ctx_v2); // Overwrite
        assert_eq!(manager.compressor_context_count(), 1);
        let retrieved_v2 = manager.get_compressor_context(1.into()).unwrap();
        assert_eq!(
            retrieved_v2
                .as_any()
                .downcast_ref::<MockCompressorCtx>()
                .unwrap()
                .data,
            "version2"
        );
        assert_eq!(retrieved_v2.last_accessed(), time2); // Check the new context's time
    }
}
