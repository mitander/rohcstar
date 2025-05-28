//! The ROHC (Robust Header Compression) Engine.
//!
//! This module provides the `RohcEngine`, which is the central orchestrator for
//! ROHC compression and decompression operations. It manages different ROHC
//! profile handlers and their associated contexts, including context timeout logic.

use std::collections::HashMap;
use std::fmt::Debug;
use std::sync::Arc;
use std::time::Duration;

use crate::constants::{
    ROHC_GENERIC_IR_D_BIT_MASK, ROHC_GENERIC_IR_PACKET_TYPE_BASE, ROHC_SMALL_CID_MASK,
};
use crate::context_manager::ContextManager;
use crate::error::{RohcError, RohcParsingError};
use crate::packet_defs::{GenericUncompressedHeaders, RohcProfile};
use crate::time::{Clock, SystemClock};
use crate::traits::ProfileHandler;

/// The main ROHC processing engine.
#[derive(Debug)]
pub struct RohcEngine {
    profile_handlers: HashMap<RohcProfile, Box<dyn ProfileHandler>>,
    context_manager: ContextManager,
    default_ir_refresh_interval: u32,
    /// Duration after which an inactive context is considered stale and can be pruned.
    context_timeout: Duration,
    clock: Arc<dyn Clock>,
}

impl RohcEngine {
    /// Creates a new `RohcEngine`.
    ///
    /// # Parameters
    /// - `default_ir_refresh_interval`: Default IR refresh interval for new compressor contexts.
    /// - `context_timeout`: Duration after which inactive contexts are considered stale.
    pub fn new(
        default_ir_refresh_interval: u32,
        context_timeout: Duration,
        clock: Arc<dyn Clock>,
    ) -> Self {
        RohcEngine {
            profile_handlers: HashMap::new(),
            context_manager: ContextManager::new(),
            default_ir_refresh_interval,
            context_timeout,
            clock,
        }
    }

    /// Registers a ROHC profile handler with the engine.
    ///
    /// # Parameters
    /// - `handler`: A `Box<dyn ProfileHandler>` for the profile.
    ///
    /// # Returns
    /// `Ok(())` or `Err(RohcError::Internal)` if profile already registered.
    pub fn register_profile_handler(
        &mut self,
        handler: Box<dyn ProfileHandler>,
    ) -> Result<(), RohcError> {
        let profile_id = handler.profile_id();
        if self.profile_handlers.contains_key(&profile_id) {
            return Err(RohcError::Internal(format!(
                "Profile handler for {:?} already registered.",
                profile_id
            )));
        }
        self.profile_handlers.insert(profile_id, handler);
        Ok(())
    }

    /// Compresses uncompressed headers for a given Context ID (CID).
    /// Updates the context's last accessed time on success.
    ///
    /// # Parameters
    /// - `cid`: The Context ID for the flow.
    /// - `profile_id_hint`: Optional `RohcProfile` hint for new context creation.
    /// - `uncompressed_headers`: The `GenericUncompressedHeaders` to compress.
    ///
    /// # Returns
    /// `Result<Vec<u8>, RohcError>` containing the compressed ROHC packet.
    pub fn compress(
        &mut self,
        cid: u16,
        profile_id_hint: Option<RohcProfile>,
        uncompressed_headers: &GenericUncompressedHeaders,
    ) -> Result<Vec<u8>, RohcError> {
        // Attempt to get an existing compressor context
        match self.context_manager.get_compressor_context_mut(cid) {
            Ok(context_box) => {
                // Found existing context, get its profile and handler
                let profile_id = context_box.profile_id();
                let handler = self.profile_handlers.get(&profile_id).ok_or_else(|| {
                    RohcError::Internal(format!(
                        "Compressor context for CID {} (profile {:?}) exists, but no handler registered.",
                        cid, profile_id
                    ))
                })?;
                let result = handler.compress(context_box.as_mut(), uncompressed_headers);

                if result.is_ok() {
                    // Success: update last access
                    context_box.set_last_accessed(self.clock.now());
                }
                result
            }
            Err(RohcError::ContextNotFound(_)) => {
                // Context not found, create a new one
                let profile_to_use = profile_id_hint.ok_or_else(|| {
                    RohcError::Internal(format!(
                        "Cannot create new compressor context for CID {} without profile hint.",
                        cid
                    ))
                })?;
                let handler = self
                    .profile_handlers
                    .get(&profile_to_use)
                    .ok_or_else(|| RohcError::UnsupportedProfile(profile_to_use.into()))?;

                let mut new_context = handler.create_compressor_context(
                    cid,
                    self.default_ir_refresh_interval,
                    self.clock.now(),
                );
                // First compression call will typically send IR and initialize/update context
                let result = handler.compress(new_context.as_mut(), uncompressed_headers);
                if result.is_ok() {
                    // Success: update last access
                    new_context.set_last_accessed(self.clock.now());
                }
                self.context_manager
                    .add_compressor_context(cid, new_context);
                result
            }
            Err(e) => Err(e), // Other errors from get_compressor_context_mut
        }
    }

    /// Decompresses an incoming ROHC packet.
    /// Updates the context's last accessed time on success.
    ///
    /// # Parameters
    /// - `rohc_packet_bytes`: Byte slice of the complete incoming ROHC packet.
    ///
    /// # Returns
    /// `Result<GenericUncompressedHeaders, RohcError>` with reconstructed headers.
    pub fn decompress(
        &mut self,
        rohc_packet_bytes: &[u8],
    ) -> Result<GenericUncompressedHeaders, RohcError> {
        if rohc_packet_bytes.is_empty() {
            return Err(RohcError::Parsing(RohcParsingError::NotEnoughData {
                needed: 1,
                got: 0,
                context: "ROHC packet input".to_string(),
            }));
        }

        let (cid, _, core_packet_slice) = self.parse_cid_from_packet(rohc_packet_bytes)?;
        if core_packet_slice.is_empty() {
            return Err(RohcError::Parsing(RohcParsingError::NotEnoughData {
                needed: 1,
                got: 0,
                context: "Core ROHC packet after CID processing".to_string(),
            }));
        }

        match self.context_manager.get_decompressor_context_mut(cid) {
            Ok(context_box) => {
                let profile_id = context_box.profile_id();
                let handler = self.profile_handlers.get(&profile_id).ok_or_else(|| {
                    RohcError::Internal(format!(
                        "Decompressor context for CID {} (profile {:?}) exists, but no handler registered.",
                        cid, profile_id
                    ))
                })?;
                let result = handler.decompress(context_box.as_mut(), core_packet_slice);
                if result.is_ok() {
                    context_box.set_last_accessed(self.clock.now());
                }
                result
            }
            Err(RohcError::ContextNotFound(_)) => {
                // Context not found, attempt to create from IR packet
                let profile_id = self.peek_profile_from_core_packet(core_packet_slice)?;
                let handler = self
                    .profile_handlers
                    .get(&profile_id)
                    .ok_or_else(|| RohcError::UnsupportedProfile(profile_id.into()))?;

                let mut new_context = handler.create_decompressor_context(cid, self.clock.now());
                let result = handler.decompress(new_context.as_mut(), core_packet_slice);
                if result.is_ok() {
                    // Success: update last access
                    new_context.set_last_accessed(self.clock.now());
                }
                self.context_manager
                    .add_decompressor_context(cid, new_context);
                result
            }
            Err(e) => Err(e),
        }
    }

    /// Parses CID from a ROHC packet, handling Add-CID octets.
    ///
    /// # Parameters
    /// - `rohc_packet_bytes`: Slice of the ROHC packet.
    ///
    /// # Returns
    /// Tuple `(cid, is_add_cid_present, core_packet_slice)` or `RohcError`.
    fn parse_cid_from_packet<'a>(
        &self,
        rohc_packet_bytes: &'a [u8],
    ) -> Result<(u16, bool, &'a [u8]), RohcError> {
        // (Implementation from previous step is fine here, no timeout logic directly involves it)
        if rohc_packet_bytes.is_empty() {
            return Err(RohcError::Parsing(RohcParsingError::NotEnoughData {
                needed: 1,
                got: 0,
                context: "CID parsing".to_string(),
            }));
        }
        let first_byte = rohc_packet_bytes[0];
        // Check for Add-CID octet (1110xxxx prefix)
        if (first_byte >> 4) == 0b1110 {
            let cid_val = (first_byte & ROHC_SMALL_CID_MASK) as u16;
            Ok((cid_val, true, &rohc_packet_bytes[1..]))
        } else {
            // No Add-CID, or it's another packet type (like IR for CID 0). Assume implicit CID 0.
            Ok((0, false, rohc_packet_bytes))
        }
    }

    /// Peeks profile ID from a core ROHC packet (typically IR).
    ///
    /// # Parameters
    /// - `core_packet_slice`: Packet data after Add-CID processing.
    ///
    /// # Returns
    /// Inferred `RohcProfile` or `RohcError`.
    fn peek_profile_from_core_packet(
        &self,
        core_packet_slice: &[u8],
    ) -> Result<RohcProfile, RohcError> {
        // (Implementation from previous step is fine)
        if core_packet_slice.len() < 2 {
            // Need type byte + profile byte
            return Err(RohcError::Parsing(RohcParsingError::NotEnoughData {
                needed: 2,
                got: core_packet_slice.len(),
                context: "Peeking profile ID from core packet".to_string(),
            }));
        }
        let packet_type_octet = core_packet_slice[0];
        // Check if it's an IR packet (1111110D)
        if (packet_type_octet & !ROHC_GENERIC_IR_D_BIT_MASK) == ROHC_GENERIC_IR_PACKET_TYPE_BASE {
            let profile_id_byte = core_packet_slice[1];
            Ok(RohcProfile::from(profile_id_byte))
        } else {
            Err(RohcError::InvalidState(
                "Cannot determine ROHC profile from non-IR packet for new CID.".to_string(),
            ))
        }
    }

    /// Removes stale compressor and decompressor contexts that haven't been accessed
    /// within the configured `context_timeout`.
    ///
    /// This method should be called periodically by the application using the RohcEngine
    /// to manage context lifecycle and prevent resource leaks.
    pub fn prune_stale_contexts(&mut self) {
        let now = self.clock.now();
        let timeout_duration = self.context_timeout;

        // Identify stale compressor CIDs
        let stale_compressor_cids: Vec<u16> = self
            .context_manager
            .compressor_contexts_iter()
            .filter_map(|(cid, context_box)| {
                // Check if context has been inactive longer than the timeout duration
                if now.duration_since(context_box.last_accessed()) > timeout_duration {
                    Some(*cid)
                } else {
                    None
                }
            })
            .collect();

        // Remove stale compressor contexts
        for cid in stale_compressor_cids {
            self.context_manager.remove_compressor_context(cid);
            // Example: log::debug!("RohcEngine: Pruned stale compressor context for CID: {}", cid);
        }

        // Identify stale decompressor CIDs
        let stale_decompressor_cids: Vec<u16> = self
            .context_manager
            .decompressor_contexts_iter()
            .filter_map(|(cid, context_box)| {
                if now.duration_since(context_box.last_accessed()) > timeout_duration {
                    Some(*cid)
                } else {
                    None
                }
            })
            .collect();

        // Remove stale decompressor contexts
        for cid in stale_decompressor_cids {
            self.context_manager.remove_decompressor_context(cid);
            // Example: log::debug!("RohcEngine: Pruned stale decompressor context for CID: {}", cid);
        }
    }

    /// Provides access to the underlying `ContextManager`.
    pub fn context_manager(&self) -> &ContextManager {
        &self.context_manager
    }

    /// Provides mutable access to the underlying `ContextManager`.
    pub fn context_manager_mut(&mut self) -> &mut ContextManager {
        &mut self.context_manager
    }
}

impl Default for RohcEngine {
    fn default() -> Self {
        Self::new(
            crate::constants::DEFAULT_IR_REFRESH_INTERVAL,
            Duration::from_secs(60 * 5), // Default context timeout: 5 minutes
            Arc::new(SystemClock),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::{ROHC_ADD_CID_FEEDBACK_PREFIX_VALUE, ROHC_SMALL_CID_MASK};
    use crate::profiles::profile1::protocol_types::Timestamp;
    use crate::profiles::profile1::{
        P1_BASE_DYNAMIC_CHAIN_LENGTH_BYTES, P1_ROHC_IR_PACKET_TYPE_WITH_DYN,
        P1_STATIC_CHAIN_LENGTH_BYTES, P1_UO_1_SN_MARKER_BIT_MASK, P1_UO_1_SN_PACKET_TYPE_PREFIX,
        Profile1Handler, RtpUdpIpv4Headers,
    };
    use crate::time::mock_clock::MockClock;
    use std::time::Duration;
    use std::time::Instant;

    const DEFAULT_TEST_TIMEOUT: Duration = Duration::from_secs(60 * 5);

    // Helper function from your tests, ensure it's defined or accessible
    fn create_test_rtp_headers_for_engine(sn: u16, ts: u32, marker: bool) -> RtpUdpIpv4Headers {
        RtpUdpIpv4Headers {
            ip_src: "192.168.1.10".parse().unwrap(),
            ip_dst: "192.168.1.20".parse().unwrap(),
            udp_src_port: 10010,
            udp_dst_port: 20020,
            rtp_ssrc: 0xAABBCCDD,
            rtp_sequence_number: sn,
            rtp_timestamp: Timestamp::new(ts),
            rtp_marker: marker,
            ..Default::default()
        }
    }

    #[test]
    fn engine_new_and_register_handler() {
        let mock_clock = Arc::new(MockClock::new(Instant::now()));
        let mut engine = RohcEngine::new(20, DEFAULT_TEST_TIMEOUT, mock_clock);
        assert_eq!(engine.profile_handlers.len(), 0);
        assert_eq!(engine.context_timeout, DEFAULT_TEST_TIMEOUT);

        let p1_handler: Box<dyn ProfileHandler> = Box::new(Profile1Handler::new());
        engine.register_profile_handler(p1_handler).unwrap();
        assert_eq!(engine.profile_handlers.len(), 1);
        assert!(engine.profile_handlers.contains_key(&RohcProfile::RtpUdpIp));

        let p1_handler_again: Box<dyn ProfileHandler> = Box::new(Profile1Handler::new());
        let result = engine.register_profile_handler(p1_handler_again);
        assert!(matches!(result, Err(RohcError::Internal(_))));
    }

    #[test]
    fn engine_compress_decompress_cid0_flow() {
        let mock_clock = Arc::new(MockClock::new(Instant::now()));
        let mut engine = RohcEngine::new(5, DEFAULT_TEST_TIMEOUT, mock_clock);
        engine
            .register_profile_handler(Box::new(Profile1Handler::new()))
            .unwrap();

        let headers1 = create_test_rtp_headers_for_engine(100, 1000, false);
        let generic_headers1 = GenericUncompressedHeaders::RtpUdpIpv4(headers1.clone());
        let compressed1 = engine
            .compress(0, Some(RohcProfile::RtpUdpIp), &generic_headers1)
            .unwrap();
        assert!(!compressed1.is_empty());
        assert_eq!(compressed1[0], P1_ROHC_IR_PACKET_TYPE_WITH_DYN);

        let decompressed_generic1 = engine.decompress(&compressed1).unwrap();
        match decompressed_generic1 {
            GenericUncompressedHeaders::RtpUdpIpv4(h) => {
                assert_eq!(h.rtp_ssrc, headers1.rtp_ssrc);
                assert_eq!(h.rtp_sequence_number, headers1.rtp_sequence_number);
            }
            _ => panic!("Unexpected decompressed header type"),
        }
        assert_eq!(engine.context_manager.compressor_context_count(), 1);
        assert_eq!(engine.context_manager.decompressor_context_count(), 1);

        let headers2 = create_test_rtp_headers_for_engine(101, 1000, false); // UO-0 conditions
        let generic_headers2 = GenericUncompressedHeaders::RtpUdpIpv4(headers2.clone());
        let compressed2 = engine
            .compress(0, Some(RohcProfile::RtpUdpIp), &generic_headers2)
            .unwrap();
        assert_eq!(compressed2.len(), 1);

        let decompressed_generic2 = engine.decompress(&compressed2).unwrap();
        match decompressed_generic2 {
            GenericUncompressedHeaders::RtpUdpIpv4(h) => {
                assert_eq!(h.rtp_ssrc, headers1.rtp_ssrc);
                assert_eq!(h.rtp_sequence_number, headers2.rtp_sequence_number);
                assert_eq!(h.rtp_timestamp, headers1.rtp_timestamp);
                assert_eq!(h.rtp_marker, headers1.rtp_marker);
            }
            _ => panic!("Unexpected decompressed header type"),
        }
    }

    #[test]
    fn engine_compress_decompress_add_cid_flow() {
        let mock_clock = Arc::new(MockClock::new(Instant::now()));
        let mut engine = RohcEngine::new(5, DEFAULT_TEST_TIMEOUT, mock_clock);
        engine
            .register_profile_handler(Box::new(Profile1Handler::new()))
            .unwrap();
        let cid: u16 = 5;

        let headers1 = create_test_rtp_headers_for_engine(200, 2000, true);
        let generic_headers1 = GenericUncompressedHeaders::RtpUdpIpv4(headers1.clone());
        let compressed1 = engine
            .compress(cid, Some(RohcProfile::RtpUdpIp), &generic_headers1)
            .unwrap();

        assert!(!compressed1.is_empty());
        assert_eq!(
            compressed1[0],
            ROHC_ADD_CID_FEEDBACK_PREFIX_VALUE | (cid as u8 & ROHC_SMALL_CID_MASK)
        );
        assert_eq!(compressed1[1], P1_ROHC_IR_PACKET_TYPE_WITH_DYN);

        let decompressed_generic1 = engine.decompress(&compressed1).unwrap();
        match decompressed_generic1 {
            GenericUncompressedHeaders::RtpUdpIpv4(h) => {
                assert_eq!(h.rtp_ssrc, headers1.rtp_ssrc);
                assert_eq!(h.rtp_sequence_number, headers1.rtp_sequence_number);
                assert_eq!(h.rtp_marker, headers1.rtp_marker);
            }
            _ => panic!("Unexpected decompressed header type"),
        }
        assert_eq!(engine.context_manager.compressor_context_count(), 1);
        assert_eq!(engine.context_manager.decompressor_context_count(), 1);

        let headers2 = create_test_rtp_headers_for_engine(201, 2000, false); // Marker changed
        let generic_headers2 = GenericUncompressedHeaders::RtpUdpIpv4(headers2.clone());
        let compressed2 = engine
            .compress(cid, Some(RohcProfile::RtpUdpIp), &generic_headers2)
            .unwrap();

        assert!(compressed2.len() > 1);
        assert_eq!(
            compressed2[0],
            ROHC_ADD_CID_FEEDBACK_PREFIX_VALUE | (cid as u8 & ROHC_SMALL_CID_MASK)
        );
        assert_eq!(
            compressed2[1] & P1_UO_1_SN_PACKET_TYPE_PREFIX,
            P1_UO_1_SN_PACKET_TYPE_PREFIX
        );
        assert_eq!(compressed2[1] & P1_UO_1_SN_MARKER_BIT_MASK, 0);

        let decompressed_generic2 = engine.decompress(&compressed2).unwrap();
        match decompressed_generic2 {
            GenericUncompressedHeaders::RtpUdpIpv4(h) => {
                assert_eq!(h.rtp_ssrc, headers1.rtp_ssrc);
                assert_eq!(h.rtp_sequence_number, headers2.rtp_sequence_number);
                assert_eq!(h.rtp_marker, headers2.rtp_marker);
            }
            _ => panic!("Unexpected decompressed header type"),
        }
    }

    #[test]
    fn decompress_unknown_cid_not_ir_fails_gracefully() {
        let mock_clock = Arc::new(MockClock::new(Instant::now()));
        let mut engine = RohcEngine::new(5, DEFAULT_TEST_TIMEOUT, mock_clock);
        engine
            .register_profile_handler(Box::new(Profile1Handler::new()))
            .unwrap();

        let uo0_packet_cid0 = vec![(0x0A << 3) | 0x05]; // SN=10, CRC=5, for implicit CID 0
        let result = engine.decompress(&uo0_packet_cid0);
        let result_clone = result.clone();

        // Expect error because context for CID 0 doesn't exist and UO-0 cannot init
        assert!(
            matches!(
                result,
                Err(RohcError::Parsing(RohcParsingError::NotEnoughData { needed: 2, got: 1, context}))
                if context == "Peeking profile ID from core packet"
            ),
            "Expected NotEnoughData from peek_profile, got {:?}",
            result_clone
        );

        if let Err(RohcError::InvalidState(msg)) = result_clone {
            assert!(msg.contains("Cannot determine ROHC profile from non-IR packet for new CID"));
        }
    }

    #[test]
    fn decompress_unsupported_profile_in_ir() {
        let mock_clock = Arc::new(MockClock::new(Instant::now()));
        let mut engine = RohcEngine::new(5, DEFAULT_TEST_TIMEOUT, mock_clock);
        engine
            .register_profile_handler(Box::new(Profile1Handler::new()))
            .unwrap();

        let mut fake_ir_packet_bytes = vec![P1_ROHC_IR_PACKET_TYPE_WITH_DYN, 0xFF]; // 0xFF is unsupported
        fake_ir_packet_bytes.extend_from_slice(
            &[0u8; P1_STATIC_CHAIN_LENGTH_BYTES + P1_BASE_DYNAMIC_CHAIN_LENGTH_BYTES + 1],
        );

        let result = engine.decompress(&fake_ir_packet_bytes);
        assert!(matches!(result, Err(RohcError::UnsupportedProfile(0xFF))));
    }

    #[test]
    fn engine_decompress_cid0_context_persistence() {
        let mock_clock = Arc::new(MockClock::new(Instant::now()));
        let mut engine = RohcEngine::new(50, DEFAULT_TEST_TIMEOUT, mock_clock);
        engine
            .register_profile_handler(Box::new(Profile1Handler::new()))
            .unwrap();
        let cid = 0u16;

        let headers_ir = create_test_rtp_headers_for_engine(100, 1000, false);
        let generic_headers_ir = GenericUncompressedHeaders::RtpUdpIpv4(headers_ir);
        let compressed_ir = engine
            .compress(cid, Some(RohcProfile::RtpUdpIp), &generic_headers_ir)
            .unwrap();
        engine
            .decompress(&compressed_ir)
            .expect("Decompression of IR packet failed");

        assert!(
            engine
                .context_manager
                .get_decompressor_context_mut(cid)
                .is_ok()
        );

        let headers_uo0 = create_test_rtp_headers_for_engine(101, 1000, false); // UO-0 conditions
        let generic_headers_uo0 = GenericUncompressedHeaders::RtpUdpIpv4(headers_uo0);
        let compressed_uo0 = engine
            .compress(cid, Some(RohcProfile::RtpUdpIp), &generic_headers_uo0)
            .unwrap();
        let decompressed_generic_uo0 = engine.decompress(&compressed_uo0).unwrap();

        match decompressed_generic_uo0 {
            GenericUncompressedHeaders::RtpUdpIpv4(h) => {
                assert_eq!(h.rtp_sequence_number, 101);
            }
            _ => panic!("Unexpected decompressed header type for UO-0"),
        }
    }

    #[test]
    fn engine_prune_stale_contexts_works() {
        use crate::packet_defs::RohcProfile; // Ensure RohcProfile is in scope
        use crate::profiles::profile1::Profile1Handler; // Ensure Profile1Handler is in scope
        use crate::time::mock_clock::MockClock; // For the mock clock
        use std::sync::Arc;
        use std::time::{Duration, Instant};

        // Define a fixed start time for deterministic testing
        let start_time = Instant::now(); // In a real test suite, you might pick a truly fixed Instant
        let mock_clock = Arc::new(MockClock::new(start_time));
        let short_timeout = Duration::from_millis(100); // Contexts stale after 100ms

        let mut engine = RohcEngine::new(
            5, // default_ir_refresh_interval
            short_timeout,
            mock_clock.clone(),
        );
        engine
            .register_profile_handler(Box::new(Profile1Handler::new()))
            .unwrap();

        let headers = create_test_rtp_headers_for_engine(1, 10, false); // Assuming this helper is available
        let generic_headers = GenericUncompressedHeaders::RtpUdpIpv4(headers);

        let cid10 = 10u16;
        let cid11 = 11u16;
        let cid_fresh = 2u16; // Used in Phase 3

        // --- Phase 1: Prune cid11 contexts, keep cid10 compressor ---

        // Create and access context for cid10. Engine uses mock_clock.now() for last_accessed.
        let _ = engine
            .compress(cid10, Some(RohcProfile::RtpUdpIp), &generic_headers)
            .unwrap();
        // Current time: start_time (let's call this T0)
        // cid10 compressor: last_accessed = T0

        // Advance clock before creating cid11 contexts
        mock_clock.advance(Duration::from_millis(10)); // Clock is now T0 + 10ms
        let compressed_ir_cid11 = engine
            .compress(cid11, Some(RohcProfile::RtpUdpIp), &generic_headers)
            .unwrap();
        // cid11 compressor: last_accessed = T0 + 10ms

        mock_clock.advance(Duration::from_millis(10)); // Clock is now T0 + 20ms
        let _ = engine.decompress(&compressed_ir_cid11).unwrap();
        // cid11 decompressor: last_accessed = T0 + 20ms

        assert_eq!(
            engine.context_manager().compressor_context_count(),
            2,
            "Initial compressor count"
        );
        assert_eq!(
            engine.context_manager().decompressor_context_count(),
            1,
            "Initial decompressor count"
        );

        // Advance clock so cid10 and cid11 are about halfway to stale
        mock_clock.advance(short_timeout / 2); // Clock is now T0 + 20ms + 50ms = T0 + 70ms
        // cid10 age: 70ms
        // cid11 comp age: 60ms
        // cid11 decomp age: 50ms

        // Refresh cid10 to keep it alive
        let _ = engine
            .compress(cid10, Some(RohcProfile::RtpUdpIp), &generic_headers)
            .unwrap();
        // cid10 compressor: last_accessed updated to T0 + 70ms

        // Advance clock so cid11 contexts become stale, but refreshed cid10 does not.
        // We want:
        //   (clock_now - cid11_last_access) > short_timeout
        //   (clock_now - cid10_last_access) < short_timeout
        // Current clock: T0 + 70ms.
        // cid11 comp last access: T0 + 10ms. Age = 60ms.
        // cid11 decomp last access: T0 + 20ms. Age = 50ms.
        // cid10 comp last access: T0 + 70ms. Age = 0ms (relative to this point).
        // If we advance by, say, 60ms:
        // Clock will be T0 + 130ms.
        // cid11 comp age: 120ms (> 100ms timeout) -> STALE
        // cid11 decomp age: 110ms (> 100ms timeout) -> STALE
        // cid10 comp age: 60ms (< 100ms timeout) -> FRESH
        mock_clock.advance(Duration::from_millis(60));

        engine.prune_stale_contexts();

        assert_eq!(
            engine.context_manager().compressor_context_count(),
            1,
            "Compressor contexts after first prune"
        );
        assert!(
            engine
                .context_manager()
                .get_compressor_context(cid10)
                .is_ok(),
            "CID 10 compressor should remain"
        );
        assert!(
            engine
                .context_manager()
                .get_compressor_context(cid11)
                .is_err(),
            "CID 11 compressor should be pruned"
        );
        assert_eq!(
            engine.context_manager().decompressor_context_count(),
            0,
            "Decompressor contexts after first prune"
        );
        assert!(
            engine
                .context_manager()
                .get_decompressor_context(cid11)
                .is_err(),
            "CID 11 decompressor should be pruned"
        );

        // --- Phase 2: Test pruning of the remaining cid10 context ---
        // cid10 was last accessed when clock was T0 + 70ms.
        // Current clock is T0 + 130ms. Its age is 60ms.
        // To make it stale (age > 100ms), we need to advance by > 40ms. Let's advance by 50ms.
        mock_clock.advance(Duration::from_millis(50)); // Clock is now T0 + 180ms. cid10 age is 110ms.

        engine.prune_stale_contexts();
        assert_eq!(
            engine.context_manager().compressor_context_count(),
            0,
            "CID 10 compressor should now be pruned"
        );
        assert!(
            engine
                .context_manager()
                .get_compressor_context(cid10)
                .is_err()
        );

        // --- Phase 3: Test fresh context survives a prune if accessed within timeout ---
        // Clock is T0 + 180ms
        let _ = engine
            .compress(cid_fresh, Some(RohcProfile::RtpUdpIp), &generic_headers)
            .unwrap();
        // cid_fresh last_accessed = T0 + 180ms
        assert_eq!(engine.context_manager().compressor_context_count(), 1);

        mock_clock.advance(short_timeout / 2); // Advance by 50ms. Clock = T0 + 230ms. cid_fresh age = 50ms.

        let _ = engine
            .compress(cid_fresh, Some(RohcProfile::RtpUdpIp), &generic_headers)
            .unwrap(); // Refresh cid_fresh
        // cid_fresh last_accessed = T0 + 230ms.

        mock_clock.advance(short_timeout / 3); // Advance by ~33ms. Clock = T0 + ~263ms. cid_fresh age = ~33ms.

        engine.prune_stale_contexts(); // Should not prune cid_fresh
        assert_eq!(
            engine.context_manager().compressor_context_count(),
            1,
            "Freshly accessed CID {} should remain",
            cid_fresh
        );
        assert!(
            engine
                .context_manager()
                .get_compressor_context(cid_fresh)
                .is_ok()
        );
    }
}
