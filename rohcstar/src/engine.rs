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
    DEFAULT_IR_REFRESH_INTERVAL, ROHC_GENERIC_IR_D_BIT_MASK, ROHC_GENERIC_IR_PACKET_TYPE_BASE,
    ROHC_SMALL_CID_MASK,
};
use crate::context_manager::ContextManager;
use crate::error::{EngineError, ParseContext, RohcError, RohcParsingError};
use crate::packet_defs::{GenericUncompressedHeaders, RohcProfile};
use crate::time::{Clock, SystemClock};
use crate::traits::ProfileHandler;
use crate::types::ContextId;

/// Central orchestrator for ROHC compression and decompression operations.
///
/// Manages profile handlers and contexts with automatic cleanup and timeout handling.
///
/// ## Usage
///
/// 1. Create an engine with [`RohcEngine::new`]
/// 2. Register profile handlers using [`register_profile_handler`]
/// 3. Use [`compress`] and [`decompress`] methods to process packets
/// 4. Periodically call [`prune_stale_contexts`] to clean up inactive contexts
///
/// [`register_profile_handler`]: Self::register_profile_handler
/// [`compress`]: Self::compress
/// [`decompress`]: Self::decompress
/// [`prune_stale_contexts`]: Self::prune_stale_contexts
#[derive(Debug)]
pub struct RohcEngine {
    /// Stores registered ROHC profile handlers, keyed by their `RohcProfile` identifier.
    profile_handlers: HashMap<RohcProfile, Box<dyn ProfileHandler>>,
    /// Manages active compressor and decompressor contexts.
    context_manager: ContextManager,
    /// Default interval (in number of packets) for sending IR (Initialization/Refresh)
    /// packets by compressors if a profile-specific interval is not used.
    default_ir_refresh_interval: u32,
    /// Duration after which an inactive context is considered stale and may be pruned
    /// by `prune_stale_contexts`.
    context_timeout: Duration,
    /// Shared clock instance for managing time-dependent operations like context timeouts.
    clock: Arc<dyn Clock>,
}

impl RohcEngine {
    /// Creates a new ROHC engine with specified configuration.
    ///
    /// Profile handlers must be registered separately before processing packets.
    ///
    /// [`register_profile_handler`]: Self::register_profile_handler
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
    /// # Errors
    /// - `RohcError::Internal` - Handler for this profile ID already registered
    pub fn register_profile_handler(
        &mut self,
        handler: Box<dyn ProfileHandler>,
    ) -> Result<(), RohcError> {
        let profile_id = handler.profile_id();
        if self.profile_handlers.contains_key(&profile_id) {
            return Err(RohcError::Engine(
                EngineError::ProfileHandlerAlreadyRegistered {
                    profile: profile_id,
                },
            ));
        }
        self.profile_handlers.insert(profile_id, handler);
        Ok(())
    }

    /// Compresses uncompressed headers into ROHC packet.
    ///
    /// Creates new context if needed using profile hint. Updates context access time on success.
    ///
    /// # Errors
    /// - `RohcError::Internal` - Context issues or handler missing
    /// - `RohcError::UnsupportedProfile` - Profile not supported
    /// - `RohcError::Building` - Profile-specific compression errors
    pub fn compress(
        &mut self,
        context_id: ContextId,
        profile_id_hint: Option<RohcProfile>,
        headers: &GenericUncompressedHeaders,
        out: &mut [u8],
    ) -> Result<usize, RohcError> {
        match self.context_manager.get_compressor_context_mut(context_id) {
            Ok(context_dyn) => {
                let profile_id = context_dyn.profile_id();
                let handler = self.profile_handlers.get(&profile_id).ok_or({
                    RohcError::Engine(EngineError::ProfileHandlerNotRegistered {
                        profile: profile_id,
                    })
                })?;
                let result = handler.compress(context_dyn.as_mut(), headers, out);

                if result.is_ok() {
                    context_dyn.update_access_time(self.clock.now());
                }
                result
            }
            Err(RohcError::ContextNotFound(_)) => {
                let profile_to_use = profile_id_hint.ok_or({
                    RohcError::Engine(EngineError::Internal {
                        reason: "Cannot create new compressor context without profile hint",
                    })
                })?;
                let handler = self
                    .profile_handlers
                    .get(&profile_to_use)
                    .ok_or_else(|| RohcError::UnsupportedProfile(profile_to_use.into()))?;

                let mut new_context = handler.create_compressor_context(
                    context_id,
                    self.default_ir_refresh_interval,
                    self.clock.now(),
                );
                let result = handler.compress(new_context.as_mut(), headers, out);
                if result.is_ok() {
                    new_context.update_access_time(self.clock.now());
                }
                self.context_manager
                    .add_compressor_context(context_id, new_context);
                result
            }
            Err(e) => Err(e),
        }
    }

    /// Decompresses a ROHC packet into uncompressed headers.
    ///
    /// Processes a complete ROHC packet by extracting the Context ID (CID), locating or creating
    /// the appropriate decompressor context, and delegating to the registered profile handler.
    /// Updates the context's last accessed time on successful decompression.
    ///
    /// Errors are automatically classified: packet loss related errors are wrapped in
    /// `PacketLoss` error type, while critical implementation issues return raw error types.
    ///
    /// # Errors
    /// - `RohcError::Engine(EngineError::PacketLoss)` - Expected packet loss
    /// - `RohcError::Parsing` - Invalid packet format (critical issues)
    /// - `RohcError::UnsupportedProfile` - Profile handler not registered
    /// - Other `RohcError` variants - Critical implementation issues
    pub fn decompress(&mut self, packet: &[u8]) -> Result<GenericUncompressedHeaders, RohcError> {
        if packet.is_empty() {
            return Err(RohcError::Parsing(RohcParsingError::NotEnoughData {
                needed: 1,
                got: 0,
                context: ParseContext::RohcPacketInput,
            }));
        }

        let (context_id, _, core_packet_slice) = self.parse_cid_from_packet(packet)?;
        if core_packet_slice.is_empty() {
            return Err(RohcError::Parsing(RohcParsingError::NotEnoughData {
                needed: 1,
                got: 0,
                context: ParseContext::CorePacketAfterCid,
            }));
        }

        let result = match self
            .context_manager
            .get_decompressor_context_mut(context_id)
        {
            Ok(context_dyn) => {
                let profile_id = context_dyn.profile_id();
                let handler = self.profile_handlers.get(&profile_id).ok_or({
                    RohcError::Engine(EngineError::ProfileHandlerNotRegistered {
                        profile: profile_id,
                    })
                })?;

                match handler.decompress(context_dyn.as_mut(), core_packet_slice) {
                    Ok(headers) => {
                        context_dyn.update_access_time(self.clock.now());
                        Ok(headers)
                    }
                    Err(e) => Err(e),
                }
            }
            Err(RohcError::ContextNotFound(_)) => {
                match self.peek_profile_from_core_packet(core_packet_slice) {
                    Ok(profile_id) => {
                        let handler = self
                            .profile_handlers
                            .get(&profile_id)
                            .ok_or_else(|| RohcError::UnsupportedProfile(profile_id.into()))?;

                        let mut new_context =
                            handler.create_decompressor_context(context_id, self.clock.now());
                        match handler.decompress(new_context.as_mut(), core_packet_slice) {
                            Ok(headers) => {
                                new_context.update_access_time(self.clock.now());
                                self.context_manager
                                    .add_decompressor_context(context_id, new_context);
                                Ok(headers)
                            }
                            Err(e) => Err(e),
                        }
                    }
                    Err(e) => Err(e),
                }
            }
            Err(e) => Err(e),
        };

        // Classify errors: wrap packet loss errors, return others as-is
        match result {
            Ok(headers) => Ok(headers),
            Err(e) if e.is_expected_with_packet_loss() => {
                Err(RohcError::Engine(EngineError::PacketLoss {
                    underlying_error: Box::new(e),
                }))
            }
            Err(e) => Err(e),
        }
    }

    /// Decompresses a ROHC packet returning raw, unclassified errors.
    ///
    /// This method provides direct access to the underlying decompression errors
    /// without packet loss classification. It's primarily intended for testing
    /// and debugging where the exact error type matters.
    ///
    /// # Errors
    /// - `RohcError::Parsing` - Invalid packet format or packet loss effects
    /// - `RohcError::ContextNotFound` - No context exists and packet is not IR type
    /// - `RohcError::UnsupportedProfile` - Profile handler not registered
    /// - `RohcError::Decompression` - Context damage from packet loss or real issues
    pub fn decompress_raw(
        &mut self,
        packet: &[u8],
    ) -> Result<GenericUncompressedHeaders, RohcError> {
        if packet.is_empty() {
            return Err(RohcError::Parsing(RohcParsingError::NotEnoughData {
                needed: 1,
                got: 0,
                context: ParseContext::RohcPacketInput,
            }));
        }

        let (cid, _, core_packet_slice) = self.parse_cid_from_packet(packet)?;
        if core_packet_slice.is_empty() {
            return Err(RohcError::Parsing(RohcParsingError::NotEnoughData {
                needed: 1,
                got: 0,
                context: ParseContext::CorePacketAfterCid,
            }));
        }

        match self.context_manager.get_decompressor_context_mut(cid) {
            Ok(context_dyn) => {
                let profile_id = context_dyn.profile_id();
                let handler = self.profile_handlers.get(&profile_id).ok_or({
                    RohcError::Engine(EngineError::ProfileHandlerNotRegistered {
                        profile: profile_id,
                    })
                })?;

                match handler.decompress(context_dyn.as_mut(), core_packet_slice) {
                    Ok(headers) => {
                        context_dyn.update_access_time(self.clock.now());
                        Ok(headers)
                    }
                    Err(e) => Err(e),
                }
            }
            Err(RohcError::ContextNotFound(_)) => {
                match self.peek_profile_from_core_packet(core_packet_slice) {
                    Ok(profile_id) => {
                        let handler = self
                            .profile_handlers
                            .get(&profile_id)
                            .ok_or_else(|| RohcError::UnsupportedProfile(profile_id.into()))?;

                        let mut new_context =
                            handler.create_decompressor_context(cid, self.clock.now());
                        match handler.decompress(new_context.as_mut(), core_packet_slice) {
                            Ok(headers) => {
                                new_context.update_access_time(self.clock.now());
                                self.context_manager
                                    .add_decompressor_context(cid, new_context);
                                Ok(headers)
                            }
                            Err(e) => Err(e),
                        }
                    }
                    Err(e) => Err(e),
                }
            }
            Err(e) => Err(e),
        }
    }

    /// Parses CID from a ROHC packet, handling Add-CID octets.
    ///
    /// This is an internal helper function.
    ///
    /// # Errors
    /// - `RohcError::Parsing` - Insufficient packet data
    fn parse_cid_from_packet<'a>(
        &self,
        packet: &'a [u8],
    ) -> Result<(ContextId, bool, &'a [u8]), RohcError> {
        if packet.is_empty() {
            return Err(RohcError::Parsing(RohcParsingError::NotEnoughData {
                needed: 1,
                got: 0,
                context: ParseContext::CidParsing,
            }));
        }
        let first_byte = packet[0];
        // Check for Add-CID octet (1110xxxx prefix)
        if (first_byte >> 4) == 0b1110 {
            let cid_val = ContextId::new((first_byte & ROHC_SMALL_CID_MASK) as u16);
            Ok((cid_val, true, &packet[1..]))
        } else {
            // No Add-CID, assume implicit CID 0
            Ok((ContextId::new(0), false, packet))
        }
    }

    /// Peeks profile ID from a core ROHC packet (typically an IR packet).
    /// Assumes the packet is an IR packet if a new context needs to be created.
    /// Determines ROHC profile from packet format.
    ///
    /// This is an internal helper function.
    ///
    /// # Errors
    /// - `RohcError::NoSuitableProfile` - Unable to determine profile from packet format
    /// - `RohcError::Parsing` - Insufficient data for profile determination
    /// - `RohcError::InvalidState` - Non-IR packet for new CID
    fn peek_profile_from_core_packet(
        &self,
        core_packet_slice: &[u8],
    ) -> Result<RohcProfile, RohcError> {
        if core_packet_slice.len() < 2 {
            return Err(RohcError::Parsing(RohcParsingError::NotEnoughData {
                needed: 2,
                got: core_packet_slice.len(),
                context: ParseContext::ProfileIdPeek,
            }));
        }
        let packet_type_octet = core_packet_slice[0];
        // Check if it's an IR packet (1111110D)
        if (packet_type_octet & !ROHC_GENERIC_IR_D_BIT_MASK) == ROHC_GENERIC_IR_PACKET_TYPE_BASE {
            let profile_id_byte = core_packet_slice[1];
            Ok(RohcProfile::from(profile_id_byte))
        } else {
            Err(RohcError::Engine(EngineError::Internal {
                reason: "Cannot determine ROHC profile from non-IR packet for new CID",
            }))
        }
    }

    /// Removes contexts that have been inactive beyond the configured timeout.
    ///
    /// Iterates through all compressor and decompressor contexts, removing those whose
    /// last access time exceeds the engine's `context_timeout` duration. This method
    /// should be called periodically to manage context lifecycle and prevent resource leaks.
    pub fn prune_stale_contexts(&mut self) {
        let now = self.clock.now();
        let timeout_duration = self.context_timeout;

        let stale_compressor_cids: Vec<ContextId> = self
            .context_manager
            .compressor_contexts_iter()
            .filter_map(|(cid, context_dyn)| {
                if now.duration_since(context_dyn.last_accessed()) > timeout_duration {
                    Some(*cid)
                } else {
                    None
                }
            })
            .collect();

        for cid in stale_compressor_cids {
            self.context_manager.remove_compressor_context(cid);
        }

        let stale_decompressor_cids: Vec<ContextId> = self
            .context_manager
            .decompressor_contexts_iter()
            .filter_map(|(cid, context_dyn)| {
                if now.duration_since(context_dyn.last_accessed()) > timeout_duration {
                    Some(*cid)
                } else {
                    None
                }
            })
            .collect();

        for cid in stale_decompressor_cids {
            self.context_manager.remove_decompressor_context(cid);
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
            DEFAULT_IR_REFRESH_INTERVAL,
            Duration::from_secs(60 * 5), // Default context timeout: 5 minutes
            Arc::new(SystemClock),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::{ROHC_ADD_CID_FEEDBACK_PREFIX_VALUE, ROHC_SMALL_CID_MASK};
    use crate::error::EngineError;
    use crate::profiles::profile1::{
        P1_BASE_DYNAMIC_CHAIN_LENGTH_BYTES, P1_ROHC_IR_PACKET_TYPE_WITH_DYN,
        P1_STATIC_CHAIN_LENGTH_BYTES, Profile1Handler, RtpUdpIpv4Headers,
    };
    use crate::time::mock_clock::MockClock;
    use crate::types::SequenceNumber;
    use std::time::Duration;
    use std::time::Instant;

    const DEFAULT_TEST_TIMEOUT: Duration = Duration::from_secs(60 * 5);
    const TEST_COMPRESS_BUF_SIZE: usize = 128; // Sufficient for most ROHC test packets

    fn create_test_rtp_headers_for_engine(sn: u16, ts: u32, marker: bool) -> RtpUdpIpv4Headers {
        RtpUdpIpv4Headers {
            ip_src: "192.168.1.10".parse().unwrap(),
            ip_dst: "192.168.1.20".parse().unwrap(),
            udp_src_port: 10010,
            udp_dst_port: 20020,
            rtp_ssrc: 0xAABBCCDD.into(),
            rtp_sequence_number: sn.into(),
            rtp_timestamp: ts.into(),
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
        assert!(matches!(
            result,
            Err(RohcError::Engine(
                EngineError::ProfileHandlerAlreadyRegistered { .. }
            ))
        ));
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
        let mut compressed_buf1 = [0u8; TEST_COMPRESS_BUF_SIZE];
        let len1 = engine
            .compress(
                0.into(),
                Some(RohcProfile::RtpUdpIp),
                &generic_headers1,
                &mut compressed_buf1,
            )
            .unwrap();
        let compressed1_slice = &compressed_buf1[..len1];

        assert!(!compressed1_slice.is_empty());
        assert_eq!(compressed1_slice[0], P1_ROHC_IR_PACKET_TYPE_WITH_DYN);

        let decompressed_generic1 = engine.decompress(compressed1_slice).unwrap();
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
        let mut compressed_buf2 = [0u8; TEST_COMPRESS_BUF_SIZE];
        let len2 = engine
            .compress(
                0.into(),
                Some(RohcProfile::RtpUdpIp),
                &generic_headers2,
                &mut compressed_buf2,
            )
            .unwrap();
        let compressed2_slice = &compressed_buf2[..len2];
        assert_eq!(compressed2_slice.len(), 1);

        let decompressed_generic2 = engine.decompress(compressed2_slice).unwrap();
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
        let cid = 5.into();

        let headers1 = create_test_rtp_headers_for_engine(200, 2000, true);
        let generic_headers1 = GenericUncompressedHeaders::RtpUdpIpv4(headers1.clone());
        let mut compressed_buf1 = [0u8; TEST_COMPRESS_BUF_SIZE];
        let len1 = engine
            .compress(
                cid,
                Some(RohcProfile::RtpUdpIp),
                &generic_headers1,
                &mut compressed_buf1,
            )
            .unwrap();
        let compressed1_slice = &compressed_buf1[..len1];

        assert!(!compressed1_slice.is_empty());
        assert_eq!(
            compressed1_slice[0],
            ROHC_ADD_CID_FEEDBACK_PREFIX_VALUE | (*cid as u8 & ROHC_SMALL_CID_MASK)
        );
        assert_eq!(compressed1_slice[1], P1_ROHC_IR_PACKET_TYPE_WITH_DYN);

        let decompressed_generic1 = engine.decompress(compressed1_slice).unwrap();
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

        let headers2 = create_test_rtp_headers_for_engine(201, 2000, true);
        let generic_headers2 = GenericUncompressedHeaders::RtpUdpIpv4(headers2.clone());
        let mut compressed_buf2 = [0u8; TEST_COMPRESS_BUF_SIZE];
        let len2 = engine
            .compress(
                cid,
                Some(RohcProfile::RtpUdpIp),
                &generic_headers2,
                &mut compressed_buf2,
            )
            .unwrap();
        let compressed2_slice = &compressed_buf2[..len2];

        assert_eq!(compressed2_slice.len(), 2); // Add-CID + UO-0
        assert_eq!(
            compressed2_slice[0],
            ROHC_ADD_CID_FEEDBACK_PREFIX_VALUE | (*cid as u8 & ROHC_SMALL_CID_MASK)
        );
        assert_eq!(compressed2_slice[1] & 0x80, 0); // UO-0 discriminator: bit 7 = 0

        let decompressed_generic2 = engine.decompress(compressed2_slice).unwrap();
        match decompressed_generic2 {
            GenericUncompressedHeaders::RtpUdpIpv4(h) => {
                assert_eq!(h.rtp_ssrc, headers1.rtp_ssrc);
                assert_eq!(h.rtp_sequence_number, headers2.rtp_sequence_number);
                assert_eq!(h.rtp_marker, headers2.rtp_marker);
                assert_eq!(h.rtp_timestamp, headers1.rtp_timestamp);
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

        // SN=10, CRC=5, for implicit CID 0. Length is 1.
        let uo0_packet_cid0 = vec![(0x0A << 3) | 0x05];
        let result = engine.decompress(&uo0_packet_cid0);
        let result_clone_for_assert_msg = result.clone();

        assert!(
            matches!(
                result,
                Err(RohcError::Parsing(RohcParsingError::NotEnoughData {
                    needed: 2, got: 1, context
                }))
                if context == ParseContext::ProfileIdPeek
            ),
            "Expected NotEnoughData from peek_profile_from_core_packet for 1-byte UO-0, got {:?}",
            result_clone_for_assert_msg
        );
    }

    #[test]
    fn decompress_unsupported_profile_in_ir() {
        let mock_clock = Arc::new(MockClock::new(Instant::now()));
        let mut engine = RohcEngine::new(5, DEFAULT_TEST_TIMEOUT, mock_clock);
        engine
            .register_profile_handler(Box::new(Profile1Handler::new()))
            .unwrap();

        // 0xFF is unsupported
        let mut fake_ir_packet_bytes = vec![P1_ROHC_IR_PACKET_TYPE_WITH_DYN, 0xFF];
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
        let cid = ContextId::new(0);

        let headers_ir = create_test_rtp_headers_for_engine(100, 1000, false);
        let generic_headers_ir = GenericUncompressedHeaders::RtpUdpIpv4(headers_ir);
        let mut compressed_ir_buf = [0u8; TEST_COMPRESS_BUF_SIZE];
        let len_ir = engine
            .compress(
                cid,
                Some(RohcProfile::RtpUdpIp),
                &generic_headers_ir,
                &mut compressed_ir_buf,
            )
            .unwrap();
        let compressed_ir_slice = &compressed_ir_buf[..len_ir];
        engine
            .decompress(compressed_ir_slice)
            .expect("Decompression of IR packet failed");

        assert!(
            engine
                .context_manager
                .get_decompressor_context_mut(cid)
                .is_ok()
        );

        let headers_uo0 = create_test_rtp_headers_for_engine(101, 1000, false); // UO-0 conditions
        let generic_headers_uo0 = GenericUncompressedHeaders::RtpUdpIpv4(headers_uo0);
        let mut compressed_uo0_buf = [0u8; TEST_COMPRESS_BUF_SIZE];
        let len_uo0 = engine
            .compress(
                cid,
                Some(RohcProfile::RtpUdpIp),
                &generic_headers_uo0,
                &mut compressed_uo0_buf,
            )
            .unwrap();
        let compressed_uo0_slice = &compressed_uo0_buf[..len_uo0];
        let decompressed_generic_uo0 = engine.decompress(compressed_uo0_slice).unwrap();

        match decompressed_generic_uo0 {
            GenericUncompressedHeaders::RtpUdpIpv4(h) => {
                assert_eq!(h.rtp_sequence_number, 101);
            }
            _ => panic!("Unexpected decompressed header type for UO-0"),
        }
    }

    #[test]
    fn engine_prune_stale_contexts_works() {
        let start_time = Instant::now();
        let mock_clock = Arc::new(MockClock::new(start_time));
        let short_timeout = Duration::from_millis(100);

        let mut engine = RohcEngine::new(5, short_timeout, mock_clock.clone());
        engine
            .register_profile_handler(Box::new(Profile1Handler::new()))
            .unwrap();

        let headers = create_test_rtp_headers_for_engine(1, 10, false);
        let generic_headers = GenericUncompressedHeaders::RtpUdpIpv4(headers);
        let mut compress_buf = [0u8; TEST_COMPRESS_BUF_SIZE];

        let cid10 = ContextId::new(10);
        let cid11 = ContextId::new(11);
        let cid_fresh = ContextId::new(2);

        // Phase 1: Prune cid11 contexts, keep cid10 compressor
        let _ = engine
            .compress(
                cid10,
                Some(RohcProfile::RtpUdpIp),
                &generic_headers,
                &mut compress_buf,
            )
            .unwrap();

        mock_clock.advance(Duration::from_millis(10));
        let _ = engine
            .compress(
                cid11,
                Some(RohcProfile::RtpUdpIp),
                &generic_headers,
                &mut compress_buf,
            )
            .unwrap();

        mock_clock.advance(Duration::from_millis(10));

        assert_eq!(
            engine.context_manager().compressor_context_count(),
            2,
            "Initial compressor count"
        );
        assert_eq!(
            engine.context_manager().decompressor_context_count(),
            0,
            "Initial decompressor count"
        );

        // Refresh cid10 to keep it fresh
        mock_clock.advance(short_timeout / 2);

        let headers_refresh = create_test_rtp_headers_for_engine(2, 10, false);
        let generic_headers_refresh = GenericUncompressedHeaders::RtpUdpIpv4(headers_refresh);

        let _ = engine
            .compress(
                cid10,
                Some(RohcProfile::RtpUdpIp),
                &generic_headers_refresh,
                &mut compress_buf,
            )
            .unwrap();

        // Prune - cid11 contexts should be stale, cid10 should remain fresh
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

        // Phase 2: Make cid10 stale and prune it
        mock_clock.advance(Duration::from_millis(50)); // cid10 age is now 60+50 = 110ms > 100ms
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

        // Phase 3: Test fresh context survives a prune if accessed within timeout
        // Current clock: T0 + 10(c10_c) + 10(c11_c) + 10(c11_d) + 50(c10_r)
        // + 60(p1) + 50(p2) = T0 + 190ms
        let _ = engine
            .compress(
                cid_fresh,
                Some(RohcProfile::RtpUdpIp),
                &generic_headers,
                &mut compress_buf,
            )
            .unwrap(); // cid_fresh last_accessed = T0 + 190ms
        assert_eq!(engine.context_manager().compressor_context_count(), 1);

        // Clock = T0 + 190 + 50 = T0 + 240ms (cid_fresh age = 50ms). Refresh.
        mock_clock.advance(short_timeout / 2); // Advance by 50ms

        let headers_final_refresh = create_test_rtp_headers_for_engine(2, 10, false); // SN changed
        let generic_headers_final_refresh =
            GenericUncompressedHeaders::RtpUdpIpv4(headers_final_refresh);

        let _ = engine
            .compress(
                cid_fresh,
                Some(RohcProfile::RtpUdpIp),
                &generic_headers_final_refresh,
                &mut compress_buf,
            )
            .unwrap(); // cid_fresh last_accessed = T0 + 240ms.

        // Clock = T0 + 240 + ~33 = T0 + ~273ms (cid_fresh age = ~33ms). Prune.
        mock_clock.advance(short_timeout / 3); // Advance by 33ms
        engine.prune_stale_contexts(); // Should not prune cid_fresh
        assert_eq!(
            engine.context_manager().compressor_context_count(),
            1,
            "Freshly accessed CID {} should remain",
            cid_fresh
        );
    }

    #[test]
    fn engine_compress_decompress_explicit_uo0() {
        let mock_clock = Arc::new(MockClock::new(Instant::now()));
        let mut engine = RohcEngine::new(5, DEFAULT_TEST_TIMEOUT, mock_clock);
        engine
            .register_profile_handler(Box::new(Profile1Handler::new()))
            .unwrap();

        let cid = 5.into();
        let mut compress_buf = [0u8; TEST_COMPRESS_BUF_SIZE];

        let headers1 = create_test_rtp_headers_for_engine(100, 1000, false);
        let generic_headers1 = GenericUncompressedHeaders::RtpUdpIpv4(headers1.clone());

        let len1 = engine
            .compress(
                cid,
                Some(RohcProfile::RtpUdpIp),
                &generic_headers1,
                &mut compress_buf,
            )
            .unwrap();
        let compressed1_slice = &compress_buf[..len1];

        let _decompressed1 = engine.decompress(compressed1_slice).unwrap();

        let mut headers2 = headers1.clone();
        headers2.rtp_sequence_number = SequenceNumber::new(101);
        let generic_headers2 = GenericUncompressedHeaders::RtpUdpIpv4(headers2.clone());

        let len2 = engine
            .compress(
                cid,
                Some(RohcProfile::RtpUdpIp),
                &generic_headers2,
                &mut compress_buf,
            )
            .unwrap();
        let compressed2_slice = &compress_buf[..len2];

        assert_eq!(compressed2_slice.len(), 2); // Add-CID + UO-0
        assert_eq!(
            compressed2_slice[0],
            ROHC_ADD_CID_FEEDBACK_PREFIX_VALUE | (*cid as u8 & ROHC_SMALL_CID_MASK)
        );
        assert_eq!(compressed2_slice[1] & 0x80, 0); // UO-0 discriminator (bit 7 = 0)

        let decompressed2 = engine.decompress(compressed2_slice).unwrap();
        match decompressed2 {
            GenericUncompressedHeaders::RtpUdpIpv4(h) => {
                assert_eq!(h.rtp_sequence_number, headers2.rtp_sequence_number);
                assert_eq!(h.rtp_timestamp, headers1.rtp_timestamp);
                assert_eq!(h.rtp_marker, headers2.rtp_marker);
            }
            _ => panic!("Unexpected decompressed header type"),
        }
    }
}
