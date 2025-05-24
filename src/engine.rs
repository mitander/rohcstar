//! The ROHC (Robust Header Compression) Engine.
//!
//! This module provides the `RohcEngine`, which is the central orchestrator for
//! ROHC compression and decompression operations. It manages different ROHC
//! profile handlers and their associated contexts.

use std::collections::HashMap;
use std::fmt::Debug;

use crate::constants::{
    ROHC_ADD_CID_FEEDBACK_PREFIX_MASK, ROHC_ADD_CID_FEEDBACK_PREFIX_VALUE,
    ROHC_GENERIC_IR_D_BIT_MASK, ROHC_GENERIC_IR_PACKET_TYPE_BASE, ROHC_SMALL_CID_MASK,
};
use crate::context_manager::ContextManager;
use crate::error::{RohcError, RohcParsingError};
use crate::packet_defs::{GenericUncompressedHeaders, RohcProfile};
use crate::traits::ProfileHandler;

/// The main ROHC processing engine.
///
/// The `RohcEngine` allows users to register ROHC profile handlers and then
/// use these handlers to compress outgoing packet headers or decompress incoming
/// ROHC packets. It manages the lifecycle and storage of compression and
/// decompression contexts via a `ContextManager`.
#[derive(Debug)]
pub struct RohcEngine {
    /// Stores registered profile handlers, keyed by their `RohcProfile` identifier.
    profile_handlers: HashMap<RohcProfile, Box<dyn ProfileHandler>>,
    /// Manages all active compressor and decompressor contexts.
    context_manager: ContextManager,
    /// Default IR (Initialization/Refresh) interval to suggest to new compressor contexts.
    default_ir_refresh_interval: u32,
}

impl RohcEngine {
    /// Creates a new `RohcEngine` with no registered profiles.
    ///
    /// # Parameters
    /// - `default_ir_refresh_interval`: The default interval (in packets) for IR refreshes,
    ///   used when creating new compressor contexts if no other interval is specified.
    pub fn new(default_ir_refresh_interval: u32) -> Self {
        RohcEngine {
            profile_handlers: HashMap::new(),
            context_manager: ContextManager::new(),
            default_ir_refresh_interval,
        }
    }

    /// Registers a ROHC profile handler with the engine.
    ///
    /// The engine will use this handler for any operations related to its
    /// declared `RohcProfile` ID.
    ///
    /// # Parameters
    /// - `handler`: A `Box<dyn ProfileHandler>` for the profile to be registered.
    ///
    /// # Returns
    /// - `Ok(())` if registration is successful.
    /// - `Err(RohcError::Internal)` if a handler for that profile is already registered.
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
    ///
    /// The engine retrieves or creates the appropriate compressor context for the CID,
    /// then delegates the compression task to the registered `ProfileHandler` associated
    /// with that context's profile.
    ///
    /// # Parameters
    /// - `cid`: The Context ID for the flow to be compressed.
    /// - `profile_id_hint`: An optional hint for the `RohcProfile` if a new context needs to be created.
    ///   If `None` and the context doesn't exist, an error may occur
    ///   if the profile cannot be inferred.
    /// - `uncompressed_headers`: The `GenericUncompressedHeaders` to compress.
    ///
    /// # Returns
    /// A `Result` containing the compressed ROHC packet as `Vec<u8>`, or a `RohcError`.
    pub fn compress(
        &mut self,
        cid: u16,
        profile_id_hint: Option<RohcProfile>,
        uncompressed_headers: &GenericUncompressedHeaders,
    ) -> Result<Vec<u8>, RohcError> {
        let context_result = self.context_manager.get_compressor_context_mut(cid);

        match context_result {
            Ok(context_box) => {
                let profile_id = context_box.profile_id();
                let handler = self.profile_handlers.get(&profile_id).ok_or_else(|| {
                    RohcError::Internal(format!(
                        "Compressor context for CID {} exists with profile {:?}, but no matching handler is registered.",
                        cid, profile_id
                    ))
                })?;
                handler.compress(context_box.as_mut(), uncompressed_headers)
            }
            Err(RohcError::ContextNotFound(_)) => {
                let profile_to_use = profile_id_hint.ok_or_else(|| RohcError::Internal(
                    format!("Cannot create new compressor context for CID {} without a profile ID hint.", cid)
                ))?;

                let handler = self
                    .profile_handlers
                    .get(&profile_to_use)
                    .ok_or_else(|| RohcError::UnsupportedProfile(profile_to_use.into()))?;

                let mut new_context =
                    handler.create_compressor_context(cid, self.default_ir_refresh_interval);
                // The first call to compress with a new context will typically send an IR packet,
                // which initializes the context based on the headers.
                let compressed_data =
                    handler.compress(new_context.as_mut(), uncompressed_headers)?;
                self.context_manager
                    .add_compressor_context(cid, new_context);
                Ok(compressed_data)
            }
            Err(e) => Err(e), // Other errors from get_compressor_context_mut
        }
    }

    /// Decompresses an incoming ROHC packet.
    ///
    /// This method performs the following steps:
    /// 1. Parses the initial bytes of the `rohc_packet` to detect a CID (e.g., via Add-CID octet).
    /// 2. Retrieves or creates the decompressor context for the determined CID.
    ///    - If creating a new context, it may peek at the packet to infer the ROHC profile
    ///      (e.g., from an IR packet).
    /// 3. Dispatches the core ROHC packet data to the appropriate `ProfileHandler` for decompression.
    ///
    /// # Parameters
    /// - `rohc_packet_bytes`: A byte slice containing the complete incoming ROHC packet.
    ///
    /// # Returns
    /// A `Result` containing the reconstructed `GenericUncompressedHeaders`, or a `RohcError`.
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

        // 1. Parse CID and get core packet slice
        let (cid, _, core_packet_slice) = self.parse_cid_from_packet(rohc_packet_bytes)?;

        if core_packet_slice.is_empty() {
            return Err(RohcError::Parsing(RohcParsingError::NotEnoughData {
                needed: 1, // Need at least one byte for the core ROHC packet type
                got: 0,
                context: "Core ROHC packet after CID processing".to_string(),
            }));
        }

        // 2. Get or Create Decompressor Context
        match self.context_manager.get_decompressor_context_mut(cid) {
            Ok(context_box) => {
                let profile_id = context_box.profile_id();
                let handler = self.profile_handlers.get(&profile_id).ok_or_else(|| {
                    RohcError::Internal(format!(
                        "Decompressor context for CID {} exists with profile {:?}, but no matching handler registered.",
                        cid, profile_id
                    ))
                })?;
                // If Add-CID was present, some profiles might need to re-verify or update based on it.
                // For now, assume set_cid handled it if necessary upon creation.
                handler.decompress(context_box.as_mut(), core_packet_slice)
            }
            Err(RohcError::ContextNotFound(_)) => {
                // Context does not exist. This packet should ideally be an IR packet
                // from which we can infer the profile and initialize a new context.
                let profile_id = self.peek_profile_from_core_packet(core_packet_slice)?;
                let handler = self
                    .profile_handlers
                    .get(&profile_id)
                    .ok_or_else(|| RohcError::UnsupportedProfile(profile_id.into()))?;

                let mut new_context = handler.create_decompressor_context(cid);
                // The `set_cid` is already done by `create_decompressor_context`.
                // The first call to decompress with an IR packet will initialize the context.
                let decompressed_headers =
                    handler.decompress(new_context.as_mut(), core_packet_slice)?;
                self.context_manager
                    .add_decompressor_context(cid, new_context);
                Ok(decompressed_headers)
            }
            Err(e) => Err(e), // Other errors
        }
    }

    /// Parses the CID information from the beginning of a ROHC packet.
    /// Handles implicit CID 0 and Add-CID octets for small CIDs.
    ///
    /// # Parameters
    /// - `rohc_packet_bytes`: A byte slice containing the complete incoming ROHC packet.
    ///
    /// # Returns
    /// A tuple `(cid, is_add_cid_present, core_packet_slice)`.
    /// - `cid`: The determined Context ID.
    /// - `is_add_cid_present`: Boolean indicating if an Add-CID octet was parsed.
    /// - `core_packet_slice`: Slice of the packet after any Add-CID octet.
    fn parse_cid_from_packet<'a>(
        &self,
        rohc_packet_bytes: &'a [u8],
    ) -> Result<(u16, bool, &'a [u8]), RohcError> {
        if rohc_packet_bytes.is_empty() {
            // This should have been caught by the caller, but defensive check.
            return Err(RohcError::Parsing(RohcParsingError::NotEnoughData {
                needed: 1,
                got: 0,
                context: "CID parsing".to_string(),
            }));
        }

        let first_byte = rohc_packet_bytes[0];
        if (first_byte & ROHC_ADD_CID_FEEDBACK_PREFIX_MASK) == ROHC_ADD_CID_FEEDBACK_PREFIX_VALUE {
            // Ensure it's not an IR packet that happens to match the prefix loosely.
            // The ROHC_GENERIC_IR_PACKET_TYPE_BASE starts with 1111110...
            // If it's an IR packet, its prefix when masked by 0xE0 would also be 0xE0.
            // However, IR packets are handled differently; they don't signal CID *in this first byte*
            // in the same way Add-CID does.
            // A true Add-CID octet (like 0xE0 to 0xEF) means CID is in lower nibble.
            // An IR packet type (like 0xFC, 0xFD) means it's an IR packet for implicit CID 0
            // (if no prior Add-CID was present for other CIDs).

            // Let's be very specific: an Add-CID octet uses 1110 as the top nibble.
            // The only ROHC packet types that start with 1111 are IR/IR-DYN and some Feedback Type 2.
            if (first_byte >> 4) == 0b1110 {
                // Is it 1110xxxx?
                let cid_val = (first_byte & ROHC_SMALL_CID_MASK) as u16;
                return Ok((cid_val, true, &rohc_packet_bytes[1..]));
            }
            // If it starts with 1111xxxx (like IR), it's not an Add-CID octet.
            // Fall through to implicit CID 0.
        }
        // No Add-CID octet, or it was an IR/other packet starting differently. Assume implicit CID 0.
        Ok((0, false, rohc_packet_bytes))
    }

    /// Attempts to peek at the ROHC profile ID from a core ROHC packet.
    /// This is typically possible for IR (Initialization/Refresh) packets,
    /// which carry the profile ID directly after the packet type octet.
    ///
    /// # Parameters
    /// - `core_packet_slice`: The ROHC packet data *after* any Add-CID processing.
    ///
    /// # Returns
    /// The inferred `RohcProfile` or an error if it cannot be determined.
    fn peek_profile_from_core_packet(
        &self,
        core_packet_slice: &[u8],
    ) -> Result<RohcProfile, RohcError> {
        if core_packet_slice.len() < 2 {
            return Err(RohcError::Parsing(RohcParsingError::NotEnoughData {
                needed: 2,
                got: core_packet_slice.len(),
                context: "Peeking profile ID from core packet".to_string(),
            }));
        }

        let packet_type_octet = core_packet_slice[0];
        let condition_check_lhs = packet_type_octet & !ROHC_GENERIC_IR_D_BIT_MASK;
        let condition_check_rhs = ROHC_GENERIC_IR_PACKET_TYPE_BASE;

        if condition_check_lhs == condition_check_rhs {
            let profile_id_byte = core_packet_slice[1];
            Ok(RohcProfile::from(profile_id_byte))
        } else {
            Err(RohcError::InvalidState(
                "Cannot determine ROHC profile from non-IR packet for new CID.".to_string(),
            ))
        }
    }

    /// Provides access to the underlying `ContextManager`.
    /// Useful for advanced scenarios like context inspection or manual removal.
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
        Self::new(crate::constants::DEFAULT_IR_REFRESH_INTERVAL)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profiles::profile1::Profile1Handler;
    use crate::profiles::profile1::RtpUdpIpv4Headers;
    use crate::profiles::profile1::*;

    fn create_test_rtp_headers_for_engine(sn: u16, ts: u32, marker: bool) -> RtpUdpIpv4Headers {
        RtpUdpIpv4Headers {
            ip_src: "192.168.1.10".parse().unwrap(),
            ip_dst: "192.168.1.20".parse().unwrap(),
            udp_src_port: 10010,
            udp_dst_port: 20020,
            rtp_ssrc: 0xAABBCCDD,
            rtp_sequence_number: sn,
            rtp_timestamp: ts,
            rtp_marker: marker,
            ..Default::default()
        }
    }

    #[test]
    fn engine_new_and_register_handler() {
        let mut engine = RohcEngine::new(20);
        assert_eq!(engine.profile_handlers.len(), 0);

        let p1_handler: Box<dyn ProfileHandler> = Box::new(Profile1Handler::new());
        engine.register_profile_handler(p1_handler).unwrap();
        assert_eq!(engine.profile_handlers.len(), 1);
        assert!(engine.profile_handlers.contains_key(&RohcProfile::RtpUdpIp));

        // Try registering again (should fail)
        let p1_handler_again: Box<dyn ProfileHandler> = Box::new(Profile1Handler::new());
        let result = engine.register_profile_handler(p1_handler_again);
        assert!(matches!(result, Err(RohcError::Internal(_))));
    }

    #[test]
    fn engine_compress_decompress_cid0_flow() {
        let mut engine = RohcEngine::new(5); // IR refresh interval 5
        engine
            .register_profile_handler(Box::new(Profile1Handler::new()))
            .unwrap();

        // Packet 1 (IR)
        let headers1 = create_test_rtp_headers_for_engine(100, 1000, false);
        let generic_headers1 = GenericUncompressedHeaders::RtpUdpIpv4(headers1.clone());
        let compressed1 = engine
            .compress(0, Some(RohcProfile::RtpUdpIp), &generic_headers1)
            .unwrap();
        assert!(!compressed1.is_empty());
        // First byte of core IR packet for P1
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

        // Packet 2 (UO-0)
        let headers2 = create_test_rtp_headers_for_engine(101, 1100, false); // TS changed but marker same
        let generic_headers2 = GenericUncompressedHeaders::RtpUdpIpv4(headers2.clone());
        let compressed2 = engine
            .compress(0, Some(RohcProfile::RtpUdpIp), &generic_headers2)
            .unwrap();
        assert_eq!(compressed2.len(), 1); // UO-0 for CID 0

        let decompressed_generic2 = engine.decompress(&compressed2).unwrap();
        match decompressed_generic2 {
            GenericUncompressedHeaders::RtpUdpIpv4(h) => {
                assert_eq!(h.rtp_ssrc, headers1.rtp_ssrc); // SSRC from context
                assert_eq!(h.rtp_sequence_number, headers2.rtp_sequence_number);
                assert_eq!(h.rtp_timestamp, headers1.rtp_timestamp); // TS from context for UO-0
                assert_eq!(h.rtp_marker, headers1.rtp_marker); // Marker from context
            }
            _ => panic!("Unexpected decompressed header type"),
        }
    }

    #[test]
    fn engine_compress_decompress_add_cid_flow() {
        let mut engine = RohcEngine::new(5);
        engine
            .register_profile_handler(Box::new(Profile1Handler::new()))
            .unwrap();
        let cid: u16 = 5;

        // Packet 1 (IR with Add-CID)
        let headers1 = create_test_rtp_headers_for_engine(200, 2000, true);
        let generic_headers1 = GenericUncompressedHeaders::RtpUdpIpv4(headers1.clone());
        let compressed1 = engine
            .compress(cid, Some(RohcProfile::RtpUdpIp), &generic_headers1)
            .unwrap();

        assert!(!compressed1.is_empty());
        // Check for Add-CID octet
        assert_eq!(
            compressed1[0],
            ROHC_ADD_CID_FEEDBACK_PREFIX_VALUE | (cid as u8 & ROHC_SMALL_CID_MASK)
        );
        // Check core IR packet type
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

        // Packet 2 (UO-1 with Add-CID, assuming marker changed or SN jump forces UO-1)
        // To force UO-1, let's make SN jump significantly or marker change
        let headers2 = create_test_rtp_headers_for_engine(201, 2100, false); // Marker changed from true to false
        let generic_headers2 = GenericUncompressedHeaders::RtpUdpIpv4(headers2.clone());
        let compressed2 = engine
            .compress(cid, Some(RohcProfile::RtpUdpIp), &generic_headers2)
            .unwrap();

        assert!(compressed2.len() > 1); // UO-1 with Add-CID
        assert_eq!(
            compressed2[0],
            ROHC_ADD_CID_FEEDBACK_PREFIX_VALUE | (cid as u8 & ROHC_SMALL_CID_MASK)
        );
        // Core UO-1 packet type should be P1_UO_1_SN_PACKET_TYPE_PREFIX (marker false)
        assert_eq!(
            compressed2[1] & P1_UO_1_SN_PACKET_TYPE_PREFIX,
            P1_UO_1_SN_PACKET_TYPE_PREFIX
        );
        assert_eq!(compressed2[1] & P1_UO_1_SN_MARKER_BIT_MASK, 0); // Marker bit is false

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
        let mut engine = RohcEngine::new(5);
        engine
            .register_profile_handler(Box::new(Profile1Handler::new()))
            .unwrap();

        // A UO-0 packet for CID 0, but no context exists for CID 0 yet.
        // This should fail because UO-0 cannot initialize context.
        let uo0_packet_cid0 = vec![(0x0A << 3) | 0x05]; // SN=10, CRC=5
        let result = engine.decompress(&uo0_packet_cid0);
        assert!(matches!(
            result,
            Err(RohcError::Parsing(RohcParsingError::NotEnoughData {
                needed: 2,
                got: 1,
                ..
            }))
        ));
    }

    #[test]
    fn decompress_unsupported_profile_in_ir() {
        let mut engine = RohcEngine::new(5);
        // Profile1Handler registered
        engine
            .register_profile_handler(Box::new(Profile1Handler::new()))
            .unwrap();

        // Manually create an IR packet that claims to be for an unsupported profile (e.g., Profile 0xFF)
        // Type (IR-DYN) + Profile (0xFF) + Dummy Static(16) + Dummy Dynamic(7) + Dummy CRC(1)
        let mut fake_ir_packet_bytes = vec![P1_ROHC_IR_PACKET_TYPE_WITH_DYN, 0xFF];
        fake_ir_packet_bytes.extend_from_slice(
            &[0u8; P1_STATIC_CHAIN_LENGTH_BYTES + P1_DYNAMIC_CHAIN_LENGTH_BYTES + 1],
        );
        // (CRC not correctly calculated, but peek_profile should happen before CRC check)

        let result = engine.decompress(&fake_ir_packet_bytes);
        assert!(matches!(result, Err(RohcError::UnsupportedProfile(0xFF))));
    }

    #[test]
    fn engine_decompress_cid0_context_persistence() {
        let mut engine = RohcEngine::new(5);
        engine
            .register_profile_handler(Box::new(Profile1Handler::new()))
            .unwrap();
        let cid = 0u16;

        // Packet 1: IR to establish context for CID 0
        let headers_ir = create_test_rtp_headers_for_engine(100, 1000, false);
        let generic_headers_ir = GenericUncompressedHeaders::RtpUdpIpv4(headers_ir);
        let compressed_ir = engine
            .compress(cid, Some(RohcProfile::RtpUdpIp), &generic_headers_ir)
            .unwrap();

        // This call should create and add decompressor context for CID 0
        let _ = engine
            .decompress(&compressed_ir)
            .expect("Decompression of IR packet failed");

        // Check if context for CID 0 exists NOW
        assert!(
            engine
                .context_manager
                .get_decompressor_context_mut(cid)
                .is_ok(),
            "Decompressor context for CID 0 should exist after IR decompress"
        );

        // Packet 2: UO-0 for the SAME CID 0
        let headers_uo0 = create_test_rtp_headers_for_engine(101, 1100, false);
        let generic_headers_uo0 = GenericUncompressedHeaders::RtpUdpIpv4(headers_uo0);
        let compressed_uo0 = engine
            .compress(cid, Some(RohcProfile::RtpUdpIp), &generic_headers_uo0)
            .unwrap();

        // This call should FIND and USE existing decompressor context for CID 0
        // This is the line that panics in the original test:
        let decompressed_generic_uo0 = engine.decompress(&compressed_uo0).unwrap();

        match decompressed_generic_uo0 {
            GenericUncompressedHeaders::RtpUdpIpv4(h) => {
                assert_eq!(h.rtp_sequence_number, 101);
            }
            _ => panic!("Unexpected decompressed header type for UO-0"),
        }
    }
}
