use crate::constants::{DEFAULT_IR_REFRESH_INTERVAL, PROFILE_ID_RTP_UDP_IP};
use crate::context::{RtpUdpIpP1CompressorContext, RtpUdpIpP1DecompressorContext};
use crate::protocol_types::{RohcIrProfile1Packet, RtpUdpIpv4Headers};

/// A simple context manager for ROHC Profile 1 (RTP/UDP/IP).
///
/// This manager handles a single compressor context and a single decompressor context.
/// It's suitable for scenarios where only one ROHC flow (identified by a CID,
/// or CID 0 if implicit) is being managed at a time by this instance.
///
/// For managing multiple concurrent ROHC flows (multiple CIDs), a more sophisticated
/// context manager would be required, likely using a map from CID to context.
#[derive(Debug, Default)]
pub struct SimpleContextManager {
    /// The single compressor context managed by this instance.
    compressor_context: Option<RtpUdpIpP1CompressorContext>,
    /// The single decompressor context managed by this instance.
    decompressor_context: Option<RtpUdpIpP1DecompressorContext>,
}

impl SimpleContextManager {
    /// Creates a new, empty `SimpleContextManager`.
    ///
    /// Both compressor and decompressor contexts will be `None` initially.
    pub fn new() -> Self {
        Self::default()
    }

    /// Retrieves the existing compressor context for the given CID, or initializes a new one
    /// if no context exists or if the existing context is for a different CID or flow.
    ///
    /// A "flow" is identified by the combination of CID and key static header fields
    /// (IP addresses, ports, SSRC). If these static fields change for the given CID,
    /// the existing context is re-initialized.
    ///
    /// # Arguments
    /// * `cid`: The Context Identifier for the compressor.
    /// * `headers`: The uncompressed headers of the current packet, used for initialization
    ///   or to check if the existing context matches the current flow.
    ///
    /// # Returns
    /// A mutable reference to the `RtpUdpIpP1CompressorContext`.
    pub fn get_or_init_compressor_context(
        &mut self,
        cid: u16,
        headers: &RtpUdpIpv4Headers,
    ) -> &mut RtpUdpIpP1CompressorContext {
        let needs_reinitialization = match &self.compressor_context {
            Some(ctx) => {
                // Context exists. Check if it's for the same CID and flow.
                ctx.cid != cid ||
                // Key static fields that define a flow for Profile 1
                ctx.rtp_ssrc != headers.rtp_ssrc ||
                ctx.ip_source != headers.ip_src ||
                ctx.ip_destination != headers.ip_dst ||
                ctx.udp_source_port != headers.udp_src_port ||
                ctx.udp_destination_port != headers.udp_dst_port
            }
            None => true, // No context exists, so it needs initialization.
        };

        if needs_reinitialization {
            let mut new_context = RtpUdpIpP1CompressorContext::new(
                cid,
                PROFILE_ID_RTP_UDP_IP, // Assuming Profile 1 for this manager
                DEFAULT_IR_REFRESH_INTERVAL, // Default refresh interval
            );
            // This will set mode to InitializationAndRefresh, ensuring IR is sent.
            new_context.initialize_static_part_with_uncompressed_headers(headers);
            self.compressor_context = Some(new_context);
        }
        // `unwrap` is safe here because we ensure `compressor_context` is `Some` above.
        self.compressor_context.as_mut().unwrap()
    }

    /// Retrieves the existing decompressor context for the given CID, or initializes a new one
    /// if no context exists or if the existing context is for a different CID.
    ///
    /// Unlike the compressor, this does not re-initialize based on packet content here;
    /// re-initialization for decompressor typically happens upon receiving an IR packet.
    ///
    /// # Arguments
    /// * `cid`: The Context Identifier for the decompressor.
    ///
    /// # Returns
    /// A mutable reference to the `RtpUdpIpP1DecompressorContext`.
    pub fn get_or_init_decompressor_context(
        &mut self,
        cid: u16,
    ) -> &mut RtpUdpIpP1DecompressorContext {
        let needs_initialization = match &self.decompressor_context {
            Some(ctx) => ctx.cid != cid,
            None => true,
        };

        if needs_initialization {
            self.decompressor_context = Some(RtpUdpIpP1DecompressorContext::new(
                cid,
                PROFILE_ID_RTP_UDP_IP, // Assuming Profile 1
            ));
        }
        // `unwrap` is safe here due to the logic above.
        self.decompressor_context.as_mut().unwrap()
    }

    /// Updates the decompressor context using data from a parsed IR packet.
    ///
    /// This first ensures a decompressor context exists for the IR packet's CID (or creates one),
    /// and then calls the context's `initialize_from_ir_packet` method.
    ///
    /// # Arguments
    /// * `ir_packet`: The parsed `RohcIrProfile1Packet`.
    ///
    /// # Returns
    /// A mutable reference to the updated `RtpUdpIpP1DecompressorContext`.
    pub fn update_decompressor_context_from_ir(
        &mut self,
        ir_packet: &RohcIrProfile1Packet,
    ) -> &mut RtpUdpIpP1DecompressorContext {
        // Get (or create) the context for the CID specified in the IR packet.
        // Note: The CID in ir_packet.cid might come from an Add-CID octet or be implicit (0).
        let context = self.get_or_init_decompressor_context(ir_packet.cid);
        context.initialize_from_ir_packet(ir_packet);
        context
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::{CompressorMode, DecompressorMode};
    use crate::protocol_types::RtpUdpIpv4Headers;
    use std::net::Ipv4Addr;

    fn sample_headers_builder(ssrc: u32, sn: u16) -> RtpUdpIpv4Headers {
        RtpUdpIpv4Headers {
            ip_src: Ipv4Addr::new(1, 1, 1, 1),
            ip_dst: Ipv4Addr::new(2, 2, 2, 2),
            udp_src_port: 1000,
            udp_dst_port: 2000,
            rtp_ssrc: ssrc,
            rtp_sequence_number: sn,
            rtp_timestamp: sn as u32 * 10,
            rtp_marker: false,
            ..Default::default()
        }
    }

    #[test]
    fn get_or_init_compressor_context_creation_and_retrieval() {
        let mut manager = SimpleContextManager::new();
        let headers1 = sample_headers_builder(123, 10);

        let context1 = manager.get_or_init_compressor_context(0, &headers1);
        assert_eq!(context1.cid, 0);
        assert_eq!(context1.ip_source, headers1.ip_src);
        assert_eq!(context1.rtp_ssrc, headers1.rtp_ssrc);
        assert_eq!(context1.mode, CompressorMode::InitializationAndRefresh);
        assert_eq!(context1.last_sent_rtp_sn_full, headers1.rtp_sequence_number);

        let headers1_next_packet = RtpUdpIpv4Headers {
            rtp_sequence_number: headers1.rtp_sequence_number + 1,
            ..headers1.clone()
        };
        let context1_again = manager.get_or_init_compressor_context(0, &headers1_next_packet);
        assert_eq!(
            context1_again.last_sent_rtp_sn_full, headers1.rtp_sequence_number,
            "Context SN should reflect the first initialization, not the 'get' call's headers if flow is same."
        );
        assert_eq!(
            context1_again.mode,
            CompressorMode::InitializationAndRefresh,
            "Mode should remain IR if it was just initialized, compressor logic will transition it."
        );
    }

    #[test]
    fn get_or_init_compressor_context_reinitializes_for_new_flow() {
        let mut manager = SimpleContextManager::new();
        let headers_flow1 = sample_headers_builder(123, 10);
        let _context_flow1 = manager.get_or_init_compressor_context(0, &headers_flow1);

        let headers_flow2 = sample_headers_builder(456, 20);
        let context_flow2 = manager.get_or_init_compressor_context(0, &headers_flow2);

        assert_eq!(context_flow2.rtp_ssrc, headers_flow2.rtp_ssrc);
        assert_eq!(
            context_flow2.last_sent_rtp_sn_full,
            headers_flow2.rtp_sequence_number
        );
        assert_eq!(context_flow2.mode, CompressorMode::InitializationAndRefresh);
    }

    #[test]
    fn get_or_init_compressor_context_reinitializes_for_new_cid() {
        let mut manager = SimpleContextManager::new();
        let headers1 = sample_headers_builder(123, 10);
        let _context_cid0 = manager.get_or_init_compressor_context(0, &headers1);

        let context_cid1 = manager.get_or_init_compressor_context(1, &headers1);

        assert_eq!(context_cid1.cid, 1);
        assert_eq!(context_cid1.rtp_ssrc, headers1.rtp_ssrc);
        assert_eq!(
            context_cid1.last_sent_rtp_sn_full,
            headers1.rtp_sequence_number
        );
        assert_eq!(context_cid1.mode, CompressorMode::InitializationAndRefresh);
    }

    #[test]
    fn get_or_init_decompressor_context_creation_and_retrieval() {
        let mut manager = SimpleContextManager::new();

        let context1 = manager.get_or_init_decompressor_context(0);
        assert_eq!(context1.cid, 0);
        assert_eq!(context1.profile_id, PROFILE_ID_RTP_UDP_IP);
        assert_eq!(context1.mode, DecompressorMode::NoContext);

        let context1_ptr_before = context1 as *mut _;
        let context1_again = manager.get_or_init_decompressor_context(0);
        let context1_ptr_after = context1_again as *mut _;
        assert_eq!(
            context1_ptr_before, context1_ptr_after,
            "Should be the same context instance"
        );
    }

    #[test]
    fn get_or_init_decompressor_context_creates_new_for_different_cid() {
        let mut manager = SimpleContextManager::new();

        // First call for CID 0
        let cid0_value;
        {
            let context_cid0 = manager.get_or_init_decompressor_context(0);
            assert_eq!(context_cid0.cid, 0);
            cid0_value = context_cid0.cid;
        }

        // Second call for CID 5 - manager can now be mutably borrowed again
        let cid5_value;
        {
            let context_cid5 = manager.get_or_init_decompressor_context(5);
            assert_eq!(context_cid5.cid, 5);
            cid5_value = context_cid5.cid;
        }

        assert_ne!(cid0_value, cid5_value, "CIDs should differ");
    }

    #[test]
    fn update_decompressor_context_from_ir_packet() {
        let mut manager = SimpleContextManager::new();
        let ir_data = RohcIrProfile1Packet {
            cid: 0,
            profile: PROFILE_ID_RTP_UDP_IP,
            static_rtp_ssrc: 999,
            dyn_rtp_sn: 100,
            ..Default::default()
        };

        assert!(manager.decompressor_context.is_none());

        let context_after_update = manager.update_decompressor_context_from_ir(&ir_data);
        assert_eq!(context_after_update.cid, 0);
        assert_eq!(context_after_update.rtp_ssrc, 999);
        assert_eq!(context_after_update.last_reconstructed_rtp_sn_full, 100);
        assert_eq!(context_after_update.mode, DecompressorMode::FullContext);

        let ir_data_cid5 = RohcIrProfile1Packet {
            cid: 5,
            profile: PROFILE_ID_RTP_UDP_IP,
            static_rtp_ssrc: 888,
            dyn_rtp_sn: 200,
            ..Default::default()
        };
        let context_cid5_after_update = manager.update_decompressor_context_from_ir(&ir_data_cid5);
        assert_eq!(context_cid5_after_update.cid, 5);
        assert_eq!(context_cid5_after_update.rtp_ssrc, 888);
        assert_eq!(
            context_cid5_after_update.mode,
            DecompressorMode::FullContext
        );
    }
}
