use crate::context::{RtpUdpIpP1CompressorContext, RtpUdpIpP1DecompressorContext};
use crate::packet_processor::PROFILE_ID_RTP_UDP_IP;
use crate::protocol_types::RohcIrProfile1Packet;
use crate::protocol_types::RtpUdpIpv4Headers;

const DEFAULT_IR_REFRESH_INTERVAL: u32 = 20;

#[derive(Debug, Default)]
pub struct SimpleContextManager {
    compressor_context: Option<RtpUdpIpP1CompressorContext>,
    decompressor_context: Option<RtpUdpIpP1DecompressorContext>,
}

impl SimpleContextManager {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn get_or_init_compressor_context(
        &mut self,
        cid: u16,
        headers: &RtpUdpIpv4Headers,
    ) -> &mut RtpUdpIpP1CompressorContext {
        if self.compressor_context.is_none() || self.compressor_context.as_ref().unwrap().cid != cid
        {
            let mut new_context = RtpUdpIpP1CompressorContext::new(
                cid,
                PROFILE_ID_RTP_UDP_IP,
                DEFAULT_IR_REFRESH_INTERVAL,
            );
            new_context.initialize_static_part_with_uncompressed_headers(headers);
            self.compressor_context = Some(new_context);
        } else if let Some(ctx) = &mut self.compressor_context {
            if ctx.rtp_ssrc != headers.rtp_ssrc
                || ctx.ip_source != headers.ip_src
                || ctx.ip_destination != headers.ip_dst
                || ctx.udp_source_port != headers.udp_src_port
                || ctx.udp_destination_port != headers.udp_dst_port
            {
                ctx.initialize_static_part_with_uncompressed_headers(headers);
            }
        }
        self.compressor_context.as_mut().unwrap()
    }

    pub fn get_or_init_decompressor_context(
        &mut self,
        cid: u16,
    ) -> &mut RtpUdpIpP1DecompressorContext {
        if self.decompressor_context.is_none()
            || self.decompressor_context.as_ref().unwrap().cid != cid
        {
            self.decompressor_context = Some(RtpUdpIpP1DecompressorContext::new(
                cid,
                PROFILE_ID_RTP_UDP_IP,
            ));
        }
        self.decompressor_context.as_mut().unwrap()
    }

    pub fn update_decompressor_context_from_ir(
        &mut self,
        ir_packet: &RohcIrProfile1Packet,
    ) -> &mut RtpUdpIpP1DecompressorContext {
        let context = self.get_or_init_decompressor_context(ir_packet.cid);
        context.initialize_from_ir_packet(ir_packet);
        context
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol_types::RtpUdpIpv4Headers;
    use std::net::Ipv4Addr;

    #[test]
    fn test_get_or_init_compressor_context() {
        let mut manager = SimpleContextManager::new();
        let headers = RtpUdpIpv4Headers {
            ip_src: Ipv4Addr::new(1, 1, 1, 1),
            rtp_ssrc: 123,
            ..Default::default()
        };

        let context = manager.get_or_init_compressor_context(0, &headers);
        assert_eq!(context.cid, 0);
        assert_eq!(context.ip_source, headers.ip_src);
        assert_eq!(context.rtp_ssrc, headers.rtp_ssrc);

        // Call again, should return same context without re-init if headers match key fields
        let headers_same_flow = RtpUdpIpv4Headers {
            ip_src: Ipv4Addr::new(1, 1, 1, 1),
            rtp_ssrc: 123,
            rtp_sequence_number: headers.rtp_sequence_number + 1, // only SN changed
            ..Default::default()
        };
        let context_again = manager.get_or_init_compressor_context(0, &headers_same_flow);
        // Should not have re-initialized last_sent from new header
        assert_eq!(
            context_again.last_sent_rtp_sn_full,
            headers.rtp_sequence_number
        );

        // Call with different SSRC, should re-initialize
        let headers_different_flow = RtpUdpIpv4Headers {
            ip_src: Ipv4Addr::new(1, 1, 1, 1),
            rtp_ssrc: 456, // Different SSRC
            rtp_sequence_number: 10,
            ..Default::default()
        };
        let context_new_flow = manager.get_or_init_compressor_context(0, &headers_different_flow);
        assert_eq!(context_new_flow.rtp_ssrc, 456);
        assert_eq!(context_new_flow.last_sent_rtp_sn_full, 10);
    }

    #[test]
    fn test_get_or_init_decompressor_context() {
        let mut manager = SimpleContextManager::new();
        let context = manager.get_or_init_decompressor_context(0);
        assert_eq!(context.cid, 0);
        assert_eq!(context.mode, crate::context::DecompressorMode::NoContext);

        let _ = manager.get_or_init_decompressor_context(0); // instance should be the same
    }

    #[test]
    fn test_update_decompressor_context_from_ir() {
        let mut manager = SimpleContextManager::new();
        let ir_data = crate::protocol_types::RohcIrProfile1Packet {
            cid: 0,
            static_rtp_ssrc: 999,
            dyn_rtp_sn: 100,
            ..Default::default()
        };
        let context = manager.update_decompressor_context_from_ir(&ir_data);
        assert_eq!(context.cid, 0);
        assert_eq!(context.rtp_ssrc, 999);
        assert_eq!(context.last_reconstructed_rtp_sn_full, 100);
        assert_eq!(context.mode, crate::context::DecompressorMode::FullContext);
    }
}
