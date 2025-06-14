//! Tests for Profile 1 compression logic.

use crate::crc::CrcCalculators;
use crate::error::{CompressionError, RohcError};
use crate::traits::RohcCompressorContext;
use std::time::Instant;

use super::super::constants::*;
use super::super::context::{Profile1CompressorContext, Profile1CompressorMode};
use crate::protocol_types::RtpUdpIpv4Headers;
use super::uo_compression::compress_as_uo;

fn create_test_context(
    ssrc: u32,
    last_sn: u16,
    last_ts: u32,
    last_marker: bool,
    last_ip_id: u16,
) -> Profile1CompressorContext {
    let mut context = Profile1CompressorContext::new(0.into(), 20, Instant::now());
    context.rtp_ssrc = ssrc.into();
    context.last_sent_rtp_sn_full = last_sn.into();
    context.last_sent_rtp_ts_full = last_ts.into();
    context.last_sent_rtp_marker = last_marker;
    context.last_sent_ip_id_full = last_ip_id.into();
    context.mode = Profile1CompressorMode::FirstOrder;
    context
}

fn create_test_headers(ssrc: u32, sn: u16, ts: u32, marker: bool, ip_id: u16) -> RtpUdpIpv4Headers {
    RtpUdpIpv4Headers {
        rtp_ssrc: ssrc.into(),
        rtp_sequence_number: sn.into(),
        rtp_timestamp: ts.into(),
        rtp_marker: marker,
        ip_identification: ip_id.into(),
        ip_src: "192.168.0.1".parse().unwrap(),
        ip_dst: "192.168.0.2".parse().unwrap(),
        udp_src_port: 1000,
        udp_dst_port: 2000,
        ..Default::default()
    }
}

#[test]
fn compress_as_uo_selects_uo0() {
    let crc_calculators = CrcCalculators::new();
    let mut context = create_test_context(1, 100, 1000, false, 10);
    let headers = create_test_headers(1, 101, 1000, false, 10); // Only SN changed, TS/IP-ID static

    let mut packet_buf = [0u8; 16];
    let packet_len =
        compress_as_uo(&mut context, &headers, &crc_calculators, &mut packet_buf).unwrap();
    let packet = &packet_buf[..packet_len];
    assert_eq!(packet.len(), 1, "UO-0 packet should be 1 byte");
    assert_eq!(packet[0] & 0x80, 0, "UO-0 discriminator check");
}

#[test]
fn compress_as_uo_uo0_requires_static_fields() {
    let crc_calculators = CrcCalculators::new();
    let mut context = create_test_context(1, 100, 1000, false, 10);

    // UO-0 should NOT be selected when timestamp changes, even with stride
    context.ts_stride = Some(160);
    let headers_ts_changed = create_test_headers(1, 101, 1160, false, 10); // TS changed

    let mut packet_buf = [0u8; 16];
    let packet_len = compress_as_uo(
        &mut context,
        &headers_ts_changed,
        &crc_calculators,
        &mut packet_buf,
    )
    .unwrap();
    let packet = &packet_buf[..packet_len];
    assert_ne!(
        packet.len(),
        1,
        "UO-0 should not be selected when timestamp changes"
    );

    // UO-0 should NOT be selected when IP-ID changes
    let mut context2 = create_test_context(1, 100, 1000, false, 10);
    let headers_ip_id_changed = create_test_headers(1, 101, 1000, false, 11); // IP-ID changed

    let mut packet_buf2 = [0u8; 16];
    let packet_len2 = compress_as_uo(
        &mut context2,
        &headers_ip_id_changed,
        &crc_calculators,
        &mut packet_buf2,
    )
    .unwrap();
    let packet2 = &packet_buf2[..packet_len2];
    assert_ne!(
        packet2.len(),
        1,
        "UO-0 should not be selected when IP-ID changes"
    );
}

#[test]
fn compress_as_uo_selects_uo1_sn_marker_change() {
    let crc_calculators = CrcCalculators::new();
    let mut context = create_test_context(1, 100, 1000, false, 10); // last_marker = false
    context.ts_stride = Some(160); // UO-1-SN requires stride established
    let headers = create_test_headers(1, 101, 1000, true, 10); // current_marker = true (changed)

    let mut packet_buf = [0u8; 16];
    let packet_len =
        compress_as_uo(&mut context, &headers, &crc_calculators, &mut packet_buf).unwrap();
    let packet = &packet_buf[..packet_len];
    assert_eq!(packet.len(), 3, "UO-1-SN packet should be 3 bytes");
    assert_eq!(
        packet[0] & P1_UO_1_SN_PACKET_TYPE_PREFIX, // Check base prefix for UO-1-SN
        P1_UO_1_SN_PACKET_TYPE_PREFIX
    );
    assert_ne!(
        packet[0] & P1_UO_1_SN_MARKER_BIT_MASK,
        0,
        "Marker bit should be set in UO-1-SN type octet"
    );
}

#[test]
fn compress_as_uo_selects_uo1_ts() {
    let crc_calculators = CrcCalculators::new();
    let mut context = create_test_context(1, 100, 1000, false, 10);
    let headers = create_test_headers(1, 101, 2000, false, 10); // SN+1, TS changed significantly

    let mut packet_buf = [0u8; 16];
    let packet_len =
        compress_as_uo(&mut context, &headers, &crc_calculators, &mut packet_buf).unwrap();
    let packet = &packet_buf[..packet_len];
    assert_eq!(packet.len(), 4, "UO-1-TS packet should be 4 bytes");
    assert_eq!(packet[0], P1_UO_1_TS_DISCRIMINATOR);
}

#[test]
fn compress_as_uo_selects_uo1_id() {
    let crc_calculators = CrcCalculators::new();
    let mut context = create_test_context(1, 100, 1000, false, 10);
    let headers = create_test_headers(1, 101, 1000, false, 11); // IP-ID changes, SN+1, TS same

    let mut packet_buf = [0u8; 16];
    let packet_len =
        compress_as_uo(&mut context, &headers, &crc_calculators, &mut packet_buf).unwrap();
    let packet = &packet_buf[..packet_len];
    assert_eq!(packet.len(), 3, "UO-1-ID packet should be 3 bytes");
    assert_eq!(packet[0], P1_UO_1_ID_DISCRIMINATOR);
}

#[test]
fn compress_as_uo_selects_uo1_rtp_scaled_mode() {
    let crc_calculators = CrcCalculators::new();
    let mut context = create_test_context(1, 100, 1000, false, 10);
    context.ts_scaled_mode = true;
    context.ts_stride = Some(160);
    context.ts_offset = 1000.into(); // TS_Offset aligned with last_sent_ts_full for this test

    let headers = create_test_headers(1, 101, 1160, false, 10); // current_ts = offset + 1 * stride

    let mut packet_buf = [0u8; 16];
    let packet_len =
        compress_as_uo(&mut context, &headers, &crc_calculators, &mut packet_buf).unwrap();
    let packet = &packet_buf[..packet_len];
    assert_eq!(packet.len(), 3, "UO-1-RTP packet should be 3 bytes");
    assert_eq!(
        packet[0] & !P1_UO_1_RTP_MARKER_BIT_MASK, // Check base without marker bit
        P1_UO_1_RTP_DISCRIMINATOR_BASE
    );
    assert_eq!(packet[1], 1, "TS_SCALED should be 1"); // (1160 - 1000) / 160 = 1
}

#[test]
fn compress_as_uo_error_no_stride_for_fallback() {
    let crc_calculators = CrcCalculators::new();
    let mut context = create_test_context(1, 100, 1000, false, 10);
    context.ts_stride = None; // Ensure no stride for UO-1-SN fallback

    // Conditions that would typically lead to UO-1-SN if stride existed (e.g., marker change, SN jump > 15)
    let headers = create_test_headers(1, 120, 1000, true, 10); // SN delta 20, marker true

    let mut packet_buf = [0u8; 16];
    let result = compress_as_uo(&mut context, &headers, &crc_calculators, &mut packet_buf);
    assert!(
        result.is_err(),
        "Should return error when no stride for UO-1-SN fallback"
    );

    if let Err(RohcError::Compression(CompressionError::ContextInsufficient { cid, field })) =
        result
    {
        assert_eq!(cid, *context.cid());
        assert_eq!(field, crate::error::Field::TsScaled);
    } else {
        panic!("Expected InvalidState error, got {:?}", result);
    }
}

#[test]
fn mode_transition_to_second_order() {
    let crc_calculators = CrcCalculators::new();
    let mut context = create_test_context(1, 100, 1000, false, 10);
    context.mode = Profile1CompressorMode::FirstOrder;
    context.consecutive_fo_packets_sent = P1_COMPRESSOR_FO_TO_SO_THRESHOLD - 1; // One short of threshold

    let headers = create_test_headers(1, 101, 1000, false, 10); // UO-0 conditions
    let mut packet_buf = [0u8; 16];
    let _ = compress_as_uo(&mut context, &headers, &crc_calculators, &mut packet_buf).unwrap();

    assert_eq!(context.mode, Profile1CompressorMode::SecondOrder);
    assert_eq!(context.consecutive_fo_packets_sent, 0); // Reset after transition
}
