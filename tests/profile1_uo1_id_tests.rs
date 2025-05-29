//! Integration tests for ROHC Profile 1 UO-1-ID packet handling.
//!
//! This module tests the UO-1-ID packet format, which is used when the
//! IP Identification field changes, while RTP SN increments by one, and
//! RTP TS and Marker bit remain unchanged from the context.
//! (RFC 3095, Section 5.7.5)

mod common;
use common::{
    create_rtp_headers, create_test_engine_with_system_clock, establish_ir_context,
    get_compressor_context, get_decompressor_context, get_ip_id_established_by_ir,
};

use rohcstar::packet_defs::{GenericUncompressedHeaders, RohcProfile};
use rohcstar::profiles::profile1::context::Profile1CompressorContext;
use rohcstar::profiles::profile1::protocol_types::Timestamp;
use rohcstar::profiles::profile1::{
    P1_ROHC_IR_PACKET_TYPE_WITH_DYN, P1_UO_1_ID_DISCRIMINATOR, P1_UO_1_SN_PACKET_TYPE_PREFIX,
    P1_UO_1_TS_DISCRIMINATOR, Profile1Handler,
};

/// Tests basic UO-1-ID packet compression and decompression when IP-ID changes
/// and SN increments by one, with TS and Marker stable.
#[test]
fn p1_uo1_id_basic_ipid_change_sn_plus_one() {
    let mut engine = create_test_engine_with_system_clock(100);
    engine
        .register_profile_handler(Box::new(Profile1Handler::new()))
        .unwrap();
    let cid = 0u16;
    let ssrc = 0x1122EEFF;

    let initial_sn: u16 = 50;
    let initial_ts_val: u32 = 5000;
    let initial_marker = false;

    establish_ir_context(
        &mut engine,
        cid,
        initial_sn,
        initial_ts_val,
        initial_marker,
        ssrc,
    );
    let ip_id_in_ir_context = get_ip_id_established_by_ir(initial_sn, ssrc);

    let comp_ctx = get_compressor_context(&engine, cid);
    assert_eq!(comp_ctx.last_sent_ip_id_full, ip_id_in_ir_context);
    let decomp_ctx = get_decompressor_context(&engine, cid);
    assert_eq!(decomp_ctx.last_reconstructed_ip_id_full, 0); // Decompressor IP-ID is 0 after IR for P1

    let sn2 = initial_sn.wrapping_add(1);
    let ts2_val = initial_ts_val;
    let marker2 = initial_marker;

    let target_ip_id_for_uo1id = ip_id_in_ir_context.wrapping_add(10);
    let headers2 =
        create_rtp_headers(sn2, ts2_val, marker2, ssrc).with_ip_id(target_ip_id_for_uo1id);

    let generic2 = GenericUncompressedHeaders::RtpUdpIpv4(headers2.clone());
    let compressed2 = engine
        .compress(cid, Some(RohcProfile::RtpUdpIp), &generic2)
        .unwrap();

    assert_eq!(compressed2.len(), 3); // Type + IP-ID LSB + CRC8
    assert_eq!(compressed2[0], P1_UO_1_ID_DISCRIMINATOR);
    assert_eq!(compressed2[1], (target_ip_id_for_uo1id & 0xFF) as u8); // Sent IP-ID LSB

    let decompressed_generic2 = engine.decompress(&compressed2).unwrap();
    let decomp_headers2 = decompressed_generic2.as_rtp_udp_ipv4().unwrap();

    assert_eq!(decomp_headers2.rtp_sequence_number, sn2);
    assert_eq!(decomp_headers2.rtp_timestamp, Timestamp::new(ts2_val));
    assert_eq!(decomp_headers2.rtp_marker, marker2);

    // Decompressor reconstructs IP-ID using LSBs relative to its context's IP-ID (0 after IR)
    let expected_reconstructed_ip_id = target_ip_id_for_uo1id & 0xFF;
    assert_eq!(
        decomp_headers2.ip_identification,
        expected_reconstructed_ip_id
    );

    let comp_ctx_after = get_compressor_context(&engine, cid);
    assert_eq!(comp_ctx_after.last_sent_rtp_sn_full, sn2);
    assert_eq!(comp_ctx_after.last_sent_ip_id_full, target_ip_id_for_uo1id);

    let decomp_ctx_after = get_decompressor_context(&engine, cid);
    assert_eq!(decomp_ctx_after.last_reconstructed_rtp_sn_full, sn2);
    assert_eq!(
        decomp_ctx_after.last_reconstructed_ip_id_full,
        expected_reconstructed_ip_id
    );
    assert_eq!(
        decomp_ctx_after.last_reconstructed_rtp_ts_full,
        Timestamp::new(initial_ts_val)
    );
}

/// Verifies that a large jump in IP-ID (beyond LSB encodable range for UO-1-ID)
/// forces the compressor to send an IR packet.
#[test]
fn p1_uo1_id_large_ipid_jump_forces_ir() {
    let mut engine = create_test_engine_with_system_clock(100);
    engine
        .register_profile_handler(Box::new(Profile1Handler::new()))
        .unwrap();
    let cid = 0u16;
    let ssrc = 0x3344AABB;

    let initial_sn: u16 = 70;
    let initial_ts_val: u32 = 7000;
    let initial_marker = true;

    establish_ir_context(
        &mut engine,
        cid,
        initial_sn,
        initial_ts_val,
        initial_marker,
        ssrc,
    );
    let ip_id_in_ir_context = get_ip_id_established_by_ir(initial_sn, ssrc);

    let comp_ctx_ir = get_compressor_context(&engine, cid);
    assert_eq!(comp_ctx_ir.last_sent_ip_id_full, ip_id_in_ir_context);

    let sn2 = initial_sn.wrapping_add(1);
    let ts2_val = initial_ts_val;
    let marker2 = initial_marker;
    // Large jump, UO-1-ID uses 8 LSBs for IP-ID. Max delta approx 127 (2^7-1).
    // 260 is chosen to be > 127.
    let target_ip_id_for_next_packet = ip_id_in_ir_context.wrapping_add(260);

    let headers2 =
        create_rtp_headers(sn2, ts2_val, marker2, ssrc).with_ip_id(target_ip_id_for_next_packet);
    let generic2 = GenericUncompressedHeaders::RtpUdpIpv4(headers2.clone());
    let compressed2 = engine
        .compress(cid, Some(RohcProfile::RtpUdpIp), &generic2)
        .unwrap();

    assert_eq!(compressed2.len(), 26); // IR packet length for CID 0
    assert_eq!(compressed2[0], P1_ROHC_IR_PACKET_TYPE_WITH_DYN);
}

/// Tests IP-ID LSB reconstruction when the IP-ID value wraps around (e.g., from 65533 to 2),
/// ensuring UO-1-ID is used if the effective difference is small.
#[test]
fn p1_uo1_id_ipid_lsb_wraparound_reconstruction() {
    let mut engine = create_test_engine_with_system_clock(100);
    engine
        .register_profile_handler(Box::new(Profile1Handler::new()))
        .unwrap();
    let cid = 0u16;
    let ssrc = 0x4455BBCC;
    let base_sn = 400;
    let base_ts_val: u32 = 4000;
    let base_marker = false;

    establish_ir_context(&mut engine, cid, base_sn, base_ts_val, base_marker, ssrc);

    // Manipulate compressor context to simulate high last_sent_ip_id_full
    let comp_ctx_dyn = engine
        .context_manager_mut()
        .get_compressor_context_mut(cid)
        .unwrap();
    let p1_comp_ctx = comp_ctx_dyn
        .as_any_mut()
        .downcast_mut::<Profile1CompressorContext>()
        .unwrap();
    p1_comp_ctx.last_sent_rtp_sn_full = base_sn;
    p1_comp_ctx.last_sent_rtp_ts_full = Timestamp::new(base_ts_val);
    p1_comp_ctx.last_sent_rtp_marker = base_marker;
    p1_comp_ctx.last_sent_ip_id_full = 65533; // High previous IP-ID
    p1_comp_ctx.mode = rohcstar::profiles::profile1::context::Profile1CompressorMode::FirstOrder;

    let next_sn = base_sn.wrapping_add(1);
    let target_actual_ip_id: u16 = 2; // IP-ID wraps around to a small value

    let headers_wrap =
        create_rtp_headers(next_sn, base_ts_val, base_marker, ssrc).with_ip_id(target_actual_ip_id);
    let generic_wrap = GenericUncompressedHeaders::RtpUdpIpv4(headers_wrap.clone());

    let compressed_wrap = engine
        .compress(cid, Some(RohcProfile::RtpUdpIp), &generic_wrap)
        .unwrap();

    assert_eq!(
        compressed_wrap.len(),
        3,
        "Expected UO-1-ID for IP-ID wraparound"
    );
    assert_eq!(
        compressed_wrap[0], P1_UO_1_ID_DISCRIMINATOR,
        "Packet type should be UO-1-ID"
    );
    assert_eq!(
        compressed_wrap[1], target_actual_ip_id as u8,
        "IP-ID LSB in packet mismatch"
    );

    let decompressed_generic_wrap = engine.decompress(&compressed_wrap).unwrap();
    let decomp_headers_wrap = decompressed_generic_wrap.as_rtp_udp_ipv4().unwrap();

    assert_eq!(decomp_headers_wrap.rtp_sequence_number, next_sn);
    assert_eq!(
        decomp_headers_wrap.rtp_timestamp,
        Timestamp::new(base_ts_val)
    );
    assert_eq!(decomp_headers_wrap.rtp_marker, base_marker);
    assert_eq!(
        decomp_headers_wrap.ip_identification, target_actual_ip_id,
        "Reconstructed IP-ID mismatch"
    );
}

/// Verifies that UO-1-ID is not used if SN does not increment by exactly one,
/// even if IP-ID changes and TS/Marker are stable. Expects UO-1-SN instead.
#[test]
fn p1_uo1_id_not_used_if_sn_not_plus_one() {
    let mut engine = create_test_engine_with_system_clock(100);
    engine
        .register_profile_handler(Box::new(Profile1Handler::new()))
        .unwrap();
    let cid = 0u16;
    let ssrc = 0x5566CCDD;

    let initial_sn: u16 = 80;
    let initial_ts_val: u32 = 8000;
    let initial_marker = false;

    establish_ir_context(
        &mut engine,
        cid,
        initial_sn,
        initial_ts_val,
        initial_marker,
        ssrc,
    );
    let ip_id_for_ir_context = get_ip_id_established_by_ir(initial_sn, ssrc);

    let sn2 = initial_sn.wrapping_add(2); // SN increments by 2
    let ts2_val = initial_ts_val;
    let marker2 = initial_marker;
    let ip_id2 = ip_id_for_ir_context.wrapping_add(5);

    let headers2 = create_rtp_headers(sn2, ts2_val, marker2, ssrc).with_ip_id(ip_id2);

    let generic2 = GenericUncompressedHeaders::RtpUdpIpv4(headers2.clone());
    let compressed2 = engine
        .compress(cid, Some(RohcProfile::RtpUdpIp), &generic2)
        .unwrap();

    assert_eq!(compressed2.len(), 3); // Expect UO-1-SN (Type + SN LSB + CRC8)
    assert_ne!(
        compressed2[0], P1_UO_1_ID_DISCRIMINATOR,
        "Should not be UO-1-ID"
    );
    assert_eq!(
        compressed2[0] & 0b11111110,
        P1_UO_1_SN_PACKET_TYPE_PREFIX,
        "Should be UO-1-SN type"
    );

    let decompressed_generic2 = engine.decompress(&compressed2).unwrap();
    let decomp_headers2 = decompressed_generic2.as_rtp_udp_ipv4().unwrap();

    assert_eq!(decomp_headers2.rtp_sequence_number, sn2);
    assert_eq!(decomp_headers2.ip_identification, 0); // IP-ID not in UO-1-SN
}

/// Verifies that UO-1-ID is not used if RTP Timestamp changes, even if SN increments by one
/// and IP-ID changes. Expects UO-1-SN as fallback (since both TS and IP-ID changed).
#[test]
fn p1_uo1_id_not_used_if_ts_changes() {
    let mut engine = create_test_engine_with_system_clock(100);
    engine
        .register_profile_handler(Box::new(Profile1Handler::new()))
        .unwrap();
    let cid = 0u16;
    let ssrc = 0x7788EEFF;

    let initial_sn: u16 = 90;
    let initial_ts_val: u32 = 9000;
    let initial_marker = false;

    establish_ir_context(
        &mut engine,
        cid,
        initial_sn,
        initial_ts_val,
        initial_marker,
        ssrc,
    );
    let ip_id_for_ir_context = get_ip_id_established_by_ir(initial_sn, ssrc);

    let sn2 = initial_sn.wrapping_add(1);
    let ts2_val = initial_ts_val.wrapping_add(100); // TS changes
    let marker2 = initial_marker;
    let ip_id2 = ip_id_for_ir_context.wrapping_add(7); // IP-ID also changes

    let headers2 = create_rtp_headers(sn2, ts2_val, marker2, ssrc).with_ip_id(ip_id2);

    let generic2 = GenericUncompressedHeaders::RtpUdpIpv4(headers2.clone());
    let compressed2 = engine
        .compress(cid, Some(RohcProfile::RtpUdpIp), &generic2)
        .unwrap();

    // Since both TS and IP-ID changed, it should fall back to UO-1-SN.
    assert_eq!(compressed2.len(), 3); // Expect UO-1-SN
    assert_ne!(
        compressed2[0], P1_UO_1_ID_DISCRIMINATOR,
        "Should not be UO-1-ID"
    );
    assert_ne!(
        compressed2[0], P1_UO_1_TS_DISCRIMINATOR,
        "Should not be UO-1-TS directly"
    );
    assert_eq!(
        compressed2[0] & 0b11111110,
        P1_UO_1_SN_PACKET_TYPE_PREFIX,
        "Should be UO-1-SN type"
    );

    let decompressed_generic2 = engine.decompress(&compressed2).unwrap();
    let decomp_headers2 = decompressed_generic2.as_rtp_udp_ipv4().unwrap();

    assert_eq!(decomp_headers2.rtp_sequence_number, sn2);
    assert_eq!(
        decomp_headers2.rtp_timestamp,
        Timestamp::new(initial_ts_val)
    ); // TS from context for UO-1-SN
    assert_eq!(decomp_headers2.ip_identification, 0); // IP-ID not in UO-1-SN
}
