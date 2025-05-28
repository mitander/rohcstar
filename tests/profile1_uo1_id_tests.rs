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
    assert_eq!(decomp_ctx.last_reconstructed_ip_id_full, 0);

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

    assert_eq!(compressed2.len(), 3);
    assert_eq!(compressed2[0], P1_UO_1_ID_DISCRIMINATOR);
    assert_eq!(compressed2[1], (target_ip_id_for_uo1id & 0xFF) as u8);

    let decompressed_generic2 = engine.decompress(&compressed2).unwrap();
    let decomp_headers2 = decompressed_generic2.as_rtp_udp_ipv4().unwrap();

    assert_eq!(decomp_headers2.rtp_sequence_number, sn2);
    assert_eq!(decomp_headers2.rtp_timestamp, Timestamp::new(ts2_val));
    assert_eq!(decomp_headers2.rtp_marker, marker2);

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

#[test]
fn p1_uo1_id_large_ipid_jump_forces_ir() {
    // Renamed test
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
    let target_ip_id_for_next_packet = 260; // This is a large jump from typical ip_id_in_ir_context

    let headers2 =
        create_rtp_headers(sn2, ts2_val, marker2, ssrc).with_ip_id(target_ip_id_for_next_packet);
    let generic2 = GenericUncompressedHeaders::RtpUdpIpv4(headers2.clone());
    let compressed2 = engine
        .compress(cid, Some(RohcProfile::RtpUdpIp), &generic2)
        .unwrap();

    assert_eq!(compressed2.len(), 26);
    assert_eq!(compressed2[0], P1_ROHC_IR_PACKET_TYPE_WITH_DYN);
}

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

    // Establish an IR context, then manipulate the compressor's context
    // to simulate a state where the last sent IP-ID was high.
    establish_ir_context(&mut engine, cid, base_sn, base_ts_val, base_marker, ssrc);

    let comp_ctx_dyn = engine
        .context_manager_mut()
        .get_compressor_context_mut(cid)
        .unwrap();
    let p1_comp_ctx = comp_ctx_dyn
        .as_any_mut()
        .downcast_mut::<Profile1CompressorContext>()
        .unwrap();
    p1_comp_ctx.last_sent_rtp_sn_full = base_sn; // Align with IR
    p1_comp_ctx.last_sent_rtp_ts_full = Timestamp::new(base_ts_val); // Align with IR
    p1_comp_ctx.last_sent_rtp_marker = base_marker; // Align with IR
    p1_comp_ctx.last_sent_ip_id_full = 65533; // Set a high last IP-ID
    p1_comp_ctx.mode = rohcstar::profiles::profile1::context::Profile1CompressorMode::FirstOrder; // Move out of IR mode

    // Next packet: SN increments, TS/Marker same, IP-ID wraps around to a small value (e.g., 2)
    // The effective change in IP-ID is small (65533 -> 65534 -> 65535 -> 0 -> 1 -> 2, which is +4).
    let next_sn = base_sn.wrapping_add(1);
    let target_actual_ip_id: u16 = 2;

    let headers_wrap =
        create_rtp_headers(next_sn, base_ts_val, base_marker, ssrc).with_ip_id(target_actual_ip_id);
    let generic_wrap = GenericUncompressedHeaders::RtpUdpIpv4(headers_wrap.clone());

    let compressed_wrap = engine
        .compress(cid, Some(RohcProfile::RtpUdpIp), &generic_wrap)
        .unwrap();

    // Expect UO-1-ID because SN+1, TS/Marker same, and IP-ID effectively changed by a small amount (+4).
    // The LSBs sent in the packet for IP-ID should be 2.
    assert_eq!(
        compressed_wrap.len(),
        3,
        "UO-1-ID expected for IP-ID wraparound with small effective diff"
    );
    assert_eq!(
        compressed_wrap[0], P1_UO_1_ID_DISCRIMINATOR,
        "Packet type should be UO-1-ID"
    );
    assert_eq!(
        compressed_wrap[1], target_actual_ip_id as u8,
        "IP-ID LSB in packet should be target IP-ID's LSB"
    );

    // Decompress and verify
    // Decompressor's context `last_reconstructed_ip_id_full` was 0 after IR.
    // When it sees IP-ID LSB = 2, it should reconstruct to 2.
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

    let comp_ctx_ir = get_compressor_context(&engine, cid);
    assert_eq!(comp_ctx_ir.last_sent_ip_id_full, ip_id_for_ir_context);

    let sn2 = initial_sn.wrapping_add(2);
    let ts2_val = initial_ts_val;
    let marker2 = initial_marker;
    let ip_id2 = ip_id_for_ir_context.wrapping_add(5);

    let headers2 = create_rtp_headers(sn2, ts2_val, marker2, ssrc).with_ip_id(ip_id2);

    let generic2 = GenericUncompressedHeaders::RtpUdpIpv4(headers2.clone());
    let compressed2 = engine
        .compress(cid, Some(RohcProfile::RtpUdpIp), &generic2)
        .unwrap();

    assert_eq!(compressed2.len(), 3);
    assert_ne!(compressed2[0], P1_UO_1_ID_DISCRIMINATOR);
    assert_eq!(compressed2[0] & 0b11111110, P1_UO_1_SN_PACKET_TYPE_PREFIX);

    let decompressed_generic2 = engine.decompress(&compressed2).unwrap();
    let decomp_headers2 = decompressed_generic2.as_rtp_udp_ipv4().unwrap();

    assert_eq!(decomp_headers2.rtp_sequence_number, sn2);
    assert_eq!(decomp_headers2.ip_identification, 0);
}

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

    let comp_ctx_ir = get_compressor_context(&engine, cid);
    assert_eq!(comp_ctx_ir.last_sent_ip_id_full, ip_id_for_ir_context);

    let sn2 = initial_sn.wrapping_add(1);
    let ts2_val = initial_ts_val.wrapping_add(100);
    let marker2 = initial_marker;
    let ip_id2 = ip_id_for_ir_context.wrapping_add(7);

    let headers2 = create_rtp_headers(sn2, ts2_val, marker2, ssrc).with_ip_id(ip_id2);

    let generic2 = GenericUncompressedHeaders::RtpUdpIpv4(headers2.clone());
    let compressed2 = engine
        .compress(cid, Some(RohcProfile::RtpUdpIp), &generic2)
        .unwrap();

    assert_eq!(compressed2.len(), 3);
    assert_ne!(compressed2[0], P1_UO_1_ID_DISCRIMINATOR);
    assert_ne!(compressed2[0], P1_UO_1_TS_DISCRIMINATOR);
    assert_eq!(compressed2[0] & 0b11111110, P1_UO_1_SN_PACKET_TYPE_PREFIX);

    let decompressed_generic2 = engine.decompress(&compressed2).unwrap();
    let decomp_headers2 = decompressed_generic2.as_rtp_udp_ipv4().unwrap();

    assert_eq!(decomp_headers2.rtp_sequence_number, sn2);
    assert_eq!(
        decomp_headers2.rtp_timestamp,
        Timestamp::new(initial_ts_val)
    );
    assert_eq!(decomp_headers2.ip_identification, 0);
}
