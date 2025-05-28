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
    let initial_ts = 5000;
    let initial_marker = false;

    // Establish IR context. The IP-ID set in the compressor will be derived from initial_sn and ssrc.
    establish_ir_context(
        &mut engine,
        cid,
        initial_sn,
        initial_ts,
        initial_marker,
        ssrc,
    );
    let ip_id_in_ir_context = get_ip_id_established_by_ir(initial_sn, ssrc);

    let comp_ctx = get_compressor_context(&engine, cid);
    assert_eq!(
        comp_ctx.last_sent_ip_id_full, ip_id_in_ir_context,
        "Compressor IP-ID after IR should match calculated IR IP-ID"
    );
    let decomp_ctx = get_decompressor_context(&engine, cid);
    assert_eq!(
        decomp_ctx.last_reconstructed_ip_id_full, 0,
        "Decompressor IP-ID context should be 0 after P1 IR (as IR doesn't carry IP-ID)"
    );

    // Packet 2: SN+1, TS same, Marker same, IP-ID changes. Expect UO-1-ID.
    let sn2 = initial_sn.wrapping_add(1);
    let ts2 = initial_ts; // TS must be unchanged for UO-1-ID
    let marker2 = initial_marker; // Marker must be unchanged for UO-1-ID

    // Target a new IP-ID for the UO-1-ID packet.
    // Make it a small change from the compressor's current context to ensure UO-1-ID is chosen over IR.
    let target_ip_id_for_uo1id = ip_id_in_ir_context.wrapping_add(10);
    let headers2 = create_rtp_headers(sn2, ts2, marker2, ssrc).with_ip_id(target_ip_id_for_uo1id);

    let generic2 = GenericUncompressedHeaders::RtpUdpIpv4(headers2.clone());
    let compressed2 = engine
        .compress(cid, Some(RohcProfile::RtpUdpIp), &generic2)
        .unwrap();

    // Verify UO-1-ID packet format
    assert_eq!(
        compressed2.len(),
        3,
        "UO-1-ID packet length should be 3 bytes for CID 0. Got: {:?}",
        compressed2
    );
    assert_eq!(
        compressed2[0], P1_UO_1_ID_DISCRIMINATOR,
        "Packet discriminator should be UO-1-ID type."
    );
    assert_eq!(
        compressed2[1],
        (target_ip_id_for_uo1id & 0xFF) as u8, // LSB of the target IP-ID
        "IP-ID LSB in packet should match LSB of target IP-ID."
    );

    // Decompress and verify reconstructed headers
    let decompressed_generic2 = engine.decompress(&compressed2).unwrap();
    let decomp_headers2 = decompressed_generic2.as_rtp_udp_ipv4().unwrap();

    assert_eq!(
        decomp_headers2.rtp_sequence_number, sn2,
        "Reconstructed SN mismatch."
    );
    assert_eq!(
        decomp_headers2.rtp_timestamp, ts2,
        "Reconstructed TS should be from context."
    );
    assert_eq!(
        decomp_headers2.rtp_marker, marker2,
        "Reconstructed Marker should be from context."
    );

    // Decompressor's IP-ID context was 0 after IR.
    // UO-1-ID sent LSBs of target_ip_id_for_uo1id.
    // Reconstructed IP-ID will be (target_ip_id_for_uo1id & 0xFF) due to v_ref=0 for IP-ID.
    let expected_reconstructed_ip_id = target_ip_id_for_uo1id & 0xFF;
    assert_eq!(
        decomp_headers2.ip_identification, expected_reconstructed_ip_id,
        "Reconstructed IP-ID mismatch."
    );

    // Verify context updates
    let comp_ctx_after = get_compressor_context(&engine, cid);
    assert_eq!(comp_ctx_after.last_sent_rtp_sn_full, sn2);
    assert_eq!(comp_ctx_after.last_sent_ip_id_full, target_ip_id_for_uo1id); // Compressor tracks full new IP-ID

    let decomp_ctx_after = get_decompressor_context(&engine, cid);
    assert_eq!(decomp_ctx_after.last_reconstructed_rtp_sn_full, sn2);
    assert_eq!(
        decomp_ctx_after.last_reconstructed_ip_id_full,
        expected_reconstructed_ip_id, // Decompressor context updated with LSB-reconstructed IP-ID
        "Decompressor context IP-ID after UO-1-ID mismatch."
    );
    assert_eq!(decomp_ctx_after.last_reconstructed_rtp_ts_full, initial_ts);
}

#[test]
fn p1_uo1_id_ip_id_wraparound_lsb() {
    let mut engine = create_test_engine_with_system_clock(100);
    engine
        .register_profile_handler(Box::new(Profile1Handler::new()))
        .unwrap();
    let cid = 0u16;
    let ssrc = 0x3344AABB;

    let initial_sn: u16 = 70;
    let initial_ts = 7000;
    let initial_marker = true;

    establish_ir_context(
        &mut engine,
        cid,
        initial_sn,
        initial_ts,
        initial_marker,
        ssrc,
    );
    let ip_id_in_ir_context = get_ip_id_established_by_ir(initial_sn, ssrc);

    let comp_ctx_ir = get_compressor_context(&engine, cid);
    assert_eq!(comp_ctx_ir.last_sent_ip_id_full, ip_id_in_ir_context);

    // Packet 2: SN+1.
    // Target IP-ID is 260. LSB of 260 is 4.
    // The change from ip_id_in_ir_context (e.g., 43777) to 260 is very large.
    // This will force an IR packet, not a UO-1-ID.
    let sn2 = initial_sn.wrapping_add(1);
    let ts2 = initial_ts;
    let marker2 = initial_marker;
    let target_ip_id_for_next_packet = 260; // Value whose LSB (4) is desired for the test.

    let headers2 =
        create_rtp_headers(sn2, ts2, marker2, ssrc).with_ip_id(target_ip_id_for_next_packet);
    let generic2 = GenericUncompressedHeaders::RtpUdpIpv4(headers2.clone());
    let compressed2 = engine
        .compress(cid, Some(RohcProfile::RtpUdpIp), &generic2)
        .unwrap();

    // Expect an IR packet due to the large jump in IP-ID from compressor's context.
    assert_eq!(
        compressed2.len(),
        26, // Length of IR-DYN for CID 0
        "Expected IR packet length due to large IP-ID jump. Got: {:?}",
        compressed2
    );
    assert_eq!(
        compressed2[0], P1_ROHC_IR_PACKET_TYPE_WITH_DYN,
        "Packet type should be IR-DYN due to large IP-ID jump."
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
    let initial_ts = 8000;
    let initial_marker = false;

    establish_ir_context(
        &mut engine,
        cid,
        initial_sn,
        initial_ts,
        initial_marker,
        ssrc,
    );
    let ip_id_for_ir_context = get_ip_id_established_by_ir(initial_sn, ssrc);

    let comp_ctx_ir = get_compressor_context(&engine, cid);
    assert_eq!(comp_ctx_ir.last_sent_ip_id_full, ip_id_for_ir_context);

    // Packet 2: SN+2 (not +1), IP-ID changes. Expect UO-1-SN, not UO-1-ID.
    let sn2 = initial_sn.wrapping_add(2);
    let ts2 = initial_ts; // TS must be unchanged from context
    let marker2 = initial_marker; // Marker must be unchanged
    let ip_id2 = ip_id_for_ir_context.wrapping_add(5); // IP-ID changes by a small amount

    let headers2 = create_rtp_headers(sn2, ts2, marker2, ssrc).with_ip_id(ip_id2);

    let generic2 = GenericUncompressedHeaders::RtpUdpIpv4(headers2.clone());
    let compressed2 = engine
        .compress(cid, Some(RohcProfile::RtpUdpIp), &generic2)
        .unwrap();

    // Should be UO-1-SN because SN didn't increment by exactly 1.
    assert_eq!(
        compressed2.len(),
        3,
        "Packet should be UO-1-SN when SN is not +1. Got: {:?}",
        compressed2
    );
    assert_ne!(
        compressed2[0], P1_UO_1_ID_DISCRIMINATOR,
        "Packet should not be UO-1-ID."
    );
    assert_eq!(
        compressed2[0] & 0b11111110, // Mask out marker bit
        P1_UO_1_SN_PACKET_TYPE_PREFIX,
        "Packet should be UO-1-SN type."
    );

    let decompressed_generic2 = engine.decompress(&compressed2).unwrap();
    let decomp_headers2 = decompressed_generic2.as_rtp_udp_ipv4().unwrap();

    assert_eq!(decomp_headers2.rtp_sequence_number, sn2);
    // UO-1-SN doesn't carry IP-ID. Decompressor uses its context IP-ID (0 after IR for P1).
    assert_eq!(
        decomp_headers2.ip_identification, 0,
        "Reconstructed IP-ID should be from decompressor context (0 after IR)."
    );
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
    let initial_ts = 9000;
    let initial_marker = false;

    establish_ir_context(
        &mut engine,
        cid,
        initial_sn,
        initial_ts,
        initial_marker,
        ssrc,
    );
    let ip_id_for_ir_context = get_ip_id_established_by_ir(initial_sn, ssrc);

    let comp_ctx_ir = get_compressor_context(&engine, cid);
    assert_eq!(comp_ctx_ir.last_sent_ip_id_full, ip_id_for_ir_context);

    // Packet 2: SN+1, TS changes, IP-ID also changes.
    // Expect UO-1-SN because UO-1-ID requires TS unchanged.
    // UO-1-TS would require IP-ID unchanged, which is not the case here.
    let sn2 = initial_sn.wrapping_add(1);
    let ts2 = initial_ts.wrapping_add(100); // TS changes
    let marker2 = initial_marker; // Marker same
    let ip_id2 = ip_id_for_ir_context.wrapping_add(7); // IP-ID changes

    let headers2 = create_rtp_headers(sn2, ts2, marker2, ssrc).with_ip_id(ip_id2);

    let generic2 = GenericUncompressedHeaders::RtpUdpIpv4(headers2.clone());
    let compressed2 = engine
        .compress(cid, Some(RohcProfile::RtpUdpIp), &generic2)
        .unwrap();

    // Should fall back to UO-1-SN.
    assert_eq!(
        compressed2.len(),
        3,
        "Packet should be UO-1-SN when TS changes. Got: {:?}",
        compressed2
    );
    assert_ne!(
        compressed2[0], P1_UO_1_ID_DISCRIMINATOR,
        "Packet should not be UO-1-ID."
    );
    assert_ne!(
        compressed2[0], P1_UO_1_TS_DISCRIMINATOR,
        "Packet should not be UO-1-TS as IP-ID also changed."
    );
    assert_eq!(
        compressed2[0] & 0b11111110, // Mask out marker bit
        P1_UO_1_SN_PACKET_TYPE_PREFIX,
        "Packet should be UO-1-SN type."
    );

    let decompressed_generic2 = engine.decompress(&compressed2).unwrap();
    let decomp_headers2 = decompressed_generic2.as_rtp_udp_ipv4().unwrap();

    assert_eq!(decomp_headers2.rtp_sequence_number, sn2);
    // UO-1-SN uses context for TS and IP-ID.
    assert_eq!(
        decomp_headers2.rtp_timestamp, initial_ts,
        "Reconstructed TS should be from context."
    );
    assert_eq!(
        decomp_headers2.ip_identification, 0,
        "Reconstructed IP-ID should be from decompressor context (0 after IR)."
    );
}
