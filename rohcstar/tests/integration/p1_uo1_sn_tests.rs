//! Integration tests for ROHC Profile 1 UO-1-SN packet handling.
//!
//! This module tests the UO-1-SN packet format, which provides extended sequence
//! number encoding and marker bit transmission. Tests cover sequence number jumps,
//! marker bit changes, wraparound scenarios, and packet type selection logic.

use rohcstar::packet_defs::{GenericUncompressedHeaders, RohcProfile};
use rohcstar::profiles::profile1::{
    P1_UO_1_SN_MARKER_BIT_MASK, P1_UO_1_SN_PACKET_TYPE_PREFIX, Profile1Handler, RtpUdpIpv4Headers,
};

use super::common::{
    create_rtp_headers, create_test_engine_with_system_clock, establish_ir_context,
    establish_stride_after_ir, get_compressor_context, get_decompressor_context,
    get_ip_id_established_by_ir,
};

/// Tests UO-1-SN with SN wraparound and marker bit handling.
#[test]
fn p1_uo1_sn_with_sn_wraparound() {
    let mut engine = create_test_engine_with_system_clock(200);
    engine
        .register_profile_handler(Box::new(Profile1Handler::new()))
        .unwrap();
    let cid = 0u16;
    let ssrc = 0xABCDEF01;

    let ir_sn = 65532;
    let ir_ts_val: u32 = 1000;
    let ir_marker = false;
    establish_ir_context(&mut engine, cid, ir_sn, ir_ts_val, ir_marker, ssrc);
    let ip_id_from_ir = get_ip_id_established_by_ir(ir_sn, ssrc);

    let stride_val = 160u32;
    establish_stride_after_ir(
        &mut engine,
        cid,
        ssrc,
        ir_sn,
        ir_ts_val,
        ir_marker,
        ip_id_from_ir,
        stride_val,
    );

    // Packet 1 (UO-1-SN): SN continues from stride establishment, marker true
    let comp_ctx_p1 = get_compressor_context(&engine, cid);
    let sn1: u16 = comp_ctx_p1.last_sent_rtp_sn_full.wrapping_add(1).value();
    let marker1 = true; // Marker changes
    let sn_delta_p1 = sn1.wrapping_sub(comp_ctx_p1.last_sent_rtp_sn_full.value()); // Should be 1
    let expected_ts1_val = comp_ctx_p1
        .last_sent_rtp_ts_full
        .value()
        .wrapping_add(sn_delta_p1 as u32 * stride_val);

    let headers1 =
        create_rtp_headers(sn1, expected_ts1_val, marker1, ssrc).with_ip_id(ip_id_from_ir.into());
    let generic1 = GenericUncompressedHeaders::RtpUdpIpv4(headers1.clone());
    let mut compress_buf1 = [0u8; 128];
    let compress_len1 = engine
        .compress(
            cid.into(),
            Some(RohcProfile::RtpUdpIp),
            &generic1,
            &mut compress_buf1,
        )
        .unwrap();
    let compressed1 = &compress_buf1[..compress_len1];

    assert_eq!(compressed1.len(), 3);
    assert_eq!(
        compressed1[0] & !P1_UO_1_SN_MARKER_BIT_MASK,
        P1_UO_1_SN_PACKET_TYPE_PREFIX
    );
    assert_eq!(
        compressed1[0] & P1_UO_1_SN_MARKER_BIT_MASK,
        P1_UO_1_SN_MARKER_BIT_MASK
    );

    let decomp1 = engine
        .decompress(compressed1)
        .unwrap()
        .as_rtp_udp_ipv4()
        .unwrap()
        .clone();
    assert_eq!(decomp1.rtp_sequence_number, sn1);
    assert_eq!(decomp1.rtp_marker, marker1);
    assert_eq!(decomp1.rtp_timestamp, expected_ts1_val);

    let comp_ctx_p2 = get_compressor_context(&engine, cid);
    let sn2: u16 = 2;
    let marker2 = false;
    let sn_delta_p2 = sn2.wrapping_sub(*comp_ctx_p2.last_sent_rtp_sn_full);
    let expected_ts2_val = comp_ctx_p2
        .last_sent_rtp_ts_full
        .value()
        .wrapping_add(sn_delta_p2 as u32 * stride_val);

    let headers2 =
        create_rtp_headers(sn2, expected_ts2_val, marker2, ssrc).with_ip_id(ip_id_from_ir.into());
    let generic2 = GenericUncompressedHeaders::RtpUdpIpv4(headers2.clone());

    let mut compress_buf = [0u8; 1500];
    let compressed2_len = engine
        .compress(
            cid.into(),
            Some(RohcProfile::RtpUdpIp),
            &generic2,
            &mut compress_buf,
        )
        .unwrap();
    let compressed2 = &compress_buf[..compressed2_len];

    assert_eq!(compressed2.len(), 3);
    assert_eq!(
        compressed2[0] & !P1_UO_1_SN_MARKER_BIT_MASK,
        P1_UO_1_SN_PACKET_TYPE_PREFIX
    );
    assert_eq!(compressed2[0] & P1_UO_1_SN_MARKER_BIT_MASK, 0);

    let decomp2 = engine
        .decompress(compressed2)
        .unwrap()
        .as_rtp_udp_ipv4()
        .unwrap()
        .clone();
    assert_eq!(decomp2.rtp_sequence_number, sn2);
    assert_eq!(decomp2.rtp_marker, marker2);
    assert_eq!(decomp2.rtp_timestamp, expected_ts2_val);
}

/// Tests rapid marker bit changes forcing UO-1-SN packet selection.
#[test]
fn p1_rapid_marker_toggling_forces_uo1() {
    let mut engine = create_test_engine_with_system_clock(200);
    engine
        .register_profile_handler(Box::new(Profile1Handler::new()))
        .unwrap();
    let cid = 0u16;
    let ssrc = 0x1234FEDC;

    let initial_sn_ir = 100;
    let initial_ts_ir_val: u32 = 5000;
    let initial_marker_ir = false;

    establish_ir_context(
        &mut engine,
        cid,
        initial_sn_ir,
        initial_ts_ir_val,
        initial_marker_ir,
        ssrc,
    );
    let ip_id_from_ir = get_ip_id_established_by_ir(initial_sn_ir, ssrc);

    let stride_val = 160u32;
    establish_stride_after_ir(
        &mut engine,
        cid,
        ssrc,
        initial_sn_ir,
        initial_ts_ir_val,
        initial_marker_ir,
        ip_id_from_ir,
        stride_val,
    );

    let mut current_marker_in_loop = initial_marker_ir;

    for i in 0..5 {
        let comp_ctx_before = get_compressor_context(&engine, cid);
        let prev_sn_in_comp = comp_ctx_before.last_sent_rtp_sn_full;
        let prev_ts_in_comp = comp_ctx_before.last_sent_rtp_ts_full.value();

        let current_loop_sn = prev_sn_in_comp.wrapping_add(1); // SN always increments by 1 from previous
        current_marker_in_loop = !current_marker_in_loop; // Toggle for this packet

        let sn_delta_for_comp = current_loop_sn.wrapping_sub(prev_sn_in_comp); // Will be 1
        let ts_val_for_packet = prev_ts_in_comp.wrapping_add(sn_delta_for_comp as u32 * stride_val);

        let headers = create_rtp_headers(
            *current_loop_sn,
            ts_val_for_packet,
            current_marker_in_loop,
            ssrc,
        )
        .with_ip_id(ip_id_from_ir.into());
        let generic = GenericUncompressedHeaders::RtpUdpIpv4(headers.clone());

        let mut compress_buf = [0u8; 1500];
        let compressed_len = engine
            .compress(
                cid.into(),
                Some(RohcProfile::RtpUdpIp),
                &generic,
                &mut compress_buf,
            )
            .unwrap_or_else(|e| {
                panic!(
                    "Compress failed iter {}: SN={}, M={}, PrevSN={}, PrevTS={}, Err: {:?}",
                    i, current_loop_sn, current_marker_in_loop, prev_sn_in_comp, prev_ts_in_comp, e
                )
            });
        let compressed = &compress_buf[..compressed_len];

        assert_eq!(
            compressed.len(),
            3,
            "Loop {}: UO-1-SN len. SN={}",
            i,
            current_loop_sn
        );
        assert_eq!(
            compressed[0] & !P1_UO_1_SN_MARKER_BIT_MASK,
            P1_UO_1_SN_PACKET_TYPE_PREFIX,
            "Loop {}: Not UO-1-SN type",
            i
        );
        if current_marker_in_loop {
            assert_eq!(
                compressed[0] & P1_UO_1_SN_MARKER_BIT_MASK,
                P1_UO_1_SN_MARKER_BIT_MASK,
                "Loop {}: Marker bit mismatch (should be 1)",
                i
            );
        } else {
            assert_eq!(
                compressed[0] & P1_UO_1_SN_MARKER_BIT_MASK,
                0,
                "Loop {}: Marker bit mismatch (should be 0)",
                i
            );
        }

        let decomp_generic = engine.decompress(compressed).unwrap_or_else(|e| {
            panic!(
                "Decompress failed iter {}: SN={}, M={}, CompPkt: {:02X?}. Err: {:?}",
                i, current_loop_sn, current_marker_in_loop, compressed, e
            )
        });
        let decomp = decomp_generic.as_rtp_udp_ipv4().unwrap().clone();

        assert_eq!(
            decomp.rtp_sequence_number, current_loop_sn,
            "Loop {}: SN mismatch",
            i
        );
        assert_eq!(
            decomp.rtp_marker, current_marker_in_loop,
            "Loop {}: Marker mismatch",
            i
        );
        assert_eq!(
            decomp.rtp_timestamp, ts_val_for_packet,
            "Loop {}: TS mismatch",
            i
        );
    }
}

/// Tests UO-1-SN encoding for a significant positive SN jump.
/// The "out of order" part is tricky because LSB decoding is relative, so a jump-back
/// might be interpreted as a small forward jump if it falls within the window, or a large
/// forward jump if it's outside, potentially leading to CRC error if implicit TS is wrong.
#[test]
fn p1_uo1_sn_max_sn_jump_encodable() {
    let mut engine = create_test_engine_with_system_clock(500);
    engine
        .register_profile_handler(Box::new(Profile1Handler::new()))
        .unwrap();
    let cid = 0u16;
    let ssrc = 0x778899AA;

    let initial_sn_ir = 1000;
    let initial_ts_ir_val: u32 = 10000;
    let initial_marker = false;
    establish_ir_context(
        &mut engine,
        cid,
        initial_sn_ir,
        initial_ts_ir_val,
        initial_marker,
        ssrc,
    );
    let initial_ip_id = get_ip_id_established_by_ir(initial_sn_ir, ssrc);

    let stride_val = 160u32;
    // After this, comp context: last_sn=1001, last_ts=10160, last_marker=false,
    // last_ip_id=initial_ip_id, stride=Some(160)
    establish_stride_after_ir(
        &mut engine,
        cid,
        ssrc,
        initial_sn_ir,
        initial_ts_ir_val,
        initial_marker,
        initial_ip_id,
        stride_val,
    );

    let comp_ctx_base_pos = get_compressor_context(&engine, cid);
    let base_sn_for_pos_jump = comp_ctx_base_pos.last_sent_rtp_sn_full; // 1001
    let base_ts_val_for_pos_jump = comp_ctx_base_pos.last_sent_rtp_ts_full.value(); // 10160
    let base_marker_for_pos_jump = comp_ctx_base_pos.last_sent_rtp_marker; // false
    let base_ip_id_for_pos_jump = comp_ctx_base_pos.last_sent_ip_id_full; // initial_ip_id

    let sn_delta_large_pos = 100u16;
    let target_sn_pos = base_sn_for_pos_jump.wrapping_add(sn_delta_large_pos); // 1101
    let target_marker_pos = !base_marker_for_pos_jump; // true (marker changes)

    // TS and IP-ID same as context to ensure UO-1-SN is chosen due to SN delta & marker change, not
    // other IR reasons
    let target_ts_val_pos = base_ts_val_for_pos_jump; // 10160
    let target_ip_id_pos = base_ip_id_for_pos_jump;

    let headers_positive_jump = RtpUdpIpv4Headers {
        rtp_ssrc: ssrc.into(),
        rtp_sequence_number: target_sn_pos,
        rtp_timestamp: target_ts_val_pos.into(),
        rtp_marker: target_marker_pos,
        ip_identification: target_ip_id_pos,
        ip_src: comp_ctx_base_pos.ip_source,
        ip_dst: comp_ctx_base_pos.ip_destination,
        udp_src_port: comp_ctx_base_pos.udp_source_port,
        udp_dst_port: comp_ctx_base_pos.udp_destination_port,
        ..Default::default()
    };

    let generic_positive_jump =
        GenericUncompressedHeaders::RtpUdpIpv4(headers_positive_jump.clone());

    let mut compress_buf = [0u8; 1500];
    let compressed_positive_jump_len = engine
        .compress(
            cid.into(),
            Some(RohcProfile::RtpUdpIp),
            &generic_positive_jump,
            &mut compress_buf,
        )
        .expect("engine.compress call failed for positive jump UO-1-SN packet");
    let compressed_positive_jump = &compress_buf[..compressed_positive_jump_len];

    assert_eq!(
        compressed_positive_jump.len(),
        3,
        "Positive jump should be UO-1-SN (len 3). Got len {}. Pkt: {:02X?}. Header SN={}, TS={}, \
         M={}",
        compressed_positive_jump.len(),
        compressed_positive_jump,
        target_sn_pos,
        target_ts_val_pos,
        target_marker_pos
    );

    let decomp_result_positive = engine.decompress(compressed_positive_jump);
    let decomp_headers_positive = decomp_result_positive
        .unwrap()
        .as_rtp_udp_ipv4()
        .unwrap()
        .clone();
    assert_eq!(decomp_headers_positive.rtp_sequence_number, target_sn_pos);
    assert_eq!(decomp_headers_positive.rtp_marker, target_marker_pos);

    // Decompressor calculates implicit TS for UO-1-SN
    // Implicit TS = base_ts_for_pos_jump + sn_delta_large_pos * stride_val
    let expected_decomp_ts_positive =
        base_ts_val_for_pos_jump.wrapping_add(sn_delta_large_pos as u32 * stride_val);
    assert_eq!(
        decomp_headers_positive.rtp_timestamp,
        expected_decomp_ts_positive
    );

    let comp_ctx_before_neg_jump = get_compressor_context(&engine, cid);
    // State after positive jump: last_sn=1101, last_ts=26160 (implicit from UO-1-SN),
    // last_marker=true
    assert_eq!(
        comp_ctx_before_neg_jump.last_sent_rtp_sn_full,
        target_sn_pos
    );
    assert_eq!(
        comp_ctx_before_neg_jump.last_sent_rtp_ts_full,
        expected_decomp_ts_positive
    );
    assert_eq!(
        comp_ctx_before_neg_jump.last_sent_rtp_marker,
        target_marker_pos
    );

    let ip_id_for_neg_jump = comp_ctx_before_neg_jump
        .last_sent_ip_id_full
        .wrapping_add(1); // Change IP-ID
    let last_sn_for_neg_calc = comp_ctx_before_neg_jump.last_sent_rtp_sn_full;
    let last_ts_for_neg_calc = comp_ctx_before_neg_jump.last_sent_rtp_ts_full.value();
    let last_marker_for_neg_calc = comp_ctx_before_neg_jump.last_sent_rtp_marker;

    let sn_jump_neg = initial_sn_ir; // Jump back to 1000
    let marker_jump_neg = !last_marker_for_neg_calc; // Toggle marker again

    // This TS calculation will result in a very large TS value, forcing IR by "Large TS jump"
    let sn_delta_neg_effective_for_ts_calc = sn_jump_neg.wrapping_sub(*last_sn_for_neg_calc);
    let ts_for_neg_jump_header_forcing_ir = last_ts_for_neg_calc
        .wrapping_add(sn_delta_neg_effective_for_ts_calc as u32 * stride_val)
        .wrapping_add(50000); // Add large offset

    let headers_jump_neg = create_rtp_headers(
        sn_jump_neg,
        ts_for_neg_jump_header_forcing_ir,
        marker_jump_neg,
        ssrc,
    )
    .with_ip_id(ip_id_for_neg_jump);
    let generic_jump_neg = GenericUncompressedHeaders::RtpUdpIpv4(headers_jump_neg.clone());

    let mut compress_buf = [0u8; 1500];
    let compressed_jump_neg_len = engine
        .compress(
            cid.into(),
            Some(RohcProfile::RtpUdpIp),
            &generic_jump_neg,
            &mut compress_buf,
        )
        .unwrap();
    let compressed_jump_neg = &compress_buf[..compressed_jump_neg_len];

    assert_eq!(
        compressed_jump_neg.len(),
        36,
        "Negative jump part should result in an IR with TS stride"
    );

    let decompress_result_neg_jump = engine.decompress(compressed_jump_neg);
    match decompress_result_neg_jump {
        Ok(decomp_neg_headers_generic) => {
            let decomp_neg_headers = decomp_neg_headers_generic.as_rtp_udp_ipv4().unwrap();
            assert_eq!(decomp_neg_headers.rtp_sequence_number, sn_jump_neg);
            assert_eq!(decomp_neg_headers.rtp_marker, marker_jump_neg);
            assert_eq!(
                decomp_neg_headers.rtp_timestamp,
                ts_for_neg_jump_header_forcing_ir
            );
        }
        Err(e) => panic!(
            "Decompression of negative jump (which was an IR) failed: {:?}. CompPkt: {:02X?}",
            e, compressed_jump_neg
        ),
    }
}

/// Tests that UO-1-SN is preferred over UO-0 when the SN difference from context is too large
/// for UO-0's limited LSB encoding (typically > 15 for 4-bit LSBs).
#[test]
fn p1_uo1_sn_prefered_over_uo0_for_larger_sn_delta() {
    let mut engine = create_test_engine_with_system_clock(100);
    engine
        .register_profile_handler(Box::new(Profile1Handler::new()))
        .unwrap();
    let cid = 0u16;
    let ssrc = 0xBBCCDDFF;

    let initial_sn_ir = 500;
    let initial_ts_ir_val: u32 = 6000;
    let initial_marker = false;

    establish_ir_context(
        &mut engine,
        cid,
        initial_sn_ir,
        initial_ts_ir_val,
        initial_marker,
        ssrc,
    );
    let ip_id_from_ir = get_ip_id_established_by_ir(initial_sn_ir, ssrc);

    let stride_val = 160u32;
    establish_stride_after_ir(
        &mut engine,
        cid,
        ssrc,
        initial_sn_ir,
        initial_ts_ir_val,
        initial_marker,
        ip_id_from_ir,
        stride_val,
    );

    let comp_ctx_after_stride = get_compressor_context(&engine, cid);
    let sn_after_stride_packet = comp_ctx_after_stride.last_sent_rtp_sn_full;
    let ts_after_stride_packet = comp_ctx_after_stride.last_sent_rtp_ts_full.value();

    // Packet 1: UO-1-SN (SN delta 15, timestamp changes by stride)
    let sn_delta_uo1 = 15u16;
    let sn_uo1_target = sn_after_stride_packet.wrapping_add(sn_delta_uo1);
    let expected_ts_uo1 = ts_after_stride_packet.wrapping_add(sn_delta_uo1 as u32 * stride_val);
    let headers_uo1 = create_rtp_headers(*sn_uo1_target, expected_ts_uo1, initial_marker, ssrc)
        .with_ip_id(ip_id_from_ir.into());

    let mut compress_buf_uo1 = [0u8; 1500];
    let compressed_uo1_len = engine
        .compress(
            cid.into(),
            Some(RohcProfile::RtpUdpIp),
            &GenericUncompressedHeaders::RtpUdpIpv4(headers_uo1.clone()),
            &mut compress_buf_uo1,
        )
        .unwrap();
    let compressed_uo1 = &compress_buf_uo1[..compressed_uo1_len];
    assert_eq!(
        compressed_uo1.len(),
        3,
        "Should be UO-1-SN for SN delta 15 with changing timestamp. CompPkt: {:02X?}",
        compressed_uo1
    );
    let _ = engine.decompress(compressed_uo1).unwrap();

    let decomp_ctx_after_uo1 = get_decompressor_context(&engine, cid);
    assert_eq!(
        decomp_ctx_after_uo1.potential_ts_stride,
        Some(stride_val),
        "Decompressor potential stride should remain {} after UO-1-SN with SN delta {}. Got {:?}. \
         Prev D state: sn={}, ts={}",
        stride_val,
        sn_delta_uo1,
        decomp_ctx_after_uo1.potential_ts_stride,
        sn_after_stride_packet,
        ts_after_stride_packet
    );

    // Packet 2: The UO-1-SN to be tested (SN delta 16 from current context)
    let comp_ctx_before_uo1 = get_compressor_context(&engine, cid);
    let prev_sn_for_uo1 = comp_ctx_before_uo1.last_sent_rtp_sn_full;
    let prev_ts_for_uo1 = comp_ctx_before_uo1.last_sent_rtp_ts_full.value();

    let sn_delta_uo1 = 16u16;
    let sn_force_uo1_target = prev_sn_for_uo1.wrapping_add(sn_delta_uo1);
    let ts_compressor_will_use_for_uo1_crc =
        prev_ts_for_uo1.wrapping_add(sn_delta_uo1 as u32 * stride_val);

    let headers_uo1 = create_rtp_headers(
        *sn_force_uo1_target,
        ts_compressor_will_use_for_uo1_crc,
        initial_marker,
        ssrc,
    )
    .with_ip_id(ip_id_from_ir.wrapping_add(1).into());

    let mut compress_buf_uo1 = [0u8; 1500];
    let compressed_uo1_len = engine
        .compress(
            cid.into(),
            Some(RohcProfile::RtpUdpIp),
            &GenericUncompressedHeaders::RtpUdpIpv4(headers_uo1.clone()),
            &mut compress_buf_uo1,
        )
        .unwrap_or_else(|e| {
            panic!(
                "Compress failed for UO-1-SN (delta > 15): {:?}. Header SN: {}, TS: {}. Prev Comp \
                 SN: {}, TS: {}",
                e,
                sn_force_uo1_target,
                ts_compressor_will_use_for_uo1_crc,
                prev_sn_for_uo1,
                prev_ts_for_uo1
            )
        });
    let compressed_uo1 = &compress_buf_uo1[..compressed_uo1_len];
    assert_eq!(
        compressed_uo1.len(),
        3,
        "Should be UO-1-SN. Pkt: {:02X?}",
        compressed_uo1
    );

    let decomp_uo1_res = engine.decompress(compressed_uo1);
    let decomp_uo1 = decomp_uo1_res.unwrap().as_rtp_udp_ipv4().unwrap().clone();

    assert_eq!(decomp_uo1.rtp_sequence_number, sn_force_uo1_target);
    assert_eq!(decomp_uo1.rtp_timestamp, ts_compressor_will_use_for_uo1_crc);
}
