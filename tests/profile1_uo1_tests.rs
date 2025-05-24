use rohcstar::engine::RohcEngine;
use rohcstar::error::{RohcError, RohcParsingError};
use rohcstar::packet_defs::{GenericUncompressedHeaders, RohcProfile};
use rohcstar::profiles::profile1::context::Profile1DecompressorContext;
use rohcstar::profiles::profile1::{
    P1_UO_1_SN_MARKER_BIT_MASK, P1_UO_1_SN_PACKET_TYPE_PREFIX, Profile1Handler, RtpUdpIpv4Headers,
};

fn create_test_rtp_headers_minimal(sn: u16, ts: u32, marker: bool, ssrc: u32) -> RtpUdpIpv4Headers {
    RtpUdpIpv4Headers {
        ip_src: "192.168.0.1".parse().unwrap(),
        ip_dst: "192.168.0.2".parse().unwrap(),
        udp_src_port: 1000,
        udp_dst_port: 2000,
        rtp_ssrc: ssrc,
        rtp_sequence_number: sn,
        rtp_timestamp: ts,
        rtp_marker: marker,
        ..Default::default()
    }
}

fn establish_ir_context_for_uo1_tests(
    engine: &mut RohcEngine,
    cid: u16,
    initial_sn: u16,
    initial_ts: u32,
    initial_marker: bool,
    ssrc: u32,
) {
    let headers_ir = create_test_rtp_headers_minimal(initial_sn, initial_ts, initial_marker, ssrc);
    let generic_ir = GenericUncompressedHeaders::RtpUdpIpv4(headers_ir);
    let compressed_ir = engine
        .compress(cid, Some(RohcProfile::RtpUdpIp), &generic_ir)
        .unwrap();
    engine.decompress(&compressed_ir).unwrap_or_else(|e| {
        panic!(
            "IR Decompression failed during setup for SN={}, SSRC={}: {:?}",
            initial_sn, ssrc, e
        );
    });
}

// --- Phase 3: UO-1-SN Packet Implementation Edge Case Tests ---

#[test]
fn p1_uo1_sn_with_sn_wraparound() {
    let mut engine = RohcEngine::new(200); // High refresh interval
    engine
        .register_profile_handler(Box::new(Profile1Handler::new()))
        .unwrap();
    let cid = 0u16;
    let ssrc = 0xABCDEF01;

    // Establish context with SN near wraparound, marker=false
    let ir_sn = 65530;
    let ir_ts = 1000;
    let ir_marker = false;
    establish_ir_context_for_uo1_tests(&mut engine, cid, ir_sn, ir_ts, ir_marker, ssrc);
    // Compressor context: last_sn=65530, last_marker=false

    // Packet 1: SN = 65532, Marker=true (forces UO-1)
    // (65532 - 65530) = 2. Encodable by UO-0 if marker was same. But marker changes.
    let sn1 = 65532;
    let marker1 = true;
    let headers1 = create_test_rtp_headers_minimal(sn1, ir_ts + 10, marker1, ssrc);
    let generic1 = GenericUncompressedHeaders::RtpUdpIpv4(headers1.clone());
    let compressed1 = engine
        .compress(cid, Some(RohcProfile::RtpUdpIp), &generic1)
        .unwrap();
    assert_eq!(compressed1.len(), 3, "SN 65532, M=true should be UO-1");
    assert_eq!(
        compressed1[0] & P1_UO_1_SN_PACKET_TYPE_PREFIX,
        P1_UO_1_SN_PACKET_TYPE_PREFIX
    );
    assert_ne!(compressed1[0] & P1_UO_1_SN_MARKER_BIT_MASK, 0); // Marker bit is set

    let decomp1 = engine
        .decompress(&compressed1)
        .unwrap()
        .as_rtp_udp_ipv4()
        .unwrap()
        .clone();
    assert_eq!(decomp1.rtp_sequence_number, sn1);
    assert_eq!(decomp1.rtp_marker, marker1);
    // Compressor context: last_sn=65532, last_marker=true

    // Packet 2: SN = 2 (wraparound), Marker=false (forces UO-1)
    // (2 (or 65538) - 65532) = 6. Encodable by UO-0 if marker was same. But marker changes.
    let sn2 = 2;
    let marker2 = false;
    let headers2 = create_test_rtp_headers_minimal(sn2, ir_ts + 20, marker2, ssrc);
    let generic2 = GenericUncompressedHeaders::RtpUdpIpv4(headers2.clone());
    let compressed2 = engine
        .compress(cid, Some(RohcProfile::RtpUdpIp), &generic2)
        .unwrap();
    assert_eq!(compressed2.len(), 3, "SN 2 (wrap), M=false should be UO-1");
    assert_eq!(
        compressed2[0] & P1_UO_1_SN_PACKET_TYPE_PREFIX,
        P1_UO_1_SN_PACKET_TYPE_PREFIX
    );
    assert_eq!(compressed2[0] & P1_UO_1_SN_MARKER_BIT_MASK, 0); // Marker bit is clear

    let decomp2 = engine
        .decompress(&compressed2)
        .unwrap()
        .as_rtp_udp_ipv4()
        .unwrap()
        .clone();
    assert_eq!(decomp2.rtp_sequence_number, sn2);
    assert_eq!(decomp2.rtp_marker, marker2);
}

#[test]
fn p1_rapid_marker_toggling_forces_uo1() {
    let mut engine = RohcEngine::new(200);
    engine
        .register_profile_handler(Box::new(Profile1Handler::new()))
        .unwrap();
    let cid = 0u16;
    let ssrc = 0x1234FEDC;

    let initial_sn = 100;
    let initial_ts = 5000;
    let mut current_marker = false;

    establish_ir_context_for_uo1_tests(
        &mut engine,
        cid,
        initial_sn,
        initial_ts,
        current_marker,
        ssrc,
    );

    for i in 1..=5 {
        let current_sn = initial_sn + i;
        current_marker = !current_marker; // Toggle marker

        let headers = create_test_rtp_headers_minimal(
            current_sn,
            initial_ts + (i as u32 * 10),
            current_marker,
            ssrc,
        );
        let generic = GenericUncompressedHeaders::RtpUdpIpv4(headers.clone());
        let compressed = engine
            .compress(cid, Some(RohcProfile::RtpUdpIp), &generic)
            .unwrap();

        assert_eq!(
            compressed.len(),
            3,
            "Packet {} with toggled marker should be UO-1",
            i
        );
        assert_eq!(
            compressed[0] & P1_UO_1_SN_PACKET_TYPE_PREFIX,
            P1_UO_1_SN_PACKET_TYPE_PREFIX
        );
        if current_marker {
            assert_ne!(compressed[0] & P1_UO_1_SN_MARKER_BIT_MASK, 0);
        } else {
            assert_eq!(compressed[0] & P1_UO_1_SN_MARKER_BIT_MASK, 0);
        }

        let decomp = engine
            .decompress(&compressed)
            .unwrap()
            .as_rtp_udp_ipv4()
            .unwrap()
            .clone();
        assert_eq!(decomp.rtp_sequence_number, current_sn);
        assert_eq!(decomp.rtp_marker, current_marker);

        // Verify decompressor context marker state
        let decomp_ctx_dyn = engine
            .context_manager()
            .get_decompressor_context(cid)
            .unwrap();
        let decomp_ctx = decomp_ctx_dyn
            .as_any()
            .downcast_ref::<Profile1DecompressorContext>()
            .unwrap();
        assert_eq!(decomp_ctx.last_reconstructed_rtp_marker, current_marker);
    }
}

#[test]
fn p1_uo1_sn_max_sn_jump_encodable() {
    let mut engine = RohcEngine::new(500);
    engine
        .register_profile_handler(Box::new(Profile1Handler::new()))
        .unwrap();
    let cid = 0u16;
    let ssrc = 0x778899AA;

    let initial_sn = 1000;
    let initial_ts = 10000;
    let initial_marker = false;
    establish_ir_context_for_uo1_tests(
        &mut engine,
        cid,
        initial_sn,
        initial_ts,
        initial_marker,
        ssrc,
    );
    // Compressor context: last_sn = 1000
    // Decompressor context: last_reconstructed_sn = 1000

    // Case 1: Large positive jump, but within UO-1's LSB decoding capability (relative to last SN)
    let sn_jump_pos = initial_sn + 100; // 1100. LSB = 0x6C. Decodes to 1100 from ref 1000.
    let headers_jump_pos =
        create_test_rtp_headers_minimal(sn_jump_pos, initial_ts + 100, initial_marker, ssrc);
    let generic_jump_pos = GenericUncompressedHeaders::RtpUdpIpv4(headers_jump_pos.clone());
    let compressed_jump_pos = engine
        .compress(cid, Some(RohcProfile::RtpUdpIp), &generic_jump_pos)
        .unwrap();
    assert_eq!(compressed_jump_pos.len(), 3, "SN jump +100 should be UO-1");
    let decomp_jump_pos_result = engine.decompress(&compressed_jump_pos);
    assert!(
        decomp_jump_pos_result.is_ok(),
        "Decompression of positive jump failed: {:?}",
        decomp_jump_pos_result.err()
    );
    let decomp_jump_pos = decomp_jump_pos_result
        .unwrap()
        .as_rtp_udp_ipv4()
        .unwrap()
        .clone();
    assert_eq!(decomp_jump_pos.rtp_sequence_number, sn_jump_pos);
    // Compressor context: last_sn = 1100
    // Decompressor context: last_reconstructed_sn = 1100

    // Case 2: "Negative" jump via wraparound. SN goes from 1100 (last sent) back to 1000.
    // Compressor sends LSBs of 1000 (0xE8) with CRC calculated for SN=1000.
    // Decompressor has v_ref=1100. decode_lsb(0xE8, v_ref=1100, k=8, p=0) yields 1256.
    // CRC calculated with SN=1256 will not match CRC from packet (for SN=1000).
    // This SHOULD result in a CrcMismatch.
    let sn_jump_neg = initial_sn; // 1000
    let headers_jump_neg =
        create_test_rtp_headers_minimal(sn_jump_neg, initial_ts + 200, initial_marker, ssrc);
    let generic_jump_neg = GenericUncompressedHeaders::RtpUdpIpv4(headers_jump_neg.clone());
    let compressed_jump_neg = engine
        .compress(cid, Some(RohcProfile::RtpUdpIp), &generic_jump_neg)
        .unwrap();
    assert_eq!(
        compressed_jump_neg.len(),
        3,
        "SN jump -100 (wrap) should still be UO-1 based on SN diff > 16 from 1100"
    );

    let decompress_result_neg_jump = engine.decompress(&compressed_jump_neg);
    match decompress_result_neg_jump {
        Err(RohcError::Parsing(RohcParsingError::CrcMismatch { .. })) => {
            // This is the expected behavior because W-LSB p=0 decoding failed to get back to 1000
        }
        Ok(h) => panic!(
            "Expected CrcMismatch for large negative SN jump with p=0, but got Ok({:?})",
            h
        ),
        Err(e) => panic!("Expected CrcMismatch, but got other error: {:?}", e),
    }
}

#[test]
fn p1_uo1_sn_prefered_over_uo0_for_larger_sn_diff() {
    let mut engine = RohcEngine::new(100);
    engine
        .register_profile_handler(Box::new(Profile1Handler::new()))
        .unwrap();
    let cid = 0u16;
    let ssrc = 0xBBCCDDFF;

    let initial_sn = 500;
    let initial_ts = 6000;
    let initial_marker = false;
    establish_ir_context_for_uo1_tests(
        &mut engine,
        cid,
        initial_sn,
        initial_ts,
        initial_marker,
        ssrc,
    );
    // last_sn = 500

    // SN diff = 15, should be UO-0
    let sn_uo0_max = initial_sn + 15; // 515
    let headers_uo0 =
        create_test_rtp_headers_minimal(sn_uo0_max, initial_ts + 10, initial_marker, ssrc);
    let compressed_uo0 = engine
        .compress(
            cid,
            Some(RohcProfile::RtpUdpIp),
            &GenericUncompressedHeaders::RtpUdpIpv4(headers_uo0),
        )
        .unwrap();
    assert_eq!(compressed_uo0.len(), 1, "SN diff 15 should be UO-0");
    let _ = engine.decompress(&compressed_uo0).unwrap();
    // last_sn = 515

    // The previous packet (SN 515) made last_sent_rtp_sn_full = 515.
    // For current_sn = 516, diff = 516.wrapping_sub(515) = 1. This is < 16. This will be UO-0.
    // We need a jump of 16 from the *last sent SN* to force UO-1.
    // If last_sent_sn is 515, then current_sn = 515+16 = 531 will force UO-1.

    let sn_force_uo1 = 515 + 16; // 531
    let headers_uo1 =
        create_test_rtp_headers_minimal(sn_force_uo1, initial_ts + 20, initial_marker, ssrc);
    let compressed_uo1 = engine
        .compress(
            cid,
            Some(RohcProfile::RtpUdpIp),
            &GenericUncompressedHeaders::RtpUdpIpv4(headers_uo1),
        )
        .unwrap();
    assert_eq!(
        compressed_uo1.len(),
        3,
        "SN diff 16 (from 515) should be UO-1"
    );
    assert_eq!(
        compressed_uo1[0] & P1_UO_1_SN_PACKET_TYPE_PREFIX,
        P1_UO_1_SN_PACKET_TYPE_PREFIX
    );

    let decomp_uo1 = engine
        .decompress(&compressed_uo1)
        .unwrap()
        .as_rtp_udp_ipv4()
        .unwrap()
        .clone();
    assert_eq!(decomp_uo1.rtp_sequence_number, sn_force_uo1);
}
