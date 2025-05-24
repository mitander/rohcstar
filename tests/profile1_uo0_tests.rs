use rohcstar::engine::RohcEngine;
use rohcstar::error::{RohcError, RohcParsingError};
use rohcstar::packet_defs::{GenericUncompressedHeaders, RohcProfile};
use rohcstar::profiles::profile1::constants::P1_ROHC_IR_PACKET_TYPE_WITH_DYN;
use rohcstar::profiles::profile1::context::{
    Profile1CompressorContext, Profile1CompressorMode, Profile1DecompressorContext,
    Profile1DecompressorMode,
};
use rohcstar::profiles::profile1::{
    P1_DECOMPRESSOR_FC_TO_SC_CRC_FAILURE_THRESHOLD, P1_UO_1_SN_PACKET_TYPE_PREFIX, Profile1Handler,
    RtpUdpIpv4Headers,
};

// Helper from previous tests, ensure it's accessible
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

// --- Helper function to establish IR context ---
fn establish_ir_context_for_uo0_tests(
    engine: &mut RohcEngine,
    cid: u16,
    initial_sn: u16,
    initial_ts: u32,
    initial_marker: bool,
    ssrc: u32,
) {
    // Force the compressor context (if it exists) into IR mode to ensure an IR is sent
    if let Ok(comp_ctx_dyn) = engine.context_manager_mut().get_compressor_context_mut(cid) {
        if let Some(p1_comp_ctx) = comp_ctx_dyn
            .as_any_mut()
            .downcast_mut::<Profile1CompressorContext>()
        {
            // Only reset if SSRC is the same, otherwise SSRC change logic in handler will force IR
            if p1_comp_ctx.rtp_ssrc == ssrc {
                p1_comp_ctx.mode = Profile1CompressorMode::InitializationAndRefresh;
            }
        }
    }
    // If context doesn't exist, it will be created in IR mode anyway.

    let headers_ir = create_test_rtp_headers_minimal(initial_sn, initial_ts, initial_marker, ssrc);
    let generic_ir = GenericUncompressedHeaders::RtpUdpIpv4(headers_ir.clone());

    let compressed_ir = engine
        .compress(cid, Some(RohcProfile::RtpUdpIp), &generic_ir)
        .unwrap();

    // Verify it was actually an IR packet if cid = 0 (no add-cid)
    if cid == 0 {
        assert_eq!(
            compressed_ir[0], P1_ROHC_IR_PACKET_TYPE_WITH_DYN,
            "Setup compress call did not produce an IR packet"
        );
    } else if cid <= 15 {
        assert_eq!(
            compressed_ir[1], P1_ROHC_IR_PACKET_TYPE_WITH_DYN,
            "Setup compress call did not produce an IR packet (core)"
        );
    }

    engine.decompress(&compressed_ir).unwrap_or_else(|e| {
        panic!(
            "IR Decompression failed during setup for SN={}, SSRC={}: {:?}",
            initial_sn, ssrc, e
        );
    });
}

// --- Phase 2: UO-0 Packet Implementation Edge Case Tests ---

#[test]
fn p1_uo0_sn_wraparound_65535_to_0() {
    let mut engine = RohcEngine::new(100); // High refresh interval
    engine
        .register_profile_handler(Box::new(Profile1Handler::new()))
        .unwrap();
    let cid = 0u16;
    let ssrc = 0xABC123;

    // Establish context with SN near wraparound
    let initial_sn = 65534;
    let initial_ts = 1000;
    let initial_marker = false;
    establish_ir_context_for_uo0_tests(
        &mut engine,
        cid,
        initial_sn,
        initial_ts,
        initial_marker,
        ssrc,
    );

    // Packet: SN = 65535 (should be UO-0)
    let headers_65535 =
        create_test_rtp_headers_minimal(65535, initial_ts + 10, initial_marker, ssrc);
    let generic_65535 = GenericUncompressedHeaders::RtpUdpIpv4(headers_65535.clone());
    let compressed_65535 = engine
        .compress(cid, Some(RohcProfile::RtpUdpIp), &generic_65535)
        .unwrap();
    assert_eq!(compressed_65535.len(), 1, "SN 65535 should be UO-0");
    let decomp_65535 = engine
        .decompress(&compressed_65535)
        .unwrap()
        .as_rtp_udp_ipv4()
        .unwrap()
        .clone();
    assert_eq!(decomp_65535.rtp_sequence_number, 65535);

    // Packet: SN = 0 (wraparound, should be UO-0)
    let headers_0 = create_test_rtp_headers_minimal(0, initial_ts + 20, initial_marker, ssrc);
    let generic_0 = GenericUncompressedHeaders::RtpUdpIpv4(headers_0.clone());
    let compressed_0 = engine
        .compress(cid, Some(RohcProfile::RtpUdpIp), &generic_0)
        .unwrap();
    assert_eq!(compressed_0.len(), 1, "SN 0 (after 65535) should be UO-0");
    let decomp_0 = engine
        .decompress(&compressed_0)
        .unwrap()
        .as_rtp_udp_ipv4()
        .unwrap()
        .clone();
    assert_eq!(decomp_0.rtp_sequence_number, 0);

    // Packet: SN = 1 (should be UO-0)
    let headers_1 = create_test_rtp_headers_minimal(1, initial_ts + 30, initial_marker, ssrc);
    let generic_1 = GenericUncompressedHeaders::RtpUdpIpv4(headers_1.clone());
    let compressed_1 = engine
        .compress(cid, Some(RohcProfile::RtpUdpIp), &generic_1)
        .unwrap();
    assert_eq!(compressed_1.len(), 1, "SN 1 (after 0) should be UO-0");
    let decomp_1 = engine
        .decompress(&compressed_1)
        .unwrap()
        .as_rtp_udp_ipv4()
        .unwrap()
        .clone();
    assert_eq!(decomp_1.rtp_sequence_number, 1);
}

#[test]
fn p1_uo0_sn_at_lsb_window_edge() {
    let mut engine = RohcEngine::new(100);
    engine
        .register_profile_handler(Box::new(Profile1Handler::new()))
        .unwrap();
    let cid = 0u16;
    let ssrc = 0xDEF456;

    let initial_sn_ir = 100; // SN for the IR packet
    let initial_ts = 2000;
    let initial_marker = false;
    establish_ir_context_for_uo0_tests(
        &mut engine,
        cid,
        initial_sn_ir,
        initial_ts,
        initial_marker,
        ssrc,
    );
    // context.last_sent_rtp_sn_full is now 100

    // Packet 1: SN = 100 + 15 = 115. (Relative to 100, diff = 15. 15 < 16. Should be UO-0)
    let sn_at_edge = initial_sn_ir + 15; // 115
    let headers_at_edge =
        create_test_rtp_headers_minimal(sn_at_edge, initial_ts + 10, initial_marker, ssrc);
    let generic_at_edge = GenericUncompressedHeaders::RtpUdpIpv4(headers_at_edge.clone());
    let compressed_at_edge = engine
        .compress(cid, Some(RohcProfile::RtpUdpIp), &generic_at_edge)
        .unwrap();
    assert_eq!(
        compressed_at_edge.len(),
        1,
        "SN 115 (from 100) should be UO-0"
    );
    let decomp_at_edge = engine
        .decompress(&compressed_at_edge)
        .unwrap()
        .as_rtp_udp_ipv4()
        .unwrap()
        .clone();
    assert_eq!(decomp_at_edge.rtp_sequence_number, sn_at_edge);
    // context.last_sent_rtp_sn_full is now 115

    // Packet 2: SN = 115 + 1 = 116. (Relative to 115, diff = 1. 1 < 16. Should be UO-0)
    let sn_next_to_edge = sn_at_edge + 1; // 116
    let headers_next_to_edge =
        create_test_rtp_headers_minimal(sn_next_to_edge, initial_ts + 20, initial_marker, ssrc);
    let generic_next_to_edge = GenericUncompressedHeaders::RtpUdpIpv4(headers_next_to_edge.clone());
    let compressed_next_to_edge = engine
        .compress(cid, Some(RohcProfile::RtpUdpIp), &generic_next_to_edge)
        .unwrap();
    assert_eq!(
        compressed_next_to_edge.len(),
        1,
        "SN 116 (from 115) should be UO-0"
    );
    let decomp_next_to_edge = engine
        .decompress(&compressed_next_to_edge)
        .unwrap()
        .as_rtp_udp_ipv4()
        .unwrap()
        .clone();
    assert_eq!(decomp_next_to_edge.rtp_sequence_number, sn_next_to_edge);
    // context.last_sent_rtp_sn_full is now 116

    // Packet 3: SN = 115 + 16 = 131. (Relative to 115, last_sent_sn_full, diff = 16. 16 is NOT < 16. Should be UO-1)
    // To test this, we need to set the last_sent_sn_full to 115 again.
    // Re-establish context at 115 to make the next jump clearly outside.
    establish_ir_context_for_uo0_tests(
        &mut engine,
        cid,
        115,
        initial_ts + 20,
        initial_marker,
        ssrc,
    ); // Resets last_sent to 115

    let sn_outside_window = 115 + 16; // 131
    let headers_outside_window =
        create_test_rtp_headers_minimal(sn_outside_window, initial_ts + 30, initial_marker, ssrc);
    let generic_outside_window =
        GenericUncompressedHeaders::RtpUdpIpv4(headers_outside_window.clone());
    let compressed_outside_window = engine
        .compress(cid, Some(RohcProfile::RtpUdpIp), &generic_outside_window)
        .unwrap();
    assert_eq!(
        compressed_outside_window.len(),
        3,
        "SN 131 (from 115) should be UO-1 as diff is 16"
    );
    let decomp_outside_window = engine
        .decompress(&compressed_outside_window)
        .unwrap()
        .as_rtp_udp_ipv4()
        .unwrap()
        .clone();
    assert_eq!(decomp_outside_window.rtp_sequence_number, sn_outside_window);
}

#[test]
fn p1_uo0_crc_failures_trigger_context_downgrade() {
    let mut engine = RohcEngine::new(100);
    engine
        .register_profile_handler(Box::new(Profile1Handler::new()))
        .unwrap();
    let cid = 0u16;
    let ssrc = 0xFAFBFCD;

    establish_ir_context_for_uo0_tests(&mut engine, cid, 200, 3000, false, ssrc);

    for i in 1..=P1_DECOMPRESSOR_FC_TO_SC_CRC_FAILURE_THRESHOLD {
        // Create a UO-0 packet that would be valid if CRC was correct
        let headers_good_uo0 =
            create_test_rtp_headers_minimal(200 + i as u16, 3000 + (i as u32 * 10), false, ssrc);
        let generic_good_uo0 = GenericUncompressedHeaders::RtpUdpIpv4(headers_good_uo0);

        // Compress to get a valid UO-0 structure
        let mut compressed_uo0 = engine
            .compress(cid, Some(RohcProfile::RtpUdpIp), &generic_good_uo0)
            .unwrap();
        assert_eq!(compressed_uo0.len(), 1, "Should be a UO-0 packet");

        // Corrupt the CRC (which is part of the single byte for UO-0)
        compressed_uo0[0] = compressed_uo0[0].wrapping_add(1); // Flip a bit, likely changes CRC part
        if compressed_uo0[0] & 0x80 != 0 {
            // Ensure it's still a UO-0 type (MSB=0)
            compressed_uo0[0] &= 0x7F; // if corruption made MSB=1, reset it
        }

        let result = engine.decompress(&compressed_uo0);
        assert!(
            matches!(
                result,
                Err(RohcError::Parsing(RohcParsingError::CrcMismatch { .. }))
            ),
            "Attempt {} should result in CRC mismatch",
            i
        );

        let decomp_ctx_dyn = engine
            .context_manager()
            .get_decompressor_context(cid)
            .unwrap();
        let decomp_ctx = decomp_ctx_dyn
            .as_any()
            .downcast_ref::<Profile1DecompressorContext>()
            .unwrap();

        if i < P1_DECOMPRESSOR_FC_TO_SC_CRC_FAILURE_THRESHOLD {
            assert_eq!(
                decomp_ctx.mode,
                Profile1DecompressorMode::FullContext,
                "Mode should be FC before threshold"
            );
            assert_eq!(decomp_ctx.consecutive_crc_failures_in_fc, i);
        } else {
            assert_eq!(
                decomp_ctx.mode,
                Profile1DecompressorMode::StaticContext,
                "Mode should downgrade to SC after threshold"
            );
            // consecutive_crc_failures_in_fc might be reset or not strictly i after downgrade,
            // the mode change is the key. The current handler code increments then checks.
        }
    }
}

#[test]
fn p1_uo0_not_used_when_marker_changes() {
    // This test verifies that Profile1Handler::compress chooses UO-1 when marker changes,
    // even if SN is UO-0 encodable.
    let mut engine = RohcEngine::new(100);
    engine
        .register_profile_handler(Box::new(Profile1Handler::new()))
        .unwrap();
    let cid = 0u16;
    let ssrc = 0x1A2B3C;

    // Initial IR: marker=false
    establish_ir_context_for_uo0_tests(&mut engine, cid, 300, 4000, false, ssrc);

    // Next packet: SN is UO-0 encodable (301), but marker changes to true
    let headers_marker_change = create_test_rtp_headers_minimal(301, 4010, true, ssrc);
    let generic_marker_change =
        GenericUncompressedHeaders::RtpUdpIpv4(headers_marker_change.clone());

    let compressed_packet = engine
        .compress(cid, Some(RohcProfile::RtpUdpIp), &generic_marker_change)
        .unwrap();

    // Expecting a UO-1 packet (typically 3 bytes for CID 0) because marker changed
    assert_eq!(
        compressed_packet.len(),
        3,
        "Packet should be UO-1 due to marker change, not UO-0"
    );
    assert_eq!(
        compressed_packet[0] & P1_UO_1_SN_PACKET_TYPE_PREFIX,
        P1_UO_1_SN_PACKET_TYPE_PREFIX,
        "Should be UO-1 type"
    );

    // Decompress to verify
    let decomp_headers = engine
        .decompress(&compressed_packet)
        .unwrap()
        .as_rtp_udp_ipv4()
        .unwrap()
        .clone();
    assert_eq!(decomp_headers.rtp_sequence_number, 301);
    assert!(decomp_headers.rtp_marker); // Marker from packet
}

// Note: `p1_uo0_not_used_when_ts_changes()`
// Your current Profile1Handler::compress for UO-0/UO-1-SN does NOT explicitly check TS stride.
// It uses `context.last_sent_rtp_ts_full` for CRC calculation for these packets.
// A change in TS that breaks an *expected stride* would, in a more advanced implementation,
// force a UO-1-TS or IR.
// For the current MVP, a simple TS change (without marker change or large SN jump)
// will still result in UO-0 or UO-1-SN, and the TS in the decompressed header will be
// the one from the *decompressor's context*, not the current packet's actual TS.
// This is acceptable for UO-0/UO-1-SN which don't transmit TS.
// So, a test "p1_uo0_not_used_when_ts_changes" would currently *pass* by generating UO-0,
// which might be counter-intuitive if you expect strict TS stride checking *for packet type selection*.
//
// If you want to test that a TS change *DOES NOT* prevent UO-0 (given other conditions met):
#[test]
fn p1_uo0_is_used_despite_ts_change_if_marker_sn_ok() {
    let mut engine = RohcEngine::new(100);
    engine
        .register_profile_handler(Box::new(Profile1Handler::new()))
        .unwrap();
    let cid = 0u16;
    let ssrc = 0x4B5C6D;

    let initial_sn = 400;
    let initial_ts = 5000;
    let initial_marker = false;
    establish_ir_context_for_uo0_tests(
        &mut engine,
        cid,
        initial_sn,
        initial_ts,
        initial_marker,
        ssrc,
    );

    // Next packet: SN is UO-0 encodable, marker same, but TS changes significantly
    let next_sn = initial_sn + 1;
    let next_ts = initial_ts + 500; // A non-standard jump
    let headers_ts_change = create_test_rtp_headers_minimal(next_sn, next_ts, initial_marker, ssrc);
    let generic_ts_change = GenericUncompressedHeaders::RtpUdpIpv4(headers_ts_change.clone());

    let compressed_packet = engine
        .compress(cid, Some(RohcProfile::RtpUdpIp), &generic_ts_change)
        .unwrap();

    // Current MVP logic should still produce UO-0 as TS change isn't a primary factor for UO-0 vs UO-1-SN choice
    assert_eq!(
        compressed_packet.len(),
        1,
        "Packet should be UO-0 even with TS change, given other criteria match"
    );
    assert_eq!(
        compressed_packet[0] & 0x80,
        0x00,
        "Should be UO-0 type (MSB=0)"
    );

    // Decompress to verify
    let decomp_headers = engine
        .decompress(&compressed_packet)
        .unwrap()
        .as_rtp_udp_ipv4()
        .unwrap()
        .clone();
    assert_eq!(decomp_headers.rtp_sequence_number, next_sn);
    assert_eq!(decomp_headers.rtp_marker, initial_marker); // Marker from context
    assert_eq!(decomp_headers.rtp_timestamp, initial_ts); // TS from context, not the `next_ts`
}
