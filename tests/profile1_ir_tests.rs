use rohcstar::ProfileHandler;
use rohcstar::engine::RohcEngine;
use rohcstar::error::{RohcBuildingError, RohcError, RohcParsingError};
use rohcstar::packet_defs::{GenericUncompressedHeaders, RohcProfile};
use rohcstar::profiles::profile1::context::{
    Profile1CompressorContext, Profile1CompressorMode, Profile1DecompressorContext,
    Profile1DecompressorMode,
};
use rohcstar::profiles::profile1::packet_processor::build_profile1_ir_packet;
use rohcstar::profiles::profile1::{
    IrPacket, P1_ROHC_IR_PACKET_TYPE_STATIC_ONLY, P1_ROHC_IR_PACKET_TYPE_WITH_DYN,
    P1_STATIC_CHAIN_LENGTH_BYTES, Profile1Handler, RtpUdpIpv4Headers,
};

// A minimal helper to create RtpUdpIpv4Headers for tests
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

// Helper to create a default IrPacket struct for modification
fn default_ir_packet_data(cid: u16, ssrc: u32, sn: u16) -> IrPacket {
    IrPacket {
        cid,
        profile: RohcProfile::RtpUdpIp,
        static_ip_src: "1.1.1.1".parse().unwrap(),
        static_ip_dst: "2.2.2.2".parse().unwrap(),
        static_udp_src_port: 100,
        static_udp_dst_port: 200,
        static_rtp_ssrc: ssrc,
        dyn_rtp_sn: sn,
        dyn_rtp_timestamp: sn as u32 * 10, // Simple TS progression
        dyn_rtp_marker: false,
        crc8: 0, // Will be calculated by builder
    }
}

// --- 1. IR Packet Error Handling Tests ---

#[test]
fn p1_ir_packet_with_corrupted_crc_fails() {
    let handler = Profile1Handler::new();
    let mut decomp_ctx_dyn = handler.create_decompressor_context(0);

    let ir_data = default_ir_packet_data(0, 0x12345678, 100);
    let mut ir_packet_bytes = build_profile1_ir_packet(&ir_data).unwrap();

    // Corrupt the CRC (last byte)
    let crc_index = ir_packet_bytes.len() - 1;
    ir_packet_bytes[crc_index] = ir_packet_bytes[crc_index].wrapping_add(1);

    let result = handler.decompress(decomp_ctx_dyn.as_mut(), &ir_packet_bytes);

    match result {
        Err(RohcError::Parsing(RohcParsingError::CrcMismatch { .. })) => { /* Expected */ }
        _ => panic!("Expected CRC mismatch error, got: {:?}", result),
    }
}

#[test]
fn p1_ir_packet_with_wrong_profile_id_fails() {
    let handler = Profile1Handler::new(); // Profile1Handler
    let mut decomp_ctx_dyn = handler.create_decompressor_context(0);

    // Build a packet as if for Profile 1, but then change the profile ID byte
    let mut ir_data = default_ir_packet_data(0, 0x12345678, 100);
    ir_data.profile = RohcProfile::RtpUdpIp; // Ensure it's built for P1 initially

    let mut ir_packet_bytes = build_profile1_ir_packet(&ir_data).unwrap();

    // Assuming CID 0 (no Add-CID), profile ID is the second byte (after Type octet)
    // Type (0xFD for IR-DYN) | Profile | Static Chain ... | CRC
    // ir_packet_bytes[0] is Type
    // ir_packet_bytes[1] is Profile ID
    if ir_packet_bytes.len() > 1 {
        ir_packet_bytes[1] = RohcProfile::UdpIp.into(); // Change to a different profile ID (e.g., 0x02)

        // Recalculate CRC because profile ID is part of CRC payload
        // CRC payload starts at profile ID, ends before CRC byte
        let crc_payload_slice = &ir_packet_bytes[1..ir_packet_bytes.len() - 1];
        let new_crc = rohcstar::crc::calculate_rohc_crc8(crc_payload_slice);
        *ir_packet_bytes.last_mut().unwrap() = new_crc;
    } else {
        panic!("Generated IR packet is too short to modify profile ID.");
    }

    let result = handler.decompress(decomp_ctx_dyn.as_mut(), &ir_packet_bytes);

    // The Profile1Handler should reject a packet that, despite being an IR structure,
    // explicitly states a different profile *within its payload*.
    // The `parse_profile1_ir_packet` specifically checks this.
    match result {
        Err(RohcError::Parsing(RohcParsingError::InvalidProfileId(id))) => {
            assert_eq!(id, RohcProfile::UdpIp.into());
        }
        _ => panic!("Expected InvalidProfileId error, got: {:?}", result),
    }
}

#[test]
fn p1_ir_packet_too_short_fails() {
    let handler = Profile1Handler::new();
    let mut decomp_ctx_dyn = handler.create_decompressor_context(0);

    let ir_data = default_ir_packet_data(0, 0x12345678, 100);
    let ir_packet_bytes_full = build_profile1_ir_packet(&ir_data).unwrap();

    // Test various truncations
    // Length of IR-DYN for CID 0: Type(1) + Profile(1) + Static(16) + Dynamic(7) + CRC(1) = 26
    for len in 0..ir_packet_bytes_full.len() - 1 {
        // Exclude full length
        let truncated_packet = &ir_packet_bytes_full[0..len];
        let result = handler.decompress(decomp_ctx_dyn.as_mut(), truncated_packet);
        match result {
            Err(RohcError::Parsing(RohcParsingError::NotEnoughData { .. })) => { /* Expected */ }
            _ => panic!(
                "Expected NotEnoughData for truncated packet of len {}, got: {:?}",
                len, result
            ),
        }
    }
    // Test empty packet
    let result_empty = handler.decompress(decomp_ctx_dyn.as_mut(), &[]);
    match result_empty {
        Err(RohcError::Parsing(RohcParsingError::NotEnoughData { .. })) => { /* Expected */ }
        _ => panic!(
            "Expected NotEnoughData for empty packet, got: {:?}",
            result_empty
        ),
    }
}

// --- 2. Context State Verification Tests ---

#[test]
fn p1_compressor_context_static_fields_remain_constant() {
    let handler = Profile1Handler::new();
    let mut comp_ctx_dyn = handler.create_compressor_context(0, 5); // CID 0, refresh interval 5

    let ssrc1 = 0x11111111;
    let headers1 = create_test_rtp_headers_minimal(100, 1000, false, ssrc1);
    let generic_headers1 = GenericUncompressedHeaders::RtpUdpIpv4(headers1.clone());

    // First packet (IR) initializes static fields
    let _ = handler
        .compress(comp_ctx_dyn.as_mut(), &generic_headers1)
        .unwrap();

    let comp_ctx_snapshot1 = comp_ctx_dyn
        .as_any()
        .downcast_ref::<Profile1CompressorContext>()
        .unwrap()
        .clone();
    assert_eq!(comp_ctx_snapshot1.rtp_ssrc, ssrc1);
    assert_eq!(comp_ctx_snapshot1.ip_source, headers1.ip_src);

    // Subsequent packets (UO, assuming SSRC and static IP/UDP ports don't change)
    for i in 1..=3 {
        let headers_next =
            create_test_rtp_headers_minimal(100 + i, 1000 + (i as u32 * 100), false, ssrc1);
        let generic_headers_next = GenericUncompressedHeaders::RtpUdpIpv4(headers_next);
        let _ = handler
            .compress(comp_ctx_dyn.as_mut(), &generic_headers_next)
            .unwrap();

        let comp_ctx_current = comp_ctx_dyn
            .as_any()
            .downcast_ref::<Profile1CompressorContext>()
            .unwrap();
        assert_eq!(
            comp_ctx_current.rtp_ssrc, ssrc1,
            "SSRC should remain constant"
        );
        assert_eq!(
            comp_ctx_current.ip_source, headers1.ip_src,
            "IP source should remain constant"
        );
        assert_eq!(
            comp_ctx_current.udp_source_port, headers1.udp_src_port,
            "UDP source port should remain constant"
        );
        // Dynamic fields should update
        assert_eq!(comp_ctx_current.last_sent_rtp_sn_full, 100 + i);
    }
}

#[test]
fn p1_decompressor_stays_in_no_context_without_ir() {
    let handler = Profile1Handler::new();
    let mut decomp_ctx_dyn = handler.create_decompressor_context(0); // CID 0

    // Attempt to decompress a UO-0 packet (which requires context)
    // For CID 0, UO-0 is 1 byte: 0 SSSS CCC. Example: SN=1, CRC=1 => 0001001 = 0x09
    let uo0_packet_bytes = vec![0x09];
    let result = handler.decompress(decomp_ctx_dyn.as_mut(), &uo0_packet_bytes);

    match result {
        Err(RohcError::InvalidState(msg)) => {
            assert!(msg.contains("decompressor not in Full Context mode"));
        }
        _ => panic!(
            "Expected InvalidState error for UO packet in NoContext, got: {:?}",
            result
        ),
    }

    let decomp_ctx = decomp_ctx_dyn
        .as_any()
        .downcast_ref::<Profile1DecompressorContext>()
        .unwrap();
    assert_eq!(
        decomp_ctx.mode,
        Profile1DecompressorMode::NoContext,
        "Decompressor mode should remain NoContext"
    );
}

// --- 3. CID Handling Edge Cases ---

#[test]
fn p1_ir_packet_large_cid_not_supported_by_builder() {
    // This tests the current limitation of `build_profile1_ir_packet`
    let large_cid = 16u16;
    let ir_data = default_ir_packet_data(large_cid, 0x12345678, 100);

    let result = build_profile1_ir_packet(&ir_data);
    match result {
        Err(RohcBuildingError::InvalidFieldValueForBuild {
            field_name,
            description,
        }) => {
            assert_eq!(field_name, "CID");
            assert!(description.contains("Large CID 16 for IR packet Add-CID not supported"));
        }
        _ => panic!(
            "Expected InvalidFieldValueForBuild for large CID, got {:?}",
            result
        ),
    }
}

#[test]
fn p1_multiple_flows_different_cids() {
    let mut engine = RohcEngine::new(5);
    engine
        .register_profile_handler(Box::new(Profile1Handler::new()))
        .unwrap();

    let cid1: u16 = 1;
    let ssrc1: u32 = 0xAAAA1111;
    let headers1_flow1 = create_test_rtp_headers_minimal(10, 100, false, ssrc1);
    let generic1_flow1 = GenericUncompressedHeaders::RtpUdpIpv4(headers1_flow1.clone());

    let cid2: u16 = 2;
    let ssrc2: u32 = 0xBBBB2222;
    let headers1_flow2 = create_test_rtp_headers_minimal(50, 500, true, ssrc2);
    let generic1_flow2 = GenericUncompressedHeaders::RtpUdpIpv4(headers1_flow2.clone());

    // Compress and decompress first packet for flow 1 (CID 1)
    let compressed1_flow1 = engine
        .compress(cid1, Some(RohcProfile::RtpUdpIp), &generic1_flow1)
        .unwrap();
    assert_eq!(compressed1_flow1[0], 0xE0 | cid1 as u8); // Check Add-CID
    let decompressed1_flow1 = engine
        .decompress(&compressed1_flow1)
        .unwrap()
        .as_rtp_udp_ipv4()
        .unwrap()
        .clone();
    assert_eq!(decompressed1_flow1.rtp_ssrc, ssrc1);
    assert_eq!(decompressed1_flow1.rtp_sequence_number, 10);

    // Compress and decompress first packet for flow 2 (CID 2)
    let compressed1_flow2 = engine
        .compress(cid2, Some(RohcProfile::RtpUdpIp), &generic1_flow2)
        .unwrap();
    assert_eq!(compressed1_flow2[0], 0xE0 | cid2 as u8); // Check Add-CID
    let decompressed1_flow2 = engine
        .decompress(&compressed1_flow2)
        .unwrap()
        .as_rtp_udp_ipv4()
        .unwrap()
        .clone();
    assert_eq!(decompressed1_flow2.rtp_ssrc, ssrc2);
    assert_eq!(decompressed1_flow2.rtp_sequence_number, 50);

    // Verify context manager has two distinct contexts
    assert_eq!(engine.context_manager().compressor_context_count(), 2);
    assert_eq!(engine.context_manager().decompressor_context_count(), 2);

    // Send another packet for flow 1 (should use CID 1 context)
    let headers2_flow1 = create_test_rtp_headers_minimal(11, 110, false, ssrc1); // UO-0
    let generic2_flow1 = GenericUncompressedHeaders::RtpUdpIpv4(headers2_flow1.clone());
    let compressed2_flow1 = engine
        .compress(cid1, Some(RohcProfile::RtpUdpIp), &generic2_flow1)
        .unwrap();
    // UO-0 with Add-CID: Add-CID byte + UO-0 byte = 2 bytes
    assert_eq!(compressed2_flow1.len(), 2);
    assert_eq!(compressed2_flow1[0], 0xE0 | cid1 as u8);

    let decompressed2_flow1 = engine
        .decompress(&compressed2_flow1)
        .unwrap()
        .as_rtp_udp_ipv4()
        .unwrap()
        .clone();
    assert_eq!(decompressed2_flow1.rtp_ssrc, ssrc1);
    assert_eq!(decompressed2_flow1.rtp_sequence_number, 11);
    assert_eq!(decompressed2_flow1.rtp_marker, headers1_flow1.rtp_marker); // From context
}

// --- 4. SSRC Change Detection ---

#[test]
fn p1_ssrc_change_forces_context_reinitialization_and_ir() {
    let handler = Profile1Handler::new();
    let mut comp_ctx_dyn = handler.create_compressor_context(0, 5);

    let ssrc1 = 0xAAAA0001;
    let headers1 = create_test_rtp_headers_minimal(200, 2000, false, ssrc1);
    let generic1 = GenericUncompressedHeaders::RtpUdpIpv4(headers1.clone());

    // First packet: IR
    let compressed1 = handler.compress(comp_ctx_dyn.as_mut(), &generic1).unwrap();
    assert_eq!(compressed1[0], P1_ROHC_IR_PACKET_TYPE_WITH_DYN); // IR
    let comp_ctx1 = comp_ctx_dyn
        .as_any()
        .downcast_ref::<Profile1CompressorContext>()
        .unwrap();
    assert_eq!(comp_ctx1.rtp_ssrc, ssrc1);
    assert_eq!(comp_ctx1.mode, Profile1CompressorMode::FirstOrder);

    // Second packet: UO-0
    let headers2 = create_test_rtp_headers_minimal(201, 2100, false, ssrc1);
    let generic2 = GenericUncompressedHeaders::RtpUdpIpv4(headers2);
    let compressed2 = handler.compress(comp_ctx_dyn.as_mut(), &generic2).unwrap();
    assert_ne!(compressed2[0], P1_ROHC_IR_PACKET_TYPE_WITH_DYN); // Should be UO-0

    // Third packet: SSRC changes
    let ssrc2 = 0xBBBB0002;
    let headers3 = create_test_rtp_headers_minimal(10, 100, true, ssrc2); // New flow params
    let generic3 = GenericUncompressedHeaders::RtpUdpIpv4(headers3.clone());
    let compressed3 = handler.compress(comp_ctx_dyn.as_mut(), &generic3).unwrap();

    // Should force a new IR because SSRC changed
    assert_eq!(
        compressed3[0], P1_ROHC_IR_PACKET_TYPE_WITH_DYN,
        "SSRC change should force IR"
    );
    let comp_ctx3 = comp_ctx_dyn
        .as_any()
        .downcast_ref::<Profile1CompressorContext>()
        .unwrap();
    assert_eq!(comp_ctx3.rtp_ssrc, ssrc2, "Context SSRC should be updated");
    assert_eq!(
        comp_ctx3.last_sent_rtp_sn_full, 10,
        "Context SN should be from new flow"
    );
    assert_eq!(
        comp_ctx3.mode,
        Profile1CompressorMode::FirstOrder,
        "Mode should be FO after new IR"
    );
    assert_eq!(
        comp_ctx3.fo_packets_sent_since_ir, 0,
        "FO count reset after new IR"
    );
}

// --- 5. IR Refresh Boundary Tests ---

#[test]
fn p1_ir_refresh_interval_edge_cases() {
    let handler = Profile1Handler::new();
    let ssrc = 0xCCCC0001; // Define ssrc outside for reuse

    // Case 1: ir_refresh_interval = 0 (disabled)
    // ... (this part was likely correct) ...
    let mut comp_ctx_dyn_0 = handler.create_compressor_context(0, 0);
    let headers_ir0 = create_test_rtp_headers_minimal(1, 10, false, ssrc);
    let _ = handler
        .compress(
            comp_ctx_dyn_0.as_mut(),
            &GenericUncompressedHeaders::RtpUdpIpv4(headers_ir0),
        )
        .unwrap(); // IR
    for i in 2..=10 {
        // Send many UO packets
        let headers_uo = create_test_rtp_headers_minimal(i, 10 + (i as u32 * 10), false, ssrc);
        let compressed = handler
            .compress(
                comp_ctx_dyn_0.as_mut(),
                &GenericUncompressedHeaders::RtpUdpIpv4(headers_uo),
            )
            .unwrap();
        assert_ne!(
            compressed[0], P1_ROHC_IR_PACKET_TYPE_WITH_DYN,
            "IR refresh should be disabled (interval 0)"
        );
    }
    let comp_ctx_0 = comp_ctx_dyn_0
        .as_any()
        .downcast_ref::<Profile1CompressorContext>()
        .unwrap();
    assert_eq!(comp_ctx_0.fo_packets_sent_since_ir, 9);

    // Case 2: ir_refresh_interval = 1 (every packet after first is IR)
    // ... (this part was likely correct) ...
    let mut comp_ctx_dyn_1 = handler.create_compressor_context(0, 1);
    let headers_ir1_1 = create_test_rtp_headers_minimal(101, 1010, false, ssrc);
    let compressed_ir1_1 = handler
        .compress(
            comp_ctx_dyn_1.as_mut(),
            &GenericUncompressedHeaders::RtpUdpIpv4(headers_ir1_1),
        )
        .unwrap();
    assert_eq!(
        compressed_ir1_1[0], P1_ROHC_IR_PACKET_TYPE_WITH_DYN,
        "P1 (interval 1) should be IR"
    );

    let headers_ir1_2 = create_test_rtp_headers_minimal(102, 1020, false, ssrc);
    let compressed_ir1_2 = handler
        .compress(
            comp_ctx_dyn_1.as_mut(),
            &GenericUncompressedHeaders::RtpUdpIpv4(headers_ir1_2),
        )
        .unwrap();
    assert_eq!(
        compressed_ir1_2[0], P1_ROHC_IR_PACKET_TYPE_WITH_DYN,
        "P2 (interval 1) should be IR"
    );
    let comp_ctx_1 = comp_ctx_dyn_1
        .as_any()
        .downcast_ref::<Profile1CompressorContext>()
        .unwrap();
    assert_eq!(comp_ctx_1.fo_packets_sent_since_ir, 0);

    // Case 3: ir_refresh_interval = large (e.g., 100)
    let large_interval = 100u32;
    let mut comp_ctx_dyn_large = handler.create_compressor_context(0, large_interval);
    let headers_ir_large = create_test_rtp_headers_minimal(201, 2010, false, ssrc);
    let _ = handler
        .compress(
            comp_ctx_dyn_large.as_mut(),
            &GenericUncompressedHeaders::RtpUdpIpv4(headers_ir_large),
        )
        .unwrap(); // IR (Packet 1)
    // fo_packets_sent_since_ir = 0

    // Send large_interval - 1 FO packets (i.e., packets 2 through 100)
    // This will be 99 FO packets.
    for i in 1..=(large_interval - 1) {
        let current_sn = 201 + i as u16; // SNs 202 to 300
        let headers_uo = create_test_rtp_headers_minimal(current_sn, 2010 + (i * 10), false, ssrc);
        let compressed = handler
            .compress(
                comp_ctx_dyn_large.as_mut(),
                &GenericUncompressedHeaders::RtpUdpIpv4(headers_uo),
            )
            .unwrap();
        assert_ne!(
            compressed[0],
            P1_ROHC_IR_PACKET_TYPE_WITH_DYN,
            "Packet #{} (SN {}) with large interval should be FO",
            i + 1,
            current_sn
        );
    }
    // After this loop, fo_packets_sent_since_ir should be large_interval - 1 (which is 99)
    let comp_ctx_large_before_refresh = comp_ctx_dyn_large
        .as_any()
        .downcast_ref::<Profile1CompressorContext>()
        .unwrap();
    assert_eq!(
        comp_ctx_large_before_refresh.fo_packets_sent_since_ir,
        large_interval - 1
    );

    // The NEXT packet (Packet 101 overall) should trigger IR.
    // fo_packets_sent_since_ir (99) >= large_interval.saturating_sub(1) (99) -> true
    let headers_refresh_ir = create_test_rtp_headers_minimal(
        201 + large_interval as u16,
        2010 + (large_interval * 10),
        false,
        ssrc,
    ); // SN=301
    let compressed_refresh_ir = handler
        .compress(
            comp_ctx_dyn_large.as_mut(),
            &GenericUncompressedHeaders::RtpUdpIpv4(headers_refresh_ir),
        )
        .unwrap();
    assert_eq!(
        compressed_refresh_ir[0],
        P1_ROHC_IR_PACKET_TYPE_WITH_DYN,
        "Packet after {} FOs (Packet {}) should be IR",
        large_interval - 1,
        large_interval + 1
    );

    let comp_ctx_large_after_refresh = comp_ctx_dyn_large
        .as_any()
        .downcast_ref::<Profile1CompressorContext>()
        .unwrap();
    assert_eq!(
        comp_ctx_large_after_refresh.fo_packets_sent_since_ir, 0,
        "FO count should reset after IR refresh"
    );
}

// --- 6. Robustness Tests ---

#[test]
fn p1_ir_packet_with_static_only_d_bit_0_parse_fails_gracefully() {
    // Your current parse_profile1_ir_packet assumes IR-DYN (D-bit=1).
    // We need to construct a fake IR packet with D-bit=0.
    let handler = Profile1Handler::new();
    let mut decomp_ctx_dyn = handler.create_decompressor_context(0);

    let ir_data = default_ir_packet_data(0, 0xFEEDF00D, 10);
    let mut ir_packet_bytes = Vec::new();

    // Type octet for IR static-only (D-bit = 0)
    ir_packet_bytes.push(P1_ROHC_IR_PACKET_TYPE_STATIC_ONLY); // 0xFC
    // Profile ID
    ir_packet_bytes.push(RohcProfile::RtpUdpIp.into());
    // Static Chain
    ir_packet_bytes.extend_from_slice(&ir_data.static_ip_src.octets());
    ir_packet_bytes.extend_from_slice(&ir_data.static_ip_dst.octets());
    ir_packet_bytes.extend_from_slice(&ir_data.static_udp_src_port.to_be_bytes());
    ir_packet_bytes.extend_from_slice(&ir_data.static_udp_dst_port.to_be_bytes());
    ir_packet_bytes.extend_from_slice(&ir_data.static_rtp_ssrc.to_be_bytes());
    // NO Dynamic Chain

    // CRC (over Profile + Static Chain)
    let crc_payload = &ir_packet_bytes[1..]; // Profile + Static
    let crc = rohcstar::crc::calculate_rohc_crc8(crc_payload);
    ir_packet_bytes.push(crc);

    // Expected length for IR static-only: Type(1)+Profile(1)+Static(16)+CRC(1) = 19
    assert_eq!(
        ir_packet_bytes.len(),
        1 + 1 + P1_STATIC_CHAIN_LENGTH_BYTES + 1
    );

    // Current `parse_profile1_ir_packet` expects D-bit to be set and thus expects dynamic chain length.
    // It will likely fail with NotEnoughData because it expects more bytes for the dynamic chain.
    let result = handler.decompress(decomp_ctx_dyn.as_mut(), &ir_packet_bytes);

    match result {
        // The parse_profile1_ir_packet calculates expected length based on D-bit.
        // If D-bit is 0, expected_chain_length = P1_STATIC_CHAIN_LENGTH_BYTES.
        // expected_crc_payload_length = 1 + P1_STATIC_CHAIN_LENGTH_BYTES.
        // expected_total_core_packet_length = 1 (type) + 1 (profile) + P1_STATIC_CHAIN_LENGTH_BYTES + 1 (CRC) = 19.
        // The packet IS 19 bytes. The parser should parse it, but the IrPacket struct might have default dynamic values.
        // The handler::decompress further uses this to init context.
        // The primary check is that it *doesn't panic* and processes.
        // The test for *supporting* IR static-only would be more involved.
        // This test verifies graceful handling if the parser/handler *assumes* IR-DYN.
        //
        // If `parse_profile1_ir_packet` strictly checks `packet_type_octet == P1_ROHC_IR_PACKET_TYPE_WITH_DYN`,
        // it would fail with InvalidPacketType.
        // If it checks `(packet_type_octet & !P1_ROHC_IR_PACKET_TYPE_D_BIT_MASK) == P1_ROHC_IR_PACKET_TYPE_BASE`
        // and then uses `d_bit_is_set`, it should parse.
        //
        // The current `parse_profile1_ir_packet` checks:
        // `if (packet_type_octet & !P1_ROHC_IR_PACKET_TYPE_D_BIT_MASK) != P1_ROHC_IR_PACKET_TYPE_BASE`
        // This will pass for 0xFC. Then `d_bit_is_set` will be false.
        // The length calculation will be correct for static-only.
        // So it *should* parse correctly.
        Ok(GenericUncompressedHeaders::RtpUdpIpv4(h)) => {
            assert_eq!(h.rtp_ssrc, ir_data.static_rtp_ssrc);
            assert_eq!(h.rtp_sequence_number, 0); // Default from IrPacket if D-bit=0
        }
        _ => panic!(
            "Expected successful parse for static-only IR, or specific error if not supported by current logic. Got: {:?}",
            result
        ),
    }
}

#[test]
fn p1_decompressor_context_persistence_across_ir_packets() {
    let mut engine = RohcEngine::new(10); // High refresh interval to avoid auto-refresh
    engine
        .register_profile_handler(Box::new(Profile1Handler::new()))
        .unwrap();
    let cid = 0u16;
    let ssrc1 = 0xABCDE001;
    let ssrc2 = 0xABCDE002; // Different SSRC for the second IR

    // Packet 1: IR for SSRC1
    let headers_ir1 = create_test_rtp_headers_minimal(10, 100, false, ssrc1);
    let generic_ir1 = GenericUncompressedHeaders::RtpUdpIpv4(headers_ir1.clone());
    let compressed_ir1 = engine
        .compress(cid, Some(RohcProfile::RtpUdpIp), &generic_ir1)
        .unwrap();
    let decomp_ir1 = engine
        .decompress(&compressed_ir1)
        .unwrap()
        .as_rtp_udp_ipv4()
        .unwrap()
        .clone();
    assert_eq!(decomp_ir1.rtp_ssrc, ssrc1);
    assert_eq!(decomp_ir1.rtp_sequence_number, 10);

    // Decompressor context check after IR1
    {
        let decomp_ctx_dyn = engine
            .context_manager_mut()
            .get_decompressor_context_mut(cid)
            .unwrap();
        let decomp_ctx = decomp_ctx_dyn
            .as_any()
            .downcast_ref::<Profile1DecompressorContext>()
            .unwrap();
        assert_eq!(decomp_ctx.mode, Profile1DecompressorMode::FullContext);
        assert_eq!(decomp_ctx.rtp_ssrc, ssrc1);
        assert_eq!(decomp_ctx.last_reconstructed_rtp_sn_full, 10);
    }

    // Simulate some UO packets for SSRC1 (not strictly needed for this test focus, but good for state)
    let headers_uo = create_test_rtp_headers_minimal(11, 110, false, ssrc1);
    let generic_uo = GenericUncompressedHeaders::RtpUdpIpv4(headers_uo);
    let compressed_uo = engine
        .compress(cid, Some(RohcProfile::RtpUdpIp), &generic_uo)
        .unwrap();
    let _ = engine.decompress(&compressed_uo).unwrap();

    // Packet 2: Another IR, this time with SSRC2 (implies a stream change or re-sync)
    let headers_ir2 = create_test_rtp_headers_minimal(50, 500, true, ssrc2);
    let generic_ir2 = GenericUncompressedHeaders::RtpUdpIpv4(headers_ir2.clone());
    let compressed_ir2 = engine
        .compress(cid, Some(RohcProfile::RtpUdpIp), &generic_ir2)
        .unwrap();
    let decomp_ir2 = engine
        .decompress(&compressed_ir2)
        .unwrap()
        .as_rtp_udp_ipv4()
        .unwrap()
        .clone();
    assert_eq!(decomp_ir2.rtp_ssrc, ssrc2);
    assert_eq!(decomp_ir2.rtp_sequence_number, 50);
    assert!(decomp_ir2.rtp_marker);

    // Decompressor context check after IR2
    {
        let decomp_ctx_dyn = engine
            .context_manager_mut()
            .get_decompressor_context_mut(cid)
            .unwrap();
        let decomp_ctx = decomp_ctx_dyn
            .as_any()
            .downcast_ref::<Profile1DecompressorContext>()
            .unwrap();
        assert_eq!(
            decomp_ctx.mode,
            Profile1DecompressorMode::FullContext,
            "Should remain in FullContext after a valid IR"
        );
        assert_eq!(
            decomp_ctx.rtp_ssrc, ssrc2,
            "SSRC should be updated by the new IR"
        );
        assert_eq!(
            decomp_ctx.last_reconstructed_rtp_sn_full, 50,
            "SN should be updated"
        );
        assert_eq!(
            decomp_ctx.last_reconstructed_rtp_ts_full, 500,
            "TS should be updated"
        );
        assert!(
            decomp_ctx.last_reconstructed_rtp_marker,
            "Marker should be updated"
        );
        assert_eq!(
            decomp_ctx.consecutive_crc_failures_in_fc, 0,
            "CRC failure count should be reset"
        );
    }
}

// --- 7. Memory and Performance Tests  ---

#[test]
#[ignore]
fn p1_ir_packet_processing_performance() {
    use std::time::Instant;

    let mut engine = RohcEngine::new(u32::MAX); // Disable auto-refresh for perf test
    engine
        .register_profile_handler(Box::new(Profile1Handler::new()))
        .unwrap();

    let num_packets = 10_000;
    let mut uncompressed_packets = Vec::with_capacity(num_packets);
    for i in 0..num_packets {
        let headers = create_test_rtp_headers_minimal(
            i as u16,
            (i * 10) as u32,
            false,
            0x12345000 + i as u32,
        );
        uncompressed_packets.push(GenericUncompressedHeaders::RtpUdpIpv4(headers));
    }

    let mut compressed_packets = Vec::with_capacity(num_packets);

    // Compression benchmark
    let start_compress = Instant::now();
    (0..num_packets).for_each(|i| {
        // For IR, each packet effectively creates/re-initializes a context conceptually for SSRC change
        // To test pure IR build performance, we might use the handler directly with a pre-set context.
        // Or, for engine test, use different CIDs to force new IRs.
        let cid = i as u16;
        let compressed = engine
            .compress(cid, Some(RohcProfile::RtpUdpIp), &uncompressed_packets[i])
            .unwrap();
        compressed_packets.push(compressed);
    });
    let compress_duration = start_compress.elapsed();
    println!(
        "IR Compression: {} packets in {:?}, {:.2} packets/sec",
        num_packets,
        compress_duration,
        num_packets as f64 / compress_duration.as_secs_f64()
    );

    // Decompression benchmark
    let start_decompress = Instant::now();
    (0..num_packets).for_each(|i| {
        let _ = engine.decompress(&compressed_packets[i]).unwrap();
    });
    let decompress_duration = start_decompress.elapsed();
    println!(
        "IR Decompression: {} packets in {:?}, {:.2} packets/sec",
        num_packets,
        decompress_duration,
        num_packets as f64 / decompress_duration.as_secs_f64()
    );

    // TODO: Figure out reasonable value to test against here.
    assert!(compress_duration.as_millis() < 500, "Compression too slow");
}
