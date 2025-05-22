use crate::constants::{
    ADD_CID_OCTET_CID_MASK, ADD_CID_OCTET_PREFIX_MASK, ADD_CID_OCTET_PREFIX_VALUE,
    DECOMPRESSOR_FC_TO_SC_CRC_FAILURE_THRESHOLD, IP_PROTOCOL_UDP, ROHC_IR_PACKET_TYPE_BASE,
    ROHC_IR_PACKET_TYPE_D_BIT_MASK, RTP_VERSION, UO_1_SN_PACKET_TYPE_BASE,
};
use crate::context::{DecompressorMode, RtpUdpIpP1DecompressorContext};
use crate::encodings::decode_lsb;
use crate::error::{RohcError, RohcParsingError};
use crate::packet_processor::{
    parse_ir_profile1_packet, parse_uo0_profile1_cid0_packet, parse_uo1_sn_profile1_packet,
};
use crate::protocol_types::{RohcIrProfile1Packet, RtpUdpIpv4Headers};

/// Creates the byte sequence from reconstructed header fields for UO-packet CRC verification.
///
/// This input must exactly match the input used by the compressor when it calculated the CRC.
/// For ROHC Profile 1 (RTP/UDP/IP) U-mode, this includes:
/// - SSRC (from context)
/// - Reconstructed RTP Sequence Number
/// - Reconstructed RTP Timestamp (Note: For UO-0 and UO-1-SN, TS is typically from context)
/// - Reconstructed RTP Marker bit
///
/// # Arguments
/// * `context`: The current decompressor context.
/// * `reconstructed_sn`: The fully reconstructed RTP Sequence Number for the current packet.
/// * `reconstructed_ts`: The RTP Timestamp to be used for CRC (often from context for UO-0/1-SN).
/// * `reconstructed_marker`: The reconstructed RTP Marker bit for the current packet.
///
/// # Returns
/// A `Vec<u8>` containing the bytes for CRC calculation.
fn create_crc_input_for_uo_packet_verification(
    context: &RtpUdpIpP1DecompressorContext,
    reconstructed_sn: u16,
    reconstructed_ts: u32,
    reconstructed_marker: bool,
) -> Vec<u8> {
    // Capacity: SSRC (4) + SN (2) + TS (4) + Marker (1) = 11 bytes
    let mut crc_input = Vec::with_capacity(11);

    crc_input.extend_from_slice(&context.rtp_ssrc.to_be_bytes());
    crc_input.extend_from_slice(&reconstructed_sn.to_be_bytes());
    crc_input.extend_from_slice(&reconstructed_ts.to_be_bytes());
    crc_input.push(if reconstructed_marker { 0x01 } else { 0x00 });
    crc_input
}

/// Reconstructs uncompressed RTP/UDP/IPv4 headers from a parsed IR packet.
///
/// This is a straightforward mapping as the IR packet contains most fields uncompressed.
///
/// # Arguments
/// * `ir_packet`: The parsed `RohcIrProfile1Packet`.
///
/// # Returns
/// The reconstructed `RtpUdpIpv4Headers`.
fn reconstruct_headers_from_ir(ir_packet: &RohcIrProfile1Packet) -> RtpUdpIpv4Headers {
    RtpUdpIpv4Headers {
        ip_src: ir_packet.static_ip_src,
        ip_dst: ir_packet.static_ip_dst,
        udp_src_port: ir_packet.static_udp_src_port,
        udp_dst_port: ir_packet.static_udp_dst_port,
        rtp_ssrc: ir_packet.static_rtp_ssrc,
        rtp_sequence_number: ir_packet.dyn_rtp_sn,
        rtp_timestamp: ir_packet.dyn_rtp_timestamp,
        rtp_marker: ir_packet.dyn_rtp_marker,
        ip_protocol: IP_PROTOCOL_UDP,
        rtp_version: RTP_VERSION,
        ip_ihl: 5,
        ip_ttl: 64,
        ..Default::default()
    }
}

/// Handles the processing of a parsed IR packet.
///
/// Updates the decompressor context with information from the IR packet and
/// reconstructs the uncompressed headers.
///
/// # Arguments
/// * `context`: Mutable reference to the decompressor context.
/// * `parsed_ir`: The `RohcIrProfile1Packet` parsed from the input.
/// * `cid_from_packet_stream`: The CID determined from the packet stream (e.g., from Add-CID).
///
/// # Returns
/// `Ok(RtpUdpIpv4Headers)` if successful, or `RohcError` on failure.
fn process_ir_packet(
    context: &mut RtpUdpIpP1DecompressorContext,
    mut parsed_ir: RohcIrProfile1Packet, // Made mutable to update CID
    cid_from_packet_stream: u16,
) -> Result<RtpUdpIpv4Headers, RohcError> {
    // Ensure the parsed_ir's CID field reflects the CID used for context association.
    parsed_ir.cid = cid_from_packet_stream;

    context.cid = parsed_ir.cid; // Update context's CID
    context.initialize_from_ir_packet(&parsed_ir);
    // CRC was already verified by parse_ir_profile1_packet
    // Reset consecutive CRC failure count as IR reception implies successful context sync.
    context.consecutive_crc_failures_in_fc = 0;
    Ok(reconstruct_headers_from_ir(&parsed_ir))
}

/// Handles the processing of a parsed UO-0 packet.
///
/// Reconstructs headers, verifies CRC, and updates context.
///
/// # Arguments
/// * `context`: Mutable reference to the decompressor context.
/// * `core_packet_slice`: Slice of bytes representing the UO-0 packet (after Add-CID, if any).
/// * `cid_from_packet_stream`: The CID determined from the packet stream.
///
/// # Returns
/// `Ok(RtpUdpIpv4Headers)` if successful, or `RohcError` on failure (e.g. CRC mismatch).
fn process_uo0_packet(
    context: &mut RtpUdpIpP1DecompressorContext,
    core_packet_slice: &[u8],
    cid_from_packet_stream: u16,
) -> Result<RtpUdpIpv4Headers, RohcError> {
    if context.mode != DecompressorMode::FullContext {
        return Err(RohcError::InvalidState(
            "Received UO-0 packet but decompressor is not in Full Context mode.".to_string(),
        ));
    }
    if context.cid != cid_from_packet_stream {
        // This can happen if an Add-CID was present for a UO packet for a CID
        // different from the one currently active in the single context.
        // For SimpleContextManager, this is an error as it expects UO packets for current CID.
        return Err(RohcError::ContextNotFound(cid_from_packet_stream));
    }

    let parsed_uo0 =
        parse_uo0_profile1_cid0_packet(core_packet_slice).map_err(RohcError::Parsing)?;

    let reconstructed_sn = decode_lsb(
        parsed_uo0.sn_lsb as u64,
        context.last_reconstructed_rtp_sn_full as u64,
        context.expected_lsb_sn_width,
        context.p_sn,
    )
    .map_err(RohcError::Parsing)? as u16;

    let reconstructed_ts_for_header = context.last_reconstructed_rtp_ts_full;
    let reconstructed_marker_for_header = context.last_reconstructed_rtp_marker;

    let reconstructed_headers = RtpUdpIpv4Headers {
        ip_src: context.ip_source,
        ip_dst: context.ip_destination,
        udp_src_port: context.udp_source_port,
        udp_dst_port: context.udp_destination_port,
        rtp_ssrc: context.rtp_ssrc,
        rtp_sequence_number: reconstructed_sn,
        rtp_timestamp: reconstructed_ts_for_header,
        rtp_marker: reconstructed_marker_for_header,
        ip_protocol: IP_PROTOCOL_UDP,
        rtp_version: RTP_VERSION,
        ip_ihl: 5,
        ip_ttl: 64,
        ..Default::default()
    };

    // For CRC verification, we use the reconstructed SN, and the TS/Marker values
    // that the *compressor* would have used from its original uncompressed packet.
    // For UO-0, the compressor assumes TS doesn't change significantly from its context,
    // and marker also doesn't change (else it would send UO-1).
    let crc_payload_bytes = create_crc_input_for_uo_packet_verification(
        context,
        reconstructed_sn,
        context.last_reconstructed_rtp_ts_full,
        context.last_reconstructed_rtp_marker,
    );
    let calculated_crc3 = crate::crc::calculate_rohc_crc3(&crc_payload_bytes);

    if calculated_crc3 == parsed_uo0.crc3 {
        context.last_reconstructed_rtp_sn_full = reconstructed_sn;
        context.consecutive_crc_failures_in_fc = 0;
        Ok(reconstructed_headers)
    } else {
        context.consecutive_crc_failures_in_fc += 1;
        if context.consecutive_crc_failures_in_fc >= DECOMPRESSOR_FC_TO_SC_CRC_FAILURE_THRESHOLD {
            context.mode = DecompressorMode::StaticContext;
        }
        Err(RohcError::Parsing(RohcParsingError::CrcMismatch {
            expected: parsed_uo0.crc3,
            calculated: calculated_crc3,
        }))
    }
}

/// Handles the processing of a parsed UO-1-SN packet.
///
/// Reconstructs headers, verifies CRC, and updates context.
///
/// # Arguments
/// * `context`: Mutable reference to the decompressor context.
/// * `core_packet_slice`: Slice of bytes representing the UO-1-SN packet.
/// * `cid_from_packet_stream`: The CID determined from the packet stream.
///
/// # Returns
/// `Ok(RtpUdpIpv4Headers)` if successful, or `RohcError` on failure.
fn process_uo1_sn_packet(
    context: &mut RtpUdpIpP1DecompressorContext,
    core_packet_slice: &[u8],
    cid_from_packet_stream: u16,
) -> Result<RtpUdpIpv4Headers, RohcError> {
    if context.mode != DecompressorMode::FullContext {
        return Err(RohcError::InvalidState(
            "Received UO-1 packet but decompressor is not in Full Context mode.".to_string(),
        ));
    }
    if context.cid != cid_from_packet_stream {
        return Err(RohcError::ContextNotFound(cid_from_packet_stream));
    }

    let parsed_uo1 = parse_uo1_sn_profile1_packet(core_packet_slice).map_err(RohcError::Parsing)?;

    let reconstructed_sn = decode_lsb(
        parsed_uo1.sn_lsb as u64,
        context.last_reconstructed_rtp_sn_full as u64,
        parsed_uo1.num_sn_lsb_bits,
        context.p_sn,
    )
    .map_err(RohcError::Parsing)? as u16;

    // UO-1-SN carries the marker bit directly.
    let reconstructed_marker_for_header = parsed_uo1.rtp_marker_bit_value.ok_or_else(|| {
        RohcError::Parsing(RohcParsingError::MandatoryFieldMissing {
            field_name: "UO-1-SN Marker bit".to_string(),
        })
    })?;
    // For UO-1-SN, timestamp is taken from context (not conveyed in this packet type).
    let reconstructed_ts_for_header = context.last_reconstructed_rtp_ts_full;

    let reconstructed_headers = RtpUdpIpv4Headers {
        ip_src: context.ip_source,
        ip_dst: context.ip_destination,
        udp_src_port: context.udp_source_port,
        udp_dst_port: context.udp_destination_port,
        rtp_ssrc: context.rtp_ssrc,
        rtp_sequence_number: reconstructed_sn,
        rtp_timestamp: reconstructed_ts_for_header,
        rtp_marker: reconstructed_marker_for_header,
        ip_protocol: IP_PROTOCOL_UDP,
        rtp_version: RTP_VERSION,
        ip_ihl: 5,
        ip_ttl: 64,
        ..Default::default()
    };

    // For CRC verification with UO-1-SN:
    // - SN is the reconstructed_sn.
    // - Marker is the reconstructed_marker_for_header (carried in UO-1-SN).
    // - TS: The compressor, when forming UO-1-SN, would have used its *current* uncompressed TS
    //   for CRC calculation, even though UO-1-SN doesn't transmit TS LSBs (in this MVP variant).
    //   The decompressor *infers* TS from context for header reconstruction, but for CRC
    //   it needs to conceptually match what the compressor used.
    let crc_payload_bytes = create_crc_input_for_uo_packet_verification(
        context,
        reconstructed_sn,
        context.last_reconstructed_rtp_ts_full,
        reconstructed_marker_for_header,
    );
    let calculated_crc8 = crate::crc::calculate_rohc_crc8(&crc_payload_bytes);

    if calculated_crc8 == parsed_uo1.crc8 {
        context.last_reconstructed_rtp_sn_full = reconstructed_sn;
        context.last_reconstructed_rtp_marker = reconstructed_marker_for_header;
        context.consecutive_crc_failures_in_fc = 0;
        Ok(reconstructed_headers)
    } else {
        context.consecutive_crc_failures_in_fc += 1;
        if context.consecutive_crc_failures_in_fc >= DECOMPRESSOR_FC_TO_SC_CRC_FAILURE_THRESHOLD {
            context.mode = DecompressorMode::StaticContext;
        }
        Err(RohcError::Parsing(RohcParsingError::CrcMismatch {
            expected: parsed_uo1.crc8,
            calculated: calculated_crc8,
        }))
    }
}

/// Decompresses a ROHC packet for Profile 1 (RTP/UDP/IP) in Unidirectional mode (U-mode).
///
/// This function first checks for an Add-CID octet to determine the effective CID.
/// Then, based on the packet type discriminator, it dispatches to the appropriate
/// parser (IR, UO-0, UO-1) and processing logic.
/// It updates the decompressor context and returns the reconstructed uncompressed headers.
///
/// # Arguments
/// * `context`: A mutable reference to the `RtpUdpIpP1DecompressorContext` for this flow.
/// * `rohc_packet_bytes`: A slice containing the raw bytes of the ROHC packet.
///
/// # Returns
/// A `Result` containing the reconstructed `RtpUdpIpv4Headers`, or a `RohcError`
/// if decompression fails (e.g., parsing error, CRC mismatch, invalid state).
pub fn decompress_rtp_udp_ip_umode(
    context: &mut RtpUdpIpP1DecompressorContext,
    rohc_packet_bytes: &[u8],
) -> Result<RtpUdpIpv4Headers, RohcError> {
    if rohc_packet_bytes.is_empty() {
        return Err(RohcError::Parsing(RohcParsingError::NotEnoughData {
            needed: 1,
            got: 0,
        }));
    }

    let mut cursor: usize = 0;
    let mut cid_from_packet_stream: u16 = context.cid;

    // Check for Add-CID octet
    if (rohc_packet_bytes[cursor] & ADD_CID_OCTET_PREFIX_MASK) == ADD_CID_OCTET_PREFIX_VALUE {
        let cid_val_from_add_cid = rohc_packet_bytes[cursor] & ADD_CID_OCTET_CID_MASK;
        if cid_val_from_add_cid == 0 {
            // An Add-CID octet with CID bits = 0 is padding, not a CID indication for CID 0.
            // This is an invalid use if it's the *only* byte and implies CID 0.
            // If followed by other ROHC packet types, it's padding.
            // For now, consider it an error if it's the only thing suggesting a CID.
            return Err(RohcError::Parsing(RohcParsingError::InvalidPacketType(
                rohc_packet_bytes[cursor],
            )));
        }
        cid_from_packet_stream = cid_val_from_add_cid as u16;
        cursor += 1; // Advance past Add-CID octet
        if cursor >= rohc_packet_bytes.len() {
            // Add-CID octet was the only byte, not a valid ROHC packet.
            return Err(RohcError::Parsing(RohcParsingError::NotEnoughData {
                needed: cursor + 1, // Expected at least one more byte for packet type
                got: rohc_packet_bytes.len(),
            }));
        }
    }

    let core_packet_slice = &rohc_packet_bytes[cursor..];
    if core_packet_slice.is_empty() {
        // This case should be caught by the check above if cursor advanced.
        // If cursor didn't advance, rohc_packet_bytes.is_empty() at the start handles it.
        return Err(RohcError::Parsing(RohcParsingError::NotEnoughData {
            needed: 1, // Need at least one byte for packet type
            got: 0,
        }));
    }

    let type_determining_byte = core_packet_slice[0];

    // Dispatch based on packet type
    if (type_determining_byte & !ROHC_IR_PACKET_TYPE_D_BIT_MASK) == ROHC_IR_PACKET_TYPE_BASE {
        let parsed_ir = parse_ir_profile1_packet(core_packet_slice).map_err(RohcError::Parsing)?;
        process_ir_packet(context, parsed_ir, cid_from_packet_stream)
    } else if (type_determining_byte & 0xF0) == UO_1_SN_PACKET_TYPE_BASE {
        process_uo1_sn_packet(context, core_packet_slice, cid_from_packet_stream)
    } else if (type_determining_byte & 0x80) == 0x00 {
        process_uo0_packet(context, core_packet_slice, cid_from_packet_stream)
    } else {
        Err(RohcError::Parsing(RohcParsingError::InvalidPacketType(
            type_determining_byte,
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::DEFAULT_UO0_SN_LSB_WIDTH;
    use crate::constants::PROFILE_ID_RTP_UDP_IP;
    use crate::context::RtpUdpIpP1CompressorContext;
    use crate::packet_processor::build_ir_profile1_packet;
    use crate::packet_processor::build_uo0_profile1_cid0_packet;
    use crate::profiles::profile1_compressor::compress_rtp_udp_ip_umode;

    fn default_uncompressed_headers_for_decomp_test(sn: u16) -> RtpUdpIpv4Headers {
        RtpUdpIpv4Headers {
            ip_src: "192.168.1.10".parse().unwrap(),
            ip_dst: "192.168.1.20".parse().unwrap(),
            udp_src_port: 1234,
            udp_dst_port: 5678,
            rtp_ssrc: 0x11223344,
            rtp_sequence_number: sn,
            rtp_timestamp: 1000 + (sn.wrapping_sub(100) as u32 * 160),
            rtp_marker: false,
            ip_ttl: 64,
            ..Default::default()
        }
    }

    #[test]
    fn decompress_ir_packet_cid0() {
        let mut decompressor_context = RtpUdpIpP1DecompressorContext::new(0, PROFILE_ID_RTP_UDP_IP);
        let headers = default_uncompressed_headers_for_decomp_test(100);
        let ir_data_to_build = RohcIrProfile1Packet {
            cid: 0, // Implicit CID 0
            profile: PROFILE_ID_RTP_UDP_IP,
            static_ip_src: headers.ip_src,
            static_ip_dst: headers.ip_dst,
            static_udp_src_port: headers.udp_src_port,
            static_udp_dst_port: headers.udp_dst_port,
            static_rtp_ssrc: headers.rtp_ssrc,
            dyn_rtp_sn: headers.rtp_sequence_number,
            dyn_rtp_timestamp: headers.rtp_timestamp,
            dyn_rtp_marker: headers.rtp_marker,
            ..Default::default()
        };
        let ir_packet_bytes = build_ir_profile1_packet(&ir_data_to_build).unwrap();

        let decompressed_headers =
            decompress_rtp_udp_ip_umode(&mut decompressor_context, &ir_packet_bytes).unwrap();

        assert_eq!(decompressor_context.mode, DecompressorMode::FullContext);
        assert_eq!(decompressor_context.cid, 0);
        assert_eq!(decompressed_headers.rtp_ssrc, headers.rtp_ssrc);
        assert_eq!(
            decompressed_headers.rtp_sequence_number,
            headers.rtp_sequence_number
        );
    }

    #[test]
    fn decompress_ir_packet_with_add_cid() {
        let cid_val: u16 = 7;
        // Decompressor context might be for CID 0 initially or not yet existing for CID 7
        let mut decompressor_context = RtpUdpIpP1DecompressorContext::new(0, PROFILE_ID_RTP_UDP_IP);

        // Simulate initial state
        decompressor_context.mode = DecompressorMode::NoContext;

        let headers = default_uncompressed_headers_for_decomp_test(100);
        let ir_data_to_build = RohcIrProfile1Packet {
            cid: cid_val, // This CID will be encoded in Add-CID octet by builder
            profile: PROFILE_ID_RTP_UDP_IP,
            static_ip_src: headers.ip_src,
            static_ip_dst: headers.ip_dst,
            ..headers.clone().into()
        };
        let ir_packet_bytes = build_ir_profile1_packet(&ir_data_to_build).unwrap();

        let decompressed_headers =
            decompress_rtp_udp_ip_umode(&mut decompressor_context, &ir_packet_bytes).unwrap();

        assert_eq!(
            decompressor_context.cid, cid_val,
            "Context CID should be updated to Add-CID value"
        );
        assert_eq!(decompressor_context.mode, DecompressorMode::FullContext);
        assert_eq!(decompressed_headers.rtp_ssrc, headers.rtp_ssrc);
    }

    // Helper impl for tests
    impl From<RtpUdpIpv4Headers> for RohcIrProfile1Packet {
        fn from(h: RtpUdpIpv4Headers) -> Self {
            RohcIrProfile1Packet {
                cid: 0,
                profile: PROFILE_ID_RTP_UDP_IP,
                crc8: 0,
                static_ip_src: h.ip_src,
                static_ip_dst: h.ip_dst,
                static_udp_src_port: h.udp_src_port,
                static_udp_dst_port: h.udp_dst_port,
                static_rtp_ssrc: h.rtp_ssrc,
                dyn_rtp_sn: h.rtp_sequence_number,
                dyn_rtp_timestamp: h.rtp_timestamp,
                dyn_rtp_marker: h.rtp_marker,
            }
        }
    }

    #[test]
    fn decompress_uo0_packet_cid0_success() {
        let mut compressor_context = RtpUdpIpP1CompressorContext::new(0, PROFILE_ID_RTP_UDP_IP, 10);
        let mut decompressor_context = RtpUdpIpP1DecompressorContext::new(0, PROFILE_ID_RTP_UDP_IP);
        decompressor_context.expected_lsb_sn_width = DEFAULT_UO0_SN_LSB_WIDTH;
        let headers1 = default_uncompressed_headers_for_decomp_test(100);

        // Initialize compressor context (implicitly done by first compress call if in IR mode)
        compressor_context.initialize_static_part_with_uncompressed_headers(&headers1);

        // Send IR to establish full context at decompressor
        let ir_packet_bytes =
            compress_rtp_udp_ip_umode(&mut compressor_context, &headers1).unwrap();
        let _ = decompress_rtp_udp_ip_umode(&mut decompressor_context, &ir_packet_bytes).unwrap();
        assert_eq!(decompressor_context.mode, DecompressorMode::FullContext);
        assert_eq!(decompressor_context.last_reconstructed_rtp_sn_full, 100);

        // Send UO-0
        let headers2 = default_uncompressed_headers_for_decomp_test(101); // SN = 101
        let uo0_packet_bytes =
            compress_rtp_udp_ip_umode(&mut compressor_context, &headers2).unwrap();

        let decompressed_headers =
            decompress_rtp_udp_ip_umode(&mut decompressor_context, &uo0_packet_bytes).unwrap();

        assert_eq!(decompressor_context.cid, 0);
        assert_eq!(
            decompressed_headers.rtp_sequence_number,
            headers2.rtp_sequence_number // SN=101
        );
        assert_eq!(decompressed_headers.rtp_timestamp, headers1.rtp_timestamp);
        assert_eq!(decompressed_headers.rtp_marker, headers1.rtp_marker);
        assert_eq!(decompressor_context.last_reconstructed_rtp_sn_full, 101);
    }

    #[test]
    fn decompress_uo0_crc_failure_leads_to_static_context_mode() {
        let mut decompressor_context = RtpUdpIpP1DecompressorContext::new(0, PROFILE_ID_RTP_UDP_IP);

        let ir_headers = default_uncompressed_headers_for_decomp_test(99);
        decompressor_context.ip_source = ir_headers.ip_src;
        decompressor_context.ip_destination = ir_headers.ip_dst;
        decompressor_context.udp_source_port = ir_headers.udp_src_port;
        decompressor_context.udp_destination_port = ir_headers.udp_dst_port;
        decompressor_context.rtp_ssrc = ir_headers.rtp_ssrc;
        decompressor_context.last_reconstructed_rtp_sn_full = ir_headers.rtp_sequence_number;
        decompressor_context.last_reconstructed_rtp_ts_full = ir_headers.rtp_timestamp;
        decompressor_context.last_reconstructed_rtp_marker = ir_headers.rtp_marker;
        decompressor_context.mode = DecompressorMode::FullContext;
        decompressor_context.expected_lsb_sn_width = DEFAULT_UO0_SN_LSB_WIDTH;

        let sn_for_packet: u16 = 100;
        let sn_lsb = crate::encodings::encode_lsb(sn_for_packet as u64, DEFAULT_UO0_SN_LSB_WIDTH)
            .unwrap() as u8;

        let crc_input_for_correct_packet = create_crc_input_for_uo_packet_verification(
            &decompressor_context,
            sn_for_packet,
            decompressor_context.last_reconstructed_rtp_ts_full,
            decompressor_context.last_reconstructed_rtp_marker,
        );
        let correct_crc3 = crate::crc::calculate_rohc_crc3(&crc_input_for_correct_packet);
        let corrupted_crc3 = correct_crc3.wrapping_add(1) & 0x07;

        let uo0_packet_bytes_corrupted_crc =
            build_uo0_profile1_cid0_packet(sn_lsb, corrupted_crc3).unwrap();

        for i in 0..DECOMPRESSOR_FC_TO_SC_CRC_FAILURE_THRESHOLD {
            let result = decompress_rtp_udp_ip_umode(
                &mut decompressor_context,
                &uo0_packet_bytes_corrupted_crc,
            );
            assert!(
                matches!(
                    result,
                    Err(RohcError::Parsing(RohcParsingError::CrcMismatch { .. }))
                ),
                "Iteration {} failed to produce CrcMismatch. Got: {:?}",
                i,
                result
            );
            if i < DECOMPRESSOR_FC_TO_SC_CRC_FAILURE_THRESHOLD - 1 {
                assert_eq!(
                    decompressor_context.mode,
                    DecompressorMode::FullContext,
                    "Should still be FC before threshold"
                );
            }
        }
        assert_eq!(
            decompressor_context.mode,
            DecompressorMode::StaticContext,
            "Should transition to SC after threshold CRC failures"
        );
        assert_eq!(
            decompressor_context.consecutive_crc_failures_in_fc,
            DECOMPRESSOR_FC_TO_SC_CRC_FAILURE_THRESHOLD
        );
    }
}
