//! IR (Initialization/Refresh) packet serialization and deserialization for Profile 1.
//!
//! This module handles the creation and parsing of IR packets, which carry static
//! and dynamic chain information for context initialization or refresh operations.
//! IR packets are used when establishing new contexts or recovering from errors.

use std::net::Ipv4Addr;

use super::super::constants::*;
use super::super::packet_types::IrPacket;
use crate::constants::{DEFAULT_IPV4_TTL, ROHC_ADD_CID_FEEDBACK_PREFIX_VALUE, ROHC_SMALL_CID_MASK};
use crate::crc::CrcCalculators;
use crate::error::{CrcType, Field, ParseContext, RohcBuildingError, RohcParsingError};
use crate::packet_defs::RohcProfile;
use crate::types::{ContextId, IpId, SequenceNumber, Ssrc, Timestamp};

/// Serializes a ROHC Profile 1 IR (Initialization/Refresh) packet into a provided buffer.
///
/// This function constructs an IR packet from its constituent parts, calculating
/// the required size and CRC. It handles the optional Add-CID octet for small CIDs
/// and the optional TS_STRIDE extension within the dynamic chain.
///
/// # Errors
/// - `RohcError::Building` - Serialization failed due to invalid packet data
///
/// # Errors
/// - [`RohcBuildingError::BufferTooSmall`] - Output buffer is insufficient.
/// - [`RohcBuildingError::InvalidFieldValueForBuild`] - CID is too large for an IR packet.
pub fn serialize_ir(
    ir_data: &IrPacket,
    crc_calculators: &CrcCalculators,
    out: &mut [u8],
) -> Result<usize, RohcBuildingError> {
    debug_assert_eq!(
        ir_data.profile_id,
        RohcProfile::RtpUdpIp,
        "IR packet must be for Profile 1"
    );

    let has_add_cid = ir_data.cid > 0 && ir_data.cid <= 15;
    let has_dyn_chain = true; // IR with D-bit is the only supported type for now
    let has_ts_stride = ir_data.ts_stride.is_some();

    // Type (1) + Profile (1) + Static Chain + CRC (1)
    let mut required_size = 1 + 1 + P1_STATIC_CHAIN_LENGTH_BYTES + 1;
    if has_add_cid {
        required_size += 1;
    }
    if has_dyn_chain {
        required_size += P1_BASE_DYNAMIC_CHAIN_LENGTH_BYTES;
    }
    if has_ts_stride {
        required_size += P1_TS_STRIDE_EXTENSION_LENGTH_BYTES;
    }

    if out.len() < required_size {
        return Err(RohcBuildingError::BufferTooSmall {
            needed: required_size,
            available: out.len(),
            context: ParseContext::IrSerialization,
        });
    }

    let crc_payload_start;
    let payload_end_offset;

    // This block limits the scope of `writer`'s mutable borrow on `out`.
    {
        let mut writer = PacketWriter::new(out);

        if has_add_cid {
            writer.write_u8(
                ROHC_ADD_CID_FEEDBACK_PREFIX_VALUE | (ir_data.cid.0 as u8 & ROHC_SMALL_CID_MASK),
            );
        } else if ir_data.cid > 15 {
            return Err(RohcBuildingError::InvalidFieldValueForBuild {
                field: Field::Cid,
                value: ir_data.cid.0 as u32,
                max_bits: 4,
            });
        }

        writer.write_u8(P1_ROHC_IR_PACKET_TYPE_WITH_DYN);
        crc_payload_start = writer.offset();
        serialize_static_chain(ir_data, &mut writer);
        serialize_dynamic_chain(ir_data, &mut writer);
        payload_end_offset = writer.offset();
    }

    let crc_payload = &out[crc_payload_start..payload_end_offset];
    let crc = crc_calculators.crc8(crc_payload);

    // Manually write the final CRC byte into the buffer.
    out[payload_end_offset] = crc;

    let final_size = payload_end_offset + 1;
    debug_assert_eq!(
        final_size, required_size,
        "Mismatch between calculated and written size"
    );

    Ok(final_size)
}

/// Deserializes a ROHC Profile 1 IR (Initialization/Refresh) packet.
///
/// Parses the core content of an IR packet, starting from the packet type octet.
/// This function validates the packet's CRC-8 checksum before attempting to
/// deserialize the static and dynamic chains. It assumes the Add-CID octet,
/// if present, has already been processed by the caller.
///
/// # Errors
/// - [`RohcParsingError::NotEnoughData`] - The packet is too small for its claimed content.
/// - [`RohcParsingError::InvalidPacketType`] - The discriminator is not a valid IR type.
/// - [`RohcParsingError::CrcMismatch`] - The calculated CRC-8 does not match the received CRC.
/// - [`RohcParsingError::InvalidProfileId`] - The profile is not Profile 1.
pub(crate) fn deserialize_ir(
    core_packet_bytes: &[u8],
    cid_from_engine: ContextId,
    crc_calculators: &CrcCalculators,
) -> Result<IrPacket, RohcParsingError> {
    let mut reader = PacketReader::new(core_packet_bytes);
    let packet_type = reader.read_u8().ok_or(RohcParsingError::NotEnoughData {
        needed: 1,
        got: reader.len(),
        context: ParseContext::IrPacketTypeOctet,
    })?;

    if (packet_type & !P1_ROHC_IR_PACKET_TYPE_D_BIT_MASK) != P1_ROHC_IR_PACKET_TYPE_BASE {
        return Err(RohcParsingError::InvalidPacketType {
            discriminator: packet_type,
            profile_id: Some(RohcProfile::RtpUdpIp.into()),
        });
    }
    let d_bit_set = (packet_type & P1_ROHC_IR_PACKET_TYPE_D_BIT_MASK) != 0;

    validate_ir_crc(core_packet_bytes, d_bit_set, crc_calculators)?;
    let received_crc = core_packet_bytes.last().unwrap(); // Safe due to validation

    let static_chain = deserialize_static_chain(&mut reader)?;
    let (dyn_chain, ts_stride) = if d_bit_set {
        deserialize_dynamic_chain(&mut reader)?
    } else {
        // Default values for IR packet without dynamic part
        (
            (
                SequenceNumber::new(0),
                Timestamp::new(0),
                false,
                DEFAULT_IPV4_TTL,
                0.into(),
            ),
            None,
        )
    };

    Ok(IrPacket {
        cid: cid_from_engine,
        profile_id: RohcProfile::from(static_chain.0),
        crc8: *received_crc,
        static_ip_src: static_chain.1,
        static_ip_dst: static_chain.2,
        static_udp_src_port: static_chain.3,
        static_udp_dst_port: static_chain.4,
        static_rtp_ssrc: static_chain.5,
        static_rtp_payload_type: static_chain.6,
        static_rtp_extension: static_chain.7,
        static_rtp_padding: static_chain.8,
        dyn_rtp_sn: dyn_chain.0,
        dyn_rtp_timestamp: dyn_chain.1,
        dyn_rtp_marker: dyn_chain.2,
        dyn_ip_ttl: dyn_chain.3,
        dyn_ip_id: dyn_chain.4,
        ts_stride,
    })
}

// RFC 5775: The CRC is computed over the entire packet, starting from the
// Profile Indicator octet and up to the octet preceding the CRC.
fn validate_ir_crc(
    core_packet_bytes: &[u8],
    d_bit_set: bool,
    crc_calculators: &CrcCalculators,
) -> Result<(), RohcParsingError> {
    let rtp_flags_offset =
        1 + 1 + P1_STATIC_CHAIN_LENGTH_BYTES + P1_BASE_DYNAMIC_CHAIN_LENGTH_BYTES - 1;
    let mut crc_payload_len = 1 + P1_STATIC_CHAIN_LENGTH_BYTES; // Profile octet + static chain

    if d_bit_set {
        crc_payload_len += P1_BASE_DYNAMIC_CHAIN_LENGTH_BYTES;
        // Check for TS_STRIDE flag to include it in the CRC calculation.
        let rtp_flags =
            *core_packet_bytes
                .get(rtp_flags_offset)
                .ok_or(RohcParsingError::NotEnoughData {
                    needed: rtp_flags_offset + 1,
                    got: core_packet_bytes.len(),
                    context: ParseContext::IrPacketRtpFlags,
                })?;
        if (rtp_flags & P1_IR_DYN_RTP_FLAGS_TS_STRIDE_BIT_MASK) != 0 {
            crc_payload_len += P1_TS_STRIDE_EXTENSION_LENGTH_BYTES;
        }
    }

    let crc_payload_end = 1 + crc_payload_len;
    if core_packet_bytes.len() < crc_payload_end + 1 {
        // +1 for the CRC octet itself
        return Err(RohcParsingError::NotEnoughData {
            needed: crc_payload_end + 1,
            got: core_packet_bytes.len(),
            context: ParseContext::IrPacketCrcAndPayload,
        });
    }

    let crc_payload = &core_packet_bytes[1..crc_payload_end];
    let received_crc = core_packet_bytes[crc_payload_end];
    let calculated_crc = crc_calculators.crc8(crc_payload);

    if received_crc != calculated_crc {
        return Err(RohcParsingError::CrcMismatch {
            expected: received_crc,
            calculated: calculated_crc,
            crc_type: CrcType::Rohc8,
        });
    }
    Ok(())
}

fn serialize_static_chain(ir_data: &IrPacket, writer: &mut PacketWriter) {
    writer.write_u8(ir_data.profile_id.into());
    writer.write_slice(&ir_data.static_ip_src.octets());
    writer.write_slice(&ir_data.static_ip_dst.octets());
    writer.write_u16_be(ir_data.static_udp_src_port);
    writer.write_u16_be(ir_data.static_udp_dst_port);
    writer.write_u32_be(ir_data.static_rtp_ssrc.into());
    writer.write_u8(ir_data.static_rtp_payload_type);
    writer.write_u8(ir_data.static_rtp_extension as u8);
    writer.write_u8(ir_data.static_rtp_padding as u8);
}

fn serialize_dynamic_chain(ir_data: &IrPacket, writer: &mut PacketWriter) {
    writer.write_u16_be(ir_data.dyn_rtp_sn.into());
    writer.write_u32_be(ir_data.dyn_rtp_timestamp.into());
    writer.write_u8(ir_data.dyn_ip_ttl);
    writer.write_u16_be(ir_data.dyn_ip_id.into());

    let mut rtp_flags = 0u8;
    if ir_data.dyn_rtp_marker {
        rtp_flags |= P1_IR_DYN_RTP_FLAGS_MARKER_BIT_MASK;
    }
    if ir_data.ts_stride.is_some() {
        rtp_flags |= P1_IR_DYN_RTP_FLAGS_TS_STRIDE_BIT_MASK;
    }
    writer.write_u8(rtp_flags);

    if let Some(stride) = ir_data.ts_stride {
        writer.write_u32_be(stride);
    }
}

type StaticChainData = (u8, Ipv4Addr, Ipv4Addr, u16, u16, Ssrc, u8, bool, bool);
type DynamicChainData = (SequenceNumber, Timestamp, bool, u8, IpId);

fn deserialize_static_chain(
    reader: &mut PacketReader,
) -> Result<StaticChainData, RohcParsingError> {
    let profile_id = reader.read_u8_or_err(ParseContext::IrPacketStaticChain)?;
    if profile_id != u8::from(RohcProfile::RtpUdpIp) {
        return Err(RohcParsingError::InvalidProfileId(profile_id));
    }
    let ip_src = reader.read_ipv4_addr_or_err(ParseContext::IrPacketStaticChain)?;
    let ip_dst = reader.read_ipv4_addr_or_err(ParseContext::IrPacketStaticChain)?;
    let udp_src_port = reader.read_u16_be_or_err(ParseContext::IrPacketStaticChain)?;
    let udp_dst_port = reader.read_u16_be_or_err(ParseContext::IrPacketStaticChain)?;
    let ssrc = Ssrc::new(reader.read_u32_be_or_err(ParseContext::IrPacketStaticChain)?);
    let payload_type = reader.read_u8_or_err(ParseContext::IrPacketStaticChain)?;
    let extension = reader.read_u8_or_err(ParseContext::IrPacketStaticChain)? == 1;
    let padding = reader.read_u8_or_err(ParseContext::IrPacketStaticChain)? == 1;
    Ok((
        profile_id,
        ip_src,
        ip_dst,
        udp_src_port,
        udp_dst_port,
        ssrc,
        payload_type,
        extension,
        padding,
    ))
}

fn deserialize_dynamic_chain(
    reader: &mut PacketReader,
) -> Result<(DynamicChainData, Option<u32>), RohcParsingError> {
    let sn = SequenceNumber::new(reader.read_u16_be_or_err(ParseContext::IrPacketDynamicChain)?);
    let ts = Timestamp::new(reader.read_u32_be_or_err(ParseContext::IrPacketDynamicChain)?);
    let ttl = reader.read_u8_or_err(ParseContext::IrPacketDynamicChain)?;
    let ip_id = reader
        .read_u16_be_or_err(ParseContext::IrPacketDynamicChain)?
        .into();
    let rtp_flags = reader.read_u8_or_err(ParseContext::IrPacketDynamicChain)?;

    let marker = (rtp_flags & P1_IR_DYN_RTP_FLAGS_MARKER_BIT_MASK) != 0;
    let ts_stride_present = (rtp_flags & P1_IR_DYN_RTP_FLAGS_TS_STRIDE_BIT_MASK) != 0;

    let ts_stride = if ts_stride_present {
        Some(reader.read_u32_be_or_err(ParseContext::IrPacketTsStrideExtension)?)
    } else {
        None
    };

    Ok(((sn, ts, marker, ttl, ip_id), ts_stride))
}

// A minimal, safe packet writer for controlled serialization.
struct PacketWriter<'a> {
    buf: &'a mut [u8],
    offset: usize,
}

impl<'a> PacketWriter<'a> {
    fn new(buf: &'a mut [u8]) -> Self {
        Self { buf, offset: 0 }
    }

    fn offset(&self) -> usize {
        self.offset
    }

    fn write_u8(&mut self, val: u8) {
        self.write_slice(&[val]);
    }

    fn write_u16_be(&mut self, val: u16) {
        self.write_slice(&val.to_be_bytes());
    }

    fn write_u32_be(&mut self, val: u32) {
        self.write_slice(&val.to_be_bytes());
    }

    fn write_slice(&mut self, slice: &[u8]) {
        let len = slice.len();
        debug_assert!(self.offset + len <= self.buf.len(), "PacketWriter overflow");
        self.buf[self.offset..self.offset + len].copy_from_slice(slice);
        self.offset += len;
    }
}

// A minimal, safe packet reader for controlled deserialization.
struct PacketReader<'a> {
    buf: &'a [u8],
    offset: usize,
}
impl<'a> PacketReader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, offset: 0 }
    }

    fn len(&self) -> usize {
        self.buf.len()
    }

    fn read_u8(&mut self) -> Option<u8> {
        self.read_slice(1).map(|s| s[0])
    }

    fn read_slice(&mut self, len: usize) -> Option<&'a [u8]> {
        if self.offset + len > self.buf.len() {
            return None;
        }
        let slice = &self.buf[self.offset..self.offset + len];
        self.offset += len;
        Some(slice)
    }

    // Helper to map Option to RohcParsingError for cleaner code.
    fn read_u8_or_err(&mut self, context: ParseContext) -> Result<u8, RohcParsingError> {
        self.read_u8().ok_or(RohcParsingError::NotEnoughData {
            needed: self.offset + 1,
            got: self.len(),
            context,
        })
    }

    fn read_u16_be_or_err(&mut self, context: ParseContext) -> Result<u16, RohcParsingError> {
        self.read_slice(2)
            .map(|s| u16::from_be_bytes(s.try_into().unwrap()))
            .ok_or(RohcParsingError::NotEnoughData {
                needed: self.offset + 2,
                got: self.len(),
                context,
            })
    }

    fn read_u32_be_or_err(&mut self, context: ParseContext) -> Result<u32, RohcParsingError> {
        self.read_slice(4)
            .map(|s| u32::from_be_bytes(s.try_into().unwrap()))
            .ok_or(RohcParsingError::NotEnoughData {
                needed: self.offset + 4,
                got: self.len(),
                context,
            })
    }

    fn read_ipv4_addr_or_err(
        &mut self,
        context: ParseContext,
    ) -> Result<Ipv4Addr, RohcParsingError> {
        self.read_slice(4)
            .map(|s| Ipv4Addr::new(s[0], s[1], s[2], s[3]))
            .ok_or(RohcParsingError::NotEnoughData {
                needed: self.offset + 4,
                got: self.len(),
                context,
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crc::CrcCalculators;

    fn default_ir_packet() -> IrPacket {
        IrPacket {
            cid: 1.into(),
            profile_id: RohcProfile::RtpUdpIp,
            static_ip_src: Ipv4Addr::new(192, 168, 1, 1),
            static_ip_dst: Ipv4Addr::new(192, 168, 1, 2),
            static_udp_src_port: 1000,
            static_udp_dst_port: 2000,
            static_rtp_ssrc: Ssrc::new(0xDEADBEEF),
            static_rtp_payload_type: 96,
            dyn_rtp_sn: 12345.into(),
            dyn_rtp_timestamp: 54321.into(),
            dyn_ip_ttl: 64,
            dyn_ip_id: 1.into(),
            ..Default::default()
        }
    }

    #[test]
    fn p1_ir_roundtrip_no_extensions() {
        let crc = CrcCalculators::new();
        let mut ir = default_ir_packet();
        let mut buf = [0u8; 256];

        let len = serialize_ir(&ir, &crc, &mut buf).unwrap();
        let parsed = deserialize_ir(&buf[1..len], 1.into(), &crc).unwrap();

        // Set the expected crc to the one that was actually calculated and parsed.
        ir.crc8 = parsed.crc8;

        assert_eq!(ir, parsed);
    }

    #[test]
    fn p1_ir_roundtrip_with_ts_stride() {
        let crc = CrcCalculators::new();
        let mut ir = default_ir_packet();
        ir.ts_stride = Some(160);
        ir.dyn_rtp_marker = true;

        let mut buf = [0u8; 256];
        let len = serialize_ir(&ir, &crc, &mut buf).unwrap();
        let parsed = deserialize_ir(&buf[1..len], 1.into(), &crc).unwrap();

        // Set the expected crc to the one that was actually calculated and parsed.
        ir.crc8 = parsed.crc8;

        assert_eq!(ir, parsed);
    }

    #[test]
    fn serialize_deserialize_static_chain_roundtrip() {
        let ir = default_ir_packet();
        let mut write_buf = [0u8; 100];
        let bytes_written;

        {
            let mut writer = PacketWriter::new(&mut write_buf);
            serialize_static_chain(&ir, &mut writer);
            bytes_written = writer.offset();
        }

        let mut reader = PacketReader::new(&write_buf[..bytes_written]);
        let (p, src, _dst, _sp, _dp, ssrc, _pt, ext, _pad) =
            deserialize_static_chain(&mut reader).unwrap();

        assert_eq!(p, u8::from(ir.profile_id));
        assert_eq!(src, ir.static_ip_src);
        assert_eq!(ssrc, ir.static_rtp_ssrc);
        assert_eq!(ext, ir.static_rtp_extension);
    }

    #[test]
    fn serialize_deserialize_dynamic_chain_roundtrip() {
        let ir = default_ir_packet();
        let mut write_buf = [0u8; 100];
        let bytes_written;

        {
            let mut writer = PacketWriter::new(&mut write_buf);
            serialize_dynamic_chain(&ir, &mut writer);
            bytes_written = writer.offset();
        }

        let mut reader = PacketReader::new(&write_buf[..bytes_written]);
        let ((sn, ts, m, _ttl, _id), stride) = deserialize_dynamic_chain(&mut reader).unwrap();

        assert_eq!(sn, ir.dyn_rtp_sn);
        assert_eq!(ts, ir.dyn_rtp_timestamp);
        assert_eq!(m, ir.dyn_rtp_marker);
        assert_eq!(stride, ir.ts_stride);
    }

    #[test]
    fn crc_validation_detects_mismatch() {
        let crc = CrcCalculators::new();
        let ir = default_ir_packet();
        let mut buf = [0u8; 256];
        let len = serialize_ir(&ir, &crc, &mut buf).unwrap();

        // Corrupt the CRC byte
        buf[len - 1] = !buf[len - 1];

        let result = deserialize_ir(&buf[1..len], 1.into(), &crc);
        assert!(matches!(result, Err(RohcParsingError::CrcMismatch { .. })));
    }
}
