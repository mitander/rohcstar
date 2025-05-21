use crc::{CRC_3_ROHC, CRC_8_ROHC, Crc};

/// Calculates the 8-bit ROHC CRC (CRC-8/ROHC) for the given data.
///
/// This CRC is defined in RFC 3095, Section 5.9.1.
/// It uses the polynomial `x^8 + x^2 + x^1 + 1` (0x107, which is 0x07 reversed without high bit).
/// The initial value is 0xFF, and it's non-reflected.
///
/// # Arguments
/// * `data`: A byte slice containing the data over which the CRC is computed.
///
/// # Returns
/// The 8-bit CRC value.
pub fn calculate_rohc_crc8(data: &[u8]) -> u8 {
    // The Crc object can be created once and reused if performance is critical,
    // but for clarity and typical ROHC packet rates, creating it per call is acceptable.
    let crc_calculator = Crc::<u8>::new(&CRC_8_ROHC);
    crc_calculator.checksum(data)
}

/// Calculates the 3-bit ROHC CRC (CRC-3/ROHC) for the given data.
///
/// This CRC is defined in RFC 3095, Section 5.9.2.
/// It uses the polynomial `x^3 + x^1 + 1` (0x0B, which is 0x3 reversed without high bit).
/// The initial value is 0x07, and it's non-reflected. The result is the 3 LSBs.
///
/// # Arguments
/// * `data`: A byte slice containing the data over which the CRC is computed.
///
/// # Returns
/// The 3-bit CRC value (masked to fit in `u8`, effectively `0x00` to `0x07`).
pub fn calculate_rohc_crc3(data: &[u8]) -> u8 {
    let crc_calculator = Crc::<u8>::new(&CRC_3_ROHC);
    crc_calculator.checksum(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rohc_crc8_calculation_standard_input() {
        let data = b"123456789";
        // As per crc crate's CRC_8_ROHC preset, this is the expected value.
        // Online calculators might give different results for "CRC-8" if they don't match
        // ROHC's specific parameters (poly 0x07, init 0xFF, non-reflected).
        let expected_crc = 0xD0;
        let calculated_crc = calculate_rohc_crc8(data);
        assert_eq!(
            calculated_crc, expected_crc,
            "CRC-8 mismatch for '123456789'. Expected ROHC-specific 0xD0."
        );

        // Verify against the crc crate's built-in check value for CRC_8_ROHC.
        let crc_instance_8 = Crc::<u8>::new(&CRC_8_ROHC);
        assert_eq!(
            crc_instance_8.checksum(b"123456789"),
            CRC_8_ROHC.check, // This check value is 0xD0 for "123456789"
            "Crate's CRC_8_ROHC preset check value (0xD0) does not match direct calculation for '123456789'."
        );
    }

    #[test]
    fn rohc_crc3_calculation_standard_input() {
        let data = b"123456789";
        // For CRC-3/ROHC (poly 0x3, init 0x7, non-reflected), "123456789" yields 0x06.
        let expected_crc = 0x06;
        let calculated_crc = calculate_rohc_crc3(data);
        assert_eq!(
            calculated_crc, expected_crc,
            "CRC-3 mismatch for '123456789'. Expected ROHC-specific 0x06."
        );

        // The crc crate's CRC_3_ROHC.check value is 0x04 for "123456789".
        // This seems to be a discrepancy if ROHC standard indeed expects 0x06 for "123456789".
        // Test against the known ROHC expectation for "123456789" -> 0x06.
        let crc_instance_3 = Crc::<u8>::new(&CRC_3_ROHC);
        let actual_calc_for_123456789 = crc_instance_3.checksum(b"123456789");

        if actual_calc_for_123456789 != expected_crc {
            eprintln!(
                "Note: Calculated CRC-3 for '123456789' is 0x{:02X}, but expected 0x{:02X} based on common ROHC examples. The crc crate's CRC_3_ROHC.check is 0x{:02X}.",
                actual_calc_for_123456789, expected_crc, CRC_3_ROHC.check
            );
        }
        assert_eq!(
            actual_calc_for_123456789, expected_crc,
            "CRC_3_ROHC calculation for '123456789' by crate preset (0x{:02X}) is not the expected ROHC value 0x06.",
            actual_calc_for_123456789
        );
    }

    #[test]
    fn rohc_crc8_rfc3095_example_empty_input() {
        // RFC 3095, Section 5.9.1: "The ROHC CRC-8 is calculated over all octets of the
        // ROHC packet following the CID or Add-CID field (if present) up to and
        // including the last octet before the CRC field itself. Initial value for
        // calculation is 0xFF." An empty input (0 bytes) should result in 0xFF.
        let data = b"";
        let expected_crc = 0xFF;
        let calculated_crc = calculate_rohc_crc8(data);
        assert_eq!(
            calculated_crc, expected_crc,
            "CRC-8 mismatch for empty data; expected 0xFF"
        );
    }

    #[test]
    fn rohc_crc3_rfc3095_example_empty_input() {
        // RFC 3095, Section 5.9.2: "The ROHC CRC-3 is calculated over all octets
        // of the ROHC packet following the CID or Add-CID field (if present) up
        // to and including the last octet before the CRC field itself. Initial
        // value for calculation is 0x7." An empty input should result in 0x07.
        let data = b"";
        let expected_crc = 0x07;
        let calculated_crc = calculate_rohc_crc3(data);
        assert_eq!(
            calculated_crc, expected_crc,
            "CRC-3 mismatch for empty data; expected 0x07"
        );
    }

    #[test]
    fn rohc_crc8_single_byte_input() {
        let data_zero = b"\x00"; // Single byte: 0
        let expected_crc_zero = 0xCF; // CRC-8/ROHC of 0x00 is 0xCF
        let calculated_crc_zero = calculate_rohc_crc8(data_zero);
        assert_eq!(
            calculated_crc_zero, expected_crc_zero,
            "CRC-8 mismatch for single zero byte"
        );

        let data_5a = b"\x5A"; // Single byte: 0x5A
        let expected_crc_5a = 0x4E; // CRC-8/ROHC of 0x5A is 0x4E
        let calculated_crc_5a = calculate_rohc_crc8(data_5a);
        assert_eq!(
            calculated_crc_5a, expected_crc_5a,
            "CRC-8 mismatch for 0x5A"
        );
    }

    #[test]
    fn rohc_crc3_single_byte_input() {
        let data_zero = b"\x00"; // Single byte: 0
        let expected_crc_zero = 0x05; // CRC-3/ROHC of 0x00 is 0x05
        let calculated_crc_zero = calculate_rohc_crc3(data_zero);
        assert_eq!(
            calculated_crc_zero, expected_crc_zero,
            "CRC-3 mismatch for single zero byte"
        );

        let data_5a = b"\x5A"; // Single byte: 0x5A
        let expected_crc_5a = 0x06; // CRC-3/ROHC of 0x5A is 0x06
        let calculated_crc_5a = calculate_rohc_crc3(data_5a);
        assert_eq!(
            calculated_crc_5a, expected_crc_5a,
            "CRC-3 mismatch for 0x5A"
        );
    }
}
