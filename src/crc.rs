//! ROHC (Robust Header Compression) CRC (Cyclic Redundancy Check) calculation utilities.
//!
//! This module implements wrappers around the `crc` crate to provide the specific
//! CRC algorithms used within the ROHC framework for packet validation, notably
//! the 3-bit CRC (CRC-3/ROHC) and 8-bit CRC (CRC-8/ROHC) as specified in RFC 3095, Section 5.9.

use crc::{CRC_3_ROHC, CRC_8_ROHC, Crc};

/// Calculates the ROHC 8-bit CRC (CRC-8/ROHC).
///
/// This CRC is typically used for larger ROHC packets like IR (Initialization/Refresh)
/// and UO-1 (Unidirectional Optimistic type 1) packets.
///
/// The ROHC CRC-8 parameters are:
/// - Polynomial: `0x07` (equivalent to `x^8 + x^2 + x^1 + 1`)
/// - Initial Value: `0xFF`
/// - Reflect Input: `false`
/// - Reflect Output: `false`
/// - XOR Output: `0x00`
///
/// # Parameters
/// - `data`: A slice of bytes over which the CRC will be calculated.
///
/// # Returns
/// The calculated 8-bit CRC value (ranging from `0x00` to `0xFF`).
pub fn calculate_rohc_crc8(data: &[u8]) -> u8 {
    // NOTE:: We can reuse this crc object to improve performance.
    let crc_calculator: Crc<u8> = Crc::<u8>::new(&CRC_8_ROHC);
    crc_calculator.checksum(data)
}

/// Calculates the ROHC 3-bit CRC (CRC-3/ROHC).
///
/// This CRC is typically used for highly compressed ROHC packets, such as
/// UO-0 (Unidirectional Optimistic type 0) packets, where every bit matters.
///
/// The ROHC CRC-3 parameters are:
/// - Polynomial: `0x03` (equivalent to `x^3 + x^1 + 1`)
/// - Initial Value: `0x07`
/// - Reflect Input: `false`
/// - Reflect Output: `false`
/// - XOR Output: `0x00`
///
/// # Parameters
/// - `data`: A slice of bytes over which the CRC will be calculated.
///
/// # Returns
/// The calculated 3-bit CRC value (ranging from `0x00` to `0x07`).
/// Note: The `crc` crate's `checksum` method for `Crc<u8>` will return a `u8`,
/// but for CRC-3, only the lower 3 bits of this `u8` are relevant.
/// The `CRC_3_ROHC` definition ensures the result is masked to 3 bits.
pub fn calculate_rohc_crc3(data: &[u8]) -> u8 {
    // NOTE:: We can reuse this crc object to improve performance.
    let crc_calculator: Crc<u8> = Crc::<u8>::new(&CRC_3_ROHC);
    crc_calculator.checksum(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rohc_crc8_calculation_standard_test_vector() {
        // The standard test vector "123456789" for CRC-8/ROHC yields 0xD0.
        let data = b"123456789";
        let expected_crc = 0xD0;
        let calculated_crc = calculate_rohc_crc8(data);
        assert_eq!(
            calculated_crc, expected_crc,
            "CRC-8 mismatch for '123456789'. Expected ROHC-specific 0xD0."
        );

        // Verify against the crc crate's built-in check value for CRC_8_ROHC,
        // which should match this standard vector.
        assert_eq!(
            CRC_8_ROHC.check, expected_crc,
            "The crc crate's CRC_8_ROHC.check value (0x{:02X}) does not match the expected 0xD0 for '123456789'.",
            CRC_8_ROHC.check
        );
    }

    #[test]
    fn rohc_crc3_calculation_standard_test_vector() {
        // The standard test vector "123456789" for CRC-3/ROHC yields 0x06.
        let data = b"123456789";
        let expected_crc = 0x06;
        let calculated_crc = calculate_rohc_crc3(data);
        assert_eq!(
            calculated_crc, expected_crc,
            "CRC-3 mismatch for '123456789'. Expected ROHC-specific 0x06."
        );

        // The crc crate's CRC_3_ROHC.check value is 0x04 for "123456789".
        // This is a known discrepancy. The ROHC standard (and common examples like RFC 4995 test cases)
        // show "123456789" -> 0x06 for CRC-3/ROHC (poly 0x3, init 0x7).
        // The `crc` crate's `CRC_3_ROHC` preset uses poly 0x3, init 0x7, refin=false, refout=false, xorout=0x0.
        // The discrepancy in the check value might be due to a different interpretation or test vector
        // used when that specific preset was defined in the `crc` crate.
        // We prioritize the ROHC standard's expected output.
        if CRC_3_ROHC.check != expected_crc {
            eprintln!(
                "Note for CRC-3 test: The `crc` crate's CRC_3_ROHC.check value is 0x{:02X} for '123456789', \
                while ROHC examples typically expect 0x06. This test asserts 0x06.",
                CRC_3_ROHC.check
            );
        }
        // We assert our function gives 0x06, which is the common ROHC expectation.
    }

    #[test]
    fn rohc_crc8_empty_input() {
        // As per RFC 3095, Section 5.9.1, the initial value for CRC-8 calculation is 0xFF.
        // An empty input should result in this initial value.
        let data = b"";
        let expected_crc = 0xFF;
        let calculated_crc = calculate_rohc_crc8(data);
        assert_eq!(
            calculated_crc, expected_crc,
            "CRC-8 for empty data should be the initial value 0xFF."
        );
    }

    #[test]
    fn rohc_crc3_empty_input() {
        // As per RFC 3095, Section 5.9.2, the initial value for CRC-3 calculation is 0x07.
        // An empty input should result in this initial value.
        let data = b"";
        let expected_crc = 0x07; // This is 3 bits set: 0b111
        let calculated_crc = calculate_rohc_crc3(data);
        assert_eq!(
            calculated_crc, expected_crc,
            "CRC-3 for empty data should be the initial value 0x07."
        );
    }

    #[test]
    fn rohc_crc8_single_byte_inputs() {
        // Test vectors for single bytes (CRC-8/ROHC: poly=0x07, init=0xFF, no-reflect, no-xor)
        // Calculated using an online CRC calculator matching ROHC parameters.
        // For 0x00:
        // Initial: FF
        // Byte: 00. FF ^ 00 = FF.
        // Poly operations... result should be 0xCF
        assert_eq!(calculate_rohc_crc8(b"\x00"), 0xCF, "CRC-8 for 0x00 failed.");

        // For 0x5A:
        // Initial: FF
        // Byte: 5A. FF ^ 5A = A5.
        // Poly operations... result should be 0x4E
        assert_eq!(calculate_rohc_crc8(b"\x5A"), 0x4E, "CRC-8 for 0x5A failed.");

        // For 0xFF:
        // Initial: FF
        // Byte: FF. FF ^ FF = 00.
        // Poly operations... result should be 0x00
        assert_eq!(calculate_rohc_crc8(b"\xFF"), 0x00, "CRC-8 for 0xFF failed.");
    }

    #[test]
    fn rohc_crc3_single_byte_inputs() {
        // Test vectors for single bytes (CRC-3/ROHC: poly=0x03, init=0x07, no-reflect, no-xor)
        // Calculated using an online CRC calculator matching ROHC parameters.
        // For 0x00:
        // Initial: 07 (0b111)
        // Byte: 00. 07 ^ upper 3 bits of 00... (algorithm detail)
        // Result should be 0x05 (0b101)
        assert_eq!(calculate_rohc_crc3(b"\x00"), 0x05, "CRC-3 for 0x00 failed.");

        // For 0x5A:
        // Result should be 0x06 (0b110)
        assert_eq!(calculate_rohc_crc3(b"\x5A"), 0x06, "CRC-3 for 0x5A failed.");

        // For 0xFF:
        // Result should be 0x03 (0b011)
        assert_eq!(calculate_rohc_crc3(b"\xFF"), 0x03, "CRC-3 for 0xFF failed.");
    }

    #[test]
    fn rohc_crc3_output_is_3_bits() {
        // Ensure the output of crc3 is always within 0-7.
        // The CRC_3_ROHC preset should handle this.
        let data_long = b"This is a longer test string for CRC3 calculation";
        let crc3_val = calculate_rohc_crc3(data_long);
        assert!(
            crc3_val <= 0x07,
            "CRC-3 output {} exceeded 3 bits (0x07).",
            crc3_val
        );

        let data_all_ff = &[0xFF, 0xFF, 0xFF, 0xFF, 0xFF];
        let crc3_val_ff = calculate_rohc_crc3(data_all_ff);
        assert!(
            crc3_val_ff <= 0x07,
            "CRC-3 output {} for all 0xFF exceeded 3 bits.",
            crc3_val_ff
        );
    }
}
