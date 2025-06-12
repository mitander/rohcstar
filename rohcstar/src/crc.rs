//! ROHC (Robust Header Compression) CRC (Cyclic Redundancy Check) calculation utilities.
//!
//! This module implements wrappers around the `crc` crate to provide the specific
//! CRC algorithms used within the ROHC framework for packet validation, notably
//! the 3-bit CRC (CRC-3/ROHC) and 8-bit CRC (CRC-8/ROHC) as specified in RFC 3095, Section 5.9.
//! It also provides a `CrcCalculators` struct for convenient reuse of CRC algorithm instances.

use crc::{CRC_3_ROHC, CRC_8_ROHC, Crc};
use std::fmt;

/// A struct holding pre-initialized CRC algorithm instances for ROHC.
///
/// This is intended for reuse to avoid re-creating `Crc<u8>` instances
/// repeatedly, which can offer a minor performance benefit in high-throughput scenarios.
pub struct CrcCalculators {
    crc3_calculator: Crc<u8>,
    crc8_calculator: Crc<u8>,
}

impl fmt::Debug for CrcCalculators {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CrcCalculators")
            .field("crc3_calculator", &format_args!("Crc<u8>(ROHC_CRC3_Algo)"))
            .field("crc8_calculator", &format_args!("Crc<u8>(ROHC_CRC8_Algo)"))
            .finish()
    }
}

impl CrcCalculators {
    /// Creates a new `CrcCalculators` instance, initializing the ROHC CRC-3 and CRC-8 algorithms.
    ///
    /// # Returns
    /// A new `CrcCalculators` instance with pre-initialized CRC algorithm instances.
    pub fn new() -> Self {
        Self {
            crc3_calculator: Crc::<u8>::new(&CRC_3_ROHC),
            crc8_calculator: Crc::<u8>::new(&CRC_8_ROHC),
        }
    }

    /// Calculates the ROHC 3-bit CRC (CRC-3/ROHC) using the pre-initialized instance.
    ///
    /// # Parameters
    /// - `input`: A slice of bytes over which the CRC will be calculated.
    ///
    /// # Returns
    /// The calculated 3-bit CRC value (ranging from `0x00` to `0x07`).
    #[inline]
    pub fn crc3(&self, input: &[u8]) -> u8 {
        self.crc3_calculator.checksum(input)
    }

    /// Calculates the ROHC 8-bit CRC (CRC-8/ROHC) using the pre-initialized instance.
    ///
    /// # Parameters
    /// - `input`: A slice of bytes over which the CRC will be calculated.
    ///
    /// # Returns
    /// The calculated 8-bit CRC value (ranging from `0x00` to `0xFF`).
    #[inline]
    pub fn crc8(&self, input: &[u8]) -> u8 {
        self.crc8_calculator.checksum(input)
    }
}

impl Default for CrcCalculators {
    /// Creates a default `CrcCalculators` instance.
    fn default() -> Self {
        Self::new()
    }
}

/// Calculates the ROHC 8-bit CRC (CRC-8/ROHC) directly.
///
/// This function creates a new `Crc<u8>` instance on each call. For frequent calculations
/// within a single context (like Profile1Handler), using `CrcCalculators` is preferred.
///
/// The ROHC CRC-8 parameters are:
/// - Polynomial: `0x07` (equivalent to `x^8 + x^2 + x^1 + 1`)
/// - Initial Value: `0xFF`
/// - Reflect Input: `false`
/// - Reflect Output: `false`
/// - XOR Output: `0x00`
///
/// # Parameters
/// - `input`: A slice of bytes over which the CRC will be calculated.
///
/// # Returns
/// The calculated 8-bit CRC value (0x00 to 0xFF).
pub fn calculate_rohc_crc8(input: &[u8]) -> u8 {
    let crc_calc: Crc<u8> = Crc::<u8>::new(&CRC_8_ROHC);
    crc_calc.checksum(input)
}

/// Calculates the ROHC 3-bit CRC (CRC-3/ROHC) directly.
///
/// This function creates a new `Crc<u8>` instance on each call.
///
/// The ROHC CRC-3 parameters are:
/// - Polynomial: `0x03` (equivalent to `x^3 + x^1 + 1`)
/// - Initial Value: `0x07`
/// - Reflect Input: `false`
/// - Reflect Output: `false`
/// - XOR Output: `0x00`
///
/// # Parameters
/// - `input`: A slice of bytes over which the CRC will be calculated.
///
/// # Returns
/// The calculated 3-bit CRC value (ranging from `0x00` to `0x07`).
pub fn calculate_rohc_crc3(input: &[u8]) -> u8 {
    let crc_calc: Crc<u8> = Crc::<u8>::new(&CRC_3_ROHC);
    crc_calc.checksum(input)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crc_calculators_debug_format() {
        let calculators = CrcCalculators::new();
        let debug_str = format!("{:?}", calculators);
        assert!(debug_str.contains("CrcCalculators"));
        assert!(debug_str.contains("crc3_calculator: Crc<u8>(ROHC_CRC3_Algo)"));
        assert!(debug_str.contains("crc8_calculator: Crc<u8>(ROHC_CRC8_Algo)"));
    }

    #[test]
    fn crc_calculators_rohc_crc8_standard_test_vector() {
        let calculators = CrcCalculators::new();
        let data = b"123456789";
        let expected_crc = 0xD0;
        let calculated_crc = calculators.crc8(data);
        assert_eq!(
            calculated_crc, expected_crc,
            "CrcCalculators: CRC-8 mismatch for '123456789'. Expected ROHC-specific 0xD0."
        );
        assert_eq!(CRC_8_ROHC.check, expected_crc);
    }

    #[test]
    fn crc_calculators_rohc_crc3_standard_test_vector() {
        let calculators = CrcCalculators::new();
        let data = b"123456789";
        let expected_crc = 0x06;
        let calculated_crc = calculators.crc3(data);
        assert_eq!(
            calculated_crc, expected_crc,
            "CrcCalculators: CRC-3 mismatch for '123456789'. Expected ROHC-specific 0x06."
        );
    }

    #[test]
    fn direct_rohc_crc8_calculation_standard_test_vector() {
        let data = b"123456789";
        let expected_crc = 0xD0;
        let calculated_crc = calculate_rohc_crc8(data);
        assert_eq!(
            calculated_crc, expected_crc,
            "Direct CRC-8 mismatch for '123456789'. Expected ROHC-specific 0xD0."
        );
        assert_eq!(CRC_8_ROHC.check, expected_crc);
    }

    #[test]
    fn direct_rohc_crc3_calculation_standard_test_vector() {
        let data = b"123456789";
        let expected_crc = 0x06;
        let calculated_crc = calculate_rohc_crc3(data);
        assert_eq!(
            calculated_crc, expected_crc,
            "Direct CRC-3 mismatch for '123456789'. Expected ROHC-specific 0x06."
        );
        if CRC_3_ROHC.check != expected_crc {
            eprintln!(
                "Note for direct CRC-3 test: `crc` crate's CRC_3_ROHC.check value (0x{:02X}) differs from ROHC examples (0x06).",
                CRC_3_ROHC.check
            );
        }
    }

    #[test]
    fn direct_rohc_crc8_empty_input() {
        let data = b"";
        let expected_crc = 0xFF;
        let calculated_crc = calculate_rohc_crc8(data);
        assert_eq!(calculated_crc, expected_crc);
    }

    #[test]
    fn direct_rohc_crc3_empty_input() {
        let data = b"";
        let expected_crc = 0x07;
        let calculated_crc = calculate_rohc_crc3(data);
        assert_eq!(calculated_crc, expected_crc);
    }

    #[test]
    fn direct_rohc_crc3_output_is_3_bits() {
        let data_long = b"This is a longer test string for CRC3 calculation";
        let crc3_val = calculate_rohc_crc3(data_long);
        assert!(
            crc3_val <= 0x07,
            "CRC-3 output {} exceeded 3 bits (0x07).",
            crc3_val
        );
    }
}
