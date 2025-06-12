//! Property-based tests for ROHC core functionality.
//!
//! Uses QuickCheck to generate random test cases that verify invariants and properties
//! of LSB encoding/decoding, CRC operations, and context state machine behavior.

use quickcheck::TestResult;
use quickcheck_macros::quickcheck as qc_quickcheck;
use rohcstar::crc::{calculate_rohc_crc3, calculate_rohc_crc8};
use rohcstar::encodings::{decode_lsb, encode_lsb, is_value_in_lsb_interval};

/// Property: LSB encoding/decoding roundtrip preserves values within the interpretation window.
///
/// For any value within the W-LSB interpretation window, encoding followed by decoding
/// must reconstruct the original value exactly.
#[qc_quickcheck]
fn p1_lsb_encoding_roundtrip_preserves_values(value: u16, reference: u16) -> TestResult {
    let k = 8; // Start with fixed k=8 for broader window
    let p_offset = 0; // Standard case with p=0

    // Check if value is within interpretation window
    if !is_value_in_lsb_interval(value as u64, reference as u64, k, p_offset) {
        return TestResult::discard(); // Skip values outside window
    }

    // Property test: encode then decode should preserve the value
    let encoded = match encode_lsb(value as u64, k) {
        Ok(encoded) => encoded,
        Err(_) => return TestResult::failed(), // Encoding should never fail for valid inputs
    };

    let decoded = match decode_lsb(encoded, reference as u64, k, p_offset) {
        Ok(decoded) => decoded as u16,
        Err(_) => return TestResult::failed(), // Decoding should never fail for valid inputs
    };

    TestResult::from_bool(decoded == value)
}

/// Property: LSB encoding always produces values that fit in k bits.
#[qc_quickcheck]
fn p1_lsb_encoding_output_fits_k_bits(value: u64, k: u8) -> TestResult {
    if k == 0 || k > 64 {
        return TestResult::discard(); // Invalid k values
    }

    let encoded = match encode_lsb(value, k) {
        Ok(encoded) => encoded,
        Err(_) => return TestResult::failed(),
    };

    // Property: encoded value must fit in k bits
    let max_value = if k == 64 { u64::MAX } else { (1u64 << k) - 1 };
    TestResult::from_bool(encoded <= max_value)
}

/// Property: LSB decoding is deterministic for valid inputs.
#[qc_quickcheck]
fn p1_lsb_decoding_deterministic_results(received_lsbs: u8, reference: u16, k: u8) -> TestResult {
    if k == 0 || k >= 64 {
        return TestResult::discard(); // Invalid k values
    }

    let max_lsb_value = if k >= 8 { 255u8 } else { (1u8 << k) - 1 };
    if received_lsbs > max_lsb_value {
        return TestResult::discard(); // LSB value too large for k bits
    }

    let p_offset = 0;
    let result1 = decode_lsb(received_lsbs as u64, reference as u64, k, p_offset);
    let result2 = decode_lsb(received_lsbs as u64, reference as u64, k, p_offset);

    TestResult::from_bool(result1 == result2)
}

/// Property: Window-based interpretation is consistent.
///
/// If a value is reported as being in the interpretation window,
/// then decoding its LSBs should reconstruct that value.
#[qc_quickcheck]
fn p1_lsb_window_interpretation_consistent(value: u16, reference: u16, k: u8) -> TestResult {
    if k == 0 || k >= 64 {
        return TestResult::discard();
    }

    let p_offset = 0;

    // If value is in window, then encode/decode should preserve it
    if is_value_in_lsb_interval(value as u64, reference as u64, k, p_offset) {
        let encoded = match encode_lsb(value as u64, k) {
            Ok(e) => e,
            Err(_) => return TestResult::failed(),
        };

        let decoded = match decode_lsb(encoded, reference as u64, k, p_offset) {
            Ok(d) => d as u16,
            Err(_) => return TestResult::failed(),
        };

        TestResult::from_bool(decoded == value)
    } else {
        TestResult::discard()
    }
}

/// Property: CRC3 computation is deterministic and bounded.
#[qc_quickcheck]
fn p1_crc3_computation_deterministic_bounded(data: Vec<u8>) -> TestResult {
    if data.len() > 1000 {
        return TestResult::discard(); // Limit test data size
    }

    let crc1 = calculate_rohc_crc3(&data);
    let crc2 = calculate_rohc_crc3(&data);

    // Property 1: Deterministic
    if crc1 != crc2 {
        return TestResult::failed();
    }

    // Property 2: Result is 3-bit value (0-7)
    TestResult::from_bool(crc1 <= 7)
}

/// Property: CRC8 computation is deterministic and bounded.
#[qc_quickcheck]
fn p1_crc8_computation_deterministic_bounded(data: Vec<u8>) -> TestResult {
    if data.len() > 1000 {
        return TestResult::discard(); // Limit test data size
    }

    let crc1 = calculate_rohc_crc8(&data);
    let crc2 = calculate_rohc_crc8(&data);

    // Property 1: Deterministic
    if crc1 != crc2 {
        return TestResult::failed();
    }

    // Property 2: Result is 8-bit value (always true for u8)
    TestResult::passed()
}

/// Property: CRC changes when data changes.
#[qc_quickcheck]
fn p1_crc_computation_changes_with_data(mut data: Vec<u8>) -> TestResult {
    if data.is_empty() || data.len() > 100 {
        return TestResult::discard();
    }

    let original_crc3 = calculate_rohc_crc3(&data);
    let original_crc8 = calculate_rohc_crc8(&data);

    // Flip one bit in the data
    data[0] ^= 0x01;

    let modified_crc3 = calculate_rohc_crc3(&data);
    let modified_crc8 = calculate_rohc_crc8(&data);

    // Property: CRC should change (not guaranteed for all cases, but expected most of the time)
    // Allow some false positives due to CRC collisions
    TestResult::from_bool((original_crc3 != modified_crc3) || (original_crc8 != modified_crc8))
}

/// Property: P-offset shifts the interpretation window as expected.
#[qc_quickcheck]
fn p1_lsb_p_offset_shifts_window_correctly(reference: u16, k: u8, p_offset: i8) -> TestResult {
    if k == 0 || k >= 64 {
        return TestResult::discard();
    }

    let ref_val = reference as u64;
    let p = p_offset as i64;

    // Calculate expected window bounds
    let window_base = if p >= 0 {
        ref_val.wrapping_sub(p as u64)
    } else {
        ref_val.wrapping_add((-p) as u64)
    };

    let window_size = 1u64 << k;

    // Property: Values at window boundaries should be correctly identified
    let in_window_start = is_value_in_lsb_interval(window_base, ref_val, k, p);
    let in_window_end =
        is_value_in_lsb_interval(window_base.wrapping_add(window_size - 1), ref_val, k, p);
    let out_of_window_before = is_value_in_lsb_interval(window_base.wrapping_sub(1), ref_val, k, p);
    let out_of_window_after =
        is_value_in_lsb_interval(window_base.wrapping_add(window_size), ref_val, k, p);

    TestResult::from_bool(
        in_window_start && in_window_end && !out_of_window_before && !out_of_window_after,
    )
}

/// Property: Multiple k values produce consistent hierarchical encoding.
#[qc_quickcheck]
fn p1_lsb_hierarchical_encoding_consistent(value: u32, k1: u8, k2: u8) -> TestResult {
    if k1 == 0 || k1 >= 32 || k2 == 0 || k2 >= 32 || k1 >= k2 {
        return TestResult::discard(); // k1 should be smaller than k2
    }

    let encoded_k1 = match encode_lsb(value as u64, k1) {
        Ok(e) => e,
        Err(_) => return TestResult::failed(),
    };

    let encoded_k2 = match encode_lsb(value as u64, k2) {
        Ok(e) => e,
        Err(_) => return TestResult::failed(),
    };

    // Property: LSBs from smaller k should match lower bits of larger k encoding
    let mask_k1 = (1u64 << k1) - 1;
    TestResult::from_bool((encoded_k2 & mask_k1) == encoded_k1)
}

#[cfg(test)]
mod manual_property_tests {
    use super::*;

    /// Manual property function for LSB roundtrip testing.
    fn test_lsb_roundtrip(value: u16, reference: u16) -> bool {
        let k = 8;
        let p_offset = 0;

        if !is_value_in_lsb_interval(value as u64, reference as u64, k, p_offset) {
            return true; // Skip values outside window
        }

        let encoded = match encode_lsb(value as u64, k) {
            Ok(encoded) => encoded,
            Err(_) => return false,
        };

        let decoded = match decode_lsb(encoded, reference as u64, k, p_offset) {
            Ok(decoded) => decoded as u16,
            Err(_) => return false,
        };

        decoded == value
    }

    /// Manual execution of property tests for deterministic testing.
    #[test]
    fn p1_lsb_encoding_manual_roundtrip_cases() {
        // Test specific edge cases manually
        assert!(
            test_lsb_roundtrip(100, 100),
            "LSB roundtrip failed for (100, 100)"
        );
        assert!(
            test_lsb_roundtrip(105, 100),
            "LSB roundtrip failed for (105, 100)"
        );
        assert!(
            test_lsb_roundtrip(255, 255),
            "LSB roundtrip failed for (255, 255)"
        );
    }

    #[test]
    fn p1_lsb_encoding_manual_bounded_output_cases() {
        // Test encoding bounds manually
        let test_cases = [(0xFFFF_u64, 8_u8), (42, 4), (0, 1), (255, 8)];

        for (value, k) in test_cases {
            if k == 0 || k > 64 {
                continue;
            }

            let encoded = encode_lsb(value, k).unwrap();
            let max_value = if k == 64 { u64::MAX } else { (1u64 << k) - 1 };
            assert!(
                encoded <= max_value,
                "Encoded value {} exceeds max for {} bits",
                encoded,
                k
            );
        }
    }

    #[test]
    fn p1_crc_computation_manual_determinism_cases() {
        // Test CRC determinism and bounds manually
        let test_data = vec![
            vec![1, 2, 3, 4, 5],
            vec![0xFF, 0xAA, 0x55],
            vec![],
            b"test".to_vec(),
        ];

        for data in test_data {
            let crc3_1 = calculate_rohc_crc3(&data);
            let crc3_2 = calculate_rohc_crc3(&data);
            assert_eq!(crc3_1, crc3_2, "CRC3 not deterministic");
            assert!(crc3_1 <= 7, "CRC3 value {} exceeds 3 bits", crc3_1);

            let crc8_1 = calculate_rohc_crc8(&data);
            let crc8_2 = calculate_rohc_crc8(&data);
            assert_eq!(crc8_1, crc8_2, "CRC8 not deterministic");
            // CRC8 is u8, always <= 255
        }
    }

    #[test]
    fn p1_lsb_window_manual_consistency_cases() {
        // Test window properties manually
        let test_cases = [(105_u16, 100_u16, 8_u8), (10, 10, 4), (255, 200, 6)];

        for (value, reference, k) in test_cases {
            if k == 0 || k >= 64 {
                continue;
            }

            let p_offset = 0;
            if is_value_in_lsb_interval(value as u64, reference as u64, k, p_offset) {
                let encoded = encode_lsb(value as u64, k).unwrap();
                let decoded = decode_lsb(encoded, reference as u64, k, p_offset).unwrap() as u16;
                assert_eq!(
                    decoded, value,
                    "Window consistency failed for value={}, ref={}, k={}",
                    value, reference, k
                );
            }
        }
    }
}
