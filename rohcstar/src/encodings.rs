//! ROHC (Robust Header Compression) encoding and decoding utilities.
//!
//! This module implements core encoding schemes used in ROHC, primarily focusing on
//! Window-based Least Significant Bits (W-LSB) encoding and decoding as specified
//! in RFC 3095, Section 4.5 and Section 5.3.1. These utilities are designed to be
//! generic and usable by various ROHC profiles.

use crate::error::{Field, RohcParsingError};

/// Determines if a value falls within the W-LSB interpretation window.
///
/// The interpretation window is defined as:
/// `[reference_value - p_offset, reference_value - p_offset + (2^num_lsb_bits) - 1]`
/// All calculations are performed modulo `2^N` where `N` is the bit-width of the value.
pub fn is_value_in_lsb_interval(
    value: u64,
    reference_value: u64,
    num_lsb_bits: u8,
    p_offset: i64,
) -> bool {
    if num_lsb_bits == 0 || num_lsb_bits > 64 {
        return false;
    }
    if num_lsb_bits == 64 {
        // All 64 bits are LSBs, value is fully known
        return true;
    }

    let window_size = 1u64 << num_lsb_bits;

    // Calculate interpretation window: [v_ref - p, v_ref - p + 2^k - 1]
    let interval_base = if p_offset >= 0 {
        reference_value.wrapping_sub(p_offset as u64)
    } else {
        reference_value.wrapping_add((-p_offset) as u64)
    };

    // Check if value is in window: (v - interval_base) mod 2^64 < window_size
    value.wrapping_sub(interval_base) < window_size
}

/// Extracts the N least significant bits from a value for W-LSB encoding.
///
/// # Errors
/// - `RohcParsingError::InvalidLsbOperation` - Invalid `num_lsb_bits` parameter
pub fn encode_lsb(value: u64, num_lsb_bits: u8) -> Result<u64, RohcParsingError> {
    if num_lsb_bits == 0 {
        return Err(RohcParsingError::InvalidLsbOperation {
            field: Field::NumLsbBits,
            description: "Number of LSBs (k) cannot be 0 for encoding.".to_string(),
        });
    }
    if num_lsb_bits > 64 {
        return Err(RohcParsingError::InvalidLsbOperation {
            field: Field::NumLsbBits,
            description: format!(
                "Number of LSBs (k) cannot exceed 64 for u64 LSB encoding, got {}.",
                num_lsb_bits
            ),
        });
    }

    if num_lsb_bits == 64 {
        Ok(value)
    } else {
        let mask = (1u64 << num_lsb_bits) - 1;
        Ok(value & mask)
    }
}

/// Fast path W-LSB decode optimized for UO-0 sequence numbers (4 bits, p=0).
///
/// Eliminates bounds checking and error handling for the most common case in ROHC Profile 1.
#[inline]
pub fn decode_lsb_uo0_sn(received_lsbs: u8, reference_value: u16) -> u16 {
    debug_assert!(
        received_lsbs < 16,
        "Range violation: {} >= 16",
        received_lsbs
    );

    // UO-0 uses 4 bits with p=0, interpretation window is [v_ref, v_ref + 15]
    // Highly optimized for the specific case where k=4, p=0
    let ref_val = reference_value;
    let lsbs = received_lsbs as u16;

    // Align reference to 16-boundary and add LSBs
    let base = ref_val & 0xFFF0; // Clear lower 4 bits (same as (ref_val >> 4) << 4)
    let candidate = base + lsbs;

    // UO-0 window is [v_ref, v_ref + 15]. Choose the candidate in this range.
    // If candidate >= ref_val, it's already in range. Otherwise, add 16.
    if candidate >= ref_val {
        candidate
    } else {
        candidate.wrapping_add(16)
    }
}

/// Reconstructs the original value from its W-LSB encoded representation.
///
/// Finds a candidate value that has the same `k` least significant bits as `received_lsbs`
/// and falls within the W-LSB interpretation window:
/// `[reference_value - p_offset, reference_value - p_offset + (2^k) - 1]`.
///
/// # Errors
/// - `RohcParsingError::InvalidLsbOperation` - Invalid parameters, LSBs too large, or no unique
///   resolution
pub fn decode_lsb(
    received_lsb: u64,
    reference_value: u64,
    num_lsb_bits: u8,
    p_offset: i64,
) -> Result<u64, RohcParsingError> {
    if num_lsb_bits == 0 || num_lsb_bits >= 64 {
        return Err(RohcParsingError::InvalidLsbOperation {
            field: Field::NumLsbBits,
            description: format!(
                "Number of LSBs (k) must be between 1 and 63 for W-LSB decoding, got {}.",
                num_lsb_bits
            ),
        });
    }

    let window_size = 1u64 << num_lsb_bits;
    debug_assert!(window_size > 0, "Invalid window: size must be positive");
    let lsb_mask = window_size - 1;

    // Validate received_lsbs fit in k bits
    if received_lsb > lsb_mask {
        return Err(RohcParsingError::InvalidLsbOperation {
            field: Field::ReceivedLsbs,
            description: format!(
                "Received LSB value {:#x} is too large for {} LSBs (max value {:#x}).",
                received_lsb, num_lsb_bits, lsb_mask
            ),
        });
    }

    let interval_base = if p_offset >= 0 {
        reference_value.wrapping_sub(p_offset as u64)
    } else {
        reference_value.wrapping_add((-p_offset) as u64)
    };

    // RFC 3095 Section 4.5.1: Find v_cand where v_cand % 2^k == received_lsbs
    // and v_cand is in interpretation window
    let mut candidate_v = (interval_base & !lsb_mask).wrapping_add(received_lsb);

    // Ensure candidate >= interval_base
    if candidate_v < interval_base {
        candidate_v = candidate_v.wrapping_add(window_size);
    }

    // Check if candidate is in interpretation window
    if candidate_v.wrapping_sub(interval_base) < window_size {
        Ok(candidate_v)
    } else {
        // Try alternative candidate (wrapping case)
        let alternative_candidate_v = candidate_v.wrapping_sub(window_size);
        if alternative_candidate_v.wrapping_sub(interval_base) < window_size {
            Ok(alternative_candidate_v)
        } else {
            // LSB value cannot be resolved - context drift or synchronization issue
            Err(RohcParsingError::InvalidLsbOperation {
                field: Field::ReceivedLsbs,
                description: format!(
                    "Cannot be uniquely resolved to a value in the interpretation window. LSBs: \
                     {:#x}, ref: {:#x}, k: {}, p: {}. Candidates: ({:#x}, {:#x}). Window base: \
                     {:#x}, Window size: {:#x}.",
                    received_lsb,
                    reference_value,
                    num_lsb_bits,
                    p_offset,
                    candidate_v,
                    alternative_candidate_v,
                    interval_base,
                    window_size
                ),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_lsb_uo0_sn_basic_cases() {
        // Basic case: LSB matches reference exactly
        assert_eq!(decode_lsb_uo0_sn(4, 100), 100);

        // Window wrapping: reference 100, LSB 0 -> should be 112 (100 + 12)
        assert_eq!(decode_lsb_uo0_sn(0, 100), 112);

        // Window boundary: reference 100, LSB 15 -> should be 111 (100 + 11)
        assert_eq!(decode_lsb_uo0_sn(15, 100), 111);

        // Reference at boundary: reference 15, LSB 0 -> should be 16
        assert_eq!(decode_lsb_uo0_sn(0, 15), 16);
    }

    #[test]
    fn decode_lsb_uo0_sn_wraparound_u16() {
        // Test u16 wraparound scenarios
        assert_eq!(decode_lsb_uo0_sn(2, 65535), 2);
        assert_eq!(decode_lsb_uo0_sn(0, 65530), 0); // Wraps to 0
        assert_eq!(decode_lsb_uo0_sn(5, 65530), 5); // Wraps to 5
    }

    #[test]
    fn decode_lsb_uo0_sn_consistency_with_generic() {
        // Verify optimized version matches generic decode_lsb for UO-0 parameters
        for ref_val in [0u16, 100, 1000, 32767, 65535] {
            for lsb in 0u8..16 {
                let optimized = decode_lsb_uo0_sn(lsb, ref_val);
                let generic = decode_lsb(lsb as u64, ref_val as u64, 4, 0).unwrap() as u16;
                assert_eq!(
                    optimized, generic,
                    "Mismatch for ref={}, lsb={}: optimized={}, generic={}",
                    ref_val, lsb, optimized, generic
                );
            }
        }
    }

    #[test]
    fn decode_lsb_uo0_sn_window_properties() {
        // Test interpretation window [v_ref, v_ref + 15] properties
        let ref_val = 1000u16;

        // All LSBs should decode to values in window [1000, 1015]
        for lsb in 0u8..16 {
            let decoded = decode_lsb_uo0_sn(lsb, ref_val);
            assert!(
                decoded >= ref_val && decoded <= ref_val + 15,
                "Decoded value {} outside window [{}, {}] for LSB {}",
                decoded,
                ref_val,
                ref_val + 15,
                lsb
            );
        }
    }

    #[test]
    #[cfg(debug_assertions)]
    #[should_panic]
    fn decode_lsb_uo0_sn_debug_assert_invalid_lsb() {
        // This should panic in debug builds due to debug_assert
        decode_lsb_uo0_sn(16, 100); // LSB > 15 is invalid for 4-bit encoding
    }

    #[test]
    fn encode_lsb_valid_inputs() {
        assert_eq!(encode_lsb(0x1234, 8).unwrap(), 0x34);
        assert_eq!(encode_lsb(0x1234, 4).unwrap(), 0x04);
        assert_eq!(encode_lsb(0xFFFF, 16).unwrap(), 0xFFFF);
        assert_eq!(encode_lsb(u64::MAX, 64).unwrap(), u64::MAX);
        assert_eq!(encode_lsb(0, 1).unwrap(), 0);
    }

    #[test]
    fn encode_lsb_invalid_num_bits() {
        let err_k0 = encode_lsb(0x1234, 0).unwrap_err();
        match err_k0 {
            RohcParsingError::InvalidLsbOperation { field, description } => {
                assert_eq!(field, crate::error::Field::NumLsbBits);
                assert!(description.contains("cannot be 0"));
            }
            _ => panic!("Unexpected error type for k=0: {:?}", err_k0),
        }

        let err_k65 = encode_lsb(0x1234, 65).unwrap_err();
        match err_k65 {
            RohcParsingError::InvalidLsbOperation { field, description } => {
                assert_eq!(field, crate::error::Field::NumLsbBits);
                assert!(description.contains("cannot exceed 64"));
            }
            _ => panic!("Unexpected error type for k=65: {:?}", err_k65),
        }
    }

    #[test]
    fn decode_lsb_p0_basic_no_wrap() {
        // Scenario: p_offset = 0. v_ref=100, k=4. Window [100, 115].
        // For received_lsbs = 0x4 (4), expected decoded value is 100.
        // (100 & !0xF) | 0x4 = 96 | 4 = 100. 100 >= 100. 100.wrapping_sub(100) < 16. OK.
        assert_eq!(decode_lsb(0x4, 100, 4, 0).unwrap(), 100);

        // For received_lsbs = 0x0 (0), expected decoded value is 112.
        // (100 & !0xF) | 0x0 = 96 | 0 = 96. 96 < 100. candidate_v = 96 + 16 = 112.
        // 112.wrapping_sub(100) = 12. 12 < 16. OK.
        assert_eq!(decode_lsb(0x0, 100, 4, 0).unwrap(), 112);

        // For received_lsbs = 0xF (15), expected decoded value is 111.
        // (100 & !0xF) | 0xF = 96 | 15 = 111. 111 >= 100.
        // 111.wrapping_sub(100) = 11. 11 < 16. OK.
        assert_eq!(decode_lsb(0xF, 100, 4, 0).unwrap(), 111);

        // For received_lsbs = 0xA (10), expected decoded value is 106.
        // (100 & !0xF) | 0xA = 96 | 10 = 106. 106 >= 100.
        // 106.wrapping_sub(100) = 6. 6 < 16. OK.
        assert_eq!(decode_lsb(0xA, 100, 4, 0).unwrap(), 106);
    }

    #[test]
    fn decode_lsb_p0_around_reference_candidate_selection() {
        // Scenario: p_offset = 0. v_ref=10, k=4. Window [10, 25].
        // interval_base = 10. lsb_mask = 0xF. window_size = 16.
        // (10 & !0xF) = 0.
        // For received_lsbs = 0xC (12):
        // candidate_v = (0 | 12) = 12. 12 >= 10.
        // 12.wrapping_sub(10) = 2. 2 < 16. OK. => 12
        assert_eq!(decode_lsb(0xC, 10, 4, 0).unwrap(), 12);

        // For received_lsbs = 0x4 (4):
        // candidate_v = (0 | 4) = 4. 4 < 10. candidate_v = 4 + 16 = 20.
        // 20.wrapping_sub(10) = 10. 10 < 16. OK. => 20
        assert_eq!(decode_lsb(0x4, 10, 4, 0).unwrap(), 20);

        // For received_lsbs = 0x9 (9):
        // candidate_v = (0 | 9) = 9. 9 < 10. candidate_v = 9 + 16 = 25.
        // 25.wrapping_sub(10) = 15. 15 < 16. OK. => 25
        assert_eq!(decode_lsb(0x9, 10, 4, 0).unwrap(), 25);
    }

    #[test]
    fn decode_lsb_p_positive_shifts_window_left() {
        // Scenario: p_offset > 0. v_ref=100, k=4, p_offset=2. Window [98, 113].
        // interval_base = 100 - 2 = 98. lsb_mask = 0xF. window_size = 16.
        // (98 & !0xF) = 96.
        // For received_lsbs = 0x3 (3):
        // candidate_v = (96 | 3) = 99. 99 >= 98.
        // 99.wrapping_sub(98) = 1. 1 < 16. OK. => 99
        assert_eq!(decode_lsb(0x3, 100, 4, 2).unwrap(), 99);

        // For received_lsbs = 0x2 (2):
        // candidate_v = (96 | 2) = 98. 98 >= 98.
        // 98.wrapping_sub(98) = 0. 0 < 16. OK. => 98
        assert_eq!(decode_lsb(0x2, 100, 4, 2).unwrap(), 98);

        // For received_lsbs = 0xD (13):
        // candidate_v = (96 | 13) = 109. 109 >= 98.
        // 109.wrapping_sub(98) = 11. 11 < 16. OK. => 109
        assert_eq!(decode_lsb(0xD, 100, 4, 2).unwrap(), 109);

        // For received_lsbs = 0x1 (1):
        // candidate_v = (96 | 1) = 97. 97 < 98. candidate_v = 97 + 16 = 113.
        // 113.wrapping_sub(98) = 15. 15 < 16. OK. => 113
        assert_eq!(decode_lsb(0x1, 100, 4, 2).unwrap(), 113);

        // For received_lsbs = 0x0 (0):
        // candidate_v = (96 | 0) = 96. 96 < 98. candidate_v = 96 + 16 = 112.
        // 112.wrapping_sub(98) = 14. 14 < 16. OK. => 112
        assert_eq!(decode_lsb(0x0, 100, 4, 2).unwrap(), 112);
    }

    #[test]
    fn decode_lsb_p_negative_shifts_window_right() {
        // Scenario: p_offset < 0. v_ref=10, k=3, p_offset=-1. Window [11, 18].
        // interval_base = 10 - (-1) = 11. lsb_mask = 0x7. window_size = 8.
        // (11 & !0x7) = 8.
        // For received_lsbs = 0x3 (3):
        // candidate_v = (8 | 3) = 11. 11 >= 11.
        // 11.wrapping_sub(11) = 0. 0 < 8. OK. => 11
        assert_eq!(decode_lsb(0x3, 10, 3, -1).unwrap(), 11);

        // For received_lsbs = 0x2 (2):
        // candidate_v = (8 | 2) = 10. 10 < 11. candidate_v = 10 + 8 = 18.
        // 18.wrapping_sub(11) = 7. 7 < 8. OK. => 18
        assert_eq!(decode_lsb(0x2, 10, 3, -1).unwrap(), 18);

        // For received_lsbs = 0x7 (7):
        // candidate_v = (8 | 7) = 15. 15 >= 11.
        // 15.wrapping_sub(11) = 4. 4 < 8. OK. => 15
        assert_eq!(decode_lsb(0x7, 10, 3, -1).unwrap(), 15);
    }

    #[test]
    fn decode_lsb_p0_wrapping_around_max_u64() {
        // Test W-LSB decoding with p_offset = 0 when the reference value is near u64::MAX,
        // causing the interpretation window to wrap around 0.
        let k = 4; // Use 4 LSBs
        let lsb_mask = (1u64 << k) - 1; // For k=4, lsb_mask = 15. This is also (2^k - 1).
        let ref_val = u64::MAX - 5; // Reference value: ...FFFB (if k=4, LSBs are 0xB)

        // Case 1: Received LSBs match the LSBs of ref_val itself.
        // Expected: ref_val should be reconstructed.
        assert_eq!(
            decode_lsb(ref_val & lsb_mask, ref_val, k, 0).unwrap(), // LSBs of ref_val are 0xB
            ref_val
        );

        // Case 2: Received LSBs are u64::MAX's LSBs (0xF if k=4).
        // ref_val is u64::MAX - 5.
        // Expected: u64::MAX, as it's the closest value to ref_val with LSBs 0xF.
        assert_eq!(
            decode_lsb(u64::MAX & lsb_mask, ref_val, k, 0).unwrap(), // LSBs of u64::MAX are 0xF
            u64::MAX
        );

        // Case 3: Received LSBs are 0. ref_val is u64::MAX - 5.
        // Expected: 0 (after wrapping), as it's within the window
        // relative to ref_val and matches LSBs.
        assert_eq!(decode_lsb(0, ref_val, k, 0).unwrap(), 0);

        // Case 4: Received LSBs are 3. ref_val is u64::MAX - 5.
        // Expected: 3 (after wrapping).
        assert_eq!(decode_lsb(3, ref_val, k, 0).unwrap(), 3);

        // Case 5: Test the value that has LSBs corresponding to lsb_mask (all 1s for k bits)
        // within the window around ref_val.
        // This should reconstruct to a value ending in 0xF if k=4.
        // For ref_val = u64::MAX - 5 (ends in ...B), window is [u64::MAX - 5, u64::MAX - 5 + 15].
        // The value in this window that ends in F is u64::MAX.
        // If we change the LSBs from 0xB (for MAX-5) to 0xF, we add (0xF - 0xB) = 4.
        // So, (MAX-5) + 4 = MAX - 1.
        // The value in window [ref_val, ref_val + 2^k - 1] that has LSBs `lsb_mask`
        // is ref_val + (lsb_mask - (ref_val & lsb_mask)).
        let upper_val_in_window = ref_val.wrapping_add(lsb_mask - (ref_val & lsb_mask));
        let upper_val_lsb = upper_val_in_window & lsb_mask; // Should be lsb_mask
        assert_eq!(
            upper_val_lsb, lsb_mask,
            "Upper value LSBs should be the lsb_mask itself"
        );
        assert_eq!(
            decode_lsb(upper_val_lsb, ref_val, k, 0).unwrap(),
            upper_val_in_window
        );
    }

    #[test]
    fn decode_lsb_error_invalid_num_bits_combined() {
        let err_k0 = decode_lsb(0x01, 10, 0, 0).unwrap_err();
        match err_k0 {
            RohcParsingError::InvalidLsbOperation { field, description } => {
                assert_eq!(field, crate::error::Field::NumLsbBits);
                assert!(description.contains("between 1 and 63"));
            }
            _ => panic!("Unexpected error type for k=0: {:?}", err_k0),
        }

        let err_k64 = decode_lsb(0x01, 10, 64, 0).unwrap_err();
        match err_k64 {
            RohcParsingError::InvalidLsbOperation { field, description } => {
                assert_eq!(field, crate::error::Field::NumLsbBits);
                assert!(description.contains("between 1 and 63"));
            }
            _ => panic!("Unexpected error type for k=64: {:?}", err_k64),
        }
    }

    #[test]
    fn decode_lsb_error_received_lsbs_too_large_for_k_combined() {
        let err = decode_lsb(0x10, 10, 3, 0).unwrap_err(); // 0x10 (16) is too large for k=3 (max 7)
        match err {
            RohcParsingError::InvalidLsbOperation { field, description } => {
                assert_eq!(field, crate::error::Field::ReceivedLsbs);
                assert!(description.contains("too large for 3 LSBs"));
                assert!(description.contains("max value 0x7"));
            }
            _ => panic!(
                "Expected InvalidLsbOperation for oversized LSBs, got {:?}",
                err
            ),
        }
    }

    #[test]
    fn decode_lsb_error_conditions_no_resolution() {
        assert_eq!(decode_lsb(0, 10, 3, 10).unwrap(), 0);

        // ref=200, k=3 (win=8, mask=7), received_lsb=0, p=10.
        // interval_base = 200-10=190. Window [190,197].
        // cand1_base = (190 & !7) | 0 = (190 - 190%8) | 0 = (190 - 6) | 0 = 184.
        // cand1 = 184. 184 < 190. cand1 = 184+8 = 192.
        // Is 192.sub(190) < 8? 2 < 8. Yes. Result is 192.
        assert_eq!(decode_lsb(0, 200, 3, 10).unwrap(), 192);

        // ref=50, k=3, received_lsb=0. p=40. interval_base=10. Window [10,17].
        // cand_base = (10 & !7) | 0 = 8 | 0 = 8.
        // cand1 = 8. 8 < 10. cand1 = 8+8 = 16.
        // Is 16.sub(10) < 8? 6 < 8. Yes. Result 16.
        assert_eq!(decode_lsb(0, 50, 3, 40).unwrap(), 16);
    }

    #[test]
    fn value_in_lsb_interval_verifies_correctly() {
        // Scenario: p_offset = 0, v_ref = 10, k = 4. Window [10, 25].
        assert!(is_value_in_lsb_interval(12, 10, 4, 0));
        assert!(is_value_in_lsb_interval(25, 10, 4, 0));
        assert!(is_value_in_lsb_interval(10, 10, 4, 0));
        assert!(!is_value_in_lsb_interval(9, 10, 4, 0));
        assert!(!is_value_in_lsb_interval(26, 10, 4, 0));

        // Scenario: p_offset > 0, v_ref = 100, k = 5, p_offset = 15. Window [85, 116].
        // interval_base = 100 - 15 = 85. window_size = 32.
        assert!(is_value_in_lsb_interval(85, 100, 5, 15)); // 85.sub(85) = 0 < 32.
        assert!(is_value_in_lsb_interval(116, 100, 5, 15)); // 116.sub(85) = 31 < 32.
        assert!(!is_value_in_lsb_interval(84, 100, 5, 15)); // 84.sub(85) = MAX_U64 > 32.
        assert!(!is_value_in_lsb_interval(117, 100, 5, 15)); // 117.sub(85) = 32. Not < 32.

        // Scenario: p_offset < 0, v_ref near u64::MAX, k = 4, p_offset = -2.
        let ref_near_max = u64::MAX - 10; // Example: ...FFF5
        let k_val = 4; // window_size = 16
        let p_neg = -2;
        let interval_base_neg_p = ref_near_max.wrapping_add(2); // ...FFF7

        assert!(is_value_in_lsb_interval(
            interval_base_neg_p,
            ref_near_max,
            k_val,
            p_neg
        )); // diff 0
        assert!(is_value_in_lsb_interval(
            u64::MAX,
            ref_near_max,
            k_val,
            p_neg
        )); // u64::MAX is ...FFFF. diff = MAX - (...FFF7) = 8. 8 < 16.
        // 0.sub(...FFF7) = 9. 9 < 16.
        assert!(is_value_in_lsb_interval(0, ref_near_max, k_val, p_neg));

        // ...FFF7 + 15 = ...0006 (wrapped)
        let upper_val_in_window = interval_base_neg_p.wrapping_add(15);
        assert!(is_value_in_lsb_interval(
            upper_val_in_window,
            ref_near_max,
            k_val,
            p_neg
        ));

        // Test outside lower bound
        assert!(!is_value_in_lsb_interval(
            interval_base_neg_p.wrapping_sub(1), // ...FFF6
            ref_near_max,
            k_val,
            p_neg
        ));

        // Test outside upper bound
        assert!(!is_value_in_lsb_interval(
            upper_val_in_window.wrapping_add(1), // ...0007
            ref_near_max,
            k_val,
            p_neg
        ));

        // Invalid k values
        assert!(!is_value_in_lsb_interval(10, 10, 0, 0)); // k=0, invalid
        assert!(!is_value_in_lsb_interval(10, 10, 65, 0)); // k=65, invalid

        // k=64 is a special case, always true if num_lsb_bits == 64
        assert!(is_value_in_lsb_interval(12345, 67890, 64, 0));
    }
}
