//! ROHC encoding and decoding utilities.
//!
//! Implements the core encoding schemes used in ROHC, including
//! LSB (Least Significant Bits) encoding and other compression
//! algorithms defined in the ROHC specifications.

use crate::error::RohcParsingError;

/// Checks if a value is within the LSB interpretation window.
///
/// The window is `[reference_value - p, reference_value - p + 2^k - 1]`
/// where `k = num_lsb_bits`.
///
/// # Parameters
/// - `value`: Value to check
/// - `reference_value`: Base value for the window
/// - `num_lsb_bits`: Number of LSBs (k in RFCs), 1-64
/// - `p_offset`: Window offset (positive = left shift, negative = right shift)
///
/// # Returns
/// `true` if value is in the interpretation window, `false` otherwise.
pub fn value_in_lsb_interval(
    value: u64,
    reference_value: u64,
    num_lsb_bits: u8,
    p_offset: i64,
) -> bool {
    if num_lsb_bits == 0 || num_lsb_bits > 64 {
        // Invalid number of LSB bits, cannot form a meaningful interval.
        return false;
    }
    if num_lsb_bits == 64 {
        // If all bits are LSBs, any value is uniquely identified and considered within its "interval".
        return true;
    }

    let window_size = 1u64 << num_lsb_bits; // This is 2^k

    // Calculate the lower bound of the interpretation window.
    // interval_base = v_ref - p
    let interval_base = if p_offset >= 0 {
        reference_value.wrapping_sub(p_offset as u64)
    } else {
        // p_offset is negative, so -p_offset is positive.
        reference_value.wrapping_add((-p_offset) as u64)
    };

    // A value 'v' is in the interval [interval_base, interval_base + window_size - 1] (modulo 2^64)
    // if and only if (v - interval_base) mod 2^64 < window_size.
    // Equivalent to v.wrapping_sub(interval_base) < window_size
    value.wrapping_sub(interval_base) < window_size
}

/// Extracts the N least significant bits from a value.
///
/// # Parameters
/// - `value`: Value to encode
/// - `num_lsb_bits`: Number of LSBs to keep (1-64)
///
/// # Returns
/// A `Result` containing the LSB-encoded value as `u64`, or a `RohcParsingError`
/// if `num_lsb_bits` is invalid.
pub fn encode_lsb(value: u64, num_lsb_bits: u8) -> Result<u64, RohcParsingError> {
    if num_lsb_bits == 0 {
        return Err(RohcParsingError::InvalidLsbEncoding {
            field_name: "num_lsb_bits".to_string(),
            description: "cannot be 0 for LSB encoding".to_string(),
        });
    }
    if num_lsb_bits > 64 {
        return Err(RohcParsingError::InvalidLsbEncoding {
            field_name: "num_lsb_bits".to_string(),
            description: format!(
                "cannot exceed 64 for u64 LSB encoding, got {}",
                num_lsb_bits
            ),
        });
    }

    if num_lsb_bits == 64 {
        // If k=64, all bits are LSBs, so the value itself is the "encoded" LSBs.
        Ok(value)
    } else {
        let mask = (1u64 << num_lsb_bits) - 1;
        Ok(value & mask)
    }
}

/// Reconstructs a value from its LSBs using a reference value and window offset.
///
/// Finds a value in the window `[v_ref - p, v_ref - p + 2^k - 1]`
/// whose LSBs match `received_lsbs`.
///
/// # Parameters
/// - `received_lsbs`: Received LSBs of the value
/// - `reference_value`: Reference value (v_ref)
/// - `num_lsb_bits`: Number of LSBs used (k), 1-63
/// - `p_offset`: Window offset (p in RFC 3095-5.3.1)
///
/// # Returns
/// A `Result` containing the reconstructed `u64` value, or a `RohcParsingError`
/// if decoding fails (e.g., invalid parameters, LSBs cannot be uniquely resolved).
pub fn decode_lsb(
    received_lsbs: u64,
    reference_value: u64,
    num_lsb_bits: u8,
    p_offset: i64,
) -> Result<u64, RohcParsingError> {
    if num_lsb_bits == 0 || num_lsb_bits >= 64 {
        // k must be > 0. k=64 implies full value, no LSB "decoding" needed in this sense.
        // RFC 3095 typically implies k < field_size.
        return Err(RohcParsingError::InvalidLsbEncoding {
            field_name: "num_lsb_bits".to_string(),
            description: format!(
                "must be between 1 and 63 for LSB decoding, got {}",
                num_lsb_bits
            ),
        });
    }

    let window_size = 1u64 << num_lsb_bits; // This is 2^k
    let lsb_mask = window_size - 1;

    // Ensure received_lsbs themselves are valid for the given k
    if received_lsbs > lsb_mask {
        return Err(RohcParsingError::InvalidLsbEncoding {
            field_name: "received_lsbs".to_string(),
            description: format!(
                "value {:#x} is too large for {} LSBs (mask {:#x})",
                received_lsbs, num_lsb_bits, lsb_mask
            ),
        });
    }

    // Calculate the lower bound of the interpretation window: v_ref - p
    let interval_base = if p_offset >= 0 {
        reference_value.wrapping_sub(p_offset as u64)
    } else {
        reference_value.wrapping_add((-p_offset) as u64)
    };

    // Candidate value construction (RFC 3095, Section 4.5.1, logic for v_cand):
    // v_cand = (v_ref - p - ( (v_ref - p) % 2^k ) ) + LSBs(v')
    // If v_cand < (v_ref - p), then v_cand = v_cand + 2^k
    // This can be simplified: find the number X such that X % 2^k == received_lsbs and
    // X is "closest" to reference_value, within the window starting at interval_base.
    //
    // Start by aligning interval_base down to the nearest multiple of 2^k, then add received_lsbs.
    let mut candidate_v = (interval_base & !lsb_mask) | received_lsbs;

    // Adjust candidate_v to be >= interval_base.
    if candidate_v < interval_base {
        candidate_v = candidate_v.wrapping_add(window_size);
    }

    // Check if this candidate_v is within the interpretation window.
    // The window is [interval_base, interval_base + window_size - 1].
    if candidate_v.wrapping_sub(interval_base) < window_size {
        Ok(candidate_v)
    } else {
        // If the first candidate was too high (wrapped around due to interval_base itself being high),
        // try the candidate that is 2^k lower. This occurs if interval_base is near MAX_U64
        // and received_lsbs causes candidate_v to wrap past 0 but still be "above" interval_base
        // after the first adjustment.
        let alternative_candidate_v = candidate_v.wrapping_sub(window_size);
        if alternative_candidate_v.wrapping_sub(interval_base) < window_size {
            Ok(alternative_candidate_v)
        } else {
            // Neither candidate is in the window. This implies the LSBs are inconsistent
            // with the reference and p_offset, or the reference itself is too far off.
            Err(RohcParsingError::InvalidLsbEncoding {
                field_name: "received_lsbs".to_string(),
                description: format!(
                    "cannot be uniquely resolved to a value in the interpretation window. LSBs: {:#x}, ref: {:#x}, k: {}, p: {}. Candidates: {:#x}, {:#x}. Window base: {:#x}",
                    received_lsbs,
                    reference_value,
                    num_lsb_bits,
                    p_offset,
                    candidate_v,
                    alternative_candidate_v,
                    interval_base
                ),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::RohcParsingError;

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
        // k=0 is invalid for LSB encoding.
        assert!(matches!(
            encode_lsb(0x1234, 0), // num_lsb_bits = 0
            Err(RohcParsingError::InvalidLsbEncoding { .. })
        ));
        // k>64 is invalid for u64.
        assert!(matches!(
            encode_lsb(0x1234, 65), // num_lsb_bits = 65
            Err(RohcParsingError::InvalidLsbEncoding { .. })
        ));
    }

    #[test]
    fn decode_lsb_p0_basic_no_wrap() {
        // Scenario: p_offset = 0. v_ref=100, k=4. Window [100, 115].
        assert_eq!(decode_lsb(0x4, 100, 4, 0).unwrap(), 100);
        assert_eq!(decode_lsb(0x0, 100, 4, 0).unwrap(), 112);
        assert_eq!(decode_lsb(0xF, 100, 4, 0).unwrap(), 111);
        assert_eq!(decode_lsb(0xA, 100, 4, 0).unwrap(), 106);
    }

    #[test]
    fn decode_lsb_p0_around_reference_candidate_selection() {
        // Scenario: p_offset = 0. v_ref=10, k=4. Window [10, 25].
        assert_eq!(decode_lsb(0xC, 10, 4, 0).unwrap(), 12);
        assert_eq!(decode_lsb(0x4, 10, 4, 0).unwrap(), 20);
        assert_eq!(decode_lsb(0x9, 10, 4, 0).unwrap(), 25);
    }

    #[test]
    fn decode_lsb_p_positive_shifts_window_left() {
        // Scenario: p_offset > 0. v_ref=100, k=4, p_offset=2. Window [98, 113].
        assert_eq!(decode_lsb(0x3, 100, 4, 2).unwrap(), 99);
        assert_eq!(decode_lsb(0x2, 100, 4, 2).unwrap(), 98);
        assert_eq!(decode_lsb(0xD, 100, 4, 2).unwrap(), 109);
        assert_eq!(decode_lsb(0x1, 100, 4, 2).unwrap(), 113);
        assert_eq!(decode_lsb(0x0, 100, 4, 2).unwrap(), 112);
    }

    #[test]
    fn decode_lsb_p_negative_shifts_window_right() {
        // Scenario: p_offset < 0. v_ref=10, k=3, p_offset=-1. Window [11, 18].
        assert_eq!(decode_lsb(0x3, 10, 3, -1).unwrap(), 11);
        assert_eq!(decode_lsb(0x2, 10, 3, -1).unwrap(), 18);
        assert_eq!(decode_lsb(0x7, 10, 3, -1).unwrap(), 15);
    }

    #[test]
    fn decode_lsb_p0_wrapping_around_max_u64() {
        // Scenario: p_offset = 0, v_ref near u64::MAX, k=4. Window wraps around 0.
        let k = 4;
        let lsb_mask = (1u64 << k) - 1;
        let ref_val = u64::MAX - 5;

        assert_eq!(
            decode_lsb(ref_val & lsb_mask, ref_val, k, 0).unwrap(),
            ref_val
        );
        assert_eq!(
            decode_lsb(u64::MAX & lsb_mask, ref_val, k, 0).unwrap(),
            u64::MAX
        );
        assert_eq!(decode_lsb(0, ref_val, k, 0).unwrap(), 0);
        assert_eq!(decode_lsb(3, ref_val, k, 0).unwrap(), 3);
        let upper_val_in_window = ref_val.wrapping_add(15);
        assert_eq!(
            decode_lsb(upper_val_in_window & lsb_mask, ref_val, k, 0).unwrap(),
            upper_val_in_window
        );
    }

    #[test]
    fn decode_lsb_p_positive_wrapping_around_max_u64() {
        // Scenario: p_offset > 0, v_ref near u64::MAX, k=4, p_offset=7. Window wraps.
        let k = 4;
        let p_offset = 7;
        let lsb_mask = (1u64 << k) - 1;
        let ref_val = u64::MAX - 2;
        let interval_base = ref_val.wrapping_sub(p_offset as u64);

        assert_eq!(
            decode_lsb(interval_base & lsb_mask, ref_val, k, p_offset).unwrap(),
            interval_base
        );
        assert_eq!(
            decode_lsb(u64::MAX & lsb_mask, ref_val, k, p_offset).unwrap(),
            u64::MAX
        );
        assert_eq!(decode_lsb(0, ref_val, k, p_offset).unwrap(), 0);
        let upper_val_in_window = interval_base.wrapping_add(15);
        assert_eq!(
            decode_lsb(upper_val_in_window & lsb_mask, ref_val, k, p_offset).unwrap(),
            upper_val_in_window
        );
    }

    #[test]
    fn decode_lsb_p_negative_wrapping_around_max_u64() {
        // Scenario: p_offset < 0, v_ref near u64::MAX, k=3, p_offset=-1. Window wraps.
        let k = 3;
        let p_offset = -1;
        let lsb_mask = (1u64 << k) - 1;
        let ref_val = u64::MAX - 2;
        let interval_base = ref_val.wrapping_add((-p_offset) as u64);

        assert_eq!(
            decode_lsb(interval_base & lsb_mask, ref_val, k, p_offset).unwrap(),
            interval_base
        );
        assert_eq!(
            decode_lsb(u64::MAX & lsb_mask, ref_val, k, p_offset).unwrap(),
            u64::MAX
        );
        assert_eq!(decode_lsb(0, ref_val, k, p_offset).unwrap(), 0);
        assert_eq!(decode_lsb(1, ref_val, k, p_offset).unwrap(), 1);
        let upper_val_in_window = interval_base.wrapping_add((1 << k) - 1);
        assert_eq!(
            decode_lsb(upper_val_in_window & lsb_mask, ref_val, k, p_offset).unwrap(),
            upper_val_in_window
        );
    }

    #[test]
    fn decode_lsb_error_invalid_num_bits_combined() {
        // num_lsb_bits must be > 0 and < 64 for decode_lsb.
        assert!(matches!(
            decode_lsb(0x01, 10, 0, 0), // k=0 is invalid
            Err(RohcParsingError::InvalidLsbEncoding { .. })
        ));
        assert!(matches!(
            decode_lsb(0x01, 10, 64, 0), // k=64 is invalid for LSB *decoding* context
            Err(RohcParsingError::InvalidLsbEncoding { .. })
        ));
    }

    #[test]
    fn decode_lsb_error_received_lsbs_too_large_for_k_combined() {
        // received_lsbs (0x10) cannot be represented by k=3 bits (max LSB value 0x07).
        match decode_lsb(0x10, 10, 3, 0) {
            Err(RohcParsingError::InvalidLsbEncoding {
                field_name,
                description,
            }) => {
                assert_eq!(field_name, "received_lsbs");
                assert!(description.contains("too large for 3 LSBs"));
            }
            res => panic!(
                "Expected InvalidLsbEncoding for oversized LSBs, got {:?}",
                res
            ),
        }
    }

    #[test]
    fn decode_lsb_error_conditions_leading_to_no_resolution_original() {
        assert_eq!(decode_lsb(0, 200, 3, 10).unwrap(), 192);
    }

    #[test]
    fn value_in_lsb_interval_verifies_correctly() {
        // Scenario: p_offset = 0, v_ref = 10, k = 4. Window [10, 25].
        assert!(value_in_lsb_interval(12, 10, 4, 0));
        assert!(value_in_lsb_interval(25, 10, 4, 0));
        assert!(value_in_lsb_interval(10, 10, 4, 0));
        assert!(!value_in_lsb_interval(9, 10, 4, 0));
        assert!(!value_in_lsb_interval(26, 10, 4, 0));

        // Scenario: p_offset > 0, v_ref = 100, k = 5, p_offset = 15. Window [85, 116].
        assert!(value_in_lsb_interval(85, 100, 5, 15));
        assert!(value_in_lsb_interval(116, 100, 5, 15));
        assert!(!value_in_lsb_interval(84, 100, 5, 15));
        assert!(!value_in_lsb_interval(117, 100, 5, 15));

        // Scenario: p_offset < 0, v_ref near u64::MAX, k = 4, p_offset = -2.
        let ref_near_max = u64::MAX - 10;
        let k_val = 4;
        let p_neg = -2;
        let interval_base_neg_p = ref_near_max.wrapping_add((-p_neg) as u64);
        assert!(value_in_lsb_interval(
            interval_base_neg_p,
            ref_near_max,
            k_val,
            p_neg
        ));
        assert!(value_in_lsb_interval(u64::MAX, ref_near_max, k_val, p_neg));
        assert!(value_in_lsb_interval(0, ref_near_max, k_val, p_neg));
        let upper_val = interval_base_neg_p.wrapping_add(15);
        assert!(value_in_lsb_interval(upper_val, ref_near_max, k_val, p_neg));
        assert!(!value_in_lsb_interval(
            interval_base_neg_p.wrapping_sub(1),
            ref_near_max,
            k_val,
            p_neg
        ));
        assert!(!value_in_lsb_interval(
            upper_val.wrapping_add(1),
            ref_near_max,
            k_val,
            p_neg
        ));

        // Invalid k values
        assert!(!value_in_lsb_interval(10, 10, 0, 0)); // k=0, invalid
        assert!(!value_in_lsb_interval(10, 10, 65, 0)); // k=65, invalid
        assert!(value_in_lsb_interval(12345, 67890, 64, 0)); // k=64, valid special case
    }
}
