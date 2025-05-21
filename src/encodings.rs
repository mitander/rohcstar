use crate::error::RohcParsingError;

/// Checks if a `value` falls within the LSB interpretation interval defined by a
/// `reference_value`, the number of LSBs (`num_lsb_bits`), and an offset `p`.
///
/// The interpretation interval is `[reference_value - p, reference_value - p + 2^num_lsb_bits - 1]`.
/// This function is used by the decompressor to validate if a reconstructed value
/// is plausible given the LSBs received and the current context.
///
/// # Arguments
/// * `value`: The full value to check.
/// * `reference_value`: The reference value (e.g., last successfully decoded value).
/// * `num_lsb_bits`: The number of LSBs used for encoding (k in ROHC RFCs). Must be > 0 and <= 64.
/// * `p_offset`: The interpretation interval offset `p` (RFC 3095, Section 4.5.1).
///   A non-negative `p_offset` shifts the window backward from `reference_value`.
///   A negative `p_offset` effectively shifts it forward.
///
/// # Returns
/// `true` if `value` is within the LSB interpretation interval, `false` otherwise or if `num_lsb_bits` is invalid.
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
    // This is equivalent to v.wrapping_sub(interval_base) < window_size.
    value.wrapping_sub(interval_base) < window_size
}

/// Encodes a `value` by retaining only its `num_lsb_bits` least significant bits.
///
/// # Arguments
/// * `value`: The original `u64` value to encode.
/// * `num_lsb_bits`: The number of LSBs to retain. Must be between 1 and 64, inclusive.
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

/// Decodes a full value from its received LSBs, a reference value, the number of LSBs used,
/// and an interpretation interval offset `p_offset`.
///
/// This function implements the LSB decoding logic as described in ROHC (e.g., RFC 3095, Section 4.5.1).
/// It finds a candidate value `v` within the interpretation window
/// `[reference_value - p_offset, reference_value - p_offset + 2^num_lsb_bits - 1]`
/// such that the `num_lsb_bits` LSBs of `v` match `received_lsbs`.
///
/// # Arguments
/// * `received_lsbs`: The LSBs of the value that were transmitted/received.
/// * `reference_value`: The reference value (e.g., last successfully decoded value, `v_ref`).
/// * `num_lsb_bits`: The number of LSBs used for encoding (k). Must be > 0 and < 64.
///   (k=64 is trivial, handled by `encode_lsb` but not typical for LSB decoding context).
/// * `p_offset`: The interpretation interval offset `p`.
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

    #[test]
    fn encode_lsb_valid_inputs() {
        assert_eq!(
            encode_lsb(0x1234, 8).unwrap(),
            0x34,
            "Encode 0x1234 with 8 LSBs"
        );
        assert_eq!(
            encode_lsb(0x1234, 4).unwrap(),
            0x04,
            "Encode 0x1234 with 4 LSBs"
        );
        assert_eq!(
            encode_lsb(0xFFFF, 8).unwrap(),
            0xFF,
            "Encode 0xFFFF with 8 LSBs"
        );
        assert_eq!(
            encode_lsb(0xFFFF, 16).unwrap(),
            0xFFFF,
            "Encode 0xFFFF with 16 LSBs"
        );
        assert_eq!(
            encode_lsb(u64::MAX, 64).unwrap(),
            u64::MAX,
            "Encode u64::MAX with 64 LSBs"
        );
        assert_eq!(encode_lsb(0, 1).unwrap(), 0, "Encode 0 with 1 LSB");
    }

    #[test]
    fn encode_lsb_invalid_num_bits() {
        assert!(
            encode_lsb(0x1234, 0).is_err(),
            "num_lsb_bits = 0 should be an error"
        );
        assert!(
            encode_lsb(0x1234, 65).is_err(),
            "num_lsb_bits > 64 should be an error"
        );
    }

    // Test cases for decode_lsb based on RFC 3095 examples or logic
    // v_ref is reference_value, k is num_lsb_bits, LSBs(v') is received_lsbs
    // p is p_offset

    #[test]
    fn decode_lsb_rfc_style_cases_p0() {
        // Example: v_ref = 10, k = 4, p = 0. Window [10, 25].
        // LSBs(12) = 0xC. Expected: 12.
        assert_eq!(decode_lsb(0xC, 10, 4, 0).unwrap(), 12);
        // LSBs(20) = 0x4. Expected: 20.
        assert_eq!(decode_lsb(0x4, 10, 4, 0).unwrap(), 20);
        // LSBs(34) = 0x2. v_ref=20, k=4, p=0. Window [20, 35]. Expected: 34.
        assert_eq!(decode_lsb(0x2, 20, 4, 0).unwrap(), 34);
        // Example from RFC 3095 section 4.5.1: f(v_ref=250, k=5, p=0) for LSBs(255)=31 -> 255
        assert_eq!(decode_lsb(31, 250, 5, 0).unwrap(), 255);

        // Test wrapping: v_ref = MAX-5, k=4, p=0. Window [MAX-5, MAX-5+15]
        // LSBs(3) = 3. This means we're looking for a number ending in ...0011.
        // MAX-5 is ...1011. MAX-4 ...1100. MAX-3 ...1101. MAX-2 ...1110. MAX-1 ...1111.
        // 0 ...0000. 1 ...0001. 2 ...0010. 3 ...0011.
        // So 3 is in the window [MAX-5, MAX-5+15] which includes MAX-5, ..., MAX, 0, 1, ..., MAX-5+15-2^k
        assert_eq!(decode_lsb(3, u64::MAX - 5, 4, 0).unwrap(), 3);
    }

    #[test]
    fn decode_lsb_rfc_style_cases_p_negative() {
        // p = -1. Window [v_ref + 1, v_ref + 1 + 2^k - 1] (always increasing)
        // Example: v_ref = 5, k = 3, p = -1. Window [6, 6+7=13]
        // LSBs(7) = 7. Expected: 7.
        assert_eq!(decode_lsb(0x7, 5, 3, -1).unwrap(), 7);
        // LSBs(13) = 5. Expected: 13.
        assert_eq!(decode_lsb(0x5, 5, 3, -1).unwrap(), 13);

        // Wrapping with p=-1
        // v_ref = MAX-2, k=3, p=-1. Window [MAX-1, MAX-1+7]. Contains MAX-1, MAX, 0, 1, 2, 3, 4
        // LSBs(1) = 1. Expected: 1.
        assert_eq!(decode_lsb(1, u64::MAX - 2, 3, -1).unwrap(), 1);
    }

    #[test]
    fn decode_lsb_invalid_num_bits() {
        assert!(decode_lsb(0x01, 10, 0, 0).is_err()); // k=0
        assert!(decode_lsb(0x01, 10, 64, 0).is_err()); // k=64
    }

    #[test]
    fn decode_lsb_received_lsbs_too_large_for_k() {
        match decode_lsb(0x10, 10, 3, 0) {
            // 0x10 (16) is too large for k=3 (max value 7)
            Err(RohcParsingError::InvalidLsbEncoding {
                field_name,
                description,
            }) => {
                assert_eq!(field_name, "received_lsbs");
                assert!(description.contains("too large for 3 LSBs"));
            }
            _ => panic!("Expected InvalidLsbEncoding error for oversized LSBs"),
        }
    }

    #[test]
    fn value_in_lsb_interval_logic() {
        // p = 0: v_ref = 10, k = 4. Window [10, 25]
        assert!(value_in_lsb_interval(12, 10, 4, 0));
        assert!(value_in_lsb_interval(20, 10, 4, 0));
        assert!(!value_in_lsb_interval(9, 10, 4, 0)); // Below window
        assert!(!value_in_lsb_interval(26, 10, 4, 0)); // Above window

        // p = -1: v_ref = 5, k = 3. Window [6, 13]
        assert!(value_in_lsb_interval(7, 5, 3, -1));
        assert!(value_in_lsb_interval(13, 5, 3, -1));
        assert!(!value_in_lsb_interval(5, 5, 3, -1)); // Below window

        // p > 0: v_ref = 100, k = 5, p = 15. Window [85, 116] (100-15 to 100-15 + 32-1)
        assert!(value_in_lsb_interval(90, 100, 5, 15));
        assert!(!value_in_lsb_interval(84, 100, 5, 15)); // Below
        assert!(!value_in_lsb_interval(117, 100, 5, 15)); // Above

        // Wrapping cases
        // v_ref = MAX - 5, k = 4, p = 0. Window [MAX-5, MAX-5+15]
        // This window wraps around, e.g., includes MAX-1, MAX, 0, 1, 2, 3
        assert!(value_in_lsb_interval(3, u64::MAX - 5, 4, 0));
        assert!(!value_in_lsb_interval(u64::MAX - 7, u64::MAX - 5, 4, 0)); // Too "low" before wrap
        assert!(value_in_lsb_interval(u64::MAX, u64::MAX - 5, 4, 0));

        // Invalid k
        assert!(!value_in_lsb_interval(10, 10, 0, 0));
        assert!(!value_in_lsb_interval(10, 10, 65, 0));
        // k=64 should always be true
        assert!(value_in_lsb_interval(12345, 67890, 64, 0));
    }
}
