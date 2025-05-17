use crate::error::RohcParsingError;

pub fn value_in_lsb_interval(value: u64, reference_value: u64, num_lsb_bits: u8, p: i64) -> bool {
    if num_lsb_bits == 0 || num_lsb_bits > 64 {
        return false;
    }
    if num_lsb_bits == 64 {
        // For k=64, any value is uniquely identified by its 64 LSBs.
        return true;
    }

    let k_power_of_2 = 1u64 << num_lsb_bits;

    let lower_bound_interval = if p >= 0 {
        reference_value.wrapping_sub(p as u64)
    } else {
        reference_value.wrapping_add((-p) as u64)
    };

    // The interval is [lower_bound_interval, lower_bound_interval + 2^k - 1] (potentially wrapped)
    // A value 'v' is in this interval if v.wrapping_sub(lower_bound_interval) < k_power_of_2
    value.wrapping_sub(lower_bound_interval) < k_power_of_2
}

pub fn encode_lsb(value: u64, num_lsb_bits: u8) -> Result<u64, String> {
    if num_lsb_bits == 0 {
        return Err("num_lsb_bits cannot be 0 for LSB encoding".to_string());
    }
    if num_lsb_bits > 64 {
        return Err("num_lsb_bits cannot exceed 64 for u64 LSB encoding".to_string());
    }

    if num_lsb_bits == 64 {
        Ok(value) // All bits are LSBs
    } else {
        let mask = (1u64 << num_lsb_bits) - 1;
        Ok(value & mask)
    }
}

pub fn decode_lsb(
    received_lsbs: u64,
    reference_value: u64,
    num_lsb_bits: u8,
    p: i64,
) -> Result<u64, RohcParsingError> {
    if num_lsb_bits == 0 || num_lsb_bits > 63 {
        return Err(RohcParsingError::InvalidLsbEncoding {
            field_name: format!("k_bits={}", num_lsb_bits),
        });
    }

    let k_power_of_2 = 1u64 << num_lsb_bits;
    let lsb_mask = k_power_of_2 - 1;

    if received_lsbs > lsb_mask {
        return Err(RohcParsingError::InvalidLsbEncoding {
            field_name: format!("received_lsbs {:#x} > mask {:#x}", received_lsbs, lsb_mask),
        });
    }

    let lower_bound_interval = if p >= 0 {
        reference_value.wrapping_sub(p as u64)
    } else {
        reference_value.wrapping_add((-p) as u64)
    };

    // Find candidate 'v' in the interval starting at lower_bound_interval
    // such that v's LSBs match received_lsbs.
    // v = lower_bound_interval - (lower_bound_interval % 2^k) + received_lsbs
    // If this candidate is less than lower_bound_interval, add 2^k.
    // This is effectively finding the smallest 'v' >= 'lower_bound_interval'
    // where 'v % 2^k == received_lsbs'.

    let mut v = (lower_bound_interval & !lsb_mask) | received_lsbs;
    if v < lower_bound_interval {
        v = v.wrapping_add(k_power_of_2);
    }

    // If v is now outside the interval [lower_bound_interval, lower_bound_interval + 2^k -1],
    // it implies something went wrong or the LSBs cannot be resolved.
    // The check value.wrapping_sub(lower_bound_interval) < k_power_of_2 ensures it's in window.
    if v.wrapping_sub(lower_bound_interval) < k_power_of_2 {
        Ok(v)
    } else {
        // This should ideally not be hit if the LSBs belong to a value within the window
        // defined by reference_value, k, and p. It suggests v_ref_d might be too far off,
        // or the LSBs are corrupted.
        // Let's try a second candidate if the first was too high
        let v_minus_k = v.wrapping_sub(k_power_of_2);
        if (v_minus_k & lsb_mask) == received_lsbs
            && v_minus_k.wrapping_sub(lower_bound_interval) < k_power_of_2
        {
            Ok(v_minus_k)
        } else {
            Err(RohcParsingError::InvalidLsbEncoding {
                field_name: format!(
                    "Cannot uniquely decode LSBs {:#x} with ref {:#x}, k={}, p={}. Candidate {} not in window.",
                    received_lsbs, reference_value, num_lsb_bits, p, v
                ),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_lsb_simple() {
        assert_eq!(encode_lsb(0x1234, 8).unwrap(), 0x34);
        assert_eq!(encode_lsb(0x1234, 4).unwrap(), 0x04);
        assert_eq!(encode_lsb(0xFFFF, 8).unwrap(), 0xFF);
        assert_eq!(encode_lsb(0xFFFF, 16).unwrap(), 0xFFFF);
        assert_eq!(encode_lsb(u64::MAX, 64).unwrap(), u64::MAX); // Check k=64
        assert_eq!(encode_lsb(0, 1).unwrap(), 0);
    }

    #[test]
    fn test_encode_lsb_invalid_k() {
        assert!(encode_lsb(0x1234, 0).is_err());
        assert!(encode_lsb(0x1234, 65).is_err());
    }

    #[test]
    fn test_decode_lsb_non_decreasing_p0() {
        assert_eq!(decode_lsb(0xC, 10, 4, 0).unwrap(), 12);
        assert_eq!(decode_lsb(0x4, 10, 4, 0).unwrap(), 20);
        assert_eq!(decode_lsb(0x2, 20, 4, 0).unwrap(), 34);
        assert_eq!(decode_lsb(31, 250, 5, 0).unwrap(), 255);
        assert_eq!(decode_lsb(3, u64::MAX - 5, 4, 0).unwrap(), 3);
    }

    #[test]
    fn test_decode_lsb_always_increasing_p_neg1() {
        assert_eq!(decode_lsb(0x7, 5, 3, -1).unwrap(), 7);
        assert_eq!(decode_lsb(0x5, 5, 3, -1).unwrap(), 13);
        assert_eq!(decode_lsb(1, u64::MAX - 2, 3, -1).unwrap(), 1);
    }

    #[test]
    fn test_value_in_lsb_interval_logic() {
        assert!(value_in_lsb_interval(12, 10, 4, 0));
        assert!(value_in_lsb_interval(20, 10, 4, 0));
        assert!(!value_in_lsb_interval(9, 10, 4, 0));
        assert!(!value_in_lsb_interval(26, 10, 4, 0));
        assert!(value_in_lsb_interval(7, 5, 3, -1));
        assert!(value_in_lsb_interval(13, 5, 3, -1));
        assert!(!value_in_lsb_interval(5, 5, 3, -1));
        assert!(value_in_lsb_interval(90, 100, 5, 15));
        assert!(!value_in_lsb_interval(84, 100, 5, 15));
        assert!(!value_in_lsb_interval(117, 100, 5, 15));
        assert!(value_in_lsb_interval(3, u64::MAX - 5, 4, 0));
        assert!(!value_in_lsb_interval(u64::MAX - 7, u64::MAX - 5, 4, 0));
        assert!(value_in_lsb_interval(u64::MAX, u64::MAX - 5, 4, 0));
    }
}
