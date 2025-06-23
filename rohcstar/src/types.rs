//! Core type definitions for ROHC implementation.
//!
//! Provides zero-cost newtypes to prevent field mixups at compile time.
//! All types use `#[repr(transparent)]` for guaranteed zero runtime cost.

use std::fmt;
use std::ops::{Add, AddAssign, Deref, Sub};

use serde::{Deserialize, Serialize};

/// Macro to generate ROHC newtype wrappers with common implementations
macro_rules! rohc_newtype {
    (
        $(#[$meta:meta])*
        $name:ident($inner:ty) => $prefix:literal
        $(, custom_methods: { $($custom:tt)* })?
    ) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
        #[derive(Serialize, Deserialize)]
        #[repr(transparent)]
        pub struct $name(pub $inner);

        impl $name {
            /// Creates a new instance
            #[inline]
            pub const fn new(value: $inner) -> Self {
                Self(value)
            }

            /// Raw value
            #[inline]
            pub const fn value(self) -> $inner {
                self.0
            }

            /// Cast to u64 for arithmetic operations
            #[inline]
            pub const fn as_u64(self) -> u64 {
                self.0 as u64
            }

            /// Wrapping addition
            #[inline]
            pub const fn wrapping_add(self, rhs: $inner) -> Self {
                Self(self.0.wrapping_add(rhs))
            }

            /// Wrapping subtraction returning the inner type
            #[inline]
            pub const fn wrapping_sub(self, rhs: Self) -> $inner {
                self.0.wrapping_sub(rhs.0)
            }

            $($($custom)*)?
        }

        // Display with custom prefix
        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}{}", $prefix, self.0)
            }
        }

        // Deref for transparent access
        impl Deref for $name {
            type Target = $inner;

            #[inline]
            fn deref(&self) -> &Self::Target {
                &self.0
            }
        }

        // From/Into conversions
        impl From<$inner> for $name {
            #[inline]
            fn from(value: $inner) -> Self {
                Self(value)
            }
        }

        impl From<$name> for $inner {
            #[inline]
            fn from(value: $name) -> Self {
                value.0
            }
        }

        // Enable direct comparisons with raw values
        impl PartialEq<$inner> for $name {
            #[inline]
            fn eq(&self, other: &$inner) -> bool {
                self.0 == *other
            }
        }

        impl PartialEq<$name> for $inner {
            #[inline]
            fn eq(&self, other: &$name) -> bool {
                *self == other.0
            }
        }

        impl PartialOrd<$inner> for $name {
            #[inline]
            fn partial_cmp(&self, other: &$inner) -> Option<std::cmp::Ordering> {
                self.0.partial_cmp(other)
            }
        }

        impl PartialOrd<$name> for $inner {
            #[inline]
            fn partial_cmp(&self, other: &$name) -> Option<std::cmp::Ordering> {
                self.partial_cmp(&other.0)
            }
        }

        // Arithmetic with raw values
        impl Add<$inner> for $name {
            type Output = Self;

            #[inline]
            fn add(self, rhs: $inner) -> Self::Output {
                self.wrapping_add(rhs)
            }
        }

        impl AddAssign<$inner> for $name {
            #[inline]
            fn add_assign(&mut self, rhs: $inner) {
                *self = self.wrapping_add(rhs);
            }
        }

        impl Sub<Self> for $name {
            type Output = $inner;

            #[inline]
            fn sub(self, rhs: Self) -> Self::Output {
                self.wrapping_sub(rhs)
            }
        }
    };
}

// Define ROHC types with their custom methods
rohc_newtype!(
    /// Context identifier for ROHC compression/decompression state.
    ContextId(u16) => "CID"
);

rohc_newtype!(
    /// RTP sequence number with wrapping arithmetic support.
    SequenceNumber(u16) => "SN",
    custom_methods: {
        /// Convert to big-endian bytes.
        #[inline]
        pub fn to_be_bytes(self) -> [u8; 2] {
            self.0.to_be_bytes()
        }
    }
);

rohc_newtype!(
    /// IP identification field for IPv4 headers.
    IpId(u16) => "IP_ID"
);

rohc_newtype!(
    /// RTP timestamp value with arithmetic support.
    Timestamp(u32) => "TS",
    custom_methods: {
        /// Calculates the wrapping difference between this timestamp and another.
        #[inline]
        pub fn wrapping_diff(self, other: Timestamp) -> u32 {
            self.0.wrapping_sub(other.0)
        }

        /// Converts the timestamp to big-endian bytes.
        #[inline]
        pub fn to_be_bytes(self) -> [u8; 4] {
            self.0.to_be_bytes()
        }
    }
);

rohc_newtype!(
    /// RTP Synchronization Source (SSRC) identifier.
    Ssrc(u32) => "SSRC",
    custom_methods: {
        /// Converts the SSRC to big-endian bytes.
        #[inline]
        pub fn to_be_bytes(self) -> [u8; 4] {
            self.0.to_be_bytes()
        }
    }
);

// Convenience constants
impl ContextId {
    /// Maximum valid context ID for small CID mode
    pub const MAX_SMALL_CID: Self = Self::new(15);
}

impl SequenceNumber {
    /// The initial sequence number
    pub const INITIAL: Self = Self::new(0);
}

impl IpId {
    /// The initial IP ID
    pub const INITIAL: Self = Self::new(0);
}

impl Timestamp {
    /// The initial timestamp
    pub const INITIAL: Self = Self::new(0);
}

impl Ssrc {
    /// The initial SSRC
    pub const INITIAL: Self = Self::new(0);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn context_id_usage() {
        let cid = ContextId::new(42);
        assert_eq!(cid, 42); // Direct comparison
        assert_eq!(format!("{}", cid), "CID42");
        assert_eq!(cid.value(), 42);

        // Use as u16 directly
        assert_eq!(cid.count_ones(), 3);
    }

    #[test]
    fn sequence_number_wrapping() {
        let sn1 = SequenceNumber::new(65534);
        let sn2 = sn1 + 3; // Direct addition
        assert_eq!(sn2, 1);

        let diff = sn2 - sn1; // Returns u16
        assert_eq!(diff, 3);
    }

    #[test]
    fn direct_assignment() {
        let mut ts = Timestamp::INITIAL;
        ts += 1000; // Direct AddAssign
        assert_eq!(ts, 1000);

        let ts2: Timestamp = 2000u32.into(); // From conversion
        assert!(ts2 > ts); // Direct comparison

        // Using deref to access u32 methods
        assert_eq!(ts.leading_zeros(), 22);
    }

    #[test]
    fn no_explicit_conversions_needed() {
        // Function that takes our newtypes
        fn process_packet(cid: ContextId, sn: SequenceNumber, ts: Timestamp) -> bool {
            cid < ContextId::MAX_SMALL_CID && sn > 0 && ts > 0
        }

        // Direct usage without .into() or .value()
        let result = process_packet(
            ContextId::new(5),
            SequenceNumber::new(100),
            Timestamp::new(48000),
        );
        assert!(result);
    }

    #[test]
    fn zero_cost_verification() {
        // Verify size matches underlying type
        assert_eq!(std::mem::size_of::<ContextId>(), std::mem::size_of::<u16>());
        assert_eq!(
            std::mem::size_of::<SequenceNumber>(),
            std::mem::size_of::<u16>()
        );
        assert_eq!(std::mem::size_of::<IpId>(), std::mem::size_of::<u16>());
        assert_eq!(std::mem::size_of::<Timestamp>(), std::mem::size_of::<u32>());
        assert_eq!(std::mem::size_of::<Ssrc>(), std::mem::size_of::<u32>());
    }

    #[test]
    fn ssrc_usage() {
        let ssrc = Ssrc::new(0x12345678);
        assert_eq!(ssrc, 0x12345678);
        assert_eq!(format!("{}", ssrc), "SSRC305419896");
        assert_eq!(ssrc.value(), 0x12345678);
        assert_eq!(ssrc.to_be_bytes(), [0x12, 0x34, 0x56, 0x78]);

        // Test arithmetic and comparisons
        let ssrc2: Ssrc = 0x12345679u32.into();
        assert!(ssrc2 > ssrc);
    }
}
