//! Time abstraction for Rohcstar, allowing for mockable clocks in testing.

use std::fmt::Debug;
use std::time::Instant;

/// A trait abstracting the concept of "now" to allow for time mocking in tests.
pub trait Clock: Send + Debug {
    /// Current `Instant`.
    fn now(&self) -> Instant;
}

/// The default system clock implementation using `std::time::Instant`.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> Instant {
        Instant::now()
    }
}

/// Test utilities for mocking time.
pub mod mock_clock {
    use super::*;
    use std::sync::Mutex;
    use std::time::Duration;

    /// A mock clock that allows for manual control over the current time in tests.
    #[derive(Debug)]
    pub struct MockClock {
        current_time: Mutex<Instant>,
    }

    impl MockClock {
        /// Creates a new `MockClock` starting at the given `start_time`.
        pub fn new(start_time: Instant) -> Self {
            Self {
                current_time: Mutex::new(start_time),
            }
        }

        /// Advances the mock clock's current time by the specified duration.
        pub fn advance(&self, duration: Duration) {
            let mut current = self.current_time.lock().unwrap();
            *current += duration;
        }

        /// Sets the mock clock's current time to a specific instant.
        #[allow(dead_code)] // May not be used in all test scenarios initially
        pub fn set_time(&self, new_time: Instant) {
            let mut current = self.current_time.lock().unwrap();
            *current = new_time;
        }
    }

    impl Default for MockClock {
        fn default() -> Self {
            Self::new(Instant::now())
        }
    }

    impl Clock for MockClock {
        fn now(&self) -> Instant {
            *self.current_time.lock().unwrap()
        }
    }
}
