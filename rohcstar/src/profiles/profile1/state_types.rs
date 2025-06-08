//! State machine types for Profile 1 decompressor.

use super::constants::*;

/// State machine counters for Profile 1 decompressor.
#[derive(Debug, Clone, Default)]
pub struct StateCounters {
    pub fc_crc_failures: u8,
    pub fc_success_streak: u32,
    pub sc_k_failures: u8,
    pub sc_n_window: u8,
    pub so_static_confidence: u32,
    pub so_dynamic_confidence: u32,
    pub so_consecutive_failures: u32,
    pub so_packets_in_so: u32,
}

impl StateCounters {
    pub fn reset_for_nc(&mut self) {
        *self = Self::default();
    }

    pub fn reset_for_fc(&mut self) {
        self.fc_crc_failures = 0;
        self.fc_success_streak = 0;
        self.sc_k_failures = 0;
        self.sc_n_window = 0;
    }

    pub fn init_for_so(&mut self) {
        self.so_static_confidence = P1_SO_INITIAL_STATIC_CONFIDENCE;
        self.so_dynamic_confidence = P1_SO_INITIAL_DYNAMIC_CONFIDENCE;
        self.so_consecutive_failures = 0;
        self.so_packets_in_so = 0;
        self.fc_success_streak = 0;
    }
}
