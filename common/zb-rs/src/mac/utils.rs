use embassy_time::Duration;

use crate::mac::constants::A_BASE_SUPER_FRAME_DURATION;

pub fn calculate_duration(n_symbols: u32) -> Duration {
    // we assume a symbol period of 16us (QPSK, 2.4Ghz)
    Duration::from_micros((n_symbols * 16) as u64)
}

pub fn calculate_duration_micros(n_symbols: u32) -> u32 { 16 * n_symbols }

pub fn calculate_scan_duration_max_us(duration: u8) -> u32 {
    // we assume a symbol period of 16us (QPSK, 2.4Ghz)
    16 * A_BASE_SUPER_FRAME_DURATION * (2 * (duration as u32) + 1)
}
