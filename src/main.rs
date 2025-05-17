use rohcstar::crc::{calculate_rohc_crc3, calculate_rohc_crc8};

fn main() {
    let data = b"123456789";

    // Test CRC-8
    let expected_crc8 = 0xD0; // This is what CRC_8_ROHC from the crate computes
    let calculated_crc8 = calculate_rohc_crc8(data);
    println!(
        "CRC-8 for '123456789': Expected {:#04x}, Got {:#04x} ({})",
        expected_crc8, calculated_crc8, calculated_crc8
    );
    assert_eq!(calculated_crc8, expected_crc8, "Main CRC-8 Check");

    // Test CRC-3
    let expected_crc3 = 0x06; // This is what CRC_3_ROHC from the crate computes for "123456789"
    let calculated_crc3 = calculate_rohc_crc3(data);
    println!(
        "CRC-3 for '123456789': Expected {:#04x}, Got {:#04x} ({})",
        expected_crc3, calculated_crc3, calculated_crc3
    );
    assert_eq!(calculated_crc3, expected_crc3, "Main CRC-3 Check");

    println!("All main.rs checks passed if no panic.");
}
