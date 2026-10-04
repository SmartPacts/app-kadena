//! Fuzz target: JSON tokenizer, parser and review-item builder, as a signing
//! command drives them (0x22 / 0x03 after the last chunk): read the JSON, build
//! the review items for the device's key, render every item.
//!
//! The device key is the test seed's key at m/44'/626'/0'/0/0, as in the seed
//! corpus (fuzz/seeds/review). Any panic is a finding.
#![no_main]

use kadena_core::buffering::FLASH_CAP;
use kadena_core::items::{ItemCrypto, TxType, TITLE_BUF, VALUE_BUF};
use kadena_core::parser::{ParseCrypto, Parsed};
use libfuzzer_sys::fuzz_target;

/// de12b5e16b93fe81ca4d70656bee4334f2e40f9f28b9796e792d28f2cead74ad
const PK: [u8; 32] = [
    0xde, 0x12, 0xb5, 0xe1, 0x6b, 0x93, 0xfe, 0x81, 0xca, 0x4d, 0x70, 0x65, 0x6b, 0xee, 0x43, 0x34,
    0xf2, 0xe4, 0x0f, 0x9f, 0x28, 0xb9, 0x79, 0x6e, 0x79, 0x2d, 0x28, 0xf2, 0xce, 0xad, 0x74, 0xad,
];

struct Device;

impl ItemCrypto for Device {
    fn address(&self) -> Option<[u8; 32]> {
        Some(PK)
    }
}

impl ParseCrypto for Device {
    // The hash only feeds the display of the hash item; its value does not
    // change any parsing decision.
    fn blake2b_256(&self, data: &[u8]) -> Option<[u8; 32]> {
        let mut h = [0u8; 32];
        for (i, b) in data.iter().enumerate() {
            h[i % 32] ^= b.rotate_left((i % 7) as u32);
        }
        Some(h)
    }
}

/// Parse, build and render, with the token cap of Nano X (110) or of the other
/// devices (768).
fn review<const T: usize>(data: &[u8]) {
    let mut parsed: Box<Parsed<T>> = Box::new(Parsed::new());
    if parsed.read_json(data).is_err() {
        return;
    }
    for expert in [false, true] {
        if parsed
            .store_items(&Device, TxType::Json, data, None, expert)
            .is_err()
        {
            return;
        }
        if parsed.validate(&Device, data).is_err() {
            continue;
        }
        let mut title = [0u8; TITLE_BUF];
        let mut value = [0u8; VALUE_BUF];
        for i in 0..parsed.num_items() {
            if let Ok((t, v)) = parsed.item(&Device, data, i, &mut title, &mut value) {
                assert!(t <= TITLE_BUF && v <= VALUE_BUF);
            }
        }
    }
}

fuzz_target!(|data: &[u8]| {
    // The largest transaction the device buffers.
    let data = &data[..data.len().min(FLASH_CAP)];
    review::<110>(data);
    review::<768>(data);
});
