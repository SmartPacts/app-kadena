//! The device side of `kadena_core::app::Platform`: key derivation, signing,
//! hashing (all through the OS), the transaction buffer (RAM, then flash for large
//! transactions, as in the C app), the transfer template (flash), settings.

use core::cell::UnsafeCell;

use kadena_core::app::Platform;
use kadena_core::buffering::{Buffering, FlashWriter, RAM_CAP};
use kadena_core::transfer::TEMPLATE_BUF;
use ledger_device_sdk::ecc::{Ed25519, SeedDerive};
use ledger_device_sdk::hash::{blake2::Blake2b_256, HashInit};
use ledger_device_sdk::sys;

use crate::settings;
use crate::storage;

/// The 8192-byte RAM transaction buffer (C: `ram_buffer`), in `.bss`.
struct RamBuffer(UnsafeCell<[u8; RAM_CAP]>);

// SAFETY: single-threaded app; the buffer is borrowed once, by `Device::new`,
// which `sample_main` calls once.
unsafe impl Sync for RamBuffer {}

static RAM: RamBuffer = RamBuffer(UnsafeCell::new([0; RAM_CAP]));

/// Flash writes of the transaction buffer.
struct TxFlash;

impl FlashWriter for TxFlash {
    fn write(&mut self, offset: usize, data: &[u8]) {
        storage::tx_write(offset, data);
    }
}

pub struct Device {
    buffer: Buffering,
    ram: &'static mut [u8; RAM_CAP],
    template_len: usize,
}

impl Device {
    /// Call once.
    pub fn new() -> Self {
        Device {
            buffer: Buffering::new(),
            // SAFETY: the only reference ever taken to RAM (see `RamBuffer`).
            ram: unsafe { &mut *RAM.0.get() },
            template_len: 0,
        }
    }
}

/// The C app's `crypto_extractPublicKey` encoding: `W` is `04 || X || Y` with big
/// endian coordinates; the compressed key is Y little endian with the parity of X
/// in the top bit.
fn compress(w: &[u8; 65]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (i, b) in out.iter_mut().enumerate() {
        *b = w[64 - i];
    }
    if w[32] & 1 != 0 {
        out[31] |= 0x80;
    }
    out
}

impl Platform for Device {
    fn version(&self) -> [u16; 3] {
        crate::VERSION
    }

    fn pin_validated(&self) -> bool {
        // SAFETY: syscall without arguments.
        let v = unsafe { sys::os_global_pin_is_validated() };
        v as u32 == sys::BOLOS_UX_OK
    }

    fn ux_locked(&self) -> bool {
        // The C app reports `!IS_UX_ALLOWED`, read from zxlib's copy of the OS UX
        // parameters, which the Rust SDK does not maintain. Its meaning is "the
        // device is locked": 0 whenever the app is usable, as in C.
        !self.pin_validated()
    }

    fn target_id(&self) -> u32 {
        sys::TARGET_ID
    }

    fn device_info(&self, out: &mut [u8]) -> usize {
        let tid = sys::TARGET_ID.to_be_bytes();
        out[..4].copy_from_slice(&tid);
        let mut n = 4;
        let mut tmp = [0u8; 64];
        // SAFETY: tmp is 64 bytes, the length passed.
        let len = (unsafe { sys::os_version(tmp.as_mut_ptr(), 64) } as u8) as usize;
        let len = len.min(64);
        out[n] = len as u8;
        out[n + 1..n + 1 + len].copy_from_slice(&tmp[..len]);
        n += 1 + len;
        // Flags: length 0.
        out[n] = 0;
        n += 1;
        // SAFETY: as above.
        let len = (unsafe { sys::os_seph_version(tmp.as_mut_ptr(), 64) } as u8) as usize;
        let len = len.min(64);
        out[n] = len as u8;
        out[n + 1..n + 1 + len].copy_from_slice(&tmp[..len]);
        n + 1 + len
    }

    fn expert(&self) -> bool {
        settings::get(settings::EXPERT_MODE)
    }

    fn blind_signing(&self) -> bool {
        settings::get(settings::BLIND_SIGNING)
    }

    fn public_key(&self, path: &[u32; 5]) -> Option<[u8; 32]> {
        // HDW_NORMAL derivation, as the C app (os_derive_bip32_with_seed_no_throw
        // with HDW_NORMAL). Never the SLIP-10 variant: it gives other addresses.
        let sk = Ed25519::derive_from_path(path);
        let pk = sk.public_key().ok()?;
        Some(compress(&pk.pubkey))
    }

    fn sign(&self, path: &[u32; 5], msg: &[u8; 32]) -> Option<[u8; 64]> {
        let sk = Ed25519::derive_from_path(path);
        let (sig, len) = sk.sign(msg).ok()?;
        if len != 64 {
            return None;
        }
        Some(sig)
    }

    fn blake2b_256(&self, data: &[u8]) -> Option<[u8; 32]> {
        let mut h = Blake2b_256::new();
        let mut out = [0u8; 32];
        h.hash(data, &mut out).ok()?;
        Some(out)
    }

    fn tx_reset(&mut self) {
        self.buffer.reset();
    }

    fn tx_append(&mut self, data: &[u8]) -> bool {
        self.buffer.append(self.ram, &mut TxFlash, data)
    }

    fn tx(&self) -> &[u8] {
        self.buffer.get(self.ram, storage::tx())
    }

    fn template_store(&mut self, data: &[u8]) {
        let len = data.len().min(TEMPLATE_BUF);
        storage::template_write(&data[..len]);
        self.template_len = len;
    }

    fn template(&self) -> &[u8] {
        &storage::template()[..self.template_len]
    }
}
