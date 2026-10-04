//! Persistent settings: two switches, both OFF on install.

use ledger_device_sdk::nbgl::SETTINGS_SIZE;
use ledger_device_sdk::nvm::{AtomicStorage, SingleStorage};

use crate::storage;

/// Index of the "Blind signing" switch.
pub const BLIND_SIGNING: usize = 0;
/// Index of the "Expert mode" switch.
pub const EXPERT_MODE: usize = 1;

/// The storage the home screen's switches write to: a borrow for the one call
/// that hands it to the SDK (which keeps a raw pointer).
pub fn storage<'a>() -> &'a mut AtomicStorage<[u8; SETTINGS_SIZE]> {
    // SAFETY: single-threaded; the borrow is used only for the SDK call in
    // `ui::home` and no other reference to the settings is live then.
    unsafe { &mut *storage::settings_ptr() }
}

pub fn get(index: usize) -> bool {
    // SAFETY: a short shared read through the same raw pointer; the SDK writes
    // the settings only while its settings page runs, never during this read.
    unsafe { (*storage::settings_ptr()).get_ref()[index] == 1 }
}
