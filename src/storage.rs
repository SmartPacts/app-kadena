//! Everything the app keeps in flash, in one `.nvm_data` object.
//!
//! One `repr(C)` struct fixes the layout: the settings come first. Their initial
//! content is not all zero (the SDK's `AtomicStorage` carries validity flags), and
//! Speculos only loads the start of a Rust app's `.nvm_data` from the ELF; the two
//! transaction buffers start as zeros and are only ever written at run time.
//!
//! Aliasing: one raw pointer to the store is taken, once, from the only
//! reference ever made to the whole store; every access is a place projection
//! from it. The settings go to the NBGL settings page as a borrow that ends with
//! the call (the SDK keeps a raw pointer), and the app reads them through the same
//! raw pointer, never while the settings page runs. The transaction buffers live
//! in `UnsafeCell`s: the OS flash write goes through the cell's own pointer.
//! Callers read them only through `platform::Device`, whose `&self` reads and
//! `&mut self` writes keep every slice from outliving a write.

use core::cell::{Cell, UnsafeCell};
use core::ffi::c_void;

use kadena_core::transfer::TEMPLATE_BUF;
use ledger_device_sdk::nbgl::SETTINGS_SIZE;
use ledger_device_sdk::nvm::AtomicStorage;
use ledger_device_sdk::sys;
use ledger_device_sdk::NVMData;

/// Flash transaction buffer size: the C app's `FLASH_BUFFER_SIZE` (16384 - 1280).
pub use kadena_core::buffering::FLASH_CAP as TX_CAP;

/// A page-aligned flash buffer, written only by `nvm_write`.
#[repr(C, align(64))]
struct FlashBuf<const N: usize>(UnsafeCell<[u8; N]>);

impl<const N: usize> FlashBuf<N> {
    const fn zeroed() -> Self {
        FlashBuf(UnsafeCell::new([0; N]))
    }

    fn get(&self) -> &[u8; N] {
        // SAFETY: the only writes are `write` below, which callers never overlap
        // with a live slice (see the module comment).
        unsafe { &*self.0.get() }
    }

    /// Writes `data` at `offset`; the range must be inside the buffer.
    fn write(&self, offset: usize, data: &[u8]) {
        assert!(offset <= N && data.len() <= N - offset);
        if data.is_empty() {
            return;
        }
        // SAFETY: in bounds (checked above); the pointer comes from the cell, so
        // the flash write does not go through a shared reference; nvm_write is
        // the OS flash-write syscall.
        unsafe {
            let dst = self.0.get().cast::<u8>().add(offset);
            sys::nvm_write(
                dst as *mut c_void,
                data.as_ptr() as *mut c_void,
                data.len() as u32,
            );
        }
    }
}

#[repr(C)]
pub struct Store {
    /// Setting switches; all OFF on install.
    settings: AtomicStorage<[u8; SETTINGS_SIZE]>,
    /// Structured-transfer template (C: `N_appdata.templete_json`).
    template: FlashBuf<TEMPLATE_BUF>,
    /// Raw transaction bytes (C: `N_appdata.buffer`).
    tx: FlashBuf<TX_CAP>,
}

#[link_section = ".nvm_data"]
static mut STORE: NVMData<Store> = NVMData::new(Store {
    settings: AtomicStorage::new(&[0u8; SETTINGS_SIZE]),
    template: FlashBuf::zeroed(),
    tx: FlashBuf::zeroed(),
});

struct Base(Cell<*mut Store>);
// SAFETY: the device runs one thread.
unsafe impl Sync for Base {}
// Null until first use (all zero: the app may not have a `.data` section).
static BASE: Base = Base(Cell::new(core::ptr::null_mut()));

/// The store's address (the NVM data is position-independent, so the SDK
/// computes it), from the one reference ever made to the whole store, which ends
/// here.
#[inline(never)]
#[allow(clippy::deref_addrof)]
fn base() -> *mut Store {
    let p = BASE.0.get();
    if !p.is_null() {
        return p;
    }
    // SAFETY: single-threaded; no other reference to STORE exists or is ever made.
    let p: *mut Store = unsafe { (*(&raw mut STORE)).get_mut() };
    BASE.0.set(p);
    p
}

/// The settings switches, as a raw pointer: the NBGL settings page gets a borrow
/// of it for the duration of one call (`ui::home`), and `settings::get` reads
/// through it.
pub fn settings_ptr() -> *mut AtomicStorage<[u8; SETTINGS_SIZE]> {
    // SAFETY: a place projection inside the store; no reference is created.
    unsafe { &raw mut (*base()).settings }
}

fn tx_buf() -> &'static FlashBuf<TX_CAP> {
    // SAFETY: the buffer is only ever borrowed shared; its bytes are in an
    // UnsafeCell (see FlashBuf).
    unsafe { &(*base()).tx }
}

fn template_buf() -> &'static FlashBuf<TEMPLATE_BUF> {
    // SAFETY: as for `tx_buf`.
    unsafe { &(*base()).template }
}

pub fn tx() -> &'static [u8; TX_CAP] {
    tx_buf().get()
}

pub fn template() -> &'static [u8; TEMPLATE_BUF] {
    template_buf().get()
}

/// Writes `data` at `offset` of the transaction buffer.
pub fn tx_write(offset: usize, data: &[u8]) {
    tx_buf().write(offset, data);
}

/// Replaces the start of the template buffer with `data` (at most its size).
pub fn template_write(data: &[u8]) {
    template_buf().write(0, data);
}
