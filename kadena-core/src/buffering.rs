//! The transaction buffer: RAM first, flash only for large transactions.
//!
//! A port of zxlib `buffering.c` as the C app uses it (`common/tx.c`): an 8192-byte
//! RAM buffer is used while the transaction fits; the append that would overflow it
//! moves everything to the 15104-byte flash buffer, and the transaction stays there
//! until the next reset. Most transactions therefore never touch flash.

/// RAM buffer size (`RAM_BUFFER_SIZE`, every device the app supports).
pub const RAM_CAP: usize = 8192;
/// Flash buffer size (`FLASH_BUFFER_SIZE` = 16384 - 1280).
pub const FLASH_CAP: usize = 15104;

/// Where the bytes live; the storage itself belongs to the caller.
pub trait FlashWriter {
    /// Writes `data` at `offset` of the flash buffer (bounds already checked).
    fn write(&mut self, offset: usize, data: &[u8]);
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Buffering {
    ram_pos: usize,
    flash_pos: usize,
    in_ram: bool,
}

impl Default for Buffering {
    fn default() -> Self {
        Self::new()
    }
}

impl Buffering {
    pub const fn new() -> Self {
        Buffering {
            ram_pos: 0,
            flash_pos: 0,
            in_ram: true,
        }
    }

    /// `buffering_reset`.
    pub fn reset(&mut self) {
        *self = Buffering::new();
    }

    pub fn in_ram(&self) -> bool {
        self.in_ram
    }

    fn append_flash<F: FlashWriter>(&mut self, flash: &mut F, data: &[u8]) -> bool {
        if FLASH_CAP - self.flash_pos < data.len() {
            return false;
        }
        if !data.is_empty() {
            flash.write(self.flash_pos, data);
        }
        self.flash_pos += data.len();
        true
    }

    /// `buffering_append`: appends all of `data` or nothing (returns false).
    pub fn append<F: FlashWriter>(
        &mut self,
        ram: &mut [u8; RAM_CAP],
        flash: &mut F,
        data: &[u8],
    ) -> bool {
        if self.in_ram {
            if RAM_CAP - self.ram_pos >= data.len() {
                ram[self.ram_pos..self.ram_pos + data.len()].copy_from_slice(data);
                self.ram_pos += data.len();
                return true;
            }
            // RAM is full: move what it holds to flash, then append there.
            self.in_ram = false;
            let held = self.ram_pos;
            self.ram_pos = 0;
            if held > 0 {
                self.append_flash(flash, &ram[..held]);
            }
            return self.append_flash(flash, data);
        }
        self.append_flash(flash, data)
    }

    /// `buffering_get_buffer`: the buffered bytes.
    pub fn get<'a>(&self, ram: &'a [u8; RAM_CAP], flash: &'a [u8]) -> &'a [u8] {
        if self.in_ram {
            &ram[..self.ram_pos]
        } else {
            &flash[..self.flash_pos]
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::vec;
    use std::vec::Vec;

    struct Flash {
        bytes: Vec<u8>,
        writes: usize,
    }

    impl FlashWriter for Flash {
        fn write(&mut self, offset: usize, data: &[u8]) {
            self.bytes[offset..offset + data.len()].copy_from_slice(data);
            self.writes += 1;
        }
    }

    fn setup() -> (Buffering, [u8; RAM_CAP], Flash) {
        (
            Buffering::new(),
            [0; RAM_CAP],
            Flash {
                bytes: vec![0; FLASH_CAP],
                writes: 0,
            },
        )
    }

    #[test]
    fn small_transactions_never_touch_flash() {
        let (mut b, mut ram, mut flash) = setup();
        for _ in 0..32 {
            assert!(b.append(&mut ram, &mut flash, &[1u8; 250]));
        }
        assert!(b.append(&mut ram, &mut flash, &[2u8; 192]));
        assert!(b.in_ram());
        assert_eq!(b.get(&ram, &flash.bytes).len(), RAM_CAP);
        assert_eq!(flash.writes, 0);
    }

    #[test]
    fn overflowing_ram_moves_everything_to_flash() {
        let (mut b, mut ram, mut flash) = setup();
        let mut all = Vec::new();
        for i in 0..40u8 {
            let chunk = vec![i; 250];
            assert!(b.append(&mut ram, &mut flash, &chunk));
            all.extend_from_slice(&chunk);
        }
        assert!(!b.in_ram());
        assert_eq!(b.get(&ram, &flash.bytes), &all[..]);
        // Once in flash, it stays there until reset.
        assert!(b.append(&mut ram, &mut flash, b"x"));
        all.push(b'x');
        assert_eq!(b.get(&ram, &flash.bytes), &all[..]);
        b.reset();
        assert!(b.in_ram());
        assert_eq!(b.get(&ram, &flash.bytes), b"");
    }

    #[test]
    fn capacity_is_15104_and_a_failed_append_changes_nothing() {
        let (mut b, mut ram, mut flash) = setup();
        let chunk = vec![3u8; 250];
        for _ in 0..60 {
            assert!(b.append(&mut ram, &mut flash, &chunk));
        }
        assert!(b.append(&mut ram, &mut flash, &chunk[..104]));
        assert_eq!(b.get(&ram, &flash.bytes).len(), FLASH_CAP);
        assert!(!b.append(&mut ram, &mut flash, b"y"));
        assert_eq!(b.get(&ram, &flash.bytes).len(), FLASH_CAP);
        // An append too large even for flash, straight from RAM: the RAM bytes
        // are kept (moved to flash), the new bytes are not appended.
        b.reset();
        assert!(b.append(&mut ram, &mut flash, b"abc"));
        assert!(!b.append(&mut ram, &mut flash, &vec![4u8; FLASH_CAP]));
        assert_eq!(b.get(&ram, &flash.bytes), b"abc");
    }
}
