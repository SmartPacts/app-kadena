//! Screen text for review values (divergence V13).
//!
//! Values are raw JSON bytes. A byte outside printable ASCII is shown as `\xNN`
//! (uppercase hex), on every device, so that nothing invisible or confusable
//! reaches the screen: C1 controls (U+0080-U+009F), NBSP (U+00A0) and the soft
//! hyphen (U+00AD) are valid in Kadena account names, and a font may draw them
//! as nothing or as a space. The signed bytes are not changed. A literal `\x`
//! cannot occur in a value: the tokenizer refuses that JSON escape.

const HEX: &[u8; 16] = b"0123456789ABCDEF";

/// Calls `out` with the screen text of `bytes`, piece by piece.
pub fn escape<F: FnMut(&[u8])>(bytes: &[u8], mut out: F) {
    let mut start = 0;
    for (i, b) in bytes.iter().enumerate() {
        if (0x20..0x7F).contains(b) {
            continue;
        }
        out(&bytes[start..i]);
        out(&[b'\\', b'x', HEX[(b >> 4) as usize], HEX[(b & 15) as usize]]);
        start = i + 1;
    }
    out(&bytes[start..]);
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::escape;
    use std::vec::Vec;

    fn shown(b: &[u8]) -> Vec<u8> {
        let mut v = Vec::new();
        escape(b, |p| v.extend_from_slice(p));
        v
    }

    #[test]
    fn printable_ascii_is_unchanged() {
        let all: Vec<u8> = (0x20..0x7F).collect();
        assert_eq!(shown(&all), all);
    }

    #[test]
    fn everything_else_is_an_explicit_escape() {
        // C1 NEL, NBSP, soft hyphen (UTF-8), DEL, a C0 control, a stray byte.
        assert_eq!(shown(b"bob\xC2\x85"), b"bob\\xC2\\x85");
        assert_eq!(shown(b"bob\xC2\xA0x"), b"bob\\xC2\\xA0x");
        assert_eq!(shown(b"b\xC2\xADob"), b"b\\xC2\\xADob");
        assert_eq!(shown(b"\x7F\x01\xFF"), b"\\x7F\\x01\\xFF");
        assert_eq!(shown(b""), b"");
    }
}
