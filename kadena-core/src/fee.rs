//! V15: the maximum fee, `gasLimit` × `gasPrice`, computed exactly in decimal.
//!
//! Both values are JSON numbers as the transaction carries them (a quoted number
//! is read the same way): digits, an optional fraction, an optional exponent
//! (hosts send gas prices such as `1.0e-6`). Nothing is rounded; a value that is
//! not a non-negative number, or a fee too long to display, is refused.

/// Largest number of significant digits read from one value (values are at most
/// 299 bytes on screen).
const MAX_DIGITS: usize = 300;
/// Largest exponent magnitude accepted.
const MAX_EXP: i32 = 400;

/// `digits` × 10^(-scale).
struct Dec {
    digits: [u8; MAX_DIGITS],
    len: usize,
    scale: i32,
}

fn parse(s: &[u8]) -> Option<Dec> {
    let mut d = Dec {
        digits: [0; MAX_DIGITS],
        len: 0,
        scale: 0,
    };
    let mut i = 0;
    let push = |d: &mut Dec, b: u8| -> Option<()> {
        if d.len == MAX_DIGITS {
            return None;
        }
        d.digits[d.len] = b - b'0';
        d.len += 1;
        Some(())
    };
    // Integer part: at least one digit.
    let start = i;
    while i < s.len() && s[i].is_ascii_digit() {
        push(&mut d, s[i])?;
        i += 1;
    }
    if i == start {
        return None;
    }
    // Fraction.
    if i < s.len() && s[i] == b'.' {
        i += 1;
        let f = i;
        while i < s.len() && s[i].is_ascii_digit() {
            push(&mut d, s[i])?;
            i += 1;
        }
        if i == f {
            return None;
        }
        d.scale = (i - f) as i32;
    }
    // Exponent.
    if i < s.len() && (s[i] == b'e' || s[i] == b'E') {
        i += 1;
        let neg = match s.get(i) {
            Some(b'-') => {
                i += 1;
                true
            }
            Some(b'+') => {
                i += 1;
                false
            }
            _ => false,
        };
        let e0 = i;
        let mut e: i32 = 0;
        while i < s.len() && s[i].is_ascii_digit() {
            e = e.checked_mul(10)?.checked_add((s[i] - b'0') as i32)?;
            if e > MAX_EXP {
                return None;
            }
            i += 1;
        }
        if i == e0 {
            return None;
        }
        d.scale -= if neg { -e } else { e };
    }
    if i != s.len() {
        return None;
    }
    Some(d)
}

/// Writes `limit` × `price` in plain decimal notation (no exponent, no trailing
/// fraction zeros) into `out`; returns its length, or None if either value is not
/// a non-negative number or the result does not fit.
pub fn max_fee(limit: &[u8], price: &[u8], out: &mut [u8]) -> Option<usize> {
    let a = parse(limit)?;
    let b = parse(price)?;
    // Schoolbook product, least significant digit last.
    let mut acc = [0u32; 2 * MAX_DIGITS];
    let n = a.len + b.len;
    for i in 0..a.len {
        for j in 0..b.len {
            acc[i + j + 1] += a.digits[i] as u32 * b.digits[j] as u32;
        }
    }
    for k in (1..n).rev() {
        let c = acc[k] / 10;
        acc[k] %= 10;
        acc[k - 1] += c;
    }
    // acc[0..n] are the product's digits (acc[0] < 10 since the product has at
    // most n digits).
    let digits = &acc[..n];
    let scale = a.scale + b.scale;
    let lead = digits.iter().take_while(|d| **d == 0).count();
    let p = &digits[lead..];
    let mut w = 0usize;
    let mut put = |out: &mut [u8], b: u8| -> Option<()> {
        *out.get_mut(w)? = b;
        w += 1;
        Some(())
    };
    if p.is_empty() {
        put(out, b'0')?;
        return Some(w);
    }
    let len = p.len() as i32;
    if scale <= 0 {
        for d in p {
            put(out, b'0' + *d as u8)?;
        }
        for _ in 0..(-scale) {
            put(out, b'0')?;
        }
        return Some(w);
    }
    // Fraction digits, trailing zeros dropped.
    let int_len = len - scale;
    let frac_end = p.len() - p.iter().rev().take_while(|d| **d == 0).count();
    if int_len > 0 {
        for d in &p[..int_len as usize] {
            put(out, b'0' + *d as u8)?;
        }
    } else {
        put(out, b'0')?;
    }
    let frac_start = int_len.max(0) as usize;
    if frac_end > frac_start || (int_len < 0 && frac_end > 0) {
        put(out, b'.')?;
        for _ in 0..(-int_len).max(0) {
            put(out, b'0')?;
        }
        for d in &p[frac_start..frac_end] {
            put(out, b'0' + *d as u8)?;
        }
    }
    Some(w)
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::max_fee;
    use std::string::String;

    fn fee(l: &str, p: &str) -> Option<String> {
        let mut out = [0u8; 300];
        let n = max_fee(l.as_bytes(), p.as_bytes(), &mut out)?;
        Some(String::from_utf8(out[..n].to_vec()).unwrap())
    }

    #[test]
    fn exact_products() {
        assert_eq!(fee("600", "1.0e-6").as_deref(), Some("0.0006"));
        assert_eq!(fee("600", "1.0e-5").as_deref(), Some("0.006"));
        assert_eq!(fee("2300", "0.00000001").as_deref(), Some("0.000023"));
        assert_eq!(fee("150000", "1e+2").as_deref(), Some("15000000"));
        assert_eq!(fee("150000", "1E2").as_deref(), Some("15000000"));
        assert_eq!(fee("1500", "2.5").as_deref(), Some("3750"));
        assert_eq!(fee("3", "0.1").as_deref(), Some("0.3"));
        assert_eq!(
            fee("7", "1.011111111111111e-6").as_deref(),
            Some("0.000007077777777777777")
        );
        assert_eq!(fee("10", "0.5").as_deref(), Some("5"));
        assert_eq!(fee("0", "1.0e-6").as_deref(), Some("0"));
        assert_eq!(fee("0123", "1").as_deref(), Some("123"));
        assert_eq!(fee("1.5", "1.5").as_deref(), Some("2.25"));
        assert_eq!(fee("25", "4e-2").as_deref(), Some("1"));
        // Beyond f64 precision: exact (checked with Python's fractions.Fraction).
        assert_eq!(
            fee("99999999999999999999", "0.000000000000000000011").as_deref(),
            Some("1.099999999999999999989")
        );
    }

    #[test]
    fn refusals() {
        for (l, p) in [
            ("", "1"),
            ("1", ""),
            ("-1", "1"),
            ("1", "-1.0"),
            (".5", "1"),
            ("1.", "1"),
            ("1", "e5"),
            ("1", "1e"),
            ("1", "1e+"),
            ("1", "1x"),
            ("1", "1e401"),
            ("abc", "1"),
        ] {
            assert_eq!(fee(l, p), None, "{l} x {p}");
        }
        // Too long for the screen.
        assert_eq!(fee("1", "1e-300"), None);
        assert_eq!(fee("1", "1e+300"), None);
    }
}
