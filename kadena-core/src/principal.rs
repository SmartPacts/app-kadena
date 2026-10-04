//! V16: whether an account name is a Pact principal (pact-5 `Principal.hs`,
//! `principalParser`). coin binds a principal account to the guard its name
//! encodes, so its receiver cannot be created with someone else's guard; any
//! other (vanity) name takes the guard the transaction's code and data give it.
//!
//! Identifiers follow pact-5 `RuntimeParsers.style` restricted to ASCII letters
//! (a name using other letters is reported as not principal, which only adds a
//! warning). The whitespace the Haskell token parsers skip is not accepted either.

const B64URL: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
const SYMBOLS: &[u8] = b"%#+-_&$@<>=^?*!|/~";

fn ident_start(b: u8) -> bool {
    b.is_ascii_alphabetic() || SYMBOLS.contains(&b)
}

fn ident_rest(b: u8) -> bool {
    b.is_ascii_alphanumeric() || SYMBOLS.contains(&b)
}

/// One identifier at the start of `s` (not `true`/`false`); the rest.
fn ident(s: &[u8]) -> Option<&[u8]> {
    if !ident_start(*s.first()?) {
        return None;
    }
    let n = 1 + s[1..].iter().take_while(|b| ident_rest(**b)).count();
    if &s[..n] == b"true" || &s[..n] == b"false" {
        return None;
    }
    Some(&s[n..])
}

/// `ident ('.' ident ('.' ident)?)?` (nameMatcher); the rest.
fn name(s: &[u8]) -> Option<&[u8]> {
    let mut rest = ident(s)?;
    for _ in 0..2 {
        match rest.strip_prefix(b".").and_then(ident) {
            Some(r) => rest = r,
            None => break,
        }
    }
    Some(rest)
}

/// `ident ('.' ident)?` (moduleNameParser); the rest.
fn module(s: &[u8]) -> Option<&[u8]> {
    let rest = ident(s)?;
    Some(rest.strip_prefix(b".").and_then(ident).unwrap_or(rest))
}

/// 43 base64url characters (an unpadded hash); the rest.
fn hash(s: &[u8]) -> Option<&[u8]> {
    if s.len() < 43 || !s[..43].iter().all(|b| B64URL.contains(b)) {
        return None;
    }
    Some(&s[43..])
}

fn colon(s: &[u8]) -> Option<&[u8]> {
    s.strip_prefix(b":")
}

/// True if `account` parses as a Pact principal (the whole text).
pub fn is_principal(account: &[u8]) -> bool {
    let (Some(&kind), Some(b':')) = (account.first(), account.get(1)) else {
        return false;
    };
    let body = &account[2..];
    let end = |r: Option<&[u8]>| r == Some(&[][..]);
    match kind {
        b'k' => body.len() == 64 && body.iter().all(u8::is_ascii_hexdigit),
        b'w' => end(hash(body).and_then(colon).and_then(name)),
        // A keyset name `ns.name`, or (legacy) any non-empty text.
        b'r' => !body.is_empty(),
        b'u' => end(name(body).and_then(colon).and_then(hash)),
        b'm' => end(module(body).and_then(colon).and_then(name)),
        b'p' => end(hash(body).and_then(colon).and_then(name)),
        b'c' => end(hash(body)),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::is_principal as p;
    use std::format;

    const H: &str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNO_-";

    #[test]
    fn principals() {
        let k = "k:de12b5e16b93fe81ca4d70656bee4334f2e40f9f28b9796e792d28f2cead74ad";
        assert!(p(k.as_bytes()));
        assert!(p(k.to_uppercase().replacen("K:", "k:", 1).as_bytes()));
        for s in [
            &format!("w:{H}:keys-all"),
            &format!("w:{H}:free.my-pred"),
            "r:free.my-keyset",
            "r:anything at all",
            &format!("u:free.mod.fn:{H}"),
            &format!("u:fn:{H}"),
            "m:free.mod:guard-fn",
            "m:mod:free.mod.fn",
            &format!("p:{H}:free.mod.pact"),
            &format!("c:{H}"),
        ] {
            assert!(p(s.as_bytes()), "{s}");
        }
    }

    #[test]
    fn not_principals() {
        let long = format!("k:{}", "a".repeat(65));
        for s in [
            "bob",
            "alice",
            "",
            "k:",
            "k:bob",
            "k:de12b5e16b93fe81ca4d70656bee4334f2e40f9f28b9796e792d28f2cead74a",
            long.as_str(),
            "x:foo",
            "K:de12b5e16b93fe81ca4d70656bee4334f2e40f9f28b9796e792d28f2cead74ad",
            "w:short:keys-all",
            &format!("w:{H}"),
            &format!("w:{H}:"),
            &format!("w:{H}:9bad"),
            "r:",
            &format!("u:free.mod.fn:{H}x"),
            &format!("u:1bad:{H}"),
            "m:free.mod",
            "m:true:fn",
            &format!("p:{H}:"),
            &format!("c:{H}x"),
            &format!("c:{}", &H[..42]),
            "k\u{a0}xyz",
        ] {
            assert!(!p(s.as_bytes()), "{s}");
        }
    }
}
