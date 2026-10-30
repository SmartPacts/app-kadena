//! JSON tokenizer.
//!
//! A line-by-line port of the jsmn tokenizer vendored by the C app
//! (`app/src/jsmn/jsmn.c`, non-strict mode: `JSMN_STRICT` and `JSMN_PARENT_LINKS`
//! are not defined). The accept/reject set and the produced token array are the
//! same as the C code's, because every later lookup (and therefore what the
//! device shows) is defined in terms of token indices.
//!
//! [`parse_strict`] is the tokenizer the app uses (F-3): the same scan and the
//! same tokens, plus the JSON grammar rules non-strict jsmn skips, so that a
//! document the node's decoder (aeson) rejects for its structure is refused too:
//! the top-level value must be an object, every object key a string, members
//! and elements separated by exactly one comma (none trailing), a key followed
//! by a colon, and no raw byte below 0x20 inside a string. [`parse`] keeps the
//! C behaviour for the C test vectors. Everything after the top-level object is
//! left to the caller, which refuses it (V12).
//!
//! The one place where the C code reads outside its token array is reproduced by
//! value, not by memory access: a `,` seen while the "superior" token index is -1
//! reads `tokens[-1].type`. In the C app that memory is the zeroed header of
//! `parsed_json_t` (`json_parse` clears the whole struct before tokenizing), so the
//! type it reads is always `JSMN_UNDEFINED`. This port uses `Undefined` directly.

/// Token type. Values match `jsmntype_t`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum TokType {
    Undefined = 0,
    Object = 1,
    Array = 2,
    String = 4,
    Primitive = 8,
}

/// One token: a type and a byte span `[start, end)` into the input.
/// For strings the span excludes the quotes.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Token {
    pub kind: TokType,
    pub start: u16,
    pub end: u16,
}

impl Token {
    pub const EMPTY: Token = Token {
        kind: TokType::Undefined,
        start: 0,
        end: 0,
    };

    /// Length of the span (`end - start`), as the C code computes it.
    pub fn len(&self) -> u16 {
        self.end.wrapping_sub(self.start)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// jsmn error codes (`enum jsmnerr`).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum JsmnError {
    /// JSMN_ERROR_NOMEM: not enough tokens.
    NoMem,
    /// JSMN_ERROR_INVAL: invalid character.
    Inval,
    /// JSMN_ERROR_PART: incomplete input.
    Part,
}

/// Sentinel used by jsmn for "not set" start/end.
const UNSET: u16 = 0xFFFF;

struct Parser {
    pos: usize,
    toknext: usize,
    toksuper: i32,
}

fn alloc_token(p: &mut Parser, tokens: &mut [Token]) -> Option<usize> {
    if p.toknext >= tokens.len() {
        return None;
    }
    let idx = p.toknext;
    p.toknext += 1;
    tokens[idx].start = UNSET;
    tokens[idx].end = UNSET;
    Some(idx)
}

fn is_open(t: &Token) -> bool {
    t.start != UNSET && t.end == UNSET
}

/// `jsmn_parse_primitive` (jsmn.c:56-104, non-strict branch).
fn parse_primitive(p: &mut Parser, js: &[u8], tokens: &mut [Token]) -> Result<(), JsmnError> {
    let start = p.pos;
    while p.pos < js.len() && js[p.pos] != 0 {
        match js[p.pos] {
            b':' | b'\t' | b'\r' | b'\n' | b' ' | b',' | b']' | b'}' => break,
            _ => {}
        }
        // `js[pos] < 32 || js[pos] >= 127`: bytes 0x80..=0xFF are rejected too
        // (on the device `char` is unsigned, on x86 negative; both reject).
        if js[p.pos] < 32 || js[p.pos] >= 127 {
            p.pos = start;
            return Err(JsmnError::Inval);
        }
        p.pos += 1;
    }
    // found:
    let Some(idx) = alloc_token(p, tokens) else {
        p.pos = start;
        return Err(JsmnError::NoMem);
    };
    tokens[idx] = Token {
        kind: TokType::Primitive,
        start: start as u16,
        end: p.pos as u16,
    };
    p.pos -= 1;
    Ok(())
}

fn is_hex(c: u8) -> bool {
    c.is_ascii_digit() || (b'A'..=b'F').contains(&c) || (b'a'..=b'f').contains(&c)
}

/// `jsmn_parse_string` (jsmn.c:109-177).
/// With `strict` (F-3), a raw byte below 0x20 inside the string is invalid, as in JSON.
fn parse_string(
    p: &mut Parser,
    js: &[u8],
    tokens: &mut [Token],
    strict: bool,
) -> Result<(), JsmnError> {
    let start = p.pos;
    // Skip starting quote
    p.pos += 1;
    while p.pos < js.len() && js[p.pos] != 0 {
        let c = js[p.pos];
        if strict && c < 0x20 {
            p.pos = start;
            return Err(JsmnError::Inval);
        }
        if c == b'"' {
            let Some(idx) = alloc_token(p, tokens) else {
                p.pos = start;
                return Err(JsmnError::NoMem);
            };
            tokens[idx] = Token {
                kind: TokType::String,
                start: (start + 1) as u16,
                end: p.pos as u16,
            };
            return Ok(());
        }
        if c == b'\\' && p.pos + 1 < js.len() {
            p.pos += 1;
            match js[p.pos] {
                b'"' | b'/' | b'\\' | b'b' | b'f' | b'r' | b'n' | b't' => {}
                b'u' => {
                    p.pos += 1;
                    let mut i = 0;
                    while i < 4 && p.pos < js.len() && js[p.pos] != 0 {
                        if !is_hex(js[p.pos]) {
                            p.pos = start;
                            return Err(JsmnError::Inval);
                        }
                        p.pos += 1;
                        i += 1;
                    }
                    p.pos -= 1;
                }
                _ => {
                    p.pos = start;
                    return Err(JsmnError::Inval);
                }
            }
        }
        p.pos += 1;
    }
    p.pos = start;
    Err(JsmnError::Part)
}

/// F-3: what the strict tokenizer accepts next.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Expect {
    /// The top-level value, which must be an object.
    Root,
    /// A value: after `:`, or after `,` in an array.
    Value,
    /// A value or `]`: after `[`.
    ValueOrClose,
    /// A key (a string): after `,` in an object.
    Key,
    /// A key or `}`: after `{`.
    KeyOrClose,
    /// `:` after a key.
    Colon,
    /// `,` or the container's closing bracket, after a value.
    CommaOrClose,
    /// The top-level object is closed; the rest is the caller's (V12).
    Done,
}

/// `jsmn_parse` (jsmn.c:182-355, non-strict, no parent links), starting from a
/// freshly initialised parser. Returns the number of tokens written to `tokens`.
/// Tokenizing stops at the first NUL byte, as in C.
pub fn parse(js: &[u8], tokens: &mut [Token]) -> Result<usize, JsmnError> {
    parse_impl(js, tokens, false)
}

/// [`parse`] with the JSON grammar rules of F-3 (module docs): a document that
/// breaks one is `Inval`. A document both accept gives the same tokens.
pub fn parse_strict(js: &[u8], tokens: &mut [Token]) -> Result<usize, JsmnError> {
    parse_impl(js, tokens, true)
}

/// The innermost open object or array, if any (after the `,` handling below
/// has pointed `toksuper` at it).
fn open_container(p: &Parser, tokens: &[Token]) -> Option<TokType> {
    let t = tokens.get(usize::try_from(p.toksuper).ok()?)?;
    (is_open(t) && matches!(t.kind, TokType::Array | TokType::Object)).then_some(t.kind)
}

fn parse_impl(js: &[u8], tokens: &mut [Token], strict: bool) -> Result<usize, JsmnError> {
    for t in tokens.iter_mut() {
        *t = Token::EMPTY;
    }
    let mut p = Parser {
        pos: 0,
        toknext: 0,
        toksuper: -1,
    };
    let mut count: usize = 0;
    let mut expect = Expect::Root;

    while p.pos < js.len() && js[p.pos] != 0 {
        let c = js[p.pos];
        // F-3: the grammar is checked up to the end of the top-level object.
        let check = strict && expect != Expect::Done;
        match c {
            b'{' | b'[' => {
                if check {
                    expect = match (expect, c) {
                        (Expect::Root | Expect::Value | Expect::ValueOrClose, b'{') => {
                            Expect::KeyOrClose
                        }
                        (Expect::Value | Expect::ValueOrClose, _) => Expect::ValueOrClose,
                        _ => return Err(JsmnError::Inval),
                    };
                }
                count += 1;
                let Some(idx) = alloc_token(&mut p, tokens) else {
                    return Err(JsmnError::NoMem);
                };
                tokens[idx].kind = if c == b'{' {
                    TokType::Object
                } else {
                    TokType::Array
                };
                tokens[idx].start = p.pos as u16;
                p.toksuper = p.toknext as i32 - 1;
            }
            b'}' | b']' => {
                if check
                    && !matches!(
                        (expect, c),
                        (Expect::CommaOrClose | Expect::KeyOrClose, b'}')
                            | (Expect::CommaOrClose | Expect::ValueOrClose, b']')
                    )
                {
                    return Err(JsmnError::Inval);
                }
                let kind = if c == b'}' {
                    TokType::Object
                } else {
                    TokType::Array
                };
                let mut i: isize = p.toknext as isize - 1;
                while i >= 0 {
                    let t = &mut tokens[i as usize];
                    if is_open(t) {
                        if t.kind != kind {
                            return Err(JsmnError::Inval);
                        }
                        p.toksuper = -1;
                        t.end = (p.pos + 1) as u16;
                        break;
                    }
                    i -= 1;
                }
                // Error if unmatched closing bracket
                if i == -1 {
                    return Err(JsmnError::Inval);
                }
                while i >= 0 {
                    if is_open(&tokens[i as usize]) {
                        p.toksuper = i as i32;
                        break;
                    }
                    i -= 1;
                }
                if check {
                    // `toksuper` is now the enclosing open container, or -1.
                    expect = if p.toksuper >= 0 {
                        Expect::CommaOrClose
                    } else {
                        Expect::Done
                    };
                }
            }
            b'"' => {
                if check {
                    expect = match expect {
                        Expect::Key | Expect::KeyOrClose => Expect::Colon,
                        Expect::Value | Expect::ValueOrClose => Expect::CommaOrClose,
                        _ => return Err(JsmnError::Inval),
                    };
                }
                parse_string(&mut p, js, tokens, check)?;
                count += 1;
            }
            b'\t' | b'\r' | b'\n' | b' ' => {}
            b':' => {
                if check {
                    if expect != Expect::Colon {
                        return Err(JsmnError::Inval);
                    }
                    expect = Expect::Value;
                }
                p.toksuper = p.toknext as i32 - 1;
            }
            b',' => {
                if check && expect != Expect::CommaOrClose {
                    return Err(JsmnError::Inval);
                }
                // C: `toksuper != 0xFFFF` is always true for an int holding -1..767,
                // and `tokens[-1].type` is the zeroed struct header (see module docs).
                let sup_kind = if p.toksuper >= 0 {
                    tokens[p.toksuper as usize].kind
                } else {
                    TokType::Undefined
                };
                if sup_kind != TokType::Array && sup_kind != TokType::Object {
                    let mut i: isize = p.toknext as isize - 1;
                    while i >= 0 {
                        let t = &tokens[i as usize];
                        if (t.kind == TokType::Array || t.kind == TokType::Object) && is_open(t) {
                            p.toksuper = i as i32;
                            break;
                        }
                        i -= 1;
                    }
                }
                if check {
                    expect = match open_container(&p, tokens) {
                        Some(TokType::Object) => Expect::Key,
                        Some(_) => Expect::Value,
                        None => return Err(JsmnError::Inval),
                    };
                }
            }
            _ => {
                if check {
                    // A primitive is a value, never a key.
                    expect = match expect {
                        Expect::Value | Expect::ValueOrClose => Expect::CommaOrClose,
                        _ => return Err(JsmnError::Inval),
                    };
                }
                parse_primitive(&mut p, js, tokens)?;
                count += 1;
            }
        }
        p.pos += 1;
    }

    for t in tokens[..p.toknext].iter().rev() {
        // Unmatched opened object or array
        if is_open(t) {
            return Err(JsmnError::Part);
        }
    }

    Ok(count)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tok(js: &str) -> Result<usize, JsmnError> {
        let mut t = [Token::EMPTY; 64];
        parse(js.as_bytes(), &mut t)
    }

    #[test]
    fn nested_object_token_order() {
        let mut t = [Token::EMPTY; 8];
        assert_eq!(parse(b"{\"a\":1,\"b\":{\"c\":2}}", &mut t), Ok(7));
        let kinds: [TokType; 6] = [
            TokType::Object,
            TokType::String,
            TokType::Primitive,
            TokType::String,
            TokType::Object,
            TokType::String,
        ];
        for (i, k) in kinds.iter().enumerate() {
            assert_eq!(t[i].kind, *k);
        }
    }

    #[test]
    fn rejects() {
        assert_eq!(tok("{\"a\":1"), Err(JsmnError::Part));
        assert_eq!(tok("\"abc"), Err(JsmnError::Part));
        assert_eq!(tok("[1}"), Err(JsmnError::Inval));
        assert_eq!(tok("]"), Err(JsmnError::Inval));
        assert_eq!(tok("\"\\x\""), Err(JsmnError::Inval));
        assert_eq!(tok("\"\\u12g4\""), Err(JsmnError::Inval));
        assert_eq!(tok("\"\\u12\""), Err(JsmnError::Inval));
        assert_eq!(tok("a\u{1}"), Err(JsmnError::Inval));
        assert_eq!(tok("\u{7f}"), Err(JsmnError::Inval));
        let mut t = [Token::EMPTY; 2];
        assert_eq!(parse(b"[1,2]", &mut t), Err(JsmnError::NoMem));
        assert_eq!(parse(b"\"\xff\"", &mut t), Ok(1));
        assert_eq!(parse(b"[\xff]", &mut t), Err(JsmnError::Inval));
    }

    #[test]
    fn stops_at_nul_and_keeps_escapes_raw() {
        let mut t = [Token::EMPTY; 8];
        assert_eq!(parse(b"{\"a\":\"x\\\"y\"}\0garbage{", &mut t), Ok(3));
        assert_eq!(
            &b"{\"a\":\"x\\\"y\"}"[t[2].start as usize..t[2].end as usize],
            b"x\\\"y"
        );
        // A string cut by a NUL is incomplete.
        assert_eq!(parse(b"\"ab\0cd\"", &mut t), Err(JsmnError::Part));
        // A trailing backslash at the end of the input is not an escape.
        assert_eq!(parse(b"\"ab\\", &mut t), Err(JsmnError::Part));
        // \u cut by the end of the input is incomplete, not invalid.
        assert_eq!(parse(b"\"\\u12", &mut t), Err(JsmnError::Part));
    }
}
