//! Token-array navigation, ported from the C app's `app/src/json/json_parser.c`.
//!
//! These helpers define which token a key or an array element resolves to, so they
//! decide what the device displays. They are kept statement-for-statement equivalent
//! to C, including writing the out-parameter on failure paths where C does, and the
//! "first match wins" rule for duplicate keys (duplicates are refused earlier by
//! [`check_key_integrity`], divergence V4).

use crate::error::{PResult, ParserError};
use crate::jsmn::{TokType, Token};

/// A tokenized JSON document: the byte buffer and its `numberOfTokens` tokens.
#[derive(Clone, Copy)]
pub struct Json<'a> {
    pub buf: &'a [u8],
    pub tokens: &'a [Token],
}

impl<'a> Json<'a> {
    pub fn n(&self) -> usize {
        self.tokens.len()
    }

    /// `json->tokens[i]`. An index at or past `numberOfTokens` reads a zeroed
    /// token in C (the array is cleared before tokenizing); reproduced here.
    pub fn tok(&self, i: u16) -> Token {
        self.tokens.get(i as usize).copied().unwrap_or(Token::EMPTY)
    }

    /// The bytes of token `i` (`buffer + start`, `end - start` bytes).
    pub fn span(&self, i: u16) -> &'a [u8] {
        let t = self.tok(i);
        self.buf
            .get(t.start as usize..t.end as usize)
            .unwrap_or(&[])
    }

    /// `array_get_element_count` (json_parser.c:21-47).
    pub fn array_get_element_count(&self, array: u16, out: &mut u16) -> PResult {
        *out = 0;
        if array as usize >= self.n() {
            return Err(ParserError::NoData);
        }
        let at = self.tok(array);
        let mut ti = array;
        let mut prev_end = at.start;
        loop {
            ti = ti.wrapping_add(1);
            if ti as usize >= self.n() {
                break;
            }
            let cur = self.tok(ti);
            if cur.start > at.end {
                break;
            }
            if cur.start <= prev_end {
                continue;
            }
            prev_end = cur.end;
            *out = out.wrapping_add(1);
        }
        Ok(())
    }

    /// `array_get_nth_element` (json_parser.c:49-78).
    pub fn array_get_nth_element(&self, array: u16, element: u16, out: &mut u16) -> PResult {
        if array as usize >= self.n() {
            return Err(ParserError::NoData);
        }
        let at = self.tok(array);
        *out = array;
        let mut count: u16 = 0;
        let mut prev_end = at.start;
        while (*out as usize) < self.n() {
            *out = out.wrapping_add(1);
            if *out as usize >= self.n() {
                break;
            }
            let cur = self.tok(*out);
            if cur.start > at.end {
                break;
            }
            if cur.start <= prev_end {
                continue;
            }
            prev_end = cur.end;
            if count == element {
                return Ok(());
            }
            count = count.wrapping_add(1);
        }
        Err(ParserError::NoData)
    }

    /// `object_get_element_count` (json_parser.c:80-109).
    pub fn object_get_element_count(&self, object: u16, out: &mut u16) -> PResult {
        *out = 0;
        if object as usize >= self.n() {
            return Err(ParserError::NoData);
        }
        let ot = self.tok(object);
        let mut ti = object.wrapping_add(1);
        let mut prev_end = ot.start;
        loop {
            if ti as usize >= self.n() {
                break;
            }
            let key = self.tok(ti);
            ti = ti.wrapping_add(1);
            if ti as usize >= self.n() {
                break;
            }
            let value = self.tok(ti);
            if key.start > ot.end {
                break;
            }
            if key.start <= prev_end {
                continue;
            }
            prev_end = value.end;
            *out = out.wrapping_add(1);
        }
        Ok(())
    }

    /// `object_get_nth_key` (json_parser.c:111-144).
    pub fn object_get_nth_key(&self, object: u16, element: u16, out: &mut u16) -> PResult {
        *out = object;
        if object as usize >= self.n() {
            return Err(ParserError::NoData);
        }
        let ot = self.tok(object);
        let mut count: u16 = 0;
        let mut prev_end = ot.start;
        *out = out.wrapping_add(1);
        loop {
            if *out as usize >= self.n() {
                break;
            }
            let key = self.tok(*out);
            *out = out.wrapping_add(1);
            if *out as usize >= self.n() {
                break;
            }
            let value = self.tok(*out);
            if key.start > ot.end {
                break;
            }
            if key.start <= prev_end {
                continue;
            }
            prev_end = value.end;
            if count == element {
                *out = out.wrapping_sub(1);
                return Ok(());
            }
            count = count.wrapping_add(1);
        }
        Err(ParserError::NoData)
    }

    /// `object_get_nth_value` (json_parser.c:146-156).
    pub fn object_get_nth_value(&self, object: u16, element: u16, out: &mut u16) -> PResult {
        if object as usize >= self.n() {
            return Err(ParserError::NoData);
        }
        self.object_get_nth_key(object, element, out)?;
        *out = out.wrapping_add(1);
        Ok(())
    }

    /// `object_get_value` (json_parser.c:158-194): the FIRST key whose raw bytes
    /// equal `key` wins.
    pub fn object_get_value(&self, object: u16, key: &[u8], out: &mut u16) -> PResult {
        if object as usize >= self.n() {
            return Err(ParserError::NoData);
        }
        let ot = self.tok(object);
        *out = object;
        let mut prev_end: i32 = ot.start as i32;
        *out = out.wrapping_add(1);
        while (*out as usize) < self.n() {
            let key_tok = self.tok(*out);
            *out = out.wrapping_add(1);
            if *out as usize >= self.n() {
                break;
            }
            let value = self.tok(*out);
            if key_tok.start > ot.end {
                break;
            }
            if (key_tok.start as i32) <= prev_end {
                continue;
            }
            prev_end = value.end as i32;
            let klen = key_tok.end as i32 - key_tok.start as i32;
            if key.len() as u16 as i32 == klen {
                let mut i = 0usize;
                while i < key.len() {
                    if self.buf.get(key_tok.start as usize + i).copied() != Some(key[i]) {
                        break;
                    }
                    i += 1;
                }
                if i == key.len() {
                    return Ok(());
                }
            }
        }
        Err(ParserError::NoData)
    }

    /// `items_isNullField` (parser_impl.c:252-261): the span is exactly `null`
    /// (a quoted `"null"` matches too, since string spans exclude the quotes).
    pub fn is_null(&self, i: u16) -> bool {
        self.span(i) == b"null" && self.tok(i).len() == 4
    }
}

/// Iterates the keys of an object in the order, and with the skipping rule,
/// that `object_get_nth_key` uses.
#[derive(Clone, Copy)]
struct ObjectKeys<'a> {
    json: Json<'a>,
    object_end: u16,
    ti: u16,
    prev_end: u16,
    done: bool,
}

impl<'a> ObjectKeys<'a> {
    fn new(json: Json<'a>, object: u16) -> Self {
        let ot = json.tok(object);
        ObjectKeys {
            json,
            object_end: ot.end,
            ti: object.wrapping_add(1),
            prev_end: ot.start,
            done: false,
        }
    }
}

impl Iterator for ObjectKeys<'_> {
    type Item = u16;
    fn next(&mut self) -> Option<u16> {
        while !self.done {
            if self.ti as usize >= self.json.n() {
                self.done = true;
                break;
            }
            let key_idx = self.ti;
            let key = self.json.tok(key_idx);
            self.ti = self.ti.wrapping_add(1);
            if self.ti as usize >= self.json.n() {
                self.done = true;
                break;
            }
            let value = self.json.tok(self.ti);
            if key.start > self.object_end {
                self.done = true;
                break;
            }
            if key.start <= self.prev_end {
                continue;
            }
            self.prev_end = value.end;
            return Some(key_idx);
        }
        None
    }
}

/// Divergences V4 and V18: the device finds object members by raw key bytes,
/// while a JSON decoder (pact-5 uses aeson) unescapes a key and then keeps one of
/// its duplicates. So, in every object of the document:
///
/// * a key containing a backslash (a JSON escape) is refused with "Unexpected
///   characters" (V18): an escaped spelling of `name`, `signers` or `meta`
///   would make the device read one member while the chain reads another;
/// * a key equal, byte for byte, to an earlier key of the same object is
///   refused with "Unexpected duplicated field" (V4), whichever duplicate the
///   node's decoder keeps.
///
/// With no backslash, two keys of a document aeson accepts (valid UTF-8, no raw
/// control characters) are equal after decoding exactly when their bytes are
/// equal. Keys are checked in document order, each against the earlier keys of
/// its object (as the C app v1.3.1 does, `parser_checkKeyIntegrity`).
pub fn check_key_integrity(json: &Json) -> PResult {
    for obj in 0..json.n() {
        let obj = obj as u16;
        if json.tok(obj).kind != TokType::Object {
            continue;
        }
        for (n, a) in ObjectKeys::new(*json, obj).enumerate() {
            let key = json.span(a);
            if key.contains(&b'\\') {
                return Err(ParserError::UnexpectedCharacters);
            }
            if ObjectKeys::new(*json, obj)
                .take(n)
                .any(|b| json.span(b) == key)
            {
                return Err(ParserError::DuplicatedField);
            }
        }
    }
    Ok(())
}
