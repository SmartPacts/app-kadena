//! Parse + validate entry points (`parser_parse`, `parser_validate`, C app
//! `app/src/parser.c` and `common/tx.c:tx_parse`).

use crate::error::ParserError;
use crate::items::{
    find_device_signer, hex_lower, ItemArray, ItemCrypto, ItemsError, TxType, TITLE_BUF, VALUE_BUF,
};
use crate::jsmn::{self, JsmnError, Token};
use crate::json::{check_key_integrity, Json};

/// JSON token cap (`MAX_NUMBER_OF_TOKENS`, json_parser.h): 110 on Nano X, 768 elsewhere.
#[cfg(target_os = "nanox")]
pub const MAX_TOKENS: usize = 110;
#[cfg(not(target_os = "nanox"))]
pub const MAX_TOKENS: usize = 768;

/// Length of a transaction hash, in bytes (`HASH_LEN`).
pub const HASH_LEN: usize = 32;

/// Crypto needed while parsing.
pub trait ParseCrypto: ItemCrypto {
    fn blake2b_256(&self, data: &[u8]) -> Option<[u8; 32]>;
}

/// Standard base64 with padding (zxlib `base64_encode`).
pub fn base64_32(data: &[u8; 32], out: &mut [u8; 44]) {
    const CS: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut o = 0;
    let mut i = 0;
    while i + 3 <= 32 {
        let v = ((data[i] as u32) << 16) | ((data[i + 1] as u32) << 8) | data[i + 2] as u32;
        out[o] = CS[(v >> 18) as usize & 63];
        out[o + 1] = CS[(v >> 12) as usize & 63];
        out[o + 2] = CS[(v >> 6) as usize & 63];
        out[o + 3] = CS[v as usize & 63];
        o += 4;
        i += 3;
    }
    // 32 = 30 + 2 remaining bytes
    let v = ((data[30] as u32) << 16) | ((data[31] as u32) << 8);
    out[o] = CS[(v >> 18) as usize & 63];
    out[o + 1] = CS[(v >> 12) as usize & 63];
    out[o + 2] = CS[(v >> 6) as usize & 63];
    out[o + 3] = b'=';
}

/// The parsed transaction: tokens, review items and the display hash.
pub struct Parsed<const T: usize> {
    tokens: [Token; T],
    ntok: usize,
    /// Length of the JSON the tokens refer to.
    json_len: usize,
    pub items: ItemArray,
    /// URL-safe base64 of the hash (the first 43 bytes are displayed).
    b64: [u8; 44],
    pub tx_type: TxType,
}

impl<const T: usize> Default for Parsed<T> {
    fn default() -> Self {
        Self::new()
    }
}

fn items_to_parser(r: Result<(), ItemsError>) -> Result<(), ParserError> {
    r.map_err(|e| match e {
        ItemsError::UnexpectedCharacters => ParserError::UnexpectedCharacters,
        _ => ParserError::UnexpectedError,
    })
}

impl<const T: usize> Parsed<T> {
    pub const fn new() -> Self {
        Parsed {
            tokens: [Token::EMPTY; T],
            ntok: 0,
            json_len: 0,
            items: ItemArray::new(),
            b64: [0; 44],
            tx_type: TxType::Json,
        }
    }

    pub fn json<'a>(&'a self, buf: &'a [u8]) -> Json<'a> {
        let end = self.json_len.min(buf.len());
        Json {
            buf: &buf[..end],
            tokens: &self.tokens[..self.ntok],
        }
    }

    /// `_read_json_tx` → `json_parse`, plus divergences V4, V12 and V18.
    pub fn read_json(&mut self, buf: &[u8]) -> Result<(), ParserError> {
        self.ntok = 0;
        self.json_len = buf.len();
        // V12: every signed byte is part of the one JSON value that is reviewed.
        // The tokenizer stops at a NUL, so a NUL anywhere is refused first.
        if buf.contains(&0) {
            return Err(ParserError::UnexpectedCharacters);
        }
        let n = match jsmn::parse(buf, &mut self.tokens) {
            Err(JsmnError::NoMem) => return Err(ParserError::JsonTooManyTokens),
            Err(JsmnError::Inval) => return Err(ParserError::UnexpectedCharacters),
            Err(JsmnError::Part) => return Err(ParserError::JsonIncompleteJson),
            Ok(0) => return Err(ParserError::JsonZeroTokens),
            Ok(n) => n,
        };
        self.ntok = n;
        // V12: nothing but whitespace after the top-level value (the tokenizer
        // accepts several top-level values).
        let root = self.tokens[0];
        // A string's span excludes its closing quote.
        let root_end = root.end as usize + usize::from(root.kind == jsmn::TokType::String);
        if !buf[root_end.min(buf.len())..]
            .iter()
            .all(|b| matches!(b, b' ' | b'\t' | b'\n' | b'\r'))
        {
            return Err(ParserError::UnexpectedUnparsedBytes);
        }
        check_key_integrity(&self.json(buf))
    }

    /// Stores the review items and the display hash (`items_initItems` +
    /// `items_storeItems`). `json_buf` is the JSON that was tokenized (unused
    /// for the hash type); `hash_input` is the raw 32-byte hash for the hash type.
    pub fn store_items<C: ParseCrypto>(
        &mut self,
        crypto: &C,
        tx_type: TxType,
        json_buf: &[u8],
        hash_input: Option<&[u8; 32]>,
        expert: bool,
    ) -> Result<(), ParserError> {
        self.tx_type = tx_type;
        self.items.init();
        if tx_type != TxType::Hash {
            let json = Json {
                buf: &json_buf[..self.json_len.min(json_buf.len())],
                tokens: &self.tokens[..self.ntok],
            };
            // F7: signature verifiers (Pact 5) grant capabilities the review
            // cannot show; refuse rather than ignore them.
            let mut verifiers = 0u16;
            if json
                .object_get_value(0, b"verifiers", &mut verifiers)
                .is_ok()
            {
                return Err(ParserError::UnexpectedValue);
            }
            // V9: review the device's own signer entry.
            let pk = crypto.address().ok_or(ParserError::UnexpectedError)?;
            let mut device_hex = [0u8; 64];
            hex_lower(&pk, &mut device_hex);
            let (signer, nsigners) = find_device_signer(&json, &device_hex)?;
            items_to_parser(self.items.store_tx_items(&json, signer, nsigners))?;
        } else {
            items_to_parser(self.items.store_hash_items())?;
        }
        // items_computeHash
        let digest = match (tx_type, hash_input) {
            (TxType::Hash, Some(h)) => *h,
            (TxType::Hash, None) => return Err(ParserError::UnexpectedError),
            _ => crypto
                .blake2b_256(&json_buf[..self.json_len.min(json_buf.len())])
                .ok_or(ParserError::UnexpectedError)?,
        };
        base64_32(&digest, &mut self.b64);
        for c in self.b64.iter_mut() {
            if *c == b'+' {
                *c = b'-';
            } else if *c == b'/' {
                *c = b'_';
            }
        }
        if expert {
            if tx_type != TxType::Hash {
                let json = Json {
                    buf: &json_buf[..self.json_len.min(json_buf.len())],
                    tokens: &self.tokens[..self.ntok],
                };
                items_to_parser(self.items.store_expert_meta(&json))?;
            }
            items_to_parser(self.items.store_expert_items())?;
        }
        Ok(())
    }

    pub fn num_items(&self) -> usize {
        self.items.num as usize
    }

    /// Renders item `idx`: `(title length, value length)`.
    pub fn item<C: ItemCrypto>(
        &self,
        crypto: &C,
        json_buf: &[u8],
        idx: usize,
        title: &mut [u8; TITLE_BUF],
        value: &mut [u8; VALUE_BUF],
    ) -> Result<(usize, usize), ItemsError> {
        if idx >= self.num_items() {
            return Err(ItemsError::Error);
        }
        let t = self.items.title(idx, title);
        let json = self.json(json_buf);
        let v = self.items.render(&json, &self.b64, crypto, idx, value)?;
        Ok((t, v))
    }

    /// `parser_validate`: every item must render.
    pub fn validate<C: ItemCrypto>(&self, crypto: &C, json_buf: &[u8]) -> Result<(), ParserError> {
        let mut t = [0u8; TITLE_BUF];
        let mut v = [0u8; VALUE_BUF];
        for i in 0..self.num_items() {
            self.item(crypto, json_buf, i, &mut t, &mut v)
                .map_err(|_| ParserError::UnexpectedError)?;
        }
        Ok(())
    }
}
