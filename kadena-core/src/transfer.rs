//! Structured transfer (INS 0x24 / legacy 0x10): the device builds the Pact
//! command JSON itself from 12 length-prefixed fields.
//!
//! Port of `parser_createJsonTemplate`, `parser_formatTxTransfer` and
//! `parser_validate_chunks` (C app `app/src/parser_impl.c:268-490`). The template
//! is byte-for-byte the C one. Divergence V2: every field is checked against a
//! per-field content allowlist before anything is built, so no field can change
//! the structure of the signed JSON or of the Pact code inside it.

use crate::error::ParserError;
use crate::items::hex_lower;

/// `TEMPLATE_JSON_BUFFER_SIZE` (common/tx.c).
pub const TEMPLATE_BUF: usize = 1280;

const RECIPIENT: usize = 0;
const RECIPIENT_CHAIN: usize = 1;
const NETWORK: usize = 2;
const AMOUNT: usize = 3;
const NAMESPACE: usize = 4;
const MODULE: usize = 5;
const GAS_PRICE: usize = 6;
const GAS_LIMIT: usize = 7;
const CREATION_TIME: usize = 8;
const CHAIN_ID: usize = 9;
const NONCE: usize = 10;
const TTL: usize = 11;
const FIELDS: usize = 12;

const TX_TYPE_TRANSFER: u8 = 0;
const TX_TYPE_TRANSFER_CREATE: u8 = 1;
const TX_TYPE_TRANSFER_CROSSCHAIN: u8 = 2;

/// Upper bound of each field (`parser_validate_chunks`); the recipient must be
/// exactly 64 bytes.
fn max_len(field: usize) -> usize {
    match field {
        RECIPIENT => 64,
        RECIPIENT_CHAIN => 2,
        NETWORK => 20,
        AMOUNT => 32,
        NAMESPACE => 63,
        MODULE => 32,
        GAS_PRICE => 20,
        GAS_LIMIT => 10,
        CREATION_TIME => 12,
        CHAIN_ID => 2,
        NONCE => 32,
        _ => 20, // TTL
    }
}

struct Reader<'a> {
    buf: &'a [u8],
    off: usize,
}

impl<'a> Reader<'a> {
    fn byte(&mut self) -> Result<u8, ParserError> {
        let b = *self
            .buf
            .get(self.off)
            .ok_or(ParserError::UnexpectedBufferEnd)?;
        self.off += 1;
        Ok(b)
    }
    fn bytes(&mut self, len: usize) -> Result<&'a [u8], ParserError> {
        if self.off + len > self.buf.len() {
            return Err(ParserError::UnexpectedBufferEnd);
        }
        let s = &self.buf[self.off..self.off + len];
        self.off += len;
        Ok(s)
    }
}

struct Out<'a> {
    buf: &'a mut [u8; TEMPLATE_BUF],
    pos: usize,
}

impl Out<'_> {
    /// `APPEND`: a short append fails the whole transfer ("Unexpected buffer end").
    fn app(&mut self, data: &[u8]) -> Result<(), ParserError> {
        if TEMPLATE_BUF - self.pos < data.len() {
            return Err(ParserError::UnexpectedBufferEnd);
        }
        self.buf[self.pos..self.pos + data.len()].copy_from_slice(data);
        self.pos += data.len();
        Ok(())
    }
}

/// Pact identifier characters (namespace, module): letters, digits and the
/// symbols the Pact lexer accepts in names.
fn is_pact_ident(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b"%#+-_&$@<>=?*!|/".contains(&b)
}

/// Consumes one or more ASCII digits at the start of `v`; None if there is none.
fn digits(v: &[u8]) -> Option<&[u8]> {
    let n = v.iter().take_while(|b| b.is_ascii_digit()).count();
    (n > 0).then(|| &v[n..])
}

/// `digits ('.' digits)?`: a number as the template pastes it into both the Pact
/// code and a JSON number position (no sign, no lone or trailing '.').
pub(crate) fn is_decimal(v: &[u8]) -> bool {
    let Some(rest) = digits(v) else {
        return false;
    };
    match rest {
        [] => true,
        [b'.', frac @ ..] => digits(frac) == Some(&[]),
        _ => false,
    }
}

/// A decimal with an optional exponent: `digits ('.' digits)? ([eE] [+-]? digits)?`.
fn is_json_number(v: &[u8]) -> bool {
    let split = v.iter().position(|b| *b == b'e' || *b == b'E');
    let Some(e) = split else {
        return is_decimal(v);
    };
    let exp = match &v[e + 1..] {
        [b'+' | b'-', rest @ ..] => rest,
        rest => rest,
    };
    is_decimal(&v[..e]) && digits(exp) == Some(&[])
}

/// V2: the per-field content allowlist. None of the allowed bytes can end a JSON
/// string, start an escape, or add JSON or Pact structure where the field is pasted,
/// and every numeric field is a well-formed number (F6).
fn field_allowed(field: usize, value: &[u8], tx_type: u8) -> bool {
    match field {
        // A public key: the template uses it as `k:<key>` and as a keyset key;
        // `k:ABC…` and `k:abc…` are different accounts, so lowercase only.
        RECIPIENT => value
            .iter()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b)),
        // Only a cross-chain transfer pastes the recipient chain.
        RECIPIENT_CHAIN if tx_type != TX_TYPE_TRANSFER_CROSSCHAIN => {
            value.iter().all(u8::is_ascii_digit)
        }
        RECIPIENT_CHAIN | CHAIN_ID => digits(value) == Some(&[]),
        NETWORK => value
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || *b == b'-' || *b == b'_' || *b == b'.'),
        // R5-3: Pact refuses an integer for `amount:decimal`, and the amount is
        // pasted as is into the code: it must have a fractional part.
        AMOUNT => is_decimal(value) && value.contains(&b'.'),
        GAS_LIMIT | CREATION_TIME | TTL => is_decimal(value),
        // A JSON number: hosts send exponents here (default "1.0e-6").
        GAS_PRICE => is_json_number(value),
        NAMESPACE | MODULE => value.iter().copied().all(is_pact_ident),
        // Free text inside a JSON string: printable ASCII except `"` and `\`.
        _ => value
            .iter()
            .all(|b| (0x20..0x7F).contains(b) && *b != b'"' && *b != b'\\'),
    }
}

/// Parses the 0x24 payload and writes the template into `out`.
/// `address` returns the device public key for the current path.
/// Returns the template length.
pub fn build<F>(
    input: &[u8],
    address: F,
    out: &mut [u8; TEMPLATE_BUF],
) -> Result<usize, ParserError>
where
    F: FnOnce() -> Option<[u8; 32]>,
{
    let mut r = Reader { buf: input, off: 0 };
    let tx_type = r.byte()?;
    if tx_type != TX_TYPE_TRANSFER
        && tx_type != TX_TYPE_TRANSFER_CREATE
        && tx_type != TX_TYPE_TRANSFER_CROSSCHAIN
    {
        return Err(ParserError::UnexpectedValue);
    }

    let mut f: [&[u8]; FIELDS] = [&[]; FIELDS];
    for field in f.iter_mut() {
        let len = r.byte()? as usize;
        if len > 0 {
            *field = r.bytes(len)?;
        }
    }
    if r.off != input.len() {
        return Err(ParserError::UnexpectedUnparsedBytes);
    }

    // parser_validate_chunks
    if f[RECIPIENT].len() != 64 {
        return Err(ParserError::ValueOutOfRange);
    }
    for (i, field) in f.iter().enumerate().skip(1) {
        if field.len() > max_len(i) {
            return Err(ParserError::ValueOutOfRange);
        }
    }

    // V2 (not in C): per-field content allowlist.
    for (i, field) in f.iter().enumerate() {
        if !field_allowed(i, field, tx_type) {
            return Err(ParserError::UnexpectedCharacters);
        }
    }

    let pk = address().ok_or(ParserError::UnexpectedError)?;
    let mut addr = [0u8; 64];
    hex_lower(&pk, &mut addr);

    format(&f, tx_type, &addr, out)
}

/// `parser_formatTxTransfer` (parser_impl.c:348-448).
fn format(
    f: &[&[u8]; FIELDS],
    tx_type: u8,
    addr: &[u8; 64],
    out: &mut [u8; TEMPLATE_BUF],
) -> Result<usize, ParserError> {
    let mut o = Out { buf: out, pos: 0 };
    let use_ns = !f[NAMESPACE].is_empty() && !f[MODULE].is_empty();
    // "%.*s.%.*s" when both are non-empty, else "coin".
    let nsmod = |o: &mut Out| -> Result<(), ParserError> {
        if use_ns {
            o.app(f[NAMESPACE])?;
            o.app(b".")?;
            o.app(f[MODULE])
        } else {
            o.app(b"coin")
        }
    };

    o.app(b"{\"networkId\":\"")?;
    o.app(f[NETWORK])?;
    o.app(b"\",\"payload\":{\"exec\":{\"data\":")?;
    if tx_type == TX_TYPE_TRANSFER {
        o.app(b"{}")?;
    } else {
        o.app(b"{\"ks\":{\"pred\":\"keys-all\",\"keys\":[\"")?;
        o.app(f[RECIPIENT])?;
        o.app(b"\"]}}")?;
    }
    o.app(b",\"code\":\"(")?;
    nsmod(&mut o)?;
    match tx_type {
        TX_TYPE_TRANSFER => o.app(b".transfer")?,
        TX_TYPE_TRANSFER_CREATE => o.app(b".transfer-create")?,
        _ => o.app(b".transfer-crosschain")?,
    }
    o.app(b" \\\"k:")?;
    o.app(addr)?;
    o.app(b"\\\" \\\"k:")?;
    o.app(f[RECIPIENT])?;
    o.app(b"\\\"")?;
    if tx_type != TX_TYPE_TRANSFER {
        o.app(b" (read-keyset \\\"ks\\\")")?;
    }
    if tx_type == TX_TYPE_TRANSFER_CROSSCHAIN {
        o.app(b" \\\"")?;
        o.app(f[RECIPIENT_CHAIN])?;
        o.app(b"\\\"")?;
    }
    o.app(b" ")?;
    o.app(f[AMOUNT])?;
    o.app(b")\"}},\"signers\":[{\"pubKey\":\"")?;
    o.app(addr)?;
    o.app(b"\",\"clist\":[{\"args\":[\"k:")?;
    o.app(addr)?;
    o.app(b"\",\"k:")?;
    o.app(f[RECIPIENT])?;
    o.app(b"\",")?;
    o.app(f[AMOUNT])?;
    if tx_type == TX_TYPE_TRANSFER_CROSSCHAIN {
        o.app(b",\"")?;
        o.app(f[RECIPIENT_CHAIN])?;
        o.app(b"\"")?;
    }
    o.app(b"],\"name\":\"")?;
    nsmod(&mut o)?;
    o.app(b".TRANSFER")?;
    if tx_type == TX_TYPE_TRANSFER_CROSSCHAIN {
        o.app(b"_XCHAIN")?;
    }
    o.app(b"\"},{\"args\":[],\"name\":\"coin.GAS\"}]}],\"meta\":{\"creationTime\":")?;
    o.app(f[CREATION_TIME])?;
    o.app(b",\"ttl\":")?;
    o.app(f[TTL])?;
    o.app(b",\"gasLimit\":")?;
    o.app(f[GAS_LIMIT])?;
    o.app(b",\"chainId\":\"")?;
    o.app(f[CHAIN_ID])?;
    o.app(b"\",\"gasPrice\":")?;
    o.app(f[GAS_PRICE])?;
    o.app(b",\"sender\":\"k:")?;
    o.app(addr)?;
    o.app(b"\"},\"nonce\":\"")?;
    o.app(f[NONCE])?;
    o.app(b"\"}")?;
    Ok(o.pos)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The template buffer's own bound (C: every APPEND checked). Unreachable
    /// through `build`, whose field caps keep templates at 1191 bytes or less, so
    /// it is exercised directly with oversized fields.
    #[test]
    fn template_overflow_fails_closed() {
        let big = [b'1'; 255];
        let mut f: [&[u8]; FIELDS] = [&big; FIELDS];
        f[NAMESPACE] = &[];
        let mut out = [0u8; TEMPLATE_BUF];
        assert_eq!(
            format(&f, 2, &[b'a'; 64], &mut out),
            Err(ParserError::UnexpectedBufferEnd)
        );
        let small: [&[u8]; FIELDS] = [b"1"; FIELDS];
        assert!(format(&small, 2, &[b'a'; 64], &mut out).is_ok());
    }
}
