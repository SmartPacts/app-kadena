//! Review items: which (title, value) pairs the device shows, in which order.
//!
//! A port of the C app's `app/src/items.c` (item selection), `items_format.c`
//! (value renderers) and the title logic of `parser.c` (`parser_getItemKey`).
//! The C code builds the list into a fixed array whose slots keep the token index
//! written by a lookup even when the item is then not stored; the next item stored
//! in that slot inherits it. That behaviour decides what some items display
//! (for example `Unscoped Signer` when `pubKey` is null), so it is reproduced.

use crate::error::ParserError;
use crate::jsmn::TokType;
use crate::json::Json;

/// `MAX_NUMBER_OF_ITEMS` (items_defs.h). At most 99 items are stored.
pub const MAX_ITEMS: usize = 100;
/// Size of the C render buffer `tempVal[300]` (parser.c); values are at most 299 bytes.
pub const VALUE_BUF: usize = 300;
/// Size of the C title buffer used at validation (`MAX_ITEM_LENGTH_IN_PAGE`).
pub const TITLE_BUF: usize = 40;

pub const WARNING_TEXT: &[u8] = b"UNSAFE TRANSACTION. This transaction's code was not recognized and does not limit capabilities for all signers. Signing this transaction may make arbitrary actions on the chain including loss of all funds.";
pub const HASH_WARNING_TEXT: &[u8] = b"Blind Signing a Transaction Hash is a very unusual operation. Do not continue unless you know what you are doing";
pub const CAUTION_TEXT: &[u8] = b"'meta' field of transaction not recognized";
/// V14: a `coin.ROTATE` capability authorises a new guard that the review cannot show.
pub const ROTATE_WARNING_TEXT: &[u8] = b"Account rotation: new owner not shown";
/// V16: the receiver of a transfer is not a Pact principal.
pub const NOT_PRINCIPAL_TEXT: &[u8] = b"Recipient is not a principal account";
/// V20: a capability the review cannot verify (anything but coin.GAS and a
/// fully shown coin.TRANSFER / coin.TRANSFER_XCHAIN); its name follows as items.
pub const CAP_NOT_VERIFIED_TEXT: &[u8] = b"Capability not verified";
pub const TX_TOO_LARGE_TEXT: &[u8] =
    b"Transaction too large for Ledger to display.  PROCEED WITH GREAT CAUTION.  Do you want to continue?";

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TxType {
    Json,
    Hash,
    Transfer,
}

/// `display_title_t`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Key {
    Signing,
    OnNetwork,
    Requiring,
    OfKey,
    UnscopedSigner,
    Warning,
    Caution,
    OnChain,
    UsingGas,
    Transfer,
    From,
    To,
    Amount,
    ToChain,
    Rotate,
    /// A capability the review cannot verify: its arguments (the C app's
    /// "Unknown Capability N", without the name, which the next two show).
    Arguments,
    /// Its name without the namespace (`module.CAP`), and the namespace.
    Capability,
    Namespace,
    TransactionHash,
    SignForAddress,
    /// V9: the number of signer entries, shown when there is more than one.
    Signers,
    /// F6: a transfer capability that does not name the signer (the signature
    /// is scoped; "Unscoped Signer" is kept for a signer with no capability list).
    KeyNotInTransfer,
    /// Expert mode (F7): `exec` or `cont`, and a continuation's pact id and step.
    Payload,
    PactId,
    Step,
    /// V15: gasLimit x gasPrice, in KDA.
    MaxFee,
    /// V15: `meta.sender`.
    PayingAccount,
    /// Expert mode: `meta.creationTime`.
    Created,
    /// Expert mode: `meta.ttl`.
    Ttl,
}

/// Which `items_*ToDisplayString` renders the value.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Render {
    None,
    Std,
    Warning,
    HashWarning,
    Caution,
    TxTooLarge,
    Signing,
    Requiring,
    Amount,
    Transfer,
    CrossTransfer,
    Rotate,
    Gas,
    Hash,
    Unknown,
    SignForAddr,
    Signers,
    MaxFee,
    RotateWarning,
    NotPrincipal,
    CapNotVerified,
    /// A capability name without its namespace, and the namespace (an item only
    /// when the name has one).
    CapName,
    CapNamespace,
    Exec,
    Cont,
}

#[derive(Clone, Copy, Debug)]
pub struct Item {
    pub key: Key,
    pub token: u16,
    pub can_display: bool,
    pub render: Render,
}

impl Item {
    const ZERO: Item = Item {
        key: Key::Signing,
        token: 0,
        can_display: false,
        render: Render::None,
    };
    const INIT: Item = Item {
        key: Key::Signing,
        token: 0,
        can_display: true,
        render: Render::None,
    };
}

/// `items_error_t`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ItemsError {
    LengthZero,
    DataTooLarge,
    TooManyItems,
    Error,
    /// Refused as "Unexpected characters" (V15 integer gas fields, V21).
    UnexpectedCharacters,
}

/// The crypto the item renderers need.
pub trait ItemCrypto {
    /// Public key for the current path (`crypto_fillAddress`).
    fn address(&self) -> Option<[u8; 32]>;
}

pub struct ItemArray {
    pub items: [Item; MAX_ITEMS],
    pub num: u8,
    num_unknown: u8,
    /// V9: the signer entry the device signs for, its `pubKey` token, and the
    /// number of signer entries.
    signer: u16,
    key_tok: u16,
    nsigners: u16,
}

type IResult = Result<(), ItemsError>;

fn pe(r: Result<(), ParserError>) -> IResult {
    r.map_err(|_| ItemsError::Error)
}

/// A small bounded writer over the render buffer.
struct W<'a> {
    out: &'a mut [u8],
    n: usize,
}

impl W<'_> {
    fn put(&mut self, b: &[u8]) {
        let end = (self.n + b.len()).min(self.out.len());
        let take = end - self.n;
        self.out[self.n..end].copy_from_slice(&b[..take]);
        self.n = end;
    }
    fn put_u32(&mut self, v: u32) {
        let mut tmp = [0u8; 10];
        let mut i = tmp.len();
        let mut v = v;
        loop {
            i -= 1;
            tmp[i] = b'0' + (v % 10) as u8;
            v /= 10;
            if v == 0 {
                break;
            }
        }
        let digits = &tmp[i..];
        let mut buf = [0u8; 10];
        buf[..digits.len()].copy_from_slice(digits);
        self.put(&buf[..digits.len()]);
    }
}

pub(crate) fn hex_lower(src: &[u8], out: &mut [u8]) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for (i, b) in src.iter().enumerate() {
        out[2 * i] = HEX[(b >> 4) as usize];
        out[2 * i + 1] = HEX[(b & 0x0F) as usize];
    }
}

/// The six `meta` keys, in canonical order (parser_impl.c `keywords[]`).
const META_KEYWORDS: [&[u8]; 6] = [
    b"creationTime",
    b"ttl",
    b"gasLimit",
    b"chainId",
    b"gasPrice",
    b"sender",
];

/// `parser_validateMetaField` (parser_impl.c:161-204), with divergence V27:
/// the keys may come in any order (C required the order above, although every
/// value is read by name, so the order @kadena/client writes was a CAUTION),
/// each at most once, and no other key. The presence rule is the one the fixed
/// order implied: a key is accepted only with every key before it in
/// [`META_KEYWORDS`], so any set of keys gives the outcome its canonical order
/// gave (a reviewed transaction carries creationTime, ttl, gasLimit, chainId and
/// gasPrice; sender is optional).
pub fn validate_meta_field(json: &Json) -> Result<(), ParserError> {
    let mut meta = 0u16;
    json.object_get_value(0, b"meta", &mut meta)?;
    if json.is_null(meta) {
        return Err(ParserError::NoData);
    }
    let mut count = 0u16;
    json.object_get_element_count(meta, &mut count)?;
    if count > 6 {
        return Err(ParserError::InvalidMetaField);
    }
    let mut present = 0u8;
    for i in 0..count {
        let mut k = 0u16;
        // The C code ignores this call's result.
        let _ = json.object_get_nth_key(meta, i, &mut k);
        let t = json.tok(k);
        let len = t.end as i32 - t.start as i32;
        if len >= 40 {
            return Err(ParserError::InvalidMetaField);
        }
        let name = json.span(k);
        match META_KEYWORDS.iter().position(|kw| *kw == name) {
            Some(p) if present & (1 << p) == 0 => present |= 1 << p,
            _ => return Err(ParserError::InvalidMetaField),
        }
    }
    // A canonical prefix: no key without every key before it.
    if present & present.wrapping_add(1) != 0 {
        return Err(ParserError::InvalidMetaField);
    }
    Ok(())
}

/// `parser_getTxName` (parser_impl.c:206-236).
pub fn get_tx_name(json: &Json, cap: u16) -> ParserError {
    let mut idx = cap;
    if json.object_get_value(cap, b"name", &mut idx).is_ok() {
        let name = json.span(idx);
        if json.tok(idx).is_empty() {
            return ParserError::NoData;
        }
        if name == b"coin.TRANSFER" {
            return ParserError::NameTxTransfer;
        }
        if name == b"coin.TRANSFER_XCHAIN" {
            return ParserError::NameTxTransferXchain;
        }
        if name == b"coin.ROTATE" {
            return ParserError::NameRotate;
        }
        if name == b"coin.GAS" {
            return ParserError::NameGas;
        }
    }
    ParserError::NoData
}

/// `parser_getValidClist` (parser_impl.c:238-255), for the device's own signer
/// entry (V9; C read `signers[0]`). V10: an empty clist is no clist. Pact reads
/// a missing, `null` or empty clist alike, as a signature valid for any
/// capability (pact-5 `Signer` FromJSON: `fromMaybe []`).
pub fn get_valid_clist(
    json: &Json,
    signer: u16,
    clist: &mut u16,
    num: &mut u16,
) -> Result<(), ParserError> {
    if json.object_get_value(signer, b"clist", clist).is_ok() && !json.is_null(*clist) {
        json.array_get_element_count(*clist, num)?;
        if *num > 0 {
            return Ok(());
        }
    }
    Err(ParserError::NoData)
}

/// V9: the one signer entry the device signs for, and the number of entries.
///
/// Pact keys each signature's scope by the entry's `addr`, else its `pubKey`,
/// and a later entry with the same key replaces an earlier one (pact-5
/// `mkMsgSigs`, `M.fromList`). So the entry to review is the one naming the
/// device key, and it must be the only entry naming it, as `pubKey` or `addr`, in
/// any letter case. Its `pubKey` must be exactly the lowercase hex of the device
/// key. `pubKey`/`addr` values inside signer entries must not use JSON escapes,
/// which could hide a second entry from this raw-byte comparison (escaped key
/// names are refused for the whole document, V18), nor may the capability names
/// of the device's entry (V18).
pub fn find_device_signer(json: &Json, device_hex: &[u8; 64]) -> Result<(u16, u16), ParserError> {
    let mut signers = 0u16;
    json.object_get_value(0, b"signers", &mut signers)
        .map_err(|_| ParserError::SignerNotFound)?;
    if json.tok(signers).kind != TokType::Array {
        return Err(ParserError::SignerNotFound);
    }
    let mut count = 0u16;
    json.array_get_element_count(signers, &mut count)?;
    let mut found = None;
    let mut matches = 0u16;
    for i in 0..count {
        let mut entry = 0u16;
        json.array_get_nth_element(signers, i, &mut entry)?;
        if json.tok(entry).kind != TokType::Object {
            continue;
        }
        // (Escaped key names were refused for the whole document by V18.)
        let mut names_device = false;
        for field in [&b"pubKey"[..], &b"addr"[..]] {
            let mut v = 0u16;
            if json.object_get_value(entry, field, &mut v).is_ok() {
                let text = json.span(v);
                if text.contains(&b'\\') {
                    return Err(ParserError::UnexpectedCharacters);
                }
                names_device |= text.eq_ignore_ascii_case(device_hex);
            }
        }
        if names_device {
            matches += 1;
            found = Some(entry);
        }
    }
    let entry = match (matches, found) {
        (1, Some(e)) => e,
        (0, _) => return Err(ParserError::SignerNotFound),
        _ => return Err(ParserError::SignerRepeated),
    };
    let mut pk = 0u16;
    json.object_get_value(entry, b"pubKey", &mut pk)
        .map_err(|_| ParserError::SignerNotFound)?;
    if json.tok(pk).kind != TokType::String || json.span(pk) != device_hex {
        return Err(ParserError::SignerNotFound);
    }
    // V18: capability names are compared by raw bytes, so an escape in one of
    // the device's (`coin.\u0052OTATE`) would hide what it is.
    let mut clist = 0u16;
    if json.object_get_value(entry, b"clist", &mut clist).is_ok()
        && json.tok(clist).kind == TokType::Array
    {
        let mut n = 0u16;
        json.array_get_element_count(clist, &mut n)?;
        for i in 0..n {
            let mut cap = 0u16;
            json.array_get_nth_element(clist, i, &mut cap)?;
            let mut name = 0u16;
            if json.object_get_value(cap, b"name", &mut name).is_ok()
                && json.span(name).contains(&b'\\')
            {
                return Err(ParserError::UnexpectedCharacters);
            }
        }
    }
    Ok((entry, count))
}

/// V21, V24: a transfer amount (argument 3) is shown as a number, so it must be
/// written in one of the two forms whose value is that number: a bare JSON
/// number, or Pact's decimal object `{"decimal":"<number>"}` with that single
/// key and a string value (what @kadena/client sends). The number is
/// `(0|[1-9][0-9]*)(.[0-9]+)?`. Anything else is refused: an exponent
/// (`1.0000000001e3` is 1000.0000001), a sign, a string, `{"int":...}`, other or
/// extra keys, a leading zero, or an escape (`{"decimal":"1\u0030\u0030\u0030.0"}`
/// is 1000.0 once the node unescapes it). Returns the token of the number's
/// text, which the review shows ("KDA 231", never the object).
fn check_amount(json: &Json, args: u16) -> Result<u16, ItemsError> {
    let mut amount = 0u16;
    pe(json.array_get_nth_element(args, 2, &mut amount))?;
    let text = match json.tok(amount).kind {
        TokType::Primitive => amount,
        TokType::Object => {
            let (mut n, mut key, mut value) = (0u16, 0u16, 0u16);
            pe(json.object_get_element_count(amount, &mut n))?;
            if n != 1 {
                return Err(ItemsError::UnexpectedCharacters);
            }
            pe(json.object_get_nth_key(amount, 0, &mut key))?;
            pe(json.object_get_nth_value(amount, 0, &mut value))?;
            // R5-2: the key must be a string (the tokenizer accepts an unquoted one).
            if json.tok(key).kind != TokType::String
                || json.span(key) != b"decimal"
                || json.tok(value).kind != TokType::String
            {
                return Err(ItemsError::UnexpectedCharacters);
            }
            value
        }
        _ => return Err(ItemsError::UnexpectedCharacters),
    };
    if !is_amount(json.span(text)) {
        return Err(ItemsError::UnexpectedCharacters);
    }
    Ok(text)
}

/// Fractional digits of coin's unit (`coin.MINIMUM_PRECISION`).
const AMOUNT_PRECISION: usize = 12;

/// `(0|[1-9][0-9]*)(.[0-9]{1,12})?`. V25: at most 12 fractional digits, coin's
/// precision; pact-5 rounds a longer JSON number (at 255 places), so a longer
/// fraction would not be the amount shown.
fn is_amount(v: &[u8]) -> bool {
    let (int, frac) = match v.iter().position(|b| *b == b'.') {
        Some(dot) => (&v[..dot], Some(&v[dot + 1..])),
        None => (v, None),
    };
    let digits = |d: &[u8]| !d.is_empty() && d.iter().all(u8::is_ascii_digit);
    digits(int)
        && (int == b"0" || int[0] != b'0')
        && frac.is_none_or(|f| digits(f) && f.len() <= AMOUNT_PRECISION)
}

/// V15 (F4): the node reads `gasLimit`, `ttl` and `creationTime` as integers
/// (rounding a fraction), so only plain digits are accepted; then "Max fee" is
/// exactly what the node charges at most.
fn check_integer_meta(json: &Json, meta: u16) -> IResult {
    for field in [&b"creationTime"[..], &b"ttl"[..], &b"gasLimit"[..]] {
        let mut v = 0u16;
        if json.object_get_value(meta, field, &mut v).is_ok() {
            let text = json.span(v);
            if json.tok(v).kind != TokType::Primitive
                || text.is_empty()
                || !text.iter().all(u8::is_ascii_digit)
            {
                return Err(ItemsError::UnexpectedCharacters);
            }
        }
    }
    Ok(())
}

/// `parser_findPubKeyInClist` (parser_impl.c:97-138) with divergence V3: an argument
/// matches the signer key only if it is EXACTLY the key or `k:` followed by exactly
/// the key (C compared only the key's length, a prefix match).
pub fn find_pubkey_in_clist(json: &Json, signer: u16, key_idx: u16) -> Result<(), ParserError> {
    let mut clist = 0u16;
    let mut count = 0u16;
    if get_valid_clist(json, signer, &mut clist, &mut count).is_err() {
        return Err(ParserError::NoData);
    }
    let mut token_index = 0u16;
    let mut args = 0u16;
    let mut nargs = 0u16;
    for i in 0..count {
        json.array_get_nth_element(clist, i, &mut args)?;
        let entry = args;
        json.object_get_value(entry, b"args", &mut args)?;
        json.array_get_element_count(args, &mut nargs)?;
        for j in 0..nargs {
            if json
                .array_get_nth_element(args, j, &mut token_index)
                .is_err()
            {
                continue;
            }
            let mut value = json.span(token_index);
            if value.len() >= 2 && &value[..2] == b"k:" {
                value = &value[2..];
            }
            if value == json.span(key_idx) {
                return Ok(());
            }
        }
    }
    Err(ParserError::NoData)
}

impl Default for ItemArray {
    fn default() -> Self {
        Self::new()
    }
}

impl ItemArray {
    /// All-zero state (see `App::new`); `init` prepares it for a parse.
    pub const fn new() -> Self {
        ItemArray {
            items: [Item::ZERO; MAX_ITEMS],
            num: 0,
            num_unknown: 0,
            signer: 0,
            key_tok: 0,
            nsigners: 0,
        }
    }

    /// `items_initItems`.
    pub fn init(&mut self) {
        self.items = [Item::INIT; MAX_ITEMS];
        self.num = 0;
        self.num_unknown = 1;
    }

    /// `INCREMENT_NUM_ITEMS`.
    fn incr(&mut self) -> IResult {
        self.num += 1;
        if self.num as usize >= MAX_ITEMS {
            return Err(ItemsError::TooManyItems);
        }
        Ok(())
    }

    fn slot(&mut self) -> &mut Item {
        let n = self.num as usize;
        &mut self.items[n]
    }

    fn push(&mut self, key: Key, render: Render) -> IResult {
        let s = self.slot();
        s.key = key;
        s.render = render;
        self.incr()
    }

    /// `items_storeItems` up to (not including) `items_computeHash`, for the
    /// device's signer entry `signer` of `nsigners` (see [`find_device_signer`]).
    pub fn store_tx_items(&mut self, json: &Json, signer: u16, nsigners: u16) -> IResult {
        self.signer = signer;
        self.nsigners = nsigners;
        pe(json.object_get_value(signer, b"pubKey", &mut self.key_tok))?;
        self.push(Key::Signing, Render::Signing)?;
        self.store_network(json)?;
        if nsigners > 1 {
            self.push(Key::Signers, Render::Signers)?;
        }
        self.push(Key::Requiring, Render::Requiring)?;
        self.store_key()?;
        self.validate_signers(json)?;
        self.store_all_transfers(json)?;
        if validate_meta_field(json).is_err() {
            self.push(Key::Caution, Render::Caution)?;
        } else {
            let mut meta = 0u16;
            pe(json.object_get_value(0, b"meta", &mut meta))?;
            check_integer_meta(json, meta)?;
            self.store_chain_id(json)?;
            self.store_using_gas(json)?;
            self.store_fee_and_payer(json)?;
        }
        self.check_tx_lengths()
    }

    /// V15: "Max fee" (gasLimit x gasPrice) and "Paying account" (`meta.sender`).
    fn store_fee_and_payer(&mut self, json: &Json) -> IResult {
        let mut meta = 0u16;
        pe(json.object_get_value(0, b"meta", &mut meta))?;
        if json.is_null(meta) {
            return Ok(());
        }
        let n = self.num as usize;
        self.items[n].token = meta;
        self.push(Key::MaxFee, Render::MaxFee)?;
        let mut sender = 0u16;
        if json.object_get_value(meta, b"sender", &mut sender).is_ok() {
            let n = self.num as usize;
            self.items[n].token = sender;
            self.push(Key::PayingAccount, Render::Std)?;
        }
        Ok(())
    }

    /// Expert mode: the payload kind (F7: `exec`, or `cont` with its pact id and
    /// step), then the validity window, `meta.creationTime` and `meta.ttl`, as
    /// sent (the device has no clock).
    pub fn store_expert_meta(&mut self, json: &Json) -> IResult {
        let mut payload = 0u16;
        if json.object_get_value(0, b"payload", &mut payload).is_ok() {
            let mut v = 0u16;
            if json.object_get_value(payload, b"exec", &mut v).is_ok() {
                self.push(Key::Payload, Render::Exec)?;
            } else if json.object_get_value(payload, b"cont", &mut v).is_ok() {
                let cont = v;
                self.push(Key::Payload, Render::Cont)?;
                for (key, field) in [(Key::PactId, &b"pactId"[..]), (Key::Step, &b"step"[..])] {
                    if json.object_get_value(cont, field, &mut v).is_ok() {
                        let n = self.num as usize;
                        self.items[n].token = v;
                        self.push(key, Render::Std)?;
                    }
                }
            }
        }
        if validate_meta_field(json).is_err() {
            return Ok(());
        }
        let mut meta = 0u16;
        pe(json.object_get_value(0, b"meta", &mut meta))?;
        for (key, field) in [
            (Key::Created, &b"creationTime"[..]),
            (Key::Ttl, &b"ttl"[..]),
        ] {
            let mut v = 0u16;
            if json.object_get_value(meta, field, &mut v).is_ok() {
                let n = self.num as usize;
                self.items[n].token = v;
                self.push(key, Render::Std)?;
            }
        }
        Ok(())
    }

    pub fn store_hash_items(&mut self) -> IResult {
        self.push(Key::Warning, Render::HashWarning)?;
        self.push(Key::TransactionHash, Render::Hash)
    }

    pub fn store_expert_items(&mut self) -> IResult {
        self.push(Key::TransactionHash, Render::Hash)?;
        self.push(Key::SignForAddress, Render::SignForAddr)
    }

    fn store_network(&mut self, json: &Json) -> IResult {
        let n = self.num as usize;
        let obj = self.items[n].token;
        let r = json.object_get_value(obj, b"networkId", &mut self.items[n].token);
        pe(r)?;
        if !json.is_null(self.items[n].token) {
            self.push(Key::OnNetwork, Render::Std)?;
        }
        Ok(())
    }

    /// "Of Key": the device's own entry (V9; C showed `signers[0]`).
    fn store_key(&mut self) -> IResult {
        let n = self.num as usize;
        self.items[n].token = self.key_tok;
        self.push(Key::OfKey, Render::Std)
    }

    /// True when the signature is not bounded by a capability list the review
    /// shows (V11): the device's entry is unscoped ("WARNING"), a value is too
    /// large to show, or `meta` is not recognised ("CAUTION").
    /// V14: so is a `coin.ROTATE` capability, whose new guard the review cannot show.
    /// V20: so is any capability other than coin.GAS and a fully shown
    /// coin.TRANSFER / coin.TRANSFER_XCHAIN (coin.DEBIT, for one, lets the code
    /// move any amount).
    pub fn needs_blind(&self) -> bool {
        self.items[..self.num as usize].iter().any(|i| {
            matches!(
                i.render,
                Render::Warning
                    | Render::TxTooLarge
                    | Render::Caution
                    | Render::RotateWarning
                    | Render::CapNotVerified
            )
        })
    }

    fn unscoped_signer(&mut self, n: usize, key: Key) -> IResult {
        let of_key = self.key_tok;
        self.items[n].key = key;
        self.items[n].token = of_key;
        self.items[n].render = Render::Std;
        self.incr()
    }

    fn validate_signers(&mut self, json: &Json) -> IResult {
        let n = self.num as usize;
        let mut count = 0u16;
        if get_valid_clist(json, self.signer, &mut self.items[n].token, &mut count).is_err() {
            return self.unscoped_signer(n, Key::UnscopedSigner);
        }
        let clist = self.items[n].token;
        pe(json.array_get_element_count(clist, &mut count))?;
        let mut token_index = 0u16;
        // `for (uint8_t i = 0; i < (uint8_t)clist_element_count; i++)`
        for i in 0..(count as u8) {
            if json
                .array_get_nth_element(clist, i as u16, &mut token_index)
                .is_ok()
                && get_tx_name(json, token_index) == ParserError::NameTxTransfer
                && find_pubkey_in_clist(json, self.signer, self.key_tok).is_err()
            {
                // F6: scoped, but no transfer names this key.
                return self.unscoped_signer(n, Key::KeyNotInTransfer);
            }
        }
        // No transfer found
        self.items[n].token = 0;
        Ok(())
    }

    fn store_all_transfers(&mut self, json: &Json) -> IResult {
        let mut curr = self.num as usize;
        let mut token_index = 0u16;
        let mut clist = 0u16;
        let mut count = 0u16;
        if get_valid_clist(json, self.signer, &mut clist, &mut count).is_ok() {
            for i in 0..count {
                if json
                    .array_get_nth_element(clist, i, &mut token_index)
                    .is_ok()
                {
                    match get_tx_name(json, token_index) {
                        ParserError::NameTxTransfer => {
                            self.items[curr].token = token_index;
                            self.store_tx_item(json, token_index)?;
                        }
                        ParserError::NameTxTransferXchain => {
                            self.items[curr].token = token_index;
                            self.store_tx_cross_item(json, token_index)?;
                        }
                        ParserError::NameRotate => {
                            self.items[curr].token = token_index;
                            self.store_tx_rotate_item(json, token_index)?;
                            // V14, whatever the arguments.
                            self.push(Key::Warning, Render::RotateWarning)?;
                        }
                        ParserError::NameGas => {}
                        _ => {
                            self.items[curr].token = token_index;
                            let cap = token_index;
                            pe(json.object_get_value(cap, b"args", &mut token_index))?;
                            let mut nargs = 0u16;
                            pe(json.array_get_element_count(token_index, &mut nargs))?;
                            self.store_unverified(json, cap, nargs, token_index, true)?;
                        }
                    }
                }
                if self.num as usize >= MAX_ITEMS {
                    return Err(ItemsError::TooManyItems);
                }
                curr = self.num as usize;
            }
        } else {
            // Missing, null or empty clist (V10)
            self.push(Key::Warning, Render::Warning)?;
            self.items[curr].token = 0;
        }
        Ok(())
    }

    fn store_args_items(
        &mut self,
        json: &Json,
        args: u16,
        n_amount_keys: &[(Key, Render)],
    ) -> IResult {
        for (pos, (key, render)) in n_amount_keys.iter().enumerate() {
            let n = self.num as usize;
            self.items[n].key = *key;
            pe(json.array_get_nth_element(args, pos as u16, &mut self.items[n].token))?;
            self.items[n].render = *render;
            self.incr()?;
        }
        Ok(())
    }

    fn store_tx_item(&mut self, json: &Json, cap: u16) -> IResult {
        let mut args = 0u16;
        let mut nargs = 0u16;
        pe(json.object_get_value(cap, b"args", &mut args))?;
        pe(json.array_get_element_count(args, &mut nargs))?;
        if nargs == 3 {
            let number = check_amount(json, args)?;
            self.push(Key::Transfer, Render::Transfer)?;
            self.store_args_items(
                json,
                args,
                &[
                    (Key::From, Render::Std),
                    (Key::To, Render::Std),
                    (Key::Amount, Render::Amount),
                ],
            )?;
            // V24: the Amount item shows the number, not a decimal object.
            self.items[self.num as usize - 1].token = number;
            self.check_receiver(json, args)
        } else {
            self.store_unverified(json, cap, nargs, args, true)
        }
    }

    fn store_tx_cross_item(&mut self, json: &Json, cap: u16) -> IResult {
        let mut args = 0u16;
        let mut nargs = 0u16;
        pe(json.object_get_value(cap, b"args", &mut args))?;
        pe(json.array_get_element_count(args, &mut nargs))?;
        if nargs == 4 {
            let number = check_amount(json, args)?;
            self.push(Key::Transfer, Render::CrossTransfer)?;
            self.store_args_items(
                json,
                args,
                &[
                    (Key::From, Render::Std),
                    (Key::To, Render::Std),
                    (Key::Amount, Render::Amount),
                    (Key::ToChain, Render::Std),
                ],
            )?;
            // V24: the Amount item shows the number, not a decimal object.
            self.items[self.num as usize - 2].token = number;
            self.check_receiver(json, args)
        } else {
            self.store_unverified(json, cap, nargs, args, true)
        }
    }

    /// A capability the review cannot verify, as separate items, each shown
    /// whole: with `warn` (V20), "WARNING: Capability not verified", which makes
    /// the review a blind-signing one; then "Capability: <module>.<NAME>",
    /// "Namespace: <namespace>" only when the name has one (a placeholder could
    /// be read as a namespace: `none` is a valid one, R7-1), and its arguments. A namespaced
    /// name is never shown in one piece, where paging would split it.
    fn store_unverified(
        &mut self,
        json: &Json,
        cap: u16,
        nargs: u16,
        args: u16,
        warn: bool,
    ) -> IResult {
        if warn {
            self.slot().token = cap;
            self.push(Key::Warning, Render::CapNotVerified)?;
        }
        self.slot().token = cap;
        self.push(Key::Capability, Render::CapName)?;
        let mut name = cap;
        if json.object_get_value(cap, b"name", &mut name).is_ok()
            && split_namespace(json.span(name)).0.is_some()
        {
            self.slot().token = cap;
            self.push(Key::Namespace, Render::CapNamespace)?;
        }
        self.slot().token = cap;
        self.store_unknown_item(json, nargs, args)
    }

    /// V16: a WARNING after a transfer whose receiver (argument 2) is not a
    /// Pact principal. Only a string's span can parse as one (a number, object or
    /// array span cannot start with `x:`).
    fn check_receiver(&mut self, json: &Json, args: u16) -> IResult {
        let mut to = 0u16;
        pe(json.array_get_nth_element(args, 1, &mut to))?;
        if !crate::principal::is_principal(json.span(to)) {
            self.push(Key::Warning, Render::NotPrincipal)?;
        }
        Ok(())
    }

    fn store_tx_rotate_item(&mut self, json: &Json, cap: u16) -> IResult {
        let mut args = 0u16;
        let mut nargs = 0u16;
        pe(json.object_get_value(cap, b"args", &mut args))?;
        pe(json.array_get_element_count(args, &mut nargs))?;
        if nargs == 1 {
            self.push(Key::Rotate, Render::Rotate)
        } else {
            // V14's own warning follows.
            self.store_unverified(json, cap, nargs, args, false)
        }
    }

    fn store_unknown_item(&mut self, json: &Json, nargs: u16, args: u16) -> IResult {
        let n = self.num as usize;
        self.items[n].key = Key::Arguments;
        self.num_unknown = self.num_unknown.wrapping_add(1);
        self.items[n].render = Render::Unknown;
        let t = json.tok(args);
        if nargs > 5 || (t.end as i32 - t.start as i32) > 256 {
            self.items[n].can_display = false;
        }
        self.incr()
    }

    fn store_chain_id(&mut self, json: &Json) -> IResult {
        let n = self.num as usize;
        pe(json.object_get_value(0, b"meta", &mut self.items[n].token))?;
        if !json.is_null(self.items[n].token) {
            let meta = self.items[n].token;
            pe(json.object_get_value(meta, b"chainId", &mut self.items[n].token))?;
            if !json.is_null(self.items[n].token) {
                self.push(Key::OnChain, Render::Std)?;
            }
        }
        Ok(())
    }

    fn store_using_gas(&mut self, json: &Json) -> IResult {
        let n = self.num as usize;
        pe(json.object_get_value(0, b"meta", &mut self.items[n].token))?;
        if !json.is_null(self.items[n].token) {
            self.push(Key::UsingGas, Render::Gas)?;
        } else {
            self.items[n].token = 0;
        }
        Ok(())
    }

    fn check_tx_lengths(&mut self) -> IResult {
        for i in 0..self.num as usize {
            if !self.items[i].can_display {
                return self.push(Key::Warning, Render::TxTooLarge);
            }
        }
        Ok(())
    }

    /// Title of item `idx`, as shown when the items are displayed in order
    /// (`parser_getItemKey`: the `%d` counters count items of that kind up to
    /// and including `idx`; transfers and cross-chain transfers share one).
    pub fn title(&self, idx: usize, out: &mut [u8; TITLE_BUF]) -> usize {
        let mut w = W { out, n: 0 };
        match self.items[idx].key {
            Key::Signing => w.put(b"Signing"),
            Key::OnNetwork => w.put(b"On Network"),
            Key::Requiring => w.put(b"Requiring"),
            Key::OfKey => w.put(b"Of Key"),
            Key::UnscopedSigner => w.put(b"Unscoped Signer"),
            Key::KeyNotInTransfer => w.put(b"Key not in transfer"),
            Key::Payload => w.put(b"Payload"),
            Key::PactId => w.put(b"Pact ID"),
            Key::Step => w.put(b"Step"),
            Key::Warning => w.put(b"WARNING"),
            Key::Caution => w.put(b"CAUTION"),
            Key::OnChain => w.put(b"On Chain"),
            Key::UsingGas => w.put(b"Using Gas"),
            Key::From => w.put(b"From"),
            Key::To => w.put(b"To"),
            Key::Amount => w.put(b"Amount"),
            Key::ToChain => w.put(b"To Chain"),
            Key::Rotate => w.put(b"Rotate for account"),
            Key::TransactionHash => w.put(b"Transaction hash"),
            Key::SignForAddress => w.put(b"Sign for Address"),
            Key::Signers => w.put(b"Signers"),
            Key::MaxFee => w.put(b"Max fee"),
            Key::PayingAccount => w.put(b"Paying account"),
            Key::Created => w.put(b"Created (unix time)"),
            Key::Ttl => w.put(b"TTL (seconds)"),
            Key::Transfer => {
                let c = self.items[1..=idx]
                    .iter()
                    .filter(|i| i.key == Key::Transfer)
                    .count() as u8;
                w.put(b"Transfer ");
                w.put_u32(c as u32);
            }
            Key::Arguments => w.put(b"Arguments"),
            Key::Capability => w.put(b"Capability"),
            Key::Namespace => w.put(b"Namespace"),
        }
        w.n
    }

    /// Renders the value of item `idx` into `out` (the `toString` callbacks of
    /// items_format.c with `outValLen = 300`). Returns the value length.
    pub fn render<C: ItemCrypto>(
        &self,
        json: &Json,
        b64_hash: &[u8; 44],
        crypto: &C,
        idx: usize,
        out: &mut [u8; VALUE_BUF],
    ) -> Result<usize, ItemsError> {
        let item = self.items[idx];
        let out_len = VALUE_BUF;
        let mut w = W { out, n: 0 };
        match item.render {
            Render::None => return Err(ItemsError::Error),
            Render::Std => {
                let len = json.tok(item.token).len() as usize;
                if len == 0 {
                    return Err(ItemsError::LengthZero);
                }
                if len >= out_len {
                    return Err(ItemsError::DataTooLarge);
                }
                w.put(json.span(item.token));
            }
            Render::Warning => w.put(WARNING_TEXT),
            Render::HashWarning => w.put(HASH_WARNING_TEXT),
            Render::Caution => w.put(CAUTION_TEXT),
            Render::TxTooLarge => w.put(TX_TOO_LARGE_TEXT),
            Render::Signing => w.put(b"Transaction"),
            Render::Requiring => w.put(b"Capabilities"),
            Render::Transfer => w.put(b"Normal Transfer"),
            Render::CrossTransfer => w.put(b"Cross-chain Transfer"),
            Render::Amount => {
                let len = json.tok(item.token).len() as usize;
                if len == 0 {
                    return Err(ItemsError::LengthZero);
                }
                // len + sizeof("KDA ") > outValLen
                if len + 5 > out_len {
                    return Err(ItemsError::DataTooLarge);
                }
                w.put(b"KDA ");
                w.put(json.span(item.token));
            }
            Render::Rotate => {
                let mut ti = 0u16;
                pe(json.object_get_value(item.token, b"args", &mut ti))?;
                let args = ti;
                pe(json.array_get_nth_element(args, 0, &mut ti))?;
                let arg_len = json.tok(ti).len() as usize;
                if arg_len + 3 > out_len {
                    return Err(ItemsError::DataTooLarge);
                }
                w.put(b"\"");
                w.put(json.span(ti));
                w.put(b"\"");
            }
            Render::Gas => {
                let mut gl = item.token;
                pe(json.object_get_value(item.token, b"gasLimit", &mut gl))?;
                let mut gp = item.token;
                pe(json.object_get_value(item.token, b"gasPrice", &mut gp))?;
                let required = json.tok(gl).len() as usize + json.tok(gp).len() as usize + 8 + 10;
                if required + 1 > out_len {
                    return Err(ItemsError::DataTooLarge);
                }
                w.put(b"at most ");
                w.put(json.span(gl));
                w.put(b" at price ");
                w.put(json.span(gp));
            }
            Render::Hash => {
                // sizeof(base64_hash) - 2 = 43: the unpadded request key.
                w.put(&b64_hash[..43]);
            }
            Render::SignForAddr => {
                let pk = crypto.address().ok_or(ItemsError::Error)?;
                let mut hex = [0u8; 64];
                hex_lower(&pk, &mut hex);
                w.put(&hex);
            }
            Render::Unknown => return render_unknown(json, &item, w.out),
            Render::Signers => w.put_u32(self.nsigners as u32),
            Render::RotateWarning => w.put(ROTATE_WARNING_TEXT),
            Render::NotPrincipal => w.put(NOT_PRINCIPAL_TEXT),
            Render::Exec => w.put(b"exec (code)"),
            Render::Cont => w.put(b"cont (continuation)"),
            Render::CapNotVerified => w.put(CAP_NOT_VERIFIED_TEXT),
            Render::CapName | Render::CapNamespace => {
                let mut name = item.token;
                pe(json.object_get_value(item.token, b"name", &mut name))?;
                let (ns, rest) = split_namespace(json.span(name));
                let text = match (item.render, ns) {
                    (Render::CapName, _) => rest,
                    (_, Some(ns)) => ns,
                    (_, None) => return Err(ItemsError::Error),
                };
                // Shown whole or refused, never cut.
                if text.is_empty() {
                    return Err(ItemsError::LengthZero);
                }
                if text.len() >= out_len {
                    return Err(ItemsError::DataTooLarge);
                }
                w.put(text);
            }
            Render::MaxFee => {
                let mut gl = item.token;
                pe(json.object_get_value(item.token, b"gasLimit", &mut gl))?;
                let mut gp = item.token;
                pe(json.object_get_value(item.token, b"gasPrice", &mut gp))?;
                w.put(b"KDA ");
                let n =
                    crate::fee::max_fee(json.span(gl), json.span(gp), &mut w.out[4..out_len - 1])
                        .ok_or(ItemsError::DataTooLarge)?;
                w.n += n;
            }
        }
        Ok(w.n)
    }
}

/// A Pact capability name is `module.NAME` or `namespace.module.NAME`; neither
/// a namespace nor a module name contains a dot. Returns (namespace, rest).
fn split_namespace(name: &[u8]) -> (Option<&[u8]>, &[u8]) {
    let dots = name.iter().filter(|b| **b == b'.').count();
    match name.iter().position(|b| *b == b'.') {
        Some(i) if dots >= 2 => (Some(&name[..i]), &name[i + 1..]),
        _ => (None, name),
    }
}

/// `items_unknownCapabilityToDisplayString` (items_format.c:235-326), without
/// the leading "name: <name>, ", which the Capability and Namespace items show.
fn render_unknown(json: &Json, item: &Item, out: &mut [u8]) -> Result<usize, ItemsError> {
    let out_len = VALUE_BUF;
    let mut ti = 0u16;
    let mut w = W { out, n: 0 };
    let mut idx = 0;

    if !item.can_display {
        let msg: &[u8] = b"args cannot be displayed on Ledger";
        if idx + msg.len() >= out_len {
            return Err(ItemsError::DataTooLarge);
        }
        w.put(msg);
        return Ok(w.n);
    }

    pe(json.object_get_value(item.token, b"args", &mut ti))?;
    let args = ti;
    let mut args_count = 0u16;
    pe(json.array_get_element_count(args, &mut args_count))?;

    if args_count != 0 {
        let mut a = 0u16;
        // `for (uint8_t i = 0; i < (uint8_t)args_count - 1; i++)`
        let last = (args_count as u8) as i32 - 1;
        let mut i: i32 = 0;
        while i < last {
            pe(json.array_get_nth_element(args, i as u16, &mut a))?;
            let t = json.tok(a);
            let raw = t.len() as usize;
            let is_str = t.kind == TokType::String;
            // sizeof("arg X: \"\",") = 11, sizeof("arg X: ,") = 9 (both count the NUL)
            let len = raw + if is_str { 11 } else { 9 };
            if idx + len > out_len {
                return Err(ItemsError::DataTooLarge);
            }
            w.put(b"arg ");
            w.put_u32((i + 1) as u32);
            w.put(b": ");
            if is_str {
                w.put(b"\"");
            }
            w.put(json.span(a));
            if is_str {
                w.put(b"\"");
            }
            w.put(b", ");
            idx += len;
            debug_assert_eq!(idx, w.n);
            i += 1;
        }
        pe(json.array_get_nth_element(args, args_count - 1, &mut a))?;
        let t = json.tok(a);
        let raw = t.len() as usize;
        let is_str = t.kind == TokType::String;
        // sizeof("arg X: \"\"") = 10, sizeof("arg X: ") = 8
        let len = raw + if is_str { 10 } else { 8 };
        if idx + len > out_len {
            return Err(ItemsError::DataTooLarge);
        }
        w.put(b"arg ");
        w.put_u32(args_count as u32);
        w.put(b": ");
        if is_str {
            w.put(b"\"");
        }
        w.put(json.span(a));
        if is_str {
            w.put(b"\"");
        }
    } else {
        let msg: &[u8] = b"no args";
        if idx + msg.len() >= out_len {
            return Err(ItemsError::DataTooLarge);
        }
        w.put(msg);
    }
    Ok(w.n)
}
