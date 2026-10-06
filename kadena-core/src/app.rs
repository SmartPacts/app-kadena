//! APDU dispatcher and command state machine.
//!
//! Ported from the C app's `app/src/apdu_handler.c` (modern family 0x20-0x24),
//! `app/src/apdu_handler_legacy.c` (legacy family 0x00-0x04, 0x10),
//! `common/actions.h` (replies) and `crypto.c` (what is signed). Every status word
//! and response byte matches the C app, except the intended divergences recorded
//! in `docs/APDUSPEC.md` (numbered list):
//!
//! * V1 legacy 0x10: an item whose length byte points past the received bytes is
//!   refused with 0x6700 (C read stale buffer bytes there);
//! * V2 structured transfer: `"`, `\` and control bytes are refused (see `transfer`);
//! * V3 signer/argument match is exact (see `items::find_pubkey_in_clist`);
//! * V4 duplicate JSON keys are refused (see `json::check_key_integrity`);
//! * V5 one streaming state for both families: a modern first chunk (P1=0) resets
//!   it, and a modern middle/last chunk with no stream of its INS open answers
//!   0x6987;
//! * V6 INS 0xFF stays unhandled (0x6D00), as in C;
//! * V7 the signing path is bound to the stream: it is taken when the signing
//!   command provides it and nothing else (e.g. a legacy 0x02) can change it
//!   before the signature (C used one global path for every command);
//! * V8 every chunk of a stream carries the INS of its first chunk: any other
//!   signing INS while a stream is open answers 0x6987 and closes the stream
//!   (C took the transaction type from the last chunk's INS);
//! * V9 the review shows the signer entry that carries the device key, which must
//!   be the only one (C showed `signers[0]`), see `items::find_device_signer`;
//! * V10 an empty clist is unscoped, as a missing or null one;
//! * V11 a JSON transaction whose signature is not bounded by a capability list
//!   the review shows (unscoped, too large to show, or `meta` not recognised) is
//!   blind signing: refused unless the "Blind signing" setting is ON, and then
//!   reviewed in the blind-signing flow (C signed it with the setting OFF);
//! * V12 a JSON document must be one value: no NUL byte, and nothing but
//!   whitespace after it (C signed bytes it never parsed);
//! * V14 a `coin.ROTATE` in the device's entry is blind signing;
//! * V18 an object key with a JSON escape, anywhere, and a capability name with
//!   one in the device's entry, are refused (see `json::check_key_integrity`);
//! * V20 only coin.GAS and fully shown coin.TRANSFER / coin.TRANSFER_XCHAIN are
//!   clear-signed; any other capability of the device's entry is blind signing;
//! * V21 a transfer amount in exponent notation is refused;
//! * V23 a structured transfer (0x24, 0x10) of a token (namespace and module
//!   given) is blind signing: while its `<ns>.<module>.TRANSFER` capability is
//!   in scope, the module's own code can use the key;
//! * V24 a coin transfer amount is a bare number `digits(.digits)?` or `{"decimal":"<it>"}`;
//! * V27 the `meta` keys are recognised in any order (see `items::validate_meta_field`).

use crate::error::ParserError;
use crate::items::{ItemCrypto, ItemsError, TxType, TITLE_BUF, VALUE_BUF};
use crate::parser::{ParseCrypto, Parsed, HASH_LEN};
use crate::sw;
use crate::transfer::{self, TEMPLATE_BUF};

pub const CLA: u8 = 0x00;

pub const INS_GET_VERSION: u8 = 0x20;
pub const INS_GET_ADDR: u8 = 0x21;
pub const INS_SIGN: u8 = 0x22;
pub const INS_SIGN_HASH: u8 = 0x23;
pub const INS_SIGN_TRANSFER: u8 = 0x24;
pub const INS_LEGACY_GET_VERSION: u8 = 0x00;
pub const INS_LEGACY_VERIFY_ADDRESS: u8 = 0x01;
pub const INS_LEGACY_GET_PUBKEY: u8 = 0x02;
pub const INS_LEGACY_SIGN_JSON: u8 = 0x03;
pub const INS_LEGACY_SIGN_HASH: u8 = 0x04;
pub const INS_LEGACY_TRANSFER: u8 = 0x10;

const P1_INIT: u8 = 0;
const P1_ADD: u8 = 1;
const P1_LAST: u8 = 2;

/// 44' and 626': the only accepted path prefix.
pub const HDPATH_0: u32 = 0x8000_002C;
pub const HDPATH_1: u32 = 0x8000_0272;

const LEGACY_HEADER_LENGTH: usize = 5;
const LEGACY_CHUNK_SIZE: usize = 230;
const LEGACY_FULL_CHUNK_SIZE: usize = LEGACY_CHUNK_SIZE + LEGACY_HEADER_LENGTH;
const LEGACY_TRANSFER_NUM_ITEMS: u8 = 12;
const LEGACY_LOCAL_BUFFER_SIZE: usize = 33;

/// Largest reply payload (GET_DEVICE_INFO: 4 + 1 + 64 + 1 + 1 + 64).
pub const REPLY_MAX: usize = 160;

/// What the device must do next.
#[derive(Debug)]
pub enum Action {
    /// Send this reply now.
    Reply(Reply),
    /// Show the address review, then send [`App::address_done`].
    ReviewAddress,
    /// Show the transaction review, then send [`App::sign_done`].
    ReviewTx { blind: bool },
    /// Show the "blind signing required" screen, then send this reply.
    BlindSignRequired(Reply),
}

#[derive(Clone, Copy)]
pub struct Reply {
    pub data: [u8; REPLY_MAX],
    pub len: usize,
    pub sw: u16,
}

impl core::fmt::Debug for Reply {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Reply({:04x}, {:02x?})", self.sw, self.payload())
    }
}

impl Reply {
    pub fn sw(sw: u16) -> Reply {
        Reply {
            data: [0; REPLY_MAX],
            len: 0,
            sw,
        }
    }

    pub fn with(parts: &[&[u8]], sw: u16) -> Reply {
        let mut r = Reply::sw(sw);
        for p in parts {
            let end = (r.len + p.len()).min(REPLY_MAX);
            let take = end - r.len;
            r.data[r.len..end].copy_from_slice(&p[..take]);
            r.len = end;
        }
        r
    }

    pub fn payload(&self) -> &[u8] {
        &self.data[..self.len]
    }
}

/// Everything the state machine needs from the device.
pub trait Platform {
    /// App version (major, minor, patch).
    fn version(&self) -> [u16; 3];
    /// `os_global_pin_is_validated() == BOLOS_UX_OK`.
    fn pin_validated(&self) -> bool;
    /// `!IS_UX_ALLOWED` (GET_VERSION byte 7).
    fn ux_locked(&self) -> bool;
    fn target_id(&self) -> u32;
    /// GET_DEVICE_INFO body (`E0 01 00 00`): target id, SE version, flags, MCU version.
    fn device_info(&self, out: &mut [u8]) -> usize;
    fn expert(&self) -> bool;
    fn blind_signing(&self) -> bool;
    /// 32-byte compressed Ed25519 public key for a 5-component path (HDW_NORMAL).
    fn public_key(&self, path: &[u32; 5]) -> Option<[u8; 32]>;
    /// Ed25519 (RFC 8032, SHA-512) signature over the 32-byte message.
    fn sign(&self, path: &[u32; 5], msg: &[u8; 32]) -> Option<[u8; 64]>;
    fn blake2b_256(&self, data: &[u8]) -> Option<[u8; 32]>;
    /// Transaction buffer (15104 bytes on device).
    fn tx_reset(&mut self);
    /// Appends all of `data`, or nothing and returns false if it does not fit.
    fn tx_append(&mut self, data: &[u8]) -> bool;
    fn tx(&self) -> &[u8];
    /// Transfer template buffer (at most [`TEMPLATE_BUF`] bytes).
    fn template_store(&mut self, data: &[u8]);
    fn template(&self) -> &[u8];
}

/// Binds the platform to the current derivation path for the parser.
struct Ctx<'a, P: Platform> {
    p: &'a P,
    path: [u32; 5],
}

impl<P: Platform> ItemCrypto for Ctx<'_, P> {
    fn address(&self) -> Option<[u8; 32]> {
        self.p.public_key(&self.path)
    }
}

impl<P: Platform> ParseCrypto for Ctx<'_, P> {
    fn blake2b_256(&self, data: &[u8]) -> Option<[u8; 32]> {
        self.p.blake2b_256(data)
    }
}

/// Which command stream is open (divergence V5: one state for both families).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Stream {
    None,
    Modern(u8),
    Legacy(u8),
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum SignKind {
    Modern(TxType),
    Legacy { tx_type: TxType, msg_len: usize },
    LegacyTransfer,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Pending {
    None,
    Address { pk: [u8; 32], legacy: bool },
    Sign(SignKind),
}

pub struct App<const T: usize> {
    /// The global `hdPath` of the C app: every path-carrying command overwrites it
    /// (before its prefix check, as in C) and signing uses its current value.
    hd_path: [u32; 5],
    /// V7: the path the open or pending signing command signs with.
    sign_path: [u32; 5],
    stream: Stream,
    pending: Pending,
    // Legacy statics (apdu_handler_legacy.c:24-32).
    payload_length: u32,
    hdpath_length: u32,
    local_data: [u8; LEGACY_LOCAL_BUFFER_SIZE],
    local_data_len: u8,
    items: u8,
    item_len: u8,
    check_item_len: bool,
    parsed: Parsed<T>,
}

fn prefix_ok(path: &[u32; 5]) -> bool {
    path[0] == HDPATH_0 && path[1] == HDPATH_1
}

fn le32(b: &[u8]) -> u32 {
    u32::from_le_bytes([b[0], b[1], b[2], b[3]])
}

/// `crypto_sign` (crypto.c:64-106): hash-type messages are signed as-is (first 32
/// bytes), everything else as blake2b-256 of the whole message.
fn crypto_sign<P: Platform>(
    p: &P,
    path: &[u32; 5],
    msg: &[u8],
    tx_type: TxType,
) -> Option<[u8; 64]> {
    if msg.is_empty() {
        return None;
    }
    let hash = if tx_type == TxType::Hash {
        if msg.len() < HASH_LEN {
            return None;
        }
        let mut h = [0u8; 32];
        h.copy_from_slice(&msg[..32]);
        h
    } else {
        p.blake2b_256(msg)?
    };
    p.sign(path, &hash)
}

/// `bip32_to_str` (zxlib zxformat.h:72-119) for the 5-component path, no `m/`.
pub fn path_to_str(path: &[u32; 5], out: &mut [u8; 64]) -> usize {
    let mut n = 0;
    for (i, c) in path.iter().enumerate() {
        let mut v = c & 0x7FFF_FFFF;
        let mut tmp = [0u8; 10];
        let mut k = tmp.len();
        loop {
            k -= 1;
            tmp[k] = b'0' + (v % 10) as u8;
            v /= 10;
            if v == 0 {
                break;
            }
        }
        let digits = tmp.len() - k;
        out[n..n + digits].copy_from_slice(&tmp[k..]);
        n += digits;
        if c & 0x8000_0000 != 0 {
            out[n] = b'\'';
            n += 1;
        }
        if i != 4 {
            out[n] = b'/';
            n += 1;
        }
    }
    n
}

impl<const T: usize> Default for App<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const T: usize> App<T> {
    /// All-zero initial state, so that a `static` of it lives in `.bss` (the
    /// device link script forbids a `.data` section).
    pub const fn new() -> Self {
        App {
            hd_path: [0; 5],
            sign_path: [0; 5],
            stream: Stream::None,
            pending: Pending::None,
            payload_length: 0,
            hdpath_length: 0,
            local_data: [0; LEGACY_LOCAL_BUFFER_SIZE],
            local_data_len: 0,
            items: 0,
            item_len: 0,
            check_item_len: false,
            parsed: Parsed::new(),
        }
    }

    /// Handles one APDU. `data` is the command data (the bytes after Lc).
    pub fn handle<P: Platform>(
        &mut self,
        p: &mut P,
        cla: u8,
        ins: u8,
        p1: u8,
        p2: u8,
        data: &[u8],
    ) -> Action {
        self.pending = Pending::None;
        // GET_DEVICE_INFO is served before the CLA check (zxlib handle_generic_apdu).
        if cla == 0xE0 && ins == 0x01 && p1 == 0 && p2 == 0 {
            let mut r = Reply::sw(sw::OK);
            r.len = p.device_info(&mut r.data);
            return Action::Reply(r);
        }
        if cla != CLA {
            return Action::Reply(Reply::sw(sw::CLA_NOT_SUPPORTED));
        }
        let result = match ins {
            INS_GET_VERSION => Ok(get_version(p)),
            INS_GET_ADDR
            | INS_SIGN
            | INS_SIGN_HASH
            | INS_SIGN_TRANSFER
            | INS_LEGACY_GET_VERSION
            | INS_LEGACY_VERIFY_ADDRESS
            | INS_LEGACY_GET_PUBKEY
            | INS_LEGACY_SIGN_JSON
            | INS_LEGACY_SIGN_HASH
            | INS_LEGACY_TRANSFER => {
                if !p.pin_validated() {
                    Err(sw::COMMAND_NOT_ALLOWED)
                } else {
                    self.dispatch(p, ins, p1, p2, data)
                }
            }
            // Includes 0xFF (divergence V6: kept unhandled, as in C).
            _ => Err(sw::INS_NOT_SUPPORTED),
        };
        match result {
            Ok(a) => a,
            Err(code) => Action::Reply(Reply::sw(code)),
        }
    }

    fn dispatch<P: Platform>(
        &mut self,
        p: &mut P,
        ins: u8,
        p1: u8,
        p2: u8,
        data: &[u8],
    ) -> Result<Action, u16> {
        match ins {
            INS_GET_ADDR => self.get_addr(p, p1, data),
            INS_SIGN => self.sign_chunk(p, ins, TxType::Json, p1, data),
            INS_SIGN_HASH => self.sign_chunk(p, ins, TxType::Hash, p1, data),
            INS_SIGN_TRANSFER => self.sign_chunk(p, ins, TxType::Transfer, p1, data),
            INS_LEGACY_GET_VERSION => {
                let [major, minor, patch] = p.version();
                Ok(Action::Reply(Reply::with(
                    &[&[major as u8, minor as u8, patch as u8]],
                    sw::OK,
                )))
            }
            INS_LEGACY_VERIFY_ADDRESS => self.legacy_get_addr(p, true, ins, p1, p2, data),
            INS_LEGACY_GET_PUBKEY => self.legacy_get_addr(p, false, ins, p1, p2, data),
            INS_LEGACY_SIGN_JSON => self.legacy_sign(p, ins, true, data),
            INS_LEGACY_SIGN_HASH => self.legacy_sign(p, ins, false, data),
            _ => self.legacy_transfer(p, ins, p1, p2, data),
        }
    }

    /// `extractHDPath` (apdu_handler.c:51-65): clears the modern stream, needs at
    /// least 20 data bytes, uses exactly 20.
    fn extract_hd_path(&mut self, data: &[u8]) -> Result<(), u16> {
        if matches!(self.stream, Stream::Modern(_)) {
            self.stream = Stream::None;
        }
        if data.len() < 20 {
            return Err(sw::WRONG_LENGTH);
        }
        for (i, c) in self.hd_path.iter_mut().enumerate() {
            *c = le32(&data[4 * i..]);
        }
        if !prefix_ok(&self.hd_path) {
            return Err(sw::DATA_INVALID);
        }
        Ok(())
    }

    /// `app_fill_address`: a derivation failure is EXECUTION_ERROR.
    fn fill_address<P: Platform>(&self, p: &P) -> Result<[u8; 32], u16> {
        p.public_key(&self.hd_path).ok_or(sw::EXECUTION_ERROR)
    }

    /// INS 0x21 (apdu_handler.c:111-128).
    fn get_addr<P: Platform>(&mut self, p: &mut P, p1: u8, data: &[u8]) -> Result<Action, u16> {
        self.extract_hd_path(data)?;
        let pk = self.fill_address(p)?;
        if p1 != 0 {
            self.pending = Pending::Address { pk, legacy: false };
            return Ok(Action::ReviewAddress);
        }
        Ok(Action::Reply(Reply::with(&[&pk], sw::OK)))
    }

    /// A modern middle/last chunk: only for an open stream of the same INS (V5, V8).
    /// Any other chunk is refused and closes whatever stream was open.
    fn continue_modern(&mut self, ins: u8) -> Result<(), u16> {
        if self.stream == Stream::Modern(ins) {
            return Ok(());
        }
        self.stream = Stream::None;
        Err(sw::TX_NOT_INITIALIZED)
    }

    /// A legacy chunk: the first chunk if no stream is open, a continuation of
    /// an open stream of the same INS; while another stream is open it is
    /// refused with 0x6987 and that stream is closed (V8).
    fn legacy_first_chunk(&mut self, ins: u8) -> Result<bool, u16> {
        match self.stream {
            Stream::None => Ok(true),
            Stream::Legacy(open) if open == ins => Ok(false),
            _ => {
                self.stream = Stream::None;
                Err(sw::TX_NOT_INITIALIZED)
            }
        }
    }

    /// INS 0x22/0x23/0x24 chunking (apdu_handler.c:67-109, 130-163).
    fn sign_chunk<P: Platform>(
        &mut self,
        p: &mut P,
        ins: u8,
        tx_type: TxType,
        p1: u8,
        data: &[u8],
    ) -> Result<Action, u16> {
        match p1 {
            P1_INIT => {
                p.tx_reset();
                // V5: a first chunk closes any open stream, of either family.
                self.stream = Stream::None;
                self.extract_hd_path(data)?;
                self.sign_path = self.hd_path;
                self.stream = Stream::Modern(ins);
                Ok(Action::Reply(Reply::sw(sw::OK)))
            }
            P1_ADD => {
                self.continue_modern(ins)?;
                if !p.tx_append(data) {
                    self.stream = Stream::None;
                    return Err(sw::OUTPUT_BUFFER_TOO_SMALL);
                }
                Ok(Action::Reply(Reply::sw(sw::OK)))
            }
            P1_LAST => {
                self.continue_modern(ins)?;
                let appended = p.tx_append(data);
                self.stream = Stream::None;
                if !appended {
                    return Err(sw::OUTPUT_BUFFER_TOO_SMALL);
                }
                let len = p.tx().len();
                match self.tx_parse(p, tx_type, len) {
                    Err(e) => Ok(error_with_message(e)),
                    Ok(blind) => {
                        // Every chunk carried this INS (V8).
                        self.pending = Pending::Sign(SignKind::Modern(tx_type));
                        Ok(Action::ReviewTx { blind })
                    }
                }
            }
            _ => Err(sw::INVALID_P1P2),
        }
    }

    /// `tx_parse` = `parser_parse` + `parser_validate` over the first `len` bytes of
    /// the transaction buffer. Returns whether the review is a blind-signing one.
    fn tx_parse<P: Platform>(
        &mut self,
        p: &mut P,
        tx_type: TxType,
        len: usize,
    ) -> Result<bool, ParserError> {
        if tx_type == TxType::Hash && !p.blind_signing() {
            return Err(ParserError::BlindsignModeRequired);
        }
        if len == 0 {
            return Err(ParserError::InitContextEmpty);
        }
        let path = self.sign_path;
        match tx_type {
            TxType::Json => self.parsed.read_json(&p.tx()[..len])?,
            TxType::Hash => {
                if len != HASH_LEN {
                    return Err(ParserError::UnexpectedBufferEnd);
                }
            }
            TxType::Transfer => {
                let mut t = [0u8; TEMPLATE_BUF];
                let n = {
                    let pr: &P = p;
                    transfer::build(&pr.tx()[..len], || pr.public_key(&path), &mut t)?
                };
                p.template_store(&t[..n]);
                self.parsed.read_json(p.template())?;
            }
        }
        let expert = p.expert();
        let p: &P = p;
        let ctx = Ctx { p, path };
        let mut hash = [0u8; 32];
        let (json_buf, hash_in): (&[u8], Option<&[u8; 32]>) = match tx_type {
            TxType::Json => (&p.tx()[..len], None),
            TxType::Transfer => (p.template(), None),
            TxType::Hash => {
                hash.copy_from_slice(&p.tx()[..HASH_LEN]);
                (&[], Some(&hash))
            }
        };
        self.parsed
            .store_items(&ctx, tx_type, json_buf, hash_in, expert)?;
        self.parsed.validate(&ctx, json_buf)?;
        match tx_type {
            TxType::Hash => Ok(true),
            // V11, V14, V20. A structured transfer can need it too: a token
            // transfer (namespace and module given) names a capability of that
            // module, which the review cannot verify (V23).
            TxType::Json | TxType::Transfer if self.parsed.items.needs_blind() => {
                if p.blind_signing() {
                    Ok(true)
                } else {
                    Err(ParserError::BlindsignModeRequired)
                }
            }
            _ => Ok(false),
        }
    }

    /// `legacy_extractHDPath` (apdu_handler_legacy.c:85-132) over `buf[..rx]`.
    fn legacy_extract_hd_path(
        &mut self,
        buf: &[u8],
        rx: u64,
        offset: u64,
        check_len: bool,
    ) -> Result<(), u16> {
        if rx <= offset {
            return Err(sw::WRONG_LENGTH);
        }
        let qty = buf[offset as usize];
        if !(2..=5).contains(&qty) {
            return Err(sw::DATA_INVALID);
        }
        let len = qty as u64 * 4;
        let start = offset + 1;
        if start + len > rx {
            return Err(sw::WRONG_LENGTH);
        }
        if check_len && rx - start != len {
            return Err(sw::WRONG_LENGTH);
        }
        self.hd_path = [0; 5];
        for i in 0..qty as usize {
            self.hd_path[i] = le32(&buf[start as usize + 4 * i..]);
        }
        if !prefix_ok(&self.hd_path) {
            return Err(sw::DATA_INVALID);
        }
        self.hdpath_length = len as u32 + 1;
        Ok(())
    }

    /// INS 0x01 / 0x02 (apdu_handler_legacy.c:378-399).
    fn legacy_get_addr<P: Platform>(
        &mut self,
        p: &mut P,
        show: bool,
        ins: u8,
        p1: u8,
        p2: u8,
        data: &[u8],
    ) -> Result<Action, u16> {
        let (raw, rx) = raw_apdu(ins, p1, p2, data);
        self.legacy_extract_hd_path(&raw, rx as u64, LEGACY_HEADER_LENGTH as u64, true)?;
        let pk = self.fill_address(p)?;
        if show {
            self.pending = Pending::Address { pk, legacy: true };
            return Ok(Action::ReviewAddress);
        }
        Ok(Action::Reply(Reply::with(&[&[32], &pk], sw::OK)))
    }

    /// Legacy append (`legacy_append_data`): a short append resets the buffer.
    fn legacy_append<P: Platform>(&mut self, p: &mut P, data: &[u8]) -> Result<(), u16> {
        if !p.tx_append(data) {
            p.tx_reset();
            self.stream = Stream::None;
            return Err(sw::OUTPUT_BUFFER_TOO_SMALL);
        }
        Ok(())
    }

    /// `legacy_check_end_of_chunk` (apdu_handler_legacy.c:134-150).
    fn legacy_check_end_of_chunk<P: Platform>(&self, p: &P) -> bool {
        let buf = p.tx();
        let n = buf.len() as u64;
        let pl = self.payload_length as u64;
        if pl < n {
            let qty = buf[pl as usize];
            if !(2..=5).contains(&qty) {
                return false;
            }
            if pl + qty as u64 * 4 + 1 == n {
                return true;
            }
        }
        false
    }

    /// INS 0x03 / 0x04: `legacy_process_chunk` + `legacy_check_request` + parse
    /// (apdu_handler_legacy.c:152-226, 401-463).
    fn legacy_sign<P: Platform>(
        &mut self,
        p: &mut P,
        ins: u8,
        json: bool,
        data: &[u8],
    ) -> Result<Action, u16> {
        let rx = LEGACY_HEADER_LENGTH + data.len();
        let mut off = 0usize;
        if self.legacy_first_chunk(ins)? {
            if json {
                if data.len() < 4 {
                    return Err(sw::WRONG_LENGTH);
                }
                self.payload_length = le32(data);
                off = 4;
            } else {
                self.payload_length = HASH_LEN as u32;
            }
            p.tx_reset();
            self.stream = Stream::Legacy(ins);
        }
        self.legacy_append(p, &data[off..])?;
        if !(rx < LEGACY_FULL_CHUNK_SIZE || self.legacy_check_end_of_chunk(p)) {
            return Ok(Action::Reply(Reply::sw(sw::OK)));
        }
        self.stream = Stream::None;

        // legacy_check_request
        let n = p.tx().len() as u64;
        let pl = self.payload_length as u64;
        if n < pl {
            p.tx_reset();
            return Err(sw::DATA_INVALID);
        }
        {
            let pr: &P = p;
            self.legacy_extract_hd_path(pr.tx(), n, pl, true)?;
        }
        if n != self.hdpath_length as u64 + pl {
            p.tx_reset();
            return Err(sw::DATA_INVALID);
        }
        let msg_len = (n - self.hdpath_length as u64) as usize;
        self.sign_path = self.hd_path;

        let tx_type = if json { TxType::Json } else { TxType::Hash };
        match self.tx_parse(p, tx_type, msg_len) {
            Err(e) => {
                if json && e != ParserError::BlindsignModeRequired {
                    // Legacy JSON: bare 0x6984, no message (legacy.c:414-421).
                    p.tx_reset();
                    Err(sw::DATA_INVALID)
                } else {
                    // Hash, or V11 on legacy JSON: the blind-signing screen.
                    Ok(error_with_message(e))
                }
            }
            Ok(blind) => {
                self.pending = Pending::Sign(SignKind::Legacy { tx_type, msg_len });
                Ok(Action::ReviewTx { blind })
            }
        }
    }

    /// INS 0x10 (apdu_handler_legacy.c:228-367, 465-492).
    fn legacy_transfer<P: Platform>(
        &mut self,
        p: &mut P,
        ins: u8,
        p1: u8,
        p2: u8,
        data: &[u8],
    ) -> Result<Action, u16> {
        let (raw, rx) = raw_apdu(ins, p1, p2, data);
        match self.legacy_transfer_chunk(p, &raw[..rx]) {
            Err(code) => {
                self.stream = Stream::None;
                Err(code)
            }
            Ok(false) => Ok(Action::Reply(Reply::sw(sw::OK))),
            Ok(true) => {
                let len = p.tx().len();
                match self.tx_parse(p, TxType::Transfer, len) {
                    Err(ParserError::BlindsignModeRequired) => {
                        // V23: the blind-signing screen, as for 0x03 and 0x04.
                        Ok(error_with_message(ParserError::BlindsignModeRequired))
                    }
                    Err(_) => {
                        p.tx_reset();
                        Err(sw::DATA_INVALID)
                    }
                    Ok(blind) => {
                        self.pending = Pending::Sign(SignKind::LegacyTransfer);
                        Ok(Action::ReviewTx { blind })
                    }
                }
            }
        }
    }

    /// `legacy_process_transfer_chunk`: Ok(true) when the 12 items are complete.
    fn legacy_transfer_chunk<P: Platform>(&mut self, p: &mut P, buf: &[u8]) -> Result<bool, u16> {
        let rx = buf.len();
        let mut payload_size: usize = 0;
        let mut offset = if self.legacy_first_chunk(INS_LEGACY_TRANSFER)? {
            self.legacy_initialize_transfer(p, buf)?
        } else {
            self.legacy_existing_transfer(p, buf, &mut payload_size)?
        };

        while offset < rx {
            offset += payload_size + 1;
            if offset > rx {
                return Err(sw::DATA_INVALID);
            }
            if offset == LEGACY_FULL_CHUNK_SIZE {
                self.check_item_len = true;
                return Ok(false);
            }
            if offset >= rx {
                return Err(sw::DATA_INVALID);
            }
            payload_size = buf[offset] as usize;
            let next = offset + payload_size + 1;
            if next > LEGACY_FULL_CHUNK_SIZE {
                // V1 (split bound): an item may only be split across APDUs at the end of
                // a full 235-byte APDU; C copied bytes past `rx` otherwise.
                if rx != LEGACY_FULL_CHUNK_SIZE {
                    return Err(sw::WRONG_LENGTH);
                }
                self.legacy_handle_overflow(buf, offset, payload_size)?;
                return Ok(false);
            }
            // V1 (length bound): the item must be inside the received bytes; C appended
            // stale buffer bytes past `rx` into the signed message otherwise.
            if next > rx {
                return Err(sw::WRONG_LENGTH);
            }
            self.legacy_append(p, &buf[offset..next])?;
            self.items = self.items.wrapping_add(1);
            if self.items > LEGACY_TRANSFER_NUM_ITEMS {
                return Err(sw::DATA_INVALID);
            }
            if next >= rx && next != LEGACY_FULL_CHUNK_SIZE {
                if self.items != LEGACY_TRANSFER_NUM_ITEMS {
                    return Err(sw::DATA_INVALID);
                }
                self.stream = Stream::None;
                return Ok(true);
            }
        }
        Err(sw::DATA_INVALID)
    }

    /// `legacy_initialize_transfer` (apdu_handler_legacy.c:228-258).
    fn legacy_initialize_transfer<P: Platform>(
        &mut self,
        p: &mut P,
        buf: &[u8],
    ) -> Result<usize, u16> {
        let rx = buf.len();
        self.local_data_len = 0;
        self.check_item_len = false;
        self.item_len = 0;
        self.items = 0;
        self.legacy_extract_hd_path(buf, rx as u64, LEGACY_HEADER_LENGTH as u64, false)?;
        self.sign_path = self.hd_path;
        p.tx_reset();
        self.stream = Stream::Legacy(INS_LEGACY_TRANSFER);
        let offset = self.hdpath_length as usize + LEGACY_HEADER_LENGTH;
        if offset + 1 > rx {
            return Err(sw::WRONG_LENGTH);
        }
        self.legacy_append(p, &buf[offset..offset + 1])?;
        self.items = 0;
        Ok(offset)
    }

    /// `legacy_process_existing_transfer` (apdu_handler_legacy.c:260-293).
    fn legacy_existing_transfer<P: Platform>(
        &mut self,
        p: &mut P,
        buf: &[u8],
        payload_size: &mut usize,
    ) -> Result<usize, u16> {
        let rx = buf.len();
        let saved = self.local_data;
        let saved_len = self.local_data_len as usize;
        self.legacy_append(p, &saved[..saved_len])?;
        let mut offset = LEGACY_HEADER_LENGTH;
        if self.check_item_len {
            // C reads buf[5] even when rx == 5; the following bound fails for any
            // value then, so the result (0x6700) is the same.
            if rx <= offset {
                return Err(sw::WRONG_LENGTH);
            }
            *payload_size = buf[offset] as usize;
            if offset + *payload_size + 1 > rx {
                return Err(sw::WRONG_LENGTH);
            }
            self.legacy_append(p, &buf[offset..offset + *payload_size + 1])?;
        } else {
            if self.item_len <= self.local_data_len {
                return Err(sw::DATA_INVALID);
            }
            *payload_size = (self.item_len - self.local_data_len) as usize;
            if offset + *payload_size > rx {
                return Err(sw::WRONG_LENGTH);
            }
            self.legacy_append(p, &buf[offset..offset + *payload_size])?;
            offset -= 1;
        }
        self.items = self.items.wrapping_add(1);
        self.local_data_len = 0;
        Ok(offset)
    }

    /// `legacy_handle_overflow` (apdu_handler_legacy.c:295-309).
    fn legacy_handle_overflow(
        &mut self,
        buf: &[u8],
        offset: usize,
        payload_size: usize,
    ) -> Result<(), u16> {
        self.check_item_len = false;
        // uint8_t: an item of 255 bytes wraps to 0 here, as in C.
        self.item_len = (payload_size + 1) as u8;
        if offset > LEGACY_FULL_CHUNK_SIZE {
            return Err(sw::DATA_INVALID);
        }
        let n = LEGACY_FULL_CHUNK_SIZE - offset;
        if n >= LEGACY_LOCAL_BUFFER_SIZE {
            return Err(sw::OUTPUT_BUFFER_TOO_SMALL);
        }
        self.local_data_len = n as u8;
        self.local_data[..n].copy_from_slice(&buf[offset..offset + n]);
        Ok(())
    }

    // ---- After the user's decision -------------------------------------------------

    /// The public key and, in expert mode, the path shown on the address review.
    pub fn address_review(&self) -> Option<[u8; 32]> {
        match self.pending {
            Pending::Address { pk, .. } => Some(pk),
            _ => None,
        }
    }

    /// The path of the last address command (shown as "Your Path").
    pub fn hd_path(&self) -> [u32; 5] {
        self.hd_path
    }

    /// Reply to an address review (`app_reply_address` / `legacy_app_reply_address`).
    pub fn address_done(&mut self, approved: bool) -> Reply {
        let pending = core::mem::replace(&mut self.pending, Pending::None);
        match (pending, approved) {
            (Pending::Address { pk, legacy }, true) => {
                if legacy {
                    Reply::with(&[&[32], &pk], sw::OK)
                } else {
                    Reply::with(&[&pk], sw::OK)
                }
            }
            _ => Reply::sw(sw::COMMAND_NOT_ALLOWED),
        }
    }

    /// The JSON buffer the review items refer to.
    fn review_json<'a, P: Platform>(&self, p: &'a P) -> &'a [u8] {
        match self.parsed.tx_type {
            TxType::Transfer => p.template(),
            TxType::Json => p.tx(),
            TxType::Hash => &[],
        }
    }

    pub fn review_len(&self) -> usize {
        self.parsed.num_items()
    }

    /// Renders review item `idx`: `(title length, value length)`.
    pub fn review_item<P: Platform>(
        &self,
        p: &P,
        idx: usize,
        title: &mut [u8; TITLE_BUF],
        value: &mut [u8; VALUE_BUF],
    ) -> Result<(usize, usize), ItemsError> {
        let ctx = Ctx {
            p,
            path: self.sign_path,
        };
        self.parsed
            .item(&ctx, self.review_json(p), idx, title, value)
    }

    /// Reply to a transaction review (`app_sign`, `legacy_app_sign`,
    /// `legacy_app_sign_transference`, `app_reject`).
    pub fn sign_done<P: Platform>(&mut self, p: &P, approved: bool) -> Reply {
        let pending = core::mem::replace(&mut self.pending, Pending::None);
        let Pending::Sign(kind) = pending else {
            return Reply::sw(sw::COMMAND_NOT_ALLOWED);
        };
        if !approved {
            return Reply::sw(sw::COMMAND_NOT_ALLOWED);
        }
        let path = self.sign_path;
        match kind {
            SignKind::Modern(tx_type) => {
                let msg = if tx_type == TxType::Transfer {
                    p.template()
                } else {
                    p.tx()
                };
                match crypto_sign(p, &path, msg, tx_type) {
                    Some(sig) => Reply::with(&[&sig], sw::OK),
                    None => Reply::sw(sw::SIGN_VERIFY_ERROR),
                }
            }
            SignKind::Legacy { tx_type, msg_len } => {
                let msg = &p.tx()[..msg_len.min(p.tx().len())];
                match crypto_sign(p, &path, msg, tx_type) {
                    Some(sig) => Reply::with(&[&sig], sw::OK),
                    None => Reply::sw(sw::SIGN_VERIFY_ERROR),
                }
            }
            SignKind::LegacyTransfer => {
                let Some(pk) = p.public_key(&path) else {
                    return Reply::sw(sw::EXECUTION_ERROR);
                };
                match crypto_sign(p, &path, p.template(), TxType::Transfer) {
                    Some(sig) => Reply::with(&[&sig, &pk], sw::OK),
                    None => Reply::sw(sw::SIGN_VERIFY_ERROR),
                }
            }
        }
    }
}

/// INS 0x20 (apdu_handler.c:165-190): test-mode byte (0 in production builds),
/// major/minor/patch as u16 BE, the "locked" byte, the target id (u32 BE).
fn get_version<P: Platform>(p: &P) -> Action {
    let [major, minor, patch] = p.version();
    Action::Reply(Reply::with(
        &[
            &[0],
            &major.to_be_bytes(),
            &minor.to_be_bytes(),
            &patch.to_be_bytes(),
            &[p.ux_locked() as u8],
            &p.target_id().to_be_bytes(),
        ],
        sw::OK,
    ))
}

/// Modern/legacy-hash parse error: the ASCII description, then 0x6984. The
/// blind-signing case first shows a screen (apdu_handler.c:142-158).
fn error_with_message(e: ParserError) -> Action {
    let r = Reply::with(&[e.description()], sw::DATA_INVALID);
    if e == ParserError::BlindsignModeRequired {
        Action::BlindSignRequired(r)
    } else {
        Action::Reply(r)
    }
}

/// The APDU as the C handlers index it (`G_io_apdu_buffer[0..rx]`): the 4 header
/// bytes, Lc, then the data. Lc is never read by the handlers.
fn raw_apdu(ins: u8, p1: u8, p2: u8, data: &[u8]) -> ([u8; 5 + 300], usize) {
    let mut raw = [0u8; 5 + 300];
    let n = data.len().min(300);
    raw[0] = CLA;
    raw[1] = ins;
    raw[2] = p1;
    raw[3] = p2;
    raw[4] = n as u8;
    raw[5..5 + n].copy_from_slice(&data[..n]);
    (raw, 5 + n)
}
