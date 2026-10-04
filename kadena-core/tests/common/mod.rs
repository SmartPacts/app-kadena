//! Host test platform: an in-memory device.
//!
//! Keys are NOT the device's HDW_NORMAL keys (that derivation lives in the OS and
//! is pinned by the Speculos tests); here each path gets a distinct deterministic
//! test key so that tests can tell which path signed. The device key for the
//! standard path is replaced by a fixed public key when a test needs the C app's
//! real address in a template (`with_pubkey`).

#![allow(dead_code)]

use blake2::digest::consts::U32;
use blake2::{Blake2b, Digest};
use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use kadena_core::app::{Action, App, Platform, Reply};

pub const TX_CAP: usize = 15104;

pub struct Mock {
    pub pin: bool,
    pub locked: bool,
    pub expert: bool,
    pub blind: bool,
    pub fail_derive: bool,
    pub fail_sign: bool,
    pub fixed_pubkey: Option<[u8; 32]>,
    /// The C app reviewed `signers[0]` whatever its key; most tests below were
    /// written for that. With `auto_signer` (the default) the device key is the
    /// first 64-hex `pubKey` found in the transaction buffer, so those tests keep
    /// the device as the first signer. The V9 tests turn it off.
    pub auto_signer: bool,
    pub tx: Vec<u8>,
    pub template: Vec<u8>,
}

impl Default for Mock {
    fn default() -> Self {
        Mock {
            pin: true,
            locked: false,
            expert: false,
            blind: false,
            fail_derive: false,
            fail_sign: false,
            fixed_pubkey: None,
            auto_signer: true,
            tx: Vec::new(),
            template: Vec::new(),
        }
    }
}

/// The first `"pubKey":"<64 lowercase hex>"` in `buf`, decoded.
pub fn first_pubkey(buf: &[u8]) -> Option<[u8; 32]> {
    let pat = br#""pubKey":""#;
    let at = buf.windows(pat.len()).position(|w| w == pat)? + pat.len();
    let hexk = buf.get(at..at + 64)?;
    if buf.get(at + 64) != Some(&b'"')
        || !hexk
            .iter()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b))
    {
        return None;
    }
    hex::decode(hexk).ok()?.try_into().ok()
}

pub fn blake2b(data: &[u8]) -> [u8; 32] {
    let mut h = Blake2b::<U32>::new();
    h.update(data);
    h.finalize().into()
}

pub fn key_for(path: &[u32; 5]) -> SigningKey {
    let mut seed_src = Vec::new();
    for c in path {
        seed_src.extend_from_slice(&c.to_le_bytes());
    }
    SigningKey::from_bytes(&blake2b(&seed_src))
}

pub const STD_PATH: [u32; 5] = [0x8000_002C, 0x8000_0272, 0x8000_0000, 0, 0];

impl Mock {
    pub fn verifying_key(path: &[u32; 5]) -> VerifyingKey {
        key_for(path).verifying_key()
    }

    pub fn verify(path: &[u32; 5], msg32: &[u8; 32], sig: &[u8]) -> bool {
        let sig = ed25519_dalek::Signature::from_slice(sig).unwrap();
        Mock::verifying_key(path).verify(msg32, &sig).is_ok()
    }
}

impl Platform for Mock {
    fn version(&self) -> [u16; 3] {
        [2, 0, 0]
    }
    fn pin_validated(&self) -> bool {
        self.pin
    }
    fn ux_locked(&self) -> bool {
        self.locked
    }
    fn target_id(&self) -> u32 {
        0x3310_0004
    }
    fn device_info(&self, out: &mut [u8]) -> usize {
        let body = [
            0x33, 0x10, 0x00, 0x04, 3, b'1', b'.', b'6', 0, 3, b'4', b'.', b'7',
        ];
        out[..body.len()].copy_from_slice(&body);
        body.len()
    }
    fn expert(&self) -> bool {
        self.expert
    }
    fn blind_signing(&self) -> bool {
        self.blind
    }
    fn public_key(&self, path: &[u32; 5]) -> Option<[u8; 32]> {
        if self.fail_derive {
            return None;
        }
        if let (Some(pk), true) = (self.fixed_pubkey, *path == STD_PATH) {
            return Some(pk);
        }
        if self.auto_signer {
            if let Some(pk) = first_pubkey(&self.tx) {
                return Some(pk);
            }
        }
        Some(key_for(path).verifying_key().to_bytes())
    }
    fn sign(&self, path: &[u32; 5], msg: &[u8; 32]) -> Option<[u8; 64]> {
        if self.fail_sign {
            return None;
        }
        Some(key_for(path).sign(msg).to_bytes())
    }
    fn blake2b_256(&self, data: &[u8]) -> Option<[u8; 32]> {
        Some(blake2b(data))
    }
    fn tx_reset(&mut self) {
        self.tx.clear();
    }
    fn tx_append(&mut self, data: &[u8]) -> bool {
        if self.tx.len() + data.len() > TX_CAP {
            return false;
        }
        self.tx.extend_from_slice(data);
        true
    }
    fn tx(&self) -> &[u8] {
        &self.tx
    }
    fn template_store(&mut self, data: &[u8]) {
        assert!(data.len() <= 1280);
        self.template = data.to_vec();
    }
    fn template(&self) -> &[u8] {
        &self.template
    }
}

pub type TestApp = App<768>;

pub fn new_app() -> Box<TestApp> {
    Box::new(App::new())
}

/// Result of one APDU after any review is resolved with `approve`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resp {
    pub data: Vec<u8>,
    pub sw: u16,
    /// Whether a review (address or transaction) was shown.
    pub reviewed: bool,
    /// Whether the blind-sign-required screen was shown.
    pub blind_screen: bool,
}

pub fn reply(r: Reply) -> Resp {
    Resp {
        data: r.payload().to_vec(),
        sw: r.sw,
        reviewed: false,
        blind_screen: false,
    }
}

/// Sends one APDU (hex) and resolves any review with `approve`.
pub fn exchange<const T: usize>(
    app: &mut App<T>,
    p: &mut Mock,
    apdu: &[u8],
    approve: bool,
) -> Resp {
    assert!(apdu.len() >= 5, "test APDUs carry Lc");
    let data = &apdu[5..];
    assert_eq!(apdu[4] as usize, data.len(), "test APDU Lc");
    match app.handle(p, apdu[0], apdu[1], apdu[2], apdu[3], data) {
        Action::Reply(r) => reply(r),
        Action::BlindSignRequired(r) => {
            let mut x = reply(r);
            x.blind_screen = true;
            x
        }
        Action::ReviewAddress => {
            let mut x = reply(app.address_done(approve));
            x.reviewed = true;
            x
        }
        Action::ReviewTx { .. } => {
            // Render every item, as the device does while the user scrolls.
            let mut t = [0u8; 40];
            let mut v = [0u8; 300];
            for i in 0..app.review_len() {
                app.review_item(p, i, &mut t, &mut v)
                    .expect("validated items render");
            }
            let mut x = reply(app.sign_done(p, approve));
            x.reviewed = true;
            x
        }
    }
}

pub fn apdu(cla: u8, ins: u8, p1: u8, p2: u8, data: &[u8]) -> Vec<u8> {
    assert!(data.len() <= 255);
    let mut v = vec![cla, ins, p1, p2, data.len() as u8];
    v.extend_from_slice(data);
    v
}

pub fn path_bytes(path: &[u32]) -> Vec<u8> {
    path.iter().flat_map(|c| c.to_le_bytes()).collect()
}

/// Legacy path encoding: qty, then qty LE u32.
pub fn legacy_path(path: &[u32]) -> Vec<u8> {
    let mut v = vec![path.len() as u8];
    v.extend(path_bytes(path));
    v
}

/// Modern chunked signing (host convention of @zondax/ledger-js): P1=0 path,
/// then 250-byte chunks, the last with P1=2.
pub fn modern_sign<const T: usize>(
    app: &mut App<T>,
    p: &mut Mock,
    ins: u8,
    path: &[u32; 5],
    msg: &[u8],
    approve: bool,
) -> Resp {
    let r = exchange(app, p, &apdu(0, ins, 0, 0, &path_bytes(path)), approve);
    if r.sw != 0x9000 {
        return r;
    }
    if msg.is_empty() {
        return exchange(app, p, &apdu(0, ins, 2, 0, &[]), approve);
    }
    let chunks: Vec<&[u8]> = msg.chunks(250).collect();
    let mut last = None;
    for (i, c) in chunks.iter().enumerate() {
        let p1 = if i + 1 == chunks.len() { 2 } else { 1 };
        let r = exchange(app, p, &apdu(0, ins, p1, 0, c), approve);
        if p1 == 1 && r.sw != 0x9000 {
            return r;
        }
        last = Some(r);
    }
    last.unwrap()
}

/// Legacy chunking (hw-app-alamgu `sendChunks`): 230-byte slices, P1=P2=0;
/// the response is the last one.
pub fn legacy_send<const T: usize>(
    app: &mut App<T>,
    p: &mut Mock,
    ins: u8,
    payload: &[u8],
    approve: bool,
) -> Resp {
    let mut last = None;
    for c in payload.chunks(230) {
        let r = exchange(app, p, &apdu(0, ins, 0, 0, c), approve);
        let done = r.sw != 0x9000 || r.reviewed || !r.data.is_empty();
        last = Some(r);
        if done {
            break;
        }
    }
    last.expect("non-empty payload")
}

/// The 0x03 payload: u32 LE length, JSON, legacy path.
pub fn legacy_json_payload(json: &[u8], path: &[u32]) -> Vec<u8> {
    let mut v = (json.len() as u32).to_le_bytes().to_vec();
    v.extend_from_slice(json);
    v.extend(legacy_path(path));
    v
}

pub struct TransferParams<'a> {
    pub recipient: &'a str,
    pub recipient_chain: &'a str,
    pub network: &'a str,
    pub amount: &'a str,
    pub namespace: &'a str,
    pub module: &'a str,
    pub gas_price: &'a str,
    pub gas_limit: &'a str,
    pub creation_time: &'a str,
    pub chain_id: &'a str,
    pub nonce: &'a str,
    pub ttl: &'a str,
}

impl TransferParams<'_> {
    pub fn fields(&self) -> [&str; 12] {
        [
            self.recipient,
            self.recipient_chain,
            self.network,
            self.amount,
            self.namespace,
            self.module,
            self.gas_price,
            self.gas_limit,
            self.creation_time,
            self.chain_id,
            self.nonce,
            self.ttl,
        ]
    }

    /// The 0x24 / 0x10 body: tx_type, then 12 x (len u8, bytes).
    pub fn encode(&self, tx_type: u8) -> Vec<u8> {
        let mut v = vec![tx_type];
        for f in self.fields() {
            v.push(f.len() as u8);
            v.extend_from_slice(f.as_bytes());
        }
        v
    }

    /// The command JSON as a HOST builds it (port of hw-app-kda `signTxInternal`),
    /// written independently of the device template code.
    pub fn host_json(&self, tx_type: u8, pubkey_hex: &str) -> String {
        let ns = self.namespace;
        let md = self.module;
        let prefix = if ns.is_empty() {
            "coin".to_string()
        } else {
            format!("{ns}.{md}")
        };
        let r = self.recipient;
        let a = self.amount;
        let mut cmd = format!("{{\"networkId\":\"{}\"", self.network);
        match tx_type {
            0 => {
                cmd += ",\"payload\":{\"exec\":{\"data\":{},\"code\":\"";
                cmd += &format!("({prefix}.transfer");
                cmd += &format!(" \\\"k:{pubkey_hex}\\\" \\\"k:{r}\\\" {a})\"}}}}");
                cmd += &format!(",\"signers\":[{{\"pubKey\":\"{pubkey_hex}\"");
                cmd += &format!(",\"clist\":[{{\"args\":[\"k:{pubkey_hex}\",\"k:{r}\",{a}]");
                cmd += &format!(
                    ",\"name\":\"{prefix}.TRANSFER\"}},{{\"args\":[],\"name\":\"coin.GAS\"}}]}}]"
                );
            }
            1 => {
                cmd += ",\"payload\":{\"exec\":{\"data\":{";
                cmd += &format!("\"ks\":{{\"pred\":\"keys-all\",\"keys\":[\"{r}\"]}}");
                cmd += "},\"code\":\"";
                cmd += &format!("({prefix}.transfer-create");
                cmd += &format!(
                    " \\\"k:{pubkey_hex}\\\" \\\"k:{r}\\\" (read-keyset \\\"ks\\\") {a})\"}}}}"
                );
                cmd += &format!(",\"signers\":[{{\"pubKey\":\"{pubkey_hex}\"");
                cmd += &format!(",\"clist\":[{{\"args\":[\"k:{pubkey_hex}\",\"k:{r}\",{a}]");
                cmd += &format!(
                    ",\"name\":\"{prefix}.TRANSFER\"}},{{\"args\":[],\"name\":\"coin.GAS\"}}]}}]"
                );
            }
            _ => {
                let rc = self.recipient_chain;
                cmd += ",\"payload\":{\"exec\":{\"data\":{";
                cmd += &format!("\"ks\":{{\"pred\":\"keys-all\",\"keys\":[\"{r}\"]}}");
                cmd += "},\"code\":\"";
                cmd += &format!("({prefix}.transfer-crosschain");
                cmd += &format!(
                    " \\\"k:{pubkey_hex}\\\" \\\"k:{r}\\\" (read-keyset \\\"ks\\\") \\\"{rc}\\\" {a})\"}}}}"
                );
                cmd += &format!(",\"signers\":[{{\"pubKey\":\"{pubkey_hex}\"");
                cmd +=
                    &format!(",\"clist\":[{{\"args\":[\"k:{pubkey_hex}\",\"k:{r}\",{a},\"{rc}\"]");
                cmd += &format!(
                    ",\"name\":\"{prefix}.TRANSFER_XCHAIN\"}},{{\"args\":[],\"name\":\"coin.GAS\"}}]}}]"
                );
            }
        }
        cmd += &format!(",\"meta\":{{\"creationTime\":{}", self.creation_time);
        cmd += &format!(
            ",\"ttl\":{},\"gasLimit\":{},\"chainId\":\"{}\"",
            self.ttl, self.gas_limit, self.chain_id
        );
        cmd += &format!(
            ",\"gasPrice\":{},\"sender\":\"k:{pubkey_hex}\"}},\"nonce\":\"{}\"}}",
            self.gas_price, self.nonce
        );
        cmd
    }
}

/// Renders all review items as "Title : value" strings (whole values).
pub fn review_items<const T: usize>(app: &App<T>, p: &Mock) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut t = [0u8; 40];
    let mut v = [0u8; 300];
    for i in 0..app.review_len() {
        let (tl, vl) = app.review_item(p, i, &mut t, &mut v).unwrap();
        out.push((
            String::from_utf8_lossy(&t[..tl]).into_owned(),
            String::from_utf8_lossy(&v[..vl]).into_owned(),
        ));
    }
    out
}

/// Pages items like the C test helper `dumpUI` with 39-byte buffers (38 chars per page).
pub fn dump_ui(items: &[(String, String)]) -> Vec<String> {
    let mut out = Vec::new();
    for (idx, (k, v)) in items.iter().enumerate() {
        let per = 38;
        let bytes = v.as_bytes();
        let mut pages = bytes.len() / per;
        if bytes.len() % per != 0 {
            pages += 1;
        }
        for pg in 0..pages {
            let chunk = &bytes[pg * per..((pg + 1) * per).min(bytes.len())];
            let mut s = format!("{idx} | {k}");
            if pages > 1 {
                s += &format!(" [{}/{}]", pg + 1, pages);
            }
            s += " : ";
            s += &String::from_utf8_lossy(chunk);
            out.push(s);
        }
    }
    out
}

/// Starts a JSON parse through the real APDU path and returns the Action result.
pub fn parse_json<const T: usize>(app: &mut App<T>, p: &mut Mock, json: &[u8]) -> Resp {
    modern_sign(app, p, 0x22, &STD_PATH, json, true)
}

pub fn hex(s: &str) -> Vec<u8> {
    hex::decode(s).unwrap()
}

pub const EXPECTED_PK_HEX: &str =
    "de12b5e16b93fe81ca4d70656bee4334f2e40f9f28b9796e792d28f2cead74ad";

// ---- Shared vectors and helpers of the APDU tests ----------------------------

pub const H: u32 = 0x8000_0000;

pub const ALT_PATH: [u32; 5] = [H | 44, H | 626, H | 5, 0, 0];

pub fn std_addr_apdu(p1: u8) -> Vec<u8> {
    apdu(0, 0x21, p1, 0, &path_bytes(&STD_PATH))
}

pub fn pk_of(path: &[u32; 5]) -> Vec<u8> {
    Mock::verifying_key(path).to_bytes().to_vec()
}

pub fn msg(desc: &str) -> Vec<u8> {
    desc.as_bytes().to_vec()
}

pub const SIMPLE_TRANSFER: &str = r#"{"networkId":"mainnet01","payload":{"exec":{"data":{},"code":"(coin.transfer \"83934c0f9b005f378ba3520f9dea952fb0a90e5aa36f1b5ff837d9b30c471790\" \"9790d119589a26114e1a42d92598b3f632551c566819ec48e0e8c54dae6ebb42\" 11.0)"}},"signers":[{"pubKey":"83934c0f9b005f378ba3520f9dea952fb0a90e5aa36f1b5ff837d9b30c471790","clist":[{"args":[],"name":"coin.GAS"},{"args":["83934c0f9b005f378ba3520f9dea952fb0a90e5aa36f1b5ff837d9b30c471790","9790d119589a26114e1a42d92598b3f632551c566819ec48e0e8c54dae6ebb42",11],"name":"coin.TRANSFER"}]}],"meta":{"creationTime":1634009214,"ttl":28800,"gasLimit":600,"chainId":"0","gasPrice":1.0e-5,"sender":"83934c0f9b005f378ba3520f9dea952fb0a90e5aa36f1b5ff837d9b30c471790"},"nonce":"\"2021-10-12T03:27:53.700Z\""}"#;

pub const META: &str =
    r#"{"creationTime":0,"ttl":28800,"gasLimit":600,"chainId":"0","gasPrice":1.0e-6,"sender":"s"}"#;

/// A JSON command signed by `pubkey` with the given clist.
pub fn cmd(pubkey: &str, clist: &str) -> String {
    format!(
        r#"{{"networkId":"mainnet01","payload":{{"exec":{{"data":{{}},"code":"(x)"}}}},"signers":[{{"pubKey":"{pubkey}","clist":{clist}}}],"meta":{META},"nonce":"n"}}"#
    )
}

/// Parses `json` with 0x22 and returns the review items (then rejects).
pub fn items_of(json: &[u8], expert: bool) -> Result<Vec<(String, String)>, Resp> {
    let mut app = new_app();
    let mut p = Mock {
        expert,
        ..Default::default()
    };
    items_with::<768>(&mut app, &mut p, json)
}

/// Parses `json` with 0x22 with the "Blind signing" setting as given; returns
/// whether the review is a blind-signing one, and its items (then rejects).
pub fn review_with_setting(
    json: &[u8],
    blind_setting: bool,
) -> Result<(bool, Vec<(String, String)>), Resp> {
    let mut app = new_app();
    let mut p = Mock {
        blind: blind_setting,
        ..Default::default()
    };
    review_flagged::<768>(&mut app, &mut p, json)
}

/// Parses `json` with blind signing ON and asserts a blind-signing review.
pub fn blind_items_of(json: &[u8]) -> Vec<(String, String)> {
    let (blind, items) = review_with_setting(json, true).expect("expected a review");
    assert!(blind, "expected a blind-signing review");
    items
}

pub fn review_flagged<const T: usize>(
    app: &mut App<T>,
    p: &mut Mock,
    json: &[u8],
) -> Result<(bool, Vec<(String, String)>), Resp> {
    let r = exchange(app, p, &apdu(0, 0x22, 0, 0, &path_bytes(&STD_PATH)), false);
    assert_eq!(r.sw, 0x9000);
    let chunks: Vec<&[u8]> = json.chunks(250).collect();
    for c in &chunks[..chunks.len().saturating_sub(1)] {
        let r = exchange(app, p, &apdu(0, 0x22, 1, 0, c), false);
        assert_eq!(r.sw, 0x9000);
    }
    let last: &[u8] = chunks.last().copied().unwrap_or(&[]);
    match app.handle(p, 0, 0x22, 2, 0, last) {
        Action::ReviewTx { blind } => {
            let items = review_items(app, p);
            app.sign_done(p, false);
            Ok((blind, items))
        }
        Action::Reply(r) | Action::BlindSignRequired(r) => Err(reply(r)),
        other => panic!("{other:?}"),
    }
}

pub fn items_with<const T: usize>(
    app: &mut App<T>,
    p: &mut Mock,
    json: &[u8],
) -> Result<Vec<(String, String)>, Resp> {
    let r = exchange(app, p, &apdu(0, 0x22, 0, 0, &path_bytes(&STD_PATH)), false);
    assert_eq!(r.sw, 0x9000);
    let chunks: Vec<&[u8]> = json.chunks(250).collect();
    for c in &chunks[..chunks.len().saturating_sub(1)] {
        let r = exchange(app, p, &apdu(0, 0x22, 1, 0, c), false);
        assert_eq!(r.sw, 0x9000);
    }
    let last: &[u8] = chunks.last().copied().unwrap_or(&[]);
    match app.handle(p, 0, 0x22, 2, 0, last) {
        Action::ReviewTx { .. } => {
            let items = review_items(app, p);
            app.sign_done(p, false);
            Ok(items)
        }
        Action::Reply(r) | Action::BlindSignRequired(r) => Err(reply(r)),
        other => panic!("{other:?}"),
    }
}

pub fn err_msg(json: &str) -> (Vec<u8>, u16) {
    let r = items_of(json.as_bytes(), false).expect_err("expected a parse error");
    (r.data, r.sw)
}

pub const UNRECOGNIZED: &str = "Unrecognized error code";

pub const NOT_SIGNER: &str = "Device key is not a signer";

pub const SIGNS_TWICE: &str = "Device key signs more than once";

pub const BLIND_REQUIRED: &str = "Blind signing mode required";

pub const HASH_1: &str = "ffd8cd79deb956fa3c7d9be0f836f20ac84b140168a087a842be4760e40e2b1c";

pub const RCPT: &str = "83934c0f9b005f378ba3520f9dea952fb0a90e5aa36f1b5ff837d9b30c471790";

pub const NONCE1: &str = "2022-10-13 07:56:50.893257 UTC";

pub const NONCE2: &str = "2022-10-14 04:41:03.193557 UTC";

/// The C app's Zemu transfer vectors (Zondax/ledger-kadena
/// tests_zemu/tests/testscases/transactions.ts), as
/// the host libraries encode them (recipient_chain is forced to "0" for types 0/1).
pub fn zemu_transfers() -> Vec<(&'static str, u8, TransferParams<'static>)> {
    let t1 = TransferParams {
        recipient: RCPT,
        recipient_chain: "0",
        network: "testnet04",
        amount: "1.23",
        namespace: "",
        module: "",
        gas_price: "1.0e-6",
        gas_limit: "2300",
        creation_time: "1665647810",
        chain_id: "0",
        nonce: NONCE1,
        ttl: "600",
    };
    let ns42 = TransferParams {
        recipient: RCPT,
        recipient_chain: "0",
        network: "testnet040000000",
        amount: "1.233333333333333333333333333333",
        namespace: "n_e595727b657fbbb3b8e362a05a7bb8d12865c1ff",
        module: "kb-USDC",
        gas_price: "1.011111111111111e-6",
        gas_limit: "0123456789",
        creation_time: "9876543210",
        chain_id: "0",
        nonce: NONCE1,
        ttl: "60000000000000000000",
    };
    let create = TransferParams {
        recipient: RCPT,
        recipient_chain: "0",
        network: "testnet04",
        amount: "23.67",
        namespace: "",
        module: "",
        gas_price: "1.0e-6",
        gas_limit: "2300",
        creation_time: "1665722463",
        chain_id: "1",
        nonce: NONCE2,
        ttl: "600",
    };
    let xchain = TransferParams {
        recipient_chain: "2",
        ..create
    };
    let xmax = TransferParams {
        recipient_chain: "19",
        ..ns42
    };
    vec![
        ("transfer_1", 0, t1),
        ("transfer_namespace_42", 0, ns42),
        ("transfer_create_1", 1, create),
        ("transfer_cross_chain_1", 2, xchain),
        ("transfer_cross_chain_max", 2, xmax),
    ]
}

pub fn legacy_handler_transfers() -> Vec<(&'static str, TransferParams<'static>)> {
    let base = TransferParams {
        recipient: RCPT,
        recipient_chain: "0",
        network: "testnet040000000",
        amount: "1.233333333333333333333333333333",
        namespace: "testnamespace012",
        module: "testmoduletestmoduletestmodule01",
        gas_price: "1.011111111111111e-6",
        gas_limit: "0123456789",
        creation_time: "9876543210",
        chain_id: "0",
        nonce: NONCE1,
        ttl: "60000000000000000000",
    };
    vec![
        ("handler_legacy_len_287", TransferParams { ..base }),
        (
            "handler_legacy_len_285",
            TransferParams {
                gas_limit: "01234567",
                ..base
            },
        ),
        (
            "handler_legacy_len_284",
            TransferParams {
                gas_limit: "0123456",
                ..base
            },
        ),
    ]
}

/// A structured transfer's result with blind signing ON (a token transfer, with
/// namespace and module, is blind signing: V23).
pub fn transfer_err(body: &[u8]) -> (Vec<u8>, u16) {
    let mut app = new_app();
    let mut p = Mock {
        blind: true,
        ..Default::default()
    };
    let r = modern_sign(&mut app, &mut p, 0x24, &STD_PATH, body, true);
    (r.data, r.sw)
}

/// R3's well-formed legacy transfer fields (repro/xfer.py `WF`).
pub fn r3_wf() -> TransferParams<'static> {
    TransferParams {
        recipient: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        recipient_chain: "0",
        network: "mainnet01",
        amount: "1.0",
        namespace: "",
        module: "",
        gas_price: "1.0e-6",
        gas_limit: "600",
        creation_time: "0",
        chain_id: "0",
        nonce: "n",
        ttl: "28800",
    }
}

/// R3 F-A: the attack APDU (qty-3 path, tx_type 0, items 1-11, then only the
/// ttl length byte claiming 20) and the primer that fills the stale bytes.
pub fn r3_fa_apdus() -> (Vec<u8>, Vec<u8>) {
    let f = r3_wf();
    let mut body = legacy_path(&STD_PATH[..3]);
    body.push(0);
    for v in &f.fields()[..11] {
        body.push(v.len() as u8);
        body.extend_from_slice(v.as_bytes());
    }
    body.push(20);
    let attack = apdu(0, 0x10, 0, 0, &body);
    let stale_start = attack.len();
    let mut primer_data = vec![0x41u8; stale_start + 20 - 5];
    primer_data[stale_start - 5..].copy_from_slice(b"99999999999999999999");
    let primer = apdu(0, 0x20, 0, 0, &primer_data);
    (primer, attack)
}

/// Builds the legacy 0x10 payload and splits it in 230-byte APDU data chunks.
pub fn legacy_chunks(params: &TransferParams, tx_type: u8) -> Vec<Vec<u8>> {
    let mut payload = legacy_path(&STD_PATH);
    payload.extend(params.encode(tx_type));
    payload
        .chunks(230)
        .map(|c| apdu(0, 0x10, 0, 0, c))
        .collect()
}
