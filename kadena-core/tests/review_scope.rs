//! V9-V12: what the review covers.
//!
//! * V9  the review shows the signer entry that carries the device key, and it
//!   must be the only entry naming that key (audit F1/F2, PoC P1/P2);
//! * V10 an empty clist is unscoped, like a missing or null one (F1);
//! * V11 a JSON signature not bounded by a displayed capability list is blind
//!   signing (F3);
//! * V12 nothing is signed that is not part of the one reviewed JSON value (F9).
//!
//! The mock's device key here is its own key for the standard path (no
//! `auto_signer`), so the transaction decides nothing about it.

mod common;
use common::*;
use kadena_core::app::Action;

fn dev() -> String {
    hex::encode(pk_of(&STD_PATH))
}

fn other() -> String {
    "a".repeat(64)
}

fn mock(blind: bool) -> Mock {
    Mock {
        blind,
        auto_signer: false,
        ..Default::default()
    }
}

/// A transfer capability from `from` to `k:<other>`.
fn transfer(from: &str, amount: &str) -> String {
    format!(
        r#"{{"args":["k:{from}","k:{}",{amount}],"name":"coin.TRANSFER"}}"#,
        other()
    )
}

/// A command with the given `signers` array.
fn with_signers(signers: &str) -> String {
    format!(
        r#"{{"networkId":"mainnet01","payload":{{"exec":{{"data":{{}},"code":"(coin.transfer \"k:{d}\" \"k:{o}\" 1000.0)"}}}},"signers":{signers},"meta":{META},"nonce":"n"}}"#,
        d = dev(),
        o = other()
    )
}

/// Sends `json` with 0x22 (or 0x03 when `legacy`) and returns the final action
/// plus the review items when there is a review.
fn run(json: &str, blind: bool, legacy: bool) -> (Action, Vec<(String, String)>) {
    let mut app = new_app();
    let mut p = mock(blind);
    let action = if legacy {
        let payload = legacy_json_payload(json.as_bytes(), &STD_PATH);
        let chunks: Vec<&[u8]> = payload.chunks(230).collect();
        for c in &chunks[..chunks.len() - 1] {
            assert_eq!(
                exchange(&mut app, &mut p, &apdu(0, 3, 0, 0, c), false).sw,
                0x9000
            );
        }
        app.handle(&mut p, 0, 3, 0, 0, chunks[chunks.len() - 1])
    } else {
        let r = exchange(
            &mut app,
            &mut p,
            &apdu(0, 0x22, 0, 0, &path_bytes(&STD_PATH)),
            false,
        );
        assert_eq!(r.sw, 0x9000);
        let chunks: Vec<&[u8]> = json.as_bytes().chunks(250).collect();
        for c in &chunks[..chunks.len() - 1] {
            assert_eq!(
                exchange(&mut app, &mut p, &apdu(0, 0x22, 1, 0, c), false).sw,
                0x9000
            );
        }
        app.handle(&mut p, 0, 0x22, 2, 0, chunks[chunks.len() - 1])
    };
    let items = match action {
        Action::ReviewTx { .. } => review_items(&app, &p),
        _ => Vec::new(),
    };
    (action, items)
}

fn refusal(action: &Action) -> (Vec<u8>, u16, bool) {
    match action {
        Action::Reply(r) => (r.payload().to_vec(), r.sw, false),
        Action::BlindSignRequired(r) => (r.payload().to_vec(), r.sw, true),
        other => panic!("expected a refusal, got {other:?}"),
    }
}

fn is_review(action: &Action, blind: bool) -> bool {
    matches!(action, Action::ReviewTx { blind: b } if *b == blind)
}

fn has(items: &[(String, String)], title: &str) -> bool {
    items.iter().any(|(t, _)| t == title)
}

fn value<'a>(items: &'a [(String, String)], title: &str) -> &'a str {
    &items.iter().find(|(t, _)| t == title).unwrap().1
}

// ---- V9 -----------------------------------------------------------------------

/// PoC P1: the device entry has `clist: []`, a second signer scopes a transfer.
#[test]
fn v9_v10_p1_empty_clist_beside_another_signer() {
    let json = with_signers(&format!(
        r#"[{{"pubKey":"{}","clist":[]}},{{"pubKey":"{}","clist":[{}]}}]"#,
        dev(),
        other(),
        transfer(&dev(), "1000.0")
    ));
    // Blind signing OFF: refused behind the blind-signing screen.
    let (action, _) = run(&json, false, false);
    assert_eq!(refusal(&action), (msg(BLIND_REQUIRED), 0x6984, true));
    // ON: a blind review of the device's own (unscoped) entry, with the warning
    // and the signer count; nothing of the other entry's capabilities.
    let (action, items) = run(&json, true, false);
    assert!(is_review(&action, true));
    assert_eq!(value(&items, "Of Key"), dev());
    assert_eq!(value(&items, "Unscoped Signer"), dev());
    assert!(has(&items, "WARNING"));
    assert_eq!(value(&items, "Signers"), "2");
    assert!(!items.iter().any(|(t, _)| t.starts_with("Transfer")));
}

/// PoC P2: the device key in two entries (Pact keeps the last one).
#[test]
fn v9_p2_duplicate_device_entry_is_refused() {
    let json = with_signers(&format!(
        r#"[{{"pubKey":"{d}","clist":[{}]}},{{"pubKey":"{d}","clist":[{}]}}]"#,
        transfer(&dev(), "1.0"),
        transfer(&dev(), "1000.0"),
        d = dev()
    ));
    for blind in [false, true] {
        for legacy in [false, true] {
            let (action, _) = run(&json, blind, legacy);
            let expect = if legacy {
                (vec![], 0x6984, false)
            } else {
                (msg(SIGNS_TWICE), 0x6984, false)
            };
            assert_eq!(refusal(&action), expect, "blind {blind} legacy {legacy}");
        }
    }
}

/// The same key twice in different letter case, or once as `addr` of another
/// entry: Pact keys scopes by `addr` else `pubKey`, so both are refused.
#[test]
fn v9_duplicate_by_case_or_addr_is_refused() {
    let upper = dev().to_uppercase();
    for second in [
        format!(
            r#"{{"pubKey":"{upper}","clist":[{}]}}"#,
            transfer(&dev(), "9.0")
        ),
        format!(
            r#"{{"pubKey":"{}","scheme":"WebAuthn","addr":"{}","clist":[]}}"#,
            other(),
            dev()
        ),
        format!(r#"{{"pubKey":"{}","addr":"{upper}"}}"#, other()),
    ] {
        let json = with_signers(&format!(
            r#"[{{"pubKey":"{}","clist":[{}]}},{second}]"#,
            dev(),
            transfer(&dev(), "1.0")
        ));
        let (action, _) = run(&json, true, false);
        assert_eq!(
            refusal(&action),
            (msg(SIGNS_TWICE), 0x6984, false),
            "{second}"
        );
    }
}

/// Case (b): the device entry is not the first one; the review is of it.
#[test]
fn v9_the_device_entry_is_reviewed_wherever_it_is() {
    let json = with_signers(&format!(
        r#"[{{"pubKey":"{}","clist":[{{"args":[],"name":"coin.GAS"}}]}},{{"pubKey":"{}","clist":[{}]}}]"#,
        other(),
        dev(),
        transfer(&dev(), "1000.0")
    ));
    let (action, items) = run(&json, false, false);
    assert!(is_review(&action, false));
    assert_eq!(value(&items, "Of Key"), dev());
    assert_eq!(value(&items, "Signers"), "2");
    assert_eq!(value(&items, "Amount"), "KDA 1000.0");
    assert!(!items
        .iter()
        .any(|(_, v)| v.contains(&other()) && !v.starts_with("k:")));
}

/// One signer: no count is shown.
#[test]
fn v9_single_signer_shows_no_count() {
    let json = with_signers(&format!(
        r#"[{{"pubKey":"{}","clist":[{}]}}]"#,
        dev(),
        transfer(&dev(), "1.0")
    ));
    let (action, items) = run(&json, false, false);
    assert!(is_review(&action, false));
    assert!(!has(&items, "Signers"));
    assert_eq!(value(&items, "Of Key"), dev());
}

#[test]
fn v9_device_key_absent_is_refused() {
    for signers in [
        format!(r#"[{{"pubKey":"{}","clist":[]}}]"#, other()),
        // Only in another letter case.
        format!(r#"[{{"pubKey":"{}","clist":[]}}]"#, dev().to_uppercase()),
        // Only as `addr`.
        format!(r#"[{{"pubKey":"{}","addr":"{}"}}]"#, other(), dev()),
        // Not an array, or not objects (Pact refuses both; the lookup must not
        // read an object as the list, or an array as an entry).
        format!(r#"{{"pubKey":"{}"}}"#, dev()),
        format!(r#"{{"x":{{"pubKey":"{}"}}}}"#, dev()),
        format!(r#"["{}"]"#, dev()),
        format!(r#"[["pubKey","{}"]]"#, dev()),
        "[]".to_string(),
        "null".to_string(),
    ] {
        let json = with_signers(&signers);
        for legacy in [false, true] {
            let (action, _) = run(&json, true, legacy);
            let expect = if legacy {
                (vec![], 0x6984, false)
            } else {
                (msg(NOT_SIGNER), 0x6984, false)
            };
            assert_eq!(refusal(&action), expect, "{signers} legacy {legacy}");
        }
    }
    // No `signers` key at all.
    let json = with_signers("[]").replace("\"signers\"", "\"signerz\"");
    assert_eq!(
        refusal(&run(&json, true, false).0),
        (msg(NOT_SIGNER), 0x6984, false)
    );
}

/// Entries that are not objects are skipped; the count includes them.
#[test]
fn v9_non_object_entries_are_skipped() {
    let json = with_signers(&format!(
        r#"["x",{{"pubKey":"{}","clist":[{}]}}]"#,
        dev(),
        transfer(&dev(), "1.0")
    ));
    let (action, items) = run(&json, false, false);
    assert!(is_review(&action, false));
    assert_eq!(value(&items, "Signers"), "2");
}

/// JSON escapes in a signer entry's key names or key values could hide a second
/// entry from the raw-byte comparison: refused.
#[test]
fn v9_escapes_in_signer_entries_are_refused() {
    let d = dev();
    for signers in [
        // A key name spelled with an escape (u004b for K) decodes to pubKey.
        format!(
            r#"[{{"pubKey":"{d}","clist":[{}]}},{{"pub{}ey":"{d}"}}]"#,
            transfer(&d, "1.0"),
            "\\u004b"
        ),
        // A key value whose first digit is an escape decodes to the device key.
        format!(
            r#"[{{"pubKey":"{d}","clist":[{}]}},{{"pubKey":"\u00{}{}"}}]"#,
            transfer(&d, "1.0"),
            hex::encode(&d[..1]),
            &d[1..]
        ),
        format!(
            r#"[{{"pubKey":"{d}","addr":"\u00{}{}"}}]"#,
            hex::encode(&d[..1]),
            &d[1..]
        ),
    ] {
        let json = with_signers(&signers);
        let (action, _) = run(&json, true, false);
        assert_eq!(
            refusal(&action),
            (msg("Unexpected characters"), 0x6984, false),
            "{signers}"
        );
    }
}

// ---- V10 / V11 ------------------------------------------------------------------

#[test]
fn v10_v11_empty_missing_or_null_clist_is_blind_signing() {
    for clist in [r#","clist":[]"#, r#","clist":null"#, ""] {
        let json = with_signers(&format!(r#"[{{"pubKey":"{}"{clist}}}]"#, dev()));
        let (action, _) = run(&json, false, false);
        assert_eq!(
            refusal(&action),
            (msg(BLIND_REQUIRED), 0x6984, true),
            "{clist}"
        );
        // Legacy 0x03 shows the same screen and reply.
        let (action, _) = run(&json, false, true);
        assert_eq!(
            refusal(&action),
            (msg(BLIND_REQUIRED), 0x6984, true),
            "{clist}"
        );
        for legacy in [false, true] {
            let (action, items) = run(&json, true, legacy);
            assert!(is_review(&action, true), "{clist}");
            assert_eq!(value(&items, "Unscoped Signer"), dev());
            assert!(has(&items, "WARNING"));
        }
    }
}

#[test]
fn v11_unrecognised_meta_or_undisplayable_args_are_blind_signing() {
    let scoped = format!(
        r#"[{{"pubKey":"{}","clist":[{}]}}]"#,
        dev(),
        transfer(&dev(), "1.0")
    );
    let caution = with_signers(&scoped).replace(META, "null");
    let too_large = with_signers(&format!(
        r#"[{{"pubKey":"{}","clist":[{{"args":[1,2,3,4,5,6],"name":"f.B"}}]}}]"#,
        dev()
    ));
    for (json, title) in [(caution, "CAUTION"), (too_large, "WARNING")] {
        let (action, _) = run(&json, false, false);
        assert_eq!(
            refusal(&action),
            (msg(BLIND_REQUIRED), 0x6984, true),
            "{title}"
        );
        let (action, items) = run(&json, true, false);
        assert!(is_review(&action, true), "{title}");
        assert!(has(&items, title));
    }
}

/// A scoped transaction stays a clear-signing review, blind signing ON or OFF,
/// including the V3 case, titled "Key not in transfer" (F6).
#[test]
fn v11_scoped_transactions_stay_clear_signed() {
    for from in [dev(), other()] {
        let json = with_signers(&format!(
            r#"[{{"pubKey":"{}","clist":[{}]}}]"#,
            dev(),
            transfer(&from, "1.0")
        ));
        for blind in [false, true] {
            let (action, items) = run(&json, blind, false);
            assert!(is_review(&action, false), "from {from} blind {blind}");
            assert_eq!(has(&items, "Key not in transfer"), from != dev());
            assert!(!has(&items, "Unscoped Signer"));
        }
    }
}

/// Structured coin transfers (0x24, legacy 0x10) are clear-signed whatever the
/// setting. A token transfer (namespace and module given, e.g. kb-USDC) scopes
/// the key to `<ns>.<module>.TRANSFER`, under which the module's own code can use
/// the key: blind signing with the "Capability not verified" warning (V23), on
/// both commands, as for the same capability in host-built JSON (V20).
#[test]
fn v23_structured_token_transfers_need_blind_signing() {
    let mut tokens = 0;
    for (name, tx_type, params) in zemu_transfers() {
        let token = !params.namespace.is_empty();
        tokens += token as usize;
        let cap = format!(
            "{}.{}.{}",
            params.namespace,
            params.module,
            if tx_type == 2 {
                "TRANSFER_XCHAIN"
            } else {
                "TRANSFER"
            }
        );
        for blind in [false, true] {
            // Legacy 0x10.
            let mut payload = legacy_path(&STD_PATH);
            payload.extend(params.encode(tx_type));
            let mut app = new_app();
            let mut p = mock(blind);
            let r = legacy_send(&mut app, &mut p, 0x10, &payload, true);
            if token && !blind {
                assert_eq!(
                    (r.data.clone(), r.sw, r.blind_screen, r.reviewed),
                    (msg(BLIND_REQUIRED), 0x6984, true, false),
                    "{name}"
                );
            } else {
                assert_eq!(
                    (r.sw, r.reviewed, r.blind_screen),
                    (0x9000, true, false),
                    "{name}"
                );
            }
            // 0x24.
            let mut app = new_app();
            let mut p = mock(blind);
            let body = params.encode(tx_type);
            let r = exchange(
                &mut app,
                &mut p,
                &apdu(0, 0x24, 0, 0, &path_bytes(&STD_PATH)),
                true,
            );
            assert_eq!(r.sw, 0x9000);
            let chunks: Vec<&[u8]> = body.chunks(250).collect();
            for c in &chunks[..chunks.len() - 1] {
                exchange(&mut app, &mut p, &apdu(0, 0x24, 1, 0, c), true);
            }
            let action = app.handle(&mut p, 0, 0x24, 2, 0, chunks[chunks.len() - 1]);
            if !token {
                assert!(is_review(&action, false), "{name} blind {blind}");
                let items = review_items(&app, &p);
                assert!(
                    !items
                        .iter()
                        .any(|(_, v)| v.starts_with("Capability not verified")),
                    "{name}"
                );
            } else if blind {
                assert!(is_review(&action, true), "{name}");
                let items = review_items(&app, &p);
                assert!(shows_unverified(&items, &cap), "{name}: {items:?}");
            } else {
                assert_eq!(
                    refusal(&action),
                    (msg(BLIND_REQUIRED), 0x6984, true),
                    "{name}"
                );
            }
        }
        if !token {
            continue;
        }
        // The same template sent by the host as JSON (V20): the same outcome.
        let json = params.host_json(tx_type, &dev());
        for legacy in [false, true] {
            let (action, _) = run(&json, false, legacy);
            assert_eq!(
                refusal(&action),
                (msg(BLIND_REQUIRED), 0x6984, true),
                "{name} legacy {legacy}"
            );
            let (action, items) = run(&json, true, legacy);
            assert!(is_review(&action, true), "{name} legacy {legacy}");
            assert!(shows_unverified(&items, &cap), "{name}: {items:?}");
        }
    }
    assert!(tokens > 0);
}

// ---- V12 --------------------------------------------------------------------------

#[test]
fn v12_trailing_bytes_and_nul_are_refused() {
    let base = with_signers(&format!(
        r#"[{{"pubKey":"{}","clist":[{}]}}]"#,
        dev(),
        transfer(&dev(), "1.0")
    ));
    // Whitespace after the value is fine.
    for tail in [" ", "\n", "\r\n\t "] {
        let (action, _) = run(&format!("{base}{tail}"), false, false);
        assert!(is_review(&action, false), "{tail:?}");
    }
    for (json, message) in [
        (format!("{base}{{}}"), "Unexpected unparsed bytes"),
        (format!("{base} x"), "Unexpected unparsed bytes"),
        (format!("{base},"), "Unexpected unparsed bytes"),
        (format!("{base}\0{{\"a\":1}}"), "Unexpected characters"),
        (
            base.replacen("\"n\"", "\"n\0\"", 1),
            "Unexpected characters",
        ),
    ] {
        let (action, _) = run(&json, true, false);
        assert_eq!(refusal(&action), (msg(message), 0x6984, false), "{json:?}");
        // Legacy 0x03: bare 0x6984.
        let (action, _) = run(&json, true, true);
        assert_eq!(refusal(&action), (vec![], 0x6984, false), "{json:?}");
    }
}

// ---- Round 2: V14-V16, fee and validity window ------------------------------------

fn rotate_cmd(clist: &str) -> String {
    format!(
        r#"{{"networkId":"mainnet01","payload":{{"exec":{{"data":{{"new":{{"keys":["attacker"],"pred":"keys-all"}}}},"code":"(coin.rotate \"alice\" (read-keyset \"new\"))"}}}},"signers":[{{"pubKey":"{}","clist":{clist}}}],"meta":{META},"nonce":"n"}}"#,
        dev()
    )
}

/// R2-1 (the review's rotate proof): a signature scoped to coin.ROTATE lets the
/// undisplayed code and data pick the new guard. It needs blind signing (V14).
#[test]
fn v14_rotation_needs_blind_signing() {
    for clist in [
        r#"[{"args":[],"name":"coin.GAS"},{"args":["alice"],"name":"coin.ROTATE"}]"#,
        // Any arguments.
        r#"[{"args":["alice","x"],"name":"coin.ROTATE"}]"#,
        r#"[{"args":[],"name":"coin.ROTATE"}]"#,
    ] {
        let json = rotate_cmd(clist);
        for legacy in [false, true] {
            let (action, _) = run(&json, false, legacy);
            assert_eq!(
                refusal(&action),
                (msg(BLIND_REQUIRED), 0x6984, true),
                "{clist}"
            );
            let (action, items) = run(&json, true, legacy);
            assert!(is_review(&action, true), "{clist}");
            assert!(items.contains(&(
                "WARNING".into(),
                String::from_utf8(kadena_core::items::ROTATE_WARNING_TEXT.to_vec()).unwrap()
            )));
        }
    }
}

fn gas_cmd(limit: &str, price: &str) -> String {
    with_signers(&format!(
        r#"[{{"pubKey":"{}","clist":[{}]}}]"#,
        dev(),
        transfer(&dev(), "1.0")
    ))
    .replace(
        r#""gasLimit":600,"chainId":"0","gasPrice":1.0e-6"#,
        &format!(r#""gasLimit":{limit},"chainId":"0","gasPrice":{price}"#),
    )
}

/// R2-2: the maximum fee, exactly, and the account that pays it (V15).
#[test]
fn v15_max_fee_and_paying_account() {
    for (limit, price, fee) in [
        ("600", "1.0e-6", "KDA 0.0006"),
        ("150000", "1e+2", "KDA 15000000"),
        ("2300", "0.00000001", "KDA 0.000023"),
        ("1500", "2.5", "KDA 3750"),
        ("3", "0.1", "KDA 0.3"),
        ("600", "1.0E-5", "KDA 0.006"),
    ] {
        let (action, items) = run(&gas_cmd(limit, price), false, false);
        assert!(is_review(&action, false), "{limit} x {price}");
        assert_eq!(value(&items, "Max fee"), fee, "{limit} x {price}");
        assert_eq!(value(&items, "Paying account"), "s");
    }
    // A gas value that is not a non-negative number, or a fee too long to show.
    for (limit, price) in [("600", "-1.0"), ("600", r#""cheap""#), ("1", "1e-300")] {
        let (action, _) = run(&gas_cmd(limit, price), true, false);
        assert_eq!(
            refusal(&action),
            (msg(UNRECOGNIZED), 0x6984, false),
            "{limit} x {price}"
        );
    }
    // A gas limit that is not plain digits is refused earlier (V15 integers).
    let (action, _) = run(&gas_cmd("-600", "1.0"), true, false);
    assert_eq!(
        refusal(&action),
        (msg("Unexpected characters"), 0x6984, false)
    );
    // A structured transfer with an exponent price (the review's R2-2 case).
    let (_, _, mut params) = zemu_transfers().remove(0);
    params.gas_price = "1e+2";
    params.gas_limit = "150000";
    let mut app = new_app();
    let mut p = mock(false);
    exchange(
        &mut app,
        &mut p,
        &apdu(0, 0x24, 0, 0, &path_bytes(&STD_PATH)),
        true,
    );
    let action = app.handle(&mut p, 0, 0x24, 2, 0, &params.encode(0));
    assert!(is_review(&action, false));
    let items = review_items(&app, &p);
    assert_eq!(value(&items, "Max fee"), "KDA 15000000");
    assert_eq!(value(&items, "Paying account"), format!("k:{}", dev()));
}

fn not_principal() -> (String, String) {
    (
        "WARNING".into(),
        String::from_utf8(kadena_core::items::NOT_PRINCIPAL_TEXT.to_vec()).unwrap(),
    )
}

/// R2-4: a transfer to a vanity (non-principal) account gets a WARNING (V16);
/// it stays a clear-signing review.
#[test]
fn v16_non_principal_receiver_is_flagged() {
    let d = dev();
    let xchain =
        |to: &str| format!(r#"{{"args":["k:{d}","{to}",1.0,"2"],"name":"coin.TRANSFER_XCHAIN"}}"#);
    for (cap, flagged) in [
        (
            transfer(&d, "1.0").replace(&format!("k:{}", other()), "bob"),
            true,
        ),
        (
            transfer(&d, "1.0").replace(&format!("k:{}", other()), "k:bob"),
            true,
        ),
        (
            transfer(&d, "1.0").replace(&format!("\"k:{}\"", other()), "7"),
            true,
        ),
        (transfer(&d, "1.0"), false),
        (
            transfer(&d, "1.0").replace(&format!("k:{}", other()), "r:free.ks"),
            false,
        ),
        (xchain("bob"), true),
        (xchain(&format!("k:{}", other())), false),
    ] {
        let json = with_signers(&format!(r#"[{{"pubKey":"{d}","clist":[{cap}]}}]"#));
        let (action, items) = run(&json, false, false);
        assert!(is_review(&action, false), "{cap}");
        assert_eq!(items.contains(&not_principal()), flagged, "{cap}");
        if flagged {
            // Right after the transfer's items.
            let at = items.iter().position(|i| *i == not_principal()).unwrap();
            assert!(
                items[at - 1].0 == "Amount" || items[at - 1].0 == "To Chain",
                "{cap}"
            );
        }
    }
    // Every Zemu structured transfer pays a k: account: no warning.
    for (name, tx_type, params) in zemu_transfers() {
        let mut app = new_app();
        let mut p = mock(false);
        exchange(
            &mut app,
            &mut p,
            &apdu(0, 0x24, 0, 0, &path_bytes(&STD_PATH)),
            true,
        );
        app.handle(&mut p, 0, 0x24, 2, 0, &params.encode(tx_type));
        assert!(!review_items(&app, &p).contains(&not_principal()), "{name}");
    }
}

/// The review shows, in this order, "WARNING: Capability not verified",
/// "Capability: <module>.<NAME>", "Namespace: <namespace>" when the name has one
/// (no Namespace item otherwise), and the arguments: each piece whole, the
/// namespaced name never in one item.
fn shows_unverified(items: &[(String, String)], name: &str) -> bool {
    let mut want = vec![("WARNING", "Capability not verified")];
    match name.split_once('.') {
        Some((ns, rest)) if rest.contains('.') => {
            want.push(("Capability", rest));
            want.push(("Namespace", ns));
        }
        _ => want.push(("Capability", name)),
    }
    let n = want.len();
    items.windows(n + 1).any(|w| {
        w[..n]
            .iter()
            .zip(&want)
            .all(|((k, v), (wk, wv))| k == wk && v == wv)
            && w[n].0 == "Arguments"
            && !w[n].1.contains(name)
    })
}

/// R3 F1: the review's DEBIT body (the hidden code installs and moves any
/// amount), a CREDIT body, other coin and non-coin capabilities, and a transfer
/// of the wrong arity: blind signing only (V20), on 0x22 and 0x03.
#[test]
fn v20_unverified_capabilities_need_blind_signing() {
    let d = dev();
    let debit_code = format!(
        r#"(install-capability (coin.TRANSFER \"k:{d}\" \"k:{o}\" 1000.0)) (coin.transfer \"k:{d}\" \"k:{o}\" 1000.0)"#,
        o = other()
    );
    let body = |clist: &str| {
        format!(
            r#"{{"networkId":"mainnet01","payload":{{"exec":{{"data":{{}},"code":"{debit_code}"}}}},"signers":[{{"pubKey":"{d}","clist":{clist}}}],"meta":{META},"nonce":"r3"}}"#
        )
    };
    for (name, cap) in [
        (
            "coin.DEBIT",
            format!(r#"{{"name":"coin.DEBIT","args":["k:{d}"]}}"#),
        ),
        (
            "coin.CREDIT",
            format!(r#"{{"name":"coin.CREDIT","args":["k:{d}"]}}"#),
        ),
        ("coin.FOO", r#"{"name":"coin.FOO","args":[]}"#.to_string()),
        (
            "free.evil.X",
            r#"{"name":"free.evil.X","args":["a"]}"#.to_string(),
        ),
        (
            "coin.TRANSFER",
            format!(
                r#"{{"name":"coin.TRANSFER","args":["k:{d}","k:{}"]}}"#,
                other()
            ),
        ),
        (
            "coin.TRANSFER_XCHAIN",
            format!(
                r#"{{"name":"coin.TRANSFER_XCHAIN","args":["k:{d}","k:{}",1.0]}}"#,
                other()
            ),
        ),
    ] {
        let json = body(&format!(r#"[{{"name":"coin.GAS","args":[]}},{cap}]"#));
        for legacy in [false, true] {
            let (action, _) = run(&json, false, legacy);
            assert_eq!(
                refusal(&action),
                (msg(BLIND_REQUIRED), 0x6984, true),
                "{name} legacy {legacy}"
            );
            let (action, items) = run(&json, true, legacy);
            assert!(is_review(&action, true), "{name}");
            assert!(shows_unverified(&items, name), "{name}: {items:?}");
        }
    }
    // Clear-signed: coin.GAS and full transfers only.
    let json = body(&format!(
        r#"[{{"name":"coin.GAS","args":[]}},{},{{"name":"coin.TRANSFER_XCHAIN","args":["k:{d}","k:{}",1.0,"2"]}}]"#,
        transfer(&d, "1.0"),
        other()
    ));
    let (action, items) = run(&json, false, false);
    assert!(is_review(&action, false));
    assert!(!items
        .iter()
        .any(|(_, v)| v.starts_with("Capability not verified")));
}

/// R3 F2: an amount in exponent notation is refused (V21).
#[test]
fn v21_exponent_amounts_are_refused() {
    let d = dev();
    for amount in ["1.0000000001e3", "1e3", "1E3", "1.0e-1"] {
        let json = with_signers(&format!(
            r#"[{{"pubKey":"{d}","clist":[{}]}}]"#,
            transfer(&d, amount)
        ));
        for legacy in [false, true] {
            let (action, _) = run(&json, true, legacy);
            let expect = if legacy {
                (vec![], 0x6984, false)
            } else {
                (msg("Unexpected characters"), 0x6984, false)
            };
            assert_eq!(refusal(&action), expect, "{amount}");
        }
        let json = with_signers(&format!(
            r#"[{{"pubKey":"{d}","clist":[{{"args":["k:{d}","k:{}",{amount},"2"],"name":"coin.TRANSFER_XCHAIN"}}]}}]"#,
            other()
        ));
        let (action, _) = run(&json, true, false);
        assert_eq!(
            refusal(&action),
            (msg("Unexpected characters"), 0x6984, false),
            "{amount}"
        );
    }
    let json = with_signers(&format!(
        r#"[{{"pubKey":"{d}","clist":[{}]}}]"#,
        transfer(&d, r#"{"decimal":"1e3"}"#)
    ));
    let (action, _) = run(&json, true, false);
    assert_eq!(
        refusal(&action),
        (msg("Unexpected characters"), 0x6984, false),
        "decimal object"
    );
    let json = with_signers(&format!(
        r#"[{{"pubKey":"{d}","clist":[{}]}}]"#,
        transfer(&d, "1000.0000001")
    ));
    let (action, items) = run(&json, false, false);
    assert!(is_review(&action, false));
    assert_eq!(value(&items, "Amount"), "KDA 1000.0000001");
}

/// R4-2 and its amendment (V24): a transfer amount is a bare JSON number or
/// Pact's decimal object `{"decimal":"<number>"}` (what @kadena/client sends),
/// the number being `(0|[1-9][0-9]*)(.[0-9]+)?`; the review shows the plain
/// number. Every other shape is refused, with Blind signing ON or OFF, on 0x22
/// and 0x03 (the same set as the C v1.3.1 patch).
#[test]
fn v24_amount_forms() {
    let d = dev();
    for amount in [
        r#"{"decimal":"1\u0030\u0030\u0030.0"}"#,
        r#"{"decimal":"1e3"}"#,
        r#"{"decimal":"-1.0"}"#,
        r#"{"decimal":"01.0"}"#,
        r#"{"decimal":""}"#,
        r#"{"decimal":".5"}"#,
        r#"{"decimal":"1."}"#,
        r#"{"decimal":1000.0}"#,
        r#"{"decimal":{"decimal":"1000.0"}}"#,
        r#"{"decimal":"1000.0","x":1}"#,
        r#"{"x":"1000.0"}"#,
        r#"{}"#,
        r#"{"int":1000}"#,
        r#""1000.0""#,
        "-1.0",
        "+1.0",
        "1e3",
        "01.0",
        "00",
        "1.",
        ".5",
        "true",
        "null",
        "[1000]",
        // R5-2: an unquoted key (the tokenizer accepts it; the node does not).
        r#"{decimal:"1.5"}"#,
    ]
    .into_iter()
    .map(String::from)
    // V25 (R5-1): more than 12 fractional digits, coin's precision, in either
    // form; pact-5 rounds a JSON number at 255 places.
    .chain([
        "1.1234567890123".to_string(),
        r#"{"decimal":"1.1234567890123"}"#.to_string(),
        format!("0.{}", "9".repeat(256)),
        format!(r#"{{"decimal":"0.{}"}}"#, "9".repeat(256)),
    ]) {
        let amount = amount.as_str();
        let json = with_signers(&format!(
            r#"[{{"pubKey":"{d}","clist":[{}]}}]"#,
            transfer(&d, amount)
        ));
        for blind in [false, true] {
            for legacy in [false, true] {
                let (action, _) = run(&json, blind, legacy);
                let expect = if legacy {
                    (vec![], 0x6984, false)
                } else {
                    (msg("Unexpected characters"), 0x6984, false)
                };
                assert_eq!(
                    refusal(&action),
                    expect,
                    "{amount} blind {blind} legacy {legacy}"
                );
            }
        }
        let json = with_signers(&format!(
            r#"[{{"pubKey":"{d}","clist":[{{"args":["k:{d}","k:{}",{amount},"2"],"name":"coin.TRANSFER_XCHAIN"}}]}}]"#,
            other()
        ));
        let (action, _) = run(&json, false, false);
        assert_eq!(
            refusal(&action),
            (msg("Unexpected characters"), 0x6984, false),
            "xchain {amount}"
        );
    }
    // Accepted: both forms, clear-signed, the plain number shown.
    for (amount, shown) in [
        ("1000", "1000"),
        ("1000.0", "1000.0"),
        ("0", "0"),
        ("0.000000000001", "0.000000000001"),
        (r#"{"decimal":"231"}"#, "231"),
        (r#"{"decimal":"0.5"}"#, "0.5"),
        (
            r#"{"decimal":"123456789.0123456789"}"#,
            "123456789.0123456789",
        ),
        // V25: 12 fractional digits are accepted and shown.
        ("1.123456789012", "1.123456789012"),
        (r#"{"decimal":"1.123456789012"}"#, "1.123456789012"),
    ] {
        for legacy in [false, true] {
            let json = with_signers(&format!(
                r#"[{{"pubKey":"{d}","clist":[{}]}}]"#,
                transfer(&d, amount)
            ));
            let (action, items) = run(&json, false, legacy);
            assert!(is_review(&action, false), "{amount}");
            assert_eq!(value(&items, "Amount"), format!("KDA {shown}"), "{amount}");
            let json = with_signers(&format!(
                r#"[{{"pubKey":"{d}","clist":[{{"args":["k:{d}","k:{}",{amount},"2"],"name":"coin.TRANSFER_XCHAIN"}}]}}]"#,
                other()
            ));
            let (action, items) = run(&json, false, legacy);
            assert!(is_review(&action, false), "xchain {amount}");
            assert_eq!(
                value(&items, "Amount"),
                format!("KDA {shown}"),
                "xchain {amount}"
            );
        }
    }
}

/// R3 F4: gasLimit, ttl and creationTime are integers on the node; anything but
/// plain digits is refused, so "Max fee" is exact.
#[test]
fn v15_integer_gas_fields() {
    for (field, bad) in [
        ("gasLimit", "1.5"),
        ("gasLimit", "6e2"),
        ("gasLimit", r#""600""#),
        ("ttl", "28800.0"),
        ("creationTime", "1e3"),
    ] {
        let json = gas_cmd("600", "1.0e-6").replace(
            &format!(
                r#""{field}":{}"#,
                if field == "gasLimit" {
                    "600"
                } else if field == "ttl" {
                    "28800"
                } else {
                    "0"
                }
            ),
            &format!(r#""{field}":{bad}"#),
        );
        assert!(json.contains(bad), "{field}");
        let (action, _) = run(&json, true, false);
        assert_eq!(
            refusal(&action),
            (msg("Unexpected characters"), 0x6984, false),
            "{field} {bad}"
        );
    }
    let (action, items) = run(&gas_cmd("1500", "1000.0"), false, false);
    assert!(is_review(&action, false));
    assert_eq!(value(&items, "Max fee"), "KDA 1500000");
}

/// R3 F6: a scoped signature whose transfer does not name the key is titled
/// "Key not in transfer"; "Unscoped Signer" is only for a signer without
/// capabilities.
#[test]
fn f6_scoped_signature_is_not_called_unscoped() {
    let json = with_signers(&format!(
        r#"[{{"pubKey":"{}","clist":[{}]}}]"#,
        dev(),
        transfer(&other(), "1.0")
    ));
    let (action, items) = run(&json, false, false);
    assert!(is_review(&action, false));
    assert_eq!(value(&items, "Key not in transfer"), dev());
    assert!(!has(&items, "Unscoped Signer"));
    let json = with_signers(&format!(r#"[{{"pubKey":"{}"}}]"#, dev()));
    let (_, items) = run(&json, true, false);
    assert_eq!(value(&items, "Unscoped Signer"), dev());
    assert!(!has(&items, "Key not in transfer"));
}

/// R3 F7: signature verifiers are refused; expert mode shows exec or cont.
#[test]
fn f7_verifiers_refused_and_payload_kind_shown() {
    let base = with_signers(&format!(
        r#"[{{"pubKey":"{}","clist":[{}]}}]"#,
        dev(),
        transfer(&dev(), "1.0")
    ));
    for v in ["[]", "null", r#"[{"name":"x","proof":"p","clist":[]}]"#] {
        let json = base.replacen(
            r#""nonce":"n""#,
            &format!(r#""nonce":"n","verifiers":{v}"#),
            1,
        );
        let (action, _) = run(&json, true, false);
        assert_eq!(
            refusal(&action),
            (msg("Unexpected value"), 0x6984, false),
            "{v}"
        );
        let (action, _) = run(&json, true, true);
        assert_eq!(refusal(&action), (vec![], 0x6984, false), "{v}");
    }
    let (i, j) = (
        base.find(r#""payload":"#).unwrap(),
        base.find(r#","signers""#).unwrap(),
    );
    let cont = format!(
        "{}{}{}",
        &base[..i],
        r#""payload":{"cont":{"pactId":"PACT-ID-1","step":1,"rollback":false,"data":{},"proof":null}}"#,
        &base[j..]
    );
    for (json, kind) in [(&base, "exec (code)"), (&cont, "cont (continuation)")] {
        let mut app = new_app();
        let mut p = Mock {
            expert: true,
            ..mock(false)
        };
        exchange(
            &mut app,
            &mut p,
            &apdu(0, 0x22, 0, 0, &path_bytes(&STD_PATH)),
            false,
        );
        let chunks: Vec<&[u8]> = json.as_bytes().chunks(250).collect();
        for c in &chunks[..chunks.len() - 1] {
            exchange(&mut app, &mut p, &apdu(0, 0x22, 1, 0, c), false);
        }
        let action = app.handle(&mut p, 0, 0x22, 2, 0, chunks[chunks.len() - 1]);
        assert!(is_review(&action, false), "{kind}");
        let items = review_items(&app, &p);
        assert_eq!(value(&items, "Payload"), kind);
        if kind.starts_with("cont") {
            assert_eq!(value(&items, "Pact ID"), "PACT-ID-1");
            assert_eq!(value(&items, "Step"), "1");
        } else {
            assert!(!has(&items, "Pact ID"));
        }
    }
}

/// R2-5: expert mode shows the validity window as sent.
#[test]
fn expert_mode_shows_creation_time_and_ttl() {
    let json =
        gas_cmd("600", "1.0e-6").replace(r#""creationTime":0"#, r#""creationTime":1759140000"#);
    for expert in [false, true] {
        let mut app = new_app();
        let mut p = Mock {
            expert,
            ..mock(false)
        };
        let r = exchange(
            &mut app,
            &mut p,
            &apdu(0, 0x22, 0, 0, &path_bytes(&STD_PATH)),
            false,
        );
        assert_eq!(r.sw, 0x9000);
        let chunks: Vec<&[u8]> = json.as_bytes().chunks(250).collect();
        for c in &chunks[..chunks.len() - 1] {
            exchange(&mut app, &mut p, &apdu(0, 0x22, 1, 0, c), false);
        }
        let action = app.handle(&mut p, 0, 0x22, 2, 0, chunks[chunks.len() - 1]);
        assert!(is_review(&action, false));
        let items = review_items(&app, &p);
        let find = |t: &str| items.iter().find(|(k, _)| k == t).map(|(_, v)| v.clone());
        if expert {
            assert_eq!(find("Created (unix time)").as_deref(), Some("1759140000"));
            assert_eq!(find("TTL (seconds)").as_deref(), Some("28800"));
        } else {
            assert_eq!(find("Created (unix time)"), None);
            assert_eq!(find("TTL (seconds)"), None);
        }
    }
}

// ---- V18: escaped and duplicate keys (C v1.3.1 review, attacks A1-A4, A8) ----------

const GAS: &str = r#"{"args":[],"name":"coin.GAS"}"#;

/// The C review's command shape: code, the device entry's clist, then `tail`
/// inserted after the signers (before `"meta"`).
fn k_cmd(code: &str, signers_key: &str, clist: &str, before_meta: &str) -> String {
    format!(
        r#"{{"networkId":"mainnet01","payload":{{"exec":{{"data":{{}},"code":"{code}"}}}},"{signers_key}":[{{"pubKey":"{d}","clist":{clist}}}],{before_meta}"meta":{META},"nonce":"n"}}"#,
        d = dev()
    )
}

fn xfer_code(amount: &str) -> String {
    format!(
        r#"(coin.transfer \"k:{}\" \"k:{}\" {amount})"#,
        dev(),
        other()
    )
}

const ROTATE_CODE: &str = r#"(coin.rotate \"alice\" (read-keyset \"new\"))"#;

fn key_attacks() -> Vec<(&'static str, String)> {
    let d = dev();
    let o = other();
    let t1000 = format!(r#"{{"args":["k:{d}","k:{o}",1000.0],"name":"coin.TRANSFER"}}"#);
    vec![
        // A1: an escaped "name" turns the shown coin.GAS into a 1000 transfer.
        (
            "A1",
            k_cmd(
                &xfer_code("1000.0"),
                "signers",
                &format!(
                    r#"[{{"n\u0061me":"coin.TRANSFER","args":["k:{d}","k:{o}",1000.0],"name":"coin.GAS"}},{GAS}]"#
                ),
                "",
            ),
        ),
        // A2: an escaped "signers" before the real one.
        (
            "A2",
            k_cmd(
                &xfer_code("1000.0"),
                "signers",
                &format!("[{},{GAS}]", transfer(&d, "1.0")),
                "",
            )
            .replacen(
                r#""signers":"#,
                &format!(
                    r#""sign\u0065rs":[{{"pubKey":"{d}","clist":[{t1000},{GAS}]}}],"signers":"#
                ),
                1,
            ),
        ),
        // A3: an escaped ROTATE name value.
        (
            "A3",
            k_cmd(
                ROTATE_CODE,
                "signers",
                &format!(r#"[{GAS},{{"args":["alice"],"name":"coin.\u0052OTATE"}}]"#),
                "",
            ),
        ),
        // A4: an escaped "name" key hides the rotation.
        (
            "A4",
            k_cmd(
                ROTATE_CODE,
                "signers",
                &format!(
                    r#"[{GAS},{{"n\u0061me":"coin.ROTATE","args":["alice"],"name":"coin.GAS"}}]"#
                ),
                "",
            ),
        ),
        // A8: an escaped "meta" hides a 150000 x 0.1 fee.
        (
            "A8",
            k_cmd(
                &xfer_code("1.0"),
                "signers",
                &format!("[{},{GAS}]", transfer(&d, "1.0")),
                &format!(
                    r#""m\u0065ta":{{"creationTime":1634009214,"ttl":28800,"gasLimit":150000,"chainId":"0","gasPrice":0.1,"sender":"k:{d}"}},"#
                ),
            ),
        ),
    ]
}

/// Each attack is refused with "Unexpected characters" (bare 0x6984 on 0x03),
/// blind signing ON or OFF.
#[test]
fn v18_escaped_keys_and_cap_names_are_refused() {
    for (name, json) in key_attacks() {
        assert!(json.contains('\\'), "{name}");
        for blind in [false, true] {
            let (action, _) = run(&json, blind, false);
            assert_eq!(
                refusal(&action),
                (msg("Unexpected characters"), 0x6984, false),
                "{name} blind {blind}"
            );
            let (action, _) = run(&json, blind, true);
            assert_eq!(refusal(&action), (vec![], 0x6984, false), "{name} legacy");
        }
    }
}

/// An escaped key anywhere, even where the review reads nothing (exec.data).
#[test]
fn v18_escaped_key_anywhere_is_refused() {
    let base = with_signers(&format!(
        r#"[{{"pubKey":"{}","clist":[{}]}}]"#,
        dev(),
        transfer(&dev(), "1.0")
    ));
    for data in [
        r#"{"k\u0073":1,"ks":2}"#,
        r#"{"na\/me":1}"#,
        r#"{"x\n":1}"#,
        r#"{"a":{"b\u0063":1}}"#,
    ] {
        let json = base.replacen(r#""data":{}"#, &format!(r#""data":{data}"#), 1);
        let (action, _) = run(&json, true, false);
        assert_eq!(
            refusal(&action),
            (msg("Unexpected characters"), 0x6984, false),
            "{data}"
        );
    }
    // Escapes in values are fine.
    let json = base.replacen(r#""nonce":"n""#, r#""nonce":"a\"b\\c\u0041""#, 1);
    let (action, _) = run(&json, false, false);
    assert!(is_review(&action, false));
}

/// Literal duplicates are refused in every object, nested ones included (the C
/// review's R2-1 shapes), and sibling or nested objects may reuse a key.
#[test]
fn v18_literal_duplicates_are_refused_in_nested_objects() {
    let d = dev();
    let control = with_signers(&format!(
        r#"[{{"pubKey":"{d}","clist":[{},{GAS}]}}]"#,
        transfer(&d, "1.0")
    ));
    let (action, _) = run(&control, false, false);
    assert!(is_review(&action, false));
    let dup_name_in_cap = control.replacen(
        GAS,
        r#"{"name":"coin.GAS","args":[],"name":"coin.TRANSFER"}"#,
        1,
    );
    let dup_clist_in_signer = control.replacen(
        &format!(r#"{{"pubKey":"{d}","clist":"#),
        &format!(r#"{{"pubKey":"{d}","clist":[{GAS}],"clist":"#),
        1,
    );
    let deep = control.replacen(r#""data":{}"#, r#""data":{"x":[{"y":{"k":1,"k":2}}]}"#, 1);
    let after_nested = control.replacen(r#""data":{}"#, r#""data":{"a":{"b":1},"c":2,"a":3}"#, 1);
    for (name, json) in [
        ("dup name in cap", dup_name_in_cap),
        ("dup clist in signer", dup_clist_in_signer),
        ("deep", deep),
        ("after nested", after_nested),
    ] {
        for legacy in [false, true] {
            let (action, _) = run(&json, true, legacy);
            let expect = if legacy {
                (vec![], 0x6984, false)
            } else {
                (msg("Unexpected duplicated field"), 0x6984, false)
            };
            assert_eq!(refusal(&action), expect, "{name} legacy {legacy}");
        }
    }
    for data in [
        r#"{"arr":[{"a":1},{"a":2}],"b":{"a":3}}"#,
        r#"{"a":{"a":{"a":1}}}"#,
    ] {
        let json = control.replacen(r#""data":{}"#, &format!(r#""data":{data}"#), 1);
        let (action, _) = run(&json, false, false);
        assert!(is_review(&action, false), "{data}");
    }
}
