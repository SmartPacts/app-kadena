//! APDU-level tests against an in-memory device: JSON signing (0x22, legacy 0x03): chunking, parse errors, review rules, V3, V4, V5.
//!
//! Every refusal branch has a test that fails if the branch is removed. Expected
//! bytes come from the C app (v1.3.0) source, its Zemu suite (same inputs) and,
//! for V1-V4, the emulator reproduction of the C defects (R3). `vN_*` names test
//! intended divergence N (item N of the list in `docs/APDUSPEC.md`).

mod common;
use common::*;

/// The device key in these tests (the mock takes the first signer's key).
const PK: &str = EXPECTED_PK_HEX;
#[allow(unused_imports)]
use kadena_core::app::{Action, App};

#[test]
fn sign_json_signs_blake2b_of_the_exact_bytes() {
    let mut app = new_app();
    let mut p = Mock::default();
    let json = SIMPLE_TRANSFER.as_bytes();
    let r = modern_sign(&mut app, &mut p, 0x22, &STD_PATH, json, true);
    assert_eq!((r.sw, r.reviewed, r.data.len()), (0x9000, true, 64));
    assert!(Mock::verify(&STD_PATH, &blake2b(json), &r.data));
    // Another path signs with its own key.
    let r = modern_sign(&mut app, &mut p, 0x22, &ALT_PATH, json, true);
    assert!(Mock::verify(&ALT_PATH, &blake2b(json), &r.data));
    assert!(!Mock::verify(&STD_PATH, &blake2b(json), &r.data));
}

#[test]
fn sign_json_reject_is_command_not_allowed() {
    let mut app = new_app();
    let mut p = Mock::default();
    let r = modern_sign(
        &mut app,
        &mut p,
        0x22,
        &STD_PATH,
        SIMPLE_TRANSFER.as_bytes(),
        false,
    );
    assert_eq!((r.sw, r.reviewed, r.data.len()), (0x6986, true, 0));
}

#[test]
fn sign_crypto_failure_is_sign_verify_error() {
    let mut app = new_app();
    let mut p = Mock {
        fail_sign: true,
        ..Default::default()
    };
    let r = modern_sign(
        &mut app,
        &mut p,
        0x22,
        &STD_PATH,
        SIMPLE_TRANSFER.as_bytes(),
        true,
    );
    assert_eq!((r.sw, r.data.len()), (0x6F01, 0));
}

#[test]
fn init_path_errors() {
    let mut app = new_app();
    let mut p = Mock::default();
    let data = path_bytes(&STD_PATH);
    assert_eq!(
        exchange(&mut app, &mut p, &apdu(0, 0x22, 0, 0, &data[..19]), true).sw,
        0x6700
    );
    // A failed INIT leaves no stream open.
    assert_eq!(
        exchange(&mut app, &mut p, &apdu(0, 0x22, 1, 0, b"{}"), true).sw,
        0x6987
    );
    let bad = path_bytes(&[H | 44, H | 1, H, 0, 0]);
    assert_eq!(
        exchange(&mut app, &mut p, &apdu(0, 0x22, 0, 0, &bad), true).sw,
        0x6984
    );
    assert_eq!(
        exchange(&mut app, &mut p, &apdu(0, 0x22, 2, 0, b"{}"), true).sw,
        0x6987
    );
}

#[test]
fn init_uses_exactly_20_bytes_and_drops_the_rest() {
    let mut app = new_app();
    let mut p = Mock::default();
    let mut data = path_bytes(&STD_PATH);
    data.extend_from_slice(b"{\"x\"");
    assert_eq!(
        exchange(&mut app, &mut p, &apdu(0, 0x22, 0, 0, &data), true).sw,
        0x9000
    );
    assert!(p.tx.is_empty());
    let json = SIMPLE_TRANSFER.as_bytes();
    let mut r = None;
    for (i, c) in json.chunks(250).enumerate() {
        let p1 = if (i + 1) * 250 >= json.len() { 2 } else { 1 };
        r = Some(exchange(&mut app, &mut p, &apdu(0, 0x22, p1, 0, c), true));
    }
    let r = r.unwrap();
    assert!(Mock::verify(&STD_PATH, &blake2b(json), &r.data));
}

#[test]
fn add_or_last_without_init_is_not_initialized() {
    let mut app = new_app();
    let mut p = Mock::default();
    for ins in [0x22u8, 0x23, 0x24] {
        assert_eq!(
            exchange(&mut app, &mut p, &apdu(0, ins, 1, 0, b"{}"), true).sw,
            0x6987
        );
        assert_eq!(
            exchange(&mut app, &mut p, &apdu(0, ins, 2, 0, b"{}"), true).sw,
            0x6987
        );
    }
}

#[test]
fn unknown_p1_is_invalid_p1p2() {
    let mut app = new_app();
    let mut p = Mock::default();
    for p1 in [3u8, 4, 0x80, 0xFF] {
        let r = exchange(
            &mut app,
            &mut p,
            &apdu(0, 0x22, p1, 0, &path_bytes(&STD_PATH)),
            true,
        );
        assert_eq!(r.sw, 0x6B00, "p1 {p1}");
    }
}

#[test]
fn buffer_holds_exactly_15104_bytes() {
    let mut app = new_app();
    let mut p = Mock::default();
    assert_eq!(
        exchange(
            &mut app,
            &mut p,
            &apdu(0, 0x22, 0, 0, &path_bytes(&STD_PATH)),
            true
        )
        .sw,
        0x9000
    );
    let chunk = [b' '; 250];
    for _ in 0..60 {
        assert_eq!(
            exchange(&mut app, &mut p, &apdu(0, 0x22, 1, 0, &chunk), true).sw,
            0x9000
        );
    }
    // 15000 bytes in; 104 more fit, 105 do not.
    assert_eq!(
        exchange(&mut app, &mut p, &apdu(0, 0x22, 1, 0, &chunk[..104]), true).sw,
        0x9000
    );
    assert_eq!(p.tx.len(), 15104);
    assert_eq!(
        exchange(&mut app, &mut p, &apdu(0, 0x22, 1, 0, &chunk[..1]), true).sw,
        0x6983
    );
    // The overflow closed the stream.
    assert_eq!(
        exchange(&mut app, &mut p, &apdu(0, 0x22, 1, 0, &chunk[..1]), true).sw,
        0x6987
    );
    // Overflow on LAST.
    assert_eq!(
        exchange(
            &mut app,
            &mut p,
            &apdu(0, 0x22, 0, 0, &path_bytes(&STD_PATH)),
            true
        )
        .sw,
        0x9000
    );
    for _ in 0..60 {
        exchange(&mut app, &mut p, &apdu(0, 0x22, 1, 0, &chunk), true);
    }
    assert_eq!(
        exchange(&mut app, &mut p, &apdu(0, 0x22, 2, 0, &chunk[..105]), true).sw,
        0x6983
    );
    assert_eq!(
        exchange(&mut app, &mut p, &apdu(0, 0x22, 2, 0, &chunk[..1]), true).sw,
        0x6987
    );
}

#[test]
fn max_size_transaction_signs() {
    // 15104 bytes: a transfer padded with a long exec.data string.
    let mut app = new_app();
    let mut p = Mock::default();
    let base = SIMPLE_TRANSFER.replace("\"data\":{}", "\"data\":{\"pad\":\"PAD\"}");
    let pad = 15104 - (base.len() - 3);
    let json = base.replace("PAD", &"x".repeat(pad));
    assert_eq!(json.len(), 15104);
    let r = modern_sign(&mut app, &mut p, 0x22, &STD_PATH, json.as_bytes(), true);
    assert_eq!(r.sw, 0x9000);
    assert!(Mock::verify(&STD_PATH, &blake2b(json.as_bytes()), &r.data));
}

#[test]
fn empty_last_is_initialized_empty_context() {
    let mut app = new_app();
    let mut p = Mock::default();
    for ins in [0x22u8, 0x24] {
        let r = modern_sign(&mut app, &mut p, ins, &STD_PATH, &[], true);
        assert_eq!((r.data, r.sw), (msg("Initialized empty context"), 0x6984));
    }
    p.blind = true;
    let r = modern_sign(&mut app, &mut p, 0x23, &STD_PATH, &[], true);
    assert_eq!((r.data, r.sw), (msg("Initialized empty context"), 0x6984));
}

#[test]
fn tokenizer_errors_map_to_the_c_messages() {
    assert_eq!(
        err_msg("{\"a\":\u{1}}"),
        (msg("Unexpected characters"), 0x6984)
    );
    assert_eq!(
        err_msg("{\"a\":\"\\q\"}"),
        (msg("Unexpected characters"), 0x6984)
    );
    assert_eq!(err_msg("[}"), (msg("Unexpected characters"), 0x6984));
    assert_eq!(err_msg("{\"a\":1"), (msg(UNRECOGNIZED), 0x6984));
    assert_eq!(err_msg("   "), (msg(UNRECOGNIZED), 0x6984));
    // V12: a NUL anywhere is refused (C tokenized up to it).
    assert_eq!(err_msg("\0{}"), (msg("Unexpected characters"), 0x6984));
}

#[test]
fn token_cap_is_768_and_110_on_nano_x() {
    // A clist of `n` GAS caps: each adds 5 tokens.
    let json_with = |n: usize| {
        let caps: Vec<String> = (0..n)
            .map(|_| r#"{"args":[],"name":"coin.GAS"}"#.to_string())
            .collect();
        cmd(PK, &format!("[{}]", caps.join(",")))
    };
    let tokens = |n: usize| {
        let s = json_with(n);
        let mut t = vec![kadena_core::jsmn::Token::EMPTY; 2000];
        kadena_core::jsmn::parse(s.as_bytes(), &mut t).unwrap()
    };
    // Find n with <= cap and > cap for both caps.
    for cap in [110usize, 768] {
        let n_ok = (0..200).rev().find(|&n| tokens(n) <= cap).unwrap();
        let ok = json_with(n_ok);
        let bad = json_with(n_ok + 1);
        assert!(tokens(n_ok + 1) > cap);
        if cap == 110 {
            let mut app = Box::new(App::<110>::new());
            let mut p = Mock::default();
            assert!(items_with(&mut app, &mut p, ok.as_bytes()).is_ok());
            let r = items_with(&mut app, &mut p, bad.as_bytes()).unwrap_err();
            assert_eq!(r.data, msg("NOMEM: JSON string contains too many tokens"));
        } else {
            assert!(items_of(ok.as_bytes(), false).is_ok());
            let r = items_of(bad.as_bytes(), false).unwrap_err();
            assert_eq!(
                (r.data, r.sw),
                (msg("NOMEM: JSON string contains too many tokens"), 0x6984)
            );
        }
    }
}

#[test]
fn required_keys() {
    let ok = cmd(PK, r#"[{"args":[],"name":"coin.GAS"}]"#);
    assert!(items_of(ok.as_bytes(), false).is_ok());
    let bad = ok.replace("\"networkId\"", "\"networkIdX\"");
    assert_eq!(err_msg(&bad), (msg(UNRECOGNIZED), 0x6984));
    // V9: without `signers` or `pubKey` the device key is not a signer.
    for (from, to) in [
        ("\"signers\"", "\"signersX\""),
        ("\"pubKey\"", "\"pubKeyX\""),
    ] {
        let bad = ok.replace(from, to);
        assert_eq!(err_msg(&bad), (msg(NOT_SIGNER), 0x6984), "{from}");
    }
    // signers present but empty (V9).
    let bad = ok.replace(
        &format!(r#""signers":[{{"pubKey":"{PK}","clist":[{{"args":[],"name":"coin.GAS"}}]}}]"#),
        r#""signers":[]"#,
    );
    assert_eq!(err_msg(&bad), (msg(NOT_SIGNER), 0x6984));
    // A non-GAS cap without args.
    let bad = cmd(PK, r#"[{"name":"foo.BAR"}]"#);
    assert_eq!(err_msg(&bad), (msg(UNRECOGNIZED), 0x6984));
    // A GAS cap without args is fine.
    assert!(items_of(cmd(PK, r#"[{"name":"coin.GAS"}]"#).as_bytes(), false).is_ok());
    // networkId "" is rejected at validation.
    let bad = ok.replace("\"mainnet01\"", "\"\"");
    assert_eq!(err_msg(&bad), (msg(UNRECOGNIZED), 0x6984));
}

#[test]
fn meta_rules() {
    let clist = r#"[{"args":[],"name":"coin.GAS"}]"#;
    let base = cmd(PK, clist);
    let items = items_of(base.as_bytes(), false).unwrap();
    assert!(items.contains(&("On Chain".into(), "0".into())));
    assert!(items.contains(&("Using Gas".into(), "at most 600 at price 1.0e-6".into())));
    // Out of order, too many keys, a key >= 40 chars, null, missing: CAUTION.
    for meta in [
        r#"{"ttl":28800,"creationTime":0,"gasLimit":600,"chainId":"0","gasPrice":1.0e-6,"sender":"s"}"#,
        r#"{"creationTime":0,"ttl":28800,"gasLimit":600,"chainId":"0","gasPrice":1.0e-6,"sender":"s","x":1}"#,
        r#"{"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa":0}"#,
        "null",
    ] {
        // V11: an unrecognised meta is blind signing.
        let j = base.replace(META, meta);
        assert_eq!(err_msg(&j), (msg(BLIND_REQUIRED), 0x6984), "{meta}");
        let items = blind_items_of(j.as_bytes());
        assert!(
            items
                .iter()
                .any(|(k, v)| k == "CAUTION" && v == "'meta' field of transaction not recognized"),
            "{meta}"
        );
    }
    let j = base.replace(&format!(",\"meta\":{META}"), "");
    assert!(blind_items_of(j.as_bytes())
        .iter()
        .any(|(k, _)| k == "CAUTION"));
    // A canonical prefix of fewer than 5 keys is rejected (chainId / gasPrice read).
    for meta in [
        r#"{"creationTime":0,"ttl":1,"gasLimit":2,"chainId":"0"}"#,
        r#"{"creationTime":0}"#,
    ] {
        let j = base.replace(META, meta);
        assert_eq!(err_msg(&j), (msg(UNRECOGNIZED), 0x6984), "{meta}");
    }
}

#[test]
fn gas_value_too_long_is_rejected() {
    // Zemu negative `gas_len_wrap`: a 301-char gasLimit.
    let clist = r#"[{"args":[],"name":"coin.GAS"}]"#;
    let big = format!("\"1{}\"", "0".repeat(300));
    let j = cmd(PK, clist).replace("\"gasLimit\":600", &format!("\"gasLimit\":{big}"));
    // A quoted gasLimit is not an integer (V15): refused before display.
    assert_eq!(err_msg(&j), (msg("Unexpected characters"), 0x6984));
    // At the bound: gl + gp + 18 + 1 <= 300.
    let gl = "1".repeat(300 - 19 - 6);
    let j = cmd(PK, clist).replace("\"gasLimit\":600", &format!("\"gasLimit\":{gl}"));
    assert!(items_of(j.as_bytes(), false).is_ok());
    let gl = "1".repeat(300 - 19 - 6 + 1);
    let j = cmd(PK, clist).replace("\"gasLimit\":600", &format!("\"gasLimit\":{gl}"));
    assert_eq!(err_msg(&j), (msg(UNRECOGNIZED), 0x6984));
}

#[test]
fn too_many_items_is_rejected_on_every_wrong_arity_branch() {
    // Zemu negatives oob_max_items_transfer / _rotate, plus the XCHAIN branch.
    for name in [
        "coin.TRANSFER",
        "coin.ROTATE",
        "coin.TRANSFER_XCHAIN",
        "foo.BAR",
    ] {
        let caps: Vec<String> = (0..96)
            .map(|_| format!(r#"{{"args":["a","b"],"name":"{name}"}}"#))
            .collect();
        let j = cmd(
            PK,
            &format!(r#"[{{"args":[],"name":"coin.GAS"}},{}]"#, caps.join(",")),
        );
        assert_eq!(err_msg(&j), (msg(UNRECOGNIZED), 0x6984), "{name}");
        // The most that fit stay within 99 items; one more is refused. (A
        // rotation or an unverified capability adds a WARNING item, V14/V20;
        // both are blind signing, so the setting is ON here.)
        let with = |n: usize| {
            let caps: Vec<String> = (0..n)
                .map(|_| format!(r#"{{"args":["a","b"],"name":"{name}"}}"#))
                .collect();
            cmd(PK, &format!(r#"[{}]"#, caps.join(",")))
        };
        let fit = (1..96)
            .rev()
            .find(|&n| review_with_setting(with(n).as_bytes(), true).is_ok())
            .unwrap();
        let (_, items) = review_with_setting(with(fit).as_bytes(), true).unwrap();
        // 99 items at most; each capability takes four (warning, capability,
        // namespace, arguments), so the last one may leave up to three free.
        assert!((96..=99).contains(&items.len()), "{name}: {}", items.len());
        let e = review_with_setting(with(fit + 1).as_bytes(), true).unwrap_err();
        assert_eq!((e.data, e.sw), (msg(UNRECOGNIZED), 0x6984), "{name}");
    }
}

#[test]
fn unknown_capability_rendering() {
    // Blind signing ON: a capability that cannot be displayed makes it a blind
    // review (V11).
    let it = |clist: &str| {
        review_with_setting(cmd(PK, clist).as_bytes(), true)
            .unwrap()
            .1
    };
    let find =
        |items: &[(String, String)], k: &str| items.iter().find(|(t, _)| t == k).unwrap().1.clone();
    // Zemu `unknown_cap_arg_render`.
    assert_eq!(
        find(&it(r#"[{"args":["AB"],"name":"foo.BAR"}]"#), "Arguments"),
        "arg 1: \"AB\""
    );
    assert_eq!(
        find(&it(r#"[{"args":[],"name":"foo.BAR"}]"#), "Arguments"),
        "no args"
    );
    assert_eq!(
        find(
            &it(r#"[{"args":[1,{"a":2},null,[3],"s"],"name":"f.B"}]"#),
            "Arguments"
        ),
        "arg 1: 1, arg 2: {\"a\":2}, arg 3: null, arg 4: [3], arg 5: \"s\""
    );
    // More than 5 args: not displayable + the TX_TOO_LARGE warning.
    let items = it(r#"[{"args":[1,2,3,4,5,6],"name":"f.B"}]"#);
    assert_eq!(
        find(&items, "Arguments"),
        "args cannot be displayed on Ledger"
    );
    assert_eq!(
        items.last().unwrap().1,
        String::from_utf8(kadena_core::items::TX_TOO_LARGE_TEXT.to_vec()).unwrap()
    );
    // Args span > 256 chars: same.
    let long = format!(r#"[{{"args":["{}"],"name":"f.B"}}]"#, "x".repeat(260));
    assert_eq!(
        find(&it(&long), "Arguments"),
        "args cannot be displayed on Ledger"
    );
    // An empty name is rejected.
    assert_eq!(
        err_msg(&cmd(PK, r#"[{"args":[],"name":""}]"#)),
        (msg(UNRECOGNIZED), 0x6984)
    );
    // The largest displayable arguments (5 strings, span <= 256) fit the value
    // whole now that it does not hold the name: 4 * (48 + 11) + (48 + 10) = 294.
    let five = |n: usize| {
        let a: Vec<String> = (0..5).map(|_| format!("\"{}\"", "x".repeat(n))).collect();
        format!(r#"[{{"args":[{}],"name":"f.B"}}]"#, a.join(","))
    };
    let (_, items) = review_with_setting(cmd(PK, &five(48)).as_bytes(), true).unwrap();
    assert_eq!(find(&items, "Arguments").len(), 293);
    assert_eq!(
        find(&it(&five(49)), "Arguments"),
        "args cannot be displayed on Ledger"
    );
}

#[test]
fn namespaced_transfer_shows_as_unknown_capability() {
    // A capability the review cannot verify: blind signing (V20).
    let items = blind_items_of(
        cmd(
            PK,
            &format!(r#"[{{"args":["k:{PK}","k:r",1.0],"name":"n_1.mod.TRANSFER"}}]"#),
        )
        .as_bytes(),
    );
    assert!(items
        .iter()
        .any(|(k, v)| k == "Capability" && v == "mod.TRANSFER"));
    assert!(items.iter().any(|(k, v)| k == "Namespace" && v == "n_1"));
    assert!(items.iter().any(|(k, _)| k == "Arguments"));
    assert!(!items.iter().any(|(k, _)| k.starts_with("Transfer")));
}

#[test]
fn no_clist_shows_unscoped_signer_and_warning() {
    let j = cmd(PK, "null");
    let items = blind_items_of(j.as_bytes());
    assert!(items.contains(&("Unscoped Signer".into(), PK.into())));
    assert!(items.contains(&(
        "WARNING".into(),
        String::from_utf8(kadena_core::items::WARNING_TEXT.to_vec()).unwrap()
    )));
}

fn has_unscoped(arg0: &str) -> bool {
    let pk = EXPECTED_PK_HEX;
    let clist = format!(
        r#"[{{"args":["{arg0}","k:{}",1.0],"name":"coin.TRANSFER"}},{{"args":[],"name":"coin.GAS"}}]"#,
        "b".repeat(64)
    );
    // The signature is scoped; the title says the transfer does not name the key
    // (F6; C titled it "Unscoped Signer").
    items_of(cmd(pk, &clist).as_bytes(), false)
        .unwrap()
        .iter()
        .any(|(k, _)| k == "Key not in transfer")
}

#[test]
fn v3_signer_match_is_exact() {
    let pk = EXPECTED_PK_HEX;
    // Exact, with and without `k:`: scoped.
    assert!(!has_unscoped(&format!("k:{pk}")));
    assert!(!has_unscoped(pk));
    // A different key: unscoped.
    assert!(has_unscoped(&format!("k:{}", "c".repeat(64))));
    // R3 #4: the signer key followed by more bytes. C matched the prefix and hid
    // the warning; the port must show it.
    assert!(has_unscoped(&format!("k:{pk}ff")));
    assert!(has_unscoped(&format!("{pk}ff")));
    // A strict prefix of the key: unscoped too.
    assert!(has_unscoped(&format!("k:{}", &pk[..60])));
}

#[test]
fn v4_duplicate_keys_are_refused_anywhere() {
    let base = cmd(PK, r#"[{"args":[],"name":"coin.GAS"}]"#);
    assert!(items_of(base.as_bytes(), false).is_ok());
    let dup = "Unexpected duplicated field";
    // R3 #5 shapes: networkId twice; a cap with two names; meta key twice.
    let j = base.replacen(
        "{\"networkId\":\"mainnet01\"",
        "{\"networkId\":\"NET_FIRST\",\"networkId\":\"NET_SECOND\"",
        1,
    );
    assert_eq!(err_msg(&j), (msg(dup), 0x6984));
    let j = cmd(
        PK,
        r#"[{"args":[],"name":"coin.GAS","name":"coin.TRANSFER"}]"#,
    );
    assert_eq!(err_msg(&j), (msg(dup), 0x6984));
    let j = base.replace("\"chainId\":\"0\"", "\"chainId\":\"3\",\"chainId\":\"7\"");
    assert_eq!(err_msg(&j), (msg(dup), 0x6984));
    // Duplicates the display never reads (exec.data) are refused too.
    let j = base.replace("\"data\":{}", "\"data\":{\"a\":1,\"a\":2}");
    assert_eq!(err_msg(&j), (msg(dup), 0x6984));
    // The same key spelled with an escape: every escaped key is refused (V18).
    let chars = "Unexpected characters";
    let j = base.replacen(
        "{\"networkId\":\"mainnet01\"",
        "{\"networkId\":\"A\",\"networ\\u006bId\":\"B\"",
        1,
    );
    assert_eq!(err_msg(&j), (msg(chars), 0x6984));
    let j = base.replace("\"data\":{}", "\"data\":{\"a/b\":1,\"a\\/b\":2}");
    assert_eq!(err_msg(&j), (msg(chars), 0x6984));
    // Surrogate pair vs raw UTF-8 of the same character.
    let j = base.replace(
        "\"data\":{}",
        "\"data\":{\"\u{1F600}\":1,\"\\ud83d\\ude00\":2}",
    );
    assert_eq!(err_msg(&j), (msg(chars), 0x6984));
    // Keys that only look alike are fine; the same key in two objects is fine.
    let j = base.replace("\"data\":{}", "\"data\":{\"a\":1,\"A\":2,\"x\":{\"a\":3}}");
    assert!(items_of(j.as_bytes(), false).is_ok());
}

#[test]
fn v4_duplicate_keys_legacy_json_is_bare_6984() {
    let mut app = new_app();
    let mut p = Mock::default();
    let j = SIMPLE_TRANSFER.replacen(
        "{\"networkId\":\"mainnet01\"",
        "{\"networkId\":\"a\",\"networkId\":\"b\"",
        1,
    );
    let r = legacy_send(
        &mut app,
        &mut p,
        0x03,
        &legacy_json_payload(j.as_bytes(), &STD_PATH),
        true,
    );
    assert_eq!((r.sw, r.data.len()), (0x6984, 0));
}

/// Zemu `test_apdu_legacy_blob_*` (chunk boundaries at 230/235 and 2-component paths).
#[test]
fn legacy_json_chunk_boundaries() {
    // The Zemu blobs are 204, 205, 206, 217, 218 and 435 bytes long; their
    // signer keys ("0123", ...) are not the device key, which V9 refuses. The
    // same lengths are rebuilt with the device key as the only, unscoped signer
    // (blind signing ON, V11) and the nonce as padding.
    let blob = |len: usize| {
        let base = format!(
            r#"{{"networkId":"mainnet01","payload":{{"exec":{{"data":{{}},"code":""}}}},"signers":[{{"pubKey":"{PK}"}}],"meta":null,"nonce":""}}"#
        );
        let json = base.replace(
            r#""nonce":"""#,
            &format!(r#""nonce":"{}""#, "x".repeat(len - base.len())),
        );
        assert_eq!(json.len(), len);
        json
    };
    let cases: [(usize, &[u32]); 6] = [
        (204, &STD_PATH),
        (205, &STD_PATH),
        (206, &STD_PATH),
        (217, &[H | 44, H | 626]),
        (218, &[H | 44, H | 626]),
        (435, &STD_PATH),
    ];
    for (len, path) in cases {
        let json = blob(len);
        let mut app = new_app();
        let mut p = Mock {
            blind: true,
            ..Default::default()
        };
        let payload = legacy_json_payload(json.as_bytes(), path);
        let r = legacy_send(&mut app, &mut p, 0x03, &payload, true);
        assert_eq!(
            (r.sw, r.reviewed),
            (0x9000, true),
            "blob {len} ({} bytes)",
            payload.len()
        );
        let mut full = [0u32; 5];
        full[..path.len()].copy_from_slice(path);
        assert!(
            Mock::verify(&full, &blake2b(json.as_bytes()), &r.data),
            "blob {len}"
        );
    }
}

#[test]
fn legacy_json_signs_the_payload_only() {
    let mut app = new_app();
    let mut p = Mock::default();
    let json = SIMPLE_TRANSFER.as_bytes();
    let r = legacy_send(
        &mut app,
        &mut p,
        0x03,
        &legacy_json_payload(json, &STD_PATH),
        true,
    );
    assert_eq!((r.sw, r.data.len()), (0x9000, 64));
    assert!(Mock::verify(&STD_PATH, &blake2b(json), &r.data));
    let r = legacy_send(
        &mut app,
        &mut p,
        0x03,
        &legacy_json_payload(json, &STD_PATH),
        false,
    );
    assert_eq!((r.sw, r.data.len()), (0x6986, 0));
}

#[test]
fn legacy_json_end_detected_on_a_full_last_apdu() {
    // Payload + path = a multiple of 230 bytes: the last APDU is full (rx = 235)
    // and completion comes from legacy_check_end_of_chunk.
    let mut app = new_app();
    let mut p = Mock::default();
    let base = SIMPLE_TRANSFER.replace("\"data\":{}", "\"data\":{\"p\":\"PAD\"}");
    let overhead = 4 + 21;
    let target = 230 * 5;
    let json = base.replace("PAD", &"x".repeat(target - overhead - (base.len() - 3)));
    let payload = legacy_json_payload(json.as_bytes(), &STD_PATH);
    assert_eq!(payload.len(), target);
    let r = legacy_send(&mut app, &mut p, 0x03, &payload, true);
    assert_eq!(r.sw, 0x9000);
    assert!(Mock::verify(&STD_PATH, &blake2b(json.as_bytes()), &r.data));
}

#[test]
fn legacy_json_errors() {
    let mut app = new_app();
    let mut p = Mock::default();
    // First APDU without the 4-byte length.
    assert_eq!(
        exchange(&mut app, &mut p, &apdu(0, 0x03, 0, 0, &[1, 0, 0]), true).sw,
        0x6700
    );
    // Buffer shorter than the announced payload.
    let mut short = (1000u32).to_le_bytes().to_vec();
    short.extend_from_slice(b"{}");
    short.extend(legacy_path(&STD_PATH));
    assert_eq!(
        exchange(&mut app, &mut p, &apdu(0, 0x03, 0, 0, &short), true).sw,
        0x6984
    );
    // Bad path after the payload.
    let bad = legacy_json_payload(b"{}", &[H | 44, H | 1, H, 0, 0]);
    assert_eq!(
        exchange(&mut app, &mut p, &apdu(0, 0x03, 0, 0, &bad), true).sw,
        0x6984
    );
    let mut bad = legacy_json_payload(b"{}", &STD_PATH);
    bad.push(0);
    assert_eq!(
        exchange(&mut app, &mut p, &apdu(0, 0x03, 0, 0, &bad), true).sw,
        0x6700
    );
    let mut bad = (2u32).to_le_bytes().to_vec();
    bad.extend_from_slice(b"{}");
    bad.push(9);
    assert_eq!(
        exchange(&mut app, &mut p, &apdu(0, 0x03, 0, 0, &bad), true).sw,
        0x6984
    );
    // Parse error: bare 0x6984, no message (unlike 0x22).
    let r = exchange(
        &mut app,
        &mut p,
        &apdu(0, 0x03, 0, 0, &legacy_json_payload(b"{\"a\":", &STD_PATH)),
        true,
    );
    assert_eq!((r.sw, r.data.len()), (0x6984, 0));
    let r = exchange(
        &mut app,
        &mut p,
        &apdu(0, 0x03, 0, 0, &legacy_json_payload(b"{}", &STD_PATH)),
        true,
    );
    assert_eq!((r.sw, r.data.len()), (0x6984, 0));
}

#[test]
fn legacy_json_buffer_overflow() {
    let mut app = new_app();
    let mut p = Mock::default();
    let mut first = (20000u32).to_le_bytes().to_vec();
    first.extend(vec![b' '; 226]);
    assert_eq!(
        exchange(&mut app, &mut p, &apdu(0, 0x03, 0, 0, &first), true).sw,
        0x9000
    );
    let chunk = vec![b' '; 230];
    let mut sw = 0x9000;
    for _ in 0..70 {
        sw = exchange(&mut app, &mut p, &apdu(0, 0x03, 0, 0, &chunk), true).sw;
        if sw != 0x9000 {
            break;
        }
    }
    assert_eq!(sw, 0x6983);
    assert!(p.tx.is_empty(), "a legacy overflow resets the buffer");
}

// ---- Render bounds (each fails if its bound is removed) -----------------------

#[test]
fn std_value_bound_is_299() {
    let clist = r#"[{"args":[],"name":"coin.GAS"}]"#;
    let ok = cmd(PK, clist).replace("\"mainnet01\"", &format!("\"{}\"", "n".repeat(299)));
    assert!(items_of(ok.as_bytes(), false).is_ok());
    let bad = cmd(PK, clist).replace("\"mainnet01\"", &format!("\"{}\"", "n".repeat(300)));
    assert_eq!(err_msg(&bad), (msg(UNRECOGNIZED), 0x6984));
}

#[test]
fn amount_bounds() {
    let tr = |amount: &str| {
        cmd(
            PK,
            &format!(r#"[{{"args":["k:{PK}","k:r",{amount}],"name":"coin.TRANSFER"}}]"#),
        )
    };
    assert!(items_of(tr(&"1".repeat(295)).as_bytes(), false).is_ok());
    assert_eq!(err_msg(&tr(&"1".repeat(296))), (msg(UNRECOGNIZED), 0x6984));
    // A string amount is refused by V24 before any display bound applies.
    assert_eq!(err_msg(&tr("\"\"")), (msg("Unexpected characters"), 0x6984));
}

#[test]
fn rotate_bound() {
    let rot = |n: usize| {
        cmd(
            PK,
            &format!(r#"[{{"args":["{}"],"name":"coin.ROTATE"}}]"#, "a".repeat(n)),
        )
    };
    // A rotation is blind signing (V14).
    let items = blind_items_of(rot(297).as_bytes());
    assert!(items
        .iter()
        .any(|(k, v)| k == "Rotate for account" && v.len() == 299));
    assert_eq!(err_msg(&rot(298)), (msg(UNRECOGNIZED), 0x6984));
}

#[test]
fn unknown_capability_name_bounds() {
    // The capability's name and its namespace are each shown whole in their own
    // item, so each is bounded at 299 bytes; the arguments item no longer holds
    // the name.
    for args in ["[]", "[1]", "[1,2,3,4,5,6]"] {
        let plain = |n: usize| {
            cmd(
                PK,
                &format!(r#"[{{"args":{args},"name":"{}"}}]"#, "n".repeat(n)),
            )
        };
        assert!(
            review_with_setting(plain(299).as_bytes(), true).is_ok(),
            "{args}"
        );
        assert_eq!(err_msg(&plain(300)), (msg(UNRECOGNIZED), 0x6984), "{args}");
        // A namespaced name: namespace and the rest bounded separately.
        let ns = |a: usize, b: usize| {
            cmd(
                PK,
                &format!(
                    r#"[{{"args":{args},"name":"{}.{}.X"}}]"#,
                    "s".repeat(a),
                    "m".repeat(b)
                ),
            )
        };
        let (_, items) = review_with_setting(ns(299, 297).as_bytes(), true).unwrap();
        assert!(items
            .iter()
            .any(|(k, v)| k == "Namespace" && v.len() == 299));
        assert!(items
            .iter()
            .any(|(k, v)| k == "Capability" && v.len() == 299));
        assert_eq!(err_msg(&ns(300, 1)), (msg(UNRECOGNIZED), 0x6984), "{args}");
        assert_eq!(err_msg(&ns(1, 298)), (msg(UNRECOGNIZED), 0x6984), "{args}");
    }
}

/// R7-1: a name without a namespace has no Namespace item (a placeholder could
/// read as a namespace: `none` is a valid one), so `none.coin.DEBIT` and
/// `coin.DEBIT` never look alike; an unnamespaced unverified capability is
/// exactly three items: WARNING, Capability, Arguments.
#[test]
fn no_namespace_differs_from_the_namespace_none() {
    let shown = |name: &str| {
        let j = cmd(PK, &format!(r#"[{{"args":["k:{PK}"],"name":"{name}"}}]"#));
        let (_, items) = review_with_setting(j.as_bytes(), true).expect("a review");
        let at = items
            .iter()
            .position(|(k, v)| k == "WARNING" && v == "Capability not verified")
            .unwrap();
        let end = items.iter().position(|(k, _)| k == "Arguments").unwrap();
        items[at..=end].to_vec()
    };
    let plain = shown("coin.DEBIT");
    let none = shown("none.coin.DEBIT");
    assert_eq!(plain.len(), 3, "{plain:?}");
    assert_eq!(plain[1], ("Capability".into(), "coin.DEBIT".into()));
    assert!(!plain.iter().any(|(k, _)| k == "Namespace"));
    assert_eq!(none.len(), 4, "{none:?}");
    assert_eq!(none[1], ("Capability".into(), "coin.DEBIT".into()));
    assert_eq!(none[2], ("Namespace".into(), "none".into()));
    assert_ne!(plain, none);
}

/// R7-3: an empty namespace (or an empty name after it) cannot be shown and is
/// refused, never shown as nothing.
#[test]
fn empty_namespace_is_refused() {
    for name in [".coin.X", "..", ".a.b"] {
        let j = cmd(PK, &format!(r#"[{{"args":[],"name":"{name}"}}]"#));
        for blind in [false, true] {
            let r = review_with_setting(j.as_bytes(), blind);
            let e = r.expect_err(name);
            assert_eq!(
                (e.data, e.sw),
                (msg(UNRECOGNIZED), 0x6984),
                "{name} blind {blind}"
            );
        }
    }
}

/// Fuzz finding (render_unknown): a 293-299 byte name used to be cut by the
/// writer and broke the length bookkeeping. The arguments item no longer holds
/// the name; such names are shown whole in the Capability item.
#[test]
fn unknown_capability_long_names_shown_whole() {
    for n in [292usize, 293, 299] {
        for args in ["[1]", "[]", "[1,2,3,4,5,6]"] {
            let j = cmd(
                PK,
                &format!(r#"[{{"args":{args},"name":"{}"}}]"#, "n".repeat(n)),
            );
            let (_, items) = review_with_setting(j.as_bytes(), true).expect("a review");
            assert!(items
                .iter()
                .any(|(k, v)| k == "Capability" && *v == "n".repeat(n)));
        }
    }
    // The fuzz input itself (also in the fuzz seed corpus): no panic.
    let crash = include_bytes!("../fuzz/seeds/review/crash-fedd1aaebbae43ce");
    for blind in [false, true] {
        let _ = review_with_setting(crash, blind);
    }
}

#[test]
fn meta_with_a_seventh_key_is_not_recognized() {
    let clist = r#"[{"args":[],"name":"coin.GAS"}]"#;
    let j = cmd(PK, clist).replace("\"sender\":\"s\"}", "\"sender\":\"s\",\"\":1}");
    let items = blind_items_of(j.as_bytes());
    assert!(items.iter().any(|(k, _)| k == "CAUTION"));
}

#[test]
fn item_limit_reached_by_expert_items() {
    // 4 + 22 transfers of 4 items + On Chain, Using Gas, Max fee, Paying
    // account = 96 items: fits. Expert mode adds 5 (payload kind, validity
    // window, hash, address): the 100th is refused.
    let t = format!(
        r#"{{"args":["k:{PK}","k:{}",1.0],"name":"coin.TRANSFER"}}"#,
        "b".repeat(64)
    );
    let caps: Vec<&str> = (0..22).map(|_| t.as_str()).collect();
    let j = cmd(PK, &format!("[{}]", caps.join(",")));
    assert_eq!(items_of(j.as_bytes(), false).unwrap().len(), 96);
    assert_eq!(
        items_of(j.as_bytes(), true).unwrap_err().data,
        msg(UNRECOGNIZED)
    );
}

#[test]
fn review_item_out_of_range() {
    let mut app = new_app();
    let mut p = Mock::default();
    assert!(items_with::<768>(&mut app, &mut p, SIMPLE_TRANSFER.as_bytes()).is_ok());
    // After the (rejected) review nothing is pending, but the parsed items stay.
    let n = app.review_len();
    let mut t = [0u8; 40];
    let mut v = [0u8; 300];
    assert!(app.review_item(&p, n - 1, &mut t, &mut v).is_ok());
    assert!(app.review_item(&p, n, &mut t, &mut v).is_err());
    assert!(app.review_item(&p, 99, &mut t, &mut v).is_err());
}
