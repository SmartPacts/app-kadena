//! APDU-level tests against an in-memory device: Structured transfers (0x24, legacy 0x10): the template, V1 and V2.
//!
//! Every refusal branch has a test that fails if the branch is removed. Expected
//! bytes come from the C app (v1.3.0) source, its Zemu suite (same inputs) and,
//! for V1-V4, the emulator reproduction of the C defects (R3). `vN_*` names test
//! intended divergence N (item N of the list in `docs/APDUSPEC.md`).

mod common;
use common::*;
#[allow(unused_imports)]
use kadena_core::app::{Action, App};

#[test]
fn transfer_template_is_the_host_json_byte_for_byte() {
    for (name, tx_type, params) in zemu_transfers() {
        let mut app = new_app();
        let mut p = Mock {
            blind: true,
            ..Default::default()
        };
        let r = modern_sign(
            &mut app,
            &mut p,
            0x24,
            &STD_PATH,
            &params.encode(tx_type),
            true,
        );
        assert_eq!(r.sw, 0x9000, "{name}");
        let pk = hex::encode(pk_of(&STD_PATH));
        let host = params.host_json(tx_type, &pk);
        assert_eq!(
            String::from_utf8(p.template.clone()).unwrap(),
            host,
            "{name}"
        );
        assert!(
            Mock::verify(&STD_PATH, &blake2b(host.as_bytes()), &r.data),
            "{name}"
        );
    }
}

#[test]
fn transfer_worked_example_hash_is_pinned() {
    // R2 §3.3: transfer_1 with the real device key de12…: template of 747 bytes,
    // blake2b-256 30a25403…, request key MKJUA4IR…-l8 (shown in expert mode).
    let (_, tx_type, params) = zemu_transfers().remove(0);
    let mut app = new_app();
    let mut pk = [0u8; 32];
    pk.copy_from_slice(&hex(EXPECTED_PK_HEX));
    let mut p = Mock {
        fixed_pubkey: Some(pk),
        expert: true,
        ..Default::default()
    };
    exchange(
        &mut app,
        &mut p,
        &apdu(0, 0x24, 0, 0, &path_bytes(&STD_PATH)),
        true,
    );
    match app.handle(&mut p, 0, 0x24, 2, 0, &params.encode(tx_type)) {
        Action::ReviewTx { blind: false } => {}
        other => panic!("{other:?}"),
    }
    assert_eq!(p.template.len(), 747);
    assert_eq!(
        hex::encode(blake2b(&p.template)),
        "30a2540382115e7d1f0b8a6788f8198c2c926dbc3c386b7cc28e47f10f34fa5f"
    );
    let items = review_items(&app, &p);
    assert!(items.contains(&(
        "Transaction hash".into(),
        "MKJUA4IRXn0fC4pniPgZjCySbbw8OGt8wo5H8Q80-l8".into()
    )));
    assert!(items.contains(&("Sign for Address".into(), EXPECTED_PK_HEX.into())));
}

#[test]
fn transfer_review_items() {
    let (_, _, params) = zemu_transfers().remove(3); // cross chain
    let mut app = new_app();
    let mut p = Mock {
        blind: true,
        ..Default::default()
    };
    exchange(
        &mut app,
        &mut p,
        &apdu(0, 0x24, 0, 0, &path_bytes(&STD_PATH)),
        true,
    );
    app.handle(&mut p, 0, 0x24, 2, 0, &params.encode(2));
    let pk = hex::encode(pk_of(&STD_PATH));
    let items = review_items(&app, &p);
    let want: Vec<(String, String)> = vec![
        ("Signing".into(), "Transaction".into()),
        ("On Network".into(), "testnet04".into()),
        ("Requiring".into(), "Capabilities".into()),
        ("Of Key".into(), pk.clone()),
        ("Transfer 1".into(), "Cross-chain Transfer".into()),
        ("From".into(), format!("k:{pk}")),
        ("To".into(), format!("k:{RCPT}")),
        ("Amount".into(), "KDA 23.67".into()),
        ("To Chain".into(), "2".into()),
        ("On Chain".into(), "1".into()),
        ("Using Gas".into(), "at most 2300 at price 1.0e-6".into()),
        // V15: 2300 x 1.0e-6.
        ("Max fee".into(), "KDA 0.0023".into()),
        ("Paying account".into(), format!("k:{pk}")),
    ];
    assert_eq!(items, want);
}

#[test]
fn transfer_input_errors() {
    let (_, _, params) = zemu_transfers().remove(0);
    let good = params.encode(0);
    for tx_type in [3u8, 0xFF] {
        assert_eq!(
            transfer_err(&params.encode(tx_type)),
            (msg("Unexpected value"), 0x6984)
        );
    }
    for cut in [1, 2, 50, good.len() - 1] {
        assert_eq!(
            transfer_err(&good[..cut]),
            (msg("Unexpected buffer end"), 0x6984),
            "cut {cut}"
        );
    }
    let mut extra = good.clone();
    extra.push(0);
    assert_eq!(
        transfer_err(&extra),
        (msg("Unexpected unparsed bytes"), 0x6984)
    );
}

#[test]
fn transfer_field_caps() {
    let (_, _, base) = zemu_transfers().remove(0);
    let caps = [64usize, 2, 20, 32, 63, 32, 20, 10, 12, 2, 32, 20];
    let fill = |i: usize| -> &'static str {
        match i {
            0 => "a",
            4 | 5 => "m",
            10 => "n",
            _ => "1",
        }
    };
    for (i, cap) in caps.iter().enumerate() {
        for (len, ok) in [(*cap, true), (cap + 1, false)] {
            // A coin amount has a fractional part (R5-3) of at most 12 digits (V25).
            let v = if i == 3 {
                format!("{}.{}", "1".repeat(len - 13), "1".repeat(12))
            } else {
                fill(i).repeat(len)
            };
            let mut f = base.fields().map(|s| s.to_string());
            f[i] = v;
            // Namespace needs a module and vice versa for a namespaced template;
            // either alone is accepted (the template falls back to coin).
            let p = TransferParams {
                recipient: &f[0],
                recipient_chain: &f[1],
                network: &f[2],
                amount: &f[3],
                namespace: &f[4],
                module: &f[5],
                gas_price: &f[6],
                gas_limit: &f[7],
                creation_time: &f[8],
                chain_id: &f[9],
                nonce: &f[10],
                ttl: &f[11],
            };
            let (data, sw) = transfer_err(&p.encode(2));
            if ok {
                assert_eq!(
                    sw,
                    0x9000,
                    "field {i} len {len}: {}",
                    String::from_utf8_lossy(&data)
                );
            } else {
                assert_eq!(
                    (data, sw),
                    (msg("Value out of range"), 0x6984),
                    "field {i} len {len}"
                );
            }
        }
    }
    // The recipient must be exactly 64.
    let mut f = base.fields().map(|s| s.to_string());
    f[0] = "a".repeat(63);
    let p = TransferParams {
        recipient: &f[0],
        ..base
    };
    assert_eq!(
        transfer_err(&p.encode(0)),
        (msg("Value out of range"), 0x6984)
    );
}

#[test]
fn transfer_at_all_caps_builds_1191_bytes() {
    let r = "a".repeat(64);
    let rc = "11".to_string();
    let n = "n".repeat(20);
    // A token transfer: its amount is not bounded to coin's 12 places.
    let a = format!("1.{}", "1".repeat(30));
    let ns = "s".repeat(63);
    let m = "m".repeat(32);
    let gp = "1".repeat(20);
    let gl = "1".repeat(10);
    let ct = "1".repeat(12);
    let ci = "11".to_string();
    let no = "o".repeat(32);
    let ttl = "1".repeat(20);
    let p = TransferParams {
        recipient: &r,
        recipient_chain: &rc,
        network: &n,
        amount: &a,
        namespace: &ns,
        module: &m,
        gas_price: &gp,
        gas_limit: &gl,
        creation_time: &ct,
        chain_id: &ci,
        nonce: &no,
        ttl: &ttl,
    };
    let mut app = new_app();
    let mut mock = Mock {
        blind: true,
        ..Default::default()
    };
    exchange(
        &mut app,
        &mut mock,
        &apdu(0, 0x24, 0, 0, &path_bytes(&STD_PATH)),
        true,
    );
    // The review may be refused later (display bounds); the template is built first.
    let _ = app.handle(&mut mock, 0, 0x24, 2, 0, &p.encode(2));
    assert_eq!(mock.template.len(), 1191);
    let pk = hex::encode(pk_of(&STD_PATH));
    assert_eq!(
        String::from_utf8(mock.template.clone()).unwrap(),
        p.host_json(2, &pk)
    );
}

/// V2 (R3 #3): each field refuses content outside its allowlist.
#[test]
fn v2_field_allowlist() {
    let (_, _, base) = zemu_transfers().remove(0);
    // (field index, value that must be refused)
    let refused: Vec<(usize, String)> = vec![
        // R3 payloads.
        (10, "x\",\"injected\":\"HID".into()),
        (3, "1,\"evil\":9".into()),
        (0, format!("a\",\"x\":\"{}", "a".repeat(56))),
        (4, "a\",\"b\":\"c".into()),
        // Every field with a quote, a backslash and a control byte.
        (0, format!("{}\"", "a".repeat(63))),
        (0, format!("{}g", "a".repeat(63))),
        (1, "1\"".into()),
        (1, "a".into()),
        (2, "net\"".into()),
        (2, "net 01".into()),
        (2, "net\\".into()),
        (3, "1.0.0".into()),
        (3, "-1".into()),
        (3, "1e5".into()),
        (3, "1 ".into()),
        (4, "ns ".into()),
        (4, "ns(".into()),
        (5, "m\"".into()),
        (5, "m.x)".into()),
        (6, "1.0e-6\"".into()),
        (6, "1,2".into()),
        (7, "23 00".into()),
        (7, "2300}".into()),
        (8, "166564781x".into()),
        (9, "0\"".into()),
        (9, "a".into()),
        (10, "a\\u0022b".into()),
        (10, "tab\there".into()),
        (10, "caf\u{e9}".into()),
        (11, "600,".into()),
        (11, "6\u{7f}".into()),
    ];
    for (i, v) in &refused {
        let mut f = base.fields().map(|s| s.to_string());
        f[*i] = v.clone();
        if *i == 4 {
            f[5] = "m".into();
        }
        let p = TransferParams {
            recipient: &f[0],
            recipient_chain: &f[1],
            network: &f[2],
            amount: &f[3],
            namespace: &f[4],
            module: &f[5],
            gas_price: &f[6],
            gas_limit: &f[7],
            creation_time: &f[8],
            chain_id: &f[9],
            nonce: &f[10],
            ttl: &f[11],
        };
        for tx_type in [0u8, 1, 2] {
            assert_eq!(
                transfer_err(&p.encode(tx_type)),
                (msg("Unexpected characters"), 0x6984),
                "field {i} value {v:?}"
            );
        }
    }
    // Accepted shapes, including the hosts' defaults and every Zemu vector.
    for (name, tx_type, params) in zemu_transfers() {
        assert_eq!(transfer_err(&params.encode(tx_type)).1, 0x9000, "{name}");
    }
    let accepted = TransferParams {
        recipient: "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
        recipient_chain: "19",
        network: "fast-development",
        amount: "1000.0",
        namespace: "free",
        module: "my_token-v2",
        gas_price: "1E-8",
        gas_limit: "150000",
        creation_time: "1700000000",
        chain_id: "10",
        nonce: "nonce: 2026-09-28 11:00 UTC {#1}",
        ttl: "28800",
    };
    assert_eq!(transfer_err(&accepted.encode(1)).1, 0x9000);
    let empty = TransferParams {
        nonce: "",
        namespace: "",
        module: "",
        ..accepted
    };
    assert_eq!(transfer_err(&empty.encode(0)).1, 0x9000);
}

/// R6-4: the amount rules hold on every structured transfer type. V26 (a
/// fractional part is required) for coin and token alike; V25 (at most 12
/// places) for coin, whose amount the review bounds.
#[test]
fn v25_v26_amount_rules_on_every_transfer_type() {
    let refused = (msg("Unexpected characters"), 0x6984);
    let cases = zemu_transfers();
    let (coin, token) = (&cases[0].2, &cases[1].2);
    let with = |base: &TransferParams, amount: &str, tx_type: u8| {
        let p = TransferParams {
            amount,
            // A cross-chain transfer needs another chain than `chain_id` ("0").
            recipient_chain: if tx_type == 2 { "2" } else { "0" },
            ..*base
        };
        transfer_err(&p.encode(tx_type))
    };
    for tx_type in 0..3u8 {
        for (base, amounts) in [
            (coin, &["0", "1000", "1.", ".5", "1.1234567890123"][..]),
            (token, &["0", "1000", "1.", ".5"][..]),
        ] {
            assert_eq!(with(base, "1.5", tx_type).1, 0x9000, "type {tx_type}");
            for v in amounts {
                assert_eq!(
                    with(base, v, tx_type),
                    refused,
                    "type {tx_type} module {:?} amount {v:?}",
                    base.module
                );
            }
        }
    }
}

/// F6: numbers must be well-formed and the recipient lowercase hex, so that the
/// template is always valid JSON and names the account the screen shows.
#[test]
fn v2_number_grammar_and_lowercase_recipient() {
    let (_, _, base) = zemu_transfers().remove(0);
    let with = |i: usize, v: &str, tx_type: u8| {
        let mut f = base.fields().map(|s| s.to_string());
        f[i] = v.to_string();
        let p = TransferParams {
            recipient: &f[0],
            recipient_chain: &f[1],
            network: &f[2],
            amount: &f[3],
            namespace: &f[4],
            module: &f[5],
            gas_price: &f[6],
            gas_limit: &f[7],
            creation_time: &f[8],
            chain_id: &f[9],
            nonce: &f[10],
            ttl: &f[11],
        };
        transfer_err(&p.encode(tx_type))
    };
    let refused = (msg("Unexpected characters"), 0x6984);
    let upper = "A".repeat(64);
    let mixed = format!("{}A", "a".repeat(63));
    for v in [upper.as_str(), mixed.as_str()] {
        assert_eq!(with(0, v, 0), refused, "recipient {v}");
    }
    // amount, gas_limit, creation_time, ttl: digits ('.' digits)?
    for i in [3usize, 7, 8, 11] {
        for v in ["", ".", "1.", ".5", "+1", "e", "1e5", "1.5.", "1..5"] {
            assert_eq!(with(i, v, 0), refused, "field {i} {v:?}");
        }
        for v in ["0", "7", "0123"] {
            if i == 3 {
                continue;
            }
            assert_eq!(with(i, v, 0).1, 0x9000, "field {i} {v:?}");
        }
    }
    // The amount: a fractional part is required (R5-3: Pact refuses an integer
    // for amount:decimal), no leading zero (V24), at most 12 places (V25).
    for v in ["0", "7", "1000", "0123", "01.5", "1.1234567890123"] {
        assert_eq!(with(3, v, 0), refused, "amount {v:?}");
    }
    for v in ["0.5", "1000.0", "1.123456789012"] {
        assert_eq!(with(3, v, 0).1, 0x9000, "amount {v:?}");
    }
    // V25 on 0x24: 12 places are shown as sent.
    let (_, tx_type, t1) = zemu_transfers().remove(0);
    let p = TransferParams {
        amount: "1.123456789012",
        ..t1
    };
    let mut app = new_app();
    let mut mock = Mock::default();
    let r = modern_sign(
        &mut app,
        &mut mock,
        0x24,
        &STD_PATH,
        &p.encode(tx_type),
        true,
    );
    assert_eq!(r.sw, 0x9000);
    let items = review_items(&app, &mock);
    assert!(
        items
            .iter()
            .any(|(k, v)| k == "Amount" && v == "KDA 1.123456789012"),
        "{items:?}"
    );
    // The amount may have a fraction; gas limit, creation time and ttl are
    // integers on the node: the review refuses anything but plain digits (V15).
    assert_eq!(with(3, "10.25", 0).1, 0x9000);
    for i in [7usize, 8, 11] {
        assert_eq!(with(i, "10.25", 0), refused, "field {i}");
    }
    // gas_price: a JSON number without sign.
    for v in [
        "", ".", "+", "-", "e", "E", "1e", "1e+", "1e-", ".e1", "1.e5", "e5", "1e5.0", "-1",
        "1e5e5", "1-5",
    ] {
        assert_eq!(with(6, v, 0), refused, "gas_price {v:?}");
    }
    for v in ["1", "1.0e-6", "1E-8", "1e+3", "0.00001", "2e10"] {
        assert_eq!(with(6, v, 0).1, 0x9000, "gas_price {v:?}");
    }
    // chain id: at least one digit.
    assert_eq!(with(9, "", 0), refused);
    // recipient chain: at least one digit on a cross-chain transfer, where it is
    // pasted; unused (and may be empty) otherwise.
    assert_eq!(with(1, "", 2), refused);
    assert_eq!(with(1, "", 0).1, 0x9000);
    assert_eq!(with(1, "", 1).1, 0x9000);
}

#[test]
fn legacy_transfers_zemu_vectors() {
    for (name, tx_type, params) in zemu_transfers() {
        let mut app = new_app();
        let mut p = Mock {
            blind: true,
            ..Default::default()
        };
        let mut payload = legacy_path(&STD_PATH);
        payload.extend(params.encode(tx_type));
        let r = legacy_send(&mut app, &mut p, 0x10, &payload, true);
        assert_eq!((r.sw, r.data.len()), (0x9000, 96), "{name}");
        let pk = pk_of(&STD_PATH);
        assert_eq!(&r.data[64..], &pk[..], "{name}");
        let host = params.host_json(tx_type, &hex::encode(&pk));
        assert!(
            Mock::verify(&STD_PATH, &blake2b(host.as_bytes()), &r.data[..64]),
            "{name}"
        );
    }
}

#[test]
fn legacy_transfer_chunk_boundaries() {
    // Zemu handler_legacy_len_287 / 285 / 284.
    for (name, params) in legacy_handler_transfers() {
        let mut app = new_app();
        let mut p = Mock {
            blind: true,
            ..Default::default()
        };
        let mut payload = legacy_path(&STD_PATH);
        payload.extend(params.encode(0));
        let r = legacy_send(&mut app, &mut p, 0x10, &payload, true);
        assert_eq!(r.sw, 0x9000, "{name} ({} bytes)", payload.len());
        let host = params.host_json(0, &hex::encode(pk_of(&STD_PATH)));
        assert!(
            Mock::verify(&STD_PATH, &blake2b(host.as_bytes()), &r.data[..64]),
            "{name}"
        );
    }
}

#[test]
fn legacy_transfer_reject_and_parse_error() {
    let (_, tx_type, params) = zemu_transfers().remove(0);
    let mut app = new_app();
    let mut p = Mock {
        blind: true,
        ..Default::default()
    };
    let mut payload = legacy_path(&STD_PATH);
    payload.extend(params.encode(tx_type));
    let r = legacy_send(&mut app, &mut p, 0x10, &payload, false);
    assert_eq!((r.sw, r.data.len()), (0x6986, 0));
    // tx_type 3: parse error -> bare 0x6984.
    let mut payload = legacy_path(&STD_PATH);
    payload.extend(params.encode(3));
    let r = legacy_send(&mut app, &mut p, 0x10, &payload, true);
    assert_eq!((r.sw, r.data.len()), (0x6984, 0));
    // V2 through 0x10: bare 0x6984.
    let bad = TransferParams {
        nonce: "x\",\"injected\":\"HID",
        ..params
    };
    let mut payload = legacy_path(&STD_PATH);
    payload.extend(bad.encode(0));
    let r = legacy_send(&mut app, &mut p, 0x10, &payload, true);
    assert_eq!((r.sw, r.data.len()), (0x6984, 0));
}

#[test]
fn v1_final_item_past_the_received_bytes_is_wrong_length() {
    let (primer, attack) = r3_fa_apdus();
    assert_eq!(attack.len(), 120);
    let mut app = new_app();
    let mut p = Mock {
        blind: true,
        ..Default::default()
    };
    assert_eq!(exchange(&mut app, &mut p, &primer, true).sw, 0x9000);
    let r = exchange(&mut app, &mut p, &attack, true);
    assert_eq!((r.sw, r.reviewed), (0x6700, false));
    // Any item (not only the last) that claims more than was sent.
    for claim in [1u8, 5, 100] {
        let mut body = legacy_path(&STD_PATH);
        body.push(0);
        body.push(claim);
        let r = exchange(&mut app, &mut p, &apdu(0, 0x10, 0, 0, &body), true);
        assert_eq!(r.sw, 0x6700, "first item claims {claim} with none sent");
    }
}

/// R3 F-B: APDU1 of 210 bytes whose module item (length byte at offset 205,
/// claiming 32) would be split although the APDU is not full.
#[test]
fn v1_split_item_in_a_short_apdu_is_wrong_length() {
    let ns = "n".repeat(63);
    let mut body = legacy_path(&STD_PATH[..3]);
    body.push(0);
    for v in [
        "a".repeat(64),
        "00".into(),
        "n".repeat(20),
        format!("1{}", "0".repeat(31)),
        ns,
    ] {
        body.push(v.len() as u8);
        body.extend_from_slice(v.as_bytes());
    }
    body.push(32);
    body.extend_from_slice(b"LEAD");
    let a1 = apdu(0, 0x10, 0, 0, &body);
    assert_eq!(a1.len(), 210);
    assert_eq!(a1[205], 32);
    let mut app = new_app();
    let mut p = Mock {
        blind: true,
        ..Default::default()
    };
    let r = exchange(&mut app, &mut p, &a1, true);
    assert_eq!(r.sw, 0x6700);
    // The stream is closed: R3's APDU2 is now a (malformed) first chunk.
    let mut b2 = b"TAL".to_vec();
    for v in ["1.0e-6", "600", "0", "0", "nn", "28800"] {
        b2.push(v.len() as u8);
        b2.extend_from_slice(v.as_bytes());
    }
    assert_ne!(
        exchange(&mut app, &mut p, &apdu(0, 0x10, 0, 0, &b2), true).sw,
        0x9000
    );
}

#[test]
fn legacy_transfer_continuation_bounds() {
    // 285: an item ends exactly at byte 235 (check_item_len path).
    let (_, p285) = legacy_handler_transfers().remove(1);
    let chunks = legacy_chunks(&p285, 0);
    assert_eq!(chunks.len(), 2);
    let mut app = new_app();
    let mut p = Mock {
        blind: true,
        ..Default::default()
    };
    assert_eq!(exchange(&mut app, &mut p, &chunks[0], true).sw, 0x9000);
    // Continuation whose first length byte claims more than it carries.
    let mut c2 = chunks[1].clone();
    c2[5] = 200;
    assert_eq!(exchange(&mut app, &mut p, &c2, true).sw, 0x6700);
    // Continuation with no data at all.
    assert_eq!(exchange(&mut app, &mut p, &chunks[0], true).sw, 0x9000);
    assert_eq!(
        exchange(&mut app, &mut p, &apdu(0, 0x10, 0, 0, &[]), true).sw,
        0x6700
    );

    // 287: an item split across the boundary with 9 bytes in APDU 1.
    let (_, p287) = legacy_handler_transfers().remove(0);
    let chunks = legacy_chunks(&p287, 0);
    let mut app = new_app();
    let mut p = Mock {
        blind: true,
        ..Default::default()
    };
    assert_eq!(exchange(&mut app, &mut p, &chunks[0], true).sw, 0x9000);
    // The split item needs 2 more bytes; the continuation carries 1.
    let short = apdu(0, 0x10, 0, 0, &chunks[1][5..6]);
    assert_eq!(exchange(&mut app, &mut p, &short, true).sw, 0x6700);
    // The saved bytes already cover the item length (a 255-byte item wraps the
    // C uint8_t item length to 0): 0x6984 on the continuation.
    let mut body = legacy_path(&STD_PATH);
    body.push(0);
    body.push(175);
    body.extend(vec![b'x'; 175]);
    assert_eq!(5 + body.len(), 203);
    body.push(255);
    body.extend(vec![b'y'; 31]);
    let a1 = apdu(0, 0x10, 0, 0, &body);
    assert_eq!(a1.len(), 235);
    let mut app = new_app();
    let mut p = Mock {
        blind: true,
        ..Default::default()
    };
    assert_eq!(exchange(&mut app, &mut p, &a1, true).sw, 0x9000);
    assert_eq!(
        exchange(&mut app, &mut p, &apdu(0, 0x10, 0, 0, &[b'z'; 40]), true).sw,
        0x6984
    );
}

#[test]
fn legacy_transfer_structure_errors() {
    let (_, tx_type, params) = zemu_transfers().remove(0);
    let mut payload = legacy_path(&STD_PATH);
    payload.extend(params.encode(tx_type));
    let mut app = new_app();
    let mut p = Mock {
        blind: true,
        ..Default::default()
    };
    // Path invalid.
    let mut bad = payload.clone();
    bad[0] = 6;
    assert_eq!(
        exchange(&mut app, &mut p, &apdu(0, 0x10, 0, 0, &bad), true).sw,
        0x6984
    );
    // Path present but no tx_type byte.
    assert_eq!(
        exchange(
            &mut app,
            &mut p,
            &apdu(0, 0x10, 0, 0, &legacy_path(&STD_PATH)),
            true
        )
        .sw,
        0x6700
    );
    // Path + tx_type only: no items.
    let mut only = legacy_path(&STD_PATH);
    only.push(0);
    assert_eq!(
        exchange(&mut app, &mut p, &apdu(0, 0x10, 0, 0, &only), true).sw,
        0x6984
    );
    // Fewer than 12 items in a single short APDU.
    let mut eleven = legacy_path(&STD_PATH);
    eleven.push(0);
    for v in &params.fields()[..11] {
        eleven.push(v.len() as u8);
        eleven.extend_from_slice(v.as_bytes());
    }
    assert_eq!(
        exchange(&mut app, &mut p, &apdu(0, 0x10, 0, 0, &eleven), true).sw,
        0x6984
    );
    // More than 12 items.
    let mut many = legacy_path(&STD_PATH);
    many.push(0);
    for _ in 0..13 {
        many.extend_from_slice(&[1, b'1']);
    }
    assert_eq!(
        exchange(&mut app, &mut p, &apdu(0, 0x10, 0, 0, &many), true).sw,
        0x6984
    );
}

#[test]
fn legacy_transfer_local_buffer_limit() {
    // An item split with 33+ bytes left in the first APDU: 0x6983.
    // First length byte at 27: items of 150 and 10 bytes, then a 60-byte item
    // at offset 189 (46 bytes left in this APDU).
    let mut body = legacy_path(&STD_PATH);
    body.push(0);
    body.push(150);
    body.extend(vec![b'x'; 150]);
    body.push(10);
    body.extend(vec![b'1'; 10]);
    let offset = 5 + body.len();
    assert_eq!(offset, 189);
    body.push(60);
    body.extend(vec![b'x'; 235 - offset - 1]);
    let a = apdu(0, 0x10, 0, 0, &body);
    assert_eq!(a.len(), 235);
    let mut app = new_app();
    let mut p = Mock {
        blind: true,
        ..Default::default()
    };
    assert_eq!(exchange(&mut app, &mut p, &a, true).sw, 0x6983);
}

#[test]
fn legacy_transfer_truncated_path() {
    // qty 5 but only 3 components before the APDU ends (transfer init reads the
    // path without an exact-length rule; the bound is rx).
    let mut app = new_app();
    let mut p = Mock {
        blind: true,
        ..Default::default()
    };
    let lp = legacy_path(&STD_PATH);
    assert_eq!(
        exchange(&mut app, &mut p, &apdu(0, 0x10, 0, 0, &lp[..13]), true).sw,
        0x6700
    );
}

#[test]
fn legacy_transfer_thirteenth_item_at_a_full_apdu() {
    // 13 items ending exactly at byte 235: refused on the 13th item, not left
    // waiting for more data.
    let mut body = legacy_path(&STD_PATH);
    body.push(0);
    for _ in 0..13 {
        body.push(15);
        body.extend([b'1'; 15]);
    }
    let a = apdu(0, 0x10, 0, 0, &body);
    assert_eq!(a.len(), 235);
    let mut app = new_app();
    let mut p = Mock {
        blind: true,
        ..Default::default()
    };
    assert_eq!(exchange(&mut app, &mut p, &a, true).sw, 0x6984);
}
