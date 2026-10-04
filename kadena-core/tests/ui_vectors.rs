//! The C app's 26 UI vectors (tests/testcases.json, run by tests/ui_tests.cpp with
//! expert mode off and on = 52 cases). Each blob goes through the real APDU path
//! (0x22 chunks), and the review items, paged exactly like the C `dumpUI` helper
//! (39-byte buffers, 38 characters per page), must equal the expected lines.
//!
//! The C unit build is not device-specific, so its expert output has no
//! `Sign for Address` item; the device build (and this port) appends it last.
//! It is checked separately and removed before the comparison.
//!
//! The device plays the vectors' signer (V9: the review is of the entry that
//! carries the device key). Vectors whose signature is not bounded by a displayed
//! capability list (WARNING, CAUTION or "too large") are blind signing (V11):
//! refused with the setting OFF, and the same items in a blind review with it ON.

mod common;
use common::*;
use kadena_core::app::Action;

struct Vector {
    index: u64,
    name: String,
    blob: String,
    output: Vec<String>,
    output_expert: Vec<String>,
}

fn strings(v: &serde_json::Value) -> Vec<String> {
    v.as_array()
        .unwrap()
        .iter()
        .map(|s| s.as_str().unwrap().to_string())
        .collect()
}

fn load() -> Vec<Vector> {
    let s = include_str!("vectors/testcases.json");
    let v: serde_json::Value = serde_json::from_str(s).unwrap();
    v.as_array()
        .unwrap()
        .iter()
        .map(|t| Vector {
            index: t["index"].as_u64().unwrap(),
            name: t["name"].as_str().unwrap().to_string(),
            blob: t["blob"].as_str().unwrap().to_string(),
            output: strings(&t["output"]),
            output_expert: strings(&t["output_expert"]),
        })
        .collect()
}

/// Sends the JSON with 0x22 (blind signing ON) and returns whether the review is
/// a blind one and its items (the review is left pending, then rejected).
fn review_of(json: &[u8], expert: bool) -> (bool, Vec<(String, String)>) {
    let mut app = new_app();
    let mut p = Mock {
        expert,
        blind: true,
        ..Default::default()
    };
    let r = exchange(
        &mut app,
        &mut p,
        &apdu(0, 0x22, 0, 0, &path_bytes(&STD_PATH)),
        false,
    );
    assert_eq!(r.sw, 0x9000);
    let chunks: Vec<&[u8]> = json.chunks(250).collect();
    for c in &chunks[..chunks.len() - 1] {
        let r = exchange(&mut app, &mut p, &apdu(0, 0x22, 1, 0, c), false);
        assert_eq!(r.sw, 0x9000);
    }
    let last = chunks[chunks.len() - 1];
    let blind = match app.handle(&mut p, 0, 0x22, 2, 0, last) {
        Action::ReviewTx { blind } => blind,
        other => panic!("expected a review, got {other:?}"),
    };
    let items = review_items(&app, &p);
    // Rejecting answers 0x6986 with no data.
    let rej = app.sign_done(&p, false);
    assert_eq!((rej.sw, rej.len), (0x6986, 0));
    (blind, items)
}

/// An independent exact product for the vectors' small gas values: (mantissa,
/// scale) in u128, formatted without trailing fraction zeros.
fn fee_oracle(limit: &str, price: &str) -> String {
    fn dec(s: &str) -> (u128, i32) {
        let (m, e) = match s.find(['e', 'E']) {
            Some(i) => (&s[..i], s[i + 1..].parse::<i32>().unwrap()),
            None => (s, 0),
        };
        let (int, frac) = m.split_once('.').unwrap_or((m, ""));
        (
            format!("{int}{frac}").parse().unwrap(),
            frac.len() as i32 - e,
        )
    }
    let ((a, sa), (b, sb)) = (dec(limit), dec(price));
    let (m, s) = (a * b, sa + sb);
    if s <= 0 {
        return format!("{}", m * 10u128.pow((-s) as u32));
    }
    let d = format!("{:0>w$}", m, w = s as usize + 1);
    let (i, f) = d.split_at(d.len() - s as usize);
    let f = f.trim_end_matches('0');
    if f.is_empty() {
        i.to_string()
    } else {
        format!("{i}.{f}")
    }
}

/// V20: the capabilities of the device's entry other than coin.GAS, full
/// transfers and coin.ROTATE (V14 has its own warning).
fn unverified_caps(json: &serde_json::Value) -> usize {
    let caps = json["signers"][0]["clist"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    caps.iter()
        .filter(|c| {
            let n = c["name"].as_str().unwrap_or("");
            let nargs = c["args"].as_array().map(|a| a.len()).unwrap_or(0);
            !(n == "coin.GAS"
                || n == "coin.ROTATE"
                || (n == "coin.TRANSFER" && nargs == 3)
                || (n == "coin.TRANSFER_XCHAIN" && nargs == 4))
        })
        .count()
}

/// Removes the items this port adds to the C review (V14, V15, V16, V19, V20, the
/// expert payload kind), checking each against the transaction, and gives back
/// the C title "Unscoped Signer" to a scoped signature this port titles "Key not
/// in transfer" (F6).
fn without_additions(
    json: &serde_json::Value,
    items: Vec<(String, String)>,
    expert: bool,
) -> Vec<(String, String)> {
    let text = |b: &[u8]| String::from_utf8(b.to_vec()).unwrap();
    let signer = &json["signers"][0];
    let caps: Vec<&serde_json::Value> = signer["clist"]
        .as_array()
        .map(|a| a.iter().collect())
        .unwrap_or_default();
    let name = |c: &serde_json::Value| c["name"].as_str().unwrap_or("").to_string();
    let nargs = |c: &serde_json::Value| c["args"].as_array().map(|a| a.len()).unwrap_or(0);
    let principal = |v: &serde_json::Value| {
        v.as_str().is_some_and(|s| {
            s.len() == 66 && s.starts_with("k:") && s[2..].bytes().all(|b| b.is_ascii_hexdigit())
        })
    };
    let not_principal = caps
        .iter()
        .filter(|c| {
            (name(c) == "coin.TRANSFER" && nargs(c) == 3)
                || (name(c) == "coin.TRANSFER_XCHAIN" && nargs(c) == 4)
        })
        .filter(|c| !principal(&c["args"][1]))
        .count();
    let rotations = caps.iter().filter(|c| name(c) == "coin.ROTATE").count();
    let unverified = unverified_caps(json);
    let cap_prefix = text(kadena_core::items::CAP_NOT_VERIFIED_TEXT);
    let count = |t: &[u8]| {
        items
            .iter()
            .filter(|(k, v)| k == "WARNING" && *v == text(t))
            .count()
    };
    assert_eq!(count(kadena_core::items::NOT_PRINCIPAL_TEXT), not_principal);
    assert_eq!(count(kadena_core::items::ROTATE_WARNING_TEXT), rotations);
    assert_eq!(
        items
            .iter()
            .filter(|(k, v)| k == "WARNING" && *v == cap_prefix)
            .count(),
        unverified
    );
    let get0 = |k: &str| items.iter().find(|(t, _)| t == k).map(|(_, v)| v.clone());
    if expert {
        let kind = if json["payload"]["exec"].is_object() {
            "exec (code)"
        } else {
            "cont (continuation)"
        };
        assert_eq!(get0("Payload").as_deref(), Some(kind));
    } else {
        assert_eq!(get0("Payload"), None);
    }
    let meta = &json["meta"];
    let known = items.iter().any(|(k, _)| k == "Using Gas");
    let get = |k: &str| items.iter().find(|(t, _)| t == k).map(|(_, v)| v.clone());
    if known {
        let fee = fee_oracle(&meta["gasLimit"].to_string(), &meta["gasPrice"].to_string());
        assert_eq!(get("Max fee"), Some(format!("KDA {fee}")));
        assert_eq!(
            get("Paying account"),
            meta["sender"].as_str().map(String::from)
        );
        if expert {
            assert_eq!(
                get("Created (unix time)"),
                Some(meta["creationTime"].to_string())
            );
            assert_eq!(get("TTL (seconds)"), Some(meta["ttl"].to_string()));
        }
    } else {
        for k in [
            "Max fee",
            "Paying account",
            "Created (unix time)",
            "TTL (seconds)",
        ] {
            assert_eq!(get(k), None);
        }
    }
    let added = [
        kadena_core::items::NOT_PRINCIPAL_TEXT,
        kadena_core::items::ROTATE_WARNING_TEXT,
    ];
    // An unverified capability is shown as "Capability", "Namespace" and
    // "Arguments"; the C app showed one item, "Unknown Capability N" =
    // "name: <namespace>.<name>, <arguments>".
    let mut merged = Vec::new();
    let mut unknown = 0;
    let mut i = 0;
    while i < items.len() {
        if items[i].0 == "Capability" {
            // "Namespace" only when the name has one.
            let (full, args) = if items[i + 1].0 == "Namespace" {
                (format!("{}.{}", items[i + 1].1, items[i].1), i + 2)
            } else {
                (items[i].1.clone(), i + 1)
            };
            assert_eq!(items[args].0, "Arguments");
            unknown += 1;
            merged.push((
                format!("Unknown Capability {unknown}"),
                format!("name: {full}, {}", items[args].1),
            ));
            i = args + 1;
        } else {
            merged.push(items[i].clone());
            i += 1;
        }
    }
    merged
        .into_iter()
        .map(|(k, v)| {
            if k == "Key not in transfer" {
                ("Unscoped Signer".to_string(), v)
            } else {
                (k, v)
            }
        })
        .filter(|(k, v)| {
            !(k == "Max fee"
                || k == "Paying account"
                || k == "Created (unix time)"
                || k == "TTL (seconds)"
                || k == "Payload"
                || (k == "WARNING" && *v == cap_prefix)
                || (k == "WARNING" && added.iter().any(|t| *v == text(t))))
        })
        .collect()
}

/// True if the C items include a warning that the signature is not bounded by
/// the capabilities shown.
fn unbounded(output: &[String]) -> bool {
    output
        .iter()
        .any(|l| l.contains(" | WARNING ") || l.contains(" | CAUTION "))
}

#[test]
fn all_26_vectors_match_c_items() {
    let vectors = load();
    assert_eq!(vectors.len(), 26);
    let mut checked = 0;
    let mut blind_vectors = 0;
    for v in &vectors {
        let blob = hex(&v.blob);
        let pk_hex = hex::encode(first_pubkey(&blob).expect("a 64-hex signer"));
        let json: serde_json::Value = serde_json::from_slice(&blob).unwrap();
        let rotates = blob.windows(11).any(|w| w == b"coin.ROTATE");
        // expert off
        let (blind, items) = review_of(&blob, false);
        let items = without_additions(&json, items, false);
        // Unbounded (V11) or a rotation (V14): blind signing.
        assert_eq!(
            blind,
            unbounded(&v.output) || rotates || unverified_caps(&json) > 0,
            "vector {} blind flag",
            v.index
        );
        if blind {
            blind_vectors += 1;
            assert_eq!(
                items_of(&blob, false).unwrap_err().data,
                msg(BLIND_REQUIRED),
                "vector {} with blind signing OFF",
                v.index
            );
        }
        assert_eq!(
            dump_ui(&items),
            plain_amounts(&v.output),
            "vector {} {} (expert off)",
            v.index,
            v.name
        );
        checked += 1;
        // expert on
        let (_, items) = review_of(&blob, true);
        let mut items = without_additions(&json, items, true);
        let last = items.pop().unwrap();
        assert_eq!(
            last,
            ("Sign for Address".to_string(), pk_hex.clone()),
            "vector {}",
            v.index
        );
        assert_eq!(
            dump_ui(&items),
            plain_amounts(&v.output_expert),
            "vector {} {} (expert on)",
            v.index,
            v.name
        );
        checked += 1;
    }
    assert_eq!(checked, 52);
    // No clist, clist null, meta missing, args too large; two rotations; and,
    // V20, the 9 vectors with a capability other than coin.GAS or a full
    // transfer (arbitrary capabilities, transfers of the wrong arity).
    assert_eq!(blind_vectors, 15);
}

/// V24: the C app showed an amount in Pact's decimal-object form as written
/// (`KDA {"decimal":"231"}`); this port shows the number (`KDA 231`).
fn plain_amounts(lines: &[String]) -> Vec<String> {
    lines
        .iter()
        .map(|l| match l.split_once(r#"KDA {"decimal":""#) {
            Some((head, rest)) => {
                let num = rest.strip_suffix(r#""}"#).expect("a whole decimal object");
                format!("{head}KDA {num}")
            }
            None => l.clone(),
        })
        .collect()
}
