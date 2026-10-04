//! APDU-level tests against an in-memory device: Hash signing (0x23, legacy 0x04) behind the blind-signing setting.
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
fn hash_blind_signing_off_is_refused_with_the_c_message() {
    let mut app = new_app();
    let mut p = Mock::default();
    for len in [32usize, 31, 33, 1] {
        let r = modern_sign(&mut app, &mut p, 0x23, &STD_PATH, &vec![7u8; len], true);
        assert_eq!(
            (r.data, r.sw, r.blind_screen, r.reviewed),
            (msg("Blind signing mode required"), 0x6984, true, false),
            "len {len}"
        );
    }
}

#[test]
fn hash_blind_signing_on_signs_the_raw_32_bytes() {
    let mut app = new_app();
    let mut p = Mock {
        blind: true,
        ..Default::default()
    };
    let h = hex(HASH_1);
    let r = modern_sign(&mut app, &mut p, 0x23, &STD_PATH, &h, true);
    assert_eq!((r.sw, r.reviewed), (0x9000, true));
    let mut h32 = [0u8; 32];
    h32.copy_from_slice(&h);
    assert!(Mock::verify(&STD_PATH, &h32, &r.data));
    let r = modern_sign(&mut app, &mut p, 0x23, &STD_PATH, &h, false);
    assert_eq!((r.sw, r.data.len()), (0x6986, 0));
}

#[test]
fn hash_wrong_length_is_unexpected_buffer_end() {
    let mut app = new_app();
    let mut p = Mock {
        blind: true,
        ..Default::default()
    };
    for len in [31usize, 33, 64] {
        let r = modern_sign(&mut app, &mut p, 0x23, &STD_PATH, &vec![1u8; len], true);
        assert_eq!(
            (r.data, r.sw),
            (msg("Unexpected buffer end"), 0x6984),
            "len {len}"
        );
    }
}

fn hash_review(expert: bool) -> Vec<(String, String)> {
    let mut app = new_app();
    let mut p = Mock {
        blind: true,
        expert,
        ..Default::default()
    };
    exchange(
        &mut app,
        &mut p,
        &apdu(0, 0x23, 0, 0, &path_bytes(&STD_PATH)),
        true,
    );
    match app.handle(&mut p, 0, 0x23, 2, 0, &hex(HASH_1)) {
        Action::ReviewTx { blind: true } => review_items(&app, &p),
        other => panic!("{other:?}"),
    }
}

#[test]
fn hash_review_items() {
    // Request key = unpadded base64url of the hash (the "-2" rule).
    let key = "_9jNed65Vvo8fZvg-DbyCshLFAFooIeoQr5HYOQOKxw";
    assert_eq!(
        hash_review(false),
        vec![
            (
                "WARNING".into(),
                String::from_utf8(kadena_core::items::HASH_WARNING_TEXT.to_vec()).unwrap()
            ),
            ("Transaction hash".into(), key.into()),
        ]
    );
    let expert = hash_review(true);
    assert_eq!(expert.len(), 4);
    assert_eq!(expert[2], ("Transaction hash".into(), key.into()));
    assert_eq!(
        expert[3],
        ("Sign for Address".into(), hex::encode(pk_of(&STD_PATH)))
    );
}

#[test]
fn legacy_hash_blind_off_and_on() {
    let mut app = new_app();
    let mut p = Mock::default();
    let mut payload = hex(HASH_1);
    payload.extend(legacy_path(&STD_PATH));
    let r = exchange(&mut app, &mut p, &apdu(0, 0x04, 0, 0, &payload), true);
    assert_eq!(
        (r.data, r.sw, r.blind_screen),
        (msg("Blind signing mode required"), 0x6984, true)
    );
    p.blind = true;
    let r = exchange(&mut app, &mut p, &apdu(0, 0x04, 0, 0, &payload), true);
    assert_eq!((r.sw, r.reviewed), (0x9000, true));
    let mut h = [0u8; 32];
    h.copy_from_slice(&hex(HASH_1));
    assert!(Mock::verify(&STD_PATH, &h, &r.data));
    // 2-component path.
    let mut payload2 = hex(HASH_1);
    payload2.extend(legacy_path(&STD_PATH[..2]));
    let r = exchange(&mut app, &mut p, &apdu(0, 0x04, 0, 0, &payload2), true);
    assert!(Mock::verify(&[H | 44, H | 626, 0, 0, 0], &h, &r.data));
    // Short hash + path: the path check fails first.
    let mut short = hex(HASH_1)[..31].to_vec();
    short.extend(legacy_path(&STD_PATH));
    assert_ne!(
        exchange(&mut app, &mut p, &apdu(0, 0x04, 0, 0, &short), true).sw,
        0x9000
    );
}
