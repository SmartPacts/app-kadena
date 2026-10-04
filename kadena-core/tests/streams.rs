//! Command streams: V5 (one stream state for both families), V7 (the signing
//! path is bound to the stream) and V8 (every chunk carries the stream's INS).
//! In the C app a legacy 0x02 between chunks changed the signing key, and the
//! last chunk's INS decided how the buffer was parsed.

mod common;
use common::*;
use kadena_core::app::Action;

fn first03() -> Vec<u8> {
    let mut d = (1000u32).to_le_bytes().to_vec();
    d.extend(vec![b' '; 226]);
    apdu(0, 0x03, 0, 0, &d)
}

fn init(ins: u8, path: &[u32; 5]) -> Vec<u8> {
    apdu(0, ins, 0, 0, &path_bytes(path))
}

// ---- V5 -----------------------------------------------------------------------

#[test]
fn v5_modern_init_closes_a_legacy_stream() {
    let mut app = new_app();
    let mut p = Mock::default();
    let payload = legacy_json_payload(SIMPLE_TRANSFER.as_bytes(), &STD_PATH);
    let chunks: Vec<&[u8]> = payload.chunks(230).collect();
    assert_eq!(
        exchange(&mut app, &mut p, &apdu(0, 0x03, 0, 0, chunks[0]), true).sw,
        0x9000
    );
    assert_eq!(
        exchange(&mut app, &mut p, &init(0x22, &STD_PATH), true).sw,
        0x9000
    );
    // The legacy stream is gone: its next chunk meets the modern stream.
    assert_eq!(
        exchange(&mut app, &mut p, &apdu(0, 0x03, 0, 0, chunks[1]), true).sw,
        0x6987
    );
}

#[test]
fn v5_v8_legacy_chunk_during_a_modern_stream_is_refused_and_closes_it() {
    let mut app = new_app();
    let mut p = Mock::default();
    assert_eq!(
        exchange(&mut app, &mut p, &init(0x22, &STD_PATH), true).sw,
        0x9000
    );
    // C read this as a new legacy command and left the modern stream open.
    assert_eq!(exchange(&mut app, &mut p, &first03(), true).sw, 0x6987);
    assert_eq!(
        exchange(&mut app, &mut p, &apdu(0, 0x22, 1, 0, b"{}"), true).sw,
        0x6987
    );
    // Nothing is open any more: a legacy command starts normally.
    let r = legacy_send(
        &mut app,
        &mut p,
        0x03,
        &legacy_json_payload(SIMPLE_TRANSFER.as_bytes(), &STD_PATH),
        true,
    );
    assert!(Mock::verify(
        &STD_PATH,
        &blake2b(SIMPLE_TRANSFER.as_bytes()),
        &r.data
    ));
}

#[test]
fn v5_v8_modern_chunk_during_a_legacy_stream_is_refused_and_closes_it() {
    let mut app = new_app();
    let mut p = Mock::default();
    let payload = legacy_json_payload(SIMPLE_TRANSFER.as_bytes(), &STD_PATH);
    let chunks: Vec<&[u8]> = payload.chunks(230).collect();
    assert_eq!(
        exchange(&mut app, &mut p, &apdu(0, 0x03, 0, 0, chunks[0]), true).sw,
        0x9000
    );
    assert_eq!(
        exchange(&mut app, &mut p, &apdu(0, 0x22, 1, 0, b"xx"), true).sw,
        0x6987
    );
    assert_eq!(
        exchange(&mut app, &mut p, &apdu(0, 0x22, 2, 0, b"xx"), true).sw,
        0x6987
    );
    // The legacy stream was closed: its next chunk is read as a new command
    // (its first 4 bytes as a length), so it cannot complete the old one.
    let r = exchange(&mut app, &mut p, &apdu(0, 0x03, 0, 0, chunks[1]), true);
    assert!(!r.reviewed);
}

// ---- V7 -----------------------------------------------------------------------

const ALT: [u32; 5] = [H | 44, H | 626, H | 5, 0, 0];

fn finish_json(app: &mut Box<TestApp>, p: &mut Mock) -> Resp {
    let json = SIMPLE_TRANSFER.as_bytes();
    let chunks: Vec<&[u8]> = json.chunks(250).collect();
    let mut r = None;
    for (i, c) in chunks.iter().enumerate() {
        let p1 = if i + 1 == chunks.len() { 2 } else { 1 };
        r = Some(exchange(app, p, &apdu(0, 0x22, p1, 0, c), true));
    }
    r.unwrap()
}

#[test]
fn v7_legacy_get_pubkey_mid_stream_does_not_change_the_signing_key() {
    let mut app = new_app();
    let mut p = Mock::default();
    let json = blake2b(SIMPLE_TRANSFER.as_bytes());
    assert_eq!(
        exchange(&mut app, &mut p, &init(0x22, &STD_PATH), true).sw,
        0x9000
    );
    let r = exchange(
        &mut app,
        &mut p,
        &apdu(0, 0x02, 0, 0, &legacy_path(&ALT)),
        true,
    );
    assert_eq!(&r.data[1..], &pk_of(&ALT)[..]);
    let r = finish_json(&mut app, &mut p);
    assert_eq!(r.sw, 0x9000);
    assert!(
        Mock::verify(&STD_PATH, &json, &r.data),
        "signed with the stream's path"
    );
    assert!(
        !Mock::verify(&ALT, &json, &r.data),
        "C signed with the 0x02 path"
    );
}

#[test]
fn v7_expert_review_shows_the_signing_key() {
    let mut app = new_app();
    // Each path has its own key here, and the transaction's signer is the
    // standard path's key.
    let mut p = Mock {
        expert: true,
        auto_signer: false,
        ..Default::default()
    };
    exchange(&mut app, &mut p, &init(0x22, &STD_PATH), true);
    exchange(
        &mut app,
        &mut p,
        &apdu(0, 0x02, 0, 0, &legacy_path(&ALT)),
        true,
    );
    let json = SIMPLE_TRANSFER.replace(RCPT, &hex::encode(pk_of(&STD_PATH)));
    let json = json.as_bytes();
    let chunks: Vec<&[u8]> = json.chunks(250).collect();
    for c in &chunks[..chunks.len() - 1] {
        exchange(&mut app, &mut p, &apdu(0, 0x22, 1, 0, c), true);
    }
    match app.handle(&mut p, 0, 0x22, 2, 0, chunks[chunks.len() - 1]) {
        Action::ReviewTx { .. } => {}
        other => panic!("{other:?}"),
    }
    let items = review_items(&app, &p);
    assert_eq!(
        items.last().unwrap(),
        &(
            "Sign for Address".to_string(),
            hex::encode(pk_of(&STD_PATH))
        )
    );
}

#[test]
fn v7_transfer_template_and_key_follow_the_stream_path() {
    // 0x24: the template's address is the INIT path's key, not the 0x02 one.
    let (_, tx_type, params) = zemu_transfers().remove(0);
    let mut app = new_app();
    // The handler vectors are token transfers (namespace and module): blind
    // signing (V23).
    let mut p = Mock {
        blind: true,
        ..Default::default()
    };
    exchange(&mut app, &mut p, &init(0x24, &STD_PATH), true);
    exchange(
        &mut app,
        &mut p,
        &apdu(0, 0x02, 0, 0, &legacy_path(&ALT)),
        true,
    );
    let r = exchange(
        &mut app,
        &mut p,
        &apdu(0, 0x24, 2, 0, &params.encode(tx_type)),
        true,
    );
    let host = params.host_json(tx_type, &hex::encode(pk_of(&STD_PATH)));
    assert_eq!(String::from_utf8(p.template.clone()).unwrap(), host);
    assert!(Mock::verify(&STD_PATH, &blake2b(host.as_bytes()), &r.data));

    // Legacy 0x10 split over two APDUs with a 0x02 between them.
    let (_, lp) = legacy_handler_transfers().remove(0);
    let mut payload = legacy_path(&STD_PATH);
    payload.extend(lp.encode(0));
    let chunks: Vec<&[u8]> = payload.chunks(230).collect();
    assert_eq!(
        exchange(&mut app, &mut p, &apdu(0, 0x10, 0, 0, chunks[0]), true).sw,
        0x9000
    );
    exchange(
        &mut app,
        &mut p,
        &apdu(0, 0x02, 0, 0, &legacy_path(&ALT)),
        true,
    );
    let r = exchange(&mut app, &mut p, &apdu(0, 0x10, 0, 0, chunks[1]), true);
    assert_eq!(r.sw, 0x9000);
    assert_eq!(&r.data[64..], &pk_of(&STD_PATH)[..]);
    let host = lp.host_json(0, &hex::encode(pk_of(&STD_PATH)));
    assert!(Mock::verify(
        &STD_PATH,
        &blake2b(host.as_bytes()),
        &r.data[..64]
    ));
}

// ---- V8 -----------------------------------------------------------------------

#[test]
fn v8_every_mixed_modern_pair_is_refused_and_closes_the_stream() {
    for first in [0x22u8, 0x23, 0x24] {
        for second in [0x22u8, 0x23, 0x24] {
            if first == second {
                continue;
            }
            for p1 in [1u8, 2] {
                let mut app = new_app();
                let mut p = Mock {
                    blind: true,
                    ..Default::default()
                };
                assert_eq!(
                    exchange(&mut app, &mut p, &init(first, &STD_PATH), true).sw,
                    0x9000
                );
                let r = exchange(&mut app, &mut p, &apdu(0, second, p1, 0, &[7u8; 32]), true);
                assert_eq!(
                    (r.sw, r.reviewed),
                    (0x6987, false),
                    "{first:#x} then {second:#x} P1={p1}"
                );
                // The stream is closed, even for its own INS.
                let r = exchange(&mut app, &mut p, &apdu(0, first, 2, 0, &[7u8; 32]), true);
                assert_eq!(r.sw, 0x6987, "{first:#x} after the refusal");
            }
        }
    }
}

#[test]
fn v8_json_stream_finished_as_a_hash_never_signs() {
    // 32 bytes sent under 0x22 and finished with 0x23: C parsed the buffer as a
    // hash (blind signing ON: a hash review and a raw signature over bytes the
    // host presented as a JSON transaction).
    for blind in [false, true] {
        let mut app = new_app();
        let mut p = Mock {
            blind,
            ..Default::default()
        };
        assert_eq!(
            exchange(&mut app, &mut p, &init(0x22, &STD_PATH), true).sw,
            0x9000
        );
        let r = exchange(&mut app, &mut p, &apdu(0, 0x23, 2, 0, &[0x5a; 32]), true);
        assert_eq!(
            (r.sw, r.data.len(), r.reviewed, r.blind_screen),
            (0x6987, 0, false, false),
            "blind {blind}"
        );
        // With chunks: 0x22 INIT, 0x22 ADD, 0x23 LAST.
        assert_eq!(
            exchange(&mut app, &mut p, &init(0x22, &STD_PATH), true).sw,
            0x9000
        );
        assert_eq!(
            exchange(&mut app, &mut p, &apdu(0, 0x22, 1, 0, &[0x5a; 16]), true).sw,
            0x9000
        );
        let r = exchange(&mut app, &mut p, &apdu(0, 0x23, 2, 0, &[0x5a; 16]), true);
        assert_eq!((r.sw, r.reviewed), (0x6987, false), "blind {blind}");
    }
}

#[test]
fn v8_mixed_legacy_commands_are_refused_and_close_the_stream() {
    let mut app = new_app();
    let mut p = Mock {
        blind: true,
        ..Default::default()
    };
    let mut hash_payload = hex("ffd8cd79deb956fa3c7d9be0f836f20ac84b140168a087a842be4760e40e2b1c");
    hash_payload.extend(legacy_path(&STD_PATH));
    // 0x03 open, then 0x04: refused (C appended it to the 0x03 data).
    assert_eq!(exchange(&mut app, &mut p, &first03(), true).sw, 0x9000);
    assert_eq!(
        exchange(&mut app, &mut p, &apdu(0, 0x04, 0, 0, &hash_payload), true).sw,
        0x6987
    );
    // Closed: the same 0x04 now works on its own.
    assert_eq!(
        exchange(&mut app, &mut p, &apdu(0, 0x04, 0, 0, &hash_payload), true).sw,
        0x9000
    );
    // 0x03 open, then 0x10.
    let (_, tx_type, params) = zemu_transfers().remove(0);
    let mut transfer = legacy_path(&STD_PATH);
    transfer.extend(params.encode(tx_type));
    assert_eq!(exchange(&mut app, &mut p, &first03(), true).sw, 0x9000);
    assert_eq!(
        exchange(&mut app, &mut p, &apdu(0, 0x10, 0, 0, &transfer), true).sw,
        0x6987
    );
    assert_eq!(
        exchange(&mut app, &mut p, &apdu(0, 0x10, 0, 0, &transfer), true).sw,
        0x9000
    );
    // 0x10 open (first of two APDUs), then 0x03.
    let (_, lp) = legacy_handler_transfers().remove(0);
    let mut payload = legacy_path(&STD_PATH);
    payload.extend(lp.encode(0));
    let chunks: Vec<&[u8]> = payload.chunks(230).collect();
    assert_eq!(
        exchange(&mut app, &mut p, &apdu(0, 0x10, 0, 0, chunks[0]), true).sw,
        0x9000
    );
    assert_eq!(exchange(&mut app, &mut p, &first03(), true).sw, 0x6987);
    // The transfer stream was closed: its second APDU no longer completes it.
    let r = exchange(&mut app, &mut p, &apdu(0, 0x10, 0, 0, chunks[1]), true);
    assert!(!r.reviewed);
}
