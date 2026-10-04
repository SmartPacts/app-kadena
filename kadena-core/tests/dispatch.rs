//! APDU-level tests against an in-memory device: Dispatcher, GET_VERSION and addresses (modern 0x20/0x21, legacy 0x00/0x01/0x02).
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
fn get_version_modern_layout() {
    let mut app = new_app();
    let mut p = Mock::default();
    let r = exchange(&mut app, &mut p, &apdu(0, 0x20, 0, 0, &[]), true);
    assert_eq!(r.sw, 0x9000);
    assert_eq!(hex::encode(&r.data), "000002000000000033100004");
    p.locked = true;
    let r = exchange(&mut app, &mut p, &apdu(0, 0x20, 7, 9, &[1, 2, 3]), true);
    assert_eq!(hex::encode(&r.data), "000002000000000133100004");
}

#[test]
fn get_version_modern_skips_pin_check() {
    let mut app = new_app();
    let mut p = Mock {
        pin: false,
        ..Default::default()
    };
    assert_eq!(
        exchange(&mut app, &mut p, &apdu(0, 0x20, 0, 0, &[]), true).sw,
        0x9000
    );
}

#[test]
fn every_other_ins_requires_pin() {
    let mut app = new_app();
    let mut p = Mock {
        pin: false,
        ..Default::default()
    };
    for ins in [0x21, 0x22, 0x23, 0x24, 0x00, 0x01, 0x02, 0x03, 0x04, 0x10] {
        let r = exchange(
            &mut app,
            &mut p,
            &apdu(0, ins, 0, 0, &path_bytes(&STD_PATH)),
            true,
        );
        assert_eq!((r.sw, r.data.len()), (0x6986, 0), "ins {ins:#x}");
    }
}

#[test]
fn wrong_cla_is_refused_before_anything() {
    let mut app = new_app();
    let mut p = Mock {
        pin: false,
        ..Default::default()
    };
    for cla in [0x01u8, 0x80, 0xE0, 0xB1] {
        let r = exchange(&mut app, &mut p, &apdu(cla, 0x20, 0, 0, &[]), true);
        assert_eq!(r.sw, 0x6E00, "cla {cla:#x}");
    }
}

#[test]
fn device_info_is_served_before_the_cla_check() {
    let mut app = new_app();
    let mut p = Mock {
        pin: false,
        ..Default::default()
    };
    let r = exchange(&mut app, &mut p, &apdu(0xE0, 0x01, 0, 0, &[]), true);
    assert_eq!(r.sw, 0x9000);
    assert_eq!(&r.data[..4], &[0x33, 0x10, 0x00, 0x04]);
    // Only E0 01 00 00: other P1/P2 fall through to the CLA check.
    assert_eq!(
        exchange(&mut app, &mut p, &apdu(0xE0, 0x01, 1, 0, &[]), true).sw,
        0x6E00
    );
}

#[test]
fn v6_unknown_ins_and_0xff_are_not_supported() {
    let mut app = new_app();
    let mut p = Mock {
        pin: false,
        ..Default::default()
    };
    for ins in [0xFFu8, 0x05, 0x11, 0x25, 0x55, 0xFE] {
        let r = exchange(&mut app, &mut p, &apdu(0, ins, 0, 0, &[]), true);
        assert_eq!(r.sw, 0x6D00, "ins {ins:#x}");
    }
}

#[test]
fn get_addr_returns_raw_pubkey() {
    let mut app = new_app();
    let mut p = Mock::default();
    let r = exchange(&mut app, &mut p, &std_addr_apdu(0), true);
    assert_eq!((r.sw, r.reviewed), (0x9000, false));
    assert_eq!(r.data, pk_of(&STD_PATH));
    let r = exchange(
        &mut app,
        &mut p,
        &apdu(0, 0x21, 0, 0, &path_bytes(&ALT_PATH)),
        true,
    );
    assert_eq!(r.data, pk_of(&ALT_PATH));
}

#[test]
fn get_addr_ignores_extra_bytes_and_hardening_of_the_tail() {
    let mut app = new_app();
    let mut p = Mock::default();
    let mut data = path_bytes(&STD_PATH);
    data.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
    let r = exchange(&mut app, &mut p, &apdu(0, 0x21, 0, 0, &data), true);
    assert_eq!(r.data, pk_of(&STD_PATH));
    let odd = [H | 44, H | 626, 7, 8, H | 9];
    let r = exchange(
        &mut app,
        &mut p,
        &apdu(0, 0x21, 0, 0, &path_bytes(&odd)),
        true,
    );
    assert_eq!((r.sw, r.data.clone()), (0x9000, pk_of(&odd)));
}

#[test]
fn get_addr_short_path_is_wrong_length() {
    let mut app = new_app();
    let mut p = Mock::default();
    let data = path_bytes(&STD_PATH);
    for n in [0, 4, 19] {
        let r = exchange(&mut app, &mut p, &apdu(0, 0x21, 0, 0, &data[..n]), true);
        assert_eq!(r.sw, 0x6700, "{n} bytes");
    }
}

#[test]
fn get_addr_bad_prefix_is_data_invalid() {
    let mut app = new_app();
    let mut p = Mock::default();
    for path in [
        [H | 45, H | 626, H, 0, 0],
        [H | 44, H | 60, H, 0, 0],
        [44, H | 626, H, 0, 0],
        [H | 44, 626, H, 0, 0],
    ] {
        let r = exchange(
            &mut app,
            &mut p,
            &apdu(0, 0x21, 0, 0, &path_bytes(&path)),
            true,
        );
        assert_eq!(r.sw, 0x6984, "{path:x?}");
    }
}

#[test]
fn get_addr_with_display_approve_and_reject() {
    let mut app = new_app();
    let mut p = Mock::default();
    for p1 in [1u8, 2, 0xFF] {
        let r = exchange(&mut app, &mut p, &std_addr_apdu(p1), true);
        assert_eq!(
            (r.sw, r.reviewed, r.data.clone()),
            (0x9000, true, pk_of(&STD_PATH))
        );
    }
    let r = exchange(&mut app, &mut p, &std_addr_apdu(1), false);
    assert_eq!((r.sw, r.reviewed, r.data.len()), (0x6986, true, 0));
}

#[test]
fn get_addr_derivation_failure_is_execution_error() {
    let mut app = new_app();
    let mut p = Mock {
        fail_derive: true,
        ..Default::default()
    };
    assert_eq!(
        exchange(&mut app, &mut p, &std_addr_apdu(0), true).sw,
        0x6400
    );
    assert_eq!(
        exchange(
            &mut app,
            &mut p,
            &apdu(0, 0x02, 0, 0, &legacy_path(&STD_PATH)),
            true
        )
        .sw,
        0x6400
    );
}

#[test]
fn get_addr_closes_an_open_modern_stream() {
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
    assert_eq!(
        exchange(&mut app, &mut p, &std_addr_apdu(0), true).sw,
        0x9000
    );
    assert_eq!(
        exchange(&mut app, &mut p, &apdu(0, 0x22, 1, 0, b"{}"), true).sw,
        0x6987
    );
}

#[test]
fn legacy_get_version() {
    let mut app = new_app();
    let mut p = Mock::default();
    let r = exchange(&mut app, &mut p, &apdu(0, 0x00, 0, 0, &[0]), true);
    assert_eq!((r.data, r.sw), (vec![2, 0, 0], 0x9000));
}

#[test]
fn legacy_get_pubkey_paths() {
    let mut app = new_app();
    let mut p = Mock::default();
    let get = |app: &mut Box<TestApp>, p: &mut Mock, data: &[u8]| {
        exchange(app, p, &apdu(0, 0x02, 0, 0, data), true)
    };
    let mut want = vec![0x20];
    want.extend(pk_of(&STD_PATH));
    assert_eq!(get(&mut app, &mut p, &legacy_path(&STD_PATH)).data, want);
    // 3 components = m/44'/626'/0' + zero tail = the standard path.
    assert_eq!(
        get(&mut app, &mut p, &legacy_path(&STD_PATH[..3])).data,
        want
    );
    // 2 components: m/44'/626'/0/0/0.
    let mut two = vec![0x20];
    two.extend(pk_of(&[H | 44, H | 626, 0, 0, 0]));
    assert_eq!(
        get(&mut app, &mut p, &legacy_path(&STD_PATH[..2])).data,
        two
    );
    // The tail is zeroed before a short copy: qty 5 with a tail, then qty 2.
    get(&mut app, &mut p, &legacy_path(&[H | 44, H | 626, 1, 2, 3]));
    assert_eq!(
        get(&mut app, &mut p, &legacy_path(&STD_PATH[..2])).data,
        two
    );
}

#[test]
fn legacy_path_guard() {
    let mut app = new_app();
    let mut p = Mock::default();
    let std = legacy_path(&STD_PATH);
    let cases: Vec<(Vec<u8>, u16)> = vec![
        // Zemu "Legacy HD-path guard": qty 63, 6, 1 -> 6984.
        ([vec![63], std[1..].to_vec()].concat(), 0x6984),
        ([vec![6], std[1..].to_vec(), vec![0; 4]].concat(), 0x6984),
        ([vec![1], std[1..5].to_vec()].concat(), 0x6984),
        (vec![0], 0x6984),
        (vec![], 0x6700),
        // qty 5 but only 3 components sent.
        ([vec![5], std[1..13].to_vec()].concat(), 0x6700),
        // exact length: one extra byte.
        ([std.clone(), vec![0]].concat(), 0x6700),
        (legacy_path(&[H | 44, H | 1, H, 0, 0]), 0x6984),
        (legacy_path(&[H | 44, H | 626]), 0x9000),
    ];
    for (data, sw) in cases {
        for ins in [0x01u8, 0x02] {
            let r = exchange(&mut app, &mut p, &apdu(0, ins, 0, 0, &data), true);
            assert_eq!(r.sw, sw, "ins {ins:#x} data {}", hex::encode(&data));
        }
    }
    // The app is still alive and answers.
    assert_eq!(
        exchange(&mut app, &mut p, &apdu(0, 0x20, 0, 0, &[]), true).sw,
        0x9000
    );
}

#[test]
fn legacy_verify_address_approve_and_reject() {
    let mut app = new_app();
    let mut p = Mock::default();
    let r = exchange(
        &mut app,
        &mut p,
        &apdu(0, 0x01, 0, 0, &legacy_path(&STD_PATH)),
        true,
    );
    let mut want = vec![0x20];
    want.extend(pk_of(&STD_PATH));
    assert_eq!((r.data, r.sw, r.reviewed), (want, 0x9000, true));
    let r = exchange(
        &mut app,
        &mut p,
        &apdu(0, 0x01, 0, 0, &legacy_path(&STD_PATH)),
        false,
    );
    assert_eq!((r.data.len(), r.sw), (0, 0x6986));
}
