"""JSON clear signing (0x22, legacy 0x03): chunking, review, errors, V3/V4/V5."""

import pytest
from cryptography.exceptions import InvalidSignature
from kadena import (
    ALT,
    EXPECTED_PK,
    SIMPLE_TRANSFER,
    STD,
    SW_OK,
    apdu,
    blake2b,
    err,
    le,
    legacy_chunks,
    legacy_json_payload,
    legacy_path,
    modern_chunks,
    rekey,
    verify,
)


def sign_json(kda, payload, path=STD, approve=True, compare=False):
    chunks = modern_chunks(0x22, payload, path)
    kda.send_all(chunks)
    with kda.pending(chunks[-1]):
        kda.approve_tx(compare) if approve else kda.reject_tx()
    return kda.result()


def pubkey(kda, path=STD):
    return kda.send(apdu(0x21, 0, 0, le(path)))[1].hex()


def test_sign_json_simple_transfer(kda):
    sw, sig = sign_json(kda, SIMPLE_TRANSFER, compare=True)
    assert sw == SW_OK and len(sig) == 64
    verify(EXPECTED_PK, blake2b(SIMPLE_TRANSFER), sig)


def test_sign_json_other_path(kda):
    pk = pubkey(kda, ALT)
    tx = rekey(SIMPLE_TRANSFER, pk)
    sw, sig = sign_json(kda, tx, ALT)
    assert sw == SW_OK
    verify(pk, blake2b(tx), sig)


def test_sign_json_reject(kda):
    assert sign_json(kda, SIMPLE_TRANSFER, approve=False) == (0x6986, b"")


def test_sign_json_max_size(kda):
    """A 15104-byte transaction (the buffer size) signs on every device, Nano X included."""
    base = SIMPLE_TRANSFER.replace(b'"data":{}', b'"data":{"pad":"PAD"}')
    tx = base.replace(b"PAD", b"x" * (15104 - (len(base) - 3)))
    assert len(tx) == 15104
    sw, sig = sign_json(kda, tx)
    assert sw == SW_OK
    verify(EXPECTED_PK, blake2b(tx), sig)
    # One byte more does not fit.
    chunks = modern_chunks(0x22, tx + b" ")
    kda.send_all(chunks)
    assert kda.send(chunks[-1]) == (0x6983, b"")


def test_chunking_refusals(kda):
    assert kda.send(apdu(0x22, 1, 0, b"{}")) == (0x6987, b"")
    assert kda.send(apdu(0x22, 2, 0, b"{}")) == (0x6987, b"")
    assert kda.send(apdu(0x22, 3, 0, le(STD))) == (0x6B00, b"")
    assert kda.send(apdu(0x22, 0, 0, le(STD)[:19])) == (0x6700, b"")
    assert kda.send(apdu(0x22, 0, 0, le([0x8000002C, 0x80000001, 0x80000000, 0, 0]))) == (0x6984, b"")
    assert kda.send(apdu(0x22, 0, 0, le(STD))) == (SW_OK, b"")
    assert kda.send(apdu(0x22, 2, 0, b"")) == (0x6984, err("Initialized empty context"))


def test_get_address_closes_the_stream(kda):
    assert kda.send(apdu(0x22, 0, 0, le(STD)))[0] == SW_OK
    assert kda.send(apdu(0x21, 0, 0, le(STD)))[0] == SW_OK
    assert kda.send(apdu(0x22, 1, 0, b"{}")) == (0x6987, b"")


@pytest.mark.parametrize(
    "payload, message",
    [
        (b'{"a":\x01}', "Unexpected characters"),
        (b'{"a":"\\q"}', "Unexpected characters"),
        (b'{"a":1', "Unrecognized error code"),
        (SIMPLE_TRANSFER.replace(b'"networkId"', b'"networkIdX"'), "Unrecognized error code"),
        (SIMPLE_TRANSFER.replace(b'"mainnet01"', b'""'), "Unrecognized error code"),
        (
            SIMPLE_TRANSFER.replace(b'"data":{}', b'"data":{' + b",".join([b'"k%d":[1,2]' % i for i in range(260)]) + b"}"),
            "NOMEM: JSON string contains too many tokens",
        ),
    ],
)
def test_parse_errors(kda, payload, message):
    chunks = modern_chunks(0x22, payload)
    kda.send_all(chunks)
    assert kda.send(chunks[-1]) == (0x6984, err(message))


def test_v4_duplicate_keys_refused(kda):
    tx = SIMPLE_TRANSFER.replace(b'{"networkId":"mainnet01"', b'{"networkId":"NET_FIRST","networkId":"NET_SECOND"', 1)
    chunks = modern_chunks(0x22, tx)
    kda.send_all(chunks)
    assert kda.send(chunks[-1]) == (0x6984, err("Unexpected duplicated field"))
    # Legacy 0x03: bare 0x6984.
    lc = legacy_chunks(0x03, legacy_json_payload(tx))
    for c in lc[:-1]:
        assert kda.send(c) == (SW_OK, b"")
    assert kda.send(lc[-1]) == (0x6984, b"")


def signer_cmd(arg0):
    meta = '{"creationTime":0,"ttl":28800,"gasLimit":600,"chainId":"0","gasPrice":1.0e-6,"sender":"k:' + EXPECTED_PK + '"}'
    clist = '[{"args":["' + arg0 + '","k:' + "b" * 64 + '",1.0],"name":"coin.TRANSFER"},{"args":[],"name":"coin.GAS"}]'
    return (
        '{"networkId":"mainnet01","payload":{"exec":{"data":{},"code":"(coin.transfer)"}},'
        '"signers":[{"pubKey":"' + EXPECTED_PK + '","clist":' + clist + '}],"meta":' + meta + ',"nonce":"n"}'
    ).encode()


@pytest.mark.parametrize(
    "arg0, unscoped",
    [
        ("k:" + EXPECTED_PK, False),
        ("k:" + "c" * 64, True),
        ("k:" + EXPECTED_PK + "ff", True),  # R3 #4: the C app hid the warning here (V3)
    ],
)
def test_v3_unscoped_signer_warning(kda, arg0, unscoped):
    chunks = modern_chunks(0x22, signer_cmd(arg0))
    kda.send_all(chunks)
    with kda.pending(chunks[-1]):
        seen = kda.review_texts()
    assert kda.result() == (0x6986, b"")
    # F6: the signature is scoped; the title says the transfer does not name the key.
    assert ("Key not in transfer" in seen) == unscoped
    assert "Unscoped Signer" not in seen


def test_legacy_sign_json(kda):
    lc = legacy_chunks(0x03, legacy_json_payload(SIMPLE_TRANSFER))
    for c in lc[:-1]:
        assert kda.send(c) == (SW_OK, b"")
    with kda.pending(lc[-1]):
        kda.approve_tx()
    sw, sig = kda.result()
    assert sw == SW_OK
    verify(EXPECTED_PK, blake2b(SIMPLE_TRANSFER), sig)


def test_legacy_sign_json_two_component_path(kda):
    """Zemu test_apdu_legacy_blob_217 signs m/44'/626'; here with that path's key
    as the signer (V9)."""
    pk = kda.send(apdu(0x02, 0, 0, legacy_path(STD[:2])))[1][1:].hex()
    blob = rekey(SIMPLE_TRANSFER, pk)
    lc = legacy_chunks(0x03, legacy_json_payload(blob, STD[:2]))
    for c in lc[:-1]:
        assert kda.send(c) == (SW_OK, b"")
    with kda.pending(lc[-1]):
        kda.approve_tx()
    sw, sig = kda.result()
    assert sw == SW_OK
    verify(pk, blake2b(blob), sig)


def test_legacy_json_refusals(kda):
    assert kda.send(apdu(0x03, 0, 0, b"\1\0\0")) == (0x6700, b"")
    assert kda.send(apdu(0x03, 0, 0, legacy_json_payload(b'{"a":'))) == (0x6984, b"")
    assert kda.send(apdu(0x03, 0, 0, legacy_json_payload(b"{}", [0x8000002C, 0x80000001]))) == (0x6984, b"")


def test_v8_legacy_chunk_during_a_modern_stream(kda):
    assert kda.send(apdu(0x22, 0, 0, le(STD))) == (SW_OK, b"")
    assert kda.send(apdu(0x03, 0, 0, (1000).to_bytes(4, "little") + b" " * 226)) == (0x6987, b"")
    # The modern stream was closed too.
    assert kda.send(apdu(0x22, 1, 0, b"{}")) == (0x6987, b"")


def test_v8_modern_chunk_during_a_legacy_stream(kda):
    lc = legacy_chunks(0x03, legacy_json_payload(SIMPLE_TRANSFER))
    assert kda.send(lc[0]) == (SW_OK, b"")
    assert kda.send(apdu(0x22, 1, 0, b"xx")) == (0x6987, b"")
    # The legacy stream is closed; a fresh legacy command signs.
    for c in lc[:-1]:
        assert kda.send(c) == (SW_OK, b"")
    with kda.pending(lc[-1]):
        kda.approve_tx()
    sw, sig = kda.result()
    assert sw == SW_OK
    verify(EXPECTED_PK, blake2b(SIMPLE_TRANSFER), sig)


@pytest.mark.parametrize("first, second", [(a, b) for a in (0x22, 0x23, 0x24) for b in (0x22, 0x23, 0x24) if a != b])
def test_v8_mixed_modern_ins(kda, first, second):
    assert kda.send(apdu(first, 0, 0, le(STD))) == (SW_OK, b"")
    assert kda.send(apdu(second, 1, 0, b"\x5a" * 32)) == (0x6987, b"")
    assert kda.send(apdu(first, 2, 0, b"\x5a" * 32)) == (0x6987, b"")


@pytest.mark.parametrize("blind", [False, True])
def test_v8_json_stream_finished_as_hash_never_signs(kda, blind):
    if blind:
        kda.toggle_settings("Blind signing")
    assert kda.send(apdu(0x22, 0, 0, le(STD))) == (SW_OK, b"")
    assert kda.send(apdu(0x23, 2, 0, b"\x5a" * 32)) == (0x6987, b"")


def test_v7_signing_key_is_bound_to_the_stream(kda):
    pk_b = kda.send(apdu(0x02, 0, 0, legacy_path(ALT)))[1][1:].hex()
    chunks = modern_chunks(0x22, SIMPLE_TRANSFER, STD)
    assert kda.send(chunks[0]) == (SW_OK, b"")
    # A legacy 0x02 for another path between the chunks (C then signed with it).
    assert kda.send(apdu(0x02, 0, 0, legacy_path(ALT)))[0] == SW_OK
    for c in chunks[1:-1]:
        assert kda.send(c) == (SW_OK, b"")
    with kda.pending(chunks[-1]):
        kda.approve_tx()
    sw, sig = kda.result()
    assert sw == SW_OK
    verify(EXPECTED_PK, blake2b(SIMPLE_TRANSFER), sig)
    with pytest.raises(InvalidSignature):
        verify(pk_b, blake2b(SIMPLE_TRANSFER), sig)


def test_warning_titles_are_whole(kda):
    """ "Key not in transfer" and "Sign for Address" are never shortened, on any
    device (Nano shortened long titles when a value spans pages)."""
    kda.toggle_settings("Expert mode")
    chunks = modern_chunks(0x22, signer_cmd("k:" + EXPECTED_PK + "ff"))
    kda.send_all(chunks)
    with kda.pending(chunks[-1]):
        seen = kda.review_texts()
    assert kda.result() == (0x6986, b"")
    assert "Key not in transfer" in seen, seen
    assert "Sign for Address" in seen, seen
    assert not any("..." in t for t in seen)


def test_warning_titles_golden(kda):
    """Screens of the review above, as golden snapshots."""
    kda.toggle_settings("Expert mode")
    chunks = modern_chunks(0x22, signer_cmd("k:" + EXPECTED_PK + "ff"))
    kda.send_all(chunks)
    with kda.pending(chunks[-1]):
        kda.approve_tx(compare=True)
    assert kda.result()[0] == SW_OK
