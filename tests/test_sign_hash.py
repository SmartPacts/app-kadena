"""Hash signing (0x23, legacy 0x04): refused unless "Blind signing" is ON (it is
OFF on install); when ON, the raw 32 bytes are signed, not re-hashed."""

import pytest
from kadena import EXPECTED_PK, HASH_1, STD, SW_OK, apdu, err, legacy_path, modern_chunks, request_key, verify

BLIND_REQUIRED = err("Blind signing mode required")


@pytest.mark.parametrize("go_to_settings", [False, True])
def test_hash_refused_with_blind_signing_off(kda, go_to_settings):
    chunks = modern_chunks(0x23, HASH_1)
    kda.send_all(chunks)
    with kda.pending(chunks[-1]):
        kda.dismiss_blind_signing_required(go_to_settings)
    assert kda.result() == (0x6984, BLIND_REQUIRED)


def test_hash_off_refuses_any_length(kda):
    chunks = modern_chunks(0x23, HASH_1[:31])
    kda.send_all(chunks)
    with kda.pending(chunks[-1]):
        kda.dismiss_blind_signing_required()
    assert kda.result() == (0x6984, BLIND_REQUIRED)


def test_legacy_hash_refused_with_blind_signing_off(kda):
    with kda.pending(apdu(0x04, 0, 0, HASH_1 + legacy_path(STD))):
        kda.dismiss_blind_signing_required()
    assert kda.result() == (0x6984, BLIND_REQUIRED)


def test_hash_signs_raw_bytes_with_blind_signing_on(kda):
    kda.toggle_settings("Blind signing")
    chunks = modern_chunks(0x23, HASH_1)
    kda.send_all(chunks)
    with kda.pending(chunks[-1]):
        kda.approve_blind_tx(compare=True)
    sw, sig = kda.result()
    assert sw == SW_OK
    verify(EXPECTED_PK, HASH_1, sig)


def test_hash_review_shows_request_key(kda):
    kda.toggle_settings("Blind signing")
    chunks = modern_chunks(0x23, HASH_1)
    kda.send_all(chunks)
    with kda.pending(chunks[-1]):
        seen = kda.review_texts()
    assert kda.result() == (0x6986, b"")
    key = request_key(HASH_1)
    assert key == "_9jNed65Vvo8fZvg-DbyCshLFAFooIeoQr5HYOQOKxw"
    assert key.replace("-", "") in "".join(seen).replace(" ", "").replace("-", "")


def test_hash_reject(kda):
    kda.toggle_settings("Blind signing")
    chunks = modern_chunks(0x23, HASH_1)
    kda.send_all(chunks)
    with kda.pending(chunks[-1]):
        kda.review_texts()
    assert kda.result() == (0x6986, b"")


def test_hash_wrong_length_with_blind_signing_on(kda):
    kda.toggle_settings("Blind signing")
    for data in (HASH_1[:31], HASH_1 + b"\0"):
        chunks = modern_chunks(0x23, data)
        kda.send_all(chunks)
        assert kda.send(chunks[-1]) == (0x6984, err("Unexpected buffer end"))


def test_legacy_hash_with_blind_signing_on(kda):
    kda.toggle_settings("Blind signing")
    with kda.pending(apdu(0x04, 0, 0, HASH_1 + legacy_path(STD))):
        kda.approve_blind_tx()
    sw, sig = kda.result()
    assert sw == SW_OK
    verify(EXPECTED_PK, HASH_1, sig)


def test_blind_signing_does_not_apply_to_json_or_transfers(kda):
    """With blind signing ON, a JSON transaction still gets the normal review."""
    from kadena import SIMPLE_TRANSFER, blake2b

    kda.toggle_settings("Blind signing")
    chunks = modern_chunks(0x22, SIMPLE_TRANSFER)
    kda.send_all(chunks)
    with kda.pending(chunks[-1]):
        kda.approve_tx()
    sw, sig = kda.result()
    assert sw == SW_OK
    verify(EXPECTED_PK, blake2b(SIMPLE_TRANSFER), sig)
