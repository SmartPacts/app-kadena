"""Structured transfers (0x24, legacy 0x10): the device builds the JSON; the
signature must verify over the JSON a host builds independently. V1, V2, and
V23 (a token transfer is blind signing)."""

import pytest
from kadena import (
    EXPECTED_PK,
    HANDLER_CASES,
    STD,
    SW_OK,
    T1,
    ZEMU_TRANSFERS,
    apdu,
    blake2b,
    err,
    host_json,
    legacy_chunks,
    legacy_json_payload,
    legacy_path,
    modern_chunks,
    transfer_body,
    verify,
)


def is_token(fields):
    """A token transfer (namespace and module given) is blind signing (V23)."""
    return fields["namespace"] != ""


def sign_modern(kda, body, approve=True, compare=False, blind=False):
    chunks = modern_chunks(0x24, body)
    kda.send_all(chunks)
    with kda.pending(chunks[-1]):
        if blind:
            kda.approve_blind_tx(compare) if approve else kda.reject_tx()
        else:
            kda.approve_tx(compare) if approve else kda.reject_tx()
    return kda.result()


def sign_legacy(kda, body, approve=True, blind=False):
    chunks = legacy_chunks(0x10, legacy_path(STD) + body)
    for c in chunks[:-1]:
        assert kda.send(c) == (SW_OK, b"")
    with kda.pending(chunks[-1]):
        if blind:
            kda.approve_blind_tx() if approve else kda.reject_tx()
        else:
            kda.approve_tx() if approve else kda.reject_tx()
    return kda.result()


@pytest.mark.parametrize("name, tx_type, fields", ZEMU_TRANSFERS, ids=[z[0] for z in ZEMU_TRANSFERS])
def test_transfer_modern(kda, name, tx_type, fields):
    if is_token(fields):
        kda.toggle_settings("Blind signing")
    sw, sig = sign_modern(kda, transfer_body(tx_type, fields), compare=(name == "transfer_1"), blind=is_token(fields))
    assert sw == SW_OK
    verify(EXPECTED_PK, blake2b(host_json(tx_type, fields, EXPECTED_PK).encode()), sig)


@pytest.mark.parametrize("name, tx_type, fields", ZEMU_TRANSFERS, ids=[z[0] for z in ZEMU_TRANSFERS])
def test_transfer_legacy(kda, name, tx_type, fields):
    if is_token(fields):
        kda.toggle_settings("Blind signing")
    sw, data = sign_legacy(kda, transfer_body(tx_type, fields), blind=is_token(fields))
    assert sw == SW_OK and data[64:].hex() == EXPECTED_PK
    verify(EXPECTED_PK, blake2b(host_json(tx_type, fields, EXPECTED_PK).encode()), data[:64])


@pytest.mark.parametrize("name, fields", HANDLER_CASES, ids=[h[0] for h in HANDLER_CASES])
def test_transfer_legacy_chunk_boundaries(kda, name, fields):
    kda.toggle_settings("Blind signing")  # token transfers (V23)
    sw, data = sign_legacy(kda, transfer_body(0, fields), blind=True)
    assert sw == SW_OK
    verify(EXPECTED_PK, blake2b(host_json(0, fields, EXPECTED_PK).encode()), data[:64])


# V23 (R4-1): a kb-USDC transfer scopes the key to the token module's TRANSFER
# capability, under which that module's code can use the key: blind signing, on
# 0x24 and 0x10 as for the same capability in host-built JSON (V20).
KB_USDC = ZEMU_TRANSFERS[1][2]


def token_chunks(kda, legacy):
    body = transfer_body(0, KB_USDC)
    if legacy:
        chunks = legacy_chunks(0x10, legacy_path(STD) + body)
        for c in chunks[:-1]:
            assert kda.send(c) == (SW_OK, b"")
    else:
        chunks = modern_chunks(0x24, body)
        kda.send_all(chunks)
    return chunks


@pytest.mark.parametrize("legacy", [False, True], ids=["0x24", "0x10"])
def test_v23_token_structured_transfer_needs_blind_signing(kda, legacy):
    assert KB_USDC["module"] == "kb-USDC"
    chunks = token_chunks(kda, legacy)
    with kda.pending(chunks[-1]):
        kda.dismiss_blind_signing_required()
    assert kda.result() == (0x6984, err("Blind signing mode required"))


@pytest.mark.parametrize("legacy", [False, True], ids=["0x24", "0x10"])
def test_v23_token_structured_transfer_blind_review_warns(kda, legacy):
    kda.toggle_settings("Blind signing")
    chunks = token_chunks(kda, legacy)
    with kda.pending(chunks[-1]):
        seen = kda.review_texts()
    assert kda.result() == (0x6986, b"")
    assert "Blind signing ahead" in seen, seen
    # The warning, the capability without its namespace, and the namespace are
    # separate items, each whole on one page (a namespaced name split across
    # pages is where a look-alike module would hide).
    ns = KB_USDC["namespace"]
    whole = {"WARNING": "Capability not verified", "Capability": "kb-USDC.TRANSFER", "Namespace": ns}
    for title, value in whole.items():
        if kda.device.is_nano:
            # A page: the title line, then the value's lines.
            assert any(p and p[0] == title and "".join(p[1:]).replace(" ", "") == value.replace(" ", "") for p in kda.pages), (
                title,
                kda.pages,
            )
        else:
            # A screen: its texts are the lines as drawn.
            assert any(title in p and value.replace(" ", "") in "".join(p).replace(" ", "") for p in kda.pages), (
                title,
                kda.pages,
            )
    # The name is never shown in one piece with its namespace.
    assert not any(ns + "." in t for t in seen), seen
    # Nano: the app pages fields itself; a page NBGL had to page again would
    # read "<title> (i/n)" with a shortened title (R3-P, F9).
    if kda.device.is_nano:
        assert not any("..." in t for t in seen), seen
    body = transfer_body(0, KB_USDC)
    if legacy:
        sw, data = sign_legacy(kda, body, blind=True)
        assert sw == SW_OK
        sig = data[:64]
    else:
        sw, sig = sign_modern(kda, body, compare=True, blind=True)
        assert sw == SW_OK
    verify(EXPECTED_PK, blake2b(host_json(0, KB_USDC, EXPECTED_PK).encode()), sig)


@pytest.mark.parametrize("legacy", [False, True], ids=["0x22", "0x03"])
def test_v20_token_capability_in_json_needs_blind_signing(kda, legacy):
    tx = host_json(0, KB_USDC, EXPECTED_PK).encode()
    if legacy:
        chunks = legacy_chunks(0x03, legacy_json_payload(tx))
        for c in chunks[:-1]:
            assert kda.send(c) == (SW_OK, b"")
    else:
        chunks = modern_chunks(0x22, tx)
        kda.send_all(chunks)
    with kda.pending(chunks[-1]):
        kda.dismiss_blind_signing_required()
    assert kda.result() == (0x6984, err("Blind signing mode required"))


# V25 and R5-3 on the structured coin transfer: at most 12 places, shown as
# sent; 13 places, or no fractional part (Pact refuses an integer for
# amount:decimal), refused.
@pytest.mark.parametrize("legacy", [False, True], ids=["0x24", "0x10"])
def test_v25_structured_amount_12_places_shown(kda, legacy):
    f = dict(T1, amount="1.123456789012")
    body = transfer_body(0, f)
    if legacy:
        chunks = legacy_chunks(0x10, legacy_path(STD) + body)
        for c in chunks[:-1]:
            assert kda.send(c) == (SW_OK, b"")
    else:
        chunks = modern_chunks(0x24, body)
        kda.send_all(chunks)
    with kda.pending(chunks[-1]):
        seen = kda.review_texts()
    assert kda.result() == (0x6986, b"")
    shown = "".join(seen).replace(" ", "")
    assert "KDA1.123456789012" in shown, seen
    sw, sig = sign_legacy(kda, body) if legacy else sign_modern(kda, body)
    assert sw == SW_OK
    verify(EXPECTED_PK, blake2b(host_json(0, f, EXPECTED_PK).encode()), sig[:64])


# R6-4: on every transfer type; a token amount is not bounded to 12 places (it
# is blind signing, V23) but still needs its fractional part.
@pytest.mark.parametrize("tx_type", [0, 1, 2], ids=["transfer", "create", "crosschain"])
@pytest.mark.parametrize(
    "base, amount",
    [(T1, "1.1234567890123"), (T1, "1000"), (KB_USDC, "1000")],
    ids=["coin-13-places", "coin-integer", "token-integer"],
)
def test_v25_r53_structured_amount_refused(kda, tx_type, base, amount):
    f = dict(base, amount=amount, recipient_chain="2" if tx_type == 2 else "0")
    if is_token(f):
        kda.toggle_settings("Blind signing")
    body = transfer_body(tx_type, f)
    chunks = modern_chunks(0x24, body)
    kda.send_all(chunks)
    assert kda.send(chunks[-1]) == (0x6984, err("Unexpected characters"))
    lc = legacy_chunks(0x10, legacy_path(STD) + body)
    for c in lc[:-1]:
        assert kda.send(c) == (SW_OK, b"")
    assert kda.send(lc[-1]) == (0x6984, b"")


def test_transfer_reject(kda):
    assert sign_modern(kda, transfer_body(0, T1), approve=False) == (0x6986, b"")
    assert sign_legacy(kda, transfer_body(0, T1), approve=False) == (0x6986, b"")


@pytest.mark.parametrize(
    "body, message",
    [
        (transfer_body(3, T1), "Unexpected value"),
        (transfer_body(0, T1)[:-1], "Unexpected buffer end"),
        (transfer_body(0, T1) + b"\0", "Unexpected unparsed bytes"),
        (transfer_body(0, dict(T1, recipient="a" * 63)), "Value out of range"),
        (transfer_body(0, dict(T1, ttl="1" * 21)), "Value out of range"),
    ],
)
def test_transfer_refusals(kda, body, message):
    chunks = modern_chunks(0x24, body)
    kda.send_all(chunks)
    assert kda.send(chunks[-1]) == (0x6984, err(message))


V2_CASES = [
    ("nonce", 'x","injected":"HID'),  # R3 #3: hidden top-level key
    ("amount", '1,"evil":9'),
    ("recipient", 'a","x":"' + "a" * 56),
    ("namespace", 'a","b":"c'),
    ("network", "net 01"),
    ("gas_limit", "23 00"),
    ("chain_id", "a"),
    ("module", "m)"),
]


@pytest.mark.parametrize("field, value", V2_CASES, ids=[c[0] for c in V2_CASES])
def test_v2_field_allowlist(kda, field, value):
    f = dict(T1, **{field: value})
    if field == "namespace":
        f["module"] = "m"
    body = transfer_body(0, f)
    chunks = modern_chunks(0x24, body)
    kda.send_all(chunks)
    assert kda.send(chunks[-1]) == (0x6984, err("Unexpected characters"))
    # Legacy 0x10: bare 0x6984.
    lc = legacy_chunks(0x10, legacy_path(STD) + body)
    for c in lc[:-1]:
        assert kda.send(c) == (SW_OK, b"")
    assert kda.send(lc[-1]) == (0x6984, b"")


R3_WF = dict(
    recipient="a" * 64,
    recipient_chain="0",
    network="mainnet01",
    amount="1.0",
    namespace="",
    module="",
    gas_price="1.0e-6",
    gas_limit="600",
    creation_time="0",
    chain_id="0",
    nonce="n",
    ttl="28800",
)


def test_v1_final_item_past_received_bytes(kda):
    """R3 F-A: the C app signed 20 stale buffer bytes as the (undisplayed) ttl."""
    from kadena import FIELDS

    body = legacy_path(STD[:3]) + b"\0"
    for k in FIELDS[:11]:
        v = R3_WF[k].encode()
        body += bytes([len(v)]) + v
    body += bytes([20])  # ttl claims 20 bytes, none follow
    attack = apdu(0x10, 0, 0, body)
    primer = bytearray(b"A" * (len(attack) + 20 - 5))
    primer[len(attack) - 5 :] = b"99999999999999999999"
    assert kda.send(apdu(0x20, 0, 0, bytes(primer)))[0] == SW_OK
    assert kda.send(attack) == (0x6700, b"")


def test_v1_split_item_in_short_apdu(kda):
    """R3 F-B: an item split in a 210-byte APDU (C copied bytes past rx)."""
    b1 = legacy_path(STD[:3]) + b"\0"
    for v in ("a" * 64, "00", "n" * 20, "1" + "0" * 31, "n" * 63):
        b1 += bytes([len(v)]) + v.encode()
    b1 += bytes([32]) + b"LEAD"
    a1 = apdu(0x10, 0, 0, b1)
    assert len(a1) == 210
    assert kda.send(apdu(0x20, 0, 0, b"B" * 230))[0] == SW_OK
    assert kda.send(a1) == (0x6700, b"")


def test_legacy_transfer_structure_refusals(kda):
    assert kda.send(apdu(0x10, 0, 0, legacy_path(STD))) == (0x6700, b"")
    assert kda.send(apdu(0x10, 0, 0, legacy_path(STD) + b"\0")) == (0x6984, b"")
    assert kda.send(apdu(0x10, 0, 0, legacy_path(STD) + b"\0" + b"\x011" * 13)) == (0x6984, b"")
    assert kda.send(apdu(0x10, 0, 0, b"\x06" + legacy_path(STD)[1:] + b"\0")) == (0x6984, b"")
