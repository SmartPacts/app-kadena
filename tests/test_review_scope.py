"""What the review covers (V9-V13, F7, F8): the device's own signer entry, blind
signing for signatures no displayed capability list bounds, one JSON value, escaped
screen text, every batch of a blind review, and the largest review in the heap."""

import re
import time

import pytest
from kadena import (
    EXPECTED_PK,
    SIMPLE_TRANSFER,
    SIMPLE_TRANSFER_C,
    SW_OK,
    blake2b,
    err,
    legacy_chunks,
    legacy_json_payload,
    modern_chunks,
    verify,
)
from ragger.navigator import NavInsID

BLIND_REQUIRED = err("Blind signing mode required")
NOT_SIGNER = err("Device key is not a signer")
SIGNS_TWICE = err("Device key signs more than once")
OTHER = "a" * 64
META = '{"creationTime":0,"ttl":28800,"gasLimit":600,"chainId":"0","gasPrice":1.0e-6,"sender":"k:' + EXPECTED_PK + '"}'


def transfer_cap(frm, to="k:" + OTHER, amount="1.0"):
    return '{"args":["' + frm + '","' + to + '",' + amount + '],"name":"coin.TRANSFER"}'


def command(signers, meta=META, tail=""):
    return (
        '{"networkId":"mainnet01","payload":{"exec":{"data":{},"code":"(coin.transfer)"}},"signers":'
        + signers
        + ',"meta":'
        + meta
        + ',"nonce":"n"}'
        + tail
    ).encode()


def entry(pk, clist=None):
    return '{"pubKey":"' + pk + '"' + ("" if clist is None else ',"clist":' + clist) + "}"


def shows(seen, title):
    """A title on screen, whole (Nano may add " (i/n)" after it)."""
    return any(t == title or t.startswith(title + " (") for t in seen)


def said(seen, phrase):
    """`phrase` on screen, whatever the line breaks (touch screens wrap inside words)
    and the page markers between Nano pages ("WARNING (2/3)", "(2/3)")."""
    pages = re.compile(r"^(WARNING )?\(\d+/\d+\)$")
    text = "".join(t for t in seen if not pages.match(t))
    return phrase.replace(" ", "") in text.replace(" ", "")


def send_last(kda, tx, ins=0x22):
    chunks = modern_chunks(ins, tx)
    kda.send_all(chunks)
    return chunks[-1]


# ---- V9 ------------------------------------------------------------------------


def test_v9_foreign_signer_is_refused(kda):
    """The Zemu simple transfer names another key: the device is not a signer."""
    assert kda.send(send_last(kda, SIMPLE_TRANSFER_C)) == (0x6984, NOT_SIGNER)
    # Legacy 0x03: bare 0x6984.
    lc = legacy_chunks(0x03, legacy_json_payload(SIMPLE_TRANSFER_C))
    for c in lc[:-1]:
        assert kda.send(c) == (SW_OK, b"")
    assert kda.send(lc[-1]) == (0x6984, b"")


def test_v9_duplicate_device_entry_is_refused(kda):
    """Audit PoC P2: Pact keeps the last entry of a key; the device refuses two."""
    signers = (
        "["
        + entry(EXPECTED_PK, "[" + transfer_cap("k:" + EXPECTED_PK, amount="1.0") + "]")
        + ","
        + entry(EXPECTED_PK, "[" + transfer_cap("k:" + EXPECTED_PK, amount="1000.0") + "]")
        + "]"
    )
    assert kda.send(send_last(kda, command(signers))) == (0x6984, SIGNS_TWICE)


def test_v9_review_is_of_the_device_entry(kda):
    """The device entry second, with a count of signers; its own transfer is shown."""
    signers = (
        "["
        + entry(OTHER, '[{"args":[],"name":"coin.GAS"}]')
        + ","
        + entry(EXPECTED_PK, "[" + transfer_cap("k:" + EXPECTED_PK, amount="1000.0") + "]")
        + "]"
    )
    tx = command(signers)
    last = send_last(kda, tx)
    with kda.pending(last):
        seen = kda.review_texts()
    assert kda.result() == (0x6986, b"")
    joined = " ".join(seen)
    assert shows(seen, "Signers") and "2" in seen
    assert "1000.0" in joined
    # And it signs.
    last = send_last(kda, tx)
    with kda.pending(last):
        kda.approve_tx()
    sw, sig = kda.result()
    assert sw == SW_OK
    verify(EXPECTED_PK, blake2b(tx), sig)


# ---- V10 / V11 -------------------------------------------------------------------

P1 = command(
    "[" + entry(EXPECTED_PK, "[]") + "," + entry(OTHER, "[" + transfer_cap("k:" + EXPECTED_PK, amount="1000.0") + "]") + "]"
)


@pytest.mark.parametrize(
    "tx",
    [
        P1,  # audit PoC P1: empty clist
        command("[" + entry(EXPECTED_PK) + "]"),  # no clist
        command("[" + entry(EXPECTED_PK, "null") + "]"),  # null clist
        command("[" + entry(EXPECTED_PK, "[" + transfer_cap("k:" + EXPECTED_PK) + "]") + "]", meta="null"),  # CAUTION
    ],
    ids=["p1-empty-clist", "no-clist", "null-clist", "meta-null"],
)
def test_v11_unbounded_json_needs_blind_signing(kda, tx):
    # OFF: the blind-signing-required screen, then C's reply.
    with kda.pending(send_last(kda, tx)):
        kda.dismiss_blind_signing_required()
    assert kda.result() == (0x6984, BLIND_REQUIRED)
    # ON: Ledger's blind-signing warning, then the review, then the signature.
    kda.toggle_settings("Blind signing")
    with kda.pending(send_last(kda, tx)):
        kda.approve_blind_tx()
    sw, sig = kda.result()
    assert sw == SW_OK
    verify(EXPECTED_PK, blake2b(tx), sig)


def test_v10_p1_blind_review_shows_the_device_entry(kda):
    kda.toggle_settings("Blind signing")
    with kda.pending(send_last(kda, P1)):
        seen = kda.review_texts()
    assert kda.result() == (0x6986, b"")
    assert shows(seen, "Unscoped Signer") and shows(seen, "WARNING")
    assert shows(seen, "Signers") and "2" in seen
    assert not any(t.startswith("Transfer") for t in seen)


def test_v11_legacy_json_needs_blind_signing(kda):
    tx = command("[" + entry(EXPECTED_PK) + "]")
    lc = legacy_chunks(0x03, legacy_json_payload(tx))
    for c in lc[:-1]:
        assert kda.send(c) == (SW_OK, b"")
    with kda.pending(lc[-1]):
        kda.dismiss_blind_signing_required()
    assert kda.result() == (0x6984, BLIND_REQUIRED)


def test_v11_scoped_json_is_clear_signed_with_blind_signing_on(kda):
    kda.toggle_settings("Blind signing")
    with kda.pending(send_last(kda, SIMPLE_TRANSFER)):
        seen = kda.review_texts()
    assert kda.result() == (0x6986, b"")
    assert not any("Blind signing" in t for t in seen)


# ---- V27: meta keys in any order --------------------------------------------------

# A plain coin transfer exactly as @kadena/client 1.18.3 writes it
# (Pact.builder.execution(...).addSigner(...).setMeta({chainId, senderAccount})
# .setNetworkId("mainnet01").createTransaction()): meta keys in the library's order,
# the amount as {"decimal":"1.0"}, gasPrice 1e-8. Request key
# HY0iK3awqWBbXADTBvUAQAqpdvpZRdDdXiy0wu1ybrM.
KADENA_CLIENT_1_18_3_COIN_TRANSFER = (
    b'{"payload":{"exec":{"code":"(coin.transfer \\"k:de12b5e16b93fe81ca4d70656bee4334f2e40f9f28b9796e792d2'
    b'8f2cead74ad\\" \\"k:9790d119589a26114e1a42d92598b3f632551c566819ec48e0e8c54dae6ebb42\\" 1.0)","data":{}'
    b'}},"nonce":"kjs:nonce:1791110121913","signers":[{"pubKey":"de12b5e16b93fe81ca4d70656bee4334f2e40f9f2'
    b'8b9796e792d28f2cead74ad","scheme":"ED25519","clist":[{"name":"coin.TRANSFER","args":["k:de12b5e16b93'
    b'fe81ca4d70656bee4334f2e40f9f28b9796e792d28f2cead74ad","k:9790d119589a26114e1a42d92598b3f632551c56681'
    b'9ec48e0e8c54dae6ebb42",{"decimal":"1.0"}]},{"name":"coin.GAS","args":[]}]}],"meta":{"gasLimit":2500,'
    b'"gasPrice":1e-8,"sender":"k:de12b5e16b93fe81ca4d70656bee4334f2e40f9f28b9796e792d28f2cead74ad","ttl":'
    b'900,"creationTime":1791110121,"chainId":"0"},"networkId":"mainnet01"}'
)

PERMUTED_META = '{"gasPrice":1.0e-6,"sender":"k:' + EXPECTED_PK + '","chainId":"0","ttl":28800,"gasLimit":600,"creationTime":0}'


def test_v27_kadena_client_coin_transfer_clear_signs(kda):
    tx = KADENA_CLIENT_1_18_3_COIN_TRANSFER
    # Blind signing OFF (the installed default): a clear-signing review, no CAUTION.
    with kda.pending(send_last(kda, tx)):
        seen = kda.review_texts()
    assert kda.result() == (0x6986, b"")
    assert not shows(seen, "CAUTION") and not any("Blind signing" in t for t in seen), seen
    assert said(seen, "KDA 1.0") and said(seen, "at most 2500 at price 1e-8"), seen
    with kda.pending(send_last(kda, tx)):
        kda.approve_tx()
    sw, sig = kda.result()
    assert sw == SW_OK
    verify(EXPECTED_PK, blake2b(tx), sig)


@pytest.mark.parametrize(
    "meta",
    [PERMUTED_META[:-1] + ',"payer":"x"}', PERMUTED_META.replace('"sender"', '"payer"')],
    ids=["unknown-seventh-key", "unknown-key-for-sender"],
)
def test_v27_unknown_meta_key_still_needs_blind_signing(kda, meta):
    tx = command("[" + entry(EXPECTED_PK, "[" + transfer_cap("k:" + EXPECTED_PK) + "]") + "]", meta=meta)
    with kda.pending(send_last(kda, tx)):
        kda.dismiss_blind_signing_required()
    assert kda.result() == (0x6984, BLIND_REQUIRED)


# ---- V12 -------------------------------------------------------------------------


@pytest.mark.parametrize(
    "tail, message",
    [
        (b"{}", "Unexpected unparsed bytes"),
        (b" x", "Unexpected unparsed bytes"),
        (b'\0{"a":1}', "Unexpected characters"),
    ],
)
def test_v12_bytes_after_the_value_are_refused(kda, tail, message):
    assert kda.send(send_last(kda, SIMPLE_TRANSFER + tail)) == (0x6984, err(message))


# ---- V13 (F5) --------------------------------------------------------------------


@pytest.mark.parametrize(
    "char, shown",
    [
        ("\u0085", "\\xC2\\x85"),  # C1 control NEL
        ("\u00a0", "\\xC2\\xA0"),  # no-break space
        ("\u00ad", "\\xC2\\xAD"),  # soft hyphen
    ],
)
def test_v13_invisible_characters_are_shown_escaped(kda, char, shown):
    to = "k:bob" + char
    tx = command("[" + entry(EXPECTED_PK, "[" + transfer_cap("k:" + EXPECTED_PK, to=to) + "]") + "]")
    with kda.pending(send_last(kda, tx)):
        seen = kda.review_texts()
    assert kda.result() == (0x6986, b"")
    assert "k:bob" + shown in seen, seen


# ---- F7: a blind review shows every batch --------------------------------------


def test_f7_blind_review_shows_every_item(kda):
    """More items than one streaming batch (16), made blind by an undisplayable
    capability (more than 5 args): the last capability must be reviewed."""
    caps = [f'{{"args":[],"name":"m.C{i:02d}"}}' for i in range(1, 14)]
    caps.append('{"args":[1,2,3,4,5,6],"name":"m.LAST"}')
    tx = command("[" + entry(EXPECTED_PK, "[" + ",".join(caps) + "]") + "]")
    kda.toggle_settings("Blind signing")
    with kda.pending(send_last(kda, tx)):
        seen = kda.review_texts()
    assert kda.result() == (0x6986, b"")
    joined = " ".join(seen)
    assert "m.LAST" in joined, seen[-12:]


# ---- F8: the largest review fits the heap --------------------------------------


def largest(device, fill="x"):
    """Values at their display bounds (299 bytes; amounts 295): as many transfers
    as the device takes (Nano X: 110 JSON tokens; others: the 15104-byte buffer).
    With a non-printable `fill` (2 bytes in UTF-8), every From/To byte after "k:"
    is shown as \\xNN."""
    n = 10 if device.name == "nanox" else 14
    body = (fill * 297).encode()[:297].decode("utf-8", "ignore")
    body += "f" * (297 - len(body.encode()))
    fr = "k:" + body
    to = "k:" + body.replace("f", "e")
    cap = transfer_cap(fr, to, "1" * 295)
    meta = (
        '{"creationTime":0,"ttl":0,"gasLimit":'
        + "2" * 140
        + ',"chainId":"'
        + "4" * 299
        + '","gasPrice":'
        + "3" * 141
        + ',"sender":"s"}'
    )
    return (
        '{"networkId":"'
        + "n" * 299
        + '","payload":{},"signers":['
        + entry(EXPECTED_PK, "[" + ",".join([cap] * n) + "]")
        + '],"meta":'
        + meta
        + ',"nonce":""}'
    ).encode()


@pytest.mark.parametrize("fill", ["x", "\u00a0"], ids=["printable", "nbsp"])
def test_f8_largest_review_signs(kda, device, fill):
    """R2-3: with non-printable values each byte is shown as \\xNN (4 characters);
    batches are budgeted on the shown text, so this review fits the heap too."""
    tx = largest(device, fill)
    assert len(tx) <= 15104
    with kda.pending(send_last(kda, tx), no_tick_timeout=True):
        kda.approve_tx(timeout=3600)
    sw, sig = kda.result()
    assert sw == SW_OK
    verify(EXPECTED_PK, blake2b(tx), sig)


# ---- Round 2 -----------------------------------------------------------------------


def rotate_command(clist):
    """The review's R2-1 proof: coin.rotate of "alice" to a keyset only the data holds."""
    return (
        '{"networkId":"mainnet01","payload":{"exec":{"data":{"new":{"keys":["attacker"],"pred":"keys-all"}},'
        '"code":"(coin.rotate \\"alice\\" (read-keyset \\"new\\"))"}},"signers":['
        + entry(EXPECTED_PK, clist)
        + '],"meta":'
        + META
        + ',"nonce":"n"}'
    ).encode()


ROTATE = rotate_command('[{"args":[],"name":"coin.GAS"},{"args":["alice"],"name":"coin.ROTATE"}]')


def test_v14_rotation_is_not_clear_signed(kda):
    """R2-1: with blind signing OFF a rotation is refused (it signed in 39a91bc)."""
    with kda.pending(send_last(kda, ROTATE)):
        kda.dismiss_blind_signing_required()
    assert kda.result() == (0x6984, BLIND_REQUIRED)


def test_v14_rotation_blind_review_warns(kda):
    kda.toggle_settings("Blind signing")
    with kda.pending(send_last(kda, ROTATE)):
        seen = kda.review_texts()
    assert kda.result() == (0x6986, b"")
    assert said(seen, "Account rotation: new owner not shown"), seen
    with kda.pending(send_last(kda, ROTATE)):
        kda.approve_blind_tx()
    sw, sig = kda.result()
    assert sw == SW_OK
    verify(EXPECTED_PK, blake2b(ROTATE), sig)


def gas_command(limit, price):
    meta = (
        '{"creationTime":1759140000,"ttl":28800,"gasLimit":'
        + limit
        + ',"chainId":"0","gasPrice":'
        + price
        + ',"sender":"k:'
        + EXPECTED_PK
        + '"}'
    )
    return command("[" + entry(EXPECTED_PK, "[" + transfer_cap("k:" + EXPECTED_PK) + "]") + "]", meta=meta)


@pytest.mark.parametrize(
    "limit, price, fee",
    [
        ("150000", "1e+2", "KDA 15000000"),
        ("2300", "0.00000001", "KDA 0.000023"),
        ("600", "1.0e-6", "KDA 0.0006"),
    ],
)
def test_v15_max_fee_and_paying_account(kda, limit, price, fee):
    with kda.pending(send_last(kda, gas_command(limit, price))):
        seen = kda.review_texts()
    assert kda.result() == (0x6986, b"")
    assert shows(seen, "Max fee") and fee in seen, seen
    assert shows(seen, "Paying account")


def test_v16_non_principal_receiver_warns(kda):
    tx = command("[" + entry(EXPECTED_PK, "[" + transfer_cap("k:" + EXPECTED_PK, to="bob") + "]") + "]")
    with kda.pending(send_last(kda, tx)):
        seen = kda.review_texts()
    assert kda.result() == (0x6986, b"")
    assert said(seen, "Recipient is not a principal account"), seen
    # A k: receiver: no warning.
    tx = command("[" + entry(EXPECTED_PK, "[" + transfer_cap("k:" + EXPECTED_PK) + "]") + "]")
    with kda.pending(send_last(kda, tx)):
        seen = kda.review_texts()
    assert kda.result() == (0x6986, b"")
    assert not said(seen, "principal account"), seen


# ---- Round 3: V20, V21, V15 integers, F7, F9 -------------------------------------


def debit_command(cap):
    """The review's F1 body: the hidden code installs a TRANSFER and moves 1000."""
    code = (
        '(install-capability (coin.TRANSFER \\"k:' + EXPECTED_PK + '\\" \\"k:' + OTHER + '\\" 1000.0)) '
        '(coin.transfer \\"k:' + EXPECTED_PK + '\\" \\"k:' + OTHER + '\\" 1000.0)'
    )
    return (
        '{"networkId":"mainnet01","payload":{"exec":{"data":{},"code":"'
        + code
        + '"}},"signers":['
        + entry(EXPECTED_PK, '[{"name":"coin.GAS","args":[]},' + cap + "]")
        + '],"meta":'
        + META
        + ',"nonce":"r3"}'
    ).encode()


UNVERIFIED = {
    "coin.DEBIT": debit_command('{"name":"coin.DEBIT","args":["k:' + EXPECTED_PK + '"]}'),
    "coin.CREDIT": debit_command('{"name":"coin.CREDIT","args":["k:' + EXPECTED_PK + '"]}'),
    "free.evil.X": debit_command('{"name":"free.evil.X","args":["a"]}'),
}


@pytest.mark.parametrize("name", sorted(UNVERIFIED))
def test_v20_unverified_capability_is_not_clear_signed(kda, name):
    """R3 F1: in 53e98c4 the DEBIT body was clear-signed with blind signing OFF."""
    tx = UNVERIFIED[name]
    with kda.pending(send_last(kda, tx)):
        kda.dismiss_blind_signing_required()
    assert kda.result() == (0x6984, BLIND_REQUIRED)
    lc = legacy_chunks(0x03, legacy_json_payload(tx))
    for c in lc[:-1]:
        assert kda.send(c) == (SW_OK, b"")
    with kda.pending(lc[-1]):
        kda.dismiss_blind_signing_required()
    assert kda.result() == (0x6984, BLIND_REQUIRED)


@pytest.mark.parametrize("name", sorted(UNVERIFIED))
def test_v20_unverified_capability_blind_review_warns(kda, name):
    tx = UNVERIFIED[name]
    kda.toggle_settings("Blind signing")
    with kda.pending(send_last(kda, tx)):
        seen = kda.review_texts()
    assert kda.result() == (0x6986, b"")
    # Separate items, each whole: the warning, the name without its namespace,
    # the namespace only when there is one, then the arguments.
    assert said(seen, "WARNING Capability not verified"), seen
    if name.count(".") >= 2:
        ns, rest = name.split(".", 1)
        assert said(seen, "Capability " + rest) and said(seen, "Namespace " + ns), seen
    else:
        assert said(seen, "Capability " + name), seen
        assert not any(t.startswith("Namespace") for t in seen), seen
    # Nano pages a long value: "Arguments (1/2)".
    assert any(t.startswith("Arguments") for t in seen), seen
    with kda.pending(send_last(kda, tx)):
        kda.approve_blind_tx()
    sw, sig = kda.result()
    assert sw == SW_OK
    verify(EXPECTED_PK, blake2b(tx), sig)


EXP_AMOUNT = command(
    "["
    + entry(EXPECTED_PK, "[" + transfer_cap("k:" + EXPECTED_PK, amount="1.0000000001e3") + ',{"name":"coin.GAS","args":[]}]')
    + "]"
)


def test_v21_exponent_amount_is_refused(kda):
    """R3 F2: "1.0000000001e3" reads as about 1 KDA; the node takes 1000.0000001."""
    assert kda.send(send_last(kda, EXP_AMOUNT)) == (0x6984, err("Unexpected characters"))
    control = EXP_AMOUNT.replace(b"1.0000000001e3", b"1000.0000001")
    with kda.pending(send_last(kda, control)):
        kda.approve_tx()
    sw, sig = kda.result()
    assert sw == SW_OK
    verify(EXPECTED_PK, blake2b(control), sig)


# V24 (R4-2, amended): a transfer amount is a bare JSON number or Pact's decimal
# object {"decimal":"<number>"}, the number being (0|[1-9][0-9]*)(.[0-9]+)?; the
# review shows the plain number. Same accept/refuse set as the C v1.3.1 patch.
V24_REFUSED = [
    ("escaped-decimal", r'{"decimal":"1\u0030\u0030\u0030.0"}'),  # shows "1...", is 1000.0
    ("decimal-exponent", '{"decimal":"1e3"}'),
    ("decimal-negative", '{"decimal":"-1.0"}'),
    ("decimal-leading-zero", '{"decimal":"01.0"}'),
    ("decimal-empty", '{"decimal":""}'),
    ("decimal-leading-dot", '{"decimal":".5"}'),
    ("decimal-trailing-dot", '{"decimal":"1."}'),
    ("decimal-number", '{"decimal":1000.0}'),
    ("decimal-nested", '{"decimal":{"decimal":"1000.0"}}'),
    ("decimal-extra-key", '{"decimal":"1000.0","x":1}'),
    ("int", '{"int":1000}'),
    ("string", '"1000.0"'),
    ("negative", "-1.0"),
    ("exponent", "1e3"),
    ("leading-zero", "01.0"),
    ("trailing-dot", "1."),
    ("decimal-unquoted-key", '{decimal:"1.5"}'),  # R5-2
    ("13-places", "1.1234567890123"),  # V25
    ("decimal-13-places", '{"decimal":"1.1234567890123"}'),  # V25
]
V24_ACCEPTED = [
    ("bare", "1000.0", "1000.0"),
    ("decimal", '{"decimal":"231"}', "231"),
    ("decimal-reviewer", '{"decimal":"1000.0"}', "1000.0"),
    ("12-places", "1.123456789012", "1.123456789012"),  # V25
    ("decimal-12-places", '{"decimal":"1.123456789012"}', "1.123456789012"),  # V25
]


def amount_tx(amount):
    tx = EXP_AMOUNT.replace(b"1.0000000001e3", amount.encode())
    assert amount.encode() in tx
    return tx


def send_legacy_json(kda, tx):
    lc = legacy_chunks(0x03, legacy_json_payload(tx))
    for c in lc[:-1]:
        assert kda.send(c) == (SW_OK, b"")
    return lc[-1]


@pytest.mark.parametrize("amount", [a for _, a in V24_REFUSED], ids=[n for n, _ in V24_REFUSED])
def test_v24_amount_shape_is_refused(kda, amount):
    tx = amount_tx(amount)
    assert kda.send(send_last(kda, tx)) == (0x6984, err("Unexpected characters"))
    assert kda.send(send_legacy_json(kda, tx)) == (0x6984, b"")  # legacy 0x03: bare
    # Blind signing ON changes nothing.
    kda.toggle_settings("Blind signing")
    assert kda.send(send_last(kda, tx)) == (0x6984, err("Unexpected characters"))


@pytest.mark.parametrize("amount, shown", [(a, s) for _, a, s in V24_ACCEPTED], ids=[n for n, _, _ in V24_ACCEPTED])
@pytest.mark.parametrize("legacy", [False, True], ids=["0x22", "0x03"])
def test_v24_accepted_amount_shows_the_number(kda, amount, shown, legacy):
    tx = amount_tx(amount)
    last = send_legacy_json(kda, tx) if legacy else send_last(kda, tx)
    with kda.pending(last):
        seen = kda.review_texts()
    assert kda.result() == (0x6986, b"")
    assert said(seen, "KDA " + shown) and not said(seen, "decimal"), seen
    last = send_legacy_json(kda, tx) if legacy else send_last(kda, tx)
    with kda.pending(last):
        kda.approve_tx()
    sw, data = kda.result()
    assert sw == SW_OK
    verify(EXPECTED_PK, blake2b(tx), data[:64])


@pytest.mark.parametrize("limit", ["1.5", "6e2"])
def test_v15_fractional_gas_limit_is_refused(kda, limit):
    """R3 F4: the node rounds a fractional gas limit; only plain digits are accepted."""
    assert kda.send(send_last(kda, gas_command(limit, "1000.0"))) == (0x6984, err("Unexpected characters"))


F7_TX = command("[" + entry(EXPECTED_PK, "[" + transfer_cap("k:" + EXPECTED_PK) + "]") + "]")


def test_f7_verifiers_are_refused(kda):
    tx = F7_TX.replace(b'"nonce":"n"}', b'"nonce":"n","verifiers":[]}')
    assert b'"verifiers"' in tx
    assert kda.send(send_last(kda, tx)) == (0x6984, err("Unexpected value"))


def test_f7_expert_mode_shows_the_payload_kind(kda):
    kda.toggle_settings("Expert mode")
    with kda.pending(send_last(kda, F7_TX)):
        seen = kda.review_texts()
    assert kda.result() == (0x6986, b"")
    assert said(seen, "Payload") and said(seen, "exec (code)"), seen


# F9: every warning title the app shows, whole, on every device (goldens on each).
ALL_WARNINGS = command(
    "["
    + entry(
        EXPECTED_PK,
        "["
        + ",".join(
            [
                transfer_cap("k:" + OTHER, to="bob"),  # Key not in transfer, not a principal
                '{"args":["alice"],"name":"coin.ROTATE"}',  # rotation
                '{"args":["a"],"name":"free.evil.X"}',  # capability not verified
                '{"args":[1,2,3,4,5,6],"name":"f.B"}',  # too large to display
            ]
        )
        + "]",
    )
    + "]",
    meta="null",
)  # CAUTION
UNSCOPED = command("[" + entry(EXPECTED_PK) + "]")


@pytest.mark.parametrize("tx", [ALL_WARNINGS, UNSCOPED], ids=["scoped", "unscoped"])
def test_f9_warning_titles_whole(kda, tx):
    kda.toggle_settings("Blind signing", "Expert mode")
    with kda.pending(send_last(kda, tx)):
        seen = kda.review_texts()
    assert kda.result() == (0x6986, b"")
    # Nothing is shortened, except a long value on a touch screen, which NBGL cuts
    # with "..." and follows with its "More" button (the whole value is one tap away).
    for i, t in enumerate(seen):
        assert "..." not in t or seen[i + 1 : i + 2] == ["More"], (t, seen)
    titles = (
        ["WARNING", "Key not in transfer", "CAUTION", "Sign for Address"]
        if tx is ALL_WARNINGS
        else ["WARNING", "Unscoped Signer", "Sign for Address"]
    )
    for title in titles:
        assert shows(seen, title), (title, seen)


def golden_blind(kda, tx):
    kda.toggle_settings("Blind signing", "Expert mode")
    with kda.pending(send_last(kda, tx)):
        kda.approve_blind_tx(compare=True)
    sw, sig = kda.result()
    assert sw == SW_OK
    verify(EXPECTED_PK, blake2b(tx), sig)


def test_f9_warning_titles_golden_scoped(kda):
    golden_blind(kda, ALL_WARNINGS)


def test_f9_warning_titles_golden_unscoped(kda):
    golden_blind(kda, UNSCOPED)


def test_expert_mode_shows_the_validity_window(kda):
    tx = gas_command("600", "1.0e-6")
    kda.toggle_settings("Expert mode")
    with kda.pending(send_last(kda, tx)):
        seen = kda.review_texts()
    assert kda.result() == (0x6986, b"")
    assert said(seen, "Created (unix time)") and "1759140000" in seen, seen
    assert said(seen, "TTL (seconds)") and "28800" in seen, seen


def test_r2_3_non_printable_review_fits_the_heap(kda, device):
    """The review's R2-3 case: 12 transfers whose From/To are "k"/"j" and 149
    no-break spaces (each byte shown as \\xNN). In 39a91bc the Flex app exited.
    Nano X takes 110 JSON tokens, so 9 transfers there (more are refused, NOMEM)."""
    body = "\u00a0" * 149
    cap = '{"args":["k' + body + '","j' + body + '",1.0],"name":"coin.TRANSFER"}'
    n = 9 if device.name == "nanox" else 12
    tx = command("[" + entry(EXPECTED_PK, "[" + ",".join([cap] * n) + "]") + "]")
    assert len(tx) <= 15104
    with kda.pending(send_last(kda, tx), no_tick_timeout=True):
        kda.approve_tx(timeout=3600)
    sw, sig = kda.result()
    assert sw == SW_OK
    verify(EXPECTED_PK, blake2b(tx), sig)


# ---- V18: escaped and duplicate keys (C v1.3.1 review, attacks A1-A4, A8) -----------
# In these strings "\\u" is the two bytes backslash-u in the JSON: a JSON escape.

GAS_CAP = '{"args":[],"name":"coin.GAS"}'
ROTATE_CODE = '(coin.rotate \\"alice\\" (read-keyset \\"new\\"))'


def xfer_code(amount):
    return '(coin.transfer \\"k:' + EXPECTED_PK + '\\" \\"k:' + OTHER + '\\" ' + amount + ")"


def key_cmd(code, clist, before_meta=""):
    return (
        '{"networkId":"mainnet01","payload":{"exec":{"data":{},"code":"'
        + code
        + '"}},"signers":['
        + entry(EXPECTED_PK, clist)
        + "],"
        + before_meta
        + '"meta":'
        + META
        + ',"nonce":"n"}'
    ).encode()


T1000 = '{"args":["k:' + EXPECTED_PK + '","k:' + OTHER + '",1000.0],"name":"coin.TRANSFER"}'
T1 = transfer_cap("k:" + EXPECTED_PK)
KEY_ATTACKS = {
    "A1": key_cmd(
        xfer_code("1000.0"),
        '[{"n\\u0061me":"coin.TRANSFER","args":["k:'
        + EXPECTED_PK
        + '","k:'
        + OTHER
        + '",1000.0],"name":"coin.GAS"},'
        + GAS_CAP
        + "]",
    ),
    "A2": key_cmd(xfer_code("1000.0"), "[" + T1 + "," + GAS_CAP + "]").replace(
        b'"signers":', ('"sign\\u0065rs":[' + entry(EXPECTED_PK, "[" + T1000 + "," + GAS_CAP + "]") + '],"signers":').encode(), 1
    ),
    "A3": key_cmd(ROTATE_CODE, "[" + GAS_CAP + ',{"args":["alice"],"name":"coin.\\u0052OTATE"}]'),
    "A4": key_cmd(ROTATE_CODE, "[" + GAS_CAP + ',{"n\\u0061me":"coin.ROTATE","args":["alice"],"name":"coin.GAS"}]'),
    "A8": key_cmd(
        xfer_code("1.0"),
        "[" + T1 + "," + GAS_CAP + "]",
        '"m\\u0065ta":{"creationTime":1634009214,"ttl":28800,"gasLimit":150000,"chainId":"0","gasPrice":0.1,'
        '"sender":"k:' + EXPECTED_PK + '"},',
    ),
}
CONTROL = key_cmd(xfer_code("1.0"), "[" + T1 + "," + GAS_CAP + "]")
DUP_NAME_IN_CAP = CONTROL.replace(GAS_CAP.encode(), b'{"name":"coin.GAS","args":[],"name":"coin.TRANSFER"}', 1)
DUP_CLIST_IN_SIGNER = CONTROL.replace(
    ('{"pubKey":"' + EXPECTED_PK + '","clist":').encode(),
    ('{"pubKey":"' + EXPECTED_PK + '","clist":[' + GAS_CAP + '],"clist":').encode(),
    1,
)


@pytest.mark.parametrize("name", sorted(KEY_ATTACKS))
def test_v18_escaped_key_attacks_are_refused(kda, name):
    """Each is reviewed and signed by the C app v1.3.0 with the hidden effect not shown."""
    tx = KEY_ATTACKS[name]
    assert b"\\u" in tx
    assert kda.send(send_last(kda, tx)) == (0x6984, err("Unexpected characters"))
    # Legacy 0x03: bare 0x6984.
    lc = legacy_chunks(0x03, legacy_json_payload(tx))
    for c in lc[:-1]:
        assert kda.send(c) == (SW_OK, b"")
    assert kda.send(lc[-1]) == (0x6984, b"")


@pytest.mark.parametrize("tx", [DUP_NAME_IN_CAP, DUP_CLIST_IN_SIGNER], ids=["dup-name-in-cap", "dup-clist-in-signer"])
def test_v18_nested_literal_duplicates_are_refused(kda, tx):
    assert kda.send(send_last(kda, tx)) == (0x6984, err("Unexpected duplicated field"))


def test_v18_control_signs(kda):
    """The same command without the escape signs, over 0x22 and legacy 0x03."""
    with kda.pending(send_last(kda, CONTROL)):
        kda.approve_tx()
    sw, sig = kda.result()
    assert sw == SW_OK
    verify(EXPECTED_PK, blake2b(CONTROL), sig)
    lc = legacy_chunks(0x03, legacy_json_payload(CONTROL))
    for c in lc[:-1]:
        assert kda.send(c) == (SW_OK, b"")
    with kda.pending(lc[-1]):
        kda.approve_tx()
    sw, sig = kda.result()
    assert sw == SW_OK
    verify(EXPECTED_PK, blake2b(CONTROL), sig)


# The blind-signing-required page: its title fits one Nano line ("Cannot
# clear-sign"), the body says what to do; both actions work.
def test_blind_required_page_golden(kda):
    with kda.pending(send_last(kda, P1)):
        deadline = time.time() + 20
        while "Cannot clear-sign" not in kda.texts():
            assert time.time() < deadline, kda.texts()
            time.sleep(0.2)
        kda.settle()
        if kda.device.is_nano:
            first = kda.texts()
            assert not any("..." in t for t in first), first
            kda.navigator.navigate_until_text_and_compare(
                NavInsID.RIGHT_CLICK,
                [NavInsID.BOTH_CLICK],
                r"^Reject Transaction$",
                kda.snapshots,
                kda.test_name,
                screen_change_before_first_instruction=False,
                screen_change_after_last_instruction=False,
            )
        else:
            kda.navigator.navigate_and_compare(
                kda.snapshots, kda.test_name, [NavInsID.USE_CASE_CHOICE_REJECT], screen_change_after_last_instruction=False
            )
    assert kda.result() == (0x6984, BLIND_REQUIRED)


def test_blind_required_go_to_settings(kda):
    with kda.pending(send_last(kda, P1)):
        kda.dismiss_blind_signing_required(go_to_settings=True)
    assert kda.result() == (0x6984, BLIND_REQUIRED)
    # The settings page is shown, with the Blind signing switch.
    deadline = time.time() + 20
    while "Blind signing" not in " ".join(kda.texts()):
        assert time.time() < deadline, kda.texts()
        time.sleep(0.2)
