"""GET_VERSION (0x20, legacy 0x00), GET_ADDR (0x21, legacy 0x01/0x02), and the
dispatcher's refusals, on the emulated device."""

import pytest
from kadena import ALT, EXPECTED_PK, STD, SW_OK, H, apdu, le, legacy_path


def test_version_modern(kda):
    sw, data = kda.send(apdu(0x20))
    assert sw == SW_OK
    # test mode 0, 2.0.0 as u16 BE, not locked, then the target id.
    assert data[:8] == bytes.fromhex("0000020000000000")
    assert len(data) == 12


def test_version_legacy(kda):
    assert kda.send(apdu(0x00, data=b"\0")) == (SW_OK, bytes([2, 0, 0]))


def test_address_derivation_is_pinned(kda):
    """The key of m/44'/626'/0'/0/0 must stay the C app's (HDW_NORMAL derivation):
    this test goes red if the derivation scheme or the key encoding changes."""
    assert kda.send(apdu(0x21, 0, 0, le(STD))) == (SW_OK, bytes.fromhex(EXPECTED_PK))
    assert kda.send(apdu(0x02, 0, 0, legacy_path(STD))) == (SW_OK, b"\x20" + bytes.fromhex(EXPECTED_PK))
    # m/44'/626'/0' is zero-padded to the same 5-component path.
    assert kda.send(apdu(0x02, 0, 0, legacy_path(STD[:3]))) == (SW_OK, b"\x20" + bytes.fromhex(EXPECTED_PK))


def test_address_other_paths(kda):
    sw, alt = kda.send(apdu(0x21, 0, 0, le(ALT)))
    assert sw == SW_OK and len(alt) == 32 and alt.hex() != EXPECTED_PK
    sw, two = kda.send(apdu(0x02, 0, 0, legacy_path(STD[:2])))
    assert sw == SW_OK and two[0] == 0x20 and two[1:].hex() != EXPECTED_PK
    # Extra bytes after the 20-byte path are ignored.
    assert kda.send(apdu(0x21, 0, 0, le(ALT) + b"\xde\xad")) == (SW_OK, alt)


@pytest.mark.parametrize(
    "data, sw",
    [
        (le(STD)[:19], 0x6700),
        (b"", 0x6700),
        (le([H | 45, H | 626, H, 0, 0]), 0x6984),
        (le([H | 44, H | 60, H, 0, 0]), 0x6984),
    ],
)
def test_address_refusals(kda, data, sw):
    assert kda.send(apdu(0x21, 0, 0, data)) == (sw, b"")


LP = legacy_path(STD)


@pytest.mark.parametrize(
    "data, sw",
    [
        (b"\x3f" + LP[1:], 0x6984),  # qty 63
        (b"\x06" + LP[1:] + b"\0" * 4, 0x6984),  # qty 6
        (b"\x01" + LP[1:5], 0x6984),  # qty 1
        (b"\x00", 0x6984),
        (b"", 0x6700),
        (b"\x05" + LP[1:13], 0x6700),  # 3 of 5 components sent
        (LP + b"\0", 0x6700),  # exact length
        (legacy_path([H | 44, H | 1, H, 0, 0]), 0x6984),
    ],
)
@pytest.mark.parametrize("ins", [0x01, 0x02])
def test_legacy_path_guard(kda, ins, data, sw):
    assert kda.send(apdu(ins, 0, 0, data)) == (sw, b"")
    assert kda.send(apdu(0x20))[0] == SW_OK


def test_show_address_approve(kda):
    with kda.pending(apdu(0x21, 1, 0, le(STD))):
        kda.approve_address(compare=True)
    assert kda.result() == (SW_OK, bytes.fromhex(EXPECTED_PK))


def test_show_address_reject(kda):
    with kda.pending(apdu(0x21, 1, 0, le(STD))):
        kda.reject_address()
    assert kda.result() == (0x6986, b"")


def test_legacy_show_address_approve(kda):
    with kda.pending(apdu(0x01, 0, 0, legacy_path(STD))):
        kda.approve_address()
    assert kda.result() == (SW_OK, b"\x20" + bytes.fromhex(EXPECTED_PK))


def test_legacy_show_address_reject(kda):
    with kda.pending(apdu(0x01, 0, 0, legacy_path(STD))):
        kda.reject_address()
    assert kda.result() == (0x6986, b"")


def test_show_address_expert_mode_shows_the_path(kda):
    kda.toggle_settings("Expert mode")
    with kda.pending(apdu(0x21, 1, 0, le(STD))):
        kda.approve_address(compare=True)
    assert kda.result() == (SW_OK, bytes.fromhex(EXPECTED_PK))


@pytest.mark.parametrize("cla", [0x80, 0xE0, 0x01])
def test_wrong_cla(kda, cla):
    assert kda.send(apdu(0x20, cla=cla)) == (0x6E00, b"")


@pytest.mark.parametrize("ins", [0xFF, 0x05, 0x25, 0x55])
def test_unknown_ins(kda, ins):
    """0xFF (defined as a version-string command, never handled) stays unhandled (V6)."""
    assert kda.send(apdu(ins)) == (0x6D00, b"")


def test_device_info(kda):
    sw, data = kda.send(apdu(0x01, cla=0xE0))
    assert sw == SW_OK
    sw2, version = kda.send(apdu(0x20))
    assert sw2 == SW_OK
    assert data[:4] == version[8:12]  # target id
