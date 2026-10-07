"""Helpers shared by the functional tests: APDU framing (as the host libraries
do it), the transfer template as a host builds it, signature checks and screen
navigation for the NBGL flows on every device."""

import hashlib
import shutil
import time
from contextlib import contextmanager
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection
from ragger.backend import RaisePolicy, SpeculosBackend
from ragger.navigator import NavInsID

H = 0x80000000
STD = [H | 44, H | 626, H | 0, 0, 0]
ALT = [H | 44, H | 626, H | 5, 0, 0]
# m/44'/626'/0'/0/0 of the test seed, as pinned by the C app's Zemu suite.
EXPECTED_PK = "de12b5e16b93fe81ca4d70656bee4334f2e40f9f28b9796e792d28f2cead74ad"

SW_OK = 0x9000


def le(path):
    return b"".join(v.to_bytes(4, "little") for v in path)


def legacy_path(path):
    return bytes([len(path)]) + le(path)


def apdu(ins, p1=0, p2=0, data=b"", cla=0):
    assert len(data) <= 255
    return bytes([cla, ins, p1, p2, len(data)]) + data


def modern_chunks(ins, payload, path=STD):
    """@zondax/ledger-js: path with P1=0, then 250-byte chunks, the last with P1=2."""
    out = [apdu(ins, 0, 0, le(path))]
    chunks = [payload[i : i + 250] for i in range(0, len(payload), 250)] or [b""]
    for i, c in enumerate(chunks):
        out.append(apdu(ins, 2 if i == len(chunks) - 1 else 1, 0, c))
    return out


def legacy_chunks(ins, payload):
    """hw-app-alamgu `sendChunks`: 230-byte slices, P1=P2=0."""
    return [apdu(ins, 0, 0, payload[i : i + 230]) for i in range(0, len(payload), 230)]


def legacy_json_payload(json_bytes, path=STD):
    return len(json_bytes).to_bytes(4, "little") + json_bytes + legacy_path(path)


FIELDS = [
    "recipient",
    "recipient_chain",
    "network",
    "amount",
    "namespace",
    "module",
    "gas_price",
    "gas_limit",
    "creation_time",
    "chain_id",
    "nonce",
    "ttl",
]


def transfer_body(tx_type, f):
    b = bytes([tx_type])
    for k in FIELDS:
        v = f[k].encode()
        b += bytes([len(v)]) + v
    return b


def host_json(tx_type, f, pk):
    """The command JSON exactly as hw-app-kda / @zondax/ledger-kadena rebuild it."""
    ns, mod = f["namespace"], f["module"]
    prefix = "coin" if ns == "" else f"{ns}.{mod}"
    r, a, rc = f["recipient"], f["amount"], f["recipient_chain"]
    cmd = '{"networkId":"' + f["network"] + '"'
    if tx_type == 0:
        cmd += ',"payload":{"exec":{"data":{},"code":"(' + prefix + ".transfer"
        cmd += ' \\"k:' + pk + '\\" \\"k:' + r + '\\" ' + a + ')"}}'
        cmd += ',"signers":[{"pubKey":"' + pk + '","clist":[{"args":["k:' + pk + '","k:' + r + '",' + a + "]"
        cmd += ',"name":"' + prefix + '.TRANSFER"},{"args":[],"name":"coin.GAS"}]}]'
    else:
        verb = ".transfer-create" if tx_type == 1 else ".transfer-crosschain"
        tail = "" if tx_type == 1 else ' \\"' + rc + '\\"'
        cmd += ',"payload":{"exec":{"data":{"ks":{"pred":"keys-all","keys":["' + r + '"]}},"code":"(' + prefix + verb
        cmd += ' \\"k:' + pk + '\\" \\"k:' + r + '\\" (read-keyset \\"ks\\")' + tail + " " + a + ')"}}'
        extra = "" if tx_type == 1 else ',"' + rc + '"'
        name = ".TRANSFER" if tx_type == 1 else ".TRANSFER_XCHAIN"
        cmd += ',"signers":[{"pubKey":"' + pk + '","clist":[{"args":["k:' + pk + '","k:' + r + '",' + a + extra + "]"
        cmd += ',"name":"' + prefix + name + '"},{"args":[],"name":"coin.GAS"}]}]'
    cmd += ',"meta":{"creationTime":' + f["creation_time"] + ',"ttl":' + f["ttl"] + ',"gasLimit":' + f["gas_limit"]
    cmd += ',"chainId":"' + f["chain_id"] + '","gasPrice":' + f["gas_price"] + ',"sender":"k:' + pk + '"}'
    cmd += ',"nonce":"' + f["nonce"] + '"}'
    return cmd


def blake2b(data):
    return hashlib.blake2b(data, digest_size=32).digest()


def verify(pk_hex, msg32, sig):
    """Raises if `sig` is not an Ed25519 signature of `msg32` by `pk_hex`."""
    Ed25519PublicKey.from_public_bytes(bytes.fromhex(pk_hex)).verify(sig, msg32)


def request_key(digest):
    import base64

    return base64.urlsafe_b64encode(digest).decode().rstrip("=")


# --- The C app's Zemu transfer vectors (Zondax/ledger-kadena tests_zemu/tests/testscases/transactions.ts) ---
RCPT = "83934c0f9b005f378ba3520f9dea952fb0a90e5aa36f1b5ff837d9b30c471790"
NONCE1 = "2022-10-13 07:56:50.893257 UTC"
NONCE2 = "2022-10-14 04:41:03.193557 UTC"
T1 = dict(
    recipient=RCPT,
    recipient_chain="0",
    network="testnet04",
    amount="1.23",
    namespace="",
    module="",
    gas_price="1.0e-6",
    gas_limit="2300",
    creation_time="1665647810",
    chain_id="0",
    nonce=NONCE1,
    ttl="600",
)
NS42 = dict(
    T1,
    network="testnet040000000",
    amount="1.233333333333333333333333333333",
    namespace="n_e595727b657fbbb3b8e362a05a7bb8d12865c1ff",
    module="kb-USDC",
    gas_price="1.011111111111111e-6",
    gas_limit="0123456789",
    creation_time="9876543210",
    ttl="60000000000000000000",
)
CREATE = dict(T1, amount="23.67", chain_id="1", creation_time="1665722463", nonce=NONCE2)
XCHAIN = dict(CREATE, recipient_chain="2")
XMAX = dict(NS42, recipient_chain="19")
ZEMU_TRANSFERS = [
    ("transfer_1", 0, T1),
    ("transfer_namespace_42", 0, NS42),
    ("transfer_create_1", 1, CREATE),
    ("transfer_cross_chain_1", 2, XCHAIN),
    ("transfer_cross_chain_max", 2, XMAX),
]
HANDLER = dict(NS42, namespace="testnamespace012", module="testmoduletestmoduletestmodule01")
HANDLER_CASES = [
    ("handler_legacy_len_287", HANDLER),
    ("handler_legacy_len_285", dict(HANDLER, gas_limit="01234567")),
    ("handler_legacy_len_284", dict(HANDLER, gas_limit="0123456")),
]

# The Zemu simple transfer, signed by 83934c0f... (not the test seed's key).
SIMPLE_TRANSFER_C = (
    b'{"networkId":"mainnet01","payload":{"exec":{"data":{},"code":"(coin.transfer \\"83934c0f9b005f378ba3520f9dea952fb0a90e5aa36f1b5ff837d9b30c471790\\" \\"9790d119589a26114e1a42d92598b3f632551c566819ec48e0e8c54dae6ebb42\\" 11.0)"}},'  # noqa: E501
    b'"signers":[{"pubKey":"83934c0f9b005f378ba3520f9dea952fb0a90e5aa36f1b5ff837d9b30c471790","clist":[{"args":[],"name":"coin.GAS"},{"args":["83934c0f9b005f378ba3520f9dea952fb0a90e5aa36f1b5ff837d9b30c471790","9790d119589a26114e1a42d92598b3f632551c566819ec48e0e8c54dae6ebb42",11],"name":"coin.TRANSFER"}]}],'
    b'"meta":{"creationTime":1634009214,"ttl":28800,"gasLimit":600,"chainId":"0","gasPrice":1.0e-5,"sender":"83934c0f9b005f378ba3520f9dea952fb0a90e5aa36f1b5ff837d9b30c471790"},"nonce":"\\"2021-10-12T03:27:53.700Z\\""}'
)

# The same transfer with the test seed's key as signer and sender (V9: the device
# reviews and signs only for its own signer entry).
SIMPLE_TRANSFER = SIMPLE_TRANSFER_C.replace(RCPT.encode(), EXPECTED_PK.encode())


def rekey(tx, pk_hex):
    """SIMPLE_TRANSFER-like bytes with another signer key."""
    return tx.replace(EXPECTED_PK.encode(), pk_hex.encode())


HASH_1 = bytes.fromhex("ffd8cd79deb956fa3c7d9be0f836f20ac84b140168a087a842be4760e40e2b1c")


def err(message):
    """Response body of a parse error: the ASCII description."""
    return message.encode()


class Device:
    """Sends APDUs and drives the review screens of one test's app instance."""

    def __init__(self, backend, navigator, device, test_name, snapshots):
        self.backend = backend
        self.navigator = navigator
        self.device = device
        self.test_name = test_name
        self.snapshots = snapshots
        backend.raise_policy = RaisePolicy.RAISE_NOTHING

    # -- plain exchanges ----------------------------------------------------
    def send(self, raw):
        r = self.backend.exchange_raw(raw)
        return r.status, bytes(r.data)

    def send_all(self, raws):
        """Sends every APDU except the last; each must answer 9000."""
        for raw in raws[:-1]:
            sw, data = self.send(raw)
            assert (sw, data) == (SW_OK, b""), f"{raw.hex()} -> {sw:#06x} {data.hex()}"

    @contextmanager
    def pending(self, raw, no_tick_timeout=False):
        """`no_tick_timeout`: Speculos ends an APDU exchange after 5 minutes of
        emulated time by default; the largest reviews take longer to walk."""
        client = self.backend._client
        original = client._apdu_exchange_nowait
        if no_tick_timeout:
            client._apdu_exchange_nowait = lambda data: client.session.post(
                f"{client.api_url}/apdu", json={"data": data.hex(), "tick_timeout": 0}, stream=True
            )
        try:
            with self.backend.exchange_async_raw(raw):
                yield
        finally:
            client._apdu_exchange_nowait = original

    def result(self):
        r = self.backend.last_async_response
        return r.status, bytes(r.data)

    def texts(self):
        return [e["text"].strip() for e in self.backend.get_current_screen_content().get("events", [])]

    # -- screens ------------------------------------------------------------
    def _nav_until(self, nav, validation, text, compare, suffix="", timeout=300):
        name = self.test_name + suffix
        if compare:
            self.navigator.navigate_until_text_and_compare(nav, validation, text, self.snapshots, name, timeout=timeout)
        else:
            self.navigator.navigate_until_text(nav, validation, text, timeout=timeout)

    def approve_tx(self, compare=False, timeout=300):
        """`timeout` (seconds) bounds the whole walk; the largest reviews take hundreds of pages on Nano."""
        if self.device.is_nano:
            self._nav_until(NavInsID.RIGHT_CLICK, [NavInsID.BOTH_CLICK], r"^Sign transaction\?$", compare, timeout=timeout)
        else:
            self._nav_until(
                NavInsID.SWIPE_CENTER_TO_LEFT,
                [NavInsID.USE_CASE_REVIEW_CONFIRM, NavInsID.USE_CASE_STATUS_DISMISS],
                r"^Hold to sign$",
                compare,
                timeout=timeout,
            )

    def approve_blind_tx(self, compare=False):
        """Hash signing: the blind-signing warning first, then the review."""
        if self.device.is_nano:
            # "Blind signing ahead / To accept risk, press both buttons".
            if compare:
                self.navigator.navigate_and_compare(
                    self.snapshots, self.test_name + "/warning", [NavInsID.BOTH_CLICK], screen_change_after_last_instruction=False
                )
            else:
                self.navigator.navigate([NavInsID.BOTH_CLICK], screen_change_after_last_instruction=False)
            self._nav_until(NavInsID.RIGHT_CLICK, [NavInsID.BOTH_CLICK], r"^Accept risk and", compare)
        else:
            if compare:
                self.navigator.navigate_and_compare(
                    self.snapshots,
                    self.test_name + "/warning",
                    [NavInsID.USE_CASE_CHOICE_REJECT],
                    screen_change_after_last_instruction=False,
                )
            else:
                self.navigator.navigate([NavInsID.USE_CASE_CHOICE_REJECT], screen_change_after_last_instruction=False)
            self._nav_until(
                NavInsID.SWIPE_CENTER_TO_LEFT,
                [NavInsID.USE_CASE_REVIEW_CONFIRM, NavInsID.USE_CASE_STATUS_DISMISS],
                r"^Hold to sign$",
                compare,
            )

    def reject_tx(self):
        if self.device.is_nano:
            self.navigator.navigate_until_text(NavInsID.RIGHT_CLICK, [NavInsID.BOTH_CLICK], r"^Reject transaction$")
        else:
            self.navigator.navigate(
                [NavInsID.USE_CASE_REVIEW_REJECT, NavInsID.USE_CASE_CHOICE_CONFIRM, NavInsID.USE_CASE_STATUS_DISMISS]
            )

    def approve_address(self, compare=False):
        if self.device.is_nano:
            self._nav_until(NavInsID.RIGHT_CLICK, [NavInsID.BOTH_CLICK], r"^Confirm$", compare)
        else:
            self._nav_until(
                NavInsID.SWIPE_CENTER_TO_LEFT,
                [NavInsID.USE_CASE_ADDRESS_CONFIRMATION_CONFIRM, NavInsID.USE_CASE_STATUS_DISMISS],
                r"^Confirm$",
                compare,
            )

    def reject_address(self):
        if self.device.is_nano:
            self.navigator.navigate_until_text(NavInsID.RIGHT_CLICK, [NavInsID.BOTH_CLICK], r"^Cancel$")
        else:
            self.navigator.navigate_until_text(
                NavInsID.SWIPE_CENTER_TO_LEFT,
                [NavInsID.USE_CASE_ADDRESS_CONFIRMATION_CANCEL, NavInsID.USE_CASE_STATUS_DISMISS],
                r"^Confirm$",
            )

    def dismiss_blind_signing_required(self, go_to_settings=False):
        """The "Cannot clear-sign" choice (blind signing required)."""
        if self.device.is_nano:
            target = r"^Go to settings$" if go_to_settings else r"^Reject Transaction$"
            self.navigator.navigate_until_text(NavInsID.RIGHT_CLICK, [NavInsID.BOTH_CLICK], target)
        else:
            ins = NavInsID.USE_CASE_CHOICE_CONFIRM if go_to_settings else NavInsID.USE_CASE_CHOICE_REJECT
            self.navigator.navigate([ins])

    def review_texts(self, nav_count=80):
        """Walks a pending review page by page (dismissing a blind-signing
        warning) without approving, returns every text seen, then rejects.
        `self.pages` keeps the texts of each page."""
        seen = []
        self.pages = []
        # Wait until the review (or its blind-signing warning) is drawn; never
        # navigate from another screen (a stale home or settings page).
        deadline = time.time() + 60
        while True:
            t = " | ".join(self.texts())
            if "Review transaction" in t or "Blind signing ahead" in t:
                break
            if time.time() > deadline:
                raise AssertionError(f"no review page: {t}")
            time.sleep(0.2)
        self.settle()
        for _ in range(nav_count):
            t = self.texts()
            seen += t
            self.pages.append(t)
            joined = " | ".join(t)
            if self.device.is_nano:
                if "Blind signing ahead" in joined:
                    self.press(NavInsID.BOTH_CLICK)
                    self.settle()
                elif "Reject transaction" in t:
                    self.press(NavInsID.BOTH_CLICK)
                    return seen
                else:
                    self.step(NavInsID.RIGHT_CLICK)
            else:
                if "Blind signing ahead" in joined:
                    self.press(NavInsID.USE_CASE_CHOICE_REJECT)
                    self.settle()
                elif "Hold to sign" in t:
                    self.press(NavInsID.USE_CASE_REVIEW_REJECT)
                    self.press(NavInsID.USE_CASE_CHOICE_CONFIRM)
                    self.press(NavInsID.USE_CASE_STATUS_DISMISS)
                    return seen
                else:
                    self.step(NavInsID.SWIPE_CENTER_TO_LEFT)
        raise AssertionError(f"review did not end: {seen[-10:]}")

    # -- settings -----------------------------------------------------------
    def press(self, *ins):
        """Navigation without waiting for a screen change (settings pages)."""
        self.navigator.navigate(
            list(ins), screen_change_before_first_instruction=False, screen_change_after_last_instruction=False
        )
        time.sleep(0.5)

    def step(self, ins):
        """One review page forward: waits until the page text changes, and sends the
        instruction once more if it did not (an input dropped while the emulator was busy).
        A page read twice or skipped makes the caller's assertions fail, never pass."""
        before = self.texts()
        for _ in range(2):
            self.navigator.navigate(
                [ins], screen_change_before_first_instruction=False, screen_change_after_last_instruction=False
            )
            # A new streaming batch can take seconds to draw in the emulator; a
            # second press before it shows would skip its first page.
            deadline = time.time() + 20
            while time.time() < deadline:
                time.sleep(0.25)
                now = self.texts()
                if now and now != before:
                    self.settle()
                    return

    def settle(self):
        """Waits until the page text stops changing (a page still being drawn reads partial)."""
        last = self.texts()
        for _ in range(20):
            time.sleep(0.3)
            now = self.texts()
            if now == last:
                return
            last = now

    def toggle_settings(self, *names):
        """Switches the named settings ("Blind signing", "Expert mode") from the home screen."""
        if self.device.is_nano:
            for _ in range(4):
                if "App settings" in self.texts():
                    break
                self.press(NavInsID.RIGHT_CLICK)
            self.press(NavInsID.BOTH_CLICK)
            for _ in range(4):
                t = self.texts()
                if "Back" in t:
                    self.press(NavInsID.BOTH_CLICK)
                    self.wait_home(names)
                    return
                if t and t[0] in names:
                    self.press(NavInsID.BOTH_CLICK)
                self.press(NavInsID.RIGHT_CLICK)
            raise AssertionError("settings pages not as expected")
        for _ in range(5):
            self.press(NavInsID.USE_CASE_HOME_SETTINGS)
            if "Quit app" not in self.texts():
                break
        for name in names:
            ev = self.backend.get_current_screen_content()["events"]
            hit = [e for e in ev if e["text"].strip() == name]
            assert hit, f"{name} not on the settings page"
            self.backend.finger_touch(hit[0]["x"] + 20, hit[0]["y"] + 10)
            time.sleep(0.5)
        self.press(NavInsID.USE_CASE_SETTINGS_SINGLE_PAGE_EXIT)
        self.wait_home(names)

    def wait_home(self, names, timeout=20):
        """Returns once the settings page is gone and a home page is drawn, so
        the next command's screens are not mistaken for the settings ones."""
        deadline = time.time() + timeout
        while True:
            t = self.texts()
            if t and not any(n in t for n in names) and "Back" not in t:
                return
            if time.time() > deadline:
                raise AssertionError(f"home page not shown after the settings: {t}")
            time.sleep(0.2)


def snapshots_root():
    return Path(__file__).parent.resolve()


# -- the app's store in the ELF (flash data loaded as it is by Speculos) -------
STORE_SYMBOL = "6kadena7storage5STORE"  # kadena::storage::STORE, mangled
# The settings, first in the store: an AtomicStorage of two halves, A then B, each
# a validity flag (0xA5 = valid) and the value, every part on its own 64 bytes.
SETTINGS_A_FLAG, SETTINGS_A_VALUE, SETTINGS_B_FLAG, SETTINGS_B_VALUE = 0x00, 0x40, 0x80, 0xC0
SETTINGS_VALID = 0xA5


def patch_store(elf_path, patch):
    """Rewrites the app's store in the ELF's `.nvm_data`: `patch` gets the store's
    bytes (a bytearray) and changes them in place. Returns the store's size."""
    with open(elf_path, "rb") as f:
        elf = ELFFile(f)
        nvm = elf.get_section_by_name(".nvm_data")
        symtab = elf.get_section_by_name(".symtab")
        assert nvm is not None and isinstance(symtab, SymbolTableSection)
        store = [s for s in symtab.iter_symbols() if STORE_SYMBOL in s.name]
        assert len(store) == 1, f"expected one store symbol, found {len(store)}"
        addr, size = store[0]["st_value"], store[0]["st_size"]
        assert nvm["sh_addr"] <= addr and addr + size <= nvm["sh_addr"] + nvm["sh_size"]
        offset = nvm["sh_offset"] + addr - nvm["sh_addr"]
    with open(elf_path, "r+b") as f:
        f.seek(offset)
        data = bytearray(f.read(size))
        # The image's settings: both halves valid, both switches OFF.
        assert data[SETTINGS_A_FLAG] == SETTINGS_VALID and data[SETTINGS_B_FLAG] == SETTINGS_VALID
        before = bytes(data)
        patch(data)
        assert bytes(data) != before, "the patch changed nothing"
        f.seek(offset)
        f.write(data)
    return size


def patched_app_backend(request, tmp_path, patch):
    """A Speculos backend on a copy of the app whose store `patch` rewrote (see
    patch_store); takes the same fixtures as Ragger's own backend."""
    # Imported here: at module level it would come before pytest registers it as a plugin.
    from ragger.conftest import base_conftest

    if request.getfixturevalue("backend_name").lower() != "speculos":
        pytest.skip("needs the emulator, which loads the modified binary")
    device = request.getfixturevalue("device")
    app, args = base_conftest.prepare_speculos_args(
        request.getfixturevalue("root_pytest_dir"),
        device,
        request.getfixturevalue("display"),
        request.getfixturevalue("pki_prod"),
        request.getfixturevalue("cli_user_seed"),
        request.getfixturevalue("additional_speculos_arguments"),
        request.getfixturevalue("verbose_speculos"),
        request.getfixturevalue("ignore_missing_binaries"),
    )
    patched = tmp_path / "app-patched-store.elf"
    shutil.copyfile(app, patched)
    assert patch_store(patched, patch) > 0
    return SpeculosBackend(patched, device=device, **args)
