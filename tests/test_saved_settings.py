"""A saved setting survives the start of the app.

At start the app stores the switches OFF only when the settings storage holds no
value (see test_zeroed_nvm.py). Here the store holds a saved "Blind signing" ON,
in each layout an update can leave: the second half valid and the first not (the
last update wrote the second half), and both halves valid (an update cut short
after it validated the half it wrote; the first half wins). The switch must read
ON and a hash must be signed without touching the settings. An app that stored
the default unconditionally at start would read OFF and refuse the hash.
"""

import pytest
from kadena import (
    EXPECTED_PK,
    HASH_1,
    SETTINGS_A_FLAG,
    SETTINGS_A_VALUE,
    SETTINGS_B_FLAG,
    SETTINGS_B_VALUE,
    SETTINGS_VALID,
    SW_OK,
    modern_chunks,
    patched_app_backend,
    verify,
)
from ragger.navigator import NavInsID

BLIND_SIGNING = 0  # index of the switch in the settings array


def second_half_valid_blind_on(store):
    store[SETTINGS_A_FLAG] = 0
    store[SETTINGS_B_FLAG] = SETTINGS_VALID
    store[SETTINGS_B_VALUE + BLIND_SIGNING] = 1


def both_halves_valid_first_blind_on(store):
    store[SETTINGS_A_FLAG] = SETTINGS_VALID
    store[SETTINGS_A_VALUE + BLIND_SIGNING] = 1
    store[SETTINGS_B_FLAG] = SETTINGS_VALID
    store[SETTINGS_B_VALUE + BLIND_SIGNING] = 0


@pytest.fixture(
    params=[second_half_valid_blind_on, both_halves_valid_first_blind_on],
    ids=["second-half-valid", "both-halves-valid"],
)
def backend(skip_tests_for_unsupported_devices, request, tmp_path):
    with patched_app_backend(request, tmp_path, request.param) as b:
        yield b


def test_saved_blind_signing_reads_on(kda):
    chunks = modern_chunks(0x23, HASH_1)
    kda.send_all(chunks)
    with kda.pending(chunks[-1]):
        kda.approve_blind_tx()
    sw, sig = kda.result()
    assert sw == SW_OK
    verify(EXPECTED_PK, HASH_1, sig)
    if kda.device.is_nano:
        # The reply comes once the status page has closed: the home page is up.
        for _ in range(4):
            if "App settings" in kda.texts():
                break
            kda.press(NavInsID.RIGHT_CLICK)
        kda.press(NavInsID.BOTH_CLICK)
        first = kda.texts()
        assert first[0] == "Blind signing" and "Enabled" in first, first
