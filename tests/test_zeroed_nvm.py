"""First start on a zeroed NVM.

The installed image carries the initial settings (both switches OFF, with the
storage's validity flags set) and zeroed transaction buffers. A loader that does
not write that initial `.nvm_data` leaves the whole store zero, flags included:
then the settings storage holds no value yet. This module starts the app with
its store zeroed and runs the first-use tests again: both switches must read
OFF and behave as OFF, both can be switched on, and the transaction buffers
work from empty. Without the app storing the default settings at start, the
first read of a switch panics and every test here fails.
"""

import pytest
from kadena import patched_app_backend

# The first-use tests, collected again here so that they run on the zeroed store.
from test_menu import test_home_and_settings, test_settings_default_off  # noqa: F401
from test_sign_hash import (  # noqa: F401
    test_hash_refused_with_blind_signing_off,
    test_hash_signs_raw_bytes_with_blind_signing_on,
)
from test_sign_json import test_sign_json_simple_transfer  # noqa: F401
from test_transfer import test_transfer_modern  # noqa: F401
from test_version_address import test_show_address_expert_mode_shows_the_path  # noqa: F401


def zero(store):
    store[:] = bytes(len(store))


@pytest.fixture
def backend(skip_tests_for_unsupported_devices, request, tmp_path):
    with patched_app_backend(request, tmp_path, zero) as b:
        yield b
