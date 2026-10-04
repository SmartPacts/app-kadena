from ragger.conftest import configuration

# The Zondax public test seed used by the C app's Zemu suite: the expected
# address below (de12b5e1...) is derived from it. Never a seed with funds.
configuration.OPTIONAL.CUSTOM_SEED = "equip will roof matter pink blind book anxiety banner elbow sun young"
# Each test gets a fresh app (settings back to OFF, no open command stream).
configuration.OPTIONAL.BACKEND_SCOPE = "function"

pytest_plugins = ("ragger.conftest.base_conftest",)


import pytest  # noqa: E402
from kadena import Device  # noqa: E402


@pytest.fixture
def kda(backend, navigator, device, test_name, default_screenshot_path):
    return Device(backend, navigator, device, test_name, default_screenshot_path)
