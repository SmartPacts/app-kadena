"""Home screen and settings (both switches OFF on install)."""

from ragger.navigator import NavInsID


def test_home_and_settings(kda, navigator, device, test_name, default_screenshot_path):
    if device.is_nano:
        instructions = [
            NavInsID.RIGHT_CLICK,
            NavInsID.BOTH_CLICK,
            NavInsID.RIGHT_CLICK,
            NavInsID.RIGHT_CLICK,
            NavInsID.BOTH_CLICK,
            NavInsID.RIGHT_CLICK,
        ]
    else:
        instructions = [
            NavInsID.USE_CASE_HOME_SETTINGS,
            NavInsID.USE_CASE_SETTINGS_SINGLE_PAGE_EXIT,
            NavInsID.USE_CASE_HOME_INFO,
            NavInsID.USE_CASE_SETTINGS_SINGLE_PAGE_EXIT,
        ]
    navigator.navigate_and_compare(default_screenshot_path, test_name, instructions, screen_change_before_first_instruction=False)


def test_settings_default_off(kda):
    """Both switches read "OFF"/"Disabled" on a fresh install (the hash test
    `test_hash_refused_with_blind_signing_off` proves the behaviour)."""
    if kda.device.is_nano:
        for _ in range(4):
            if "App settings" in kda.texts():
                break
            kda.press(NavInsID.RIGHT_CLICK)
        kda.press(NavInsID.BOTH_CLICK)
        first = kda.texts()
        kda.press(NavInsID.RIGHT_CLICK)
        second = kda.texts()
        assert first[0] == "Blind signing" and "Disabled" in first
        assert second[0] == "Expert mode" and "Disabled" in second
