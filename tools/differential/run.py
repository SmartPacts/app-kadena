"""Run the differential corpus against one app ELF in Speculos.

    python run.py --device stax --elf path/to/app.elf --label rust --out results/stax-rust.json

Runs every case of `corpus.py` in two sessions: settings as installed (both
switches OFF), then with "blind signing" and "expert mode" switched ON through
the settings screen. Reviews are driven through the screens (approve or reject,
as the case says) with Ragger's navigator; every response is recorded, plus
whether each case's marker texts (e.g. "Unscoped Signer") were ever on screen.
Between cases a fixed reset sequence closes any open command stream.
"""

import argparse
import json
import re
import threading
import time
from pathlib import Path

import requests
from ledgered.devices import Devices
from ragger.backend import SpeculosBackend
from ragger.navigator import NavInsID
from ragger.navigator.nano_navigator import NanoNavigator
from ragger.navigator.touch_navigator import TouchNavigator

import corpus

SEED = "equip will roof matter pink blind book anxiety banner elbow sun young"
# Closes any open stream: a modern INIT starts a new stream in both apps, the
# empty LAST ends it, and a 0x04 with no data ends any legacy stream the C app
# still has open. The responses are recorded but not compared (the apps may
# differ on the first one when a case left a stream open: V8).
RESET = ["0022000014" + corpus.le(corpus.STD).hex(), "0022020000", "0004000000"]

APPROVE_NANO = re.compile(r"(?i)^(approve|accept|sign|confirm|sign transaction ?\??|accept risk and sign transaction ?\??)$")
REJECT_NANO = re.compile(r"(?i)^(reject|reject transaction ?\??|cancel)$")
STATUS = re.compile(r"(?i)(signed|rejected|verified|cancell?ed)")


class Runner:
    def __init__(self, device_name, elf):
        self.device = Devices.get_by_name(device_name)
        self.backend = SpeculosBackend(elf, self.device, args=["--seed", SEED])
        nav_cls = NanoNavigator if self.device.is_nano else TouchNavigator
        self.nav = nav_cls(self.backend, self.device)

    def texts(self):
        try:
            return [e["text"].strip() for e in self.backend.get_current_screen_content().get("events", [])]
        except Exception:
            return []

    def do(self, *ins):
        self.nav.navigate(list(ins), screen_change_before_first_instruction=False,
                          screen_change_after_last_instruction=False)
        time.sleep(0.35)

    def post(self, apdu_hex):
        url = f"http://127.0.0.1:{self.backend._api_port}/apdu"
        r = requests.post(url, json={"data": apdu_hex}, timeout=600)
        r.raise_for_status()
        return r.json()["data"]

    def exchange(self, apdu_hex, decision):
        """Sends one APDU; if a screen waits for the user, drives it. Returns
        (response hex, set of texts seen while it was pending)."""
        result = {}

        def run():
            try:
                result["data"] = self.post(apdu_hex)
            except Exception as e:  # noqa: BLE001
                result["err"] = repr(e)

        before = self.texts()
        t = threading.Thread(target=run)
        t.start()
        t.join(0.6)
        # Wait for the review to be drawn before acting on the screen.
        deadline = time.time() + 5
        while t.is_alive() and self.texts() == before and time.time() < deadline:
            t.join(0.2)
        seen, last, same = set(), None, 0
        steps = 0
        while t.is_alive():
            ev = self.texts()
            seen.update(ev)
            same = same + 1 if ev == last else 0
            last = ev
            self.drive(ev, decision, same)
            t.join(0.25)
            steps += 1
            if steps > 400:
                raise RuntimeError(f"stuck on screen {ev}")
        seen.update(self.texts())
        if "err" in result:
            raise RuntimeError(result["err"])
        return result["data"], seen

    def drive(self, ev, decision, same):
        joined = " | ".join(ev)
        if self.trace:
            print("      screen:", ev, flush=True)
        if self.device.is_nano:
            if any(k in joined for k in ("Blind signing must be", "This transaction cannot", "clear-signed", "Cannot clear-sign",
                                         "Go to settings")):
                self._blind_error_seen = True
            if self._blind_error_seen:
                # Blind-signing-required screen: both answers lead to the same reply.
                if "Blind signing must be" in joined or any(REJECT_NANO.match(t) for t in ev) or same >= 6:
                    self.do(NavInsID.BOTH_CLICK)
                else:
                    self.do(NavInsID.RIGHT_CLICK)
                return
            if "Blind signing ahead" in joined:
                self.do(NavInsID.BOTH_CLICK)
                return
            if STATUS.search(joined) and len(ev) <= 2 and not any(APPROVE_NANO.match(t) for t in ev):
                time.sleep(0.5)
                return
            if decision == "approve" and ev == ["Reject transaction"]:
                # NBGL Nano: past the approve page (or a first page Speculos had not
                # reported yet): step back to it.
                self.do(NavInsID.LEFT_CLICK)
                return
            pat = APPROVE_NANO if decision == "approve" else REJECT_NANO
            # The C app's last page reads "ACCEPT RISK" / "AND APPROVE".
            two_line = decision == "approve" and re.search(r"(?i)\bapprove\b", joined)
            if any(pat.match(t) for t in ev) or two_line or same >= 6:
                self.do(NavInsID.BOTH_CLICK)
                return
            self.do(NavInsID.RIGHT_CLICK)
            return
        # Touch screens.
        if "Hold to sign" in ev:
            if decision == "approve":
                self.do(NavInsID.USE_CASE_REVIEW_CONFIRM)
            else:
                self.do(NavInsID.USE_CASE_REVIEW_REJECT, NavInsID.USE_CASE_CHOICE_CONFIRM)
            return
        if "Go to settings" in ev:
            self.do(NavInsID.USE_CASE_CHOICE_REJECT)
            return
        if "Blind signing ahead" in joined:
            self.do(NavInsID.USE_CASE_CHOICE_REJECT)
            return
        if "Confirm" in ev and "Cancel" in ev:
            if decision == "approve":
                self.do(NavInsID.USE_CASE_ADDRESS_CONFIRMATION_CONFIRM)
            else:
                self.do(NavInsID.USE_CASE_ADDRESS_CONFIRMATION_CANCEL)
            return
        if STATUS.search(joined) and len(ev) <= 2:
            self.do(NavInsID.USE_CASE_STATUS_DISMISS)
            return
        if decision == "reject" and ev and "Quit app" not in ev and "Confirm" not in ev:
            self.do(NavInsID.USE_CASE_REVIEW_REJECT, NavInsID.USE_CASE_CHOICE_CONFIRM)
            return
        self.do(NavInsID.SWIPE_CENTER_TO_LEFT)

    _blind_error_seen = False
    trace = bool(__import__("os").environ.get("DIFF_TRACE"))

    def enable_settings(self):
        """Switches ON blind signing and expert mode through the settings screen."""
        if self.device.is_nano:
            self._nano_settings()
            return
        for _ in range(5):
            self.do(NavInsID.USE_CASE_HOME_SETTINGS)
            deadline = time.time() + 3
            while "Quit app" in self.texts() and time.time() < deadline:
                time.sleep(0.2)
            if "Quit app" not in self.texts():
                break
        for name in ("Blind sign", "Expert mode"):
            ev = self.backend.get_current_screen_content().get("events", [])
            hit = [e for e in ev if e["text"].strip().startswith(name)]
            if not hit:
                raise RuntimeError(f"setting {name} not on screen: {[e['text'] for e in ev]}")
            self.backend.finger_touch(hit[0]["x"] + 20, hit[0]["y"] + 10)
            time.sleep(0.6)
        self.do(NavInsID.USE_CASE_SETTINGS_SINGLE_PAGE_EXIT)

    def _nano_settings(self):
        # C (BAGL menu): "Expert mode:" and "Blind sign:" are home menu entries.
        # Rust (NBGL): "App settings" -> one page per switch -> "Back".
        for _ in range(8):
            ev = self.texts()
            if "App settings" in ev:
                self.do(NavInsID.BOTH_CLICK)
                for _ in range(8):
                    ev = self.texts()
                    if ev and (ev[0].startswith("Blind signing") or ev[0].startswith("Expert mode")):
                        self.do(NavInsID.BOTH_CLICK)
                        self.do(NavInsID.RIGHT_CLICK)
                    elif "Back" in ev:
                        self.do(NavInsID.BOTH_CLICK)
                        return
                    else:
                        self.do(NavInsID.RIGHT_CLICK)
                raise RuntimeError("Rust settings pages not as expected")
            if ev and ev[0].startswith("Expert mode:"):
                self.do(NavInsID.BOTH_CLICK)
                self.do(NavInsID.RIGHT_CLICK)
                if not self.texts() or not self.texts()[0].startswith("Blind sign:"):
                    raise RuntimeError(f"C menu not as expected: {self.texts()}")
                self.do(NavInsID.BOTH_CLICK)
                for _ in range(4):
                    self.do(NavInsID.LEFT_CLICK)
                return
            self.do(NavInsID.RIGHT_CLICK)
        raise RuntimeError(f"settings not found: {self.texts()}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--device", required=True)
    ap.add_argument("--elf", required=True)
    ap.add_argument("--label", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--only", default="", help="regex on case names")
    args = ap.parse_args()
    all_cases = corpus.cases()
    if args.only:
        all_cases = [c for c in all_cases if re.search(args.only, c["name"])]
    out = {"device": args.device, "label": args.label, "elf": args.elf, "cases": []}
    for session in ("default", "blind_expert"):
        cases = [c for c in all_cases if c["session"] == session]
        i = 0
        while i < len(cases):
            # One emulator instance per session; restarted after an app crash.
            r = Runner(args.device, args.elf)
            with r.backend:
                time.sleep(1.5)
                if session == "blind_expert":
                    r.enable_settings()
                    r.post(corpus.apdu(0x20).hex())
                while i < len(cases):
                    c = cases[i]
                    i += 1
                    res = {"name": c["name"], "tag": c["tag"], "session": session, "steps": [], "markers": {}}
                    try:
                        r._blind_error_seen = False
                        res["reset"] = [r.post(a) for a in RESET]
                        seen_all = set()
                        for s in c["steps"]:
                            r._blind_error_seen = False
                            data, seen = r.exchange(s["apdu"], s["ui"])
                            seen_all |= seen
                            res["steps"].append({"apdu": s["apdu"], "response": data})
                        res["markers"] = {m: any(m in t for t in seen_all) for m in c["markers"]}
                    except Exception as e:  # noqa: BLE001  the emulator stopped
                        res["crash"] = repr(e)[:300]
                        while len(res["steps"]) < len(c["steps"]):
                            res["steps"].append({"apdu": c["steps"][len(res["steps"])]["apdu"], "response": "CRASH"})
                        res.setdefault("reset", [])
                        out["cases"].append(res)
                        print(f"{args.label:5} {args.device:7} {c['name'][:60]:60} CRASH", flush=True)
                        break
                    out["cases"].append(res)
                    print(f"{args.label:5} {args.device:7} {c['name'][:60]:60} "
                          f"{' '.join(x['response'][-4:] for x in res['steps'])}", flush=True)
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    Path(args.out).write_text(json.dumps(out, indent=1))


if __name__ == "__main__":
    main()
