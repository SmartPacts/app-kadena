# Ledger Kadena app
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

The Kadena app for Ledger Nano S+, Nano X, Flex, Stax, and Apex P (Nano Gen5), written in Rust on
Ledger's Rust SDK.

> **Release candidate, published for review.** Version 2.0.0 is not released: there are no binaries to
> install and it has not had the third-party audit Ledger requires. The app to install today is the C
> implementation, v1.3.3: see the [release page](https://github.com/SmartPacts/app-kadena/releases); its
> source is on the [`c-v1.3`](https://github.com/SmartPacts/app-kadena/tree/c-v1.3) branch.

## About this repository

This is the maintained continuation of the Kadena Ledger app. Version 2.0.0 is a Rust rewrite of the C
implementation (by [Zondax](https://www.zondax.ch), then this continuation up to v1.3.3; it is on the `c-v1.3` branch), which in turn kept
the command protocol of the original app by Obsidian Systems. See [NOTICE](NOTICE). It is maintained by
[Smart Pacts](https://smartpacts.io), with the goal of returning the app to the Ledger app store.

What stays the same as v1.3.0:

- every command and response, byte for byte (both command families, status words, error texts);
- the keys: addresses derive exactly as before;
- what the review shows: the same titles and values in the same order.

What changes is listed plainly under [Differences from the C implementation](#differences-from-the-c-implementation).

## ATTENTION

- **Do not use a Ledger device with funds for development purposes.**
- **Have a separate and marked device that is used ONLY for development and testing.**

## Download and install

*Once the app is approved by Ledger, it will be available in their app store (Ledger Live).*

Kadena is currently not offered in Ledger's catalog. Released versions up to v1.3.3 are the
C implementation; see the [release page](https://github.com/SmartPacts/app-kadena/releases) and the notes
there for sideloading on a Nano S+. A retail Nano X refuses sideloaded apps. The
first-generation Nano S is not supported.

## Security model

- **Keys never leave the device.** The app derives Ed25519 keys with the OS (`m/44'/626'/...`, Ledger's
  HDW_NORMAL scheme) and returns only public keys and signatures. Only paths starting with `44'/626'` are
  accepted.
- **What you see is what is signed.** For a JSON transaction the device signs `Ed25519(blake2b-256(bytes))`
  of the exact bytes it received and displayed, which must be one JSON value; it reviews the signer entry that
  carries its own key, and refuses a transaction where that key is missing or repeated. For a structured
  transfer it builds the JSON itself from checked fields and signs that. The expert-mode "Transaction hash" is
  the request key of those bytes. Bytes outside printable ASCII are shown as `\xNN`.
- **Warnings.** A signer entry without capabilities (missing, null or empty clist) shows "Unscoped Signer"
  and an UNSAFE warning; an unrecognised `meta` shows CAUTION; a capability too large to display is flagged.
  A transfer capability that does not name the signer shows "Unscoped Signer".
- **Blind signing is off by default.** Signing a bare 32-byte hash (0x23 / 0x04), a JSON transaction with one
  of the warnings above (its signature is not bounded by capabilities the screen shows), and an account rotation
  (the new owner is not shown), and any capability other than gas and a fully shown coin transfer, needs the
  "Blind signing" setting, and shows Ledger's blind-signing warning first. So does a structured token
  transfer (0x24, 0x10 with a namespace and module): the token module's code can use the key while its
  TRANSFER capability is in scope. Structured coin transfers are never blind.
- **Fee, payer and other warnings.** Every review shows the maximum fee in KDA and the paying account. A transfer
  to an account that is not a principal is flagged.
- **Memory safety.** The protocol code (`kadena-core`) contains no unsafe code and no heap allocation;
  every buffer access is bounds-checked. The device crate uses `unsafe` only for OS calls (flash writes,
  PIN state, versions) and for the single-threaded statics that hold the app state and the flash store.

## Differences from the C implementation

Intended differences from v1.3.0 (details in [docs/APDUSPEC.md](docs/APDUSPEC.md#differences-from-the-c-implementation-v130)):

1. Legacy transfer (0x10): an item longer than the bytes its APDU carries is refused (0x6700). The C app could
   sign leftover bytes as the undisplayed ttl.
2. Structured transfers (0x24, 0x10): each field must match its allowed characters, numbers must be well formed and
   the recipient lowercase hex (0x6984). The C app let a `"` in a field add JSON that the screen did not show.
3. A transfer must name the signer key exactly to count as naming it (the C app compared a prefix); a scoped
   signature whose transfers do not name the key is titled "Key not in transfer", not "Unscoped Signer".
4. JSON objects with duplicate keys, at any depth, are refused (0x6984).
5. A 0x22/0x23/0x24 first chunk closes any command stream in progress; a modern middle or last chunk with no
   stream of its INS open is refused (0x6987).
6. INS 0xFF stays unsupported (0x6D00), as in the C app.
7. The key that signs is the one for the path the signing command gave; an address command sent in the middle of
   it (e.g. 0x02 for another path) no longer changes it. The C app signed with the last path any command gave.
8. Every packet of a command must carry the INS of its first packet; a mixed stream is refused (0x6987) and
   closed. The C app parsed the buffer by the last packet's INS (a 0x22 transaction finished with 0x23 was read
   as a hash).
9. A JSON transaction is reviewed for the signer entry that carries the device key, which must be the only entry
   naming it (0x6984 otherwise); with several signers the review shows how many. The C app reviewed the first
   entry whatever its key.
10. An empty clist (`[]`) is unscoped, like a missing or null one: "Unscoped Signer" and the WARNING.
11. A JSON transaction whose signature no displayed capability list bounds (unscoped signer, a value too large to
    show, an unrecognised `meta`) is blind signing: refused unless "Blind signing" is ON, then reviewed after
    Ledger's blind-signing warning. The C app signed it with blind signing OFF.
12. A JSON document with a NUL byte or with bytes after its value is refused (0x6984).
13. Any byte of a displayed value outside printable ASCII is shown as `\xNN`, on every device.
14. A signature scoped to `coin.ROTATE` is blind signing, with the warning "Account rotation: new owner not shown"
    (the new guard is in code and data the device does not show). The C app clear-signed it.
15. The review shows the maximum fee ("Max fee", gasLimit × gasPrice in KDA, computed exactly) and the paying
    account (`meta.sender`); `gasLimit`, `ttl` and `creationTime` must be plain digits.
16. A transfer to an account that is not a Pact principal (`k:`, `w:`, `r:`, `u:`, `m:`, `p:`, `c:`) gets the
    warning "Recipient is not a principal account".
17. (Replaced by 20.)
18. A JSON object key written with an escape, anywhere, and an escaped capability name in the device's signer entry
    are refused (0x6984): the node's decoder would read such a key differently from the device.
19. Expert mode shows the payload kind (exec, or cont with its pact id and step) and the validity window:
    "Created (unix time)" and "TTL (seconds)".
20. Only `coin.GAS` and fully shown `coin.TRANSFER` / `coin.TRANSFER_XCHAIN` are clear-signed. Any other
    capability of the device's signer entry (`coin.DEBIT`, `coin.CREDIT`, other modules' capabilities) needs
    "Blind signing" and shows, as separate items each shown whole, "WARNING: Capability not verified",
    "Capability: <module>.<NAME>", "Namespace: <namespace>" (only when the name has one) and its "Arguments".
21. A transfer amount in exponent notation is refused (0x6984).
22. A command with a `verifiers` field is refused (0x6984).
23. A structured token transfer (0x24, 0x10 with a namespace and module) needs "Blind signing" and shows
    the capability as in 20 ("Capability: <module>.TRANSFER", "Namespace: <namespace>"). Structured coin
    transfers stay clear-signed.
24. A transfer amount is a bare JSON number or `{"decimal":"<number>"}` (the number `(0|[1-9][0-9]*)(.[0-9]+)?`),
    shown as the plain number; any other shape (strings, `{"int":...}`, signs, exponents, leading zeros, extra
    or unquoted keys, escapes) is refused (0x6984).
25. A coin transfer amount has at most 12 fractional digits, coin's precision (0x6984 otherwise).
26. A structured transfer amount must have a fractional part (`1000.0`): Pact refuses an integer (0x6984).

Other visible changes:

- The version is 2.0.0.
- Screens use NBGL on every device (Nano S+ and Nano X used BAGL before). The layout follows Ledger's
  standard flows. On Nano the app pages long values itself so that no title is ever shortened: a page shows the
  whole title, and "(i/n)" goes after it or on the first value line; a title wider than the screen continues on
  the first value line. A value without spaces (a key, an account, a namespace) is cut into lines at the screen
  width, so it fills its pages. The C app's "Unknown Capability N" item is shown as "Capability",
  "Namespace" and "Arguments" (see 20).
- The blind-signing-required page reads "Cannot clear-sign" / "Enable Blind signing in Settings to sign this
  transaction" (the C app's title was shortened on Nano).
- Settings are named "Blind signing" and "Expert mode" (both OFF on install).
- Framing is done by the SDK: an APDU whose length byte does not match its data is answered 0x6E03 by the SDK
  (the C app ignored that byte), and a 4-byte APDU without a length byte is read as having no data (the C app
  answered 0x6700). Hosts always send a correct length byte, so they see no difference.
- The review streams its items in batches of about 1200 bytes, so the largest transaction the app accepts
  fits the 8 KiB heap on every device (see CHANGELOG).

# Development

Everything runs in Ledger's dev-tools image, pinned by digest:

```bash
IMG=ghcr.io/ledgerhq/ledger-app-builder/ledger-app-dev-tools@sha256:1f93ba59ee02576f336653c712276f006d4d81f4e355b023489bb7b5bdcf390d
docker run --rm -it -v "$(pwd):/app" -w /app $IMG bash
```

SDK and API level: the pinned image builds with the C SDK v26.6.5 (API level 26), which is what the local
tests, the differential and the release hashes in `submission/` use, and what a Nano S+ on OS 1.6.1 accepts.
CI builds with Ledger's current `ledger-app-builder` image: since 2026-10-02 that is SDK v27.1.1, and the five
ELFs it built for this branch report API level 27 in their `ledger.api_level` section.

## Layout

- `kadena-core/` — the protocol, device-independent: APDU state machine (`app.rs`), JSON tokenizer and
  lookups (`jsmn.rs`, `json.rs`), review items (`items.rs`), transfer template (`transfer.rs`). Each module
  names the C source it ports.
- `src/` — the device app: OS crypto, the transaction buffer (RAM up to 8192 bytes, flash above, as in the C
  app) and flash storage (`platform.rs`, `storage.rs`), screens (`ui.rs`), settings.
- `tests/` — Ragger functional tests on the Speculos emulator.
- `kadena-core/fuzz/` — a libFuzzer target for the JSON tokenizer, parser and review items (see "Fuzzing").
- `tools/differential/` — the C-vs-Rust differential harness.

The C app's Zemu suite (`tests_zemu/` in Zondax/ledger-kadena) is not part of this repository: every
protocol-level case of it is in the differential corpus and the Ragger suite.

## Build

```bash
cargo ledger build nanosplus   # also: nanox, stax, flex, apex_p
# -> target/<device>/release/kadena
```

## Tests

Host tests of the protocol crate (the C app's tokenizer and UI vectors, and every command path). Run them
outside the app directory, so the device build settings do not apply:

```bash
cd /tmp && cargo +nightly-2025-12-05 test --manifest-path /app/kadena-core/Cargo.toml
```

Functional tests on the Speculos emulator (build the five targets first; `tests/README.md` has more):

```bash
python3 -m venv --system-site-packages /tmp/v && . /tmp/v/bin/activate
pip install -r tests/requirements.txt
for d in nanosp nanox stax flex apex_p; do pytest tests/ --device $d; done
```

Add `--golden_run` to regenerate the screen snapshots after an intended UI change.

The goldens and the results in `submission/` come from local runs in the pinned dev-tools image above. In CI
(`.github/workflows/build_and_functional_tests.yml`) the functional tests run on the default runner of
Ledger's reusable workflow, as in app-boilerplate-rust, because that workflow installs
`tests/requirements.txt` with pip, which the dev-tools image refuses.

Lint: `cargo fmt --check` and `cargo clippy --target <device> -- -D warnings`.

## Differential check against the C app

`tools/differential/` sends one APDU corpus (every protocol case of the C app's test suites, its UI vectors,
error cases, the security reproductions, and generated malformed inputs) to the C v1.3.0 release ELFs and to
this app in Speculos, drives the reviews, and diffs every response:

```bash
gh run download 36165620661 -R SmartPacts/app-kadena -n compiled_app_binaries -D /tmp/c-elf   # C v1.3.0
cd tools/differential
python3 run.py --device stax --elf /tmp/c-elf/stax/bin/app.elf --label c --out results/stax-c.json
python3 run.py --device stax --elf ../../target/stax/release/kadena --label rust --out results/stax-rust.json
python3 compare.py results/*.json --report report.md
```

The C binaries are the v1.3.0 release ELFs: artifact `compiled_app_binaries` of the "Reusable build" run
36165620661 of SmartPacts/app-kadena (branch main, commit 144b30fe); their sha256 are in
`tools/differential/report.md`. The harness needs only those ELFs and this repository.

`compare.py` fails on any difference that is not one of the intended differences above.

## Fuzzing

`kadena-core/fuzz/` holds a libFuzzer target (`review`) for the JSON tokenizer, the parser and the review
items, as a signing command drives them, with the token caps of Nano X and of the other devices. The seed
corpus is in `kadena-core/fuzz/seeds/review` (the C UI vectors re-keyed to the test key, and the JSON bodies
of the differential corpus). Run it from outside the app directory, with `cargo-fuzz` installed:

```bash
cd /tmp && cargo +nightly-2025-12-05 fuzz run --fuzz-dir /app/kadena-core/fuzz review \
  /tmp/fuzz-corpus /app/kadena-core/fuzz/seeds/review -- -max_len=15104 -max_total_time=600
```

The first corpus directory receives new inputs; the seeds stay unchanged. Add `-O` to build without debug
assertions, as on the device.

## APDU Specifications

- [APDU Protocol](docs/APDUSPEC.md)
