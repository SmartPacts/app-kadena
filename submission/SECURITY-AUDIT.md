# Kadena Ledger app — security review (v2.0.0, Rust, API_LEVEL 26)

v2.0.0 is a rewrite of the app in Rust on Ledger's Rust SDK (`ledger_device_sdk` =1.37.0), NBGL on all five
devices (Nano S+, Nano X, Stax, Flex, Apex P). This document describes v2.0.0 only; the C app (v1.3.x) is on the
`c-v1.3` branch.

## Scope and method

Commit ids below refer to the development history, which is not part of this repository. In the tests,
"R3" (with F-A, F-B, #3 to #5) names the emulator reproduction of the C app's defects behind V1 to V4, and
"PoC P1/P2" the first review's two inputs for F1 and F2.

- **Static reviews** (the maintainer's own, each by a reviewer with no part in writing the code; not a third-party audit): five reviews of the whole app, at `b88f6d8`, `39a91bc`, `53e98c4`, `ea87504` and `702e207` (every line
  of `src/` and `kadena-core/src/`, the build files and this folder), against Ledger's security-review
  checklist. The findings
  are listed below with their fixes (F1-F12 from the first review, R2-1 to R2-7 from the second, F1-F10 of the
  third, R4-1 to R4-5 of the fourth, R5-1 to R5-5 of the fifth). All were inherited from v1.3.0 except two display defects of the port's
  own Nano layout (F9 of the third review, and an extra empty page found while verifying it, R3-P) and one
  carve-out added between the third and fourth reviews and withdrawn after it (R4-1).
- **Evidence tiers.** Each claim below is marked with how it was checked:
  - *host*: `kadena-core` unit and integration tests (the whole protocol runs on the host, with a mock device);
  - *emulator*: Ragger tests of the device binary in Speculos, on all five devices;
  - *differential*: the same APDUs sent to the v1.3.0 release binaries and to this app in Speculos, every
    difference classified;
  - *mutation*: the check was removed or weakened and the named tests were run: they must fail;
  - *fuzz*: the libFuzzer target `kadena-core/fuzz` (JSON tokenizer, parser and review items);
  - *source*: read in the Pact 5 source (`kadena-io/pact-5`), not run.
  - *REPL*: the reviewer's Pact 5.4 REPL runs of coin, scored by exit code (R2-1 rotation, R2-4 account
    squatting, each with a mutant that must fail).
- **Not done:** no run of a signed transaction on a Kadena node
  (the on-chain half of F1 and F2 is from reading the Pact source; R2-1 and R2-4 from the REPL).
- **Open:** once, the Nano S+ app crashed in Speculos ("The app crashed with signal 11") while a test
  walked a blind-signing review (`test_v10_p1_blind_review_shows_the_device_entry`, build of `af4f83e`, with
  the host short of memory). It did not recur in 12 reruns of that test, in the later full suites on all five
  devices, in the 435-case differential on all five devices, or in three further runs of the review and JSON
  suites on Nano S+, nor in 37 runs by the fourth reviewer. The cause is not known: no fault in the app's code path was found by reading it, and an
  emulator fault is not ruled out.

## Findings and dispositions

| # | Severity | Issue (inherited from v1.3.0) | Fix in v2.0.0 | Evidence |
|---|---|---|---|---|
| F1 | Critical | An empty clist (`"clist": []`) was shown without any warning, though Pact reads it as a signature valid for any capability (*source*: `Signer` FromJSON `fromMaybe []`). | An empty clist is unscoped, like a missing or null one: "Unscoped Signer" and the WARNING (V10). | host, emulator, differential, mutation |
| F2 | Critical | The review showed `signers[0]` whatever its key. Pact scopes the signature by the entry keyed by the signing key (`addr` else `pubKey`), the last one if the key repeats (*source*: `mkMsgSigs`, `M.fromList`), so a host could show a harmless entry and have a hidden one used. | The review is of the one entry naming the device key (as `pubKey` or `addr`, any letter case); zero or several such entries, a non-exact `pubKey`, or JSON escapes inside signer entries are refused; the signer count is shown when above 1 (V9). | host, emulator, differential, mutation |
| F3 | High | Unscoped signatures, values too large to show, and unrecognised `meta` were signed after a warning page with blind signing OFF: the code the signature authorises is never displayed. | These JSON reviews are blind signing: refused with the "Cannot clear-sign" screen and `Blind signing mode required` unless the setting is ON, then shown after Ledger's blind-signing warning. Structured coin transfers are never blind (V11); structured token transfers are (V23). | host, emulator, differential, mutation |
| F4 | High | This file described the C app. | Rewritten for v2.0.0. | — |
| F5 | Medium | Values were drawn as UTF-8; C1 controls, NBSP and the soft hyphen (valid in Kadena account names) may draw as nothing. | Every byte outside printable ASCII is shown as `\xNN` on every device; the signed bytes do not change (V13). | host, emulator, mutation |
| F6 | Low | Structured transfers accepted empty or malformed numbers and uppercase recipients (JSON no node accepts; `k:ABC…` is another account than `k:abc…`). | Number grammar for every numeric field, non-empty chain ids, lowercase-hex recipient (V2). | host, differential, mutation |
| F7 | Low | The blind (hash) review rendered only its first batch of items. | Every review, blind or not, streams all its items. | emulator, mutation |
| F8 | Low | Review batches of up to about 3.3 KB of text could approach the 8 KiB heap. | Batches capped at about 1200 bytes; peak heap measured on every device with the largest accepted review (below). | emulator, mutation (touch devices) |
| F9 | Low | Bytes after a NUL or after the top-level JSON value were signed but never parsed or shown. | Refused (V12). | host, emulator, differential, mutation |
| F10 | Info | Overlapping mutable references to the flash store; a flash write through a pointer from a shared reference. | Shared access only (except the one settings borrow the SDK requires); flash buffers written through their `UnsafeCell` pointers. | review |
| F11 | Info | The duplicate-key check is quadratic in the keys of one object (bounded by the token cap). | Not changed. | — |
| F12 | Info | `flags = "0"` in `Cargo.toml` for every device, while the Ledger app database lists `0x200` for devices other than Nano S+. | Closed, no change: the SDK adds 0x200 itself where required. The `ledger.app_flags` section of the built ELFs reads `0` (nanos2) and `0x200` (nanox, stax, flex, apex_p), equal to the `kadena` entry in `LedgerHQ/ledger-app-database` `app-load-params-db.json`. | ELF section read at 39a91bc |

### Second review (at 39a91bc)

| # | Severity | Issue (inherited from v1.3.0) | Fix | Evidence |
|---|---|---|---|---|
| R2-1 | Critical | A signature scoped to `coin.ROTATE` was clear-signed; the new guard comes from code and data the device does not show, so a vanity account could be handed to another keyset (*REPL*). | A `coin.ROTATE` in the device's entry adds the WARNING "Account rotation: new owner not shown" and needs the "Blind signing" setting (V14). | host, emulator, differential, mutation |
| R2-2 | Warning | The fee was shown only as a raw limit and price, the paying account never. | "Max fee" (gasLimit × gasPrice in KDA, exact decimal, exponents included) and "Paying account" (`meta.sender`), for JSON and structured transfers (V15). | host, emulator, differential, mutation |
| R2-3 | Warning | Review batches were budgeted on raw bytes; non-printable values shown as `\xNN` are up to 4 times larger, and the Flex app ran out of heap. | Batches are budgeted on the fields as shown (after escaping and Nano paging, with a per-field overhead), an item that would exceed the budget waits for the next step, and Nano paging measures a fixed window instead of copying each value's rest. | emulator (all five devices, printable and non-printable), mutation |
| R2-4 | Warning | A transfer to a vanity account: coin lets it be created with a guard the review does not show (*REPL*). | A WARNING "Recipient is not a principal account" after a transfer whose receiver is not a Pact principal (V16). | host, emulator, differential, mutation |
| R2-5 | Warning | The validity window (creation time, TTL) was not shown; the device has no clock. | Expert mode shows "Created (unix time)" and "TTL (seconds)" as sent (V19). | host, emulator, differential, mutation |
| R2-6 | Info | While a capability of another module is in scope, code can use the key for `enforce-guard` checks. | First a clear-signed WARNING (V17); replaced by V20 after the third review (below): such capabilities are blind signing. | host, emulator, differential, mutation |
| R2-7 | Info | A `&'static mut` to the settings coexisted with shared references read by `settings::get`. | One raw pointer to the flash store; the settings borrow lasts only for the call that hands it to the SDK, and reads go through the same pointer. | review |

### Third review (at 53e98c4)

| # | Severity | Issue | Fix | Evidence |
|---|---|---|---|---|
| F1 | Critical | A `coin.DEBIT` capability was clear-signed (as "Unknown Capability"): while DEBIT is in scope the transaction's code can install any TRANSFER and move any amount from the account (inherited from v1.3.0; the reviewer drained 1000 KDA in the Pact 5.4 REPL and signed the body in Speculos). | V20: only `coin.GAS` and `coin.TRANSFER` / `coin.TRANSFER_XCHAIN` with all arguments shown are clear-signed; any other capability of the device's entry adds the "Capability not verified" warning, with the capability shown as separate items (H-1), and needs blind signing, on 0x22 and 0x03; structured token transfers on 0x24 and 0x10 likewise (V23, after R4-1). | host, emulator, differential, mutation |
| F2 | High | A transfer amount in exponent notation (`1.0000000001e3`) was shown as sent, reading as about 1 KDA; the node takes 1000.0000001. | V21: refused ("Unexpected characters"). | host, emulator, differential, mutation |
| F3 | Medium | V17's text said the capability's module can use the key; any code running while the capability is in scope can, including taking over accounts the key guards. | Covered by V20: no clear-signed capability of that kind remains; the docs say "any code the transaction runs". | host, emulator |
| F4 | Low | `gasLimit` with a fraction: the node rounds it, so "Max fee" could understate the charge. | V15: `gasLimit`, `ttl` and `creationTime` must be plain digits ("Unexpected characters"). | host, emulator, differential, mutation |
| F5 | Warning | A host can make the app write the transaction or template buffer to flash repeatedly without any user action (flash wear), as in v1.3.0. | Known limit, not changed: transactions over 8192 bytes and every structured-transfer template go to flash before the review. | — |
| F6 | Info | A scoped signature whose transfer does not name the key was titled "Unscoped Signer". | Titled "Key not in transfer"; "Unscoped Signer" only for an entry without capabilities. | host, emulator, differential, mutation |
| F7 | Info | The review could not tell `exec` from `cont`; `verifiers` were ignored. | Expert mode shows "Payload" (`exec` or `cont`, with pact id and step); a `verifiers` field is refused ("Unexpected value", V22). | host, emulator, differential, mutation |
| F8 | Info | An observation about Ledger's SDK, reported to Ledger separately. | Not changed. | — |
| F9 | Info | A value fitting no paged layout could make NBGL shorten a title on Nano. | The fallback puts each page in its own field, so no title is shortened; goldens hold every warning title on every device, and a test walks the same reviews and fails on any shortened text (on touch screens NBGL cuts a long value, never a title, and adds its "More" button). | emulator (goldens) |
| F10 | Info | JSON escapes in displayed values are shown raw (`mainnet\u00301`); the node decodes them. | Known limit, not changed: the backslash is visible, and escaped receivers get the V16 warning. | — |
| R3-P | Info | (Found while verifying F9 on the kb-USDC transfer review.) On Nano, a page break at a space left the space at the end of the page; NBGL drew it on a line of its own, paged the field again ("Unknown (1/2)") and showed an empty "(2/2)" page. Nothing was hidden. | A page break takes the space it breaks at, as NBGL does at every line wrap; further spaces start the next page. | emulator (Nano goldens; a test fails on the NBGL-added marker) |

### Fourth review (at ea87504)

| # | Severity | Issue | Fix | Evidence |
|---|---|---|---|---|
| R4-1 | High | A structured token transfer (0x24 / 0x10 with a namespace and module) was clear-signed: its scope `<ns>.<module>.TRANSFER` lets the module's own code use the key for any guard checked outside a capability body (Pact 5 `checkSigCaps`; a coin-style `rotate` of a vanity account the key guards), and a lookalike module in another `n_<hash>` namespace looks the same on screen (the reviewer's Pact 5.4 REPL proof). The carve-out was added after the third review (`931754b`). | V23: the review adds the "Capability not verified" warning for `<ns>.<module>.TRANSFER` (or `TRANSFER_XCHAIN`) and needs blind signing on 0x24 and 0x10; coin transfers stay clear-signed. | host, emulator, differential, mutation |
| R4-2 | High | V21 refused only exponents: `{"decimal":"1\u0030\u0030\u0030.0"}` was shown as written (reading "1...") on a clear-signed coin transfer; the node unescapes it to 1000.0. | V24: a coin transfer amount is a bare JSON number or `{"decimal":"<number>"}` (single key, string value, as @kadena/client sends it), the number `(0\|[1-9][0-9]*)(.[0-9]+)?`; the review shows the plain number. Every other shape (`{"int":...}`, strings, signs, exponents, extra keys, leading zeros, escapes) is refused ("Unexpected characters"), the same set as the C v1.3.1 patch. | host, emulator, differential, mutation |
| R4-3 | Info | An observation about Ledger's SDK, reported to Ledger separately. | Not changed. | — |
| R4-4 | Info | `exec` or `cont` is shown only in expert mode, and a `null` `networkId` (or the string `"null"`) drops "On Network"; a missing one is refused (corrected by R5-4). The node refuses both at mempool insert; the capability list still bounds the signature. | Known limit, not changed. | — |
| R4-5 | Info | A receiver written with JSON escapes (`k:\u0061...`) is shown raw and gets the V16 warning, though on chain it is that principal; the warning errs safe. | Known limit, not changed. | — |

The fourth review also re-ran the unexplained emulator crash (below, *Open*) 37 times without a recurrence,
found no memory-safety defect, and showed that a transaction buffer cannot be replaced during a review (the
SDK answers 0x6901 to any command while a review is shown).

### Fifth review (at 702e207)

No Critical or High; ready for the external audit.

| # | Severity | Issue | Fix | Evidence |
|---|---|---|---|---|
| R5-1 | Low | V24 accepted any number of fractional digits; pact-5 rounds a JSON number at 255 places, so `0.` followed by 256 nines, shown in full and clear-signed, is 1.0 on chain (1e-12 KDA more than coin allows per transfer). | V25: at most 12 fractional digits, coin's precision, in both amount forms and in coin structured transfers. | host, emulator, differential, mutation |
| R5-2 | Info | The tokenizer accepts an unquoted key, so `{decimal:"1.5"}` was clear-signed; the node rejects the command. | The decimal key must be a string token. | host, emulator, differential, mutation |
| R5-3 | Info | A structured transfer with an integer amount (`1000`) was clear-signed; Pact refuses an integer for `amount:decimal`, so it failed on chain. | V26: the structured amount needs a fractional part. | host, emulator, differential, mutation |
| R5-4 | Info (doc) | The known limit said a missing `networkId` drops "On Network"; it is refused. | Corrected (known limits, R4-4). | — |
| R5-5 | Info (tests) | Under host load the Ragger walker could read a stale screen after a settings change. | The walker waits for the review or blind-signing page and fails otherwise; the settings toggle waits for the home page. | emulator |

### First hardware run (Nano S+, OS 1.6.1, test seed)

Every step passed: application hash, version, key, address, clear signing verified, blind-signing gate ON and
OFF, warnings shown. Two display changes came out of it (signing unchanged):

| # | Issue | Fix | Evidence |
|---|---|---|---|
| H-1 | The "Capability not verified: <name>" warning (its form until then) paged a 60-character namespaced name (`n_e595…c1ff.kb-USDC.TRANSFER`) across two pages, splitting the namespace's hex: unreadable, and where a look-alike module would hide. | The capability is shown as separate items, each whole: "WARNING: Capability not verified", "Capability: <module>.<NAME>", "Namespace: <namespace>" (only when the name has one, R7-1), "Arguments" (the arguments item no longer holds the name). On Nano a value without spaces is cut into lines at the screen width, so a 42-character namespace fills one page (NBGL had put "n_" alone on a line). | host, emulator (goldens on all five devices; a test asserts on Nano S+ that the namespace and the capability each appear whole on one page) |
| H-2 | The blind-signing-required page's title, "This transaction cannot be clear-signed", was shortened on Nano. | "Cannot clear-sign" / "Enable Blind signing in Settings to sign this transaction"; "Go to settings" opens the settings page, "Reject Transaction" answers the refusal. | emulator (goldens on all five devices; both actions tested) |

### Review of the hardware-run changes (at 575868d)

GO for a test device.

| # | Severity | Issue | Fix | Evidence |
|---|---|---|---|---|
| R7-1 | Low | "Namespace: none" for a name without a namespace was ambiguous: `none` is a valid Pact namespace, so `none.coin.DEBIT` and `coin.DEBIT` looked the same. | No Namespace item when the name has no namespace (maintainer's decision): `coin.DEBIT` shows WARNING / Capability / Arguments, `none.coin.DEBIT` adds "Namespace: none". | host (both names; three items without a namespace), emulator, mutation |
| R7-2 | Info | Three or four items per unverified capability (four with a namespace): about 22 namespaced ones fit a transaction; the next is refused ("Unrecognized error code"), never cut. | Known limit, not changed. | host |
| R7-3 | Info | An empty namespace (`.coin.X`, `..`) is refused, but no named test pinned it. | Named test, Blind signing ON and OFF. | host, mutation |
| R7-4 | Info (doc) | The heap table predated the Nano line cutting. | Measured again (below). | emulator |
| R7-5 | Info (design) | For `evil.coin.TRANSFER` the Capability page reads `coin.TRANSFER` and the namespace is on the next page; the warning comes first and Blind signing is required. | Not changed. | — |
| R7-6 | Info | A non-string `name` is shown as its raw JSON (`null`, an object split at its dots); every byte is shown, Blind signing is required, and the node refuses such a name. | Known limit, not changed. | — |

### Later reviews (at eeb52e3 and 33750a1)

Two further reviews covered the changes after the fifth review and after R7-1. Neither found anything above
Info. The sixth asked for the V25 and V26 refusal tests to cover every structured transfer type and the token
form (now pinned: host test `v25_v26_amount_rules_on_every_transfer_type`, Ragger
`test_v25_r53_structured_amount_refused`), and for the CI write permissions to be narrowed (the build job no
longer has `contents: write`; Ledger's reusable build workflow itself requires the other two).

### Hardware runs of the release build (Nano S+ OS 1.6.1, Nano Gen5 / Apex P OS 1.1.1)

On both devices, with the binaries listed below: the application hash shown by the device equals the one
computed from the build; version 2.0.0 over the wire; the address shown on screen equals the key returned; a
coin transfer is clear-signed with Blind signing OFF and its signature verifies over blake2b-256 of the exact
bytes; a token transfer is refused with Blind signing OFF ("Cannot clear-sign") and signed, with the warning,
with it ON. On the Nano S+ the key equals the one the C app (v1.3.1) derives at the same path. Nano X, Stax
and Flex: emulator only.

### Review of the C v1.3.1 patch, carried into v2.0.0

| # | Severity | Issue (inherited from v1.3.0) | Fix | Evidence |
|---|---|---|---|---|
| A1-A4, A8 | Critical | Members are found by raw key bytes, while the node's decoder unescapes keys and keeps the first duplicate: an escaped `"name"` (A1, A4), `"signers"` (A2) or `"meta"` (A8), or an escaped `coin.ROTATE` name (A3), hid a transfer, a rotation or a fee (proven by the reviewer in Speculos against aeson-2.2.3.0). | Any object key with a backslash, anywhere, and a backslash in a capability name of the device's entry are refused with "Unexpected characters"; literal duplicates are refused in every object, nested ones included (V18, same rule, status words and messages as C v1.3.1 `parser_checkKeyIntegrity`). | host, emulator, differential, mutation |

The other intended differences from v1.3.0 (V1-V8: legacy 0x10 bounds, the transfer allowlist, the exact
signer match of the "Unscoped Signer" warning, duplicate JSON keys, stream rules, the path bound to the signing
command) are listed in `docs/APDUSPEC.md`.

## What was verified, and how

- **What is signed is what was parsed and shown** (*host*, *emulator*): JSON signs blake2b of the exact
  buffer that was tokenized and reviewed, and V12 leaves no byte of it outside the reviewed value; a transfer
  signs the template the device built and reviewed; a hash signs exactly the 32 bytes shown as the request key.
- **The key that signs** (*host*, *emulator*, *differential*): the path given by the signing command (V7);
  derivation `m/44'/626'/…` only, 5 components, Ed25519 via `Ed25519::derive_from_path` (HDW_NORMAL); the
  derivation of the Zemu test vector is pinned by an emulator test.
- **Streams** (*host*, *emulator*, *differential*): one command per stream (V8), any first chunk resets the
  buffer, a mixed stream never produces a signature (blind signing ON or OFF).
- **Settings** (*emulator*): "Blind signing" and "Expert mode" are OFF on install.
- **Every refusal and warning has a test that fails without it** (*mutation*): 25 mutants of the V9-V13 and
  transfer checks, 16 of the V14-V17, fee and expert-window code (15 failed their tests; the one that did not
  showed a redundant check, which was removed), 3 of the V18 key rules and 14 of the round-3 rules (V20, V21,
  integer gas fields, F6, F7; 13 failed their tests, the one that did not showed a redundant check in the
  structured-transfer allowlist, which was reverted) and 6 of V23 and V24 (the blind gate for structured
  transfers; the decimal object's key count, key name and string value, the leading-zero rule and the display
  of the plain number; all failed their tests), 4 of the fifth review's fixes (V25's 12-place bound, the
  quoted key, V26 and the name bound; all failed their tests) in `kadena-core`, and 4 of the device
  review code (F5, F7, F8, R2-3), each made its named tests fail (F8's on the touch devices; on Nano X the
  largest printable review fits the heap even without the byte cap, the item cap bounds it; R2-3's on Flex,
  the reviewer's case).
- **Heap** (*emulator*, measurement build `--features heap-probe`, not shipped): the largest review the app
  accepts (values at their display bounds, as many as the token cap or the 15104-byte buffer allows), fully
  approved, with printable values and with every From/To byte non-printable (shown as `\xNN`); peak = heap
  size minus the largest block still allocatable. Nano S+ and Flex were measured again at `38f56c4` and `71cf734` (same figures), after the
  Nano line cutting (H-1, which briefly keeps a second copy of a value without spaces): Nano S+ grew by 40 bytes
  with non-printable values, Flex did not change. Nano X, Stax and Apex P were last measured at `df65483`; Nano
  X runs the same screen code as Nano S+ and had the same figures before, so its non-printable peak is expected
  to grow the same way (not measured); Stax and Apex P run the touch code Flex runs:

  | device | heap (bytes) | peak in use, printable (bytes) | peak in use, non-printable (bytes) |
  |---|---|---|---|
  | Nano S+ (`71cf734`) | 8192 | 3400 | 5884 |
  | Nano X (`df65483`) | 8192 | 3400 | 5844 |
  | Stax (`df65483`) | 8192 | 2796 | 4156 |
  | Flex (`71cf734`) | 8192 | 2796 | 4156 |
  | Apex P (`df65483`) | 8192 | 2796 | 4156 |

- **Differential** (*differential*): 486 cases, 1603 APDUs per device, all five devices; every difference
  from v1.3.0 is one of V1-V26 or the version bytes (`tools/differential/report.md`). Run with the release ELFs
  below (`71cf734`), after the first hardware run's display changes (H-1, H-2) and R7-1.
- **Refusal tests check the whole reply** (*emulator*): every Ragger test of a refusal compares the status
  word and the response data together, so a refusal that has a message is checked word for word, and a bare
  one (legacy commands) is checked to carry none.
- **Fuzzing** (*fuzz*, seeds from the C UI vectors and the differential corpus): at `702e207`, 2,288,432
  executions without debug assertions (as on the device, 7 minutes) and 1,939,488 with them (about 9 minutes
  in two runs). With debug assertions, one input stopped on a `debug_assert_eq!` in `render_unknown`
  (`items.rs`): a capability name of 293 to 299 bytes made "name: <name>, " longer than the 300-byte value
  buffer, which the writer cut while the assertion expected the full length (a release build refused the
  transaction one check later; the writer clamps every write). Fixed at `e728f64`: such a name is refused at
  once; the input is a regression test and a seed. Then 1,113,247 executions with debug assertions (7
  minutes), and 1,629,046 (5 minutes) after the H-1 change to the capability items: no crash.
- **Where the emulator runs:** every emulator result here is from local runs in the pinned dev-tools image. In CI
  the Ragger tests run on the default runner of Ledger's reusable workflow (the dev-tools image refuses the
  workflow's pip install).
- **Build** : `cargo fmt --check`, `cargo clippy -D warnings` on all five targets and the core, Ledger's
  guidelines enforcer, and a rebuild from a fresh clone giving byte-identical ELFs.

### Release binaries (v2.0.0, `cargo ledger build`, pinned `ledger-app-dev-tools` image)

| device | ELF sha256 |
|---|---|
| Nano S+ | `9a10952d2b370371786843fca54a728b8f4658452bf9a3ac6f4601c42ba9239f` |
| Nano X | `d079e5ee94536cd7bd4f161d547bb36648b1ebfa26933c46ad769dce3de95b2a` |
| Stax | `d429ca200c191f6765741f3bde9324530223beb49ed5862b9889c64bb76ee896` |
| Flex | `765cefd84c52e80c9fff035781bffdcd205ccf17c9578512f5daa936994ec6cb` |
| Apex P | `05c44b40d92e225327fa11e304f205411aa4a7999bb99253162cfe020ddf58d6` |

## Known limits

Left as they are, with the reason in the finding's row:

- Flash wear: a host can make the app write its buffers to flash without any user action (third review F5).
- JSON escapes in shown values are displayed raw; an escaped receiver gets the V16 warning although it is a
  principal on chain (third review F10, fourth review R4-5). Both err toward showing more, not less.
- `exec` or `cont` is shown only in expert mode. A missing `networkId` is refused; a `null` one, or the
  string `"null"`, drops "On Network" (likewise `"chainId":"null"` drops "On Chain"). The node refuses such a
  command at mempool insert (network and chain id must equal its own), and the capability list still bounds
  the signature (fourth review R4-4, corrected by the fifth review R5-4).

Two observations about Ledger's SDK (third review F8, fourth review R4-3; neither has a known failing path in
this app) are being reported to Ledger and are not described here.

## Note on the submission audit

Ledger requires a functional and security audit by one of its approved partners before listing. This
document is the applicant's own review, the starting point for that audit; it does not replace it.
