# Kadena Ledger app — security review (v1.3.0 + v1.3.1 and v1.3.2 patches, API_LEVEL 26)

**Scope:** the **entire** signing, derivation, transaction-parsing, display-formatting and APDU
surface of the app, reviewed adversarially under the assumption of a fully malicious host. This is a
whole-app review, not a diff-vs-previous-release review. It supersedes the v1.2.1 diff review.

**Method:** independent cold-context review (no implementation history) over `crypto.c`,
`crypto_helper.c`, `addr.c`, `apdu_handler.c`, `apdu_handler_legacy.c`, `common/tx.c`,
`common/actions.c`, `parser.c`, `parser_impl.c`, `json/json_parser.c`, `jsmn/jsmn.c`, `items.c`,
`items_format.c`, and the derivation/signing/approval flow; every high-severity finding independently
re-verified by an adversarial skeptic; the fixed tree re-audited cold twice; overflow and
fail-closed behaviours proven against the emulator; the derivation vector proven on hardware.

## Findings and dispositions

All findings are **fixed** in v1.3.0. The two HIGH memory-corruption defects marked *(new)* are
pre-existing upstream defects surfaced only by holding the whole app — not just the last diff — to
submission standard; they are the security substance of this release.

| # | Severity | Location | Issue | Fix |
|---|---|---|---|---|
| 1 *(new)* | High | `apdu_handler_legacy.c` `legacy_extractHDPath` | A host-controlled path-component count drove a `MEMCPY` into the fixed 20-byte `hdPath` global (up to a 232-byte out-of-bounds write into adjacent memory), before the network sanity check. | Reject any count other than the fixed Kadena path length (5) before the copy; require the real received length to cover the path bytes on every legacy entry point. |
| 2 *(new)* | High | `common/tx.c` `tx_json_initialize` (+ `parser_impl.c`) | The 1 KB structured-transfer template buffer was registered with a ~15× larger capacity, so a maximum-size cross-chain transfer (~1.2 KB) wrote past it into persistent storage, pre-approval. | Register the buffer with its real size; size it to hold the largest valid template; check every append so an over-cap input aborts cleanly instead of truncating the signed bytes. |
| 3 | High | `items.c` `items_storeTxItem`/`…CrossItem`/`…RotateItem` | Three wrong-argument-count branches ignored a "too many items" return and could drive the item count one past the end of the display function-pointer array, which is invoked during pre-approval validation. | Propagate the error at all three sites; guard the loop index against the maximum. |
| 4 | Med | `apdu_handler_legacy.c` `legacy_process_existing_transfer` / init path | Transfer-continuation and init reads used a host-set / fabricated length not bounded by the received APDU length → read of stale buffer memory that would be signed. | Thread the real received length through and bound every read against it. |
| 5 | Med | `items_format.c` unknown-capability arg loop | Arguments were printed with `%s` over a non-NUL-terminated buffer → read past the token (displayed ≠ signed). | Explicit-precision `%.*s` bounded by the token length. |
| 6 | Med | `items_format.c` `items_gasToDisplayString` | Gas-value length stored in a `uint8_t` wrapped modulo 256 → a long value displayed short while the full value was signed. | Widen to `uint16_t`; oversized values now reject. |
| 7 | Low ×several | `apdu_handler_legacy.c`, `parser_impl.c`, `json/json_parser.c`, `items_format.c`, `crypto.c` | Assorted one-past-end reads, an unvalidated transfer type, a namespace/module display buffer one byte short, a hash-length defense gap, and unchecked accessor returns. | Bounds and validation added at each site; all fail closed. |
| — | Info | `items_format.c` hash display | The transaction hash is shown as the unpadded base64url request key (43 chars), matching the on-chain request key; documented, not changed. |

## Clean items confirmed by the auditor (verified sound)

- Derivation locked to `m/44'/626'` with a fixed 5-component path; no other curve/path accepted.
- Key material zeroized on every exit path; never present in APDU responses or logs; the public-key
  cache cannot serve a stale key for a different path.
- `displayed == signed` on all three signing instructions; the signed buffer is the buffer the
  display items were parsed from.
- No signature is produced without the on-device approval callback; blind-signing is gated behind a
  setting distinct from expert mode; APDU chunk reassembly is bounded.

## Verification

- **Emulator (Zemu, all 5 device models):** full matrix green on the fixed build, including new
  regression cases for the item-array bound (fail closed), the maximum-size cross-chain template
  (signs), the gas-length and unknown-capability display fixes, and a full principal-namespace
  transfer. Zero crashes.
- **Deterministic builds:** all five targets build byte-identically across independent runs.
- **Re-audit:** the fixed tree was re-audited cold twice; **zero open CRIT/HIGH**; the follow-up
  fixes were verified against a byte-exact differential model of the legacy state machine over ~950
  client-realistic transfers with zero regressions.
- **Hardware (Nano S+, test seed):** the release build installs, the on-device application hash
  matches the released build, and the derivation vector matches the emulator/upstream vector.

### Deterministic device hashes (v1.3.0)

| Target | Application hash |
|---|---|
| nanos2 | `068f376be6115e1769952fabb61020ae5070867c9b2299c259f6947c5b5ce1db` |
| nanox | `dc28a5786a81c2162725eb89dac3433066c37af3b4c7621177c66c4bad32127c` |
| stax | `592296023a6098959ff4f3e00889a6fb64c7dcc4a8fab44f367e89a77c9302e0` |
| flex | `d03d46f36b11d267de05b6f2aba60f6d798faabc1d0970afbe13dec138b1fca3` |
| apex_p | `4484159eabe9f65ffa83aaedd7eeb1a3aab3decbaa7cc34988a4bbde5fd535e5` |

## v1.3.1 — signing-policy patch (2026-09-29)

v1.3.0 closed the memory-corruption class. v1.3.1 closes thirteen **signing-integrity** gaps: because
the app builds or displays the transaction it signs, it must itself decide which transactions it
will sign, and these decisions were missing or incomplete. Each is a defect inherited from the
upstream design. S1-S11, S13 and S14 were confirmed against the released v1.3.0 binaries in the emulator
and each is fixed with a named test that fails on v1.3.0 and passes on v1.3.1; S12's consequence is
established by reading the code; its fix is pinned by named tests listed under Verification (each
says which removal it catches), and the approval handlers' own lines are reviewed by reading. The only wire-visible change is S12's 0x6986 refusal while a signing review
is pending.

| # | Severity | Location | Issue | Fix |
|---|---|---|---|---|
| S1 | High | `apdu_handler_legacy.c` `legacy_process_transfer_chunk` | A legacy transfer item (including the last, the undisplayed `ttl`) could claim more bytes than were received; the device appended stale APDU-buffer bytes and signed them. | Refuse any item whose bytes are not all within the received length (0x6700). |
| S2 | High | `apdu_handler_legacy.c` `legacy_handle_overflow` | An item was split across packets by copying to the 235-byte boundary even on a short packet, reading past the received length. | Allow a split only at a full 235-byte packet (0x6700 otherwise). |
| S3 | High | `parser_impl.c` `parser_createJsonTemplate` | Structured-transfer fields were pasted into the signed JSON with only length checks; a quote/backslash could inject JSON (e.g. a hidden key via the nonce). | Per-field content allowlist before the template is built (hex recipient, well-formed numbers, identifier namespace/module, printable nonce without `"`/`\`); violation → 0x6984. |
| S4 | Med | `parser_impl.c` `parser_findPubKeyInClist` | The signer/sender match compared only the key's length, so an argument that started with the key (a different, longer account) suppressed the "Unscoped Signer" warning. | Exact-length match after an optional `k:`. |
| S5 | High | `parser_impl.c` `parser_getValidClist` | An empty `clist` (`[]`) was treated as scoped, but Pact reads it as unscoped (valid for any capability). | Treat missing, `null` and empty alike → "Unscoped Signer" + WARNING. |
| S6 | Critical | `items.c` / `parser_impl.c` `parser_findDeviceSigner` | The review used `signers[0]`, not the entry for the key the device signs with, so a host could display one entry while the device's real (last-wins) scope sat in another, or repeat the device key with the wider scope hidden. | Derive the device key for the signing path, review the one entry naming it (`pubKey` or `addr`, any case); refuse zero or more than one (0x6984); refuse escaped signer keys; show "Signers: N". |
| S7 | Critical (vanity accounts) | `items.c` / `parser.c` | A `coin.ROTATE`-scoped signature was clear-signed although the new account owner comes from undisplayed code and data. | Show a "new owner not shown" warning and require the Blind signing setting, as hash signing does. |
| S8 | Critical | `parser_impl.c` `parser_checkKeyIntegrity`, `parser_findDeviceSigner` | The device looked up members by raw key bytes while the network decodes key escapes before its duplicate-key rule: an escaped key (`n\u0061me`, `sign\u0065rs`, `m\u0065ta`) beside the literal one hid a transfer, a signer list, a rotation or a fee behind a clean review; an escaped capability name (`coin.\u0052OTATE`) hid a rotation. Found by an independent cold review of the first v1.3.1 candidate. | Refuse any object key containing an escape (whole document), any escape in a capability name of the device's entry, and any literal duplicate key within one object (0x6984). |
| S10 | Critical | `items.c` `items_storeUnknownItem`, `parser.c` `parser_validate` | In host-built JSON (0x22, legacy 0x03), any capability in the device's entry other than GAS / TRANSFER / TRANSFER_XCHAIN / ROTATE was clear-signed as a name and argument list. A scoped `coin.DEBIT` lets the undisplayed code install any TRANSFER and move the whole balance (proved in the Pact 5 REPL by the Rust-port review; v1.3.0 clear-signs it in the emulator). Found by an independent static review of the Rust port (F1), which inherited the design. | In host-built JSON such a capability (a token module's TRANSFER included) requires the Blind signing setting (refused "Blind signing mode required", 0x6984, when off) and adds "WARNING: Capability not verified: <name>" to the review. Structured transfers (0x24, legacy 0x10) stay clear-signed; for a token there, see S13. |
| S11 | High | `items.c` `items_checkAmountForm`, `parser.c` `parser_validate` | A TRANSFER / TRANSFER_XCHAIN amount in exponent notation (`1.0000000001e3`, `{"decimal":"1e3"}`) was shown raw, while pact-5 reads a JSON number through `fromRational` and the object form through Data.Decimal's reader, both exact and exponent-aware: a 1000 KDA cap read as about 1 KDA (Rust-port review F2). | Refused: an exponent in either amount form is outside the S14 grammar, which `items_checkAmountForm` now enforces ("Unexpected characters", 0x6984; bare on 0x03). The structured-transfer amount field admits plain decimals only (S3). |
| S12 | Critical (pre-existing in v1.3.0; consequence by code reading) | `apdu_handler.c` `handleApdu`, `review_lock.c`, `common/actions.h` `app_sign`, `apdu_handler_legacy.c`, `crypto.c` `crypto_sign`, `items.c` | The app answered commands while a signing review waited for approval, and approval re-hashed the live transaction buffers, so a command arriving behind the review could change the bytes or the derivation path that approval signs. Found by the third independent review of v1.3.1 (R3-1). | While a signing review is pending, every INS but GET_VERSION is refused with 0x6986 before any handler runs; approval signs the digest computed at parse time and bound to the review. Limitation: a USB power loss during a review leaves the lock set (signing refused, fail-closed) until the app is reopened. |
| S13 | High | `items.c` `items_storeUnknownItem` | A structured transfer (0x24, legacy 0x10) of a token other than `coin` was clear-signed with no warning, although the token module's code can use the device key for anything it guards while its TRANSFER capability is held (shown in the Pact 5 REPL by the third review, R3-2, and for vanity-account rotation by the Rust port's round-4 review), and a look-alike module in another namespace reads the same on screen. | Such a transfer needs the Blind signing setting: refused with it off ("Blind signing mode required", 0x6984; bare on 0x10), reviewed with "WARNING: Capability not verified: <ns>.<module>.TRANSFER" (or TRANSFER_XCHAIN) with it on. A plain `coin` transfer stays clear-signed with no warning. |
| S14 | Med | `items.c` `items_checkAmountForm`, `parser.c` `parser_validate` | A TRANSFER / TRANSFER_XCHAIN amount in host JSON written as a string, an object (`{"decimal":"1000.0"}`, `{"int":1000}`), with a sign or a trailing dot was shown raw: a small screen truncates it (`KDA {"deci…`), and several forms read as a different decimal on the network (Rust port round-4 review). | Accept two forms only: a bare number, or `{"decimal":"<text>"}` with that single key (the `@kadena/client` form; R4-1); the number or text must be `digits('.' digits)?` with no leading zero, and the review shows the plain number. Anything else is refused ("Unexpected characters", 0x6984; bare on 0x03). This subsumes S11. |

S9 is not a separate defect: it is the requirement that S8 carry named tests that fail on v1.3.0.

Out of scope for this patch: stream path binding, INS mixing rules, non-ASCII display escaping,
trailing-byte refusal and routing every unscoped signature through blind signing, all closed by
v1.3.2 (S15 to S22 below); fee/payer display and recipient warnings, which ship with the Rust
rewrite, v2.0.0. v1.3.1 does refuse every escaped object key and every literal
duplicate key (S8); in host-built JSON every capability other than GAS / TRANSFER /
TRANSFER_XCHAIN goes through blind signing (S7, S10), and so does a structured transfer of a token
other than `coin`, with the capability-not-verified warning (S13). Non-`coin` capability warnings are
therefore no longer deferred; S12's lock covers a pending review only (INS mixing before it is S15).

Known and accepted limits in v1.3.1 (found by the fifth independent review, R5-1 and R5-2): an
amount with more than 255 decimal places is accepted and shown in full (over several pages). As a
bare number, Pact rounds it to 255 places; in the `{"decimal":"…"}` form, Pact's decimal reader
rejects it and the argument decodes as an object, so the TRANSFER capability it names matches no
transfer. No value is at risk in either case. v1.3.2 bounds the fraction digits (S20).

### Verification (v1.3.1)

- **Emulator (Zemu, all 5 device models):** a new functional suite proves each of S1-S11, S13 and S14 is refused
  or warns; every case fails on the released v1.3.0 ELFs, because v1.3.0 reaches a normal review or
  accepts the input, and passes on the patch (five pinned shapes that v1.3.0 already refused are
  labelled in the suite). The existing
  matrix (standard / transactions / legacy / negative) and the C++ unit tests (with new positive
  and negative review vectors for S4-S11, including the escaped-key attacks A1-A4 and A8, a literal
  duplicate, the `coin.DEBIT` drain, `coin.CREDIT`, a non-`coin` capability and exponent amounts,
  each refused with the fix and reviewed and signed without it) pass. Snapshots regenerated only where the shown key or the
  version string changed, and for the token structured transfers, which now run with Blind signing
  on and show the S13 warning;
  the unknown-capability render snapshots are removed, since that JSON transaction is now refused
  with Blind signing off (S10). Every refusal asserts the exact message on the commands that carry
  one (0x22, 0x24) and the bare status word on the legacy ones.
- **S12 (C++ unit tests):** `tests/review_lock.cpp` checks that `review_lock_allows` refuses every
  INS but GET_VERSION while a review is pending and none after it ends (fails if the pending flag is
  ignored), and that `review_lock_digest`, the function approval calls, returns the reviewed
  transaction's digest after the buffer holds another parsed transaction (fails if approval
  re-hashes the buffer). `tests/review_digest.cpp` checks that the digest is recorded at parse time
  and bound to the review (fails if it is not). No unit test reaches the dispatcher's call to
  `review_lock_allows` in `apdu_handler.c`; the Zemu test below fails if that call is removed. The
  approval handlers' own lines (`app_sign`, `legacy_app_sign*`) are reviewed by reading.
- **S12 (Zemu, all 5 device models):** during a pending review over 0x22, 0x03, 0x24 and 0x10 the
  device answers GET_VERSION (9000), refuses a new signing APDU with a bare 0x6986, and keeps the
  review on screen; after approval the lock is released and the same transaction signs byte for
  byte as an undisturbed review. The emulator leaves no request to receive the signature of the
  interleaved session itself, so that this approval signs the bound digest rests on the unit test
  of `review_lock_digest` above.
- **Deterministic builds:** all five targets build byte-identically across two clean runs.

### Deterministic device hashes (v1.3.1)

| Target | Application hash |
|---|---|
| nanos2 | `726078b6269fdb4ef9a70e28c66d7a00ef9f94a0f4a5c7adac11f95fc3cd814a` |
| nanox | `71a2627800a353216a8901e7d4a991ae0cc37941917a2a7e4762d2d28f07e318` |
| stax | `9bd17293b0d8c986343bc6a103440c7eabfede044c9157f2e433b914a2a1e29b` |
| flex | `9db8b6cdfc97cee019bbfc755d0ca25435af3130f463f15c7ba11279169eb3df` |
| apex_p | `5fbf36d1f9639ac508b5d32c1fb6585ce552c3c893e2258b9b43c8901adc0a1c` |

## v1.3.2 — signing-policy patch (2026-10-04)

v1.3.2 closes the gaps v1.3.1 left out of scope, with the same accept/refuse set, status words and
messages as the Rust rewrite for each of S15 to S23. S24 is specific to this app's touch-screen review
(the Rust app streams its review in batches and keeps no total). Each is fixed with named tests that fail against the
released v1.3.1 (its binaries in the emulator, its code in the unit tests) and pass on v1.3.2. No
new review item or screen layout is introduced; the fee/payer items and the recipient warning stay
with v2.0.0.

| # | Severity | Location | Issue | Fix |
|---|---|---|---|---|
| S15 | Med | `apdu_handler.c` `process_chunk`, `apdu_handler_legacy.c` `legacy_process_chunk` / `legacy_process_transfer_chunk` | The modern and legacy signing commands each kept their own "command in progress" flag, and the buffer was parsed by the INS of the last APDU: a JSON transaction sent under 0x22 could be finished with 0x23 and signed as a raw hash, and legacy and modern APDUs could be mixed into one buffer. | One stream for both families: every APDU of a stream must carry the INS of its first APDU, else 0x6987 and the stream is closed; a modern middle/last APDU with no open stream of its INS is refused (0x6987); a modern first APDU closes any open stream. |
| S16 | Low | `apdu_handler.c`, `apdu_handler_legacy.c`, `crypto.c` (`hdPath`) | Every command shared one derivation path, so an address command (0x21, legacy 0x01/0x02) between a signing command's APDUs changed the key that signed. The review then showed that key, so screen and signature agreed, but the signing command's own path was ignored. | The path is kept when the signing command gives it and restored before the transaction is parsed and signed. |
| S17 | Med | `parser_impl.c` `_read_json_tx` | The JSON reader stopped at a NUL byte and after the first value, but the whole buffer was signed: bytes after a NUL or after the transaction were signed without being parsed or shown. | A NUL byte anywhere: "Unexpected characters"; anything but whitespace after the value: "Unexpected unparsed bytes" (0x6984; bare on 0x03). |
| S18 | High | `items.c` `items_blindSignRequired`, `parser.c` `parser_validate` | A JSON transaction whose device signer entry has no capability list (missing, `null`, `[]`), or whose `meta` the device does not recognise, was signed with the Blind signing setting off, after a warning, although no capability list on screen bounds the signature. | Blind signing required ("Blind signing mode required", 0x6984, on 0x03 too); with it on, the same items as before, opened by the blind-signing warning and closed by the accept-risk approval. A review with the "too large to display" warning needs it too. |
| S19 | Med | `parser.c` `parser_getItem` | Displayed values were shown raw: C1 controls, a no-break space or a soft hyphen in an account name could be drawn as nothing or as a space, so two accounts could look alike. | Every byte outside printable ASCII is shown as `\xNN`; the signed bytes are unchanged. |
| S20 | Low | `items.c` `items_isPlainDecimal`, `parser_impl.c` `field_allowed` | A transfer amount with more than 12 fractional digits (coin's precision) was accepted, though the network rounds a longer number (the R5-1 limit above); a structured-transfer amount without a fractional part was accepted, though Pact refuses an integer for `amount:decimal` and the transfer fails on chain. | At most 12 fractional digits for a `coin.TRANSFER` / `coin.TRANSFER_XCHAIN` amount (both forms, and a structured `coin` transfer); a structured amount must have a fractional part. "Unexpected characters" (0x6984; bare on the legacy commands). |
| S21 | Med | `parser_impl.c` `parser_findDeviceSigner` | A `verifiers` field (Pact 5 signature verifiers, which can grant capabilities) was ignored and not shown. | Refused: "Unexpected value" (0x6984; bare on 0x03). |
| S22 | Low | `items.c` `items_checkIntegerMeta`, `parser.c` `parser_validate` | `gasLimit`, `ttl` and `creationTime` were accepted with a fraction, an exponent or as strings; the network reads them as integers. | In a recognised `meta` they must be plain digits: "Unexpected characters" (0x6984; bare on 0x03). |
| S23 | Low | `parser_impl.c` `parser_validateMetaField` | `meta` was recognised only with its keys in one fixed order, although every value is read by name; the order `@kadena/client` writes was shown with the CAUTION, which S18 turns into a Blind-signing requirement. | Keys accepted in any order, each once, no other key, same presence rule (see below). |
| S24 | High (Stax, Flex, Apex P) | `parser.c` `parser_validate` | The touch-screen review shows every page of every item as one pair and counts the pairs in 8 bits (zxlib `view_nbgl.c`; NBGL `nbPairs`), and the SDK then counts the review's screens in 8 bits (`nbgl_use_case.c` `useCaseReview`: a first page, the pair screens of one pair or more each, a last page). Past either count the review wraps: it ends early and items never shown are signed. In v1.3.1 this was already reachable on Apex P in a blind-signing review (46 unverified capabilities with 274-character names: 282 pairs; the released v1.3.1 binary announced 26 screens, showed 4 of the 46 capabilities and neither "On Chain" nor "Using Gas", and signed all 13960 bytes). S19's `\xNN` escaping, where a value fills up to 8 pages on Stax and Flex and 9 on Apex P, made it reachable in a clear-signed review on all three (22 transfers: 403 pairs on Stax, 8 of 22 receivers shown). Found by an independent review of this patch. | Validation renders every item at the device's value page size and refuses a review of more than 253 pairs ("Value out of range", 0x6984; bare on 0x03), whatever the settings: at one pair per screen 253 pairs are 255 screens, the most either count holds. The Nano review walks one item at a time; no such total exists there. |

The `decimal` key of the amount object form must be a quoted string; v1.3.1 already refused an
unquoted key, and a unit vector now pins it. A "too large to display" warning (S18) only follows an
unverified capability in this app, which already needed Blind signing (S10), so that part of S18
changes no outcome today; it keeps the rule for any later item that sets it.

**`meta` key order (S23).** The inherited `parser_validateMetaField` (`parser_impl.c`) recognised
`meta` only with its keys in the order `creationTime`, `ttl`, `gasLimit`, `chainId`, `gasPrice`,
`sender`, although every value the review shows or checks (chain, gas limit and price, the
integer checks of S22) is read by its key name. `@kadena/client` (1.18.3) writes `gasLimit`,
`gasPrice`, `sender`, `ttl`, `creationTime`, `chainId`, so under S18 its plain coin transfers
would have needed Blind signing. The keys are now accepted in any order, each once, with no other
key, and with the presence rule unchanged: a key is accepted only with every key before it in that
list, so a reviewed transaction carries `creationTime`, `ttl`, `gasLimit`, `chainId` and
`gasPrice` (`sender` optional), and any set of keys gives the outcome its canonical order gave
before. Pinned by the literal `@kadena/client` 1.18.3 output (unit vector and Zemu test,
clear-signed with Blind signing off; both fail without the change) and by permutations with an
unknown or a seventh key, which still need Blind signing.

### Verification (v1.3.2)

- **C++ unit tests:** 335 pass on v1.3.2. Built against the v1.3.1 sources, 43 of the new vectors
  (each run with and without expert mode) and three of the four NUL-byte tests fail; the rest are
  controls with the same outcome in both versions.
  - S15 to S22: refusal vectors with their exact message, and controls still reviewed (whitespace
    after the value, 12-place amounts). The unquoted-`decimal`-key vector pins a refusal v1.3.1
    already made. The five existing vectors for an unscoped signer or an unrecognised `meta` run
    with Blind signing on, each with a copy refused with it off.
  - S23: the literal `@kadena/client` 1.18.3 coin transfer, the library's key order and a permuted
    order are clear-signed with Blind signing off; the keys of a four-key canonical prefix in
    another order are refused as that prefix is; permutations with an unknown seventh key, an
    unknown key in place of `sender`, or without `creationTime` and `ttl` need Blind signing.
    Further vectors pin outcomes that did not change (a 40-byte key, a superstring and a prefix of
    a key, `null` and missing `meta`: CAUTION; empty, number and array `meta`: refused).
  - S24, at the host's 144-character page (Apex P, the smallest touch page): 252 and 253 pairs are
    reviewed, 254, 267 and the 282 pairs of 46 unverified capabilities are refused; on the host, expert
    mode adds one pair (a device adds two: the transaction hash and the signing address), so the 253-pair vector is refused there and the 252-pair one is reviewed. With the
    bound changed to 254 or to 252, or `>` to `>=`, two of these vectors fail each time.
  - An over-long quoted `gasLimit` is refused for its form ("Unexpected characters"), as in the Rust
    app.
- **Emulator (Zemu):** the full matrix passes on v1.3.2: standard 30, negative 20, transactions
  50, legacy 140, security 224, review lock 20. Each refusal asserts the status word and, over
  0x22 and 0x24, the message.
  - S15 to S22, all five models, 12 tests per model: stream mixing (every pair of modern signing
    commands, both ways between the families, and between legacy commands); the signing path after
    an address command for another path, over 0x22, 0x24 and a two-APDU 0x10; trailing bytes and
    NUL; unbounded signatures with Blind signing off over 0x22 and 0x03; the escaped account name
    (snapshots of every model checked by eye); amount precision and the structured amount form
    over 0x22, 0x03, 0x24 and 0x10; verifiers and integer gas fields; and controls that still sign
    (whitespace after the value, a 12-place amount, an unrecognised `meta` with Blind signing on).
    Against the v1.3.1 binaries the 45 refusal, path and display tests fail on every model; a few
    single shapes inside them are refused by v1.3.1 too, for another reason that a bare status
    word cannot tell apart (a NUL inside a value and a second transaction over 0x03, a token amount
    without a fraction over 0x10).
  - S23, all five models: the literal `@kadena/client` 1.18.3 coin transfer is clear-signed with
    Blind signing off (no CAUTION, signature verified; without the change the device shows the
    blind-signing refusal), and the canonical order still clear-signs over 0x22 and 0x03.
  - S24, Stax, Flex and Apex P: a blind-signing review of exactly 253 pairs, with the network,
    every amount and every page of every account filling a page (233, 236 and 237 screens), is
    walked to its last screen and signed, with every receiver, the unverified capability, "On
    Chain" and "Using Gas" shown; a review of 254 pairs and one of 22 transfers (403 pairs on
    Stax) are refused over 0x22 ("Value out of range") and 0x03, with Blind signing off and on.
    With the bound changed to 254 the 254-pair test fails on all three models (the device shows a
    review).
- **Snapshots** changed only where the screens did: the escaped account name (new), the version
  page (1.3.2), the app icon (in every changed image the differing pixels lie within the icon's
  box), and the five legacy chunk-boundary fixtures whose shortened `meta` is not recognised,
  which now run with Blind signing on; their review screens are byte-identical and only the
  blind-signing warning and the "accept risk" approval are added.
- **Deterministic builds:** all five targets build byte-identically across two clean runs, and the
  binaries built from the release commit are the ones the emulator suites ran on.

### Known limit (v1.3.2)

On Stax, Flex and Apex P a transfer's or an unknown capability's title can show a wrong number (the
only transfer titled "Transfer 2"), because the number follows the order in which the screen
library asks for pages; only the title is affected, never the values shown under it.

### Deterministic device hashes (v1.3.2)

| Target | Application hash |
|---|---|
| nanos2 | `0f6f62ceb5f9b841fbd1b2253a9d14c221000d8da2aeb733c4d70ee30888ccc6` |
| nanox | `61184da40282cc0843cad4b626e73a6c437531285932407c55e3824527d398c0` |
| stax | `895bd8e3989ac5d4d4ef5cf50d395918499b70155816b21fbfc36c60e9f37441` |
| flex | `e34526905e8bd26e50f915113876d1d5931c088a8894915586c1aa605c43d89a` |
| apex_p | `aec869f487aa033d670fde696b254ab640cd68a8233e0cbd01ec5ef1fe1218b8` |

## Note on submission audit

Ledger requires a functional + security audit by one of its approved partners before My-Ledger
listing, at the applicant's expense. This document is the applicant-side security substance to hand
the partner auditor as the starting point; it is **not** a substitute for the Ledger-partner audit.
