# Changelog

All notable changes to the Kadena Ledger app (this maintained continuation) are documented here.

## [1.3.4] — 2026-10-06

Built for Ledger OS API level 27 (Nano S+ 1.7.0, Nano X 2.8.0, Stax 1.11.0, Flex 1.7.0, Apex P
1.2.0); no functional change; devices on the previous OS keep using v1.3.3.

### Changed

- Built with Ledger's builder image
  `ghcr.io/ledgerhq/ledger-app-builder/ledger-app-builder@sha256:8a2f13fa687795c6e7548197c94e2e31b15b28523a6e190a129fdd15eaa03660`,
  which ships ledger-secure-sdk v27.1.1 (API level 27) for all five devices. v1.3.3 and earlier
  were built with `ghcr.io/ledgerhq/ledger-app-builder/ledger-app-builder@sha256:036d9fd1a264a068ea20f2d0edc962ecdbf1bf5861ef75215924abd77f93bf29`
  (SDK v26.5.0, API level 26), which remains the image for OS 1.6.x devices.
- The app code is that of v1.3.3; only the version number changes, and the version page reads
  1.3.4. The install parameters are those of v1.3.3 except the API level.
- One wire-visible difference comes from the SDK: from API level 27 it answers any command that
  arrives while a previous one still awaits its reply with a bare `0x6901`, before the app sees
  it. While a signing review waits, GET_VERSION and signing commands therefore get `0x6901` where
  v1.3.3 answered GET_VERSION and refused the rest with `0x6986`. Nothing more is accepted.

### Testing

- v1.3.3's code built with the new image reproduces, byte for byte on all five devices, the
  API-level-27 binaries that the public CI built from the v1.3.3 release commit.
- The unit suite and the full Zemu matrix pass on the API-level-27 binaries, all five models.
  Only the version-page snapshots change (1.3.4). The review-lock test expects `0x6901` for both
  interleaved commands on an API level 27 binary, and now also checks that the approved signature
  of the interrupted review equals the undisturbed one. The emulator image the Zemu package pins
  supports API levels up to 26 and cannot start these binaries, so this run used Speculos v0.27.1,
  which supports API level 27 (Ledger's image `ghcr.io/ledgerhq/speculos@sha256:028d1e368244631578537e7ca50b6f13ca2932b5f3fd220627289b559c07a886`).
- Not yet run on a device.

### Device hashes (deterministic)

| Target | Application hash |
|---|---|
| nanos2 (Nano S+) | `03b75bacb5f651c27c27adcc4be525c4bc9f554797a39555ee7dbdc2f69d9d85` |
| nanox | `5df77b865b44515a4e82c9c2bf3d7a5a94e2d72dcdb8ff8a69de94ba3fb3165b` |
| stax | `8b972b021bce9ab56a37316a85981744aba412492c194a9f140b834d5e500073` |
| flex | `60865900d494673d0ed9d8ef783e1796f3214a969e2f8453dd356668f02c6b2d` |
| apex_p | `1214d54bba95467395c939840d4379225454920ff937e828371e96e397ed7cee` |

## [1.3.3] — 2026-10-06

Static-analysis fixes, no functional change. Clang 21's analyser and clang-tidy reported three
findings in the 1.3.2 code; none is reachable by any input, and the device accepts, refuses and
shows exactly what 1.3.2 does.

### Fixed

- The JSON reader refuses an empty buffer before scanning it, instead of testing the pointer only
  inside the NUL check. The caller already refuses an empty buffer first (`parser_init_context`),
  so no input reaches the new branch; the analyser could not see that and reported a null
  dereference in the trailing-bytes check.
- Two integer literals in the `meta` key check are written `1U` instead of `1u`.
- The version page reads 1.3.3.

### Testing

- The full unit suite and the full Zemu matrix on all five models pass unchanged, except the
  snapshots of the version page, which now show 1.3.3.

### Device hashes (deterministic)

| Target | Application hash |
|---|---|
| nanos2 (Nano S+) | `5de2186976638313a881faabe09bbf462df9ef8c5fae9451fa22b1a99d0efed4` |
| nanox | `49ff0568570a03e6fbb944cb689ada76d1248f6c585dc0b00a396b2a97d2ec6f` |
| stax | `53117d4b9e0fd38e3bfb0fd2cafbee56c7dac1b4611eb41ed42f94375379fadb` |
| flex | `599f7494a233b33a21a1bd4eeb66861c7adbde508d62aef057d3fa5aa95900ec` |
| apex_p | `c81f0c6b8d07248ce20860ab67edcbf8f1b3cf0a87f8263f1e7ae1812750ae4d` |

## [1.3.2] — 2026-10-04

Security patch. It closes the signing-integrity gaps that v1.3.1 left for a later release: how a
signing command is split into APDUs, bytes signed but never parsed, signatures no capability list
bounds, characters a screen cannot show, and three transaction fields the device did not check.
Each fix makes the device refuse something it signed before, or (for invisible characters and the
order of `meta` keys) show it differently; nothing that v1.3.1 refused is now accepted.

The app icon is now the Kadena Community Edition mark.

### What a malicious host could do, and what the device does now

- **Finish one signing command as another, or change the key that signs.** The modern and legacy
  signing commands each kept their own record of an open multi-APDU command, and the device read
  the buffer according to the INS of the last APDU. A host could send a JSON transaction under 0x22
  and finish it with 0x23, so the device signed those bytes as a raw hash; or interleave legacy and
  modern APDUs into one buffer. An address command between the chunks (0x21, legacy 0x01 or 0x02)
  also changed the derivation path, so the key that signed was not the one the signing command
  named. The device now keeps one stream for both families: every APDU of a stream must carry the
  INS of its first APDU, or it is refused (0x6987) and the stream is closed; a modern APDU with
  P1 = 1 or 2 and no open stream of its INS is refused (0x6987); a modern first APDU closes any open
  stream. The path given by the signing command is the one that signs, whatever address commands
  come between its APDUs.
- **Sign bytes the device never parsed.** The JSON reader stopped at a NUL byte, and after the first
  JSON value, but the device signed the whole buffer. Anything after a NUL, or after the
  transaction's closing brace, was signed unseen. A NUL byte anywhere is now refused ("Unexpected
  characters", 0x6984), and so is anything but whitespace after the transaction ("Unexpected
  unparsed bytes", 0x6984); bare 0x6984 on the legacy 0x03.
- **Get an unbounded signature clear-signed.** A JSON transaction whose signer entry has no
  capability list (missing, `null` or `[]`), or whose `meta` field the device does not recognise,
  was signed with only a warning on screen, although nothing the review shows limits the
  signature. These now need the Blind signing setting: with it off the device refuses ("Blind
  signing mode required", 0x6984, on 0x03 too); with it on the review shows the same items as
  before, opened by the blind-signing warning and closed by the "accept risk" approval. A review
  with the "too large to display" warning needs the setting too (in this app that warning already
  came with a capability that needed it).
- **Hide characters in a shown value.** An account name may contain characters a font draws as
  nothing or as a space (C1 controls, a no-break space, a soft hyphen), so two different accounts
  could look the same on screen. Every byte of a displayed value outside printable ASCII is now
  shown as `\xNN`. The signed bytes do not change.
- **Pass an amount the network reads differently.** A `coin.TRANSFER` / `coin.TRANSFER_XCHAIN`
  amount may now have at most 12 fractional digits (coin's precision), in both accepted forms and
  in a structured `coin` transfer; the network rounds a longer number, so the amount shown would
  not be the one moved. A structured transfer's amount (0x24, 0x10) must have a fractional part
  (`1000.0`, not `1000`): it is pasted into the Pact code, where an integer is not a decimal and the
  transfer fails on chain. Both are refused with "Unexpected characters" (0x6984; bare on the legacy
  commands). The `decimal` key of the object form must be a quoted string, as before.
- **Grant capabilities the review cannot show.** A command with a `verifiers` field (Pact 5
  signature verifiers) is refused ("Unexpected value", 0x6984; bare on 0x03).
- **Use a fractional gas field.** In a recognised `meta`, `gasLimit`, `ttl` and `creationTime` must
  be plain digits; the network reads them as integers. Anything else is refused ("Unexpected
  characters", 0x6984; bare on 0x03).
- **`meta` keys in any order.** The device recognised `meta` only with its keys in the order
  `creationTime`, `ttl`, `gasLimit`, `chainId`, `gasPrice`, `sender`, and showed any other order
  with the "'meta' field of transaction not recognized" caution, although it reads every `meta`
  value by its name. `@kadena/client` (checked with version 1.18.3) writes `gasLimit`, `gasPrice`,
  `sender`, `ttl`, `creationTime`, `chainId`, so with the rule above its plain coin transfers would
  have needed Blind signing. `meta` is now recognised when its keys are `creationTime`, `ttl`,
  `gasLimit`, `chainId`, `gasPrice` and optionally `sender`, in any order, each once, and no other
  key; such a transaction is clear-signed. With fewer keys the order does not matter either: a set
  made of the first one to four of those names (or none) is refused ("Unrecognized error code",
  0x6984; bare on 0x03), in any order, and any other set, an unknown key or a seventh key is shown
  with the caution and needs Blind signing.
- **Hide part of a long review on a touch screen.** On Stax, Flex and Apex P the review shows every
  page of every item as one pair, and counts the pairs, and then its screens, in 8 bits. Past the
  count the review wraps: it ends early, and items never shown are signed. v1.3.1 could already be
  made to do this on Apex P in a blind-signing review (46 unverified capabilities with long names:
  282 pairs, of which the device showed the first few), and with values shown as `\xNN` a
  clear-signed transaction could do it on all three. A transaction whose review would hold more
  than 253 pairs is now refused ("Value out of range", 0x6984; bare on 0x03), whatever the
  settings; 253 pairs is the most that fits both counts. The Nano review shows one item at a time
  and has no such limit.

### Compatibility

- A plain coin transfer built with `@kadena/client` is clear-signed with Blind signing off and is
  no longer shown with the `meta` caution (see above).
- A transaction whose signer entry has no capability list now needs Blind signing.
- A partial `meta` (one to four of the first keys) in another order than the canonical one was
  shown with the caution and signed by v1.3.1; it is now refused, as the canonical order already
  was.
- A `verifiers` field is refused even with Blind signing on: transactions that use Pact signature
  verifiers cannot be signed with this app.
- The integer rule for `gasLimit`, `ttl` and `creationTime` also applies to the structured transfer
  (0x24 and legacy 0x10), whose fields are written into the same `meta`.
- A host that sends another signing command, or a chunk of another signing command, between the
  APDUs of a signing command now gets 0x6987. An address, public-key or version command in between
  is answered as before, and the signing command continues with its own derivation path. Host
  libraries that send a command's APDUs one after another are unaffected.
- On Stax, Flex and Apex P, a transaction whose review would hold more than 253 pairs is refused
  (see above).

### Not in this release

These stay with the v2.0.0 rewrite (its source is on `main`): the "Max fee" and "Paying account" review items, the
"Recipient is not a principal account" warning, the expert-mode "Created", "TTL" and "Payload"
items, showing each unverified capability as separate items, and the new screens.

Known limit on Stax, Flex and Apex P: a transfer's or an unknown capability's title can show a wrong
number (the only transfer titled "Transfer 2"); only the title is affected, never the values under it.

### Testing

- C++ unit tests: new review vectors for each rule (refusals with their exact message, and controls
  that are still reviewed), and tests for a NUL byte inside and after the transaction. The vectors
  for an unscoped signer and an unrecognised `meta` now run with Blind signing on, each with a copy
  that is refused with it off. Every new refusal fails against the v1.3.1 code, except the unquoted
  `decimal` key, which v1.3.1 already refused.
- Zemu, all five device models: new functional tests for each rule, each refusal asserting the
  status word and message, each rule with a case that still signs. Every new refusal test fails
  against the released v1.3.1 binaries on every model. Tests whose input now needs Blind signing
  run with it on; their snapshots gain the blind-signing screens. New snapshots show an escaped
  account name, and the version page reads 1.3.2.
- The literal output of `@kadena/client` 1.18.3 for a plain coin transfer is a unit vector and a
  Zemu test on all five models: clear-signed with Blind signing off, signature verified.
- On Stax, Flex and Apex P a review of exactly 253 pairs is walked to its last screen and signed,
  and one of 254 pairs is refused over 0x22 and 0x03; unit vectors of 252, 253 and 254 pairs pin
  the bound, and changing it by one makes them fail.

### Device hashes (deterministic)

| Target | Application hash |
|---|---|
| nanos2 (Nano S+) | `0f6f62ceb5f9b841fbd1b2253a9d14c221000d8da2aeb733c4d70ee30888ccc6` |
| nanox | `61184da40282cc0843cad4b626e73a6c437531285932407c55e3824527d398c0` |
| stax | `895bd8e3989ac5d4d4ef5cf50d395918499b70155816b21fbfc36c60e9f37441` |
| flex | `e34526905e8bd26e50f915113876d1d5931c088a8894915586c1aa605c43d89a` |
| apex_p | `aec869f487aa033d670fde696b254ab640cd68a8233e0cbd01ec5ef1fe1218b8` |

## [1.3.1] — 2026-10-01

Security patch. The app builds or displays the transaction it signs, so it must decide which
transactions it will sign; v1.3.0 left thirteen gaps a malicious or buggy host could use to make the
device sign or approve something other than what its owner saw. Each is closed here. The only
wire-visible change is that commands sent while a signing review waits for the user are refused
(0x6986); honest host tooling, which waits for the review's reply, is unaffected.

### What a malicious host could do, and what the device does now

- **Sign undisplayed bytes in a legacy transfer.** In the legacy make-transfer command (0x10) a
  field could claim more bytes than the host actually sent; the device appended leftover buffer
  bytes and signed them into the transaction's validity window (`ttl`), which is never shown. The
  device now refuses any field, including the last, that does not fit within the bytes received
  (0x6700), and only lets an item continue into the next packet at a full packet boundary.
- **Inject JSON into a structured transfer.** The structured transfer (0x24 and legacy 0x10) pasted
  each field verbatim into the JSON the device builds and signs, checking only lengths. A quote or
  backslash in a field could add hidden JSON — for example an extra top-level key smuggled through
  the undisplayed nonce — or change the transfer's meaning. Every field is now checked against the
  content its position allows (hex recipient, well-formed numbers, identifier-only namespace and
  module, printable nonce with no quote or backslash) before the JSON is built; a violation is
  refused (0x6984).
- **Hide the "unsafe transaction" warning with a look-alike account.** A capability argument that
  merely started with the signer's key (the key followed by extra characters — a different account)
  counted as the signer and suppressed the warning. The match is now exact.
- **Hide it with an empty capability list.** A signer with `"clist":[]` was shown as if it limited
  the signature, but the network treats an empty list as unscoped — valid for any capability. An
  empty list now shows the same "Unscoped Signer" warning as a missing one.
- **Show one signer's capabilities while the device signs for another.** The review always showed
  the first signer entry, whatever key the device signed with, so a host could display a harmless
  entry while the device key's real (wider) scope sat elsewhere, or list the device key twice with
  the wider scope hidden. The device now derives its own key for the path being signed, reviews the
  one entry that names that key, and refuses a transaction where no entry — or more than one — names
  it (0x6984). It shows "Signers: N" when there is more than one signer.
- **Take over an account through a rotation.** A signature scoped to `coin.ROTATE` was clear-signed,
  but the account's new owner comes from code and data the review never shows. Rotation now carries
  a warning that the new owner is not shown and requires the existing Blind signing setting, like
  hash signing.
- **Hide a transfer, a signer list, a rotation or a fee behind an escaped key.** The device looked
  up JSON members by their raw bytes, but the network decodes escapes in a key (such as `n\u0061me`,
  `sign\u0065rs` or `m\u0065ta`) before choosing between duplicate keys. A host could place an
  escaped spelling next to the normal one so that the device showed one member while the network
  executed the other — a hidden 1000-KDA transfer, a hidden rotation, or a hidden large fee, with a
  clean review. An escape in a capability name (`coin.\u0052OTATE`) hid a rotation the same way. The
  device now refuses any object key containing an escape, any escape in a capability name of its own
  signer entry, and any key repeated literally within one object (0x6984).
- **Drain an account through a capability the device does not check.** In a transaction the host
  writes as JSON, the review listed any capability in the device's signer entry as an argument list
  and clear-signed it. A signature scoped to `coin.DEBIT` looks narrow but lets the transaction's
  code, which the review does not show, install any transfer and move the whole balance. For
  host-written JSON (the JSON signing commands) the device now clear-signs only `coin.GAS`,
  `coin.TRANSFER` and `coin.TRANSFER_XCHAIN`. Any other capability in its signer entry
  (`coin.DEBIT`, `coin.CREDIT`, any other `coin` capability, any other module's capability, a token
  module's `TRANSFER` included) requires the Blind signing setting, like `coin.ROTATE` and hash
  signing: with it off the device refuses ("Blind signing mode required", 0x6984); with it on the
  review adds "WARNING: Capability not verified: <name>". See the next item for the structured
  transfer commands.
- **Pass a token module's code off as a plain transfer.** A structured transfer that names a
  namespace and module other than `coin` scopes the signature to that module's `TRANSFER` (or
  `TRANSFER_XCHAIN`). The device cannot check the module's code, which can use the device key for
  anything it guards while the capability is held, and a look-alike module in another namespace
  reads the same on a small screen. Such a transfer now needs the Blind signing setting: with it
  off the device refuses ("Blind signing mode required", 0x6984; a bare 0x6984 on the legacy
  command); with it on the review adds "WARNING: Capability not verified:
  <namespace>.<module>.TRANSFER". A plain KDA transfer is clear-signed with no warning.
- **Show an amount in a form the screen cannot convey.** A transfer amount was shown exactly as
  written: an object such as `{"decimal":"1000.0"}` was truncated on a small screen (`KDA {"deci…`),
  and other forms (a string, `{"int":1000}`, a sign, a trailing dot) read as a different decimal on
  the network. In a transaction the host writes as JSON, a `coin.TRANSFER` or
  `coin.TRANSFER_XCHAIN` amount is now accepted in two forms only: a bare number (`123`, `123.45`)
  or `{"decimal":"123.45"}` with that single key, the form `@kadena/client` produces. Either way the
  digits must be a plain decimal without a leading zero (`0.5` is fine, `01.0` is not), and the
  review shows the plain number (`KDA 123.45`). Anything else is refused ("Unexpected characters",
  0x6984). This includes the exponent rule above.
- **Change what is signed after the review is shown.** The app kept answering commands while a
  signing review waited for the user's approval, and on approval it hashed the transaction buffers
  again, so a command arriving behind the review could change the bytes or the derivation path that
  approval signs. While a signing review is pending the device now refuses every command except
  GET_VERSION with 0x6986 ("Command not allowed"); the device-information command, answered by the
  system library, keeps working, and the legacy version command (0x00) is refused too. Approval
  signs the hash computed when the reviewed transaction was parsed, never a new hash of the buffers.
  Known limitation: if USB power is lost while a review is pending (on battery-powered models the
  device returns to its main screen), the lock stays set and signing commands are refused with
  0x6986 until the Kadena app is closed and reopened.
- **Hide a large transfer amount in exponent notation.** A transfer amount written as
  `1.0000000001e3` (or `{"decimal":"1e3"}`) was shown as written, while the network reads it as
  1000.0000001 KDA. A `coin.TRANSFER` or `coin.TRANSFER_XCHAIN` amount containing an exponent is
  now refused ("Unexpected characters", 0x6984). The structured-transfer amount field already
  admitted plain decimals only.

### Testing

- New Zemu functional tests exercise each fix on all five device models; each one fails against the
  released v1.3.0 binaries and passes here. New C++ review vectors (positive and negative) cover the
  signer-selection, empty-clist, exact-match, rotation, escaped/duplicate-key, unverified-capability
  and exponent-amount rules, and C++ unit tests cover the review lock and the signed digest. The
  token structured-transfer snapshots are regenerated: they now run with Blind signing on and show
  the token warning. The full
  existing test matrix and the C++ unit tests continue to pass.

### Device hashes (deterministic)

| Target | Application hash |
|---|---|
| nanos2 (Nano S+) | `726078b6269fdb4ef9a70e28c66d7a00ef9f94a0f4a5c7adac11f95fc3cd814a` |
| nanox | `71a2627800a353216a8901e7d4a991ae0cc37941917a2a7e4762d2d28f07e318` |
| stax | `9bd17293b0d8c986343bc6a103440c7eabfede044c9157f2e433b914a2a1e29b` |
| flex | `9db8b6cdfc97cee019bbfc755d0ca25435af3130f463f15c7ba11279169eb3df` |
| apex_p | `5fbf36d1f9639ac508b5d32c1fb6585ce552c3c893e2258b9b43c8901adc0a1c` |

## [1.3.0] — 2026-07-22

Security- and correctness-hardening release. A fresh, whole-app cold security audit (not a
diff-scoped review) held the entire signing / derivation / parsing / display surface to
submission standard and drove every finding to zero. Two previously-unknown HIGH memory-corruption
defects in upstream-inherited code were found and fixed, along with the known parser out-of-bounds
issue and a set of display-integrity and defense-in-depth fixes.

### Security fixes (HIGH)

- **Legacy HD-path length overflow** (`apdu_handler_legacy.c`): a host-controlled path-component
  count drove a `MEMCPY` into the fixed 20-byte `hdPath` global. The count is now validated against
  the fixed Kadena path length (5) before the copy, on every legacy entry point, and the real
  received length bounds the read — a short APDU fails closed instead of reading stale buffer memory.
- **Transfer-template buffer capacity** (`common/tx.c`, `parser_impl.c`): the structured-transfer
  template buffer was registered with the wrong (much larger) capacity, so a maximum-size cross-chain
  transfer could write past it into persistent storage. The buffer is now registered with its real
  size, sized to hold the largest valid template, and every append is checked so an over-cap input
  aborts cleanly rather than truncating the signed bytes.
- **Parser item-array out-of-bounds** (`items.c`): three wrong-argument-count branches ignored a
  "too many items" signal and could drive the item count one past the end of the display
  function-pointer array (invoked before user approval). All three now propagate the error and the
  loop guards the index.

### Display-integrity and robustness fixes (MED/LOW)

- Unknown-capability arguments now render with an explicit length bound (no read past the token).
- Gas-value length widened so an oversized value is rejected rather than mis-displayed.
- Legacy transfer-continuation reads are bounded by the received length; shared reassembly state is
  reset on fresh transfers and error paths.
- `tx_type` is validated; namespace+module display buffer sized to avoid truncation; hash-signing
  length guarded; several accessor return values now checked. The transaction hash continues to be
  shown as the unpadded base64url request key.

### Notes

- No APDU / wire-protocol change; host tooling is unaffected.
- Full principal namespaces (`n_<40-hex>`) are handled on the structured transfer path, with a
  regression vector.
- Builds are deterministic across all five device targets (nanos2 / nanox / stax / flex / apex_p).
  First-generation Nano S remains unsupported.

### Device hashes (deterministic)

| Target | Application hash |
|---|---|
| nanos2 (Nano S+) | `068f376be6115e1769952fabb61020ae5070867c9b2299c259f6947c5b5ce1db` |
| nanox | `dc28a5786a81c2162725eb89dac3433066c37af3b4c7621177c66c4bad32127c` |
| stax | `592296023a6098959ff4f3e00889a6fb64c7dcc4a8fab44f367e89a77c9302e0` |
| flex | `d03d46f36b11d267de05b6f2aba60f6d798faabc1d0970afbe13dec138b1fca3` |
| apex_p | `4484159eabe9f65ffa83aaedd7eeb1a3aab3decbaa7cc34988a4bbde5fd535e5` |

## [1.2.1] — 2026-07-22

Maintained continuation rebuilt against API_LEVEL 26 (SDK v26.5.0) so the app installs on current
Nano S+ firmware. Fixed two upstream stack-overflow renderers and a toolchain-dependent PIC crash;
closed loop-internal one-past-end token reads. Full emulator regression green on all five targets.
