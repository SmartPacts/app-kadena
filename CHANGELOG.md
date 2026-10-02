# Changelog

All notable changes to the Kadena Ledger app (this maintained continuation) are documented here.

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
