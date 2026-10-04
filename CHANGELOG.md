# Changelog

All notable changes to the Kadena Ledger app (this maintained continuation) are documented here.

## [2.0.0] — unreleased

The app is rewritten in Rust on Ledger's Rust SDK (`ledger_device_sdk` 1.37.0), with the NBGL
interface on every device. The C implementation (v1.3.x) is on the `main` branch.

### Compatibility

- Same commands, same responses: both command families (0x20–0x24 and the legacy 0x00–0x04, 0x10)
  answer byte for byte like v1.3.0, including status words and error texts. Proven by running the same
  APDUs against the v1.3.0 release binaries and this app in the Speculos emulator on all five devices.
- Same keys: addresses derive exactly as in v1.3.0 (`m/44'/626'/0'/0/0` of the test seed gives
  `de12b5e1…74ad`).
- The version number reported by GET_VERSION changes to 2.0.0.

### Security changes (intended differences from v1.3.0)

- Legacy transfer (0x10): an item that claims more bytes than its APDU carries is refused (0x6700).
  v1.3.0 could sign bytes left over from an earlier command as the transfer's (undisplayed) ttl.
- Structured transfers (0x24, 0x10): every field is checked against its allowed characters before the
  JSON is built (0x6984). v1.3.0 let a `"` in a field add JSON the screen never showed.
- The "Unscoped Signer" warning compares the signer key exactly; v1.3.0 compared a prefix, so an account
  that only started with the key hid the warning.
- A JSON object with a duplicate key, at any depth, is refused (0x6984).
- A modern first chunk (P1 = 0) closes any command stream in progress; a modern middle or last chunk
  without an open stream of its INS is refused (0x6987).
- V7 — the signing key is bound to the command: the path the signing command gives is the one that signs.
  In v1.3.0 all commands shared one path, so a 0x02 (get public key) sent between the first and last
  packet of a signature changed the key that signed. Decision: the key a signature uses is fixed by the
  signing command alone.
- V8 — one command per stream: every packet must carry the INS of the stream's first packet; any mix
  (0x22/0x23/0x24, or modern with legacy) is refused (0x6987) and closes the stream. In v1.3.0 the last
  packet's INS decided how the buffer was parsed, so a 0x22 transaction finished with 0x23 was read as a
  hash and, with blind signing on, signed raw. Decision: a stream's type is fixed by its first packet.
- V9 — the review is of the device's own signer entry. Context: v1.3.0 reviewed `signers[0]` whatever its
  key, while Pact scopes a signature by the entry keyed by the signing key (the last one if the key repeats;
  `addr` replaces `pubKey` as that key). A host could show a harmless first entry, or a harmless copy of the
  device's entry, and have the device sign a hidden scope. Decision: exactly one entry may name the device key
  (as `pubKey` or `addr`, any letter case), its `pubKey` must be the exact lowercase key, escapes inside signer
  entries are refused, the review shows that entry, and a "Signers" item shows the count when it is above 1.
  Consequence: a JSON transaction that does not list the device key as a signer can no longer be signed
  ("Device key is not a signer").
- V10 — an empty clist is unscoped. Context: Pact reads a missing, null or empty clist alike (valid for any
  capability); v1.3.0 warned only for the first two. Decision: `[]` gets "Unscoped Signer" and the WARNING.
- V11 — blind signing for JSON whose signature no displayed capability list bounds. Context: v1.3.0 showed a
  WARNING (unscoped signer, value too large to show) or a CAUTION (`meta` not recognised) and signed with blind
  signing OFF, though the code the signature authorises is never displayed. Decision: these reviews need the
  "Blind signing" setting (refused with the "Cannot clear-sign" screen and `Blind signing mode required`
  otherwise, legacy 0x03 included) and open with Ledger's blind-signing warning. Structured transfers are never
  blind. Consequence: hosts that sign unscoped JSON must ask the user to enable blind signing.
- V12 — one JSON value. Context: v1.3.0 tokenized up to a NUL and accepted several top-level values, then
  signed every byte. Decision: a NUL anywhere, or anything but whitespace after the value, is refused.
- V13 — screen text is printable ASCII: any other byte of a value is shown as `\xNN` on every device, so a C1
  control, an NBSP or a soft hyphen in an account name cannot look like nothing. The signed bytes do not change.
- V14 — account rotation is blind signing. Context: `coin.ROTATE` limits only which account is rotated; the new
  guard comes from code and data the device does not show, so a host could have a vanity account handed to its
  own keyset (review round 2, reproduced in the Pact REPL). Decision: a device entry holding `coin.ROTATE` adds
  the WARNING "Account rotation: new owner not shown" and needs the "Blind signing" setting.
- V15 — fee and payer. Context: the gas limit and price were shown raw ("at most 150000 at price 1e+2") and
  the account debited for gas never. Decision: "Max fee" shows gasLimit × gasPrice in KDA, computed exactly in
  decimal (exponents included, no rounding; values that are not numbers are refused), and "Paying account" shows
  `meta.sender`, for JSON and structured transfers. `gasLimit`, `ttl` and `creationTime` must be plain digits
  (the node reads them as integers and would round a fraction), so the fee shown is exactly the most charged.
- V16 — a transfer to an account that is not a Pact principal gets a WARNING: coin lets such an account be
  created with any guard, and the guard is not shown.
- V20 (replaces V17) — only gas and coin transfers are clear-signed. Context: the third review drained an
  account with a clear-signed `coin.DEBIT` (the code installs any TRANSFER while DEBIT is in scope; proved in
  the emulator and the Pact REPL), and showed that while any capability is in scope, any code the transaction
  runs, not only its module, can use the key. Decision: in host-built JSON (0x22, 0x03) only `coin.GAS` and
  `coin.TRANSFER` / `coin.TRANSFER_XCHAIN` with all arguments shown are clear-signed; every other capability of
  the device's entry adds a "Capability not verified" warning and needs blind signing.
- V21 — a transfer amount in exponent notation is refused: `1.0000000001e3` is 1000.0000001 KDA on chain.
- V22 — a command with a `verifiers` field is refused instead of ignored.
- V23 — structured token transfers are blind signing. Context: a structured transfer with a namespace and
  module scopes the key to `<namespace>.<module>.TRANSFER`; the fourth review showed in the Pact 5.4 REPL that
  while it is in scope the module's own code can use the key for guards checked outside a capability body
  (coin's `rotate` pattern), so a lookalike token module could take over vanity accounts the key guards.
  Decision: such a transfer shows the "Capability not verified" warning and needs blind signing, on 0x24 and
  0x10; coin transfers stay clear-signed. v1.3.0 clear-signed token transfers.
- V24 — two amount forms. Context: the amount was shown as written, and `{"decimal":"1\u0030\u0030\u0030.0"}`
  reads as "1..." but is 1000.0 on chain (fourth review); @kadena/client sends `{"decimal":"231"}`. Decision:
  a coin transfer amount is a bare JSON number or `{"decimal":"<number>"}` (single key, string value), the
  number `(0|[1-9][0-9]*)(.[0-9]+)?`, and the review shows the number ("KDA 231"); every other shape is
  refused ("Unexpected characters"), the same set as the C v1.3.1 patch. The key must be quoted
  (`{decimal:"1.5"}` is refused; fifth review R5-2).
- Screens, after the first hardware run on a Nano S+: a capability the review cannot verify is shown as
  separate items, each whole: "WARNING: Capability not verified", "Capability: <module>.<NAME>", "Namespace:
  <namespace>" (only when the name has one: a placeholder could read as a namespace, `none` is one) and
  "Arguments" (V20, V23). On the device, the one-piece warning had split a 40-hex
  namespace across pages, which is where a look-alike module would hide. On Nano a value without spaces is cut
  into lines at the screen width (NBGL had put "n_" alone on a line). The blind-signing-required page reads
  "Cannot clear-sign" / "Enable Blind signing in Settings to sign this transaction" (the title was shortened
  on Nano). Signing is unchanged.
- V25 — at most 12 fractional digits in a coin transfer amount, coin's precision. Context: pact-5 rounds a
  JSON number at 255 places, so a fraction of 256 nines, shown in full, is 1.0 on chain (fifth review R5-1).
  Decision: more than 12 places, in host JSON or a coin structured transfer, is refused.
- V26 — a structured transfer amount needs a fractional part. Context: the amount is pasted into the code as
  is, and Pact refuses `1000` for `amount:decimal`, so the transaction failed on chain (fifth review R5-3).
- A capability name whose "name: <name>, " does not fit the 300-byte value is refused at once (found by the
  fuzzer: a 293-299 byte name was cut, then refused one check later).
- The "Key not in transfer" title replaces "Unscoped Signer" for a scoped signature whose transfers do not name
  the key; expert mode shows the payload kind; on Nano, no layout ever shortens a title.
- V18 — no escaped keys. Context: the device finds members by raw key bytes, while pact-5's decoder
  (aeson) unescapes keys and keeps the first of two duplicates; an escaped `"name"`, `"signers"` or `"meta"`,
  or an escaped `coin.ROTATE` name, let a host hide a transfer, a rotation or a fee (review of the C v1.3.1
  patch, attacks A1-A4 and A8). Decision: as in C v1.3.1, an object key containing a backslash, anywhere in
  the document, and a backslash in a capability name of the device's entry are refused ("Unexpected
  characters"); literal duplicates are refused byte for byte in every object. Escapes in values stay allowed.
- V19 — expert mode shows the validity window: "Created (unix time)" and "TTL (seconds)", as sent.
- Structured transfers (V2, tightened): numbers must be well formed (digits, optional fraction, optional
  exponent for the gas price), the chain id and a cross-chain recipient chain non-empty, and the recipient
  lowercase hex, so the template is always valid JSON and names the account shown.

### Interface

- NBGL screens on Nano S+ and Nano X too (previously BAGL). Review content (titles, values, order) is
  unchanged; the layout follows the SDK's standard flows. On Nano no title is ever shortened: the app pages
  long values itself, so warnings such as "Unscoped Signer" and "Sign for Address" always show whole, and a
  page break takes the space it breaks at, as a line wrap does (no extra, empty page).
- Transactions up to 8192 bytes are buffered in RAM, larger ones in flash (up to 15104 bytes), as in v1.3.0.
- Settings: "Blind signing" and "Expert mode", both OFF on install. Blind signing affects hash signing
  (0x23 / 0x04), unbounded JSON signatures (V11), rotations (V14), every capability other than gas and a fully
  shown coin transfer (V20) and structured token transfers (V23).
- Every blind-signing review (hash, V11 JSON) streams all of its items; a review is streamed in batches of
  at most about 1200 bytes of shown text (counted after `\xNN` escaping), measured to keep the largest accepted
  review within the 8 KiB heap with printable and with non-printable values.
- Flash buffers are written through their own cell pointers, and every access to the flash store, the
  settings included, goes through one raw pointer: the app no longer creates overlapping references to it.

## [1.3.0] — 2026-07-22

Security- and correctness-hardening release. A fresh, whole-app security review (not a
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
