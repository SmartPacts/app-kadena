# Changelog

All notable changes to the Kadena Ledger app (this maintained continuation) are documented here.

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
