# Security policy

## Reporting a vulnerability

Please report security problems in this app privately, not in a public issue:

- **GitHub:** open a private vulnerability report on this repository
  ("Security" tab, "Report a vulnerability").
- **Email:** contact@smartpacts.io.

Include the app version (shown on the device's version page), the device model and OS
version, and the exact command bytes or transaction that triggers the problem. We confirm
receipt within five working days and tell you what we found and when a fix will be released.
We ask that you keep the report private until a fixed version is released; we credit
reporters in the changelog unless they prefer not to be named.

There is no bug bounty.

## Supported versions

| App | Branch | Versions receiving security fixes |
|---|---|---|
| Rust (current) | `main` | 2.0.x |
| C (maintained for devices on older OS versions) | `c-v1.3` | 1.3.x |

Earlier versions (1.2.x and before, by the previous maintainers) are not supported.

## What counts as a vulnerability here

Anything that lets a connected host obtain a signature over something the screen did not
show, or showed differently, bypass the Blind signing setting, make the device sign with a
key outside `m/44'/626'`, expose key material, corrupt the saved settings, or crash the app
into a state where a review can be confused. The threat model, the clear-signing rules and
the known limits are described in `submission/SECURITY-AUDIT.md`.

## Verifying a release

Every release lists the sha256 of each downloadable file and the application hash the device
shows after installation (behind the "i" on Nano Gen5; on the install screen of Nano S Plus).
Compare both before trusting a download.
