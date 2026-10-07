# Kadena App

## General structure

The general structure of commands and responses is as follows:

### Commands

| Field   | Type     | Content                | Note |
| :------ | :------- | :--------------------- | ---- |
| CLA     | byte (1) | Application Identifier | 0x00 |
| INS     | byte (1) | Instruction ID         |      |
| P1      | byte (1) | Parameter 1            |      |
| P2      | byte (1) | Parameter 2            |      |
| L       | byte (1) | Bytes in payload       |      |
| PAYLOAD | byte (L) | Payload                |      |

### Response

| Field   | Type     | Content     | Note                     |
| ------- | -------- | ----------- | ------------------------ |
| ANSWER  | byte (?) | Answer      | depends on the command   |
| SW1-SW2 | byte (2) | Return code | see list of return codes |

### Return codes

| Return code | Description             |
| ----------- | ----------------------- |
| 0x6400      | Execution Error         |
| 0x6901      | Command not accepted    |
| 0x6700      | Wrong buffer length     |
| 0x6982      | Empty buffer            |
| 0x6983      | Output buffer too small |
| 0x6984      | Data is invalid         |
| 0x6986      | Command not allowed     |
| 0x6987      | Tx is not initialized   |
| 0x6B00      | P1/P2 are invalid       |
| 0x6D00      | INS not supported       |
| 0x6E00      | CLA not supported       |
| 0x6F00      | Unknown                 |
| 0x6F01      | Sign / verify error     |
| 0x9000      | Success                 |

### Signing policy (v1.3.2)

The device builds or displays the transaction it signs, so it enforces which transactions it will
sign. For every JSON-signing command (INS 0x22 and legacy INS 0x03) and every structured-transfer
command (INS 0x24 and legacy INS 0x10):

- The device derives its own public key for the derivation path being signed and reviews the one
  `signers` entry that names that key, by `pubKey` or `addr`, in any letter case. If no entry names
  the device key, or more than one does, the command is refused with `0x6984` (a bare `0x6984` on
  the legacy commands, an error message plus `0x6984` on the modern ones). The reviewed entry's
  `pubKey` must be the exact lowercase hex of the device key, and signer-entry key names and their
  `pubKey`/`addr` values may not contain JSON escapes. When there is more than one entry, the review
  shows `Signers: N`.
- A `signers` entry whose capability list is missing, `null`, or empty (`[]`, any whitespace) is
  unscoped: the review shows the `Unscoped Signer` item and the unsafe-transaction WARNING.
- A JSON transaction whose signature no capability list on screen bounds is blind signing: an
  unscoped entry (the unsafe-transaction WARNING), a value too large to show (the "too large to
  display" WARNING), or a `meta` the device does not recognise (the `CAUTION` item). The device
  recognises `meta` when its keys are `creationTime`, `ttl`, `gasLimit`, `chainId`, `gasPrice` and
  optionally `sender`, in any order, each once, and no other key; a set made of the first one to
  four of those names in that list (or none), in any order, is refused (`Unrecognized error code`;
  bare on 0x03), and any other set shows the `CAUTION`. Such a transaction requires the *Blind
  signing* setting: with it off the command is refused with `0x6984` (`Blind signing mode
  required`, after the blind-signing screen, on 0x03 too); with it on the review shows the same items
  as before, opened by the blind-signing warning and closed by the accept-risk approval.
- On Stax, Flex and Apex P the review shows every page of every item as one pair and counts the
  pairs, and then its screens (a first page, the pair screens, a last page), in 8 bits. A review of
  more than 253 pairs (at the device's value page size: 159, 161 and 143 characters) is refused with
  `0x6984` (`Value out of range`; bare on 0x03), whatever the settings; on a device, expert mode adds two
  pairs (the transaction hash and the signing address). The
  Nano review shows one item at a time and has no such limit.
- A capability argument matches the signer key only when, after an optional `k:` prefix, it equals
  the key exactly (no prefix match).
- When the reviewed entry holds `coin.ROTATE`, the review shows a warning that the account's new
  owner is not shown, and signing requires the *Blind signing* setting to be enabled (the same
  refusal screen and `0x6984` as hash signing when it is off).
- For the JSON-signing commands (INS 0x22 and legacy INS 0x03), where the host writes the
  capability list, the device clear-signs only `coin.GAS`, `coin.TRANSFER` and
  `coin.TRANSFER_XCHAIN` in the reviewed entry. Any other capability there (`coin.DEBIT`,
  `coin.CREDIT`, any other `coin` capability, any other module's capability, a token module's
  `TRANSFER` included) requires the *Blind signing* setting, as `coin.ROTATE` does: with it off the
  command is refused with `0x6984` (`Blind signing mode required`, after the blind-signing screen,
  on 0x03 too); with it on the
  review adds `WARNING: Capability not verified: <name>` after the capability's items. For the
  structured-transfer commands (INS 0x24 and legacy INS 0x10), a plain `coin` transfer is
  clear-signed with no warning. When the namespace and module name a token other than `coin`, the
  transfer needs the *Blind signing* setting too, because the device cannot check that module's
  code: with it off the command is refused with `0x6984` (`Blind signing mode required` after the
  blind-signing screen on 0x24, bare on 0x10); with it on the review adds
  `WARNING: Capability not verified: <namespace>.<module>.TRANSFER` (or `TRANSFER_XCHAIN`).
- While a signing review (INS 0x22, 0x23, 0x24, legacy 0x03, 0x04, 0x10) waits for the user, every
  command except GET_VERSION (INS 0x20) is refused with `0x6986` and changes nothing; the
  device-information command (CLA 0xE0, INS 0x01) is answered by the system library, and the legacy
  version command (INS 0x00) is refused. The lock ends when the review is approved or rejected.
  Approval signs the digest computed when the reviewed transaction was parsed (blake2b-256 of the
  JSON, or the 32 bytes of a hash to sign). If USB power is lost during a review, the lock stays set
  until the app is reopened, and signing commands are refused with `0x6986` until then.
  From v1.3.4, built for API level 27, the SDK itself answers any command that arrives while a
  previous one still awaits its reply with a bare `0x6901`, before the app sees it: during a
  review, GET_VERSION and signing commands are answered `0x6901`. The `0x6986` answers above are
  those of the API level 26 builds (v1.3.3 and earlier); the app's own lock is unchanged.
- A `coin.TRANSFER` or `coin.TRANSFER_XCHAIN` amount in the reviewed entry must be either a bare
  JSON number or an object with the single key `"decimal"` whose value is a string; the number or
  string must be `digits` or `digits.digits`, with no leading zero in the integer part (`0.5` is
  accepted, `01.0` is not). The review shows the plain number (`KDA 231` for `{"decimal":"231"}`).
  Anything else (an exponent, a string, `{"int":…}`, other or extra keys, a number or object as the
  value, an escape or a space in the string, a sign, a leading or trailing dot) is refused with
  `0x6984` (`Unexpected characters`; bare on 0x03).
- That number has at most 12 fractional digits (coin's precision), in both forms. More is refused
  with `0x6984` (`Unexpected characters`; bare on 0x03). The network rounds a longer JSON number,
  so it would not be the amount shown.
- In a recognised `meta`, `gasLimit`, `ttl` and `creationTime`, when present, must be plain digits
  (the network reads them as integers): otherwise `0x6984` (`Unexpected characters`; bare on 0x03).
- A command with a `verifiers` field (Pact 5 signature verifiers, which can grant capabilities the
  review cannot show) is refused with `0x6984` (`Unexpected value`; bare on 0x03).
- The transaction is one JSON value: a NUL byte anywhere is refused with `0x6984` (`Unexpected
  characters`), and anything but whitespace after the top-level value with `0x6984` (`Unexpected
  unparsed bytes`); bare on 0x03. Every signed byte is a byte that was parsed and reviewed.
- Every byte of a displayed value outside printable ASCII (0x20-0x7E) is shown as `\xNN`
  (uppercase hex), on every device. Account names may contain characters a font draws as nothing
  (C1 controls, NBSP, the soft hyphen). The signed bytes are unchanged.
- No JSON object key may contain an escape (`\`), anywhere in the document; no capability name in
  the reviewed signer entry may contain an escape; and no key may appear twice (byte for byte)
  within one object. Otherwise the command is refused with `0x6984` (`Unexpected characters`, or
  `Unexpected duplicated field` for a repeated key; bare on the legacy commands). String values keep
  their escapes.

For the structured-transfer commands the device also checks every field against the content its
position allows (before building the JSON for the recipient, chain ids and the amount's fraction;
the gas limit, creation time and TTL are checked as integers on the built `meta`, S22), and refuses a violation with `0x6984` (`Unexpected
characters`; a bare `0x6984` on legacy 0x10): lowercase-hex recipient; digit-only chain ids; a
digit-only gas limit, creation time and TTL (they become the `meta` integers above); an amount with
a fractional part
(`digits . digits`: the amount is pasted into the Pact code, where an integer is not a decimal); a
JSON number (an optional exponent) gas price; Pact identifier characters for namespace and module;
letters, digits and `-_.` for the network; and printable ASCII without `"` or `\` for the nonce. A
`coin` transfer's amount then follows the amount rules above (no leading zero, at most 12
fractional digits).

#### Command streams

The signing commands that take several APDUs (INS 0x22, 0x23, 0x24 and legacy 0x03, 0x04, 0x10)
share one stream:

- A first chunk of 0x22, 0x23 or 0x24 (`P1 = 0x00`) closes any stream in progress, of either
  family, and opens a stream for its INS.
- A 0x22/0x23/0x24 chunk with `P1 = 0x01` or `0x02` is refused with `0x6987` unless a stream of the
  same INS is open.
- Every chunk of a stream must carry the INS of its first chunk. A signing APDU with another INS
  while a stream is open (a different modern INS, a legacy APDU during a modern stream, a modern
  APDU during a legacy stream, or another legacy command during a legacy stream) is refused with
  `0x6987` and closes the open stream. So bytes sent as one command are never parsed and signed as
  another (for example a JSON transaction finished as a hash).
- The derivation path that signs is the one the signing command gave (the first packet of 0x22,
  0x23, 0x24 and 0x10; the path after the payload on 0x03 and 0x04). An address command (0x21,
  legacy 0x01 or 0x02) sent between the chunks does not change it. A 0x21 closes an open stream of
  0x22, 0x23 or 0x24 (as before); the legacy address commands close none.

---

## Command definition

Some commands contain two different possible INS values.
Such implementation is to allow for backwards compatibility with the original Kadena App.
See [Legacy Command definition](#legacy-command-definition) for more details.

### GET_DEVICE_INFO

#### Command

| Field | Type     | Content                | Expected |
| ----- | -------- | ---------------------- | -------- |
| CLA   | byte (1) | Application Identifier | 0xE0     |
| INS   | byte (1) | Instruction ID         | 0x01     |
| P1    | byte (1) | Parameter 1            | 0x00     |
| P2    | byte (1) | Parameter 2            | 0x00     |
| L     | byte (1) | Bytes in payload       | 0x00     |

#### Response

| Field     | Type     | Content            | Note                     |
| --------- | -------- | ------------------ | ------------------------ |
| TARGET_ID | byte (4) | Target Id          |                          |
| OS_LEN    | byte (1) | OS version length  | 0..64                    |
| OS        | byte (?) | OS version         | Non terminated string    |
| FLAGS_LEN | byte (1) | Flags length       | 0                        |
| MCU_LEN   | byte (1) | MCU version length | 0..64                    |
| MCU       | byte (?) | MCU version        | Non terminated string    |
| SW1-SW2   | byte (2) | Return code        | see list of return codes |

---


### GET_VERSION

#### Command

| Field | Type     | Content                | Expected                   |
| ----- | -------- | ---------------------- | -------------------------- |
| CLA   | byte (1) | Application Identifier | 0x00                       |
| INS   | byte (1) | Instruction ID         | 0x20                       |
| P1    | byte (1) | Parameter 1            | ignored                    |
| P2    | byte (1) | Parameter 2            | ignored                    |
| L     | byte (1) | Bytes in payload       | 0                          |

#### Response

| Field      | Type     | Content          | Note                            |
| ---------- | -------- | ---------------- | ------------------------------- |
| TEST       | byte (1) | Test Mode        | 0x00; 0x01 in a test build      |
| MAJOR      | byte (2) | Version Major    | 0..65535                        |
| MINOR      | byte (2) | Version Minor    | 0..65535                        |
| PATCH      | byte (2) | Version Patch    | 0..65535                        |
| LOCKED     | byte (1) | Device is locked |                                 |
| TARGET_ID  | byte (4) | Target Id        |                                 |
| SW1-SW2    | byte (2) | Return code      | see list of return codes        |

---

### INS_GET_ADDR

#### Command

| Field   | Type     | Content                   | Expected                   |
| ------- | -------- | ------------------------- | -------------------------- |
| CLA     | byte (1) | Application Identifier    | 0x00                       |
| INS     | byte (1) | Instruction ID            | 0x21                       |
| P1      | byte (1) | Request User confirmation | No = 0  / Yes = Any Other  |
| P2      | byte (1) | Parameter 2               | ignored                    |
| L       | byte (1) | Bytes in payload          | 20                         |
| Path[0] | byte (4) | Derivation Path Data      | 0x80000000 \| 44           |
| Path[1] | byte (4) | Derivation Path Data      | 0x80000000 \| 626          |
| Path[2] | byte (4) | Derivation Path Data      | ?                          |
| Path[3] | byte (4) | Derivation Path Data      | ?                          |
| Path[4] | byte (4) | Derivation Path Data      | ?                          |

#### Response

| Field   | Type      | Content     | Note                     |
| ------- | --------- | ----------- | ------------------------ |
| PK      | byte (32) | Public Key  |                          |
| SW1-SW2 | byte (2)  | Return code | see list of return codes |

---

### INS_SIGN

#### Command

| Field | Type     | Content                | Expected                                                              |
| ----- | -------- | ---------------------- | --------------------------------------------------------------------- |
| CLA   | byte (1) | Application Identifier | 0x00                                                                  |
| INS   | byte (1) | Instruction ID         | 0x22                                                                  |
| P1    | byte (1) | ----                   | First packet = 0x00 / More packets coming = 0x01 / Last packet = 0x02 |
| P2    | byte (1) | ----                   | not used                                                              |
| L     | byte (1) | Bytes in payload       | (depends)                                                             |

For the new app, the first packet/chunk includes only the derivation path.

All other packets/chunks contain data chunks that are described below.

##### First Packet (New)

| Field   | Type     | Content              | Expected          |
| ------- | -------- | -------------------- | ----------------- |
| Path[0] | byte (4) | Derivation Path Data | 0x80000000 \| 44  |
| Path[1] | byte (4) | Derivation Path Data | 0x80000000 \| 626 |
| Path[2] | byte (4) | Derivation Path Data | ?                 |
| Path[3] | byte (4) | Derivation Path Data | ?                 |
| Path[4] | byte (4) | Derivation Path Data | ?                 |

##### Other Chunks/Packets

| Field   | Type     | Content         | Expected                  |
| ------- | -------- | --------------- | ------------------------- |
| Message | byte (?) | Message to Sign | hexadecimal string (utf8) |

#### Response

| Field   | Type      | Content     | Note                     |
| ------- | --------- | ----------- | ------------------------ |
| SIG     | byte (64) | Signature   |                          |
| SW1-SW2 | byte (2)  | Return code | see list of return codes |

---

### INS_SIGN_HASH

#### Command

| Field | Type     | Content                | Expected                                                              |
| ----- | -------- | ---------------------- | --------------------------------------------------------------------- |
| CLA   | byte (1) | Application Identifier | 0x00                                                                  |
| INS   | byte (1) | Instruction ID         | 0x23                                                                  |
| P1    | byte (1) | ----                   | First packet = 0x00 / More packets coming = 0x01 / Last packet = 0x02 |
| P2    | byte (1) | ----                   | not used                                                              |
| L     | byte (1) | Bytes in payload       | (depends)                                                             |

For the new app, the first packet/chunk includes only the derivation path

All other packets/chunks contain data chunks that are described below

##### First Packet

| Field   | Type     | Content              | Expected          |
| ------- | -------- | -------------------- | ----------------- |
| Path[0] | byte (4) | Derivation Path Data | 0x80000000 \| 44  |
| Path[1] | byte (4) | Derivation Path Data | 0x80000000 \| 626 |
| Path[2] | byte (4) | Derivation Path Data | ?                 |
| Path[3] | byte (4) | Derivation Path Data | ?                 |
| Path[4] | byte (4) | Derivation Path Data | ?                 |

##### Other Chunks/Packets

| Field   | Type      | Content         | Expected |
| ------- | --------- | --------------- | -------- |
| Hash    | byte (32) | Tx Hash to Sign |          |

#### Response

| Field   | Type      | Content     | Note                     |
| ------- | --------- | ----------- | ------------------------ |
| SIG     | byte (64) | Signature   |                          |
| SW1-SW2 | byte (2)  | Return code | see list of return codes |

---

### INS_SIGN_TRANSFER

#### Command

| Field | Type     | Content                | Expected                                                              |
| ----- | -------- | ---------------------- | --------------------------------------------------------------------- |
| CLA   | byte (1) | Application Identifier | 0x00                                                                  |
| INS   | byte (1) | Instruction ID         | 0x24                                                                  |
| P1    | byte (1) | ----                   | First packet = 0x00 / More packets coming = 0x01 / Last packet = 0x02 |
| P2    | byte (1) | ----                   | not used                                                              |
| L     | byte (1) | Bytes in payload       | (depends)                                                             |

For the new app, the first packet/chunk includes only the derivation path

All other packets/chunks contain data chunks that are described below


##### First Packet

| Field   | Type     | Content              | Expected          |
| ------- | -------- | -------------------- | ----------------- |
| Path[0] | byte (4) | Derivation Path Data | 0x80000000 \| 44  |
| Path[1] | byte (4) | Derivation Path Data | 0x80000000 \| 626 |
| Path[2] | byte (4) | Derivation Path Data | ?                 |
| Path[3] | byte (4) | Derivation Path Data | ?                 |
| Path[4] | byte (4) | Derivation Path Data | ?                 |

##### Other Chunks/Packets

| Field               | Type                        | Content                     | Expected            |
|---------------------|---------------------------- |---------------------------- |-------------------- |
| tx_type             | byte (1)                    | Transaction Type            | see list of Tx type |
| recipient_len       | byte (1)                    | Recipient Length            |                     |
| recipient           | byte (recipient_len)        | Recipient Pubkey            | should be 64 bytes  |
| recipient_chain_len | byte (1)                    | Recipient Chain Length      |                     |
| recipient_chain     | byte (recipient_chain_len)  | Recipient Chain             | (0..2)              |
| network_len         | byte (1)                    | Network Length              |                     |
| network             | byte (network_len)          | Network                     | (0..20)             |
| amount_len          | byte (1)                    | Amount Length               |                     |
| amount              | byte (amount_len)           | Amount                      | (0..32)             |
| namespace_len       | byte (1)                    | Namespace Length            |                     |
| namespace           | byte (namespace_len)        | Namespace                   | (0..63)             |
| module_len          | byte (1)                    | Module Length               |                     |
| module              | byte (module_len)           | Module                      | (0..32)             |
| gas_price_len       | byte (1)                    | Gas Price Length            |                     |
| gas_price           | byte (gas_price_len)        | Gas Price                   | (0..20)             |
| gas_limit_len       | byte (1)                    | Gas Limit Length            |                     |
| gas_limit           | byte (gas_limit_len)        | Gas Limit                   | (0..10)             |
| creation_time_len   | byte (1)                    | Creation Time Length        |                     |
| creation_time       | byte (creation_time_len)    | Creation Time               | (0..12)             |
| chain_id_len        | byte (1)                    | Chain Id Length             |                     |
| chain_id            | byte (chain_id_len)         | Chain Id                    | (0..2)              |
| nonce_len           | byte (1)                    | Nonce Length                |                     |
| nonce               | byte (nonce_len)            | Nonce                       | (0..32)             |
| ttl_len             | byte (1)                    | TTL Length                  |                     |
| ttl                 | byte (ttl_len)              | TTL                         | (0..20)             |

Each field is also validated by content (see **Signing policy (v1.3.2)**): the recipient is
lowercase hex, numeric fields are well-formed numbers, and no field may contain a quote, backslash
or other character that would change the structure of the signed JSON.

#### Tx type

| Tx type     | Description           |
| ----------- | --------------------- |
| 0           | Transfer              |
| 1           | Transfer Create       |
| 2           | Cross-Chain Transfer  |

#### Response

| Field   | Type      | Content     | Note                     |
| ------- | --------- | ----------- | ------------------------ |
| SIG     | byte (64) | Signature   |                          |
| SW1-SW2 | byte (2)  | Return code | see list of return codes |


## Legacy Command definition

### BCOMP_GET_VERSION

#### Command

| Field | Type     | Content                | Expected                   |
| ----- | -------- | ---------------------- | -------------------------- |
| CLA   | byte (1) | Application Identifier | 0x00                       |
| INS   | byte (1) | Instruction ID         | 0x00                       |
| P1    | byte (1) | Parameter 1            | ignored                    |
| P2    | byte (1) | Parameter 2            | ignored                    |
| L     | byte (1) | Bytes in payload       | 0                          |

#### Response

| Field      | Type     | Content          | Note                            |
| ---------- | -------- | ---------------- | ------------------------------- |
| MAJOR      | byte (1) | Version Major    | 0..255                          |
| MINOR      | byte (1) | Version Minor    | 0..255                          |
| PATCH      | byte (1) | Version Patch    | 0..255                          |
| SW1-SW2    | byte (2) | Return code      | see list of return codes        |

---

### BCOMP_VERIFY_ADDRESS

Same as [BCOMP_GET_PUBKEY](#bcomp_get_pubkey) but requires user confirmation.

#### Command

| Field     | Type     | Content                    | Expected                   |
| --------- | -------- | -------------------------  | -------------------------- |
| CLA       | byte (1) | Application Identifier     | 0x00                       |
| INS       | byte (1) | Instruction ID             | 0x01                       |
| P1        | byte (1) | Parameter 1                | ignored                    |
| P2        | byte (1) | Parameter 2                | ignored                    |
| L         | byte (1) | Bytes in payload           | (depends)                  |
| N         | byte (1) | Number of derivation steps | (depends)                  |
| Path[0]   | byte (4) | Derivation Path Data       | 0x80000000 \| 44           |
| Path[1]   | byte (4) | Derivation Path Data       | 0x80000000 \| 626          |
| Path[2]   | byte (4) | Derivation Path Data       | ?                          |
| .......   | .......  | .....................      | ?                          |
| Path[N-1] | byte (4) | Derivation Path Data       | ?                          |

#### Response

| Field   | Type      | Content     | Note                     |
| ------- | --------- | ----------- | ------------------------ |
| PK      | byte (32) | Public Key  |                          |
| SW1-SW2 | byte (2)  | Return code | see list of return codes |

---

### BCOMP_GET_PUBKEY

#### Command

| Field     | Type     | Content                    | Expected                   |
| --------- | -------- | -------------------------  | -------------------------- |
| CLA       | byte (1) | Application Identifier     | 0x00                       |
| INS       | byte (1) | Instruction ID             | 0x02                       |
| P1        | byte (1) | Parameter 1                | ignored                    |
| P2        | byte (1) | Parameter 2                | ignored                    |
| L         | byte (1) | Bytes in payload           | (depends)                  |
| N         | byte (1) | Number of derivation steps | (depends)                  |
| Path[0]   | byte (4) | Derivation Path Data       | 0x80000000 \| 44           |
| Path[1]   | byte (4) | Derivation Path Data       | 0x80000000 \| 626          |
| Path[2]   | byte (4) | Derivation Path Data       | ?                          |
| .......   | .......  | .....................      | ?                          |
| Path[N-1] | byte (4) | Derivation Path Data       | ?                          |

#### Response

| Field   | Type      | Content     | Note                     |
| ------- | --------- | ----------- | ------------------------ |
| PK      | byte (32) | Public Key  |                          |
| SW1-SW2 | byte (2)  | Return code | see list of return codes |

---

### BCOMP_SIGN_JSON_TX

Sign a Transaction in JSON format encoded in hexadecimal string (utf8), using the key for the given derivation path

#### Command

| Field | Type     | Content                | Expected                   |
| ----- | -------- | ---------------------- | -------------------------- |
| CLA   | byte (1) | Application Identifier | 0x00                       |
| INS   | byte (1) | Instruction ID         | 0x03                       |
| P1    | byte (1) | ----                   | not used                   |
| P2    | byte (1) | ----                   | not used                   |
| L     | byte (1) | Bytes in payload       | (depends)                  |

##### Input data

| Field     | Type          | Content                           | Expected          |
| --------- | ------------- | --------------------------------- | ----------------- |
| tx_size   | byte (4)      | Size of transaction               | u32               |
| tx        | byte(tx_size) | Transaction in hexadecimal string | ?                 |
| N         | byte (1)      | Number of derivation steps        | (depends)         |
| Path[0]   | byte (4)      | Derivation Path Data              | 0x80000000 \| 44  |
| Path[1]   | byte (4)      | Derivation Path Data              | 0x80000000 \| 626 |
| Path[2]   | byte (4)      | Derivation Path Data              | ?                 |
| .......   | ..........    | ........................          | ?                 |
| Path[N-1] | byte (4)      | Derivation Path Data              | ?                 |

#### Response

| Field   | Type      | Content     | Note                     |
| ------- | --------- | ----------- | ------------------------ |
| SIG     | byte (64) | Signature   |                          |
| SW1-SW2 | byte (2)  | Return code | see list of return codes |

---

### BCOMP_SIGN_TX_HASH

Sign a transaction hash using the key for the specified derivation path. The Blind signing setting must be enabled on the Ledger app.

#### Command

| Field | Type     | Content                | Expected                   |
| ----- | -------- | ---------------------- | -------------------------- |
| CLA   | byte (1) | Application Identifier | 0x00                       |
| INS   | byte (1) | Instruction ID         | 0x04                       |
| P1    | byte (1) | ----                   | not used                   |
| P2    | byte (1) | ----                   | not used                   |
| L     | byte (1) | Bytes in payload       | (depends)                  |

##### Input data

| Field     | Type          | Content                           | Expected          |
| --------- | ------------- | --------------------------------- | ----------------- |
| tx_hash   | byte (32)     | Transaction hash                  | ?                 |
| N         | byte (1)      | Number of derivation steps        | (depends)         |
| Path[0]   | byte (4)      | Derivation Path Data              | 0x80000000 \| 44  |
| Path[1]   | byte (4)      | Derivation Path Data              | 0x80000000 \| 626 |
| Path[2]   | byte (4)      | Derivation Path Data              | ?                 |
| .......   | ..........    | ........................          | ?                 |
| Path[N-1] | byte (4)      | Derivation Path Data              | ?                 |

#### Response

| Field   | Type      | Content     | Note                     |
| ------- | --------- | ----------- | ------------------------ |
| SIG     | byte (64) | Signature   |                          |
| SW1-SW2 | byte (2)  | Return code | see list of return codes |

---

### BCOMP_MAKE_TRANSFER_TX

Builds a transfer transaction using the input data, and provides a signature for it.

#### Command

| Field | Type     | Content                | Expected                   |
| ----- | -------- | ---------------------- | -------------------------- |
| CLA   | byte (1) | Application Identifier | 0x00                       |
| INS   | byte (1) | Instruction ID         | 0x10                       |
| P1    | byte (1) | ----                   | not used                   |
| P2    | byte (1) | ----                   | not used                   |
| L     | byte (1) | Bytes in payload       | (depends)                  |
##### Input data

| Field               | Type                        | Content                     | Expected            |
| ------------------- | --------------------------- | --------------------------- | ------------------- |
| N                   | byte (1)                    | Number of derivation steps  | (depends)           |
| Path[0]             | byte (4)                    | Derivation Path Data        | 0x80000000 \| 44    |
| Path[1]             | byte (4)                    | Derivation Path Data        | 0x80000000 \| 626   |
| Path[2]             | byte (4)                    | Derivation Path Data        | ?                   |
| .................   | ........................... | ........................    | ?                   |
| Path[N-1]           | byte (4)                    | Derivation Path Data        | ?                   |
| tx_type             | byte (1)                    | Transaction Type            | see list of Tx type |
| recipient_len       | byte (1)                    | Recipient Length            |                     |
| recipient           | byte (recipient_len)        | Recipient Pubkey            | should be 64 bytes  |
| recipient_chain_len | byte (1)                    | Recipient Chain Length      |                     |
| recipient_chain     | byte (recipient_chain_len)  | Recipient Chain             | (0..2)              |
| network_len         | byte (1)                    | Network Length              |                     |
| network             | byte (network_len)          | Network                     | (0..20)             |
| amount_len          | byte (1)                    | Amount Length               |                     |
| amount              | byte (amount_len)           | Amount                      | (0..32)             |
| namespace_len       | byte (1)                    | Namespace Length            |                     |
| namespace           | byte (namespace_len)        | Namespace                   | (0..63)             |
| module_len          | byte (1)                    | Module Length               |                     |
| module              | byte (module_len)           | Module                      | (0..32)             |
| gas_price_len       | byte (1)                    | Gas Price Length            |                     |
| gas_price           | byte (gas_price_len)        | Gas Price                   | (0..20)             |
| gas_limit_len       | byte (1)                    | Gas Limit Length            |                     |
| gas_limit           | byte (gas_limit_len)        | Gas Limit                   | (0..10)             |
| creation_time_len   | byte (1)                    | Creation Time Length        |                     |
| creation_time       | byte (creation_time_len)    | Creation Time               | (0..12)             |
| chain_id_len        | byte (1)                    | Chain Id Length             |                     |
| chain_id            | byte (chain_id_len)         | Chain Id                    | (0..2)              |
| nonce_len           | byte (1)                    | Nonce Length                |                     |
| nonce               | byte (nonce_len)            | Nonce                       | (0..32)             |
| ttl_len             | byte (1)                    | TTL Length                  |                     |
| ttl                 | byte (ttl_len)              | TTL                         | (0..20)             |

Each field is also validated by content (see **Signing policy (v1.3.2)**): the recipient is
lowercase hex, numeric fields are well-formed numbers, and no field may contain a quote, backslash
or other character that would change the structure of the signed JSON.

#### Tx type

| Tx type     | Description           |
| ----------- | --------------------- |
| 0           | Transfer              |
| 1           | Transfer Create       |
| 2           | Cross-Chain Transfer  |

#### Response

| Field   | Type      | Content                     | Note                     |
| ------- | --------- | --------------------------- | ------------------------ |
| SIG     | byte (64) | Signature                   |                          |
| PK      | byte (32) | Public key used for signing |                          |
| SW1-SW2 | byte (2)  | Return code                 | see list of return codes |

