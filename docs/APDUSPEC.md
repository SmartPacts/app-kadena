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
| 0x5515      | Device is locked        |

While the device is PIN-locked, Ledger's Rust SDK (since 1.37.1) answers every APDU with 0x5515 before the
app sees it. So the app's own 0x6986 for a command sent without a validated PIN, and a LOCKED byte other than
0x00 in the GET_VERSION reply, cannot be observed on a device.

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
| TEST       | byte (1) | Test Mode        | 0x00 (always, in release builds) |
| MAJOR      | byte (2) | Version Major    | 0..65535                        |
| MINOR      | byte (2) | Version Minor    | 0..65535                        |
| PATCH      | byte (2) | Version Patch    | 0..65535                        |
| LOCKED     | byte (1) | Device is locked | 0x00 (a locked device answers 0x5515) |
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

Sign a Pact command JSON with the key for the path of the first packet. The device reviews the signer entry that
carries that key (it must be the only one); a transaction whose signature no displayed capability list bounds
needs the "Blind signing" setting (see differences 9-12 below).

#### Command

| Field | Type     | Content                | Expected                                                              |
| ----- | -------- | ---------------------- | --------------------------------------------------------------------- |
| CLA   | byte (1) | Application Identifier | 0x00                                                                  |
| INS   | byte (1) | Instruction ID         | 0x22                                                                  |
| P1    | byte (1) | ----                   | First packet = 0x00 / More packets coming = 0x01 / Last packet = 0x02 |
| P2    | byte (1) | ----                   | not used                                                              |
| L     | byte (1) | Bytes in payload       | (depends)                                                             |

For the new app, the first packet/chunk includes only the derivation path: exactly 20 bytes are used,
any further bytes in that packet are ignored (not appended to the message).

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
| Message | byte (?) | Message to Sign | the Pact command JSON, raw UTF-8 bytes (not hex) |

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
| L     | byte (1) | Bytes in payload       | any (ignored; hosts send 1)|

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

| Field   | Type      | Content           | Note                     |
| ------- | --------- | ----------------- | ------------------------ |
| PK_LEN  | byte (1)  | Public key length | 0x20                     |
| PK      | byte (32) | Public Key        |                          |
| SW1-SW2 | byte (2)  | Return code       | see list of return codes |

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

N must be 2 to 5 (else 0x6984) and the payload must hold exactly N components (else 0x6700).
A shorter path is padded with zero components: `m/44'/626'` derives `m/44'/626'/0/0/0`.

#### Response

| Field   | Type      | Content           | Note                     |
| ------- | --------- | ----------------- | ------------------------ |
| PK_LEN  | byte (1)  | Public key length | 0x20                     |
| PK      | byte (32) | Public Key        |                          |
| SW1-SW2 | byte (2)  | Return code       | see list of return codes |

---

### BCOMP_SIGN_JSON_TX

Sign a transaction given as the raw UTF-8 bytes of the Pact command JSON, using the key for the given derivation path.
The path bytes are not part of the signed message. The same review rules as INS_SIGN apply.

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
| tx        | byte(tx_size) | Transaction JSON (raw UTF-8 bytes)| ?                 |
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

Sign a transaction hash using the key for the specified derivation path. The "Blind signing" setting must be ON
(it is OFF on install); otherwise the device shows a warning and answers `Blind signing mode required` + 0x6984.

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


---

## Chunking of the legacy signing commands

The host sends the legacy payloads (0x03, 0x04, 0x10) in slices of 230 bytes with P1 = P2 = 0. A command
is complete when an APDU carries fewer than 230 data bytes, or (0x03, 0x04) when the buffer holds exactly
the payload plus the path. Every other APDU is answered 0x9000 with no data.

## Refusals

Parse errors of 0x22, 0x23, 0x24 and 0x04 answer the ASCII error text followed by 0x6984, for example
`Unexpected characters` 0x6984; legacy 0x03 and 0x10 answer a bare 0x6984, except `Blind signing mode
required`, which 0x03 answers with its text as 0x04 does. The texts are:
`Initialized empty context`, `Unexpected buffer end`, `Unexpected value`, `Unexpected unparsed bytes`,
`Value out of range`, `Unexpected characters`, `NOMEM: JSON string contains too many tokens`,
`Unexpected duplicated field`, `Blind signing mode required`, `Device key is not a signer`,
`Device key signs more than once`, `Unrecognized error code`.

A JSON transaction is limited to 15104 bytes and to 768 JSON tokens (110 on Nano X).

## Differences from the C implementation (v1.3.0)

Version 2.0.0 is a Rust implementation that answers every command byte for byte like the C app v1.3.0,
except for these intended changes:

1. **Legacy 0x10:** an item whose length points past the bytes received in its APDU is refused with 0x6700.
   The C app could sign bytes left over from an earlier command in their place.
2. **Structured transfers (0x24, 0x10):** each field must match its allowed characters, or the command is
   refused with `Unexpected characters` 0x6984 (bare 0x6984 on 0x10):

   | Field | Allowed |
   |---|---|
   | recipient | lowercase hexadecimal digits (exactly 64) |
   | chain_id | one or more digits |
   | recipient_chain | one or more digits on a cross-chain transfer (type 2); digits, or empty, otherwise (unused) |
   | network | letters, digits, `-`, `_`, `.` |
   | amount, gas_limit, creation_time, ttl | a number: digits, then optionally `.` and digits |
   | gas_price | a number as above, then optionally `e` or `E`, an optional `+` or `-`, and digits |
   | namespace, module | letters, digits and `%#+-_&$@<>=?*!\|/` |
   | nonce | printable ASCII except `"` and `\` |

   The C app pasted the fields into the JSON unchecked, so a `"` could add JSON keys the screen never shows,
   and an empty or malformed number made JSON that no node accepts.
3. **Transfer not naming the key:** a `coin.TRANSFER` argument matches the signer key only if it is exactly the
   key or `k:` followed by exactly the key. The C app compared only the key's length, so a longer account that
   merely started with the key hid the warning. When no transfer names the key the item is titled "Key not in
   transfer" (the C app titled it "Unscoped Signer", though the signature is scoped); "Unscoped Signer" is shown
   only for a signer entry without capabilities (10).
4. **Duplicate JSON keys:** an object, at any depth, holding the same key twice (byte for byte; escaped keys are
   refused first, see 18) is refused with `Unexpected duplicated field` 0x6984 (bare 0x6984 on 0x03).
5. **Command streams:** a 0x22/0x23/0x24 first chunk (P1 = 0) closes any stream in progress, of either family;
   a 0x22/0x23/0x24 chunk with P1 = 1 or 2 is refused with 0x6987 unless a stream of the same INS is open.
6. **INS 0xFF** stays unsupported (0x6D00), as in the C app.
7. **The signing key is bound to the command:** the path given by the signing command itself (the first packet of
   0x22/0x23/0x24 and 0x10, the path after the payload of 0x03/0x04) is the one that signs. An address command
   sent in the middle of a signing command (for example 0x02 for another path) does not change it. The C app kept
   one path for all commands, so a 0x02 between the first and last packet changed the key that signed.
8. **One command per stream:** every packet of a stream must carry the INS of its first packet. A 0x22/0x23/0x24
   packet with another INS, a legacy packet while another command's stream is open, or a modern packet during a
   legacy stream is refused with 0x6987 and closes the open stream. The C app decided how to read the buffer from
   the last packet's INS, so a 0x22 transaction finished with 0x23 was read as a hash.
9. **The review is of the device's own signer entry (JSON, 0x22 and 0x03):** exactly one entry of `signers` must
   name the device key (the key of the signing path, as 64 lowercase hex digits), as its `pubKey` or `addr`, in any
   letter case, and that entry's `pubKey` must be exactly that text. Its capabilities are the ones reviewed, and
   "Of Key" shows it. When there is more than one entry, a "Signers" item shows how many. Otherwise the command
   is refused with 0x6984 and `Device key is not a signer` (no entry, or not exact) or `Device key signs more
   than once` (two or more entries); key names or `pubKey`/`addr` values written with JSON escapes inside a
   signer entry are refused with `Unexpected characters`. On 0x03 the reply is a bare 0x6984. The C app reviewed
   `signers[0]` whatever key it carried, while Pact gives the signature the scope of the entry keyed by the
   signing key, the last one if there are several.
10. **An empty clist is unscoped:** `"clist": []` is reviewed like a missing or `null` clist (Pact reads all three
    as a signature valid for any capability): "Unscoped Signer" and the unsafe-transaction WARNING. The C app
    showed neither for `[]`.
11. **Blind signing for unbounded JSON signatures:** a JSON transaction (0x22, 0x03) whose review carries the
    unsafe-transaction WARNING (unscoped signer), the "too large to display" WARNING, or the `meta` CAUTION is
    blind signing. With the "Blind signing" setting OFF it is refused like a hash: the "Cannot clear-sign"
    screen ("Enable Blind signing in Settings to sign this transaction", with "Go to settings" and "Reject
    Transaction"), then `Blind signing mode required` 0x6984 (on 0x03 too). With the setting ON, the review opens with
    Ledger's blind-signing warning. Structured coin transfers (0x24, 0x10) are never blind (token transfers: 23). The C app
    signed these with the setting OFF.
12. **One JSON value:** a JSON document (0x22, 0x03) containing a NUL byte is refused with `Unexpected
    characters` 0x6984, and one with anything but whitespace after its top-level value with `Unexpected unparsed
    bytes` 0x6984 (bare 0x6984 on 0x03). The C app stopped reading at a NUL or after the first value, and signed
    the rest unseen.
13. **Screen text:** every byte of a displayed value outside printable ASCII (0x20-0x7E) is shown as `\xNN`, on
    every device; the signed bytes do not change. Kadena account names may contain C1 controls, NBSP and the soft
    hyphen, which a font can draw as nothing.
14. **Account rotation is blind signing:** if the device's signer entry holds a `coin.ROTATE` capability (any
    arguments), the review adds a WARNING "Account rotation: new owner not shown" and needs the "Blind signing"
    setting, as in difference 11. The new guard comes from the transaction's code and data, which the device does
    not show. The C app clear-signed it.
15. **Fee and payer:** when `meta` is recognised, the review adds "Max fee" (`KDA` followed by gasLimit × gasPrice,
    computed exactly in decimal from the JSON numbers, exponents included, without rounding) and "Paying account"
    (`meta.sender`, when present). `gasLimit`, `ttl` and `creationTime` must be plain digits (the node reads them
    as integers and would round a fraction), or the command is refused with `Unexpected characters` 0x6984; so
    "Max fee" is exactly the most the node charges. A gas price that is not a non-negative number, or a fee
    longer than a value can be (299 bytes), is refused like any value that cannot be displayed (`Unrecognized
    error code` 0x6984). Applies to 0x22, 0x03 and to structured transfers.
16. **Vanity receivers:** after a `coin.TRANSFER` (3 arguments) or `coin.TRANSFER_XCHAIN` (4 arguments) whose
    receiver is not a Pact principal (`k:`, `w:`, `r:`, `u:`, `m:`, `p:`, `c:` forms, as pact-5's
    `principalParser` reads them), the review adds a WARNING "Recipient is not a principal account": such an
    account may be created with a guard the review does not show. The review stays clear-signing.
17. (Replaced by 20.)
18. **No escaped keys:** an object key containing a backslash (a JSON escape), in any object of the document, and a
    backslash in a capability `name` of the device's signer entry, are refused with `Unexpected characters` 0x6984
    (bare 0x6984 on 0x03). The device finds members by raw key bytes, while the node's decoder unescapes keys and
    keeps one of two duplicates, so an escaped `"name"`, `"signers"` or `"meta"`, or `coin.\u0052OTATE`, could
    hide a transfer, a rotation or a fee. Keys are checked in document order, each against the earlier keys of its
    object (18, then 4). Escapes in values are allowed.
19. **Expert mode:** "Payload" shows `exec (code)` or `cont (continuation)`, and for a continuation "Pact ID" and
    "Step"; "Created (unix time)" and "TTL (seconds)" show `meta.creationTime` and `meta.ttl` as sent (the device
    has no clock).
20. **Only gas and coin transfers are clear-signed:** a JSON transaction (0x22, 0x03) is clear-signed only if
    every capability of the device's signer entry is `coin.GAS`, a `coin.TRANSFER` with 3 arguments or a `coin.TRANSFER_XCHAIN`
    with 4, all shown. Any other capability (for example `coin.DEBIT`, with which the transaction's code can move
    any amount from the account; `coin.CREDIT`; another `coin.*` capability; any capability of another module; a
    transfer with another number of arguments) is shown as separate items, each whole: "WARNING: Capability not
    verified", "Capability: <module>.<NAME>" (the name without its namespace), "Namespace: <namespace>" (only when
    the name has a namespace, so `none.coin.DEBIT` and `coin.DEBIT` never look alike), and "Arguments: <arguments>" (the C app's "Unknown Capability N" without the name). A namespaced
    name is never shown in one piece, where a page break would split the namespace's hex and hide a look-alike.
    Such a capability makes the review a blind-signing one, as in 11 (`coin.ROTATE` has its own warning, 14). While such a
    capability is in scope, any code the transaction runs can use the key wherever a guard is checked outside
    capability evaluation, including taking over accounts it guards. Structured token transfers: 23.
    The name without its namespace and the namespace are each at most 299 bytes, or the transaction is refused.
21. **No exponent amounts:** a `coin.TRANSFER` / `coin.TRANSFER_XCHAIN` amount written in exponent notation is
    refused with `Unexpected characters` 0x6984 (bare on 0x03): `1.0000000001e3` reads as about 1 but is
    1000.0000001. (Superseded by the stricter 24.)
22. **No verifiers:** a command with a `verifiers` field (Pact 5 signature verifiers, which can grant
    capabilities the review cannot show) is refused with `Unexpected value` 0x6984 (bare on 0x03).
23. **Structured token transfers are blind signing:** a structured transfer (0x24, 0x10) with a namespace and
    module (a token transfer, for example kb-USDC) scopes the signature to `<namespace>.<module>.TRANSFER` (or
    `TRANSFER_XCHAIN`). While that capability is in scope, the token module's own code can use the key for any
    guard it checks outside a capability body (for example a coin-style `rotate` of an account the key guards),
    and the device cannot see that code. The review shows the capability as in 20 ("WARNING: Capability not
    verified", "Capability: <module>.TRANSFER", "Namespace: <namespace>", "Arguments") and is a blind-signing
    one: with the "Blind signing" setting OFF, the "Cannot clear-sign"
    screen and `Blind signing mode required` 0x6984 (on 0x10 too); ON, Ledger's blind-signing warning, then the
    review with the warning. Coin transfers (no namespace or module) stay clear-signed, without a warning. The
    C app clear-signed token transfers.
24. **Two amount forms:** a `coin.TRANSFER` / `coin.TRANSFER_XCHAIN` amount must be a bare JSON number, or
    Pact's decimal object with the single key `"decimal"` (a quoted key) and a string value
    (`{"decimal":"231"}`, as @kadena/client sends it), the number being `(0|[1-9][0-9]*)('.' [0-9]+)?` with at
    most 12 fractional digits (25). The review shows the number
    (`KDA 231`), never the object. Anything else is refused with `Unexpected characters` 0x6984 (bare on 0x03),
    whatever the settings: `{"int":...}`, a string, a sign, an exponent in either form, other or extra keys, a
    nested object, a non-string `decimal`, an unquoted key (`{decimal:"1.5"}`, which the node rejects), an empty
    string, a leading or trailing dot, a leading zero (`01.0`),
    or an escape (`{"decimal":"1\u0030\u0030\u0030.0"}` would read "1..." but is 1000.0 once the node decodes
    it). The same set as the C v1.3.1 patch. The C app v1.3.0 showed any amount as written. A coin structured
    transfer's amount follows the same grammar.
25. **At most 12 fractional digits:** a `coin.TRANSFER` / `coin.TRANSFER_XCHAIN` amount, in either form of 24
    and in a coin structured transfer (0x24, 0x10), has at most 12 fractional digits, coin's precision. More is
    refused with `Unexpected characters` 0x6984 (bare on 0x03 and 0x10): pact-5 rounds a JSON number at 255
    places, so `0.` followed by 256 nines, shown in full, would be read as 1.0. A token transfer's amount is not
    bounded here (each token has its own precision; it is blind signing, 23).
26. **Structured amounts have a fraction:** the amount of a structured transfer (0x24, 0x10) must have a
    fractional part (`1000.0`, not `1000`), since it is pasted into the code as is and Pact refuses an integer
    for `amount:decimal`; otherwise `Unexpected characters` 0x6984 (bare on 0x10). The C app signed such a
    transfer, which then failed on chain.
27. **`meta` keys in any order:** `meta` is recognised when its keys are `creationTime`, `ttl`, `gasLimit`,
    `chainId`, `gasPrice` and optionally `sender`, in any order, each once, with no other key (any other key,
    more than six keys, a key of 40 or more bytes, a `null` or missing `meta`: the CAUTION, as before). The
    presence rule is the one the C app's fixed order implied: a key is accepted only with every key before it
    in that list, so any set of keys gives the outcome its canonical order gives (the first one to four keys,
    or none, in any order: `Unrecognized error code` 0x6984, bare on 0x03; any other incomplete set: the
    CAUTION). For the C app v1.3.0 that refusal held for the canonical order only: the same keys in another
    order were shown with the CAUTION and signed. Every `meta` value the
    review shows or checks is read by its name. The C app v1.3.0 accepted only that order and showed any
    other with the CAUTION; `@kadena/client` writes `gasLimit`, `gasPrice`, `sender`, `ttl`, `creationTime`,
    `chainId`, so with 11 its plain coin transfers would have needed blind signing. They are clear-signed.
    Each WARNING of 14, 16, 20 and 23 is one review item; the review holds at most 99 items, as in the C app.
