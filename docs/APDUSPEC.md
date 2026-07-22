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
| TEST       | byte (1) | Test Mode        | 0xFF means test mode is enabled |
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

Sign a transaction hash using the key for the specified derivation path. Expert Mode must be enabled on the Ledger app.

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

