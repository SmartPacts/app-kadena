/*******************************************************************************
 *  (c) 2018 - 2024 Zondax AG
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 ********************************************************************************/

#include "parser_impl.h"

#include "buffering_json.h"
#include "crypto.h"
#include "crypto_helper.h"
#include "items.h"
#include "tx.h"
#include "zxformat.h"

#define RECIPIENT_POS 0
#define RECIPIENT_CHAIN_POS 1
#define NETWORK_POS 2
#define AMOUNT_POS 3
#define NAMESPACE_POS 4
#define MODULE_POS 5
#define GAS_PRICE_POS 6
#define GAS_LIMIT_POS 7
#define CREATION_TIME_POS 8
#define CHAIN_ID_POS 9
#define NONCE_POS 10
#define TTL_POS 11

#define ADDRESS_HEX_LEN 65
#define HASH_LEN 32

#define MAX_FIELDS_IN_INPUT_DATA 12
#define RECIPIENT_LEN 64
#define RECIPIENT_CHAIN_LEN 2
#define NETWORK_LEN 20
#define AMOUNT_LEN 32
#define NAMESPACE_LEN 63
#define MODULE_LEN 32
#define GAS_PRICE_LEN 20
#define GAS_LIMIT_LEN 10
#define CREATION_TIME_LEN 12
#define CHAIN_ID_LEN 2
#define NONCE_LEN 32
#define TTL_LEN 20

#define CMP_STRING_AND_BUFFER(str, buffer, len) (len == strlen(str) && MEMCMP(str, buffer, len) == 0)

static parser_error_t parser_readSingleByte(parser_context_t *ctx, uint8_t *byte);
static parser_error_t parser_readBytes(parser_context_t *ctx, uint8_t **bytes, uint16_t len);
static parser_error_t parser_formatTxTransfer(uint16_t address_len, char *address, chunk_t *chunks, uint8_t tx_type);
static parser_error_t parser_validate_chunks(chunk_t *chunks);
static parser_error_t parser_validate_chunk_contents(const chunk_t *chunks, uint8_t tx_type);

tx_json_t *parser_json_obj;
tx_hash_t *parser_hash_obj;

parser_error_t _read_json_tx(parser_context_t *c) {
    parser_json_obj = c->json;

    // parser_init_context never leaves an empty buffer here; refuse one anyway.
    if (c->buffer == NULL || c->bufferLen == 0) {
        return parser_no_data;
    }

    // Every signed byte must belong to the one JSON value that is reviewed. The tokenizer stops at a
    // NUL, so a NUL anywhere is refused first.
    if (memchr(c->buffer, '\0', c->bufferLen) != NULL) {
        return parser_unexpected_characters;
    }

    CHECK_ERROR(json_parse(&(parser_json_obj->json), (const char *)c->buffer, c->bufferLen));

    // Nothing but whitespace may follow the top-level value (the tokenizer accepts several values).
    const jsmntok_t *root = &parser_json_obj->json.tokens[0];
    // A string token's span excludes its closing quote.
    for (int i = root->end + (root->type == JSMN_STRING ? 1 : 0); i < (int)c->bufferLen; i++) {
        const char ch = (char)c->buffer[i];
        if (ch != ' ' && ch != '\t' && ch != '\n' && ch != '\r') {
            return parser_unexpected_unparsed_bytes;
        }
    }

    parser_json_obj->tx = (const char *)c->buffer;
    parser_json_obj->flags.cache_valid = 0;
    parser_json_obj->filter_msg_type_count = 0;
    parser_json_obj->filter_msg_from_count = 0;
    return parser_ok;
}

parser_error_t _read_hash_tx(parser_context_t *c) {
    if (c->bufferLen != HASH_LEN) {
        return parser_unexpected_buffer_end;
    }

    parser_hash_obj = c->hash;

    MEMZERO(parser_hash_obj, sizeof(tx_hash_t));

    parser_hash_obj->tx = (const char *)c->buffer;
    parser_hash_obj->hash_len = c->bufferLen;

    return parser_ok;
}

tx_json_t *parser_getParserJsonObj() { return parser_json_obj; }

tx_hash_t *parser_getParserHashObj() { return parser_hash_obj; }

// The signer entry the device signs for (see parser_findDeviceSigner) and the number of entries.
static uint16_t device_signer_token_index = 0;
static uint16_t signers_count = 0;

#if !defined(LEDGER_SPECIFIC)
// Host unit tests have no device key: they set the key the parser treats as the device's.
static char test_device_key_hex[ADDRESS_HEX_LEN] = "1234567890123456789012345678901234567890123456789012345678901234";

void parser_setTestDeviceKeyHex(const char *hex) { snprintf(test_device_key_hex, sizeof(test_device_key_hex), "%s", hex); }
#endif

// Lowercase hex of the device public key for the current path (hdPath). No user interaction.
static parser_error_t parser_getDeviceKeyHex(char *out, uint16_t outLen, uint16_t *len) {
#if defined(LEDGER_SPECIFIC)
    uint8_t pubkey[PUB_KEY_LENGTH] = {0};
    uint16_t pubkey_len = 0;

    if (crypto_fillAddress(pubkey, sizeof(pubkey), &pubkey_len) != zxerr_ok) {
        return parser_unexpected_error;
    }

    *len = array_to_hexstr(out, outLen, pubkey, PUB_KEY_LENGTH);
#else
    *len = snprintf(out, outLen, "%s", test_device_key_hex);
#endif
    return parser_ok;
}

static bool span_has_backslash(const parsed_json_t *json, uint16_t token_index) {
    const jsmntok_t *token = &json->tokens[token_index];
    for (int i = token->start; i < token->end; i++) {
        if (json->buffer[i] == '\\') {
            return true;
        }
    }
    return false;
}

static bool span_equals_ignore_case(const parsed_json_t *json, uint16_t token_index, const char *text, uint16_t len) {
    const jsmntok_t *token = &json->tokens[token_index];
    if (token->end - token->start != len) {
        return false;
    }
    for (uint16_t i = 0; i < len; i++) {
        char a = json->buffer[token->start + i];
        char b = text[i];
        if (a >= 'A' && a <= 'Z') {
            a = (char)(a - 'A' + 'a');
        }
        if (b >= 'A' && b <= 'Z') {
            b = (char)(b - 'A' + 'a');
        }
        if (a != b) {
            return false;
        }
    }
    return true;
}

static bool same_key_bytes(const parsed_json_t *json, uint16_t a, uint16_t b) {
    const jsmntok_t *ta = &json->tokens[a];
    const jsmntok_t *tb = &json->tokens[b];
    if (ta->end - ta->start != tb->end - tb->start) {
        return false;
    }
    return MEMCMP(json->buffer + ta->start, json->buffer + tb->start, ta->end - ta->start) == 0;
}

// The device finds an object member by comparing raw key bytes (json_parser.c), but a JSON decoder
// unescapes a key before it applies its duplicate-key rule. So an escaped spelling of a key
// ("signers", "name", "meta") would make the device read one member while the chain
// reads another, hiding a transfer, a rotation or a fee. Refuse any object key that contains a JSON
// escape, anywhere in the document. A literal duplicate key within one object is also refused: the
// device takes the first and a last-wins decoder takes the second (which rule a given decoder
// applies varies between JSON decoders, so either is possible). Values keep their escapes.
static parser_error_t parser_checkKeyIntegrity(const parsed_json_t *json) {
    const uint16_t ntok = json->numberOfTokens;
    for (uint16_t o = 0; o < ntok; o++) {
        if (json->tokens[o].type != JSMN_OBJECT) {
            continue;
        }
        const int obj_end = json->tokens[o].end;
        int prev_end = json->tokens[o].start;
        for (uint16_t i = o + 1; i + 1 < ntok; i++) {
            const jsmntok_t *key = &json->tokens[i];
            if (key->start > obj_end) {
                break;
            }
            if (key->start <= prev_end) {
                continue;  // a token nested inside an earlier member's value, not a direct key
            }
            prev_end = json->tokens[i + 1].end;  // this member's value ends here
            if (span_has_backslash(json, i)) {
                return parser_unexpected_characters;
            }
            // Compare against the earlier direct keys of this same object.
            int inner_prev = json->tokens[o].start;
            for (uint16_t j = o + 1; j < i; j++) {
                if (json->tokens[j].start <= inner_prev) {
                    continue;
                }
                inner_prev = json->tokens[j + 1].end;
                if (same_key_bytes(json, i, j)) {
                    return parser_duplicated_field;
                }
            }
        }
    }
    return parser_ok;
}

// Finds the one signer entry the device signs for. Pact keys each signature's scope by the
// entry's addr, else its pubKey, and a later entry with the same key replaces an earlier one, so
// the entry to review is the one naming the device key, and it must be the only entry naming it,
// as pubKey or addr, in any letter case. Its pubKey must be exactly the lowercase hex of the
// device key. Key names and key values inside signer entries must not use JSON escapes, which
// could hide a second entry from this raw-byte comparison.
parser_error_t parser_findDeviceSigner() {
    const parsed_json_t *json_all = &parser_json_obj->json;
    char device_hex[ADDRESS_HEX_LEN] = {0};
    uint16_t device_hex_len = 0;
    uint16_t signers_token_index = 0;
    uint16_t count = 0;
    uint16_t matches = 0;
    uint16_t found = 0;

    device_signer_token_index = 0;
    signers_count = 0;

    CHECK_ERROR(parser_checkKeyIntegrity(json_all));

    // Pact 5 signature verifiers can grant capabilities the review cannot show: refuse them.
    uint16_t verifiers_token_index = 0;
    if (object_get_value(json_all, 0, JSON_VERIFIERS, &verifiers_token_index) == parser_ok) {
        return parser_unexpected_value;
    }

    CHECK_ERROR(parser_getDeviceKeyHex(device_hex, sizeof(device_hex), &device_hex_len));
    if (device_hex_len != 2 * PUB_KEY_LENGTH) {
        return parser_unexpected_error;
    }

    if (object_get_value(json_all, 0, JSON_SIGNERS, &signers_token_index) != parser_ok ||
        json_all->tokens[signers_token_index].type != JSMN_ARRAY) {
        return parser_signer_not_found;
    }

    CHECK_ERROR(array_get_element_count(json_all, signers_token_index, &count));

    for (uint16_t i = 0; i < count; i++) {
        uint16_t entry = 0;
        uint16_t num_keys = 0;
        bool names_device = false;

        CHECK_ERROR(array_get_nth_element(json_all, signers_token_index, i, &entry));
        if (json_all->tokens[entry].type != JSMN_OBJECT) {
            continue;
        }

        CHECK_ERROR(object_get_element_count(json_all, entry, &num_keys));
        for (uint16_t k = 0; k < num_keys; k++) {
            uint16_t key = 0;
            CHECK_ERROR(object_get_nth_key(json_all, entry, k, &key));
            if (span_has_backslash(json_all, key)) {
                return parser_unexpected_characters;
            }
        }

        uint16_t value = 0;
        if (object_get_value(json_all, entry, JSON_PUBKEY, &value) == parser_ok) {
            if (span_has_backslash(json_all, value)) {
                return parser_unexpected_characters;
            }
            names_device = names_device || span_equals_ignore_case(json_all, value, device_hex, device_hex_len);
        }
        if (object_get_value(json_all, entry, JSON_ADDR, &value) == parser_ok) {
            if (span_has_backslash(json_all, value)) {
                return parser_unexpected_characters;
            }
            names_device = names_device || span_equals_ignore_case(json_all, value, device_hex, device_hex_len);
        }

        if (names_device) {
            matches++;
            found = entry;
        }
    }

    if (matches == 0) {
        return parser_signer_not_found;
    }
    if (matches > 1) {
        return parser_signer_repeated;
    }

    uint16_t pubkey_token_index = 0;
    if (object_get_value(json_all, found, JSON_PUBKEY, &pubkey_token_index) != parser_ok) {
        return parser_signer_not_found;
    }
    const jsmntok_t *pubkey_token = &json_all->tokens[pubkey_token_index];
    if (pubkey_token->type != JSMN_STRING || pubkey_token->end - pubkey_token->start != device_hex_len ||
        MEMCMP(json_all->buffer + pubkey_token->start, device_hex, device_hex_len) != 0) {
        return parser_signer_not_found;
    }

    // A capability name is compared by raw bytes (parser_getTxName), so an escape in the name of a
    // capability in the device's own entry would hide, for example, coin.ROTATE. Refuse it.
    uint16_t clist = 0;
    if (object_get_value(json_all, found, JSON_CLIST, &clist) == parser_ok && json_all->tokens[clist].type == JSMN_ARRAY) {
        uint16_t n = 0;
        CHECK_ERROR(array_get_element_count(json_all, clist, &n));
        for (uint16_t i = 0; i < n; i++) {
            uint16_t cap = 0;
            uint16_t name = 0;
            CHECK_ERROR(array_get_nth_element(json_all, clist, i, &cap));
            if (object_get_value(json_all, cap, JSON_NAME, &name) == parser_ok && span_has_backslash(json_all, name)) {
                return parser_unexpected_characters;
            }
        }
    }

    device_signer_token_index = found;
    signers_count = count;
    return parser_ok;
}

uint16_t parser_getDeviceSignerIndex() { return device_signer_token_index; }

uint16_t parser_getSignersCount() { return signers_count; }

parser_error_t parser_findPubKeyInClist(uint16_t key_token_index) {
    parsed_json_t *json_all = &parser_json_obj->json;
    uint16_t token_index = 0;
    uint16_t clist_token_index = 0;
    uint16_t args_token_index = 0;
    uint16_t number_of_args = 0;
    uint16_t clist_element_count = 0;
    jsmntok_t *value_token = NULL;
    jsmntok_t *key_token = NULL;

    if (parser_getValidClist(&clist_token_index, &clist_element_count) != parser_ok) {
        return parser_no_data;
    }

    for (uint16_t i = 0; i < clist_element_count; i++) {
        CHECK_ERROR(array_get_nth_element(json_all, clist_token_index, i, &args_token_index));
        CHECK_ERROR(object_get_value(json_all, args_token_index, JSON_ARGS, &args_token_index));
        CHECK_ERROR(array_get_element_count(json_all, args_token_index, &number_of_args));

        for (uint16_t j = 0; j < number_of_args; j++) {
            // Do not dereference a stale token_index if the lookup fails.
            if (array_get_nth_element(json_all, args_token_index, j, &token_index) != parser_ok) {
                continue;
            }
            value_token = &(json_all->tokens[token_index]);
            key_token = &(json_all->tokens[key_token_index]);
            const uint16_t key_len = key_token->end - key_token->start;
            const uint16_t value_len = value_token->end - value_token->start;
            uint8_t offset = 0;

            // Key could possibly be prefixed with "k:"
            if (value_len >= 2 && CMP_STRING_AND_BUFFER("k:", json_all->buffer + value_token->start, 2)) {
                offset = 2;
            }

            // Exact match only: an argument that merely starts with the key (the key followed by
            // more characters) is a different account and must not count as the signer.
            if (value_len - offset == key_len &&
                MEMCMP(json_all->buffer + key_token->start, json_all->buffer + value_token->start + offset, key_len) == 0) {
                return parser_ok;
            }
        }
    }

    return parser_no_data;
}

parser_error_t parser_arrayElementToString(uint16_t json_token_index, uint16_t element_idx, const char **outVal,
                                           uint8_t *outValLen) {
    uint16_t token_index = 0;
    parsed_json_t *json_all = &(parser_json_obj->json);
    jsmntok_t *token = NULL;
    uint16_t element_count = 0;

    CHECK_ERROR(array_get_element_count(json_all, json_token_index, &element_count));
    if (element_idx >= element_count) {
        return parser_no_data;
    }

    CHECK_ERROR(array_get_nth_element(json_all, json_token_index, element_idx, &token_index));
    token = &(json_all->tokens[token_index]);

    *outVal = json_all->buffer + token->start;
    *outValLen = token->end - token->start;

    return parser_ok;
}

parser_error_t parser_validateMetaField() {
    // Pointers in this table are link-time addresses; every access must go through PIC()
    static const char *const keywords[] = {JSON_CREATION_TIME, JSON_TTL,       JSON_GAS_LIMIT,
                                           JSON_CHAIN_ID,      JSON_GAS_PRICE, JSON_SENDER};
    char meta_curr_key[40];
    uint16_t meta_token_index = 0;
    uint16_t meta_num_elements = 0;
    uint16_t key_token_idx = 0;
    parsed_json_t *json_all = &(parser_json_obj->json);
    jsmntok_t *token = NULL;

    CHECK_ERROR(object_get_value(json_all, 0, JSON_META, &meta_token_index));

    if (items_isNullField(meta_token_index)) {
        return parser_no_data;
    }

    CHECK_ERROR(object_get_element_count(json_all, meta_token_index, &meta_num_elements));

    if (meta_num_elements > array_length(keywords)) {
        return parser_invalid_meta_field;
    }

    // The keys may come in any order (wallets do not all write the order above), each at most once
    // (duplicates are refused earlier). Every value is then looked up by its name.
    uint8_t present = 0;
    for (uint16_t i = 0; i < meta_num_elements; i++) {
        object_get_nth_key(json_all, meta_token_index, i, &key_token_idx);
        token = &(json_all->tokens[key_token_idx]);

        // Prevent buffer overflow in case of big key-value pair in meta field.
        if (token->end - token->start >= sizeof(meta_curr_key)) {
            return parser_invalid_meta_field;
        }

        MEMCPY(meta_curr_key, json_all->buffer + token->start, token->end - token->start);
        meta_curr_key[token->end - token->start] = '\0';

        uint8_t k = 0;
        while (k < array_length(keywords) && strcmp((const char *)PIC(keywords[k]), meta_curr_key) != 0) {
            k++;
        }
        if (k == array_length(keywords) || (present & (1U << k)) != 0) {
            return parser_invalid_meta_field;
        }
        present |= (uint8_t)(1U << k);

        MEMZERO(meta_curr_key, sizeof(meta_curr_key));
    }

    // The same keys must be present as when the order was fixed: a key is accepted only with every
    // key before it in the list above (so gasLimit, chainId and gasPrice, which the review reads,
    // come with creationTime and ttl; sender stays optional).
    if ((present & (uint8_t)(present + 1)) != 0) {
        return parser_invalid_meta_field;
    }

    return parser_ok;
}

parser_error_t parser_getTxName(uint16_t token_index) {
    parsed_json_t *json_all = &(parser_json_obj->json);

    if (object_get_value(json_all, token_index, JSON_NAME, &token_index) == parser_ok) {
        uint16_t len = 0;
        jsmntok_t *token = NULL;

        token = &(json_all->tokens[token_index]);

        len = token->end - token->start;

        if (len == 0) {
            return parser_no_data;
        }

        if (CMP_STRING_AND_BUFFER("coin.TRANSFER", json_all->buffer + token->start, len)) {
            return parser_name_tx_transfer;
        }
        if (CMP_STRING_AND_BUFFER("coin.TRANSFER_XCHAIN", json_all->buffer + token->start, len)) {
            return parser_name_tx_transfer_xchain;
        }
        if (CMP_STRING_AND_BUFFER("coin.ROTATE", json_all->buffer + token->start, len)) {
            return parser_name_rotate;
        }
        if (CMP_STRING_AND_BUFFER("coin.GAS", json_all->buffer + token->start, len)) {
            return parser_name_gas;
        }
    }

    return parser_no_data;
}

parser_error_t parser_getValidClist(uint16_t *clist_token_index, uint16_t *num_args) {
    parsed_json_t *json_all = &(parser_json_obj->json);

    // The capability list of the device's own signer entry (parser_findDeviceSigner), not signers[0].
    if (object_get_value(json_all, device_signer_token_index, JSON_CLIST, clist_token_index) == parser_ok) {
        if (!items_isNullField(*clist_token_index)) {
            CHECK_ERROR(array_get_element_count(json_all, *clist_token_index, num_args));
            // An empty list scopes nothing: Pact reads a missing, null or empty clist alike, as
            // a signature valid for any capability. Treat it as no clist (Unscoped + WARNING).
            if (*num_args > 0) {
                return parser_ok;
            }
        }
    }

    return parser_no_data;
}

bool items_isNullField(uint16_t json_token_index) {
    parsed_json_t *json_all = &(parser_getParserJsonObj()->json);
    jsmntok_t *token = &(json_all->tokens[json_token_index]);

    if (token->end - token->start != sizeof("null") - 1) {
        return false;
    }

    return CMP_STRING_AND_BUFFER("null", json_all->buffer + token->start, token->end - token->start);
}

parser_error_t parser_createJsonTemplate(parser_context_t *ctx) {
    uint8_t tx_type = 0;
    char address[ADDRESS_HEX_LEN] = {0};
    uint16_t address_len = 0;
    chunk_t chunks[MAX_FIELDS_IN_INPUT_DATA] = {0};

    CHECK_ERROR(parser_readSingleByte(ctx, &tx_type));

    // Reject an out-of-range tx_type up front. parser_formatTxTransfer's switch has no
    // default; an unhandled value would emit a template with no transfer verb (malformed).
    if (tx_type != TX_TYPE_TRANSFER && tx_type != TX_TYPE_TRANSFER_CREATE && tx_type != TX_TYPE_TRANSFER_CROSSCHAIN) {
        return parser_unexpected_value;
    }

    for (int i = 0; i < MAX_FIELDS_IN_INPUT_DATA; i++) {
        CHECK_ERROR(parser_readSingleByte(ctx, &chunks[i].len));
        if (chunks[i].len > 0) {
            CHECK_ERROR(parser_readBytes(ctx, (uint8_t **)&chunks[i].data, chunks[i].len));
        } else {
            chunks[i].data = (char *)"";
        }
    }

    if (ctx->offset != ctx->bufferLen) {
        return parser_unexpected_unparsed_bytes;
    }

    CHECK_ERROR(parser_validate_chunks(chunks));
    CHECK_ERROR(parser_validate_chunk_contents(chunks, tx_type));

    CHECK_ERROR(parser_getDeviceKeyHex(address, sizeof(address), &address_len));

    CHECK_ERROR(parser_formatTxTransfer(address_len, address, chunks, tx_type));

    return parser_ok;
}

static parser_error_t parser_readSingleByte(parser_context_t *ctx, uint8_t *byte) {
    if (ctx->offset >= ctx->bufferLen) {
        return parser_unexpected_buffer_end;
    }

    *byte = ctx->buffer[ctx->offset];
    ctx->offset++;
    return parser_ok;
}

static parser_error_t parser_readBytes(parser_context_t *ctx, uint8_t **bytes, uint16_t len) {
    if (ctx->offset + len > ctx->bufferLen) {
        return parser_unexpected_buffer_end;
    }

    *bytes = (uint8_t *)(ctx->buffer + ctx->offset);
    ctx->offset += len;
    return parser_ok;
}

// Append to the template buffer and FAIL CLOSED on a short write. buffering_json_append
// returns 0 (and appends nothing) when the buffer is full; a silently-truncated template
// would be re-parsed and SIGNED, so any short append must abort the whole transfer.
#define APPEND(data, length)                                     \
    do {                                                         \
        uint32_t __len = (uint32_t)(length);                     \
        if (tx_json_append((uint8_t *)(data), __len) != __len) { \
            return parser_unexpected_buffer_end;                 \
        }                                                        \
    } while (0)

static parser_error_t parser_formatTxTransfer(uint16_t address_len, char *address, chunk_t *chunks, uint8_t tx_type) {
    if (address == NULL || chunks == NULL) {
        return parser_unexpected_value;
    }

    // NAMESPACE_LEN + '.' + MODULE_LEN + NUL. The old +1 was one byte short at max caps
    // (63 + 1 + 32 = 96 chars need 97), silently truncating the last module char via snprintf.
    char namespace_and_module[NAMESPACE_LEN + 1 + MODULE_LEN + 1] = {0};
    if (chunks[NAMESPACE_POS].len > 0 && chunks[MODULE_POS].len > 0) {
        snprintf(namespace_and_module, sizeof(namespace_and_module), "%.*s.%.*s", chunks[NAMESPACE_POS].len,
                 chunks[NAMESPACE_POS].data, chunks[MODULE_POS].len, chunks[MODULE_POS].data);
    } else {
        snprintf(namespace_and_module, sizeof(namespace_and_module), "%s", "coin");
    }

    APPEND((uint8_t *)"{\"networkId\":\"", 14);
    APPEND((uint8_t *)chunks[NETWORK_POS].data, chunks[NETWORK_POS].len);
    APPEND((uint8_t *)"\",\"payload\":{\"exec\":{\"data\":", 28);

    if (tx_type == TX_TYPE_TRANSFER) {
        APPEND((uint8_t *)"{}", 2);
    } else {
        APPEND((uint8_t *)"{\"ks\":{\"pred\":\"keys-all\",\"keys\":[\"", 34);
        APPEND((uint8_t *)chunks[RECIPIENT_POS].data, chunks[RECIPIENT_POS].len);
        APPEND((uint8_t *)"\"]}}", 4);
    }

    APPEND((uint8_t *)",\"code\":\"(", 10);
    APPEND((uint8_t *)namespace_and_module, strlen(namespace_and_module));

    switch (tx_type) {
        case TX_TYPE_TRANSFER:
            APPEND((uint8_t *)".transfer", 9);
            break;
        case TX_TYPE_TRANSFER_CREATE:
            APPEND((uint8_t *)".transfer-create", 16);
            break;
        case TX_TYPE_TRANSFER_CROSSCHAIN:
            APPEND((uint8_t *)".transfer-crosschain", 20);
            break;
    }

    APPEND((uint8_t *)" \\\"k:", 5);
    APPEND((uint8_t *)address, address_len);
    APPEND((uint8_t *)"\\\" \\\"k:", 7);
    APPEND((uint8_t *)chunks[RECIPIENT_POS].data, chunks[RECIPIENT_POS].len);
    APPEND((uint8_t *)"\\\"", 2);

    if (tx_type != TX_TYPE_TRANSFER) {
        APPEND((uint8_t *)" (read-keyset \\\"ks\\\")", 21);
    }

    if (tx_type == TX_TYPE_TRANSFER_CROSSCHAIN) {
        APPEND((uint8_t *)" \\\"", 3);
        APPEND((uint8_t *)chunks[RECIPIENT_CHAIN_POS].data, chunks[RECIPIENT_CHAIN_POS].len);
        APPEND((uint8_t *)"\\\"", 2);
    }

    APPEND((uint8_t *)" ", 1);
    APPEND((uint8_t *)chunks[AMOUNT_POS].data, chunks[AMOUNT_POS].len);
    APPEND((uint8_t *)")\"}},\"signers\":[{\"pubKey\":\"", 27);
    APPEND((uint8_t *)address, address_len);
    APPEND((uint8_t *)"\",\"clist\":[{\"args\":[\"k:", 23);
    APPEND((uint8_t *)address, address_len);
    APPEND((uint8_t *)"\",\"k:", 5);
    APPEND((uint8_t *)chunks[RECIPIENT_POS].data, chunks[RECIPIENT_POS].len);
    APPEND((uint8_t *)"\",", 2);
    APPEND((uint8_t *)chunks[AMOUNT_POS].data, chunks[AMOUNT_POS].len);

    if (tx_type == TX_TYPE_TRANSFER_CROSSCHAIN) {
        APPEND((uint8_t *)",\"", 2);
        APPEND((uint8_t *)chunks[RECIPIENT_CHAIN_POS].data, chunks[RECIPIENT_CHAIN_POS].len);
        APPEND((uint8_t *)"\"", 1);
    }

    APPEND((uint8_t *)"],\"name\":\"", 10);
    APPEND((uint8_t *)namespace_and_module, strlen(namespace_and_module));
    APPEND((uint8_t *)".TRANSFER", 9);

    if (tx_type == TX_TYPE_TRANSFER_CROSSCHAIN) {
        APPEND((uint8_t *)"_XCHAIN", 7);
    }

    APPEND((uint8_t *)"\"},{\"args\":[],\"name\":\"coin.GAS\"}]}],\"meta\":{\"creationTime\":", 59);
    APPEND((uint8_t *)chunks[CREATION_TIME_POS].data, chunks[CREATION_TIME_POS].len);
    APPEND((uint8_t *)",\"ttl\":", 7);
    APPEND((uint8_t *)chunks[TTL_POS].data, chunks[TTL_POS].len);
    APPEND((uint8_t *)",\"gasLimit\":", 12);
    APPEND((uint8_t *)chunks[GAS_LIMIT_POS].data, chunks[GAS_LIMIT_POS].len);
    APPEND((uint8_t *)",\"chainId\":\"", 12);
    APPEND((uint8_t *)chunks[CHAIN_ID_POS].data, chunks[CHAIN_ID_POS].len);
    APPEND((uint8_t *)"\",\"gasPrice\":", 13);
    APPEND((uint8_t *)chunks[GAS_PRICE_POS].data, chunks[GAS_PRICE_POS].len);
    APPEND((uint8_t *)",\"sender\":\"k:", 13);
    APPEND((uint8_t *)address, address_len);
    APPEND((uint8_t *)"\"},\"nonce\":\"", 12);
    APPEND((uint8_t *)chunks[NONCE_POS].data, chunks[NONCE_POS].len);
    APPEND((uint8_t *)"\"}", 2);

    return parser_ok;
}

#undef APPEND

static parser_error_t parser_validate_chunks(chunk_t *chunks) {
    if (chunks[RECIPIENT_POS].len != RECIPIENT_LEN) {
        return parser_value_out_of_range;
    }
    if (chunks[RECIPIENT_CHAIN_POS].len > RECIPIENT_CHAIN_LEN) {
        return parser_value_out_of_range;
    }
    if (chunks[NETWORK_POS].len > NETWORK_LEN) {
        return parser_value_out_of_range;
    }
    if (chunks[AMOUNT_POS].len > AMOUNT_LEN) {
        return parser_value_out_of_range;
    }
    if (chunks[NAMESPACE_POS].len > NAMESPACE_LEN) {
        return parser_value_out_of_range;
    }
    if (chunks[MODULE_POS].len > MODULE_LEN) {
        return parser_value_out_of_range;
    }
    if (chunks[GAS_PRICE_POS].len > GAS_PRICE_LEN) {
        return parser_value_out_of_range;
    }
    if (chunks[GAS_LIMIT_POS].len > GAS_LIMIT_LEN) {
        return parser_value_out_of_range;
    }
    if (chunks[CREATION_TIME_POS].len > CREATION_TIME_LEN) {
        return parser_value_out_of_range;
    }
    if (chunks[CHAIN_ID_POS].len > CHAIN_ID_LEN) {
        return parser_value_out_of_range;
    }
    if (chunks[NONCE_POS].len > NONCE_LEN) {
        return parser_value_out_of_range;
    }
    if (chunks[TTL_POS].len > TTL_LEN) {
        return parser_value_out_of_range;
    }
    return parser_ok;
}

static bool is_digit(char c) { return c >= '0' && c <= '9'; }

static bool is_alnum(char c) { return is_digit(c) || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z'); }

// Number of ASCII digits at the start of v.
static uint8_t count_digits(const char *v, uint8_t len) {
    uint8_t n = 0;
    while (n < len && is_digit(v[n])) {
        n++;
    }
    return n;
}

static bool all_digits(const char *v, uint8_t len) { return count_digits(v, len) == len; }

// digits ('.' digits)?  -- no sign, no lone or trailing '.'
static bool is_decimal(const char *v, uint8_t len) {
    const uint8_t n = count_digits(v, len);
    if (n == 0) {
        return false;
    }
    if (n == len) {
        return true;
    }
    if (v[n] != '.') {
        return false;
    }
    const uint8_t frac_len = len - n - 1;
    return frac_len > 0 && all_digits(v + n + 1, frac_len);
}

// A decimal with an optional exponent: digits ('.' digits)? ([eE] [+-]? digits)?
static bool is_json_number(const char *v, uint8_t len) {
    uint8_t e = 0;
    while (e < len && v[e] != 'e' && v[e] != 'E') {
        e++;
    }
    if (e == len) {
        return is_decimal(v, len);
    }
    const char *exp = v + e + 1;
    uint8_t exp_len = len - e - 1;
    if (exp_len > 0 && (exp[0] == '+' || exp[0] == '-')) {
        exp++;
        exp_len--;
    }
    return is_decimal(v, e) && exp_len > 0 && all_digits(exp, exp_len);
}

// Characters the Pact lexer accepts in a namespace or module name.
static bool is_pact_ident(char c) {
    switch (c) {
        case '%':
        case '#':
        case '+':
        case '-':
        case '_':
        case '&':
        case '$':
        case '@':
        case '<':
        case '>':
        case '=':
        case '?':
        case '*':
        case '!':
        case '|':
        case '/':
            return true;
        default:
            return is_alnum(c);
    }
}

static bool field_allowed(uint8_t field, const char *v, uint8_t len, uint8_t tx_type) {
    switch (field) {
        case RECIPIENT_POS:
            // A public key in lowercase hex: k:ABC... and k:abc... are different accounts.
            for (uint8_t i = 0; i < len; i++) {
                if (!is_digit(v[i]) && !(v[i] >= 'a' && v[i] <= 'f')) {
                    return false;
                }
            }
            return true;
        case RECIPIENT_CHAIN_POS:
            // Only a cross-chain transfer pastes the recipient chain into the template.
            if (tx_type != TX_TYPE_TRANSFER_CROSSCHAIN) {
                return all_digits(v, len);
            }
            return len > 0 && all_digits(v, len);
        case CHAIN_ID_POS:
            return len > 0 && all_digits(v, len);
        case NETWORK_POS:
            for (uint8_t i = 0; i < len; i++) {
                if (!is_alnum(v[i]) && v[i] != '-' && v[i] != '_' && v[i] != '.') {
                    return false;
                }
            }
            return true;
        case AMOUNT_POS:
            // Pasted as is into the code, where Pact refuses an integer for amount:decimal: the amount
            // must have a fractional part.
            return is_decimal(v, len) && memchr(v, '.', len) != NULL;
        case GAS_LIMIT_POS:
        case CREATION_TIME_POS:
        case TTL_POS:
            return is_decimal(v, len);
        case GAS_PRICE_POS:
            // A JSON number: hosts send exponents here (e.g. 1.0e-6).
            return is_json_number(v, len);
        case NAMESPACE_POS:
        case MODULE_POS:
            for (uint8_t i = 0; i < len; i++) {
                if (!is_pact_ident(v[i])) {
                    return false;
                }
            }
            return true;
        default:
            // Nonce: free text inside a JSON string, printable ASCII except '"' and '\'.
            for (uint8_t i = 0; i < len; i++) {
                const uint8_t c = (uint8_t)v[i];
                if (c < 0x20 || c > 0x7E || c == '"' || c == '\\') {
                    return false;
                }
            }
            return true;
    }
}

// The device pastes every field verbatim into the JSON it signs, so each field must be checked
// against what that position may hold. None of the allowed characters can end a JSON string,
// start an escape, or add JSON or Pact structure, and every numeric field is a well-formed number.
static parser_error_t parser_validate_chunk_contents(const chunk_t *chunks, uint8_t tx_type) {
    for (uint8_t i = 0; i < MAX_FIELDS_IN_INPUT_DATA; i++) {
        if (!field_allowed(i, chunks[i].data, chunks[i].len, tx_type)) {
            return parser_unexpected_characters;
        }
    }
    return parser_ok;
}

const char *parser_getErrorDescription(parser_error_t err) {
    switch (err) {
        case parser_ok:
            return "No error";
        case parser_no_data:
            return "No more data";
        case parser_init_context_empty:
            return "Initialized empty context";
        case parser_unexpected_buffer_end:
            return "Unexpected buffer end";
        case parser_unexpected_version:
            return "Unexpected version";
        case parser_unexpected_characters:
            return "Unexpected characters";
        case parser_unexpected_field:
            return "Unexpected field";
        case parser_duplicated_field:
            return "Unexpected duplicated field";
        case parser_value_out_of_range:
            return "Value out of range";
        case parser_unexpected_chain:
            return "Unexpected chain";
        case parser_missing_field:
            return "missing field";
        case parser_expert_mode_required:
            return "Expert mode required for this operation";
        case parser_unexpected_unparsed_bytes:
            return "Unexpected unparsed bytes";

        case parser_display_idx_out_of_range:
            return "display index out of range";
        case parser_display_page_out_of_range:
            return "display page out of range";
        case parser_tx_obj_empty:
            return "Tx obj empty";
        case parser_blindsign_mode_required:
            return "Blind signing mode required";
        case parser_unexpected_value:
            return "Unexpected value";
        case parser_json_too_many_tokens:
            return "NOMEM: JSON string contains too many tokens";
        case parser_json_not_a_transfer:
            return "JSON is not a transfer";
        case parser_invalid_meta_field:
            return "Invalid meta field";
        case parser_json_unexpected_error:
            return "Unexpected JSON error";
        case parser_name_tx_transfer:
            return "Transaction type: Transfer";
        case parser_name_tx_transfer_xchain:
            return "Transaction type: Cross-chain Transfer";
        case parser_name_rotate:
            return "Transaction type: Rotate";
        case parser_name_gas:
            return "Transaction type: Gas";
        case parser_signer_not_found:
            return "Device key is not a signer";
        case parser_signer_repeated:
            return "Device key signs more than once";

        default:
            return "Unrecognized error code";
    }
}
