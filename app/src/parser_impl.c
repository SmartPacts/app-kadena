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

tx_json_t *parser_json_obj;
tx_hash_t *parser_hash_obj;

parser_error_t _read_json_tx(parser_context_t *c) {
    parser_json_obj = c->json;

    CHECK_ERROR(json_parse(&(parser_json_obj->json), (const char *)c->buffer, c->bufferLen));

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
            array_get_nth_element(json_all, args_token_index, j, &token_index);
            value_token = &(json_all->tokens[token_index]);
            key_token = &(json_all->tokens[key_token_index]);
            uint8_t offset = 0;

            // Key could possibly be prefixed with "k:"
            if (CMP_STRING_AND_BUFFER("k:", json_all->buffer + value_token->start, 2)) {
                offset = 2;
            }

            if (MEMCMP(json_all->buffer + key_token->start, json_all->buffer + value_token->start + offset,
                       key_token->end - key_token->start) == 0) {
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

    object_get_element_count(json_all, meta_token_index, &meta_num_elements);

    if (meta_num_elements > array_length(keywords)) {
        return parser_invalid_meta_field;
    }

    for (uint16_t i = 0; i < meta_num_elements; i++) {
        object_get_nth_key(json_all, meta_token_index, i, &key_token_idx);
        token = &(json_all->tokens[key_token_idx]);

        // Prevent buffer overflow in case of big key-value pair in meta field.
        if (token->end - token->start >= sizeof(meta_curr_key)) {
            return parser_invalid_meta_field;
        }

        MEMCPY(meta_curr_key, json_all->buffer + token->start, token->end - token->start);
        meta_curr_key[token->end - token->start] = '\0';

        if (strcmp((const char *)PIC(keywords[i]), meta_curr_key) != 0) {
            return parser_invalid_meta_field;
        }

        MEMZERO(meta_curr_key, sizeof(meta_curr_key));
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

    CHECK_ERROR(object_get_value(json_all, 0, JSON_SIGNERS, clist_token_index));

    if (!items_isNullField(*clist_token_index)) {
        CHECK_ERROR(array_get_nth_element(json_all, *clist_token_index, 0, clist_token_index));

        if (object_get_value(json_all, *clist_token_index, JSON_CLIST, clist_token_index) == parser_ok) {
            if (!items_isNullField(*clist_token_index)) {
                CHECK_ERROR(array_get_element_count(json_all, *clist_token_index, num_args));
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

#if defined(LEDGER_SPECIFIC)
    uint8_t pubkey[PUB_KEY_LENGTH] = {0};
    uint16_t pubkey_len = 0;

    if (crypto_fillAddress(pubkey, sizeof(pubkey), &pubkey_len) != zxerr_ok) {
        return parser_unexpected_error;
    }

    address_len = array_to_hexstr(address, sizeof(address), pubkey, PUB_KEY_LENGTH);
#else
    // Dummy address for cpp_test
    address_len =
        snprintf(address, sizeof(address), "%s", "1234567890123456789012345678901234567890123456789012345678901234");
#endif

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

static parser_error_t parser_formatTxTransfer(uint16_t address_len, char *address, chunk_t *chunks, uint8_t tx_type) {
    if (address == NULL || chunks == NULL) {
        return parser_unexpected_value;
    }

    char namespace_and_module[NAMESPACE_LEN + MODULE_LEN + 1] = {0};
    if (chunks[NAMESPACE_POS].len > 0 && chunks[MODULE_POS].len > 0) {
        snprintf(namespace_and_module, sizeof(namespace_and_module), "%.*s.%.*s", chunks[NAMESPACE_POS].len,
                 chunks[NAMESPACE_POS].data, chunks[MODULE_POS].len, chunks[MODULE_POS].data);
    } else {
        snprintf(namespace_and_module, sizeof(namespace_and_module), "%s", "coin");
    }

    tx_json_append((uint8_t *)"{\"networkId\":\"", 14);
    tx_json_append((uint8_t *)chunks[NETWORK_POS].data, chunks[NETWORK_POS].len);
    tx_json_append((uint8_t *)"\",\"payload\":{\"exec\":{\"data\":", 28);

    if (tx_type == TX_TYPE_TRANSFER) {
        tx_json_append((uint8_t *)"{}", 2);
    } else {
        tx_json_append((uint8_t *)"{\"ks\":{\"pred\":\"keys-all\",\"keys\":[\"", 34);
        tx_json_append((uint8_t *)chunks[RECIPIENT_POS].data, chunks[RECIPIENT_POS].len);
        tx_json_append((uint8_t *)"\"]}}", 4);
    }

    tx_json_append((uint8_t *)",\"code\":\"(", 10);
    tx_json_append((uint8_t *)namespace_and_module, strlen(namespace_and_module));

    switch (tx_type) {
        case TX_TYPE_TRANSFER:
            tx_json_append((uint8_t *)".transfer", 9);
            break;
        case TX_TYPE_TRANSFER_CREATE:
            tx_json_append((uint8_t *)".transfer-create", 16);
            break;
        case TX_TYPE_TRANSFER_CROSSCHAIN:
            tx_json_append((uint8_t *)".transfer-crosschain", 20);
            break;
    }

    tx_json_append((uint8_t *)" \\\"k:", 5);
    tx_json_append((uint8_t *)address, address_len);
    tx_json_append((uint8_t *)"\\\" \\\"k:", 7);
    tx_json_append((uint8_t *)chunks[RECIPIENT_POS].data, chunks[RECIPIENT_POS].len);
    tx_json_append((uint8_t *)"\\\"", 2);

    if (tx_type != TX_TYPE_TRANSFER) {
        tx_json_append((uint8_t *)" (read-keyset \\\"ks\\\")", 21);
    }

    if (tx_type == TX_TYPE_TRANSFER_CROSSCHAIN) {
        tx_json_append((uint8_t *)" \\\"", 3);
        tx_json_append((uint8_t *)chunks[RECIPIENT_CHAIN_POS].data, chunks[RECIPIENT_CHAIN_POS].len);
        tx_json_append((uint8_t *)"\\\"", 2);
    }

    tx_json_append((uint8_t *)" ", 1);
    tx_json_append((uint8_t *)chunks[AMOUNT_POS].data, chunks[AMOUNT_POS].len);
    tx_json_append((uint8_t *)")\"}},\"signers\":[{\"pubKey\":\"", 27);
    tx_json_append((uint8_t *)address, address_len);
    tx_json_append((uint8_t *)"\",\"clist\":[{\"args\":[\"k:", 23);
    tx_json_append((uint8_t *)address, address_len);
    tx_json_append((uint8_t *)"\",\"k:", 5);
    tx_json_append((uint8_t *)chunks[RECIPIENT_POS].data, chunks[RECIPIENT_POS].len);
    tx_json_append((uint8_t *)"\",", 2);
    tx_json_append((uint8_t *)chunks[AMOUNT_POS].data, chunks[AMOUNT_POS].len);

    if (tx_type == TX_TYPE_TRANSFER_CROSSCHAIN) {
        tx_json_append((uint8_t *)",\"", 2);
        tx_json_append((uint8_t *)chunks[RECIPIENT_CHAIN_POS].data, chunks[RECIPIENT_CHAIN_POS].len);
        tx_json_append((uint8_t *)"\"", 1);
    }

    tx_json_append((uint8_t *)"],\"name\":\"", 10);
    tx_json_append((uint8_t *)namespace_and_module, strlen(namespace_and_module));
    tx_json_append((uint8_t *)".TRANSFER", 9);

    if (tx_type == TX_TYPE_TRANSFER_CROSSCHAIN) {
        tx_json_append((uint8_t *)"_XCHAIN", 7);
    }

    tx_json_append((uint8_t *)"\"},{\"args\":[],\"name\":\"coin.GAS\"}]}],\"meta\":{\"creationTime\":", 59);
    tx_json_append((uint8_t *)chunks[CREATION_TIME_POS].data, chunks[CREATION_TIME_POS].len);
    tx_json_append((uint8_t *)",\"ttl\":", 7);
    tx_json_append((uint8_t *)chunks[TTL_POS].data, chunks[TTL_POS].len);
    tx_json_append((uint8_t *)",\"gasLimit\":", 12);
    tx_json_append((uint8_t *)chunks[GAS_LIMIT_POS].data, chunks[GAS_LIMIT_POS].len);
    tx_json_append((uint8_t *)",\"chainId\":\"", 12);
    tx_json_append((uint8_t *)chunks[CHAIN_ID_POS].data, chunks[CHAIN_ID_POS].len);
    tx_json_append((uint8_t *)"\",\"gasPrice\":", 13);
    tx_json_append((uint8_t *)chunks[GAS_PRICE_POS].data, chunks[GAS_PRICE_POS].len);
    tx_json_append((uint8_t *)",\"sender\":\"k:", 13);
    tx_json_append((uint8_t *)address, address_len);
    tx_json_append((uint8_t *)"\"},\"nonce\":\"", 12);
    tx_json_append((uint8_t *)chunks[NONCE_POS].data, chunks[NONCE_POS].len);
    tx_json_append((uint8_t *)"\"}", 2);

    return parser_ok;
}

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

        default:
            return "Unrecognized error code";
    }
}
