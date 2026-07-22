/*******************************************************************************
 *   (c) 2018 - 2024 Zondax AG
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

#include "common/parser.h"

#include <stdio.h>
#include <zxformat.h>
#include <zxmacros.h>
#include <zxtypes.h>

#include "app_mode.h"
#include "coin.h"
#include "crypto.h"
#include "crypto_helper.h"
#include "items.h"
#include "parser_impl.h"
#include "tx.h"

static parser_error_t parser_getItemKey(uint8_t displayIdx, char *outKey, uint16_t outKeyLen);

#define MAX_ITEM_LENGTH_IN_PAGE 40

tx_json_t tx_obj_json;
tx_hash_t tx_obj_hash;

parser_error_t parser_init_context(parser_context_t *ctx, const uint8_t *buffer, uint16_t bufferSize) {
    ctx->offset = 0;

    if (bufferSize == 0 || buffer == NULL) {
        // Not available, use defaults
        ctx->buffer = NULL;
        ctx->bufferLen = 0;
        return parser_init_context_empty;
    }

    ctx->buffer = buffer;
    ctx->bufferLen = bufferSize;
    return parser_ok;
}

parser_error_t parser_parse(parser_context_t *ctx, const uint8_t *data, size_t dataLen, tx_type_t tx_type) {
    if (tx_type == tx_type_hash && !app_mode_blindsign()) {
        return parser_blindsign_mode_required;
    }

    CHECK_ERROR(parser_init_context(ctx, data, dataLen))
    switch (tx_type) {
        case tx_type_json:
            ctx->json = &tx_obj_json;
            CHECK_ERROR(_read_json_tx(ctx));
            break;
        case tx_type_hash:
            ctx->hash = &tx_obj_hash;
            CHECK_ERROR(_read_hash_tx(ctx));
            break;
        case tx_type_transfer:
            CHECK_ERROR(parser_createJsonTemplate(ctx));
            ctx->json = &tx_obj_json;
            ctx->buffer = tx_json_get_buffer();
            ctx->bufferLen = (uint16_t)tx_json_get_buffer_length();
            CHECK_ERROR(_read_json_tx(ctx));
            break;
        default:
            return parser_unexpected_type;
    }

    ITEMS_TO_PARSER_ERROR(items_initItems())
    ITEMS_TO_PARSER_ERROR(items_storeItems(tx_type))
    return parser_ok;
}

parser_error_t parser_validate(parser_context_t *ctx) {
    // Iterate through all items to check that all can be shown and are valid
    uint8_t numItems = 0;
    CHECK_ERROR(parser_getNumItems(ctx, &numItems))

    char tmpKey[MAX_ITEM_LENGTH_IN_PAGE] = {0};
    char tmpVal[MAX_ITEM_LENGTH_IN_PAGE] = {0};

    for (uint8_t idx = 0; idx < numItems; idx++) {
        uint8_t pageCount = 0;
        CHECK_ERROR(parser_getItem(ctx, idx, tmpKey, sizeof(tmpKey), tmpVal, sizeof(tmpVal), 0, &pageCount))
    }
    return parser_ok;
}

parser_error_t parser_getNumItems(const parser_context_t *ctx, uint8_t *num_items) {
    if (ctx->json == NULL) {
        return parser_tx_obj_empty;
    }

    *num_items = items_getTotalItems();

    return parser_ok;
}

static void cleanOutput(char *outKey, uint16_t outKeyLen, char *outVal, uint16_t outValLen) {
    MEMZERO(outKey, outKeyLen);
    MEMZERO(outVal, outValLen);
    snprintf(outKey, outKeyLen, "?");
    snprintf(outVal, outValLen, " ");
}

static parser_error_t checkSanity(uint8_t numItems, uint8_t displayIdx) {
    if (displayIdx >= numItems) {
        return parser_display_idx_out_of_range;
    }
    return parser_ok;
}

parser_error_t parser_getItem(const parser_context_t *ctx, uint8_t displayIdx, char *outKey, uint16_t outKeyLen,
                              char *outVal, uint16_t outValLen, uint8_t pageIdx, uint8_t *pageCount) {
    *pageCount = 1;
    uint8_t numItems = 0;
    item_array_t *item_array = items_getItemArray();
    char tempVal[300] = {0};
    CHECK_ERROR(parser_getNumItems(ctx, &numItems))
    CHECK_APP_CANARY()

    CHECK_ERROR(checkSanity(numItems, displayIdx))
    cleanOutput(outKey, outKeyLen, outVal, outValLen);
    CHECK_ERROR(parser_getItemKey(displayIdx, outKey, outKeyLen))

    ITEMS_TO_PARSER_ERROR(item_array->toString[displayIdx](item_array->items[displayIdx], tempVal, sizeof(tempVal)));
    pageString(outVal, outValLen, tempVal, pageIdx, pageCount);

    return parser_ok;
}

static parser_error_t parser_getItemKey(uint8_t displayIdx, char *outKey, uint16_t outKeyLen) {
    item_array_t *item_array = items_getItemArray();
    static uint8_t transfer_count = 0;
    static uint8_t unk_cap_count = 0;
    static uint8_t last_displayIdx = 0;
    bool update_counts = false;

    if (displayIdx == 0) {
        transfer_count = 0;
        unk_cap_count = 0;
    }

    if (last_displayIdx != displayIdx) {
        update_counts = true;
    }

    last_displayIdx = displayIdx;

    switch (item_array->items[displayIdx].key) {
        case key_signing:
            strncpy(outKey, "Signing", outKeyLen);
            break;
        case key_on_network:
            strncpy(outKey, "On Network", outKeyLen);
            break;
        case key_requiring:
            strncpy(outKey, "Requiring", outKeyLen);
            break;
        case key_of_key:
            strncpy(outKey, "Of Key", outKeyLen);
            break;
        case key_unscoped_signer:
            strncpy(outKey, "Unscoped Signer", outKeyLen);
            break;
        case key_warning:
            strncpy(outKey, "WARNING", outKeyLen);
            break;
        case key_caution:
            strncpy(outKey, "CAUTION", outKeyLen);
            break;
        case key_on_chain:
            strncpy(outKey, "On Chain", outKeyLen);
            break;
        case key_using_gas:
            strncpy(outKey, "Using Gas", outKeyLen);
            break;
        case key_chain_id:
            strncpy(outKey, "Chain ID", outKeyLen);
            break;
        case key_paying_gas:
            strncpy(outKey, "Paying Gas", outKeyLen);
            break;
        case key_from:
            strncpy(outKey, "From", outKeyLen);
            break;
        case key_to:
            strncpy(outKey, "To", outKeyLen);
            break;
        case key_amount:
            strncpy(outKey, "Amount", outKeyLen);
            break;
        case key_to_chain:
            strncpy(outKey, "To Chain", outKeyLen);
            break;
        case key_transfer:
            if (update_counts) {
                transfer_count++;
            }
            snprintf(outKey, outKeyLen, "Transfer %d", transfer_count);
            break;
        case key_rotate:
            strncpy(outKey, "Rotate for account", outKeyLen);
            break;
        case key_unknown_capability:
            if (update_counts) {
                unk_cap_count++;
            }
            snprintf(outKey, outKeyLen, "Unknown Capability %d", unk_cap_count);
            break;
        case key_transaction_hash:
            strncpy(outKey, "Transaction hash", outKeyLen);
            break;
        case key_sign_for_address:
            strncpy(outKey, "Sign for Address", outKeyLen);
            break;
        default:
            break;
    }
    return parser_ok;
}