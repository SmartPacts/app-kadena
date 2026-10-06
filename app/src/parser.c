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

// On touch screens the review lists every page of every item as one tag/value pair. The display
// layer counts the pairs in 8 bits (zxlib view_nbgl.c get_pair_number, NBGL nbPairs), and the SDK
// then counts the review's screens in 8 bits too (nbgl_use_case.c useCaseReview: one first page, the
// tag/value screens, each holding one pair or more, and one last page). A review of more pairs
// would wrap one of them, end early and sign items never shown. So the review may hold at most 253
// pairs: at one pair per screen that is 255 screens, the most either counter holds. Validation
// renders each item at the review's value page size and refuses a larger review. The Nano review
// walks one item at a time and has no such total. Host unit tests use the smallest touch page
// (Apex P, 144).
#if defined(TARGET_STAX) || defined(TARGET_FLEX) || defined(TARGET_APEX_P)
#include "view_internal.h"
#define REVIEW_PAGE_LIMIT_CHARS MAX_CHARS_PER_VALUE1_LINE
#elif defined(TARGET_NANOS) || defined(TARGET_NANOS2) || defined(TARGET_NANOX)
// No total page count on Nano.
#elif !defined(LEDGER_SPECIFIC)
#define REVIEW_PAGE_LIMIT_CHARS 144
#else
#error "Unknown target: state whether its review counts pages in total (see MAX_REVIEW_PAGES)"
#endif
#define MAX_REVIEW_PAGES 253

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
    if (tx_type != tx_type_hash) {
        // Review the signer entry of the device's own key, found before any item is stored.
        CHECK_ERROR(parser_findDeviceSigner())
    }
    ITEMS_TO_PARSER_ERROR(items_storeItems(tx_type))
    return parser_ok;
}

parser_error_t parser_validate(parser_context_t *ctx) {
    // Iterate through all items to check that all can be shown and are valid
    uint8_t numItems = 0;
    CHECK_ERROR(parser_getNumItems(ctx, &numItems))

    // A displayed transfer amount must be a bare plain decimal (S11, S14): an exponent, a string, an
    // object or a sign is shown raw and can read as another decimal on the network. Refuse it before
    // any screen.
    // The same for a gasLimit, ttl or creationTime that is not plain digits (the network reads them as
    // integers). Checked before the items are rendered, so an over-long value of that kind is refused
    // for its form, as the Rust app does.
    if (items_amountNotPlain() || items_metaNotInteger()) {
        return parser_unexpected_characters;
    }

    char tmpKey[MAX_ITEM_LENGTH_IN_PAGE] = {0};
#if defined(REVIEW_PAGE_LIMIT_CHARS)
    char tmpVal[REVIEW_PAGE_LIMIT_CHARS] = {0};
    uint16_t reviewPages = 0;
#else
    char tmpVal[MAX_ITEM_LENGTH_IN_PAGE] = {0};
#endif

    for (uint8_t idx = 0; idx < numItems; idx++) {
        uint8_t pageCount = 0;
        CHECK_ERROR(parser_getItem(ctx, idx, tmpKey, sizeof(tmpKey), tmpVal, sizeof(tmpVal), 0, &pageCount))
#if defined(REVIEW_PAGE_LIMIT_CHARS)
        reviewPages += pageCount;
#endif
    }

#if defined(REVIEW_PAGE_LIMIT_CHARS)
    // A review that cannot be shown whole is refused, whatever the settings.
    if (reviewPages > MAX_REVIEW_PAGES) {
        return parser_value_out_of_range;
    }
#endif

    // coin.ROTATE, or any capability the device does not fully render, lets code and data the review
    // does not show move funds: sign it only with the Blind signing setting on (as a hash).
    if (items_blindSignRequired() && !app_mode_blindsign()) {
        return parser_blindsign_mode_required;
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

// pageString over the screen text of a value: a byte outside printable ASCII (0x20-0x7E) is shown as
// \xNN, so nothing invisible or confusable reaches the screen (account names may hold C1 controls,
// NBSP or a soft hyphen, which a font can draw as nothing). The signed bytes do not change. A JSON
// string cannot hold a literal "\x" (the tokenizer refuses that escape).
static void pageEscapedString(char *outValue, uint16_t outValueLen, const char *inValue, uint8_t pageIdx,
                              uint8_t *pageCount) {
    MEMZERO(outValue, outValueLen);
    *pageCount = 0;
    if (outValueLen < 2) {
        return;
    }
    const uint16_t pageLen = outValueLen - 1;  // leave space for NUL termination

    uint16_t shownLen = 0;
    for (const char *p = inValue; *p != '\0'; p++) {
        const uint8_t b = (uint8_t)*p;
        shownLen += (b >= 0x20 && b <= 0x7E) ? 1 : 4;
    }
    if (shownLen == 0) {
        return;
    }
    *pageCount = (uint8_t)((shownLen + pageLen - 1) / pageLen);
    if (pageIdx >= *pageCount) {
        return;
    }

    const uint16_t first = pageIdx * pageLen;
    uint16_t pos = 0;
    uint16_t n = 0;
    for (const char *p = inValue; *p != '\0' && n < pageLen; p++) {
        const uint8_t b = (uint8_t)*p;
        char shown[4] = {(char)b, 0, 0, 0};
        uint8_t shown_len = 1;
        if (b < 0x20 || b > 0x7E) {
            const uint8_t hi = b >> 4;
            const uint8_t lo = b & 0x0F;
            shown[0] = '\\';
            shown[1] = 'x';
            shown[2] = (char)(hi < 10 ? '0' + hi : 'A' + hi - 10);
            shown[3] = (char)(lo < 10 ? '0' + lo : 'A' + lo - 10);
            shown_len = 4;
        }
        for (uint8_t k = 0; k < shown_len && n < pageLen; k++, pos++) {
            if (pos >= first) {
                outValue[n++] = shown[k];
            }
        }
    }
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
    pageEscapedString(outVal, outValLen, tempVal, pageIdx, pageCount);

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
        case key_signers:
            strncpy(outKey, "Signers", outKeyLen);
            break;
        default:
            break;
    }
    return parser_ok;
}