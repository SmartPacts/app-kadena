
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
#include "items.h"

#include <base64.h>

#include "app_mode.h"
#include "crypto_helper.h"
#include "items_format.h"
#include "parser_impl.h"
#include "zxformat.h"

#define INCREMENT_NUM_ITEMS()                           \
    item_array.numOfItems++;                            \
    if (item_array.numOfItems >= MAX_NUMBER_OF_ITEMS) { \
        return items_too_many_items;                    \
    }

static items_error_t items_storeSigningTransaction();
static items_error_t items_storeNetwork();
static items_error_t items_storeRequiringCapabilities();
static items_error_t items_storeSigners();
static items_error_t items_storeKey();
static items_error_t items_validateSigners();
static items_error_t items_storeAllTransfers();
static items_error_t items_storeCaution();
static items_error_t items_storeHashWarning();
static items_error_t items_storeChainId();
static items_error_t items_storeUsingGas();
static items_error_t items_checkTxLengths();
static items_error_t items_computeHash(tx_type_t tx_type);
static items_error_t items_storeHash();
static items_error_t items_storeSignForAddr();
static items_error_t items_storeTxItem(uint16_t transfer_token_index, uint8_t *num_of_transfers);
static items_error_t items_storeTxCrossItem(uint16_t transfer_token_index, uint8_t *num_of_transfers);
static items_error_t items_storeTxRotateItem(uint16_t transfer_token_index);
static items_error_t items_storeUnknownItem(uint16_t num_of_args, uint16_t transfer_token_index);
static items_error_t items_storeRotateWarning();
static void items_checkIntegerMeta();

#define MAX_ITEM_LENGTH_TO_DISPLAY 256

item_array_t item_array;

uint8_t hash[BLAKE2B_HASH_SIZE] = {0};

char base64_hash[45];

// Set when the device's signer entry holds coin.ROTATE: signing then needs the Blind signing setting.
static bool rotate_in_scope = false;

// Set when the device's signer entry holds a capability the device does not fully render (anything
// but coin.GAS / coin.TRANSFER / coin.TRANSFER_XCHAIN / coin.ROTATE): signing then needs the Blind
// signing setting, and the review carries a "Capability not verified" warning. This holds for host-
// built JSON (S10) and for a structured transfer of a token other than coin (S13): the token module's
// code can use the key while its TRANSFER capability is held, and a look-alike module in another
// namespace reads the same on screen.
static bool unverified_cap_in_scope = false;

// Set when a displayed coin.TRANSFER / coin.TRANSFER_XCHAIN amount is not in one of the two accepted
// forms: a bare JSON number, or an object {"decimal":"<text>"} with that single key (the form
// @kadena/client emits), where the number or the text is a plain decimal digits('.' digits)? with no
// leading zero. Anything else (an exponent (S11), a string, {"int":…}, a sign, extra keys) is refused
// (S14): the screen would show it raw, and the network reads several of those forms as other decimals.
static bool amount_not_plain = false;

// Set when the signature is not bounded by a capability list the review shows: the device's entry has
// no capability (missing, null or empty clist: the WARNING item), a value is too large to show, or
// `meta` is not recognised (the CAUTION item). Signing then needs the Blind signing setting.
static bool unbounded_in_scope = false;

// Set when a recognised `meta` holds a gasLimit, ttl or creationTime that is not plain digits. The
// network reads these as integers and would round a fraction, so they are refused.
static bool meta_not_integer = false;

// S12: the digest the device signs. parsed_digest is computed while parsing (blake2b-256 of the JSON
// the review shows, or the 32 bytes of a hash to sign). When a signing review is shown it is copied
// to review_digest, which no later parse touches; approval signs exactly review_digest and never
// re-hashes a buffer that could have changed after the review was built.
static uint8_t parsed_digest[BLAKE2B_HASH_SIZE];
static bool parsed_digest_ready = false;
static uint8_t review_digest[BLAKE2B_HASH_SIZE];
static bool review_digest_bound = false;

items_error_t items_initItems() {
    MEMZERO(&item_array, sizeof(item_array_t));

    item_array.numOfUnknownCapabilities = 1;
    rotate_in_scope = false;
    unverified_cap_in_scope = false;
    amount_not_plain = false;
    unbounded_in_scope = false;
    meta_not_integer = false;
    MEMZERO(parsed_digest, sizeof(parsed_digest));
    parsed_digest_ready = false;

    for (uint8_t i = 0; i < MAX_NUMBER_OF_ITEMS; i++) {
        item_array.items[i].can_display = bool_true;
    }

    return items_ok;
}

item_array_t *items_getItemArray() { return &item_array; }

bool items_blindSignRequired() { return rotate_in_scope || unverified_cap_in_scope || unbounded_in_scope; }

bool items_amountNotPlain() { return amount_not_plain; }

bool items_metaNotInteger() { return meta_not_integer; }

items_error_t items_bindReviewDigest() {
    if (!parsed_digest_ready) {
        return items_error;
    }
    MEMCPY(review_digest, parsed_digest, sizeof(review_digest));
    review_digest_bound = true;
    return items_ok;
}

items_error_t items_getReviewDigest(uint8_t *out, uint16_t outLen) {
    if (out == NULL || outLen < sizeof(review_digest) || !review_digest_bound) {
        return items_error;
    }
    MEMCPY(out, review_digest, sizeof(review_digest));
    return items_ok;
}

void items_clearReviewDigest() {
    MEMZERO(review_digest, sizeof(review_digest));
    review_digest_bound = false;
}

// Fractional digits of coin's unit (coin.MINIMUM_PRECISION). The network rounds a JSON number with a
// longer fraction (at 255 places), so a longer amount would not be the one shown.
#define AMOUNT_MAX_FRACTION_DIGITS 12

// digits('.' digits)?: no sign, no exponent, no lone or trailing '.', no leading zero in the integer
// part (a single 0 before the '.' is fine), and at most 12 fractional digits.
static bool items_isPlainDecimal(const char *v, uint16_t len) {
    uint16_t i = 0;
    while (i < len && v[i] >= '0' && v[i] <= '9') {
        i++;
    }
    if (i == 0 || (i > 1 && v[0] == '0')) {
        return false;
    }
    if (i == len) {
        return true;
    }
    if (v[i] != '.' || i + 1 == len || len - i - 1 > AMOUNT_MAX_FRACTION_DIGITS) {
        return false;
    }
    for (i++; i < len; i++) {
        if (v[i] < '0' || v[i] > '9') {
            return false;
        }
    }
    return true;
}

static bool items_tokenIsPlainDecimal(const parsed_json_t *json_all, const jsmntok_t *token) {
    return token->end >= token->start &&
           items_isPlainDecimal(json_all->buffer + token->start, (uint16_t)(token->end - token->start));
}

// Checks a coin.TRANSFER / coin.TRANSFER_XCHAIN amount (clist arg 2) and flags any form but the two
// accepted ones. For {"decimal":"<text>"} it points the amount item at the inner text, so the review
// shows the plain number ("KDA 231"), never the object.
static void items_checkAmountForm(uint16_t *amount_token_index) {
    const parsed_json_t *json_all = &(parser_getParserJsonObj()->json);
    const jsmntok_t *token = &json_all->tokens[*amount_token_index];
    if (token->type == JSMN_PRIMITIVE) {
        if (!items_tokenIsPlainDecimal(json_all, token)) {
            amount_not_plain = true;
        }
        return;
    }
    uint16_t count = 0;
    uint16_t key_index = 0;
    uint16_t value_index = 0;
    if (token->type != JSMN_OBJECT || object_get_element_count(json_all, *amount_token_index, &count) != parser_ok ||
        count != 1 || object_get_nth_key(json_all, *amount_token_index, 0, &key_index) != parser_ok ||
        object_get_nth_value(json_all, *amount_token_index, 0, &value_index) != parser_ok) {
        amount_not_plain = true;
        return;
    }
    const jsmntok_t *key = &json_all->tokens[key_index];
    const jsmntok_t *value = &json_all->tokens[value_index];
    const uint16_t key_len = (uint16_t)(key->end - key->start);
    if (key->type != JSMN_STRING || key_len != strlen("decimal") ||
        MEMCMP(json_all->buffer + key->start, "decimal", key_len) != 0 || value->type != JSMN_STRING ||
        !items_tokenIsPlainDecimal(json_all, value)) {
        amount_not_plain = true;
        return;
    }
    *amount_token_index = value_index;
}

items_error_t items_storeItems(tx_type_t tx_type) {
    if (tx_type != tx_type_hash) {
        CHECK_ITEMS_ERROR(items_storeSigningTransaction());

        CHECK_ITEMS_ERROR(items_storeNetwork());

        CHECK_ITEMS_ERROR(items_storeSigners());

        CHECK_ITEMS_ERROR(items_storeRequiringCapabilities());

        CHECK_ITEMS_ERROR(items_storeKey());

        CHECK_ITEMS_ERROR(items_validateSigners());

        CHECK_ITEMS_ERROR(items_storeAllTransfers());

        if (parser_validateMetaField() != parser_ok) {
            CHECK_ITEMS_ERROR(items_storeCaution());
        } else {
            items_checkIntegerMeta();

            CHECK_ITEMS_ERROR(items_storeChainId());

            CHECK_ITEMS_ERROR(items_storeUsingGas());
        }

        CHECK_ITEMS_ERROR(items_checkTxLengths());
    } else {
        CHECK_ITEMS_ERROR(items_storeHashWarning());

        CHECK_ITEMS_ERROR(items_storeHash());
    }

    CHECK_ITEMS_ERROR(items_computeHash(tx_type));

    if (app_mode_expert()) {
        CHECK_ITEMS_ERROR(items_storeHash());

        CHECK_ITEMS_ERROR(items_storeSignForAddr());
    }

    return items_ok;
}

uint16_t items_getTotalItems() { return item_array.numOfItems; }

static items_error_t items_storeSigningTransaction() {
    item_t *item = &item_array.items[item_array.numOfItems];

    item->key = key_signing;
    item_array.toString[item_array.numOfItems] = items_signingToDisplayString;
    INCREMENT_NUM_ITEMS()

    return items_ok;
}

static items_error_t items_storeNetwork() {
    uint16_t *curr_token_idx = &item_array.items[item_array.numOfItems].json_token_index;
    item_t *item = &item_array.items[item_array.numOfItems];
    parsed_json_t *json_all = &(parser_getParserJsonObj()->json);

    PARSER_TO_ITEMS_ERROR(object_get_value(json_all, *curr_token_idx, JSON_NETWORK_ID, curr_token_idx));

    if (!items_isNullField(*curr_token_idx)) {
        item->key = key_on_network;
        item_array.toString[item_array.numOfItems] = items_stdToDisplayString;
        INCREMENT_NUM_ITEMS()
    }

    return items_ok;
}

static items_error_t items_storeRequiringCapabilities() {
    item_t *item = &item_array.items[item_array.numOfItems];
    item->key = key_requiring;
    item_array.toString[item_array.numOfItems] = items_requiringToDisplayString;
    INCREMENT_NUM_ITEMS()

    return items_ok;
}

// "Signers": the number of signer entries, shown when there is more than one.
static items_error_t items_storeSigners() {
    if (parser_getSignersCount() > 1) {
        item_t *item = &item_array.items[item_array.numOfItems];
        item->key = key_signers;
        item_array.toString[item_array.numOfItems] = items_signersToDisplayString;
        INCREMENT_NUM_ITEMS()
    }

    return items_ok;
}

// "Of Key": the pubKey of the device's own signer entry (parser_findDeviceSigner), not signers[0].
static items_error_t items_storeKey() {
    parsed_json_t *json_all = &(parser_getParserJsonObj()->json);
    uint16_t *curr_token_idx = &item_array.items[item_array.numOfItems].json_token_index;
    item_t *item = &item_array.items[item_array.numOfItems];

    PARSER_TO_ITEMS_ERROR(object_get_value(json_all, parser_getDeviceSignerIndex(), JSON_PUBKEY, curr_token_idx));
    item->key = key_of_key;
    item_array.toString[item_array.numOfItems] = items_stdToDisplayString;
    INCREMENT_NUM_ITEMS()

    return items_ok;
}

static items_error_t items_validateSigners() {
    parsed_json_t *json_all = &(parser_getParserJsonObj()->json);
    uint16_t *curr_token_idx = &item_array.items[item_array.numOfItems].json_token_index;
    item_t *item = &item_array.items[item_array.numOfItems];
    item_t *ofKey_item = &item_array.items[item_array.numOfItems - 1];
    uint16_t token_index = 0;
    uint16_t clist_element_count = 0;

    if (parser_getValidClist(curr_token_idx, &clist_element_count) != parser_ok) {
        item->key = key_unscoped_signer;
        *curr_token_idx = ofKey_item->json_token_index;
        item_array.toString[item_array.numOfItems] = items_stdToDisplayString;
        INCREMENT_NUM_ITEMS()
        return items_ok;
    }

    uint16_t clist_token_index = *curr_token_idx;
    PARSER_TO_ITEMS_ERROR(array_get_element_count(json_all, clist_token_index, &clist_element_count));

    for (uint8_t i = 0; i < (uint8_t)clist_element_count; i++) {
        if (array_get_nth_element(json_all, clist_token_index, i, &token_index) == parser_ok) {
            if (parser_getTxName(token_index) == parser_name_tx_transfer) {
                if (parser_findPubKeyInClist(ofKey_item->json_token_index) != parser_ok) {
                    item->key = key_unscoped_signer;
                    *curr_token_idx = ofKey_item->json_token_index;
                    item_array.toString[item_array.numOfItems] = items_stdToDisplayString;
                    INCREMENT_NUM_ITEMS()
                    return items_ok;
                }
            }
        }
    }
    // No transfer found
    *curr_token_idx = 0;
    return items_ok;
}

static items_error_t items_storeAllTransfers() {
    parsed_json_t *json_all = &(parser_getParserJsonObj()->json);
    uint16_t *curr_token_idx = &item_array.items[item_array.numOfItems].json_token_index;
    uint16_t token_index = 0;
    uint8_t num_of_transfers = 1;
    uint16_t clist_token_index = 0;
    uint16_t clist_element_count = 0;
    uint16_t args_element_count = 0;

    if (parser_getValidClist(&clist_token_index, &clist_element_count) == parser_ok) {
        for (uint16_t i = 0; i < clist_element_count; i++) {
            if (array_get_nth_element(json_all, clist_token_index, i, &token_index) == parser_ok) {
                switch (parser_getTxName(token_index)) {
                    case parser_name_tx_transfer:
                        *curr_token_idx = token_index;
                        CHECK_ITEMS_ERROR(items_storeTxItem(token_index, &num_of_transfers));
                        break;
                    case parser_name_tx_transfer_xchain:
                        *curr_token_idx = token_index;
                        CHECK_ITEMS_ERROR(items_storeTxCrossItem(token_index, &num_of_transfers));
                        break;
                    case parser_name_rotate:
                        *curr_token_idx = token_index;
                        CHECK_ITEMS_ERROR(items_storeTxRotateItem(token_index));
                        // Whatever its arguments: the new owner is never shown.
                        CHECK_ITEMS_ERROR(items_storeRotateWarning());
                        break;
                    case parser_name_gas:
                        break;
                    default:
                        *curr_token_idx = token_index;
                        PARSER_TO_ITEMS_ERROR(object_get_value(json_all, token_index, JSON_ARGS, &token_index));
                        PARSER_TO_ITEMS_ERROR(array_get_element_count(json_all, token_index, &args_element_count));
                        CHECK_ITEMS_ERROR(items_storeUnknownItem(args_element_count, token_index));
                        break;
                }
            }
            // Every store above is now CHECK_ITEMS_ERROR-wrapped (including the
            // wrong-arg-count else-branches inside items_storeTx*Item), so a store
            // that reached MAX has already aborted the whole parse. Guard the index
            // anyway: never form &items[MAX] (one past end) even if a future store
            // path forgets to propagate items_too_many_items.
            if (item_array.numOfItems >= MAX_NUMBER_OF_ITEMS) {
                return items_too_many_items;
            }
            curr_token_idx = &item_array.items[item_array.numOfItems].json_token_index;
        }
    } else {
        // Non-existing/Null Signers or Clist
        item_t *item = &item_array.items[item_array.numOfItems];
        unbounded_in_scope = true;
        item->key = key_warning;
        item_array.toString[item_array.numOfItems] = items_warningToDisplayString;
        INCREMENT_NUM_ITEMS()
        *curr_token_idx = 0;
    }

    return items_ok;
}

static items_error_t items_storeHashWarning() {
    item_t *item = &item_array.items[item_array.numOfItems];

    item->key = key_warning;
    item_array.toString[item_array.numOfItems] = items_hashWarningToDisplayString;
    INCREMENT_NUM_ITEMS()

    return items_ok;
}

static items_error_t items_storeCaution() {
    item_t *item = &item_array.items[item_array.numOfItems];

    unbounded_in_scope = true;
    item->key = key_caution;
    item_array.toString[item_array.numOfItems] = items_cautionToDisplayString;
    INCREMENT_NUM_ITEMS()

    return items_ok;
}

// gasLimit, ttl and creationTime of a recognised `meta`, when present, must be plain digits.
static void items_checkIntegerMeta() {
    static const char *const fields[] = {JSON_GAS_LIMIT, JSON_TTL, JSON_CREATION_TIME};
    const parsed_json_t *json_all = &(parser_getParserJsonObj()->json);
    uint16_t meta_token_index = 0;
    if (object_get_value(json_all, 0, JSON_META, &meta_token_index) != parser_ok) {
        return;
    }
    for (uint8_t f = 0; f < sizeof(fields) / sizeof(fields[0]); f++) {
        uint16_t value_index = 0;
        if (object_get_value(json_all, meta_token_index, (const char *)PIC(fields[f]), &value_index) != parser_ok) {
            continue;
        }
        const jsmntok_t *value = &json_all->tokens[value_index];
        if (value->type != JSMN_PRIMITIVE || value->end <= value->start) {
            meta_not_integer = true;
            return;
        }
        for (int i = value->start; i < value->end; i++) {
            if (json_all->buffer[i] < '0' || json_all->buffer[i] > '9') {
                meta_not_integer = true;
                return;
            }
        }
    }
}

static items_error_t items_storeChainId() {
    uint16_t *curr_token_idx = &item_array.items[item_array.numOfItems].json_token_index;
    item_t *item = &item_array.items[item_array.numOfItems];
    parsed_json_t *json_all = &(parser_getParserJsonObj()->json);

    PARSER_TO_ITEMS_ERROR(object_get_value(json_all, 0, JSON_META, curr_token_idx));

    if (!items_isNullField(*curr_token_idx)) {
        PARSER_TO_ITEMS_ERROR(object_get_value(json_all, *curr_token_idx, JSON_CHAIN_ID, curr_token_idx));
        if (!items_isNullField(*curr_token_idx)) {
            item->key = key_on_chain;
            item_array.toString[item_array.numOfItems] = items_stdToDisplayString;
            INCREMENT_NUM_ITEMS()
        }
    }

    return items_ok;
}

static items_error_t items_storeUsingGas() {
    uint16_t *curr_token_idx = &item_array.items[item_array.numOfItems].json_token_index;
    item_t *item = &item_array.items[item_array.numOfItems];
    parsed_json_t *json_all = &(parser_getParserJsonObj()->json);

    PARSER_TO_ITEMS_ERROR(object_get_value(json_all, 0, JSON_META, curr_token_idx));

    if (!items_isNullField(*curr_token_idx)) {
        item->key = key_using_gas;
        item_array.toString[item_array.numOfItems] = items_gasToDisplayString;
        INCREMENT_NUM_ITEMS()
    } else {
        *curr_token_idx = 0;
    }

    return items_ok;
}

static items_error_t items_checkTxLengths() {
    item_t *item = &item_array.items[item_array.numOfItems];

    for (uint8_t i = 0; i < item_array.numOfItems; i++) {
        if (!item_array.items[i].can_display) {
            unbounded_in_scope = true;
            item->key = key_warning;
            item_array.toString[item_array.numOfItems] = items_txTooLargeToDisplayString;
            INCREMENT_NUM_ITEMS()
            return items_ok;
        }
    }

    return items_ok;
}

static items_error_t items_computeHash(tx_type_t tx_type) {
    if (tx_type == tx_type_hash) {
        tx_hash_t *hash_obj = parser_getParserHashObj();
        if (hash_obj->hash_len != sizeof(parsed_digest)) {
            return items_error;
        }
        base64_encode(base64_hash, 44, (uint8_t *)hash_obj->tx, hash_obj->hash_len);
        MEMCPY(parsed_digest, hash_obj->tx, sizeof(parsed_digest));
    } else {
        if (blake2b_hash((uint8_t *)parser_getParserJsonObj()->json.buffer, parser_getParserJsonObj()->json.bufferLen,
                         hash) != zxerr_ok) {
            return items_error;
        }

        base64_encode(base64_hash, 44, hash, sizeof(hash));
        MEMCPY(parsed_digest, hash, sizeof(parsed_digest));
    }
    parsed_digest_ready = true;

    // Make it base64 URL safe
    for (int i = 0; base64_hash[i] != '\0'; i++) {
        if (base64_hash[i] == '+') {
            base64_hash[i] = '-';
        } else if (base64_hash[i] == '/') {
            base64_hash[i] = '_';
        }
    }

    return items_ok;
}

static items_error_t items_storeHash() {
    item_t *item = &item_array.items[item_array.numOfItems];

    item->key = key_transaction_hash;

    item_array.toString[item_array.numOfItems] = items_hashToDisplayString;
    INCREMENT_NUM_ITEMS()

    return items_ok;
}

static items_error_t items_storeSignForAddr() {
#if defined(LEDGER_SPECIFIC)
    item_t *item = &item_array.items[item_array.numOfItems];

    item->key = key_sign_for_address;
    item_array.toString[item_array.numOfItems] = items_signForAddrToDisplayString;
    INCREMENT_NUM_ITEMS()
#endif
    return items_ok;
}

static items_error_t items_storeTxItem(uint16_t transfer_token_index, uint8_t *num_of_transfers) {
    uint16_t token_index = 0;
    uint16_t num_of_args = 0;
    item_t *item = &item_array.items[item_array.numOfItems];
    parsed_json_t *json_all = &(parser_getParserJsonObj()->json);

    PARSER_TO_ITEMS_ERROR(object_get_value(json_all, transfer_token_index, "args", &token_index));

    PARSER_TO_ITEMS_ERROR(array_get_element_count(json_all, token_index, &num_of_args));

    if (num_of_args == 3) {
        item->key = key_transfer;
        (*num_of_transfers)++;
        item_array.toString[item_array.numOfItems] = items_transferToDisplayString;
        INCREMENT_NUM_ITEMS()
        item = &item_array.items[item_array.numOfItems];
        item->key = key_from;
        PARSER_TO_ITEMS_ERROR(array_get_nth_element(json_all, token_index, 0, &item->json_token_index));
        item_array.toString[item_array.numOfItems] = items_stdToDisplayString;
        INCREMENT_NUM_ITEMS()
        item = &item_array.items[item_array.numOfItems];
        item->key = key_to;
        PARSER_TO_ITEMS_ERROR(array_get_nth_element(json_all, token_index, 1, &item->json_token_index));
        item_array.toString[item_array.numOfItems] = items_stdToDisplayString;
        INCREMENT_NUM_ITEMS()
        item = &item_array.items[item_array.numOfItems];
        item->key = key_amount;
        PARSER_TO_ITEMS_ERROR(array_get_nth_element(json_all, token_index, 2, &item->json_token_index));
        items_checkAmountForm(&item->json_token_index);
        item_array.toString[item_array.numOfItems] = items_amountToDisplayString;
        INCREMENT_NUM_ITEMS()
    } else {
        CHECK_ITEMS_ERROR(items_storeUnknownItem(num_of_args, token_index));
    }

    return items_ok;
}

static items_error_t items_storeTxCrossItem(uint16_t transfer_token_index, uint8_t *num_of_transfers) {
    uint16_t token_index = 0;
    uint16_t num_of_args = 0;
    item_t *item = &item_array.items[item_array.numOfItems];
    parsed_json_t *json_all = &(parser_getParserJsonObj()->json);

    PARSER_TO_ITEMS_ERROR(object_get_value(json_all, transfer_token_index, "args", &token_index));

    PARSER_TO_ITEMS_ERROR(array_get_element_count(json_all, token_index, &num_of_args));

    if (num_of_args == 4) {
        item->key = key_transfer;
        (*num_of_transfers)++;
        item_array.toString[item_array.numOfItems] = items_crossTransferToDisplayString;
        INCREMENT_NUM_ITEMS()
        item = &item_array.items[item_array.numOfItems];
        item->key = key_from;
        PARSER_TO_ITEMS_ERROR(array_get_nth_element(json_all, token_index, 0, &item->json_token_index));
        item_array.toString[item_array.numOfItems] = items_stdToDisplayString;
        INCREMENT_NUM_ITEMS()
        item = &item_array.items[item_array.numOfItems];
        item->key = key_to;
        PARSER_TO_ITEMS_ERROR(array_get_nth_element(json_all, token_index, 1, &item->json_token_index));
        item_array.toString[item_array.numOfItems] = items_stdToDisplayString;
        INCREMENT_NUM_ITEMS()
        item = &item_array.items[item_array.numOfItems];
        item->key = key_amount;
        PARSER_TO_ITEMS_ERROR(array_get_nth_element(json_all, token_index, 2, &item->json_token_index));
        items_checkAmountForm(&item->json_token_index);
        item_array.toString[item_array.numOfItems] = items_amountToDisplayString;
        INCREMENT_NUM_ITEMS()
        item = &item_array.items[item_array.numOfItems];
        item->key = key_to_chain;
        PARSER_TO_ITEMS_ERROR(array_get_nth_element(json_all, token_index, 3, &item->json_token_index));
        item_array.toString[item_array.numOfItems] = items_stdToDisplayString;
        INCREMENT_NUM_ITEMS()
    } else {
        CHECK_ITEMS_ERROR(items_storeUnknownItem(num_of_args, token_index));
    }

    return items_ok;
}

static items_error_t items_storeTxRotateItem(uint16_t transfer_token_index) {
    uint16_t token_index = 0;
    uint16_t num_of_args = 0;
    item_t *item = &item_array.items[item_array.numOfItems];
    parsed_json_t *json_all = &(parser_getParserJsonObj()->json);

    PARSER_TO_ITEMS_ERROR(object_get_value(json_all, transfer_token_index, "args", &token_index));

    PARSER_TO_ITEMS_ERROR(array_get_element_count(json_all, token_index, &num_of_args));

    if (num_of_args == 1) {
        item->key = key_rotate;
        item_array.toString[item_array.numOfItems] = items_rotateToDisplayString;
        INCREMENT_NUM_ITEMS()
    } else {
        CHECK_ITEMS_ERROR(items_storeUnknownItem(num_of_args, token_index));
    }

    return items_ok;
}

// coin.ROTATE limits only which account is rotated. The new guard comes from the transaction's
// code and data, which the review does not show, so rotation is blind signing: it carries this
// warning and needs the Blind signing setting (parser_validate).
static items_error_t items_storeRotateWarning() {
    item_t *item = &item_array.items[item_array.numOfItems];

    rotate_in_scope = true;
    item->key = key_warning;
    item_array.toString[item_array.numOfItems] = items_rotateWarningToDisplayString;
    INCREMENT_NUM_ITEMS()

    return items_ok;
}

static items_error_t items_storeUnknownItem(uint16_t num_of_args, uint16_t transfer_token_index) {
    item_t *item = &item_array.items[item_array.numOfItems];
    parsed_json_t *json_all = &(parser_getParserJsonObj()->json);

    // The device fully renders only coin.GAS / TRANSFER / TRANSFER_XCHAIN / ROTATE; this capability
    // is none of those, so its effect is not shown. The caller set json_token_index to the cap.
    const uint16_t cap_token_index = item->json_token_index;

    item->key = key_unknown_capability;
    item_array.numOfUnknownCapabilities++;
    item_array.toString[item_array.numOfItems] = items_unknownCapabilityToDisplayString;

    if (num_of_args > 5 || json_all->tokens[transfer_token_index].end - json_all->tokens[transfer_token_index].start >
                               MAX_ITEM_LENGTH_TO_DISPLAY) {
        item->can_display = bool_false;
    }

    INCREMENT_NUM_ITEMS()

    // S10: an unverified capability in the device's own entry requires the Blind signing setting and
    // carries a warning naming it, because a scoped coin.DEBIT (or any other capability) can let
    // undisplayed code install a TRANSFER and move funds the review never showed. Resolve the name
    // token now, so the renderer just reads a string token (like items_stdToDisplayString).
    uint16_t name_token_index = cap_token_index;
    PARSER_TO_ITEMS_ERROR(object_get_value(json_all, cap_token_index, JSON_NAME, &name_token_index));
    item_t *warn = &item_array.items[item_array.numOfItems];
    warn->json_token_index = name_token_index;
    warn->key = key_warning;
    unverified_cap_in_scope = true;
    item_array.toString[item_array.numOfItems] = items_capNotVerifiedToDisplayString;
    INCREMENT_NUM_ITEMS()

    return items_ok;
}
