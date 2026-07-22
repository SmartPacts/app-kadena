
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

#define MAX_ITEM_LENGTH_TO_DISPLAY 256

item_array_t item_array;

uint8_t hash[BLAKE2B_HASH_SIZE] = {0};

char base64_hash[45];

items_error_t items_initItems() {
    MEMZERO(&item_array, sizeof(item_array_t));

    item_array.numOfUnknownCapabilities = 1;

    for (uint8_t i = 0; i < MAX_NUMBER_OF_ITEMS; i++) {
        item_array.items[i].can_display = bool_true;
    }

    return items_ok;
}

item_array_t *items_getItemArray() { return &item_array; }

items_error_t items_storeItems(tx_type_t tx_type) {
    if (tx_type != tx_type_hash) {
        CHECK_ITEMS_ERROR(items_storeSigningTransaction());

        CHECK_ITEMS_ERROR(items_storeNetwork());

        CHECK_ITEMS_ERROR(items_storeRequiringCapabilities());

        CHECK_ITEMS_ERROR(items_storeKey());

        CHECK_ITEMS_ERROR(items_validateSigners());

        CHECK_ITEMS_ERROR(items_storeAllTransfers());

        if (parser_validateMetaField() != parser_ok) {
            CHECK_ITEMS_ERROR(items_storeCaution());
        } else {
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

static items_error_t items_storeKey() {
    parsed_json_t *json_all = &(parser_getParserJsonObj()->json);
    uint16_t *curr_token_idx = &item_array.items[item_array.numOfItems].json_token_index;
    item_t *item = &item_array.items[item_array.numOfItems];

    PARSER_TO_ITEMS_ERROR(object_get_value(json_all, *curr_token_idx, JSON_SIGNERS, curr_token_idx));

    if (!items_isNullField(*curr_token_idx)) {
        PARSER_TO_ITEMS_ERROR(array_get_nth_element(json_all, *curr_token_idx, 0, curr_token_idx));
        PARSER_TO_ITEMS_ERROR(object_get_value(json_all, *curr_token_idx, JSON_PUBKEY, curr_token_idx));
        if (!items_isNullField(*curr_token_idx)) {
            item->key = key_of_key;
            item_array.toString[item_array.numOfItems] = items_stdToDisplayString;
            INCREMENT_NUM_ITEMS()
        }
    }

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
                        items_storeTxItem(token_index, &num_of_transfers);
                        break;
                    case parser_name_tx_transfer_xchain:
                        *curr_token_idx = token_index;
                        items_storeTxCrossItem(token_index, &num_of_transfers);
                        break;
                    case parser_name_rotate:
                        *curr_token_idx = token_index;
                        items_storeTxRotateItem(token_index);
                        break;
                    case parser_name_gas:
                        break;
                    default:
                        *curr_token_idx = token_index;
                        PARSER_TO_ITEMS_ERROR(object_get_value(json_all, token_index, JSON_ARGS, &token_index));
                        PARSER_TO_ITEMS_ERROR(array_get_element_count(json_all, token_index, &args_element_count));
                        items_storeUnknownItem(args_element_count, token_index);
                        break;
                }
            }
            curr_token_idx = &item_array.items[item_array.numOfItems].json_token_index;
        }
    } else {
        // Non-existing/Null Signers or Clist
        item_t *item = &item_array.items[item_array.numOfItems];
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

    item->key = key_caution;
    item_array.toString[item_array.numOfItems] = items_cautionToDisplayString;
    INCREMENT_NUM_ITEMS()

    return items_ok;
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
        base64_encode(base64_hash, 44, (uint8_t *)hash_obj->tx, hash_obj->hash_len);
    } else {
        if (blake2b_hash((uint8_t *)parser_getParserJsonObj()->json.buffer, parser_getParserJsonObj()->json.bufferLen,
                         hash) != zxerr_ok) {
            return items_error;
        }

        base64_encode(base64_hash, 44, hash, sizeof(hash));
    }

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
        item_array.toString[item_array.numOfItems] = items_amountToDisplayString;
        INCREMENT_NUM_ITEMS()
    } else {
        items_storeUnknownItem(num_of_args, token_index);
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
        item_array.toString[item_array.numOfItems] = items_amountToDisplayString;
        INCREMENT_NUM_ITEMS()
        item = &item_array.items[item_array.numOfItems];
        item->key = key_to_chain;
        PARSER_TO_ITEMS_ERROR(array_get_nth_element(json_all, token_index, 3, &item->json_token_index));
        item_array.toString[item_array.numOfItems] = items_stdToDisplayString;
        INCREMENT_NUM_ITEMS()
    } else {
        items_storeUnknownItem(num_of_args, token_index);
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
        items_storeUnknownItem(num_of_args, token_index);
    }

    return items_ok;
}

static items_error_t items_storeUnknownItem(uint16_t num_of_args, uint16_t transfer_token_index) {
    item_t *item = &item_array.items[item_array.numOfItems];
    parsed_json_t *json_all = &(parser_getParserJsonObj()->json);

    item->key = key_unknown_capability;
    item_array.numOfUnknownCapabilities++;
    item_array.toString[item_array.numOfItems] = items_unknownCapabilityToDisplayString;

    if (num_of_args > 5 || json_all->tokens[transfer_token_index].end - json_all->tokens[transfer_token_index].start >
                               MAX_ITEM_LENGTH_TO_DISPLAY) {
        item->can_display = bool_false;
    }

    INCREMENT_NUM_ITEMS()

    return items_ok;
}
