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
#pragma once

#include <zxmacros.h>

#include "zxtypes.h"

#if defined(TARGET_NANOS)
#define MAX_NUMBER_OF_ITEMS 57
#else
#define MAX_NUMBER_OF_ITEMS 100
#endif

#define CHECK_ITEMS_ERROR(__CALL)            \
    {                                        \
        items_error_t __err = __CALL;        \
        CHECK_APP_CANARY()                   \
        if (__err != items_ok) return __err; \
    }

#define PARSER_TO_ITEMS_ERROR(__CALL)               \
    {                                               \
        parser_error_t __err = __CALL;              \
        CHECK_APP_CANARY()                          \
        if (__err != parser_ok) return items_error; \
    }

#define ITEMS_TO_PARSER_ERROR(__CALL)                          \
    {                                                          \
        items_error_t __err = __CALL;                          \
        CHECK_APP_CANARY()                                     \
        if (__err != items_ok) return parser_unexpected_error; \
    }

typedef enum {
    key_signing,
    key_on_network,
    key_requiring,
    key_of_key,
    key_unscoped_signer,
    key_warning,
    key_caution,
    key_on_chain,
    key_using_gas,
    key_chain_id,
    key_paying_gas,
    key_transfer,
    key_from,
    key_to,
    key_amount,
    key_to_chain,
    key_rotate,
    key_unknown_capability,
    key_transaction_hash,
    key_sign_for_address,
} display_title_t;

typedef struct {
    display_title_t key;
    uint16_t json_token_index;
    bool_t can_display;
} item_t;

typedef enum {
    items_ok,
    items_length_zero,
    items_data_too_large,
    items_too_many_items,
    items_error,
} items_error_t;

typedef struct {
    item_t items[MAX_NUMBER_OF_ITEMS];
    uint8_t numOfItems;
    uint8_t numOfUnknownCapabilities;
    items_error_t (*toString[MAX_NUMBER_OF_ITEMS])(item_t item, char *outVal, uint16_t outValLen);
} item_array_t;
