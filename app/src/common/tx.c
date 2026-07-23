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

#include "tx.h"

#include <string.h>

#include "apdu_codes.h"
#include "buffering.h"
#include "buffering_json.h"
#include "parser.h"
#include "zxmacros.h"

// Must hold the largest transfer template parser_formatTxTransfer can assemble. The
// worst case is a cross-chain transfer with every field at its parser_validate_chunks
// cap (recipient 64, namespace 63, module 32, network 20, amount 32, nonce 32, gas
// 20/10, the 64-hex device address repeated) = 1191 bytes + NUL. 1280 leaves margin;
// the total storage_t stays 16384 (raw buffer shrinks to 15104, still ample). The
// buffer is registered with its real size in tx_json_initialize and every append is
// checked in parser_formatTxTransfer, so an over-cap template fails closed.
#define TEMPLATE_JSON_BUFFER_SIZE 1280
#if !defined(TARGET_NANOS)
#define RAM_BUFFER_SIZE 8192
#define FLASH_BUFFER_SIZE (16384 - TEMPLATE_JSON_BUFFER_SIZE)
#else
#define RAM_BUFFER_SIZE 256
#define FLASH_BUFFER_SIZE (8192 - TEMPLATE_JSON_BUFFER_SIZE)
#endif

// Ram
uint8_t ram_buffer[RAM_BUFFER_SIZE];

tx_type_t tx_type;

// Flash
typedef struct {
    uint8_t buffer[FLASH_BUFFER_SIZE];
    uint8_t templete_json[TEMPLATE_JSON_BUFFER_SIZE];
} storage_t;

#if defined(LEDGER_SPECIFIC)
storage_t NV_CONST N_appdata_impl __attribute__((aligned(64)));
#define N_appdata (*(NV_VOLATILE storage_t *)PIC(&N_appdata_impl))
#else
storage_t N_appdata_impl __attribute__((aligned(64)));
#define N_appdata (*(storage_t *)PIC(&N_appdata_impl))
#endif

static parser_context_t ctx_parsed_tx;

void set_tx_type(tx_type_t type) { tx_type = type; }

tx_type_t get_tx_type() { return tx_type; }

void tx_json_initialize() {
    // Register the template buffer with its ACTUAL size. templete_json is
    // TEMPLATE_JSON_BUFFER_SIZE (1280) bytes and is the last member of storage_t;
    // registering it as FLASH_BUFFER_SIZE (15104) let buffering_json_append write far
    // past it into adjacent NVRAM. Mirror the raw-buffer call below (sizeof).
    buffering_json_init((uint8_t *)N_appdata.templete_json, sizeof(N_appdata.templete_json));
}

void tx_json_reset() { buffering_json_reset(); }

uint32_t tx_json_append(unsigned char *buffer, uint32_t length) { return buffering_json_append(buffer, length); }

uint32_t tx_json_get_buffer_length() { return buffering_json_get_buffer()->pos; }

uint8_t *tx_json_get_buffer() { return buffering_json_get_buffer()->data; }

void tx_initialize() {
    buffering_init(ram_buffer, sizeof(ram_buffer), (uint8_t *)N_appdata.buffer, sizeof(N_appdata.buffer));
    tx_json_initialize();
}

void tx_reset() {
    buffering_reset();
    tx_json_reset();
}

uint32_t tx_append(unsigned char *buffer, uint32_t length) { return buffering_append(buffer, length); }

uint32_t tx_get_buffer_length() { return buffering_get_buffer()->pos; }

uint8_t *tx_get_buffer() { return buffering_get_buffer()->data; }

const char *tx_parse(uint32_t buffer_length, tx_type_t tx_type_parse, uint8_t *error_code) {
    uint8_t err = parser_parse(&ctx_parsed_tx, tx_get_buffer(), buffer_length, tx_type_parse);
    if (error_code != NULL) {
        *error_code = err;
    }

    CHECK_APP_CANARY()

    if (err != parser_ok) {
        return parser_getErrorDescription(err);
    }

    err = parser_validate(&ctx_parsed_tx);
    CHECK_APP_CANARY()

    if (err != parser_ok) {
        return parser_getErrorDescription(err);
    }

    return NULL;
}

zxerr_t tx_getNumItems(uint8_t *num_items) {
    parser_error_t err = parser_getNumItems(&ctx_parsed_tx, num_items);

    if (err != parser_ok) {
        return zxerr_unknown;
    }

    return zxerr_ok;
}

zxerr_t tx_getItem(int8_t displayIdx, char *outKey, uint16_t outKeyLen, char *outVal, uint16_t outValLen, uint8_t pageIdx,
                   uint8_t *pageCount) {
    uint8_t numItems = 0;

    CHECK_ZXERR(tx_getNumItems(&numItems))

    if (displayIdx >= numItems) {
        return zxerr_no_data;
    }

    parser_error_t err =
        parser_getItem(&ctx_parsed_tx, displayIdx, outKey, outKeyLen, outVal, outValLen, pageIdx, pageCount);

    // Convert error codes
    if (err == parser_no_data || err == parser_display_idx_out_of_range || err == parser_display_page_out_of_range) {
        return zxerr_no_data;
    }

    if (err != parser_ok) {
        return zxerr_unknown;
    }

    return zxerr_ok;
}
