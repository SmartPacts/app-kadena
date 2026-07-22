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

#include "apdu_handler_legacy.h"

#include "actions.h"
#include "addr.h"
#include "app_mode.h"
#include "view_internal.h"

static bool tx_initialized = false;
static uint32_t payload_length = 0;
static uint32_t hdpath_length = 0;
static tx_type_t tx_type = tx_type_json;
static uint8_t local_data_len = 0;
static uint8_t local_data[LEGACY_LOCAL_BUFFER_SIZE];
static uint8_t items = 0;
static uint8_t item_len = 0;
static bool check_item_len = false;

void legacy_app_sign() {
    const uint8_t *message = tx_get_buffer();
    const uint16_t messageLength = tx_get_buffer_length() - hdpath_length;

    const zxerr_t err = crypto_sign(G_io_apdu_buffer, IO_APDU_BUFFER_SIZE - 3, message, messageLength, tx_type);

    if (err != zxerr_ok) {
        set_code(G_io_apdu_buffer, 0, APDU_CODE_SIGN_VERIFY_ERROR);
        io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, 2);
    } else {
        set_code(G_io_apdu_buffer, SK_LEN_25519, APDU_CODE_OK);
        io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, SK_LEN_25519 + 2);
    }
}

void legacy_app_sign_transference() {
    const uint8_t *message = tx_json_get_buffer();
    const uint16_t messageLength = tx_json_get_buffer_length();

    // get pubkey
    zxerr_t zxerr = app_fill_address();
    if (zxerr != zxerr_ok) {
        THROW(APDU_CODE_DATA_INVALID);
    }
    MEMMOVE(G_io_apdu_buffer + SK_LEN_25519, G_io_apdu_buffer, action_addrResponseLen);

    zxerr = crypto_sign(G_io_apdu_buffer, IO_APDU_BUFFER_SIZE - 3, message, messageLength, tx_type);

    if (zxerr != zxerr_ok) {
        set_code(G_io_apdu_buffer, 0, APDU_CODE_SIGN_VERIFY_ERROR);
        io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, 2);
    } else {
        set_code(G_io_apdu_buffer, SK_LEN_25519 + action_addrResponseLen, APDU_CODE_OK);
        io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, SK_LEN_25519 + action_addrResponseLen + 2);
    }
}

void legacy_app_reply_address() {
    if (action_addrResponseLen + 1 > sizeof(G_io_apdu_buffer)) {
        THROW(APDU_CODE_OUTPUT_BUFFER_TOO_SMALL);
    }

    // Add the pubkey length to the beginning of the buffer
    MEMMOVE(G_io_apdu_buffer + 1, G_io_apdu_buffer, action_addrResponseLen);
    G_io_apdu_buffer[0] = action_addrResponseLen;
    action_addrResponseLen += 1;

    set_code(G_io_apdu_buffer, action_addrResponseLen, APDU_CODE_OK);
    io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, action_addrResponseLen + 2);
}

void legacy_extractHDPath(uint8_t *buffer, uint32_t rx, uint32_t offset, uint8_t check_len) {
    if (rx < offset) {
        THROW(APDU_CODE_WRONG_LENGTH);
    }

    uint8_t hdPathQty = buffer[offset];
    uint8_t hdPathLen = hdPathQty * sizeof(uint32_t);
    uint32_t offset_hdpath_data = offset + 1;

    if ((check_len == 1) && (rx - offset_hdpath_data != hdPathLen)) {
        THROW(APDU_CODE_WRONG_LENGTH);
    }

    MEMCPY(hdPath, buffer + offset_hdpath_data, hdPathLen);

    const bool mainnet = hdPath[0] == HDPATH_0_DEFAULT && hdPath[1] == HDPATH_1_DEFAULT;

    if (!mainnet) {
        THROW(APDU_CODE_DATA_INVALID);
    }

    // store hdPathLen + 1 byte for the hdPathQty
    hdpath_length = hdPathLen + LEGACY_HDPATH_LEN_BYTES;
}

bool legacy_check_end_of_chunk() {
    uint32_t tx_buffer_length = tx_get_buffer_length();

    if (payload_length < tx_buffer_length) {
        uint8_t *tx_buffer = tx_get_buffer();
        uint8_t hdPathQty = tx_buffer[payload_length];
        uint8_t hdPathLen = hdPathQty * sizeof(uint32_t);
        if ((payload_length + hdPathLen + LEGACY_HDPATH_LEN_BYTES) == tx_buffer_length) {
            return true;
        }
    }
    return false;
}

uint32_t legacy_check_request(volatile uint32_t *tx) {
    // check buffer length
    uint32_t tx_buffer_length = tx_get_buffer_length();
    uint8_t *tx_buffer = tx_get_buffer();
    int64_t hdpath_size = (int64_t)tx_buffer_length - (int64_t)payload_length;

    if (hdpath_size < 0) {
        *tx = 0;
        tx_reset();
        THROW(APDU_CODE_DATA_INVALID);
    }

    // get hdpath
    legacy_extractHDPath(tx_buffer, tx_buffer_length, payload_length, 1);

    // verify sizes
    if (tx_buffer_length != hdpath_length + payload_length) {
        tx_reset();
        *tx = 0;
        THROW(APDU_CODE_DATA_INVALID);
    }

    // return the buffer length of payload
    return tx_buffer_length - hdpath_length;
}

void legacy_append_data(uint8_t *buffer, uint32_t len) {
    uint32_t added = tx_append(buffer, len);

    if (added != len) {
        tx_reset();
        tx_initialized = false;
        THROW(APDU_CODE_OUTPUT_BUFFER_TOO_SMALL);
    }
}

bool legacy_process_chunk(__Z_UNUSED volatile uint32_t *tx, uint32_t rx, bool has_len, uint32_t fixed_len) {
    if (rx < LEGACY_HEADER_LENGTH) {
        tx_initialized = false;
        THROW(APDU_CODE_WRONG_LENGTH);
    }

    uint32_t offset = LEGACY_HEADER_LENGTH;
    uint32_t payload_size = rx - offset;

    if (!tx_initialized) {
        // read length of data
        if (has_len) {
            payload_length = (uint32_t)G_io_apdu_buffer[5] | ((uint32_t)G_io_apdu_buffer[6] << 8) |
                             ((uint32_t)G_io_apdu_buffer[7] << 16) | ((uint32_t)G_io_apdu_buffer[8] << 24);

            offset = LEGACY_PAYLOAD_LEN_BYTES + LEGACY_HEADER_LENGTH;
            payload_size = rx - offset;
            if (rx < offset) {
                THROW(APDU_CODE_WRONG_LENGTH);
            }
        } else {
            payload_length = fixed_len;
        }

        tx_initialize();
        tx_reset();
        tx_initialized = true;
    }

    legacy_append_data(&(G_io_apdu_buffer[offset]), payload_size);

    // Check if the end of the chunk is reached
    if ((rx < LEGACY_CHUNK_SIZE + LEGACY_HEADER_LENGTH) || legacy_check_end_of_chunk()) {
        tx_initialized = false;
        return true;
    }

    return false;
}

static uint32_t legacy_initialize_transfer() {
    legacy_extractHDPath(G_io_apdu_buffer, LEGACY_OFFSET_HDPATH_SIZE + 1, LEGACY_OFFSET_HDPATH_SIZE, 0);

    tx_initialize();
    tx_reset();
    tx_initialized = true;

    uint32_t offset = hdpath_length + LEGACY_OFFSET_HDPATH_SIZE;

    // save tx_type
    legacy_append_data(&G_io_apdu_buffer[offset], 1);
    items = 0;

    return offset;
}

static uint32_t legacy_process_existing_transfer(uint32_t *payload_size) {
    legacy_append_data(local_data, local_data_len);

    uint32_t offset = LEGACY_HEADER_LENGTH;

    if (check_item_len) {
        *payload_size = G_io_apdu_buffer[offset];
        legacy_append_data(&G_io_apdu_buffer[offset], *payload_size + 1);
    } else {
        if (item_len <= local_data_len) {
            THROW(APDU_CODE_DATA_INVALID);
        }
        *payload_size = item_len - local_data_len;
        legacy_append_data(&G_io_apdu_buffer[offset], *payload_size);
        offset--;
    }

    items++;
    local_data_len = 0;

    return offset;
}

static void legacy_handle_overflow(uint32_t offset, uint32_t payload_size) {
    check_item_len = false;
    item_len = payload_size + 1;

    if (offset > LEGACY_FULL_CHUNK_SIZE) {
        THROW(APDU_CODE_DATA_INVALID);
    }
    local_data_len = LEGACY_FULL_CHUNK_SIZE - offset;
    if (local_data_len >= LEGACY_LOCAL_BUFFER_SIZE) {
        THROW(APDU_CODE_OUTPUT_BUFFER_TOO_SMALL);
    }
    MEMCPY(local_data, &G_io_apdu_buffer[offset], local_data_len);
}

bool legacy_process_transfer_chunk(uint32_t rx) {
    if (rx < LEGACY_HEADER_LENGTH) {
        tx_initialized = false;
        THROW(APDU_CODE_WRONG_LENGTH);
    }

    uint32_t payload_size = 0;
    uint32_t offset = tx_initialized ? legacy_process_existing_transfer(&payload_size) : legacy_initialize_transfer();

    while (offset < rx) {
        offset += payload_size + 1;

        if (offset > rx) {
            tx_initialized = false;
            THROW(APDU_CODE_DATA_INVALID);
        }

        if (offset == LEGACY_FULL_CHUNK_SIZE) {
            check_item_len = true;
            return false;
        }

        payload_size = G_io_apdu_buffer[offset];
        uint32_t next_offset = offset + payload_size + 1;

        if (next_offset > LEGACY_FULL_CHUNK_SIZE) {
            legacy_handle_overflow(offset, payload_size);
            return false;
        }

        legacy_append_data(&G_io_apdu_buffer[offset], payload_size + 1);

        if (++items > LEGACY_TRANSFER_NUM_ITEMS) {
            tx_initialized = false;
            THROW(APDU_CODE_DATA_INVALID);
        }

        if (next_offset >= rx && next_offset != LEGACY_FULL_CHUNK_SIZE) {
            tx_initialized = false;
            if (items != LEGACY_TRANSFER_NUM_ITEMS) {
                THROW(APDU_CODE_DATA_INVALID);
            }
            return true;
        }
    }

    THROW(APDU_CODE_DATA_INVALID);
    return false;
}

void legacy_handleGetVersion(volatile uint32_t *tx) {
    G_io_apdu_buffer[0] = (MAJOR_VERSION >> 0) & 0xFF;
    G_io_apdu_buffer[1] = (MINOR_VERSION >> 0) & 0xFF;
    G_io_apdu_buffer[2] = (PATCH_VERSION >> 0) & 0xFF;

    *tx += 3;
    THROW(APDU_CODE_OK);
}

void legacy_handleGetAddr(volatile uint32_t *flags, volatile uint32_t *tx, uint32_t rx, const uint8_t requireConfirmation) {
    legacy_extractHDPath(G_io_apdu_buffer, rx, LEGACY_OFFSET_HDPATH_SIZE, 1);

    zxerr_t zxerr = app_fill_address();
    if (zxerr != zxerr_ok) {
        *tx = 0;
        THROW(APDU_CODE_DATA_INVALID);
    }
    if (requireConfirmation) {
        view_review_init(addr_getItem, addr_getNumItems, legacy_app_reply_address);
        view_review_show(REVIEW_ADDRESS);
        *flags |= IO_ASYNCH_REPLY;
        return;
    }

    // Add the pubkey length to the beginning of the buffer
    MEMMOVE(G_io_apdu_buffer + 1, G_io_apdu_buffer, action_addrResponseLen);
    G_io_apdu_buffer[0] = action_addrResponseLen;

    *tx = action_addrResponseLen + 1;
    THROW(APDU_CODE_OK);
}

// bytes: |  1  |  1  |  1 |  1 |    1       |      4      |  payload_len  |      1     |  4*hdpath_qty  |
// data:  | CLA | INS | P1 | P2 | chunk_len  | payload_len |    payload    | hdpath_qty |  hdpath_data   |
void legacy_handleSignTransaction(volatile uint32_t *flags, volatile uint32_t *tx, uint32_t rx) {
    zemu_log("handleSignTransactionLegacy\n");
    if (!legacy_process_chunk(tx, rx, true, 0)) {
        THROW(APDU_CODE_OK);
    }

    uint32_t buffer_length = legacy_check_request(tx);

    // Reset BLS UI for next transaction
    app_mode_skip_blindsign_ui();

    const char *error_msg = tx_parse(buffer_length, tx_type_json, NULL);
    tx_type = tx_type_json;
    CHECK_APP_CANARY()
    if (error_msg != NULL) {
        tx_reset();
        *tx = 0;
        THROW(APDU_CODE_DATA_INVALID);
    }

    view_review_init(tx_getItem, tx_getNumItems, legacy_app_sign);
    view_review_show(REVIEW_TXN);
    *flags |= IO_ASYNCH_REPLY;
}

// bytes: |  1  |  1  |  1 |  1 |  32  |     1      |  4*hdpath_qty  |
// data:  | CLA | INS | P1 | P2 | hash | hdpath_qty |  hdpath_data   |
void legacy_handleSignHash(volatile uint32_t *flags, volatile uint32_t *tx, uint32_t rx) {
    zemu_log("handleSignLegacyHash\n");
    if (!legacy_process_chunk(tx, rx, false, 32)) {
        THROW(APDU_CODE_OK);
    }

    uint32_t buffer_length = legacy_check_request(tx);

    uint8_t error_code = 0;
    const char *error_msg = tx_parse(buffer_length, tx_type_hash, &error_code);
    tx_type = tx_type_hash;
    CHECK_APP_CANARY()
    if (error_msg != NULL) {
        const int error_msg_length = strnlen(error_msg, sizeof(G_io_apdu_buffer));
        // Ensure we have space for error message + 2 bytes for error code
        if (error_msg_length > (int)(sizeof(G_io_apdu_buffer) - 2)) {
            *tx = 0;
            THROW(APDU_CODE_OUTPUT_BUFFER_TOO_SMALL);
        }
        MEMZERO(G_io_apdu_buffer, IO_APDU_BUFFER_SIZE);
        MEMCPY(G_io_apdu_buffer, error_msg, error_msg_length);
        *tx += (error_msg_length);
        if (error_code == parser_blindsign_mode_required) {
            G_error_message_offset = error_msg_length;
            *flags |= IO_ASYNCH_REPLY;
            view_blindsign_error_show();
        }
        THROW(APDU_CODE_DATA_INVALID);
    }

    view_review_init(tx_getItem, tx_getNumItems, legacy_app_sign);
    view_review_show(REVIEW_TXN);
    *flags |= IO_ASYNCH_REPLY;
}

// clang-format off
// bytes: |  1  |  1  |  1 |  1 |     1      |  4*hdpath_qty  |      1      | param_1_len  |       1      | param_2_len  | ... |       1       | param_12_len  |
// data:  | CLA | INS | P1 | P2 | hdpath_qty |  hdpath_data   | param_1_len | param_1_data |  param_2_len | param_2_data | ... |  param_12_len | param_12_data |
// clang-format on
void legacy_handleSignTransferTx(volatile uint32_t *flags, volatile uint32_t *tx, uint32_t rx) {
    zemu_log("handleSignLegacyTransferTx\n");
    if (!legacy_process_transfer_chunk(rx)) {
        THROW(APDU_CODE_OK);
    }

    uint32_t buffer_length = tx_get_buffer_length();

    // Reset BLS UI for next transaction
    app_mode_skip_blindsign_ui();

    const char *error_msg = tx_parse(buffer_length, tx_type_transfer, NULL);
    tx_type = tx_type_transfer;
    CHECK_APP_CANARY()
    if (error_msg != NULL) {
        tx_reset();
        *tx = 0;
        THROW(APDU_CODE_DATA_INVALID);
    }

    view_review_init(tx_getItem, tx_getNumItems, legacy_app_sign_transference);
    view_review_show(REVIEW_TXN);
    *flags |= IO_ASYNCH_REPLY;
}
