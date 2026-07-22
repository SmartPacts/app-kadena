/*******************************************************************************
 *   (c) 2018 - 2024 Zondax AG
 *   (c) 2016 Ledger
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

#include <os.h>
#include <os_io_seproxyhal.h>
#include <string.h>
#include <ux.h>

#include "actions.h"
#include "addr.h"
#include "apdu_handler_legacy.h"
#include "app_main.h"
#include "app_mode.h"
#include "coin.h"
#include "crypto.h"
#include "parser_txdef.h"
#include "tx.h"
#include "view.h"
#include "view_internal.h"
#include "zxmacros.h"

// This is for backward compatibility with the legacy app, we need to redefine some instructions
#undef INS_GET_VERSION
#define INS_GET_VERSION 0x20
#undef INS_GET_ADDR
#define INS_GET_ADDR 0x21
#undef INS_SIGN
#define INS_SIGN 0x22
#define INS_SIGN_HASH 0x23
#define INS_SIGN_TRANSFER 0x24

static bool tx_initialized = false;

// Global variable to store error message offset for custom error display
uint16_t G_error_message_offset = 0;

void extractHDPath(uint32_t rx, uint32_t offset) {
    tx_initialized = false;

    if ((rx - offset) < sizeof(uint32_t) * HDPATH_LEN_DEFAULT) {
        THROW(APDU_CODE_WRONG_LENGTH);
    }

    MEMCPY(hdPath, G_io_apdu_buffer + offset, sizeof(uint32_t) * HDPATH_LEN_DEFAULT);

    const bool mainnet = hdPath[0] == HDPATH_0_DEFAULT && hdPath[1] == HDPATH_1_DEFAULT;

    if (!mainnet) {
        THROW(APDU_CODE_DATA_INVALID);
    }
}

__Z_INLINE bool process_chunk(__Z_UNUSED volatile uint32_t *tx, uint32_t rx) {
    const uint8_t payloadType = G_io_apdu_buffer[OFFSET_PAYLOAD_TYPE];
    if (rx < OFFSET_DATA) {
        THROW(APDU_CODE_WRONG_LENGTH);
    }

    uint32_t added = 0;
    switch (payloadType) {
        case P1_INIT:
            tx_initialize();
            tx_reset();
            extractHDPath(rx, OFFSET_DATA);
            tx_initialized = true;
            return false;
        case P1_ADD:
            if (!tx_initialized) {
                THROW(APDU_CODE_TX_NOT_INITIALIZED);
            }
            added = tx_append(&(G_io_apdu_buffer[OFFSET_DATA]), rx - OFFSET_DATA);
            if (added != rx - OFFSET_DATA) {
                tx_initialized = false;
                THROW(APDU_CODE_OUTPUT_BUFFER_TOO_SMALL);
            }
            return false;
        case P1_LAST:
            if (!tx_initialized) {
                THROW(APDU_CODE_TX_NOT_INITIALIZED);
            }
            added = tx_append(&(G_io_apdu_buffer[OFFSET_DATA]), rx - OFFSET_DATA);
            tx_initialized = false;
            if (added != rx - OFFSET_DATA) {
                tx_initialized = false;
                THROW(APDU_CODE_OUTPUT_BUFFER_TOO_SMALL);
            }
            tx_initialized = false;
            return true;
        default:
            break;
    }

    THROW(APDU_CODE_INVALIDP1P2);
    return false;
}

__Z_INLINE void handleGetAddr(volatile uint32_t *flags, volatile uint32_t *tx, uint32_t rx) {
    extractHDPath(rx, OFFSET_DATA);

    const uint8_t requireConfirmation = G_io_apdu_buffer[OFFSET_P1];
    zxerr_t zxerr = app_fill_address();
    if (zxerr != zxerr_ok) {
        *tx = 0;
        THROW(APDU_CODE_DATA_INVALID);
    }
    if (requireConfirmation) {
        view_review_init(addr_getItem, addr_getNumItems, app_reply_address);
        view_review_show(REVIEW_ADDRESS);
        *flags |= IO_ASYNCH_REPLY;
        return;
    }
    *tx = action_addrResponseLen;
    THROW(APDU_CODE_OK);
}

__Z_INLINE void handleSign(volatile uint32_t *flags, volatile uint32_t *tx, uint32_t rx) {
    zemu_log("handleSignJson\n");
    if (!process_chunk(tx, rx)) {
        THROW(APDU_CODE_OK);
    }

    // Reset BLS UI for next transaction
    app_mode_skip_blindsign_ui();

    uint8_t error_code = 0;
    const char *error_msg = tx_parse(tx_get_buffer_length(), get_tx_type(), &error_code);
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

    view_review_init(tx_getItem, tx_getNumItems, app_sign);
    view_review_show(REVIEW_TXN);
    *flags |= IO_ASYNCH_REPLY;
}

__Z_INLINE void handle_getversion(__Z_UNUSED volatile uint32_t *flags, volatile uint32_t *tx) {
    G_io_apdu_buffer[0] = 0;

#if defined(APP_TESTING)
    G_io_apdu_buffer[0] = 0x01;
#endif

    G_io_apdu_buffer[1] = (MAJOR_VERSION >> 8) & 0xFF;
    G_io_apdu_buffer[2] = (MAJOR_VERSION >> 0) & 0xFF;

    G_io_apdu_buffer[3] = (MINOR_VERSION >> 8) & 0xFF;
    G_io_apdu_buffer[4] = (MINOR_VERSION >> 0) & 0xFF;

    G_io_apdu_buffer[5] = (PATCH_VERSION >> 8) & 0xFF;
    G_io_apdu_buffer[6] = (PATCH_VERSION >> 0) & 0xFF;

    G_io_apdu_buffer[7] = !IS_UX_ALLOWED;

    G_io_apdu_buffer[8] = (TARGET_ID >> 24) & 0xFF;
    G_io_apdu_buffer[9] = (TARGET_ID >> 16) & 0xFF;
    G_io_apdu_buffer[10] = (TARGET_ID >> 8) & 0xFF;
    G_io_apdu_buffer[11] = (TARGET_ID >> 0) & 0xFF;

    *tx += 12;
    THROW(APDU_CODE_OK);
}

#if defined(APP_TESTING)
void handleTest(volatile uint32_t *flags, volatile uint32_t *tx, uint32_t rx) { THROW(APDU_CODE_OK); }
#endif

void handleApdu(volatile uint32_t *flags, volatile uint32_t *tx, uint32_t rx) {
    volatile uint16_t sw = 0;

    // Reset error message offset at the beginning of each command
    G_error_message_offset = 0;

    BEGIN_TRY {
        TRY {
            if (G_io_apdu_buffer[OFFSET_CLA] != CLA) {
                THROW(APDU_CODE_CLA_NOT_SUPPORTED);
            }

            if (rx < APDU_MIN_LENGTH) {
                THROW(APDU_CODE_WRONG_LENGTH);
            }

            switch (G_io_apdu_buffer[OFFSET_INS]) {
                case INS_GET_VERSION: {
                    handle_getversion(flags, tx);
                    break;
                }

                case INS_GET_ADDR: {
                    CHECK_PIN_VALIDATED()
                    handleGetAddr(flags, tx, rx);
                    break;
                }

                case INS_SIGN: {
                    CHECK_PIN_VALIDATED()
                    set_tx_type(tx_type_json);
                    handleSign(flags, tx, rx);
                    break;
                }

                case INS_SIGN_HASH: {
                    CHECK_PIN_VALIDATED()
                    set_tx_type(tx_type_hash);
                    handleSign(flags, tx, rx);
                    break;
                }

                case INS_SIGN_TRANSFER: {
                    CHECK_PIN_VALIDATED()
                    set_tx_type(tx_type_transfer);
                    handleSign(flags, tx, rx);
                    break;
                }

                case BCOMP_GET_VERSION: {
                    CHECK_PIN_VALIDATED()
                    legacy_handleGetVersion(tx);
                    break;
                }

                case BCOMP_VERIFY_ADDRESS: {
                    CHECK_PIN_VALIDATED()
                    legacy_handleGetAddr(flags, tx, rx, LEGACY_SHOW_ADDRESS);
                    break;
                }

                case BCOMP_GET_PUBKEY: {
                    CHECK_PIN_VALIDATED()
                    legacy_handleGetAddr(flags, tx, rx, LEGACY_NOT_SHOW_ADDRESS);
                    break;
                }

                case BCOMP_SIGN_JSON_TX: {
                    CHECK_PIN_VALIDATED()
                    legacy_handleSignTransaction(flags, tx, rx);
                    break;
                }

                case BCOMP_SIGN_TX_HASH: {
                    CHECK_PIN_VALIDATED()
                    legacy_handleSignHash(flags, tx, rx);
                    break;
                }

                case BCOMP_MAKE_TRANSFER_TX: {
                    CHECK_PIN_VALIDATED()
                    legacy_handleSignTransferTx(flags, tx, rx);
                    break;
                }

#if defined(APP_TESTING)
                case INS_TEST: {
                    handleTest(flags, tx, rx);
                    THROW(APDU_CODE_OK);
                    break;
                }
#endif
                default:
                    THROW(APDU_CODE_INS_NOT_SUPPORTED);
            }
        }
        CATCH(EXCEPTION_IO_RESET) { THROW(EXCEPTION_IO_RESET); }
        CATCH_OTHER(e) {
            switch (e & 0xF000) {
                case 0x6000:
                case APDU_CODE_OK:
                    sw = e;
                    break;
                default:
                    sw = 0x6800 | (e & 0x7FF);
                    break;
            }
            G_io_apdu_buffer[*tx] = sw >> 8;
            G_io_apdu_buffer[*tx + 1] = sw & 0xFF;
            *tx += 2;
        }
        FINALLY {}
    }
    END_TRY;
}
