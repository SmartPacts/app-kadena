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

#include <stdio.h>

#include "app_mode.h"
#include "coin.h"
#include "crypto.h"
#include "review_lock.h"
#include "zxerror.h"
#include "zxformat.h"
#include "zxmacros.h"

_Static_assert(REVIEW_LOCK_KEY_LEN == PUB_KEY_LENGTH, "address copy holds one public key");
_Static_assert(REVIEW_LOCK_PATH_LEN == HDPATH_LEN_DEFAULT, "address copy holds one full path");

zxerr_t addr_getNumItems(uint8_t *num_items) {
    zemu_log_stack("addr_getNumItems");
    *num_items = 1;
    if (app_mode_expert()) {
        *num_items = 2;
    }
    return zxerr_ok;
}

// A1/F5: the review shows the key and path copied when the command arrived (review_lock_begin_address),
// never the APDU buffer or the global path, which a later command could change while it is on screen.
zxerr_t addr_getItem(int8_t displayIdx, char *outKey, uint16_t outKeyLen, char *outVal, uint16_t outValLen, uint8_t pageIdx,
                     uint8_t *pageCount) {
    ZEMU_LOGF(50, "[addr_getItem] %d/%d\n", displayIdx, pageIdx)
    const uint8_t *key = review_lock_address_key();
    const uint32_t *path = review_lock_address_path();
    if (key == NULL || path == NULL) {
        return zxerr_no_data;
    }
    char address[(2 * PUB_KEY_LENGTH) + 1] = {0};
    switch (displayIdx) {
        case 0:
            snprintf(outKey, outKeyLen, "Address");
            if (array_to_hexstr(address, sizeof(address), key, PUB_KEY_LENGTH) == 0) {
                return zxerr_unknown;
            }
            pageString(outVal, outValLen, address, pageIdx, pageCount);
            return zxerr_ok;
        case 1: {
            if (!app_mode_expert()) {
                return zxerr_no_data;
            }

            snprintf(outKey, outKeyLen, "Your Path");
            char buffer[300];
            bip32_to_str(buffer, sizeof(buffer), path, HDPATH_LEN_DEFAULT);
            pageString(outVal, outValLen, buffer, pageIdx, pageCount);
            return zxerr_ok;
        }
        default:
            return zxerr_no_data;
    }
}

// A1/F5: writes the reply of the pending address review (the copied key) to out; returns its length,
// 0 when no address review is pending or out is too small.
uint16_t addr_writeReply(uint8_t *out, uint16_t outLen) {
    const uint8_t *key = review_lock_address_key();
    if (key == NULL || out == NULL || outLen < PUB_KEY_LENGTH) {
        return 0;
    }
    MEMCPY(out, key, PUB_KEY_LENGTH);
    return PUB_KEY_LENGTH;
}
