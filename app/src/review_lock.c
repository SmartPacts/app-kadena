/*******************************************************************************
 *  (c) 2026 Smart Pacts
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
#include "review_lock.h"

#include "items.h"
#include "zxmacros.h"

// S12 + A1/F5: what is waiting for the user, set when it is shown and cleared when it is answered.
static review_lock_kind_t pending = REVIEW_LOCK_NONE;

// A1/F5: what an address review shows and replies, copied when the command arrives. Nothing on the
// screen or in the reply is read from the APDU buffer or the global path after that.
static uint8_t address_key[REVIEW_LOCK_KEY_LEN];
static uint32_t address_path[REVIEW_LOCK_PATH_LEN];

// A1/F5: the reply of the "blind signing required" notice (the error text), copied when it is shown.
static char notice[REVIEW_LOCK_NOTICE_MAX];
static uint16_t notice_len = 0;

static void forget(void) {
    MEMZERO(address_key, sizeof(address_key));
    MEMZERO(address_path, sizeof(address_path));
    MEMZERO(notice, sizeof(notice));
    notice_len = 0;
}

bool review_lock_begin() {
    if (pending != REVIEW_LOCK_NONE || items_bindReviewDigest() != items_ok) {
        return false;
    }
    pending = REVIEW_LOCK_SIGNING;
    return true;
}

bool review_lock_begin_address(const uint8_t *key, uint16_t keyLen, const uint32_t *path, uint16_t pathLen) {
    if (pending != REVIEW_LOCK_NONE || key == NULL || path == NULL || keyLen != REVIEW_LOCK_KEY_LEN ||
        pathLen != REVIEW_LOCK_PATH_LEN) {
        return false;
    }
    forget();
    MEMCPY(address_key, key, sizeof(address_key));
    MEMCPY(address_path, path, sizeof(address_path));
    pending = REVIEW_LOCK_ADDRESS;
    return true;
}

bool review_lock_begin_notice(const char *msg, uint16_t msgLen) {
    if (pending != REVIEW_LOCK_NONE || msg == NULL || msgLen > sizeof(notice)) {
        return false;
    }
    forget();
    MEMCPY(notice, msg, msgLen);
    notice_len = msgLen;
    pending = REVIEW_LOCK_NOTICE;
    return true;
}

void review_lock_end() {
    items_clearReviewDigest();
    forget();
    pending = REVIEW_LOCK_NONE;
}

bool review_lock_digest(uint8_t *out, uint16_t outLen) {
    return pending == REVIEW_LOCK_SIGNING && items_getReviewDigest(out, outLen) == items_ok;
}

const uint8_t *review_lock_address_key() { return pending == REVIEW_LOCK_ADDRESS ? address_key : NULL; }

const uint32_t *review_lock_address_path() { return pending == REVIEW_LOCK_ADDRESS ? address_path : NULL; }

uint16_t review_lock_notice(uint8_t *out, uint16_t outLen) {
    if (pending != REVIEW_LOCK_NOTICE || out == NULL || notice_len > outLen) {
        return 0;
    }
    MEMCPY(out, notice, notice_len);
    return notice_len;
}

review_lock_kind_t review_lock_kind() { return pending; }

bool review_lock_pending() { return pending != REVIEW_LOCK_NONE; }

bool review_lock_allows(uint8_t ins) { return pending == REVIEW_LOCK_NONE || ins == REVIEW_LOCK_INS_GET_VERSION; }
