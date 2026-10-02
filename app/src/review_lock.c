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

// S12: set while a signing review waits for the user, cleared when it is approved or rejected.
static bool review_pending = false;

bool review_lock_begin() {
    if (items_bindReviewDigest() != items_ok) {
        return false;
    }
    review_pending = true;
    return true;
}

void review_lock_end() {
    items_clearReviewDigest();
    review_pending = false;
}

bool review_lock_digest(uint8_t *out, uint16_t outLen) { return items_getReviewDigest(out, outLen) == items_ok; }

bool review_lock_pending() { return review_pending; }

bool review_lock_allows(uint8_t ins) { return !review_pending || ins == REVIEW_LOCK_INS_GET_VERSION; }
