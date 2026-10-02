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
#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>
#include <stdint.h>

// S12: the one command answered while a signing review is pending (GET_DEVICE_INFO is answered by
// the library before the app's dispatcher).
#define REVIEW_LOCK_INS_GET_VERSION 0x20

/// Binds the digest computed while parsing to the review about to be shown and marks a signing review
/// as pending. Call it right before showing a signing review; false if nothing was parsed.
bool review_lock_begin();

/// Ends the pending signing review (approved or rejected) and forgets its digest.
void review_lock_end();

/// The 32-byte digest bound to the pending review: approval signs exactly these bytes, never a new
/// hash of a transaction buffer. False when no review is pending.
bool review_lock_digest(uint8_t *out, uint16_t outLen);

/// True while a signing review waits for the user.
bool review_lock_pending();

/// Whether the dispatcher may run a command with this INS now: always when no signing review is
/// pending, and only GET_VERSION while one is.
bool review_lock_allows(uint8_t ins);

#ifdef __cplusplus
}
#endif
