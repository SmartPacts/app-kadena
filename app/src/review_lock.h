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

// S12: the one command answered while a review is pending (GET_DEVICE_INFO is answered by the
// library before the app's dispatcher).
#define REVIEW_LOCK_INS_GET_VERSION 0x20

// A1/F5: sizes of the copies an address review and the blind-signing notice keep.
#define REVIEW_LOCK_KEY_LEN 32     // an ed25519 public key (PUB_KEY_LENGTH)
#define REVIEW_LOCK_PATH_LEN 5     // the derivation path components (HDPATH_LEN_DEFAULT)
#define REVIEW_LOCK_NOTICE_MAX 64  // the longest parser error text, with room to spare

// What waits for the user. Each kind locks the app the same way: only GET_VERSION is answered.
typedef enum {
    REVIEW_LOCK_NONE = 0,
    REVIEW_LOCK_SIGNING,  // a transaction or hash review; approval signs the bound digest
    REVIEW_LOCK_ADDRESS,  // an address review; it shows and replies the copied key
    REVIEW_LOCK_NOTICE,   // the "blind signing required" notice; it replies the copied text
} review_lock_kind_t;

/// Binds the digest computed while parsing to the review about to be shown and marks a signing review
/// as pending. Call it right before showing a signing review; false if nothing was parsed or another
/// review is pending.
bool review_lock_begin();

/// A1/F5: marks an address review as pending and keeps a copy of the key and path it shows and
/// replies. Call it when the command arrives, right before showing the review; false if another
/// review is pending or a length is wrong.
bool review_lock_begin_address(const uint8_t *key, uint16_t keyLen, const uint32_t *path, uint16_t pathLen);

/// A1/F5: marks the blind-signing-required notice as pending and keeps a copy of the text its reply
/// carries. False if another review is pending or the text is longer than REVIEW_LOCK_NOTICE_MAX.
bool review_lock_begin_notice(const char *msg, uint16_t msgLen);

/// Ends whatever is pending (approved, rejected or dismissed) and forgets its digest and copies.
void review_lock_end();

/// The 32-byte digest bound to the pending signing review: approval signs exactly these bytes, never a
/// new hash of a transaction buffer. False when no signing review is pending.
bool review_lock_digest(uint8_t *out, uint16_t outLen);

/// The key and path copied for the pending address review; NULL when none is pending.
const uint8_t *review_lock_address_key();
const uint32_t *review_lock_address_path();

/// Copies the pending notice's text to out; returns its length (0 when no notice is pending or it
/// does not fit).
uint16_t review_lock_notice(uint8_t *out, uint16_t outLen);

/// What is pending now.
review_lock_kind_t review_lock_kind();

/// True while anything waits for the user.
bool review_lock_pending();

/// Whether the dispatcher may run a command with this INS now: always when nothing is pending, and
/// only GET_VERSION while a review, an address review or the notice is.
bool review_lock_allows(uint8_t ins);

#ifdef __cplusplus
}
#endif
