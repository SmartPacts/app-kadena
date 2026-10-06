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

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>
#include <stdint.h>

#define LEGACY_CHUNK_SIZE 230
#define LEGACY_HEADER_LENGTH 5
#define LEGACY_FULL_CHUNK_SIZE (LEGACY_CHUNK_SIZE + LEGACY_HEADER_LENGTH)
#define LEGACY_PAYLOAD_LEN_BYTES 4
#define LEGACY_OFFSET_HDPATH_SIZE 5
#define LEGACY_HDPATH_LEN_BYTES 1
#define LEGACY_TRANSFER_NUM_ITEMS 12
#define LEGACY_LOCAL_BUFFER_SIZE 33
#define LEGACY_NOT_SHOW_ADDRESS 0
#define LEGACY_SHOW_ADDRESS 1

// The signing stream shared by both command families (apdu_handler.c).
/// Opens a stream for this INS and keeps the current derivation path as its signing path.
void stream_open(uint8_t ins);
void stream_close();
/// True when a stream of this INS is open, false when none is; a stream of another INS is closed and
/// the command refused (0x6987).
bool stream_continues(uint8_t ins);
/// Puts the stream's signing path back into hdPath.
void stream_restorePath();

void legacy_handleGetVersion(volatile uint32_t *tx);
void legacy_handleGetAddr(volatile uint32_t *flags, volatile uint32_t *tx, uint32_t rx, uint8_t requireConfirmation);
void legacy_handleSignTransaction(volatile uint32_t *flags, volatile uint32_t *tx, uint32_t rx);
void legacy_handleSignHash(volatile uint32_t *flags, volatile uint32_t *tx, uint32_t rx);
void legacy_handleSignTransferTx(volatile uint32_t *flags, volatile uint32_t *tx, uint32_t rx);

#ifdef __cplusplus
}
#endif
