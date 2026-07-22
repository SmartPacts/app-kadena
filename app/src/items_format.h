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

#include "items_defs.h"
#include "zxtypes.h"

#define WARNING_TEXT                                                                                                   \
    "UNSAFE TRANSACTION. This transaction's code was not recognized and does not limit capabilities for all signers. " \
    "Signing this transaction may make arbitrary actions on the chain including loss of all funds."
#define HASH_WARNING_TEXT \
    "Blind Signing a Transaction Hash is a very unusual operation. Do not continue unless you know what you are doing"
#define CAUTION_TEXT "'meta' field of transaction not recognized"
#define TX_TOO_LARGE_TEXT \
    "Transaction too large for Ledger to display.  PROCEED WITH GREAT CAUTION.  Do you want to continue?"

items_error_t items_stdToDisplayString(item_t item, char *outVal, uint16_t outValLen);
items_error_t items_nothingToDisplayString(__Z_UNUSED item_t item, char *outVal, uint16_t outValLen);
items_error_t items_warningToDisplayString(__Z_UNUSED item_t item, char *outVal, uint16_t outValLen);
items_error_t items_hashWarningToDisplayString(__Z_UNUSED item_t item, char *outVal, uint16_t outValLen);
items_error_t items_cautionToDisplayString(__Z_UNUSED item_t item, char *outVal, uint16_t outValLen);
items_error_t items_txTooLargeToDisplayString(__Z_UNUSED item_t item, char *outVal, uint16_t outValLen);
items_error_t items_signingToDisplayString(item_t item, char *outVal, uint16_t outValLen);
items_error_t items_requiringToDisplayString(item_t item, char *outVal, uint16_t outValLen);
items_error_t items_amountToDisplayString(item_t item, char *outVal, uint16_t outValLen);
items_error_t items_transferToDisplayString(item_t item, char *outVal, uint16_t outValLen);
items_error_t items_crossTransferToDisplayString(item_t item, char *outVal, uint16_t outValLen);
items_error_t items_rotateToDisplayString(item_t item, char *outVal, uint16_t outValLen);
items_error_t items_gasToDisplayString(item_t item, char *outVal, uint16_t outValLen);
items_error_t items_hashToDisplayString(item_t item, char *outVal, uint16_t outValLen);
items_error_t items_unknownCapabilityToDisplayString(item_t item, char *outVal, uint16_t outValLen);
#if defined(LEDGER_SPECIFIC)
items_error_t items_signForAddrToDisplayString(__Z_UNUSED item_t item, char *outVal, uint16_t outValLen);
#endif
