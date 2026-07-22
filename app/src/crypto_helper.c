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

#include "crypto_helper.h"

#if defined(LEDGER_SPECIFIC)
#include "cx.h"

zxerr_t blake2b_hash(const unsigned char *in, unsigned int inLen, unsigned char *out) {
    cx_blake2b_t ctx;
    if (cx_blake2b_init2_no_throw(&ctx, BLAKE2B_OUTPUT_LEN, NULL, 0, NULL, 0) != CX_OK ||
        cx_hash_no_throw(&ctx.header, CX_LAST, in, inLen, out, 32) != CX_OK) {
        return zxerr_invalid_crypto_settings;
    }

    return zxerr_ok;
}

#else

#include "blake2.h"
#include "hexutils.h"

zxerr_t blake2b_hash(const unsigned char *in, unsigned int inLen, unsigned char *out) {
    int result = blake2(out, BLAKE2B_OUTPUT_LEN, in, inLen, NULL, 0);
    if (result != 0) {
        return zxerr_unknown;
    } else {
        return zxerr_ok;
    }
}

#endif