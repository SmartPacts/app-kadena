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

#define CLA 0x00

#define HDPATH_LEN_DEFAULT 5
#define HDPATH_0_DEFAULT (0x80000000u | 0x2c)   // 44
#define HDPATH_1_DEFAULT (0x80000000u | 0x272)  // 626

#define HDPATH_2_DEFAULT (0x80000000u | 0u)
#define HDPATH_3_DEFAULT (0u)
#define HDPATH_4_DEFAULT (0u)

#define SECP256K1_PK_LEN 65u

#define SK_LEN_25519 64u
#define SCALAR_LEN_ED25519 32u
#define SIG_PLUS_TYPE_LEN 65u

#define ED25519_SIGNATURE_SIZE 64u

#define PUB_KEY_LENGTH 32u
#define SS58_ADDRESS_MAX_LEN 65u

#define MAX_SIGN_SIZE 256u
#define BLAKE2B_DIGEST_SIZE 32u

// Legacy commands
#define BCOMP_GET_VERSION 0x00
#define BCOMP_VERIFY_ADDRESS 0x01
#define BCOMP_GET_PUBKEY 0x02
#define BCOMP_SIGN_JSON_TX 0x03
#define BCOMP_SIGN_TX_HASH 0x04
#define BCOMP_MAKE_TRANSFER_TX 0x10
#define BCOMP_GET_VERSION_STR 0xFF

#define COIN_AMOUNT_DECIMAL_PLACES 6
#define COIN_TICKER "KDA "
// #define COIN_BASIC_UNIT " "

#define MENU_MAIN_APP_LINE1 "Kadena"
#define MENU_MAIN_APP_LINE2 "Ready"
#define APPVERSION_LINE1 "Kadena"
#define APPVERSION_LINE2 "v" APPVERSION

#ifdef __cplusplus
}
#endif
