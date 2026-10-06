/*******************************************************************************
 *   (c) 2026 Smart Pacts
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

// A JSON transaction is one JSON value and every signed byte belongs to it. The tokenizer stops at a
// NUL byte, so bytes after a NUL were signed without being parsed or shown; a NUL anywhere is refused.
// (The vectors in testcases.json are read up to their first NUL, so these cases are here.) Trailing
// bytes after the value are covered by the v12_trailing_* vectors.

#include <gtest/gtest.h>

#include <string>
#include <vector>

#include "app_mode.h"
#include "parser.h"
#include "parser_impl.h"

namespace {

const char *DEVICE = "de12b5e16b93fe81ca4d70656bee4334f2e40f9f28b9796e792d28f2cead74ad";

const std::string TRANSFER =
    "{\"networkId\":\"mainnet01\",\"payload\":{\"exec\":{\"data\":{},\"code\":\"(coin.transfer "
    "\\\"k:de12b5e16b93fe81ca4d70656bee4334f2e40f9f28b9796e792d28f2cead74ad\\\" "
    "\\\"k:9790d119589a26114e1a42d92598b3f632551c566819ec48e0e8c54dae6ebb42\\\" 1.0)\"}},\"signers\":[{\"pubKey\":"
    "\"de12b5e16b93fe81ca4d70656bee4334f2e40f9f28b9796e792d28f2cead74ad\",\"clist\":[{\"name\":\"coin.GAS\","
    "\"args\":[]},{\"name\":\"coin.TRANSFER\",\"args\":[\"k:"
    "de12b5e16b93fe81ca4d70656bee4334f2e40f9f28b9796e792d28f2cead74ad\","
    "\"k:9790d119589a26114e1a42d92598b3f632551c566819ec48e0e8c54dae6ebb42\",1.0]}]}],\"meta\":{\"creationTime\":0,"
    "\"ttl\":28800,\"gasLimit\":600,\"chainId\":\"0\",\"gasPrice\":1.0e-6,\"sender\":"
    "\"k:de12b5e16b93fe81ca4d70656bee4334f2e40f9f28b9796e792d28f2cead74ad\"},\"nonce\":\"n\"}";

// Parses and validates `bytes` (with its exact length) as a JSON transaction.
parser_error_t parseJson(const std::string &bytes) {
    std::vector<uint8_t> buf(bytes.begin(), bytes.end());
    parser_context_t ctx;
    parser_error_t err = parser_parse(&ctx, buf.data(), buf.size(), tx_type_json);
    if (err == parser_ok) {
        err = parser_validate(&ctx);
    }
    return err;
}

class OneJsonValue : public ::testing::Test {
   protected:
    void SetUp() override {
        app_mode_set_expert(false);
        app_mode_set_blindsign(true);
        parser_setTestDeviceKeyHex(DEVICE);
    }
};

}  // namespace

// Control: the transaction alone is reviewed.
TEST_F(OneJsonValue, TheTransactionAloneIsReviewed) { EXPECT_EQ(parseJson(TRANSFER), parser_ok); }

// A NUL after the value, followed by more JSON the device would never parse.
TEST_F(OneJsonValue, NulAfterTheValueIsRefused) {
    const parser_error_t err = parseJson(TRANSFER + std::string(1, '\0') + "{\"a\":1}");
    EXPECT_EQ(err, parser_unexpected_characters);
    EXPECT_STREQ(parser_getErrorDescription(err), "Unexpected characters");
}

// A NUL inside a string value (the nonce).
TEST_F(OneJsonValue, NulInsideAValueIsRefused) {
    std::string tx = TRANSFER;
    const size_t at = tx.find("\"nonce\":\"n\"");
    ASSERT_NE(at, std::string::npos);
    tx.insert(at + 10, 1, '\0');  // "nonce":"n<NUL>"
    const parser_error_t err = parseJson(tx);
    EXPECT_EQ(err, parser_unexpected_characters);
    EXPECT_STREQ(parser_getErrorDescription(err), "Unexpected characters");
}

// A NUL as the last byte.
TEST_F(OneJsonValue, TrailingNulIsRefused) {
    EXPECT_EQ(parseJson(TRANSFER + std::string(1, '\0')), parser_unexpected_characters);
}
