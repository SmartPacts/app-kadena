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

// S12: the review lock and the digest that approval signs, through the same functions the app's
// dispatcher (review_lock_allows) and approval handlers (review_lock_digest) call.

#include "review_lock.h"

#include <blake2.h>
#include <gtest/gtest.h>

#include <string>
#include <vector>

#include "app_mode.h"
#include "parser.h"
#include "parser_impl.h"
extern "C" {
#include "items.h"
}

namespace {

const char *DEVICE = "de12b5e16b93fe81ca4d70656bee4334f2e40f9f28b9796e792d28f2cead74ad";

std::string transferJson(const char *amount) {
    return std::string(
               "{\"networkId\":\"mainnet01\",\"payload\":{\"exec\":{\"data\":{},\"code\":\"(coin.transfer "
               "\\\"k:de12b5e16b93fe81ca4d70656bee4334f2e40f9f28b9796e792d28f2cead74ad\\\" "
               "\\\"k:9790d119589a26114e1a42d92598b3f632551c566819ec48e0e8c54dae6ebb42\\\" ") +
           amount +
           ")\"}},\"signers\":[{\"pubKey\":\"de12b5e16b93fe81ca4d70656bee4334f2e40f9f28b9796e792d28f2cead74ad\","
           "\"clist\":[{\"name\":\"coin.GAS\",\"args\":[]},{\"name\":\"coin.TRANSFER\",\"args\":["
           "\"k:de12b5e16b93fe81ca4d70656bee4334f2e40f9f28b9796e792d28f2cead74ad\","
           "\"k:9790d119589a26114e1a42d92598b3f632551c566819ec48e0e8c54dae6ebb42\"," +
           amount +
           "]}]}],\"meta\":{\"creationTime\":0,\"ttl\":28800,\"gasLimit\":600,\"chainId\":\"0\",\"gasPrice\":1.0e-6,"
           "\"sender\":\"k:de12b5e16b93fe81ca4d70656bee4334f2e40f9f28b9796e792d28f2cead74ad\"},\"nonce\":\"s12\"}";
}

std::vector<uint8_t> blake(const uint8_t *data, size_t len) {
    std::vector<uint8_t> out(32);
    EXPECT_EQ(blake2b(out.data(), out.size(), data, len, nullptr, 0), 0);
    return out;
}

// Parses and validates a JSON transaction held in `buf`, as the device does before a review.
void parseJson(uint8_t *buf, size_t len) {
    parser_context_t ctx;
    ASSERT_EQ(parser_parse(&ctx, buf, len, tx_type_json), parser_ok);
    ASSERT_EQ(parser_validate(&ctx), parser_ok);
}

const uint8_t SIGNING_INS[] = {0x22, 0x23, 0x24, 0x03, 0x04, 0x10};

class ReviewLock : public ::testing::Test {
   protected:
    void SetUp() override {
        app_mode_set_expert(false);
        app_mode_set_blindsign(false);
        parser_setTestDeviceKeyHex(DEVICE);
        review_lock_end();
    }
    void TearDown() override { review_lock_end(); }

    // Parses a transaction and shows its review, as the signing handlers do.
    void beginReview(std::vector<uint8_t> &buf) {
        parseJson(buf.data(), buf.size());
        ASSERT_TRUE(review_lock_begin());
    }
};

}  // namespace

// While a review is pending, every signing command is refused, and every other INS but GET_VERSION.
TEST_F(ReviewLock, SigningCommandsRefusedWhileAReviewIsPending) {
    const std::string a = transferJson("1.0");
    std::vector<uint8_t> buf(a.begin(), a.end());
    beginReview(buf);
    EXPECT_TRUE(review_lock_pending());
    for (uint8_t ins : SIGNING_INS) {
        EXPECT_FALSE(review_lock_allows(ins)) << "INS 0x" << std::hex << (int)ins;
    }
    for (int ins = 0; ins < 256; ins++) {
        EXPECT_EQ(review_lock_allows((uint8_t)ins), ins == REVIEW_LOCK_INS_GET_VERSION) << "INS 0x" << std::hex << ins;
    }
}

// With no review pending (and after one ends), every INS reaches its handler.
TEST_F(ReviewLock, EverythingAllowedWithoutAPendingReview) {
    const std::string a = transferJson("1.0");
    std::vector<uint8_t> buf(a.begin(), a.end());
    beginReview(buf);
    review_lock_end();
    EXPECT_FALSE(review_lock_pending());
    for (int ins = 0; ins < 256; ins++) {
        EXPECT_TRUE(review_lock_allows((uint8_t)ins)) << "INS 0x" << std::hex << ins;
    }
}

// The digest approval signs (review_lock_digest) is the reviewed transaction's, even after the buffer
// holds another transaction and that one has been parsed. Fails if approval re-hashes the buffer.
TEST_F(ReviewLock, ApprovalSignsTheReviewedDigestNotTheBuffer) {
    const std::string a = transferJson("1.0");
    const std::string b = transferJson("1000.0");
    std::vector<uint8_t> buf(a.begin(), a.end());
    const std::vector<uint8_t> digestA = blake(buf.data(), buf.size());
    beginReview(buf);

    buf.assign(b.begin(), b.end());
    parseJson(buf.data(), buf.size());

    std::vector<uint8_t> signed_digest(32);
    ASSERT_TRUE(review_lock_digest(signed_digest.data(), signed_digest.size()));
    EXPECT_EQ(signed_digest, digestA);

    review_lock_end();
    EXPECT_FALSE(review_lock_digest(signed_digest.data(), signed_digest.size()));
}
