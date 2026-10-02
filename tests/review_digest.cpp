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

// S12 layer 2: approval signs the digest computed while parsing the transaction that the review
// shows, bound to that review. A later parse, or a change to the bytes in the buffer, must not
// change it. (The structured-transfer path cannot run here: its template buffer lives in
// common/tx.c, which the unit-test library does not build. The emulator tests cover it.)

#include <blake2.h>
#include <gtest/gtest.h>

#include <cstring>
#include <string>
#include <vector>

#include "app_mode.h"
extern "C" {
#include "items.h"
}
#include "parser.h"
#include "parser_impl.h"

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

std::vector<uint8_t> reviewDigest() {
    std::vector<uint8_t> out(32);
    EXPECT_EQ(items_getReviewDigest(out.data(), out.size()), items_ok);
    return out;
}

// Parses and validates a JSON transaction held in `buf`, as the device does before a review.
void parseJson(uint8_t *buf, size_t len) {
    parser_context_t ctx;
    ASSERT_EQ(parser_parse(&ctx, buf, len, tx_type_json), parser_ok);
    ASSERT_EQ(parser_validate(&ctx), parser_ok);
}

class ReviewDigest : public ::testing::Test {
   protected:
    void SetUp() override {
        app_mode_set_expert(false);
        app_mode_set_blindsign(false);
        parser_setTestDeviceKeyHex(DEVICE);
        items_clearReviewDigest();
    }
};

}  // namespace

// The digest bound to the review is the blake2b-256 of the bytes that were parsed and reviewed, and
// it does not change when the buffer is overwritten and another transaction is parsed afterwards.
TEST_F(ReviewDigest, SignedDigestIsTheOneRecordedAtParseTime) {
    const std::string a = transferJson("1.0");
    const std::string b = transferJson("1000.0");
    std::vector<uint8_t> buf(a.begin(), a.end());
    const std::vector<uint8_t> digestA = blake(buf.data(), buf.size());

    parseJson(buf.data(), buf.size());
    ASSERT_EQ(items_bindReviewDigest(), items_ok);  // the review of A is shown
    EXPECT_EQ(reviewDigest(), digestA);

    // The same buffer now holds B (a stream replaced behind the review), and B is parsed.
    buf.assign(b.begin(), b.end());
    const std::vector<uint8_t> digestB = blake(buf.data(), buf.size());
    parseJson(buf.data(), buf.size());
    ASSERT_NE(digestA, digestB);

    // Approval of A still signs A's digest.
    EXPECT_EQ(reviewDigest(), digestA);
}

// A hash to sign (INS 0x23 / legacy 0x04) is bound as its own 32 bytes.
TEST_F(ReviewDigest, HashSigningBindsTheHashBytes) {
    app_mode_set_blindsign(true);
    std::vector<uint8_t> h(32);
    for (size_t i = 0; i < h.size(); i++) {
        h[i] = (uint8_t)(0xA0 + i);
    }
    parser_context_t ctx;
    ASSERT_EQ(parser_parse(&ctx, h.data(), h.size(), tx_type_hash), parser_ok);
    ASSERT_EQ(parser_validate(&ctx), parser_ok);
    ASSERT_EQ(items_bindReviewDigest(), items_ok);
    const std::vector<uint8_t> bound = reviewDigest();
    h.assign(32, 0x00);  // the buffer changes after the review was built
    EXPECT_EQ(bound, std::vector<uint8_t>({0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA,
                                           0xAB, 0xAC, 0xAD, 0xAE, 0xAF, 0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5,
                                           0xB6, 0xB7, 0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF}));
    EXPECT_EQ(reviewDigest(), bound);
}

// Nothing is bound before a review is shown or after it ends, so approval cannot sign anything then.
TEST_F(ReviewDigest, NoDigestOutsideAReview) {
    std::vector<uint8_t> out(32);
    EXPECT_NE(items_getReviewDigest(out.data(), out.size()), items_ok);

    const std::string a = transferJson("1.0");
    std::vector<uint8_t> buf(a.begin(), a.end());
    parseJson(buf.data(), buf.size());
    EXPECT_NE(items_getReviewDigest(out.data(), out.size()), items_ok);  // parsed, not yet shown

    ASSERT_EQ(items_bindReviewDigest(), items_ok);
    items_clearReviewDigest();  // approved or rejected
    EXPECT_NE(items_getReviewDigest(out.data(), out.size()), items_ok);
}
