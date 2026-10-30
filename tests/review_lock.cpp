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
// A1/F5: the address review and the blind-signing notice take the same lock, and the address review
// shows and replies the copy taken when the command arrived (addr_getItem, addr_writeReply).

#include "review_lock.h"

#include <blake2.h>
#include <gtest/gtest.h>

#include <string>
#include <vector>

#include "app_mode.h"
#include "parser.h"
#include "parser_impl.h"
extern "C" {
#include "addr.h"
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

// ---- A1/F5: the address review and the blind-signing notice ------------------------------------

namespace {

const uint32_t PATH_A[5] = {0x8000002C, 0x80000272, 0x80000000, 0, 0};
const uint32_t PATH_B[5] = {0x8000002C, 0x80000272, 0x80000007, 0, 3};

std::vector<uint8_t> keyBytes(uint8_t first) {
    std::vector<uint8_t> k(32);
    for (size_t i = 0; i < k.size(); i++) {
        k[i] = (uint8_t)(first + i);
    }
    return k;
}

std::string hex(const std::vector<uint8_t> &b) {
    static const char *digits = "0123456789abcdef";
    std::string s;
    for (uint8_t v : b) {
        s += digits[v >> 4];
        s += digits[v & 0x0F];
    }
    return s;
}

struct Shown {
    zxerr_t err;
    std::string key;
    std::string value;
};

Shown addrItem(int8_t idx) {
    char key[40] = {0};
    char value[200] = {0};
    uint8_t pages = 0;
    const zxerr_t err = addr_getItem(idx, key, sizeof(key), value, sizeof(value), 0, &pages);
    return Shown{err, key, value};
}

}  // namespace

// An address review locks the app exactly as a signing review does: only GET_VERSION is answered, and
// there is no digest to sign. Fails if handleGetAddr's review is not a lock kind review_lock_allows sees.
TEST_F(ReviewLock, AddressReviewLocksEveryCommandButGetVersion) {
    std::vector<uint8_t> key = keyBytes(0x10);
    ASSERT_TRUE(review_lock_begin_address(key.data(), key.size(), PATH_A, 5));
    EXPECT_TRUE(review_lock_pending());
    EXPECT_EQ(review_lock_kind(), REVIEW_LOCK_ADDRESS);
    for (int ins = 0; ins < 256; ins++) {
        EXPECT_EQ(review_lock_allows((uint8_t)ins), ins == REVIEW_LOCK_INS_GET_VERSION) << "INS 0x" << std::hex << ins;
    }
    uint8_t digest[32];
    EXPECT_FALSE(review_lock_digest(digest, sizeof(digest)));

    review_lock_end();
    EXPECT_FALSE(review_lock_pending());
    for (int ins = 0; ins < 256; ins++) {
        EXPECT_TRUE(review_lock_allows((uint8_t)ins)) << "INS 0x" << std::hex << ins;
    }
}

// The address screen and its reply come from the copy taken when the command arrived: overwriting the
// buffer the key came from, and the path, after the review is shown changes neither. Fails if
// addr_getItem or the reply read the APDU buffer or the global path at draw or approval time.
TEST_F(ReviewLock, AddressReviewShowsAndRepliesTheKeyTakenOnArrival) {
    app_mode_set_expert(true);
    std::vector<uint8_t> buffer = keyBytes(0x10);
    const std::vector<uint8_t> shown = buffer;
    uint32_t path[5];
    memcpy(path, PATH_A, sizeof(path));
    ASSERT_TRUE(review_lock_begin_address(buffer.data(), buffer.size(), path, 5));

    // Another command's bytes land where the key was, and another path is set.
    const std::vector<uint8_t> other = keyBytes(0xA0);
    buffer = other;
    memcpy(path, PATH_B, sizeof(path));

    const Shown address = addrItem(0);
    ASSERT_EQ(address.err, zxerr_ok);
    EXPECT_EQ(address.key, "Address");
    EXPECT_EQ(address.value, hex(shown));

    const Shown yourPath = addrItem(1);
    ASSERT_EQ(yourPath.err, zxerr_ok);
    EXPECT_EQ(yourPath.key, "Your Path");
    EXPECT_EQ(yourPath.value, "44'/626'/0'/0/0");

    std::vector<uint8_t> reply(64, 0xEE);
    ASSERT_EQ(addr_writeReply(reply.data(), reply.size()), 32);
    EXPECT_EQ(std::vector<uint8_t>(reply.begin(), reply.begin() + 32), shown);

    // Once answered, nothing is shown or replied from the copy.
    review_lock_end();
    EXPECT_EQ(addrItem(0).err, zxerr_no_data);
    EXPECT_EQ(addr_writeReply(reply.data(), reply.size()), 0);
}

// The blind-signing notice locks the app too and replies the text copied when it was shown.
TEST_F(ReviewLock, NoticeLocksAndRepliesTheTextTakenWhenShown) {
    char text[] = "Blind signing mode required";
    ASSERT_TRUE(review_lock_begin_notice(text, strlen(text)));
    EXPECT_EQ(review_lock_kind(), REVIEW_LOCK_NOTICE);
    for (int ins = 0; ins < 256; ins++) {
        EXPECT_EQ(review_lock_allows((uint8_t)ins), ins == REVIEW_LOCK_INS_GET_VERSION) << "INS 0x" << std::hex << ins;
    }
    memset(text, 'x', strlen(text));

    uint8_t reply[64] = {0};
    ASSERT_EQ(review_lock_notice(reply, sizeof(reply)), strlen("Blind signing mode required"));
    EXPECT_EQ(std::string((const char *)reply), "Blind signing mode required");
    EXPECT_EQ(addr_writeReply(reply, sizeof(reply)), 0);

    review_lock_end();
    EXPECT_EQ(review_lock_notice(reply, sizeof(reply)), 0);
}

// One thing waits for the user at a time, and a copy of the wrong size is refused.
TEST_F(ReviewLock, OneReviewAtATimeAndExactCopySizes) {
    std::vector<uint8_t> key = keyBytes(0x10);
    EXPECT_FALSE(review_lock_begin_address(key.data(), 31, PATH_A, 5));
    EXPECT_FALSE(review_lock_begin_address(key.data(), 32, PATH_A, 4));
    EXPECT_FALSE(review_lock_begin_address(nullptr, 32, PATH_A, 5));
    const std::string longText(REVIEW_LOCK_NOTICE_MAX + 1, 'a');
    EXPECT_FALSE(review_lock_begin_notice(longText.c_str(), longText.size()));
    EXPECT_FALSE(review_lock_pending());

    ASSERT_TRUE(review_lock_begin_address(key.data(), key.size(), PATH_A, 5));
    EXPECT_FALSE(review_lock_begin_notice("x", 1));
    const std::string a = transferJson("1.0");
    std::vector<uint8_t> buf(a.begin(), a.end());
    parseJson(buf.data(), buf.size());
    EXPECT_FALSE(review_lock_begin());
    EXPECT_EQ(review_lock_kind(), REVIEW_LOCK_ADDRESS);
}
