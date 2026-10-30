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

// The structured transfer (INS 0x24, legacy 0x10): the device builds the JSON from 12 fields and
// reviews and signs that JSON. The template path is built by the host library (buffering_json.c).
// F6: a render longer than the review's 300-byte value line takes the "args cannot be displayed"
// notice instead of failing the whole transaction. F16: a namespace without a module, or a module
// without a namespace, is refused instead of silently becoming a coin transfer.

#include <gtest/gtest.h>

#include <string>
#include <vector>

#include "app_mode.h"
#include "parser.h"
#include "parser_impl.h"
#include "utils/common.h"

extern "C" {
void tx_json_initialize();
void tx_json_reset();
}

namespace {

const char *DEVICE = "de12b5e16b93fe81ca4d70656bee4334f2e40f9f28b9796e792d28f2cead74ad";
const char *RECIPIENT = "9790d119589a26114e1a42d92598b3f632551c566819ec48e0e8c54dae6ebb42";

struct Fields {
    std::string recipientChain = "1";
    std::string network = "mainnet01";
    std::string amount = "1.0";
    std::string ns;
    std::string module;
    std::string gasPrice = "1.0e-6";
    std::string gasLimit = "600";
    std::string creationTime = "1634009214";
    std::string chainId = "0";
    std::string nonce = "n";
    std::string ttl = "28800";
};

// tx type byte, then 12 length-prefixed fields in the order parser_createJsonTemplate reads them.
std::vector<uint8_t> payload(uint8_t txType, const Fields &f) {
    std::vector<uint8_t> out{txType};
    for (const std::string &v : {std::string(RECIPIENT), f.recipientChain, f.network, f.amount, f.ns, f.module, f.gasPrice,
                                 f.gasLimit, f.creationTime, f.chainId, f.nonce, f.ttl}) {
        out.push_back(static_cast<uint8_t>(v.size()));
        out.insert(out.end(), v.begin(), v.end());
    }
    return out;
}

class StructuredTransfer : public ::testing::Test {
   protected:
    void SetUp() override {
        app_mode_set_expert(false);
        app_mode_set_blindsign(false);
        parser_setTestDeviceKeyHex(DEVICE);
        tx_json_initialize();
    }

    parser_error_t parseAndValidate(const std::vector<uint8_t> &p) {
        buf = p;
        tx_json_reset();  // as the device does when a new signing stream opens
        parser_error_t err = parser_parse(&ctx, buf.data(), buf.size(), tx_type_transfer);
        if (err == parser_ok) {
            err = parser_validate(&ctx);
        }
        return err;
    }

    bool shows(const std::string &text) {
        for (const std::string &line : dumpUI(&ctx, 40, 400)) {
            if (line.find(text) != std::string::npos) {
                return true;
            }
        }
        return false;
    }

    parser_context_t ctx{};
    std::vector<uint8_t> buf;
};

}  // namespace

// F6 (cold review h3 V0): a cross-chain transfer of a token with a 63-character namespace, a
// 32-character module and a 32-character amount. Its capability renders past the 300-byte line, so
// the review shows the "args cannot be displayed" notice and the too-large WARNING, and signing it
// needs the Blind signing setting (it is a token transfer). 1.3.4 refused it ("Unrecognized error
// code") whatever the setting.
TEST_F(StructuredTransfer, OverLongCapabilityTakesTheTooLargeNotice) {
    Fields f;
    f.ns = std::string(63, 'n');
    f.module = std::string(32, 'm');
    f.amount = "1234567890123456789012345678.000";
    ASSERT_EQ(f.amount.size(), 32u);

    EXPECT_EQ(parseAndValidate(payload(TX_TYPE_TRANSFER_CROSSCHAIN, f)), parser_blindsign_mode_required);

    app_mode_set_blindsign(true);
    ASSERT_EQ(parseAndValidate(payload(TX_TYPE_TRANSFER_CROSSCHAIN, f)), parser_ok);
    EXPECT_TRUE(shows("args cannot be displayed on Ledger"));
    EXPECT_TRUE(shows("Transaction too large for Ledger to display"));
}

// The same token at a size that fits is shown in full.
TEST_F(StructuredTransfer, CapabilityThatFitsIsShownInFull) {
    Fields f;
    f.ns = "n_e595727b657fbbb3b8e362a05a7bb8d12865c1ff";
    f.module = "kb-USDC";
    app_mode_set_blindsign(true);
    ASSERT_EQ(parseAndValidate(payload(TX_TYPE_TRANSFER_CROSSCHAIN, f)), parser_ok);
    EXPECT_FALSE(shows("args cannot be displayed on Ledger"));
    EXPECT_TRUE(shows("n_e595727b657fbbb3b8e362a05a7bb8d12865c1ff.kb-USDC.TRANSFER_XCHAIN"));
}

// F16: half a token name is refused, never turned into a coin transfer.
TEST_F(StructuredTransfer, HalfSpecifiedNamespaceAndModuleRefused) {
    app_mode_set_blindsign(true);
    Fields onlyModule;
    onlyModule.module = "kb-USDC";
    EXPECT_EQ(parseAndValidate(payload(TX_TYPE_TRANSFER, onlyModule)), parser_unexpected_value);
    Fields onlyNamespace;
    onlyNamespace.ns = "n_e595727b657fbbb3b8e362a05a7bb8d12865c1ff";
    EXPECT_EQ(parseAndValidate(payload(TX_TYPE_TRANSFER, onlyNamespace)), parser_unexpected_value);

    // Controls: neither is a coin transfer (clear-signed), both is the token.
    app_mode_set_blindsign(false);
    ASSERT_EQ(parseAndValidate(payload(TX_TYPE_TRANSFER, Fields{})), parser_ok);
    EXPECT_TRUE(shows("Normal Transfer"));
    Fields both;
    both.ns = onlyNamespace.ns;
    both.module = "kb-USDC";
    app_mode_set_blindsign(true);
    ASSERT_EQ(parseAndValidate(payload(TX_TYPE_TRANSFER, both)), parser_ok);
    EXPECT_TRUE(shows("n_e595727b657fbbb3b8e362a05a7bb8d12865c1ff.kb-USDC.TRANSFER"));
}
