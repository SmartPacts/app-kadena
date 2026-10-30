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

// F2: the "Max fee" product, gasLimit x gasPrice in exact decimal. The table is the Rust app's
// (kadena-core fee.rs tests), so both apps show the same fee for the same transaction.

#include <gtest/gtest.h>

#include <string>

extern "C" {
#include "items_format.h"
}

namespace {

std::string fee(const std::string &limit, const std::string &price, uint16_t outLen = 300) {
    char out[300] = {0};
    const uint16_t n = items_maxFee(limit.data(), limit.size(), price.data(), price.size(), out, outLen);
    if (n == 0) {
        return "<refused>";
    }
    EXPECT_EQ(n, strlen(out));
    return std::string(out, n);
}

}  // namespace

TEST(MaxFee, ExactProducts) {
    EXPECT_EQ(fee("600", "1.0e-6"), "0.0006");
    EXPECT_EQ(fee("600", "1.0e-5"), "0.006");
    EXPECT_EQ(fee("2300", "0.00000001"), "0.000023");
    EXPECT_EQ(fee("150000", "1e+2"), "15000000");
    EXPECT_EQ(fee("150000", "1E2"), "15000000");
    EXPECT_EQ(fee("1500", "2.5"), "3750");
    EXPECT_EQ(fee("3", "0.1"), "0.3");
    EXPECT_EQ(fee("7", "1.011111111111111e-6"), "0.000007077777777777777");
    EXPECT_EQ(fee("10", "0.5"), "5");
    EXPECT_EQ(fee("0", "1.0e-6"), "0");
    EXPECT_EQ(fee("0123", "1"), "123");
    EXPECT_EQ(fee("1.5", "1.5"), "2.25");
    EXPECT_EQ(fee("25", "4e-2"), "1");
    // Beyond double precision: exact.
    EXPECT_EQ(fee("99999999999999999999", "0.000000000000000000011"), "1.099999999999999999989");
}

TEST(MaxFee, Refusals) {
    const char *cases[][2] = {{"", "1"},   {"1", ""},   {"-1", "1"},  {"1", "-1.0"}, {".5", "1"},    {"1.", "1"},
                              {"1", "e5"}, {"1", "1e"}, {"1", "1e+"}, {"1", "1x"},   {"1", "1e401"}, {"abc", "1"}};
    for (const auto &c : cases) {
        EXPECT_EQ(fee(c[0], c[1]), "<refused>") << c[0] << " x " << c[1];
    }
    // More significant digits than the product holds (40 per value).
    EXPECT_EQ(fee(std::string(41, '1'), "1"), "<refused>");
    EXPECT_EQ(fee(std::string(40, '1'), "1"), std::string(40, '1'));
    // Too long for the line.
    EXPECT_EQ(fee("1", "1e-300"), "<refused>");
    EXPECT_EQ(fee("1", "1e+300"), "<refused>");
    // The output bound counts the NUL.
    EXPECT_EQ(fee("600", "1.0e-6", 7), "0.0006");
    EXPECT_EQ(fee("600", "1.0e-6", 6), "<refused>");
}
