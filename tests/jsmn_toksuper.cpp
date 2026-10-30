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

// F4: the tokenizer's "no enclosing token" sentinel. toksuper starts at -1; a check against 0xFFFF
// never matched it, so a ',' at the top level read tokens[-1]. The token array is placed at the start
// of a page whose preceding page is unreadable: a read of tokens[-1] faults, and the child process
// that ran the parse dies of SIGSEGV instead of exiting 0.

#include <gtest/gtest.h>
#include <sys/mman.h>
#include <unistd.h>

#include <cstdlib>
#include <cstring>

#include "jsmn.h"

namespace {

// Parses `text` with the token array right after an unreadable page, then exits 0.
void parseAfterGuardPage(const char *text) {
    const long page = sysconf(_SC_PAGESIZE);
    auto *mem = static_cast<uint8_t *>(mmap(nullptr, 2 * page, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0));
    if (mem == MAP_FAILED || mprotect(mem, page, PROT_NONE) != 0) {
        std::exit(2);
    }
    auto *tokens = reinterpret_cast<jsmntok_t *>(mem + page);
    const unsigned int count = page / sizeof(jsmntok_t);
    jsmn_parser parser;
    jsmn_init(&parser);
    jsmn_parse(&parser, text, strlen(text), tokens, count);
    std::exit(0);
}

}  // namespace

TEST(JsmnToksuper, TopLevelCommaNeverReadsBeforeTheTokenArray) {
    EXPECT_EXIT(parseAfterGuardPage(R"({"a":1},{"b":2})"), ::testing::ExitedWithCode(0), "");
    EXPECT_EXIT(parseAfterGuardPage(R"("a",1)"), ::testing::ExitedWithCode(0), "");
    EXPECT_EXIT(parseAfterGuardPage(R"(1,2)"), ::testing::ExitedWithCode(0), "");
}
