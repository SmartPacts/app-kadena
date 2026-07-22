#include <cassert>
#include <cstdint>
#include <cstdio>

#include "parser.h"
#include "zxformat.h"

#ifdef NDEBUG
#error "This fuzz target won't work correctly with NDEBUG defined, which will cause asserts to be eliminated"
#endif

using std::size_t;

namespace {
char PARSER_KEY[16384];
char PARSER_VALUE[16384];
}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    parser_context_t ctx;
    parser_error_t rc;

    rc = parser_parse(&ctx, data, size, tx_type_json);
    if (rc != parser_ok) {
        return 0;
    }

    rc = parser_validate(&ctx);
    if (rc != parser_ok) {
        return 0;
    }

    uint8_t num_items;
    rc = parser_getNumItems(&ctx, &num_items);
    if (rc != parser_ok) {
        assert(false);
    }

    for (uint8_t i = 0; i < num_items; i += 1) {
        uint8_t page_idx = 0;
        uint8_t page_count = 1;
        while (page_idx < page_count) {
            rc = parser_getItem(&ctx, i, PARSER_KEY, sizeof(PARSER_KEY), PARSER_VALUE, sizeof(PARSER_VALUE), page_idx,
                                &page_count);

            if (rc != parser_ok) {
                (void)fprintf(stderr, "error getting item %u at page index %u: %s\n", (unsigned)i, (unsigned)page_idx,
                              parser_getErrorDescription(rc));
                assert(false);
            }

            page_idx += 1;
        }
    }

    return 0;
}
