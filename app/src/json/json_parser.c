/*******************************************************************************
 *  (c) 2018 - 2024 Zondax AG
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
#include "json_parser.h"

#include "../common/parser_common.h"
#include "jsmn/jsmn.h"

parser_error_t array_get_element_count(const parsed_json_t *json, uint16_t array_token_index, uint16_t *number_elements) {
    *number_elements = 0;
    if (array_token_index >= json->numberOfTokens) {
        return parser_no_data;
    }

    jsmntok_t array_token = json->tokens[array_token_index];
    uint16_t token_index = array_token_index;
    uint16_t prev_element_end = array_token.start;
    while (true) {
        token_index++;
        if (token_index >= json->numberOfTokens) {
            break;
        }
        jsmntok_t current_token = json->tokens[token_index];
        if (current_token.start > array_token.end) {
            break;
        }
        if (current_token.start <= prev_element_end) {
            continue;
        }
        prev_element_end = current_token.end;
        (*number_elements)++;
    }

    return parser_ok;
}

parser_error_t array_get_nth_element(const parsed_json_t *json, uint16_t array_token_index, uint16_t element_index,
                                     uint16_t *token_index) {
    if (array_token_index >= json->numberOfTokens) {
        return parser_no_data;
    }

    jsmntok_t array_token = json->tokens[array_token_index];
    *token_index = array_token_index;

    uint16_t element_count = 0;
    uint16_t prev_element_end = array_token.start;
    while (*token_index < json->numberOfTokens) {
        (*token_index)++;
        if (*token_index >= json->numberOfTokens) {
            break;
        }
        jsmntok_t current_token = json->tokens[*token_index];
        if (current_token.start > array_token.end) {
            break;
        }
        if (current_token.start <= prev_element_end) {
            continue;
        }
        prev_element_end = current_token.end;
        if (element_count == element_index) {
            return parser_ok;
        }
        element_count++;
    }

    return parser_no_data;
}

parser_error_t object_get_element_count(const parsed_json_t *json, uint16_t object_token_index, uint16_t *element_count) {
    *element_count = 0;
    if (object_token_index >= json->numberOfTokens) {
        return parser_no_data;
    }

    jsmntok_t object_token = json->tokens[object_token_index];
    uint16_t token_index = object_token_index;
    uint16_t prev_element_end = object_token.start;
    token_index++;
    while (true) {
        if (token_index >= json->numberOfTokens) {
            break;
        }
        jsmntok_t key_token = json->tokens[token_index++];
        if (token_index >= json->numberOfTokens) {
            break;
        }
        jsmntok_t value_token = json->tokens[token_index];
        if (key_token.start > object_token.end) {
            break;
        }
        if (key_token.start <= prev_element_end) {
            continue;
        }
        prev_element_end = value_token.end;
        (*element_count)++;
    }

    return parser_ok;
}

parser_error_t object_get_nth_key(const parsed_json_t *json, uint16_t object_token_index, uint16_t object_element_index,
                                  uint16_t *token_index) {
    *token_index = object_token_index;
    if (object_token_index >= json->numberOfTokens) {
        return parser_no_data;
    }

    jsmntok_t object_token = json->tokens[object_token_index];
    uint16_t element_count = 0;
    uint16_t prev_element_end = object_token.start;
    (*token_index)++;
    while (true) {
        if (*token_index >= json->numberOfTokens) {
            break;
        }
        jsmntok_t key_token = json->tokens[(*token_index)++];
        if (*token_index >= json->numberOfTokens) {
            break;
        }
        jsmntok_t value_token = json->tokens[*token_index];
        if (key_token.start > object_token.end) {
            break;
        }
        if (key_token.start <= prev_element_end) {
            continue;
        }
        prev_element_end = value_token.end;
        if (element_count == object_element_index) {
            (*token_index)--;
            return parser_ok;
        }
        element_count++;
    }

    return parser_no_data;
}

parser_error_t object_get_nth_value(const parsed_json_t *json, uint16_t object_token_index, uint16_t object_element_index,
                                    uint16_t *key_index) {
    if (object_token_index >= json->numberOfTokens) {
        return parser_no_data;
    }

    CHECK_ERROR(object_get_nth_key(json, object_token_index, object_element_index, key_index))
    (*key_index)++;

    return parser_ok;
}

parser_error_t object_get_value(const parsed_json_t *json, uint16_t object_token_index, const char *key_name,
                                uint16_t *token_index) {
    if (object_token_index >= json->numberOfTokens) {
        return parser_no_data;
    }

    const jsmntok_t object_token = json->tokens[object_token_index];

    *token_index = object_token_index;
    int prev_element_end = object_token.start;
    (*token_index)++;

    while (*token_index < json->numberOfTokens) {
        const jsmntok_t key_token = json->tokens[*token_index];
        (*token_index)++;
        if (*token_index >= json->numberOfTokens) {
            break;
        }
        const jsmntok_t value_token = json->tokens[*token_index];

        if (key_token.start > object_token.end) {
            break;
        }
        if (key_token.start <= prev_element_end) {
            continue;
        }
        prev_element_end = value_token.end;

        if (((uint16_t)strlen(key_name)) == (key_token.end - key_token.start)) {
            uint16_t i = 0;
            for (; i < (uint16_t)strlen(key_name); i++) {
                if (json->buffer[key_token.start + i] != key_name[i]) {
                    break;
                }
            }
            if (i == strlen(key_name)) {
                return parser_ok;
            }
        }
    }

    return parser_no_data;
}

// F3: the transaction must be JSON as the network decodes it (RFC 8259, as aeson reads it): the
// tokenizer below is lenient (unquoted keys and values, missing commas, raw control bytes in strings
// and any top-level value all pass it), so the bytes are checked against the grammar first. The root
// must be an object, and nesting is bounded by JSON_MAX_DEPTH. Bytes from 0x80 up are left to the
// display, which shows them escaped.
#define JSON_MAX_DEPTH 128
#define JSON_IS_OBJECT(level) ((in_object[(level) / 8] >> ((level) % 8)) & 1U)

typedef enum {
    json_expect_value,
    json_expect_value_or_close,  // just after '['
    json_expect_key,             // after ',' in an object
    json_expect_key_or_close,    // just after '{'
    json_expect_colon,
    json_expect_comma_or_close,  // after a value
} json_expect_t;

static bool json_isDigit(char c) { return c >= '0' && c <= '9'; }

static bool json_isHex(char c) { return json_isDigit(c) || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'); }

// A string whose opening quote is at s[*i]; on success *i is just past the closing quote.
static bool json_scanString(const char *s, uint16_t n, uint16_t *i) {
    uint16_t p = *i + 1;
    while (p < n) {
        const uint8_t c = (uint8_t)s[p];
        if (c == '"') {
            *i = p + 1;
            return true;
        }
        if (c < 0x20) {
            return false;
        }
        if (c == '\\') {
            if (p + 1 >= n) {
                return false;
            }
            switch (s[p + 1]) {
                case '"':
                case '\\':
                case '/':
                case 'b':
                case 'f':
                case 'n':
                case 'r':
                case 't':
                    p += 2;
                    continue;
                case 'u':
                    if (p + 5 >= n || !json_isHex(s[p + 2]) || !json_isHex(s[p + 3]) || !json_isHex(s[p + 4]) ||
                        !json_isHex(s[p + 5])) {
                        return false;
                    }
                    p += 6;
                    continue;
                default:
                    return false;
            }
        }
        p++;
    }
    return false;
}

// -?(0|[1-9][0-9]*)(.[0-9]+)?([eE][+-]?[0-9]+)? starting at s[*i]; *i ends just past it.
static bool json_scanNumber(const char *s, uint16_t n, uint16_t *i) {
    uint16_t p = *i;
    if (p < n && s[p] == '-') {
        p++;
    }
    if (p >= n || !json_isDigit(s[p])) {
        return false;
    }
    if (s[p] == '0') {
        p++;
    } else {
        while (p < n && json_isDigit(s[p])) {
            p++;
        }
    }
    if (p < n && s[p] == '.') {
        p++;
        if (p >= n || !json_isDigit(s[p])) {
            return false;
        }
        while (p < n && json_isDigit(s[p])) {
            p++;
        }
    }
    if (p < n && (s[p] == 'e' || s[p] == 'E')) {
        p++;
        if (p < n && (s[p] == '+' || s[p] == '-')) {
            p++;
        }
        if (p >= n || !json_isDigit(s[p])) {
            return false;
        }
        while (p < n && json_isDigit(s[p])) {
            p++;
        }
    }
    *i = p;
    return true;
}

static bool json_scanLiteral(const char *s, uint16_t n, uint16_t *i, const char *word, uint16_t len) {
    if (*i + len > n || MEMCMP(s + *i, word, len) != 0) {
        return false;
    }
    *i += len;
    return true;
}

parser_error_t json_validate_strict(const char *s, uint16_t n) {
    uint8_t in_object[JSON_MAX_DEPTH / 8] = {0};  // one bit per open level: 1 object, 0 array
    uint16_t depth = 0;
    json_expect_t expect = json_expect_value;
    bool root_seen = false;
    uint16_t i = 0;

    if (s == NULL) {
        return parser_no_data;
    }
    while (i < n) {
        const char c = s[i];
        if (c == ' ' || c == '\t' || c == '\n' || c == '\r') {
            i++;
            continue;
        }
        if (root_seen && depth == 0) {
            // The root object is complete; what follows it is refused by the caller
            // (parser_unexpected_unparsed_bytes, _read_json_tx).
            return parser_ok;
        }
        switch (expect) {
            case json_expect_key_or_close:
            case json_expect_key:
                if (c == '}' && expect == json_expect_key_or_close) {
                    depth--;
                    i++;
                    expect = json_expect_comma_or_close;
                    break;
                }
                if (c != '"' || !json_scanString(s, n, &i)) {
                    return parser_unexpected_characters;
                }
                expect = json_expect_colon;
                break;
            case json_expect_colon:
                if (c != ':') {
                    return parser_unexpected_characters;
                }
                i++;
                expect = json_expect_value;
                break;
            case json_expect_comma_or_close:
                if (c == ',') {
                    i++;
                    expect = JSON_IS_OBJECT(depth - 1) ? json_expect_key : json_expect_value;
                } else if (c == (JSON_IS_OBJECT(depth - 1) ? '}' : ']')) {
                    depth--;
                    i++;
                } else {
                    return parser_unexpected_characters;
                }
                break;
            case json_expect_value_or_close:
                if (c == ']') {
                    depth--;
                    i++;
                    expect = json_expect_comma_or_close;
                } else {
                    expect = json_expect_value;  // the same character is read again as a value
                }
                break;
            case json_expect_value:
                if (!root_seen && c != '{') {
                    return parser_unexpected_characters;  // the root must be an object
                }
                if (c == '{' || c == '[') {
                    if (depth == JSON_MAX_DEPTH) {
                        return parser_unexpected_characters;
                    }
                    if (c == '{') {
                        in_object[depth / 8] |= (uint8_t)(1U << (depth % 8));
                    } else {
                        in_object[depth / 8] &= (uint8_t)~(1U << (depth % 8));
                    }
                    depth++;
                    root_seen = true;
                    i++;
                    expect = c == '{' ? json_expect_key_or_close : json_expect_value_or_close;
                    break;
                }
                if (c == '"') {
                    if (!json_scanString(s, n, &i)) {
                        return parser_unexpected_characters;
                    }
                } else if (c == '-' || json_isDigit(c)) {
                    if (!json_scanNumber(s, n, &i)) {
                        return parser_unexpected_characters;
                    }
                } else if (!json_scanLiteral(s, n, &i, "true", 4) && !json_scanLiteral(s, n, &i, "false", 5) &&
                           !json_scanLiteral(s, n, &i, "null", 4)) {
                    return parser_unexpected_characters;
                }
                expect = json_expect_comma_or_close;
                break;
            default:
                return parser_unexpected_characters;
        }
    }
    // The root object, complete.
    return (root_seen && depth == 0) ? parser_ok : parser_unexpected_characters;
}

parser_error_t json_parse(parsed_json_t *parsed_json, const char *buffer, uint16_t bufferLen) {
    jsmn_parser parser;

    jsmn_init(&parser);

    MEMZERO(parsed_json, sizeof(parsed_json_t));
    parsed_json->buffer = buffer;
    parsed_json->bufferLen = bufferLen;

    int16_t num_tokens =
        jsmn_parse(&parser, parsed_json->buffer, parsed_json->bufferLen, parsed_json->tokens, MAX_NUMBER_OF_TOKENS);

    ZEMU_LOGF(35, "num_tokens: %d\n", num_tokens);

    if (num_tokens < 0) {
        switch (num_tokens) {
            case JSMN_ERROR_NOMEM:
                return parser_json_too_many_tokens;
            case JSMN_ERROR_INVAL:
                return parser_unexpected_characters;
            case JSMN_ERROR_PART:
                return parser_json_incomplete_json;
            default:
                return parser_json_unexpected_error;
        }
    }

    parsed_json->numberOfTokens = 0;
    parsed_json->isValid = 0;

    // Parsing error
    if (num_tokens <= 0) {
        return parser_json_zero_tokens;
    }

    // We cannot support if number of tokens exceeds the limit
    if (num_tokens > MAX_NUMBER_OF_TOKENS) {
        return parser_json_too_many_tokens;
    }

    parsed_json->numberOfTokens = num_tokens;
    parsed_json->isValid = true;

    return parser_ok;
}