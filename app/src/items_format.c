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

#include "items_format.h"

#include <zxformat.h>

#include "coin.h"
#include "common/parser.h"
#include "crypto.h"
#include "parser_impl.h"

extern char base64_hash[45];

items_error_t items_stdToDisplayString(item_t item, char *outVal, uint16_t outValLen) {
    const parsed_json_t *json_all = &(parser_getParserJsonObj()->json);
    const jsmntok_t *token = &(json_all->tokens[item.json_token_index]);
    const uint16_t len = token->end - token->start;

    if (len == 0) {
        return items_length_zero;
    }

    if (len >= outValLen) {
        return items_data_too_large;
    }

    snprintf(outVal, outValLen, "%.*s", len, json_all->buffer + token->start);

    return items_ok;
}

items_error_t items_nothingToDisplayString(__Z_UNUSED item_t item, char *outVal, uint16_t outValLen) {
    char nothing[] = " ";
    uint16_t len = 2;

    if (len > outValLen) {
        return items_data_too_large;
    }

    snprintf(outVal, len, "%s", nothing);
    return items_ok;
}

items_error_t items_warningToDisplayString(__Z_UNUSED item_t item, char *outVal, uint16_t outValLen) {
    uint16_t len = sizeof(WARNING_TEXT);

    if (len > outValLen) {
        return items_data_too_large;
    }

    snprintf(outVal, len, WARNING_TEXT);
    return items_ok;
}

items_error_t items_hashWarningToDisplayString(__Z_UNUSED item_t item, char *outVal, uint16_t outValLen) {
    uint16_t len = sizeof(HASH_WARNING_TEXT);

    if (len > outValLen) {
        return items_data_too_large;
    }

    snprintf(outVal, len, HASH_WARNING_TEXT);
    return items_ok;
}

items_error_t items_cautionToDisplayString(__Z_UNUSED item_t item, char *outVal, uint16_t outValLen) {
    uint16_t len = sizeof(CAUTION_TEXT);

    if (len > outValLen) {
        return items_data_too_large;
    }

    snprintf(outVal, len, CAUTION_TEXT);
    return items_ok;
}

items_error_t items_txTooLargeToDisplayString(__Z_UNUSED item_t item, char *outVal, uint16_t outValLen) {
    uint16_t len = sizeof(TX_TOO_LARGE_TEXT);

    if (len > outValLen) {
        return items_data_too_large;
    }

    snprintf(outVal, len, TX_TOO_LARGE_TEXT);
    return items_ok;
}

items_error_t items_rotateWarningToDisplayString(__Z_UNUSED item_t item, char *outVal, uint16_t outValLen) {
    uint16_t len = sizeof(ROTATE_WARNING_TEXT);

    if (len > outValLen) {
        return items_data_too_large;
    }

    snprintf(outVal, len, ROTATE_WARNING_TEXT);
    return items_ok;
}

// "Capability not verified: <name>" for a capability the device does not fully render (S10).
// item.json_token_index is the capability name's value token (resolved at store time), and the name
// has no JSON escape (refused in the device's entry by S8). Bounded against the caller's buffer.
items_error_t items_capNotVerifiedToDisplayString(item_t item, char *outVal, uint16_t outValLen) {
    const parsed_json_t *json_all = &(parser_getParserJsonObj()->json);
    const jsmntok_t *token = &(json_all->tokens[item.json_token_index]);
    const uint16_t name_len = token->end - token->start;

    if (name_len == 0) {
        return items_length_zero;
    }
    // prefix + name + NUL must fit.
    if (sizeof(CAP_NOT_VERIFIED_PREFIX) + name_len > outValLen) {
        return items_data_too_large;
    }

    snprintf(outVal, outValLen, "%s%.*s", CAP_NOT_VERIFIED_PREFIX, name_len, json_all->buffer + token->start);
    return items_ok;
}

items_error_t items_signingToDisplayString(__Z_UNUSED item_t item, char *outVal, uint16_t outValLen) {
    uint16_t len = sizeof("Transaction");

    if (len > outValLen) {
        return items_data_too_large;
    }

    snprintf(outVal, len, "Transaction");
    return items_ok;
}

items_error_t items_requiringToDisplayString(__Z_UNUSED item_t item, char *outVal, uint16_t outValLen) {
    uint16_t len = sizeof("Capabilities");

    if (len > outValLen) {
        return items_data_too_large;
    }

    snprintf(outVal, len, "Capabilities");
    return items_ok;
}

items_error_t items_amountToDisplayString(item_t item, char *outVal, uint16_t outValLen) {
    const parsed_json_t *json_all = &(parser_getParserJsonObj()->json);
    const jsmntok_t *token = &(json_all->tokens[item.json_token_index]);
    const uint16_t len = token->end - token->start;

    if (len == 0) {
        return items_length_zero;
    }

    // Bound against the DECORATED length so the amount is never truncated in
    // display while the full blob is signed.
    if (len + sizeof("KDA ") > outValLen) {
        return items_data_too_large;
    }

    snprintf(outVal, outValLen, "KDA %.*s", len, json_all->buffer + token->start);

    return items_ok;
}

items_error_t items_transferToDisplayString(__Z_UNUSED item_t item, char *outVal, uint16_t outValLen) {
    uint16_t len = sizeof("Normal Transfer");

    if (len > outValLen) {
        return items_data_too_large;
    }

    snprintf(outVal, len, "Normal Transfer");
    return items_ok;
}

items_error_t items_crossTransferToDisplayString(__Z_UNUSED item_t item, char *outVal, uint16_t outValLen) {
    uint16_t len = sizeof("Cross-chain Transfer");

    if (len > outValLen) {
        return items_data_too_large;
    }

    snprintf(outVal, len, "Cross-chain Transfer");
    return items_ok;
}

items_error_t items_rotateToDisplayString(item_t item, char *outVal, uint16_t outValLen) {
    uint16_t token_index = 0;
    uint16_t item_token_index = item.json_token_index;
    parsed_json_t *json_all = &(parser_getParserJsonObj()->json);
    jsmntok_t *token = NULL;

    PARSER_TO_ITEMS_ERROR(object_get_value(json_all, item_token_index, "args", &token_index));
    PARSER_TO_ITEMS_ERROR(array_get_nth_element(json_all, token_index, 0, &token_index));
    token = &(json_all->tokens[token_index]);

    const uint16_t arg_len = token->end - token->start;
    // Bound against the caller's buffer, never the (attacker-controlled) arg length.
    if (arg_len + sizeof("\"\"") > outValLen) {
        return items_data_too_large;
    }
    snprintf(outVal, outValLen, "\"%.*s\"", arg_len, json_all->buffer + token->start);

    return items_ok;
}

items_error_t items_gasToDisplayString(__Z_UNUSED item_t item, char *outVal, uint16_t outValLen) {
    const char *gasLimit = NULL;
    const char *gasPrice = NULL;
    // uint16_t, not uint8_t: a gas value span > 255 chars would wrap a uint8_t modulo
    // 256, pass the fit check, and display only (span mod 256) chars while the full
    // value is signed (displayed != signed). uint16_t lets required_len reject it.
    uint16_t gasLimit_len = 0;
    uint16_t gasPrice_len = 0;
    parsed_json_t *json_all = &(parser_getParserJsonObj()->json);
    uint16_t item_token_index = item.json_token_index;
    uint16_t meta_token_index = item.json_token_index;
    jsmntok_t *token = NULL;

    PARSER_TO_ITEMS_ERROR(object_get_value(json_all, item_token_index, JSON_GAS_LIMIT, &item_token_index));
    token = &(json_all->tokens[item_token_index]);
    gasLimit = json_all->buffer + token->start;
    gasLimit_len = token->end - token->start;

    item_token_index = meta_token_index;

    PARSER_TO_ITEMS_ERROR(object_get_value(json_all, item_token_index, JSON_GAS_PRICE, &item_token_index));
    token = &(json_all->tokens[item_token_index]);
    gasPrice = json_all->buffer + token->start;
    gasPrice_len = token->end - token->start;

    // +1 for the NUL: at required_len == outValLen the amount would truncate.
    uint16_t required_len = gasLimit_len + gasPrice_len + strlen("at most ") + strlen(" at price ");
    if (required_len + 1 > outValLen) {
        return items_data_too_large;
    }

    snprintf(outVal, outValLen, "at most %.*s at price %.*s", gasLimit_len, gasLimit, gasPrice_len, gasPrice);

    return items_ok;
}

// F2: the maximum fee, gasLimit x gasPrice, computed exactly in decimal (no floating point), as the
// Rust app does (kadena-core fee.rs). Each value is a JSON number as the transaction carries it:
// digits, an optional fraction, an optional exponent (hosts send gas prices such as 1.0e-6). At most
// FEE_MAX_DIGITS significant digits per value and an exponent of at most FEE_MAX_EXP in magnitude;
// anything else is not a fee the review can show, and the transaction is refused.
#define FEE_MAX_DIGITS 40
#define FEE_MAX_EXP 400

typedef struct {
    uint8_t digits[FEE_MAX_DIGITS];
    uint8_t len;
    int16_t scale;  // the value is digits x 10^(-scale)
} fee_decimal_t;

static bool fee_isDigit(char c) { return c >= '0' && c <= '9'; }

static bool fee_parse(const char *s, uint16_t n, fee_decimal_t *d) {
    uint16_t i = 0;
    d->len = 0;
    d->scale = 0;
    while (i < n && fee_isDigit(s[i])) {
        if (d->len == FEE_MAX_DIGITS) {
            return false;
        }
        d->digits[d->len++] = (uint8_t)(s[i++] - '0');
    }
    if (d->len == 0) {
        return false;
    }
    if (i < n && s[i] == '.') {
        i++;
        const uint16_t f = i;
        while (i < n && fee_isDigit(s[i])) {
            if (d->len == FEE_MAX_DIGITS) {
                return false;
            }
            d->digits[d->len++] = (uint8_t)(s[i++] - '0');
        }
        if (i == f) {
            return false;
        }
        d->scale = (int16_t)(i - f);
    }
    if (i < n && (s[i] == 'e' || s[i] == 'E')) {
        i++;
        bool neg = false;
        if (i < n && (s[i] == '-' || s[i] == '+')) {
            neg = s[i] == '-';
            i++;
        }
        const uint16_t e0 = i;
        int16_t e = 0;
        while (i < n && fee_isDigit(s[i])) {
            e = (int16_t)((e * 10) + (s[i++] - '0'));
            if (e > FEE_MAX_EXP) {
                return false;
            }
        }
        if (i == e0) {
            return false;
        }
        d->scale = (int16_t)(neg ? d->scale + e : d->scale - e);
    }
    return i == n;
}

bool items_isFeeOperand(const char *s, uint16_t n) {
    fee_decimal_t d;
    return fee_parse(s, n, &d);
}

// Writes limit x price in plain decimal (no exponent, no trailing fraction zeros) and a NUL to out.
// Returns the length written, 0 when either value is not a number or the result does not fit.
uint16_t items_maxFee(const char *limit, uint16_t limitLen, const char *price, uint16_t priceLen, char *out,
                      uint16_t outLen) {
    fee_decimal_t a;
    fee_decimal_t b;
    if (out == NULL || outLen == 0 || !fee_parse(limit, limitLen, &a) || !fee_parse(price, priceLen, &b)) {
        return 0;
    }
    // Schoolbook product, most significant digit first; each position holds at most
    // FEE_MAX_DIGITS * 81 before the carries.
    uint16_t acc[2 * FEE_MAX_DIGITS] = {0};
    const uint16_t n = (uint16_t)(a.len + b.len);
    for (uint16_t i = 0; i < a.len; i++) {
        for (uint16_t j = 0; j < b.len; j++) {
            acc[i + j + 1] = (uint16_t)(acc[i + j + 1] + (a.digits[i] * b.digits[j]));
        }
    }
    for (uint16_t k = n - 1; k >= 1; k--) {
        acc[k - 1] = (uint16_t)(acc[k - 1] + (acc[k] / 10));
        acc[k] %= 10;
    }
    const int16_t scale = (int16_t)(a.scale + b.scale);
    uint16_t lead = 0;
    while (lead < n && acc[lead] == 0) {
        lead++;
    }
    const uint16_t *p = acc + lead;
    const uint16_t plen = n - lead;
    uint16_t w = 0;
#define FEE_PUT(c)             \
    do {                       \
        if (w + 1 >= outLen) { \
            return 0;          \
        }                      \
        out[w++] = (char)(c);  \
    } while (0)
    if (plen == 0) {
        FEE_PUT('0');
    } else if (scale <= 0) {
        for (uint16_t i = 0; i < plen; i++) {
            FEE_PUT('0' + p[i]);
        }
        for (int16_t z = 0; z < -scale; z++) {
            FEE_PUT('0');
        }
    } else {
        const int16_t int_len = (int16_t)(plen - scale);
        uint16_t frac_end = plen;
        while (frac_end > 0 && p[frac_end - 1] == 0) {
            frac_end--;
        }
        if (int_len > 0) {
            for (int16_t i = 0; i < int_len; i++) {
                FEE_PUT('0' + p[i]);
            }
        } else {
            FEE_PUT('0');
        }
        const uint16_t frac_start = int_len > 0 ? (uint16_t)int_len : 0;
        if (frac_end > frac_start) {
            FEE_PUT('.');
            for (int16_t z = 0; z < -int_len; z++) {
                FEE_PUT('0');
            }
            for (uint16_t i = frac_start; i < frac_end; i++) {
                FEE_PUT('0' + p[i]);
            }
        }
    }
#undef FEE_PUT
    out[w] = '\0';
    return w;
}

// F2: "Max fee": KDA <gasLimit x gasPrice>. item.json_token_index is the `meta` object.
items_error_t items_maxFeeToDisplayString(item_t item, char *outVal, uint16_t outValLen) {
    const parsed_json_t *json_all = &(parser_getParserJsonObj()->json);
    uint16_t limit_index = 0;
    uint16_t price_index = 0;
    PARSER_TO_ITEMS_ERROR(object_get_value(json_all, item.json_token_index, JSON_GAS_LIMIT, &limit_index));
    PARSER_TO_ITEMS_ERROR(object_get_value(json_all, item.json_token_index, JSON_GAS_PRICE, &price_index));
    const jsmntok_t *limit = &(json_all->tokens[limit_index]);
    const jsmntok_t *price = &(json_all->tokens[price_index]);

    const uint16_t prefix_len = sizeof(COIN_TICKER) - 1;
    if (outValLen <= prefix_len) {
        return items_data_too_large;
    }
    MEMCPY(outVal, COIN_TICKER, prefix_len);
    const uint16_t fee_len =
        items_maxFee(json_all->buffer + limit->start, (uint16_t)(limit->end - limit->start), json_all->buffer + price->start,
                     (uint16_t)(price->end - price->start), outVal + prefix_len, outValLen - prefix_len);
    if (fee_len == 0) {
        return items_data_too_large;
    }
    return items_ok;
}

items_error_t items_hashToDisplayString(__Z_UNUSED item_t item, char *outVal, uint16_t outValLen) {
    // base64_hash is char[45] holding the 44-char PADDED base64 of the 32-byte blake2b
    // hash + NUL. A Kadena request key is UNPADDED base64url (43 chars for 32 bytes), so
    // -2 (= 43) intentionally drops the trailing '=' padding to match what the user looks
    // up on chain. Do NOT change to -1: that would show the '=' and diverge from the
    // network request key.
    uint16_t len = sizeof(base64_hash) - 2;
    if (len >= outValLen) {
        return items_data_too_large;
    }

    snprintf(outVal, outValLen, "%.*s", len, base64_hash);
    return items_ok;
}

items_error_t items_unknownCapabilityToDisplayString(item_t item, char *outVal, uint16_t outValLen) {
    uint16_t token_index = 0;
    uint16_t args_count = 0;
    uint16_t outVal_idx = 0;
    parsed_json_t *json_all = &(parser_getParserJsonObj()->json);
    uint16_t item_token_index = item.json_token_index;
    jsmntok_t *token = NULL;
    uint16_t len = 0;

    PARSER_TO_ITEMS_ERROR(object_get_value(json_all, item_token_index, JSON_NAME, &token_index));
    token = &(json_all->tokens[token_index]);

    len = token->end - token->start;

    if (len == 0) {
        return items_length_zero;
    }

    if (len >= outValLen) {
        return items_data_too_large;
    }

    snprintf(outVal, outValLen, "name: %.*s, ]}],\"", len, json_all->buffer + token->start);

    // outVal_idx is after the , of %.*s
    outVal_idx = sizeof("name: ") + len + 1;

    if (item.can_display == bool_false) {
        const char *msg = "args cannot be displayed on Ledger";
        uint16_t len_msg = strlen(msg);

        if (outVal_idx + len_msg >= outValLen) {
            return items_data_too_large;
        }

        snprintf(outVal + outVal_idx, len_msg + 1, "%s", msg);
        return items_ok;
    }

    PARSER_TO_ITEMS_ERROR(object_get_value(json_all, item_token_index, "args", &token_index));
    PARSER_TO_ITEMS_ERROR(array_get_element_count(json_all, token_index, &args_count));

    if (args_count) {
        uint16_t args_token_index = 0;
        for (uint8_t i = 0; i < (uint8_t)args_count - 1; i++) {
            PARSER_TO_ITEMS_ERROR(array_get_nth_element(json_all, token_index, i, &args_token_index));
            token = &(json_all->tokens[args_token_index]);

            const uint16_t raw = token->end - token->start;
            len = raw + (token->type == JSMN_STRING ? sizeof("arg X: \"\",") : sizeof("arg X: ,"));

            // Bound every write against the caller's buffer (len includes the NUL).
            if (outVal_idx + len > outValLen) {
                return items_data_too_large;
            }

            // Bound the value with an explicit precision: json_all->buffer is the raw
            // (non-NUL-terminated) signed tx, so a plain %s would over-read past
            // token->end into following JSON and print bytes that were never signed.
            snprintf(outVal + outVal_idx, len, (token->type == JSMN_STRING) ? "arg %d: \"%.*s\"," : "arg %d: %.*s,", i + 1,
                     raw, json_all->buffer + token->start);

            outVal_idx += len;
            outVal[outVal_idx - 1] = ' ';  // Remove null terminator
        }

        // Last arg (without comma)
        PARSER_TO_ITEMS_ERROR(array_get_nth_element(json_all, token_index, args_count - 1, &args_token_index));
        token = &(json_all->tokens[args_token_index]);

        const uint16_t raw = token->end - token->start;
        len = raw + (token->type == JSMN_STRING ? sizeof("arg X: \"\"") : sizeof("arg X: "));

        if (outVal_idx + len > outValLen) {
            return items_data_too_large;
        }

        snprintf(outVal + outVal_idx, len, (token->type == JSMN_STRING) ? "arg %d: \"%.*s\"" : "arg %d: %.*s", args_count,
                 raw, json_all->buffer + token->start);
    } else {
        const char *msg = "no args";
        uint16_t len_msg = strlen(msg);

        if (outVal_idx + len_msg >= outValLen) {
            return items_data_too_large;
        }

        snprintf(outVal + outVal_idx, len_msg + 1, "%s", msg);
    }

    return items_ok;
}

items_error_t items_signersToDisplayString(__Z_UNUSED item_t item, char *outVal, uint16_t outValLen) {
    const unsigned int count = parser_getSignersCount();

    // A uint16_t count has at most 5 digits, plus the NUL.
    if (outValLen < 6) {
        return items_data_too_large;
    }

    snprintf(outVal, outValLen, "%u", count);
    return items_ok;
}

#if defined(LEDGER_SPECIFIC)
items_error_t items_signForAddrToDisplayString(__Z_UNUSED item_t item, char *outVal, uint16_t outValLen) {
    uint8_t address[65];
    uint16_t address_len = 0;

    if (crypto_fillAddress(address, sizeof(address), &address_len) != zxerr_ok) {
        return items_error;
    }

    // 2 hex chars per byte + NUL; bound against the caller's buffer, never
    // overwrite outValLen.
    if ((2 * PUB_KEY_LENGTH) + 1 > outValLen) {
        return items_data_too_large;
    }
    array_to_hexstr(outVal, outValLen, address, PUB_KEY_LENGTH);

    return items_ok;
}
#endif