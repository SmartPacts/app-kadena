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

#include "common/parser.h"
#include "crypto.h"

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
            snprintf(outVal + outVal_idx, len, (token->type == JSMN_STRING) ? "arg %d: \"%.*s\"," : "arg %d: %.*s,",
                     i + 1, raw, json_all->buffer + token->start);

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

        snprintf(outVal + outVal_idx, len, (token->type == JSMN_STRING) ? "arg %d: \"%.*s\"" : "arg %d: %.*s",
                 args_count, raw, json_all->buffer + token->start);
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