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

#include "buffering_json.h"

#include <zxmacros.h>

#ifdef __cplusplus
extern "C" {
#endif

buffer_json_state_t flash_json;  // Flash

void buffering_json_init(uint8_t *flash_buffer, uint16_t flash_buffer_size) {
    flash_json.data = flash_buffer;
    flash_json.size = flash_buffer_size;
    flash_json.pos = 0;
}

void buffering_json_reset() { flash_json.pos = 0; }

int buffering_json_append(uint8_t *data, int length) {
    if (data == NULL || flash_json.data == NULL) {
        return 0;
    }

    // Flash in use, append to flash
    if (flash_json.size - flash_json.pos >= length) {
        MEMCPY_NV(flash_json.data + flash_json.pos, data, (size_t)length);
        flash_json.pos += length;
    } else {
        return 0;
    }

    return length;
}

buffer_json_state_t *buffering_json_get_flash_buffer() { return &flash_json; }

buffer_json_state_t *buffering_json_get_buffer() { return &flash_json; }

#ifdef __cplusplus
}
#endif
