/*******************************************************************************
 *   Ledger Ethereum App
 *   (c) 2016-2019 Ledger
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

// Adapted from https://github.com/calccrypto/uint256_t

#pragma once

#include <stdint.h>
#include <stdbool.h>
#include "uint128.h"

typedef struct uint256_t {
    uint128_t elements[2];
} uint256_t;

void readu256BE(const uint8_t *buffer, uint256_t *target);
void writeu256BE(const uint256_t *number, uint8_t *buffer);
bool zero256(const uint256_t *number);
void copy256(uint256_t *target, const uint256_t *number);
void clear256(uint256_t *target);
void shiftl256(const uint256_t *number, uint32_t value, uint256_t *target);
void shiftr256(const uint256_t *number, uint32_t value, uint256_t *target);
uint32_t bits256(const uint256_t *number);
bool equal256(const uint256_t *number1, const uint256_t *number2);
bool gt256(const uint256_t *number1, const uint256_t *number2);
bool gte256(const uint256_t *number1, const uint256_t *number2);
void add256(const uint256_t *number1, const uint256_t *number2, uint256_t *target);
void sub256(const uint256_t *number1, const uint256_t *number2, uint256_t *target);
void or256(const uint256_t *number1, const uint256_t *number2, uint256_t *target);
bool mul256(const uint256_t *number1, const uint256_t *number2, uint256_t *target);
void divmod256(const uint256_t *l, const uint256_t *r, uint256_t *div, uint256_t *mod);
bool tostring256(const uint256_t *number, uint32_t base, char *out, uint32_t outLength);
bool tostring256_signed(const uint256_t *number, uint32_t base, char *out, uint32_t out_length);
void convertUint256BE(const uint8_t *data, uint32_t length, uint256_t *target);
