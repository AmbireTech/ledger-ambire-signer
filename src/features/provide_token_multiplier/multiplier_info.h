#pragma once

#include <stdint.h>
#include <stdbool.h>
#include "common_utils.h"  // ADDRESS_LENGTH, INT256_LENGTH
#include "uint256.h"

// ERC-8056 UI multiplier of a single token, keyed by chain_id + address.
// The multiplier is an 18-decimals fixed-point value (1e18 == 1.0x), exactly as
// returned by the token's uiMultiplier(). It is purely cosmetic: on-chain
// amounts stay raw, the device only scales the *displayed* amount by it.
typedef struct {
    uint64_t chain_id;
    uint8_t address[ADDRESS_LENGTH];
    uint256_t multiplier;
} token_multiplier_t;

int set_token_multiplier(const token_multiplier_t *info);
void clear_token_multipliers(void);
const token_multiplier_t *get_token_multiplier(const uint64_t *chain_id, const uint8_t *address);
bool scale_amount_by_multiplier(const uint64_t *chain_id,
                                const uint8_t *address,
                                const uint8_t *raw_be,
                                uint8_t raw_len,
                                uint8_t out[INT256_LENGTH]);
