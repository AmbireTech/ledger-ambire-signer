/*******************************************************************************
 *   Ledger Ethereum App
 *   (c) 2026 Ledger
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
 *
 ********************************************************************************/

#include <string.h>
#include "lists.h"
#include "app_mem_utils.h"
#include "multiplier_info.h"

typedef struct {
    flist_node_t
        node;  // MUST be first for direct casting from flist_node_t* to token_multiplier_node_t*
    token_multiplier_t info;
} token_multiplier_node_t;

static token_multiplier_node_t *g_token_multiplier_list = NULL;

// 1e18 (1.0x), the identity ERC-8056 multiplier, as an 8-byte big-endian value.
static const uint8_t ONE_E18_BE[] = {0x0D, 0xE0, 0xB6, 0xB3, 0xA7, 0x64, 0x00, 0x00};

/**
 * @brief Store (or update) the multiplier of a token, keyed by chain_id+address.
 *
 * @param[in] info the multiplier to store
 * @return the index of the entry on success, -1 on failure
 */
int set_token_multiplier(const token_multiplier_t *info) {
    token_multiplier_node_t *node;
    int idx = 0;

    if (info == NULL) {
        return -1;
    }
    // look for an existing matching node
    for (node = g_token_multiplier_list; node != NULL;
         node = (token_multiplier_node_t *) ((flist_node_t *) node)->next) {
        if (info->chain_id == node->info.chain_id) {
            if (memcmp(info->address, node->info.address, sizeof(node->info.address)) == 0) {
                break;
            }
        }
        idx += 1;
    }

    if (node == NULL) {
        if ((node = APP_MEM_ALLOC(sizeof(*node))) == NULL) {
            return -1;
        }
        flist_push_back((flist_node_t **) &g_token_multiplier_list, (flist_node_t *) node);
    }
    memcpy(&node->info, info, sizeof(node->info));
    return idx;
}

/**
 * @brief Delete a single multiplier node (flist callback).
 *
 * @param[in] node the node to free
 */
static void delete_token_multiplier(token_multiplier_node_t *node) {
    APP_MEM_FREE(node);
}

/**
 * @brief Forget every stored token multiplier.
 *
 * Scoped to a single transaction, cleared alongside the token infos.
 */
void clear_token_multipliers(void) {
    flist_clear((flist_node_t **) &g_token_multiplier_list,
                (f_list_node_del) &delete_token_multiplier);
}

/**
 * @brief Look up the multiplier of a token.
 *
 * @param[in] chain_id chain of the token
 * @param[in] address contract address of the token
 * @return the matching multiplier, or NULL if none was provided
 */
const token_multiplier_t *get_token_multiplier(const uint64_t *chain_id, const uint8_t *address) {
    if ((chain_id != NULL) && (address != NULL)) {
        for (const token_multiplier_node_t *node = g_token_multiplier_list; node != NULL;
             node = (token_multiplier_node_t *) ((flist_node_t *) node)->next) {
            if (*chain_id == node->info.chain_id) {
                if (memcmp(address, node->info.address, sizeof(node->info.address)) == 0) {
                    return &node->info;
                }
            }
        }
    }
    return NULL;
}

/**
 * @brief Apply the stored UI multiplier (if any) to a raw big-endian amount.
 *
 * Computes `raw * multiplier / 1e18` using 256-bit arithmetic.
 *
 * @param[in] chain_id chain of the token
 * @param[in] address contract address of the token
 * @param[in] raw_be raw amount, big-endian (1..INT256_LENGTH bytes)
 * @param[in] raw_len length of @p raw_be
 * @param[out] out INT256_LENGTH-byte big-endian UI-scaled amount (only valid when true is returned)
 * @return true when an effective multiplier was applied and stored in @p out;
 *         false when nothing must be applied (no descriptor, identity 1.0x
 *         multiplier, or overflow) — the caller must then keep the raw amount.
 */
bool scale_amount_by_multiplier(const uint64_t *chain_id,
                                const uint8_t *address,
                                const uint8_t *raw_be,
                                uint8_t raw_len,
                                uint8_t out[INT256_LENGTH]) {
    const token_multiplier_t *entry;
    uint256_t one_e18;
    uint256_t raw256;
    uint256_t product;
    uint256_t scaled;
    uint256_t mod;

    if ((raw_be == NULL) || (raw_len == 0) || (raw_len > INT256_LENGTH) || (out == NULL)) {
        return false;
    }
    if ((entry = get_token_multiplier(chain_id, address)) == NULL) {
        // No multiplier descriptor for this token (e.g. token absent from CAL).
        return false;
    }
    convertUint256BE(ONE_E18_BE, sizeof(ONE_E18_BE), &one_e18);
    // A zero multiplier is meaningless, and 1.0x is a no-op ("skip label").
    if (zero256(&entry->multiplier) || equal256(&entry->multiplier, &one_e18)) {
        return false;
    }
    convertUint256BE(raw_be, raw_len, &raw256);
    if (!mul256(&raw256, &entry->multiplier, &product)) {
        // uint256 overflow: the UI amount would not fit. Fall back to the raw
        // amount rather than displaying a silently truncated value.
        PRINTF("MULTIPLIER: overflow, falling back to raw amount\n");
        return false;
    }
    divmod256(&product, &one_e18, &scaled, &mod);
    writeu256BE(&scaled, out);
    return true;
}
