/**
 * @file test_manage_asset_info.c
 * @brief Unit tests for get_matching_asset_info / forget_known_assets at
 *        src/manage_asset_info.c.
 *
 * manage_asset_info is the unified front for the legacy token-OR-NFT
 * registry pair. The Ethereum app keeps ERC-20 token info and ERC-721/1155
 * NFT info in two distinct stores; callers that don't care which one (e.g.
 * the GCS dispatcher when resolving a contract for display) ask through
 * this single helper. Tokens win over NFTs on shared addresses (the
 * comment in the source pins that precedence).
 *
 * Pin both branches of the lookup plus the bundled forget.
 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

#include "shared_context.h"
#include "manage_asset_info.h"
#include "token_info.h"
#include "nft_info.h"

// =============================================================================
// Wraps
// =============================================================================

static s_token_info s_token_fake;
static s_nft_info s_nft_fake;

const s_token_info *__wrap_get_matching_token_info(const uint64_t *chain_id,
                                                   const uint8_t *address) {
    (void) chain_id;
    (void) address;
    return (const s_token_info *) mock();
}

const s_nft_info *__wrap_get_matching_nft_info(const uint64_t *chain_id, const uint8_t *address) {
    (void) chain_id;
    (void) address;
    return (const s_nft_info *) mock();
}

static int g_clear_token_calls = 0;
void __wrap_clear_token_infos(void) {
    g_clear_token_calls++;
}

static int g_clear_nft_calls = 0;
void __wrap_clear_nft_infos(void) {
    g_clear_nft_calls++;
}

// =============================================================================
// Fixture
// =============================================================================

static int reset(void **state) {
    (void) state;
    g_clear_token_calls = 0;
    g_clear_nft_calls = 0;
    return 0;
}

// =============================================================================
// get_matching_asset_info -- token wins over NFT
// =============================================================================

static void test_token_match_returns_token_skips_nft(void **state) {
    (void) state;
    uint64_t cid = 1;
    uint8_t addr[20] = {0};
    will_return(__wrap_get_matching_token_info, &s_token_fake);
    // get_matching_nft_info MUST NOT be reached when the token lookup hits.
    extraInfo_t *got = get_matching_asset_info(&cid, addr);
    assert_ptr_equal(got, (extraInfo_t *) &s_token_fake);
}

static void test_no_token_falls_back_to_nft(void **state) {
    (void) state;
    uint64_t cid = 1;
    uint8_t addr[20] = {0};
    will_return(__wrap_get_matching_token_info, NULL);
    will_return(__wrap_get_matching_nft_info, &s_nft_fake);
    extraInfo_t *got = get_matching_asset_info(&cid, addr);
    assert_ptr_equal(got, (extraInfo_t *) &s_nft_fake);
}

static void test_no_token_no_nft_returns_null(void **state) {
    (void) state;
    uint64_t cid = 1;
    uint8_t addr[20] = {0};
    will_return(__wrap_get_matching_token_info, NULL);
    will_return(__wrap_get_matching_nft_info, NULL);
    assert_null(get_matching_asset_info(&cid, addr));
}

// =============================================================================
// forget_known_assets -- clears both registries
// =============================================================================

static void test_forget_known_assets_clears_both(void **state) {
    (void) state;
    forget_known_assets();
    assert_int_equal(g_clear_token_calls, 1);
    assert_int_equal(g_clear_nft_calls, 1);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup(test_token_match_returns_token_skips_nft, reset),
        cmocka_unit_test_setup(test_no_token_falls_back_to_nft, reset),
        cmocka_unit_test_setup(test_no_token_no_nft_returns_null, reset),
        cmocka_unit_test_setup(test_forget_known_assets_clears_both, reset),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
