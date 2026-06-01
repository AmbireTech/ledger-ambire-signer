/**
 * @file test_token_info.c
 * @brief Unit tests for the ERC-20 token-info registry at
 *        src/features/provide_erc20_token_information/token_info.c.
 *
 * The registry is the device's cache of (chain_id, contract_address)
 * -> (ticker, decimals) lookups used by every ERC-20 amount renderer
 * and by token_amount / token GCS parameters. Four public entry
 * points:
 *   - set_token_info: insert or update an entry, returning its
 *     position in the list (the same call site can ask for an index
 *     it remembered to refer back to the entry later).
 *   - clear_token_infos: drop all entries.
 *   - get_matching_token_info: strict (chain_id, address) lookup or
 *     NULL.
 *   - get_matching_token_info_or_dummy: lookup-or-create variant —
 *     missing entries are auto-registered with ticker="???" and
 *     decimals=0 so downstream code never has to special-case
 *     "unknown" tokens.
 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

#include "token_info.h"

// =============================================================================
// Globals expected by token_info.c (via network.h)
// =============================================================================

const char g_unknown_ticker[] = "???";

// =============================================================================
// Fixtures
// =============================================================================

static int reset(void **state) {
    (void) state;
    clear_token_infos();
    return 0;
}

static const uint8_t g_usdc[ADDRESS_LENGTH] = {
    0xA0, 0xb8, 0x69, 0x91, 0xc6, 0x21, 0x8b, 0x36, 0xc1, 0xd1,
    0x9D, 0x4a, 0x2e, 0x9E, 0xb0, 0xcE, 0x36, 0x06, 0xeB, 0x48,
};
static const uint8_t g_dai[ADDRESS_LENGTH] = {
    0x6B, 0x17, 0x54, 0x74, 0xE8, 0x90, 0x94, 0xC4, 0x4D, 0xa9,
    0x8b, 0x95, 0x4E, 0xed, 0xeA, 0xC4, 0x95, 0x27, 0x1d, 0x0F,
};

// =============================================================================
// set_token_info
// =============================================================================

static void test_set_null_info_rejected(void **state) {
    (void) state;
    assert_int_equal(set_token_info(NULL), -1);
}

static void test_set_first_entry_returns_index_zero(void **state) {
    (void) state;
    s_token_info info = {.chain_id = 1, .decimals = 6};
    memcpy(info.address, g_usdc, ADDRESS_LENGTH);
    strlcpy(info.ticker, "USDC", sizeof(info.ticker));

    assert_int_equal(set_token_info(&info), 0);
    const s_token_info *fetched = get_matching_token_info(&info.chain_id, info.address);
    assert_non_null(fetched);
    assert_string_equal(fetched->ticker, "USDC");
    assert_int_equal(fetched->decimals, 6);
}

static void test_set_second_distinct_entry_returns_index_one(void **state) {
    (void) state;
    s_token_info a = {.chain_id = 1, .decimals = 6};
    memcpy(a.address, g_usdc, ADDRESS_LENGTH);
    strlcpy(a.ticker, "USDC", sizeof(a.ticker));
    s_token_info b = {.chain_id = 1, .decimals = 18};
    memcpy(b.address, g_dai, ADDRESS_LENGTH);
    strlcpy(b.ticker, "DAI", sizeof(b.ticker));

    assert_int_equal(set_token_info(&a), 0);
    assert_int_equal(set_token_info(&b), 1);
}

static void test_set_existing_entry_updates_in_place_returns_same_index(void **state) {
    (void) state;
    s_token_info v1 = {.chain_id = 1, .decimals = 6};
    memcpy(v1.address, g_usdc, ADDRESS_LENGTH);
    strlcpy(v1.ticker, "USDC", sizeof(v1.ticker));
    assert_int_equal(set_token_info(&v1), 0);

    // Same (chain_id, address) — second call must update the existing
    // entry and return the same index.
    s_token_info v2 = {.chain_id = 1, .decimals = 8};
    memcpy(v2.address, g_usdc, ADDRESS_LENGTH);
    strlcpy(v2.ticker, "usdc", sizeof(v2.ticker));
    assert_int_equal(set_token_info(&v2), 0);

    const s_token_info *fetched = get_matching_token_info(&v1.chain_id, v1.address);
    assert_non_null(fetched);
    assert_string_equal(fetched->ticker, "usdc");
    assert_int_equal(fetched->decimals, 8);
}

static void test_set_same_address_different_chain_is_a_new_entry(void **state) {
    (void) state;
    s_token_info eth = {.chain_id = 1, .decimals = 6};
    memcpy(eth.address, g_usdc, ADDRESS_LENGTH);
    strlcpy(eth.ticker, "USDC", sizeof(eth.ticker));
    s_token_info polygon = {.chain_id = 137, .decimals = 6};
    memcpy(polygon.address, g_usdc, ADDRESS_LENGTH);
    strlcpy(polygon.ticker, "USDC.e", sizeof(polygon.ticker));

    assert_int_equal(set_token_info(&eth), 0);
    assert_int_equal(set_token_info(&polygon), 1);

    const s_token_info *e1 = get_matching_token_info(&eth.chain_id, eth.address);
    const s_token_info *e2 = get_matching_token_info(&polygon.chain_id, polygon.address);
    assert_string_equal(e1->ticker, "USDC");
    assert_string_equal(e2->ticker, "USDC.e");
}

// =============================================================================
// get_matching_token_info
// =============================================================================

static void test_get_null_inputs_return_null(void **state) {
    (void) state;
    uint64_t chain = 1;
    assert_null(get_matching_token_info(NULL, g_usdc));
    assert_null(get_matching_token_info(&chain, NULL));
}

static void test_get_empty_registry_returns_null(void **state) {
    (void) state;
    uint64_t chain = 1;
    assert_null(get_matching_token_info(&chain, g_usdc));
}

static void test_get_unknown_address_returns_null(void **state) {
    (void) state;
    s_token_info info = {.chain_id = 1, .decimals = 6};
    memcpy(info.address, g_usdc, ADDRESS_LENGTH);
    strlcpy(info.ticker, "USDC", sizeof(info.ticker));
    set_token_info(&info);

    uint64_t chain = 1;
    assert_null(get_matching_token_info(&chain, g_dai));
}

static void test_get_unknown_chain_returns_null(void **state) {
    (void) state;
    s_token_info info = {.chain_id = 1, .decimals = 6};
    memcpy(info.address, g_usdc, ADDRESS_LENGTH);
    strlcpy(info.ticker, "USDC", sizeof(info.ticker));
    set_token_info(&info);

    uint64_t chain = 137;  // not registered for this address
    assert_null(get_matching_token_info(&chain, g_usdc));
}

// =============================================================================
// get_matching_token_info_or_dummy
// =============================================================================

static void test_dummy_null_inputs_return_null(void **state) {
    (void) state;
    uint64_t chain = 1;
    assert_null(get_matching_token_info_or_dummy(NULL, g_usdc));
    assert_null(get_matching_token_info_or_dummy(&chain, NULL));
}

static void test_dummy_known_returns_existing(void **state) {
    (void) state;
    s_token_info info = {.chain_id = 1, .decimals = 6};
    memcpy(info.address, g_usdc, ADDRESS_LENGTH);
    strlcpy(info.ticker, "USDC", sizeof(info.ticker));
    set_token_info(&info);

    uint64_t chain = 1;
    const s_token_info *got = get_matching_token_info_or_dummy(&chain, g_usdc);
    assert_non_null(got);
    assert_string_equal(got->ticker, "USDC");
    assert_int_equal(got->decimals, 6);
}

static void test_dummy_unknown_creates_unknown_marker(void **state) {
    (void) state;
    uint64_t chain = 1;
    const s_token_info *got = get_matching_token_info_or_dummy(&chain, g_dai);
    assert_non_null(got);
    // The unknown marker uses g_unknown_ticker ("???") and decimals=0
    // so downstream renderers can fall through with no special case.
    assert_string_equal(got->ticker, g_unknown_ticker);
    assert_int_equal(got->decimals, 0);
    assert_int_equal(got->chain_id, 1);
    assert_memory_equal(got->address, g_dai, ADDRESS_LENGTH);

    // Subsequent get_matching_token_info now returns the registered
    // dummy entry (the side effect is persistent).
    assert_ptr_equal(get_matching_token_info(&chain, g_dai), got);
}

static void test_dummy_persists_across_calls(void **state) {
    (void) state;
    // Two consecutive get_or_dummy calls for the same key must return
    // the same registered entry, NOT create two dummies.
    uint64_t chain = 1;
    const s_token_info *a = get_matching_token_info_or_dummy(&chain, g_dai);
    const s_token_info *b = get_matching_token_info_or_dummy(&chain, g_dai);
    assert_ptr_equal(a, b);
}

// =============================================================================
// clear_token_infos
// =============================================================================

static void test_clear_empties_registry(void **state) {
    (void) state;
    s_token_info a = {.chain_id = 1, .decimals = 6};
    memcpy(a.address, g_usdc, ADDRESS_LENGTH);
    strlcpy(a.ticker, "USDC", sizeof(a.ticker));
    s_token_info b = {.chain_id = 1, .decimals = 18};
    memcpy(b.address, g_dai, ADDRESS_LENGTH);
    strlcpy(b.ticker, "DAI", sizeof(b.ticker));
    set_token_info(&a);
    set_token_info(&b);

    clear_token_infos();

    uint64_t chain = 1;
    assert_null(get_matching_token_info(&chain, g_usdc));
    assert_null(get_matching_token_info(&chain, g_dai));
    // After clear, the index counter restarts from 0 — verifies the
    // list was actually freed, not just unlinked.
    assert_int_equal(set_token_info(&a), 0);
}

// =============================================================================
// Runner
// =============================================================================

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup(test_set_null_info_rejected, reset),
        cmocka_unit_test_setup(test_set_first_entry_returns_index_zero, reset),
        cmocka_unit_test_setup(test_set_second_distinct_entry_returns_index_one, reset),
        cmocka_unit_test_setup(test_set_existing_entry_updates_in_place_returns_same_index, reset),
        cmocka_unit_test_setup(test_set_same_address_different_chain_is_a_new_entry, reset),
        cmocka_unit_test_setup(test_get_null_inputs_return_null, reset),
        cmocka_unit_test_setup(test_get_empty_registry_returns_null, reset),
        cmocka_unit_test_setup(test_get_unknown_address_returns_null, reset),
        cmocka_unit_test_setup(test_get_unknown_chain_returns_null, reset),
        cmocka_unit_test_setup(test_dummy_null_inputs_return_null, reset),
        cmocka_unit_test_setup(test_dummy_known_returns_existing, reset),
        cmocka_unit_test_setup(test_dummy_unknown_creates_unknown_marker, reset),
        cmocka_unit_test_setup(test_dummy_persists_across_calls, reset),
        cmocka_unit_test_setup(test_clear_empties_registry, reset),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
