/**
 * @file test_token_multiplier.c
 * @brief Unit tests for the ERC-8056 token multiplier store and scaling math at
 *        src/features/provide_token_multiplier/multiplier_info.c.
 *
 * The descriptor parsing + LedgerPKI verification path lives (file-locally) in
 * cmd_token_multiplier.c and is exercised end-to-end by the ragger functional
 * tests. Here we focus on the pure logic reachable through the public API:
 *   - the (chain_id, address -> multiplier) store: set / get / clear;
 *   - scale_amount_by_multiplier(): the 256-bit `raw * multiplier / 1e18`
 *     computation and its edge cases (identity 1.0x, missing descriptor,
 *     overflow fallback, wrong chain).
 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

#include "multiplier_info.h"

static const uint8_t g_token_addr[ADDRESS_LENGTH] = {
    0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
    0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
};

// 1e18 (1.0x) and 10e18 (10.0x), big-endian.
static const uint8_t MULT_ONE_E18[] = {0x0D, 0xE0, 0xB6, 0xB3, 0xA7, 0x64, 0x00, 0x00};
static const uint8_t MULT_TEN_E18[] = {0x8A, 0xC7, 0x23, 0x04, 0x89, 0xE8, 0x00, 0x00};

static int reset(void **state) {
    (void) state;
    clear_token_multipliers();
    return 0;
}

/**
 * @brief Build and register a multiplier for g_token_addr on chain 1.
 *
 * @param[in] mult_be the multiplier as big-endian bytes
 * @param[in] mult_len length of @p mult_be
 */
static void register_multiplier(const uint8_t *mult_be, uint8_t mult_len) {
    token_multiplier_t entry = {0};
    entry.chain_id = 1;
    memcpy(entry.address, g_token_addr, ADDRESS_LENGTH);
    convertUint256BE(mult_be, mult_len, &entry.multiplier);
    assert_int_not_equal(set_token_multiplier(&entry), -1);
}

// =============================================================================
// Store: set / get / clear
// =============================================================================

static void test_set_get_roundtrip(void **state) {
    (void) state;
    register_multiplier(MULT_TEN_E18, sizeof(MULT_TEN_E18));
    uint64_t chain = 1;
    const token_multiplier_t *m = get_token_multiplier(&chain, g_token_addr);
    assert_non_null(m);
    assert_int_equal(m->chain_id, 1);
    assert_memory_equal(m->address, g_token_addr, ADDRESS_LENGTH);
}

static void test_get_miss_wrong_chain(void **state) {
    (void) state;
    register_multiplier(MULT_TEN_E18, sizeof(MULT_TEN_E18));
    uint64_t wrong_chain = 137;
    assert_null(get_token_multiplier(&wrong_chain, g_token_addr));
}

static void test_get_miss_wrong_address(void **state) {
    (void) state;
    register_multiplier(MULT_TEN_E18, sizeof(MULT_TEN_E18));
    uint8_t wrong_addr[ADDRESS_LENGTH];
    memset(wrong_addr, 0xCC, ADDRESS_LENGTH);
    uint64_t chain = 1;
    assert_null(get_token_multiplier(&chain, wrong_addr));
}

static void test_clear_releases_entries(void **state) {
    (void) state;
    register_multiplier(MULT_TEN_E18, sizeof(MULT_TEN_E18));
    uint64_t chain = 1;
    assert_non_null(get_token_multiplier(&chain, g_token_addr));
    clear_token_multipliers();
    assert_null(get_token_multiplier(&chain, g_token_addr));
}

static void test_set_updates_in_place(void **state) {
    (void) state;
    register_multiplier(MULT_ONE_E18, sizeof(MULT_ONE_E18));
    // A second set on the same (chain, address) must update, not duplicate.
    register_multiplier(MULT_TEN_E18, sizeof(MULT_TEN_E18));
    uint64_t chain = 1;
    const uint8_t raw[] = {0x05};
    uint8_t out[INT256_LENGTH] = {0};
    // Effective multiplier is now 10x -> scaling applies.
    assert_true(scale_amount_by_multiplier(&chain, g_token_addr, raw, sizeof(raw), out));
}

// =============================================================================
// scale_amount_by_multiplier
// =============================================================================

static void test_scale_applies_ten_x(void **state) {
    (void) state;
    register_multiplier(MULT_TEN_E18, sizeof(MULT_TEN_E18));
    uint64_t chain = 1;
    const uint8_t raw[] = {0x05};  // 5 tokens (raw)
    uint8_t out[INT256_LENGTH] = {0};
    assert_true(scale_amount_by_multiplier(&chain, g_token_addr, raw, sizeof(raw), out));
    // 5 * 10e18 / 1e18 == 50 -> last byte 0x32, all others 0.
    uint8_t expected[INT256_LENGTH] = {0};
    expected[INT256_LENGTH - 1] = 50;
    assert_memory_equal(out, expected, INT256_LENGTH);
}

static void test_scale_identity_is_noop(void **state) {
    (void) state;
    register_multiplier(MULT_ONE_E18, sizeof(MULT_ONE_E18));
    uint64_t chain = 1;
    const uint8_t raw[] = {0x05};
    uint8_t out[INT256_LENGTH] = {0};
    // 1.0x must not scale ("skip label" edge case) -> caller keeps raw amount.
    assert_false(scale_amount_by_multiplier(&chain, g_token_addr, raw, sizeof(raw), out));
}

static void test_scale_without_descriptor_is_noop(void **state) {
    (void) state;
    uint64_t chain = 1;
    const uint8_t raw[] = {0x05};
    uint8_t out[INT256_LENGTH] = {0};
    // Token absent from CAL / no multiplier provided -> raw fallback.
    assert_false(scale_amount_by_multiplier(&chain, g_token_addr, raw, sizeof(raw), out));
}

static void test_scale_overflow_falls_back(void **state) {
    (void) state;
    uint8_t mult_max[INT256_LENGTH];
    memset(mult_max, 0xFF, sizeof(mult_max));  // ~2^256 multiplier
    register_multiplier(mult_max, sizeof(mult_max));
    uint64_t chain = 1;
    const uint8_t raw[] = {0x02};  // 2 * (2^256-1) overflows uint256
    uint8_t out[INT256_LENGTH] = {0};
    assert_false(scale_amount_by_multiplier(&chain, g_token_addr, raw, sizeof(raw), out));
}

static void test_scale_wrong_chain_is_noop(void **state) {
    (void) state;
    register_multiplier(MULT_TEN_E18, sizeof(MULT_TEN_E18));
    uint64_t wrong_chain = 137;
    const uint8_t raw[] = {0x05};
    uint8_t out[INT256_LENGTH] = {0};
    assert_false(scale_amount_by_multiplier(&wrong_chain, g_token_addr, raw, sizeof(raw), out));
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup(test_set_get_roundtrip, reset),
        cmocka_unit_test_setup(test_get_miss_wrong_chain, reset),
        cmocka_unit_test_setup(test_get_miss_wrong_address, reset),
        cmocka_unit_test_setup(test_clear_releases_entries, reset),
        cmocka_unit_test_setup(test_set_updates_in_place, reset),
        cmocka_unit_test_setup(test_scale_applies_ten_x, reset),
        cmocka_unit_test_setup(test_scale_identity_is_noop, reset),
        cmocka_unit_test_setup(test_scale_without_descriptor_is_noop, reset),
        cmocka_unit_test_setup(test_scale_overflow_falls_back, reset),
        cmocka_unit_test_setup(test_scale_wrong_chain_is_noop, reset),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
