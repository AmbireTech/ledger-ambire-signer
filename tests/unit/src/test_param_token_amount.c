/**
 * @file test_param_token_amount.c
 * @brief Unit tests for TOKEN_AMOUNT parameter formatting, focusing on
 *        §3.1.8 iteration broadcast (secondary collection of size 1 repeated
 *        across all iterations of the primary collection).
 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

#include "gtp_param_token_amount.h"
#include "gtp_parsed_value.h"
#include "gtp_value.h"
#include "gtp_tx_info.h"
#include "token_info.h"
#include "network.h"
#include "shared_context.h"

// Required globals
strings_t strings;
static chain_config_t g_chainConfig = {.ticker = "ETH", .chain_id = 1, .coin_type = 60};
const chain_config_t *g_chain_config = &g_chainConfig;
const char g_unknown_ticker[] = "???";
txContext_t txContext;

// ===========================================================================
// value_get / value_cleanup mock
// ===========================================================================

static int g_vg_call = 0;
static s_parsed_value_collection g_vg[2];

bool __wrap_value_get(const s_value *value, s_parsed_value_collection *collection) {
    (void) value;
    *collection = g_vg[g_vg_call++];
    return true;
}

void __wrap_value_cleanup(const s_value *value, const s_parsed_value_collection *collection) {
    (void) value;
    (void) collection;
}

// ===========================================================================
// handle_value_struct stub — TLV parse handlers reference it but are never
// called by format_param_token_amount; only needed for linkage.
// ===========================================================================

bool __wrap_handle_value_struct(const buffer_t *buf, s_value_context *context) {
    (void) buf;
    (void) context;
    return true;
}

// ===========================================================================
// Other mocks
// ===========================================================================

static s_tx_info g_fake_tx_info;

const s_tx_info *__wrap_get_current_tx_info(void) {
    return &g_fake_tx_info;
}

const s_token_info *__wrap_get_matching_token_info(const uint64_t *chain_id, const uint8_t *addr) {
    (void) chain_id;
    (void) addr;
    return (const s_token_info *) mock();
}

const char *__wrap_get_displayable_ticker(const uint64_t *chain_id,
                                          const chain_config_t *config,
                                          bool mainnet_only) {
    (void) chain_id;
    (void) config;
    (void) mainnet_only;
    return "ETH";
}

bool __wrap_add_to_field_table(e_param_type type,
                               const char *key,
                               const char *value,
                               const void *extra_data) {
    (void) extra_data;
    check_expected(type);
    check_expected(key);
    check_expected(value);
    return (bool) mock();
}

// ===========================================================================
// Test data
// ===========================================================================

// 1 USDC = 1_000_000 (6 decimals) — big-endian in 32 bytes
static uint8_t g_amount1[INT256_LENGTH] = {
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,    0,    0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x0F, 0x42, 0x40,
};

// 2 USDC = 2_000_000 (6 decimals) — big-endian in 32 bytes
static uint8_t g_amount2[INT256_LENGTH] = {
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,    0,    0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x1E, 0x84, 0x80,
};

// Fake USDC token address (20 bytes)
static uint8_t g_usdc_addr[ADDRESS_LENGTH] = {
    0xA0, 0xb8, 0x69, 0x91, 0xc6, 0x21, 0x8b, 0x36, 0xc1, 0xd1,
    0x9D, 0x4a, 0x2e, 0x9E, 0xb0, 0xcE, 0x36, 0x06, 0xeB, 0x48,
};

// Fake USDC extra_info returned by get_matching_token_info
static s_token_info g_usdc_info = {
    .address =
        {
            0xA0, 0xb8, 0x69, 0x91, 0xc6, 0x21, 0x8b, 0x36, 0xc1, 0xd1,
            0x9D, 0x4a, 0x2e, 0x9E, 0xb0, 0xcE, 0x36, 0x06, 0xeB, 0x48,
        },
    .ticker = "USDC",
    .decimals = 6,
    .chain_id = 1,
};

// ===========================================================================
// Tests
// ===========================================================================

/**
 * Broadcast: value collection has 2 elements, token collection has 1 element.
 * The single token must be reused for both amount iterations — §3.1.8.
 * Expected: format_param_token_amount returns true and add_to_field_table is
 * called twice, once for "1 USDC" and once for "2 USDC".
 */
static void test_token_amount_broadcast_ok(void **state) {
    (void) state;

    // Primary collection: two amounts
    g_vg[0].size = 2;
    g_vg[0].value[0] = (s_parsed_value){.ptr = g_amount1,
                                        .size = INT256_LENGTH,
                                        .offset = 0,
                                        .length = INT256_LENGTH};
    g_vg[0].value[1] = (s_parsed_value){.ptr = g_amount2,
                                        .size = INT256_LENGTH,
                                        .offset = 0,
                                        .length = INT256_LENGTH};

    // Secondary (token) collection: one address — broadcast
    g_vg[1].size = 1;
    g_vg[1].value[0] = (s_parsed_value){.ptr = g_usdc_addr,
                                        .size = ADDRESS_LENGTH,
                                        .offset = 0,
                                        .length = ADDRESS_LENGTH};

    g_vg_call = 0;
    memset(&g_fake_tx_info, 0, sizeof(g_fake_tx_info));
    g_fake_tx_info.chain_id = 1;

    // token resolution: USDC found (called for each of the 2 iterations)
    will_return(__wrap_get_matching_token_info, &g_usdc_info);
    will_return(__wrap_get_matching_token_info, &g_usdc_info);

    // Expected field table entries: "1 USDC" then "2 USDC"
    expect_value(__wrap_add_to_field_table, type, PARAM_TYPE_TOKEN_AMOUNT);
    expect_string(__wrap_add_to_field_table, key, "Amount");
    expect_string(__wrap_add_to_field_table, value, "1 USDC");
    will_return(__wrap_add_to_field_table, true);

    expect_value(__wrap_add_to_field_table, type, PARAM_TYPE_TOKEN_AMOUNT);
    expect_string(__wrap_add_to_field_table, key, "Amount");
    expect_string(__wrap_add_to_field_table, value, "2 USDC");
    will_return(__wrap_add_to_field_table, true);

    s_param_token_amount param;
    memset(&param, 0, sizeof(param));
    param.version = 1;
    param.has_token = true;

    assert_true(format_param_token_amount(&param, "Amount"));
}

/**
 * Mismatch rejection: value collection has 2 elements, token collection has 3.
 * Neither is 1, and 3 ≠ 2, so the size check must fail immediately —
 * add_to_field_table must NOT be called.
 */
static void test_token_amount_size_mismatch_rejected(void **state) {
    (void) state;

    // Primary collection: 2 values
    g_vg[0].size = 2;

    // Secondary (token) collection: 3 — mismatched, neither equals 1 nor 2
    g_vg[1].size = 3;

    g_vg_call = 0;

    s_param_token_amount param;
    memset(&param, 0, sizeof(param));
    param.version = 1;
    param.has_token = true;

    // format_param_token_amount must return false; add_to_field_table is NOT called
    assert_false(format_param_token_amount(&param, "Amount"));
}

// ===========================================================================
// Test runner
// ===========================================================================

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_token_amount_broadcast_ok),
        cmocka_unit_test(test_token_amount_size_mismatch_rejected),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
