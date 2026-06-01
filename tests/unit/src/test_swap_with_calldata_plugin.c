/**
 * @file test_swap_with_calldata_plugin.c
 * @brief Unit tests for the SWAP_WITH_CALLDATA internal plugin at
 *        src/plugins/swap_with_calldata/swap_with_calldata_plugin.c.
 *
 * SWAP_WITH_CALLDATA is the integration that lets Thorswap / LiFi
 * promise a swap calldata in the Exchange app and have the Eth app
 * verify, at signing time, that the calldata it sees is the one
 * that was promised. The promise is a 32-byte SHA-256 digest stored
 * in G_swap_crosschain_hash; the plugin recomputes the digest over
 * (selector || params[0..N-1]) and compares.
 *
 * If the calldata sent to the Eth app does not match the promised
 * digest, the device must NOT sign the transaction unchecked. The
 * plugin pins that:
 *  - the plugin refuses any call outside of swap context (defence in
 *    depth: this entry point should only be reachable through the
 *    swap dispatcher, but a misrouted message must fail closed),
 *  - INIT seeds the running sha256 with the 4-byte selector,
 *  - PROVIDE_PARAMETER folds each 32-byte parameter into the digest,
 *  - FINALIZE compares the digest against G_swap_crosschain_hash;
 *    mismatch -> G_swap_mode = SWAP_MODE_ERROR (the exchange app
 *    aborts the swap),
 *  - even on a match, the swap_mode must have been
 *    SWAP_MODE_CROSSCHAIN_PENDING_CHECK before; anything else is
 *    treated as out-of-protocol and flips to ERROR,
 *  - FINALIZE always returns ETH_PLUGIN_RESULT_FALLBACK so the
 *    generic ETH signing UI takes over (the error is propagated
 *    through G_swap_mode, not through the result enum).
 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

#include "shared_context.h"
#include "eth_plugin_interface.h"
#include "lcx_sha256.h"

void swap_with_calldata_plugin_call(eth_plugin_msg_t message, void *parameters);

// =============================================================================
// Globals (the source reads these unconditionally)
// =============================================================================

strings_t strings;
static chain_config_t g_chainConfig = {.ticker = "ETH", .chain_id = 1, .coin_type = 60};
const chain_config_t *g_chain_config = &g_chainConfig;
const char g_unknown_ticker[] = "???";
txContext_t txContext;
tmpContent_t tmpContent;
volatile bool G_called_from_swap;
swap_mode_t G_swap_mode;
static uint8_t g_promised_hash[CX_SHA256_SIZE];
uint8_t *G_swap_crosschain_hash = g_promised_hash;

// =============================================================================
// Wraps for the SHA-256 primitives
// =============================================================================
//
// We don't need real SHA-256 — the only behaviour we care about is:
// 1. selector + parameters are folded into a running state that grows
//    deterministically with each call,
// 2. the "final" output is whatever the test wants it to be (controlled
//    via g_force_final_digest).
//
// Implement a 32-byte XOR-accumulator that's good enough to detect
// "no update was ever called" vs "the right number of updates ran".

static uint8_t g_xor_state[CX_SHA256_SIZE];
static int g_update_calls = 0;
static cx_err_t g_update_ret = CX_OK;

cx_err_t __wrap_cx_sha256_init_no_throw(cx_sha256_t *hash) {
    (void) hash;
    memset(g_xor_state, 0, sizeof(g_xor_state));
    g_update_calls = 0;
    return CX_OK;
}

cx_err_t __wrap_cx_sha256_update(cx_sha256_t *ctx, const uint8_t *in, size_t in_len) {
    (void) ctx;
    for (size_t i = 0; i < in_len; i++) {
        g_xor_state[i % CX_SHA256_SIZE] ^= in[i];
    }
    g_update_calls++;
    return g_update_ret;
}

static const uint8_t *g_force_final_digest = NULL;
cx_err_t __wrap_cx_sha256_final(cx_sha256_t *ctx, uint8_t *digest) {
    (void) ctx;
    if (g_force_final_digest != NULL) {
        memcpy(digest, g_force_final_digest, CX_SHA256_SIZE);
    } else {
        memcpy(digest, g_xor_state, CX_SHA256_SIZE);
    }
    return CX_OK;
}

// =============================================================================
// Fixture
// =============================================================================

static int reset(void **state) {
    (void) state;
    G_called_from_swap = true;
    G_swap_mode = SWAP_MODE_CROSSCHAIN_PENDING_CHECK;
    memset(g_promised_hash, 0, sizeof(g_promised_hash));
    memset(g_xor_state, 0, sizeof(g_xor_state));
    g_update_calls = 0;
    g_update_ret = CX_OK;
    g_force_final_digest = NULL;
    return 0;
}

// =============================================================================
// Tests — INIT
// =============================================================================

static void test_init_outside_swap_rejected(void **state) {
    (void) state;
    G_called_from_swap = false;
    uint8_t ctx[sizeof(cx_sha256_t)] = {0};
    static const uint8_t selector[SELECTOR_SIZE] = {0xAA, 0xBB, 0xCC, 0xDD};
    ethPluginInitContract_t msg = {0};
    msg.pluginContext = ctx;
    msg.selector = selector;
    swap_with_calldata_plugin_call(ETH_PLUGIN_INIT_CONTRACT, &msg);
    assert_int_equal(msg.result, ETH_PLUGIN_RESULT_ERROR);
    assert_int_equal(g_update_calls, 0);
}

static void test_init_in_swap_hashes_selector(void **state) {
    (void) state;
    uint8_t ctx[sizeof(cx_sha256_t)] = {0};
    static const uint8_t selector[SELECTOR_SIZE] = {0xAA, 0xBB, 0xCC, 0xDD};
    ethPluginInitContract_t msg = {0};
    msg.pluginContext = ctx;
    msg.selector = selector;
    swap_with_calldata_plugin_call(ETH_PLUGIN_INIT_CONTRACT, &msg);
    assert_int_equal(msg.result, ETH_PLUGIN_RESULT_OK);
    // One sha256_update call, for the selector.
    assert_int_equal(g_update_calls, 1);
    // The selector bytes must appear in the XOR accumulator.
    assert_int_equal(g_xor_state[0], 0xAA);
    assert_int_equal(g_xor_state[1], 0xBB);
    assert_int_equal(g_xor_state[2], 0xCC);
    assert_int_equal(g_xor_state[3], 0xDD);
}

static void test_init_sha256_update_failure_propagates(void **state) {
    (void) state;
    g_update_ret = CX_INVALID_PARAMETER;
    uint8_t ctx[sizeof(cx_sha256_t)] = {0};
    static const uint8_t selector[SELECTOR_SIZE] = {0xAA, 0xBB, 0xCC, 0xDD};
    ethPluginInitContract_t msg = {0};
    msg.pluginContext = ctx;
    msg.selector = selector;
    swap_with_calldata_plugin_call(ETH_PLUGIN_INIT_CONTRACT, &msg);
    assert_int_equal(msg.result, ETH_PLUGIN_RESULT_ERROR);
}

// =============================================================================
// Tests — PROVIDE_PARAMETER
// =============================================================================

static void test_provide_parameter_outside_swap_rejected(void **state) {
    (void) state;
    G_called_from_swap = false;
    uint8_t ctx[sizeof(cx_sha256_t)] = {0};
    uint8_t param[PARAMETER_LENGTH] = {0};
    ethPluginProvideParameter_t msg = {0};
    msg.pluginContext = ctx;
    msg.parameter = param;
    swap_with_calldata_plugin_call(ETH_PLUGIN_PROVIDE_PARAMETER, &msg);
    assert_int_equal(msg.result, ETH_PLUGIN_RESULT_ERROR);
}

static void test_provide_parameter_in_swap_folds_into_digest(void **state) {
    (void) state;
    uint8_t ctx[sizeof(cx_sha256_t)] = {0};
    uint8_t param[PARAMETER_LENGTH];
    memset(param, 0x42, sizeof(param));
    ethPluginProvideParameter_t msg = {0};
    msg.pluginContext = ctx;
    msg.parameter = param;
    swap_with_calldata_plugin_call(ETH_PLUGIN_PROVIDE_PARAMETER, &msg);
    assert_int_equal(msg.result, ETH_PLUGIN_RESULT_OK);
    assert_int_equal(g_update_calls, 1);
}

// =============================================================================
// Tests — FINALIZE
// =============================================================================

static void test_finalize_outside_swap_rejected(void **state) {
    (void) state;
    G_called_from_swap = false;
    uint8_t ctx[sizeof(cx_sha256_t)] = {0};
    txContent_t tx = {0};
    ethPluginFinalize_t msg = {0};
    msg.pluginContext = ctx;
    msg.txContent = &tx;
    swap_with_calldata_plugin_call(ETH_PLUGIN_FINALIZE, &msg);
    assert_int_equal(msg.result, ETH_PLUGIN_RESULT_ERROR);
}

static void test_finalize_hash_mismatch_flips_swap_mode_to_error(void **state) {
    (void) state;
    // Promise = all-0x77. Force the computed digest to all-0x88.
    memset(g_promised_hash, 0x77, sizeof(g_promised_hash));
    static uint8_t forced[CX_SHA256_SIZE];
    memset(forced, 0x88, sizeof(forced));
    g_force_final_digest = forced;

    uint8_t ctx[sizeof(cx_sha256_t)] = {0};
    txContent_t tx = {0};
    ethPluginFinalize_t msg = {0};
    msg.pluginContext = ctx;
    msg.txContent = &tx;
    swap_with_calldata_plugin_call(ETH_PLUGIN_FINALIZE, &msg);

    assert_int_equal(G_swap_mode, SWAP_MODE_ERROR);
    // The result enum is ALWAYS FALLBACK at this point; error is
    // reported via G_swap_mode.
    assert_int_equal(msg.result, ETH_PLUGIN_RESULT_FALLBACK);
    assert_null(msg.tokenLookup1);
    assert_null(msg.tokenLookup2);
}

static void test_finalize_hash_match_flips_mode_to_success(void **state) {
    (void) state;
    // Promise == computed (both 0x55).
    memset(g_promised_hash, 0x55, sizeof(g_promised_hash));
    static uint8_t forced[CX_SHA256_SIZE];
    memset(forced, 0x55, sizeof(forced));
    g_force_final_digest = forced;
    G_swap_mode = SWAP_MODE_CROSSCHAIN_PENDING_CHECK;

    uint8_t ctx[sizeof(cx_sha256_t)] = {0};
    txContent_t tx = {0};
    ethPluginFinalize_t msg = {0};
    msg.pluginContext = ctx;
    msg.txContent = &tx;
    swap_with_calldata_plugin_call(ETH_PLUGIN_FINALIZE, &msg);

    assert_int_equal(G_swap_mode, SWAP_MODE_CROSSCHAIN_SUCCESS);
    assert_int_equal(msg.result, ETH_PLUGIN_RESULT_FALLBACK);
}

static void test_finalize_match_but_wrong_swap_mode_flips_error(void **state) {
    (void) state;
    // Even with a matching hash, if we're not in the dedicated
    // CROSSCHAIN_PENDING_CHECK mode (e.g. SWAP_MODE_STANDARD), the
    // plugin treats the validation as out-of-protocol and flips to
    // ERROR so the exchange aborts.
    memset(g_promised_hash, 0x55, sizeof(g_promised_hash));
    static uint8_t forced[CX_SHA256_SIZE];
    memset(forced, 0x55, sizeof(forced));
    g_force_final_digest = forced;
    G_swap_mode = SWAP_MODE_STANDARD;

    uint8_t ctx[sizeof(cx_sha256_t)] = {0};
    txContent_t tx = {0};
    ethPluginFinalize_t msg = {0};
    msg.pluginContext = ctx;
    msg.txContent = &tx;
    swap_with_calldata_plugin_call(ETH_PLUGIN_FINALIZE, &msg);

    assert_int_equal(G_swap_mode, SWAP_MODE_ERROR);
}

// =============================================================================
// Tests — dispatcher
// =============================================================================

static void test_unknown_message_is_silent_noop(void **state) {
    (void) state;
    // PROVIDE_INFO / QUERY_CONTRACT_ID / QUERY_CONTRACT_UI all fall
    // into the default arm and just PRINTF a warning; no segfault and
    // no result mutation.
    uint32_t sentinel = 0xFEEDFACEU;
    swap_with_calldata_plugin_call(ETH_PLUGIN_PROVIDE_INFO, &sentinel);
    swap_with_calldata_plugin_call(ETH_PLUGIN_QUERY_CONTRACT_ID, &sentinel);
    swap_with_calldata_plugin_call(ETH_PLUGIN_QUERY_CONTRACT_UI, &sentinel);
    assert_int_equal(sentinel, 0xFEEDFACEU);
}

// =============================================================================
// Runner
// =============================================================================

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup(test_init_outside_swap_rejected, reset),
        cmocka_unit_test_setup(test_init_in_swap_hashes_selector, reset),
        cmocka_unit_test_setup(test_init_sha256_update_failure_propagates, reset),
        cmocka_unit_test_setup(test_provide_parameter_outside_swap_rejected, reset),
        cmocka_unit_test_setup(test_provide_parameter_in_swap_folds_into_digest, reset),
        cmocka_unit_test_setup(test_finalize_outside_swap_rejected, reset),
        cmocka_unit_test_setup(test_finalize_hash_mismatch_flips_swap_mode_to_error, reset),
        cmocka_unit_test_setup(test_finalize_hash_match_flips_mode_to_success, reset),
        cmocka_unit_test_setup(test_finalize_match_but_wrong_swap_mode_flips_error, reset),
        cmocka_unit_test_setup(test_unknown_message_is_silent_noop, reset),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
