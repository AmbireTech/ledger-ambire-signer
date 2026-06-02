/**
 * @file test_handle_swap_sign_transaction.c
 * @brief Unit tests for copy_transaction_parameters at
 *        src/swap/handle_swap_sign_transaction.c.
 *
 * The Ledger Exchange app calls copy_transaction_parameters at swap-init
 * time -- the binary structure it hands the Ethereum app contains the
 * amount, fees, destination, and (for cross-chain swaps) the partner-
 * promised calldata hash. The Ethereum app COPIES these values onto its
 * own stack before validating, because the input pointer can alias
 * Ethereum-app globals.
 *
 * Pin every reject / accept branch:
 *
 *  - amount_length > 32                      false  (CWE-787 overflow on copy)
 *  - fee_amount_length > 8                   false  (idem)
 *  - destination_address overflow            false  (strlcpy truncation guard)
 *  - parse_swap_config fails                 false
 *  - amountToString(fees) fails              false
 *  - amountToString(amount) fails standard   false
 *  - amountToString(amount) fails crosschain false
 *  - EXTRA_ID_TYPE_NATIVE                    true,  G_swap_mode = STANDARD
 *  - EXTRA_ID_TYPE_EVM_CALLDATA              true,  G_swap_mode = CROSSCHAIN_PENDING_CHECK
 *                                                   + crosschain hash copied to
 * G_swap_crosschain_hash
 *  - invalid extra_id type                   true,  G_swap_mode = ERROR
 *                                                   (the function does NOT short-circuit; it
 *                                                   remembers and reports the issue later)
 *
 * The noreturn `swap_finalize_exchange_sign_transaction` and
 * `handle_swap_sign_transaction` entry points are not exercised here --
 * each calls os_lib_end() / app_quit() and would terminate the test
 * process. Their bodies are trivial passthrough.
 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

#include "shared_context.h"
#include "swap_lib_calls.h"
#include "chain_config.h"
#include "eth_swap_utils.h"

bool copy_transaction_parameters(create_transaction_parameters_t *sign_transaction_params,
                                 const chain_config_t *config);

// =============================================================================
// Globals the unit under test reads / writes
// =============================================================================
// G_swap_mode and G_swap_crosschain_hash are *defined* by
// handle_swap_sign_transaction.c, so we just observe them from here.
// G_swap_signing_return_value_address lives in the SDK lib_standard_app
// in production; provide local storage for the test.
volatile uint8_t *G_swap_signing_return_value_address;

// =============================================================================
// Wraps
// =============================================================================
// parse_swap_config / get_asset_info_on_network are wrapped through linker
// --wrap so each test can drive the parser outcome without dragging
// eth_swap_utils.c into the link.

bool __wrap_parse_swap_config(const uint8_t *config, uint8_t config_size, swap_context_t *ctx) {
    (void) config;
    (void) config_size;
    bool ok = (bool) mock();
    const char *swapped_ticker = (const char *) mock();
    if (ok && ctx != NULL) {
        // Fees-asset ticker is fixed at "ETH" (native of this chain). The
        // swapped-asset ticker is per-test: equal to "ETH" means the
        // function takes the regular amount path; different (e.g. "USDC")
        // forces the crosschain-non-native zero-amount branch.
        memset(ctx, 0, sizeof(*ctx));
        strlcpy(ctx->swapped_asset_info.ticker,
                swapped_ticker,
                sizeof(ctx->swapped_asset_info.ticker));
        ctx->swapped_asset_info.decimals = 18;
        strlcpy(ctx->fees_asset_info.ticker, "ETH", sizeof(ctx->fees_asset_info.ticker));
        ctx->fees_asset_info.decimals = 18;
    }
    return ok;
}

// Override mocks/mock.c's mem_utils_alloc via --wrap so a single test can
// simulate an out-of-memory APP_MEM_ALLOC.
void *__wrap_mem_utils_alloc(size_t size, bool permanent, const char *file, int line) {
    (void) permanent;
    (void) file;
    (void) line;
    bool ok = (bool) mock();
    return ok ? malloc(size) : NULL;
}

void __wrap_get_asset_info_on_network(bool is_fee,
                                      swap_context_t *context,
                                      chain_config_t *chain_config,
                                      char **ticker,
                                      uint8_t *decimals) {
    (void) is_fee;
    (void) chain_config;
    (void) decimals;
    // For these tests we always point ticker at the fees-asset ticker
    // (which is what production code does for is_fee=true).
    if (ticker != NULL && context != NULL) {
        *ticker = context->fees_asset_info.ticker;
    }
}

bool __wrap_amountToString(const uint8_t *amount,
                           uint8_t amount_len,
                           uint8_t decimals,
                           const char *ticker,
                           char *out_buffer,
                           size_t out_buffer_size) {
    (void) amount;
    (void) amount_len;
    (void) decimals;
    (void) ticker;
    (void) out_buffer_size;
    bool ok = (bool) mock();
    if (ok && out_buffer != NULL && out_buffer_size > 0) {
        strlcpy(out_buffer, "1 ETH", out_buffer_size);
    }
    return ok;
}

// Stubs for the rest of the BSS-reset / lib-call surface. None of these
// observe state in our tests.
void os_explicit_zero_BSS_segment(void) {
    // BSS-zero would clobber the test's own globals -- intentionally a no-op.
}

void set_swap_with_calldata_plugin_type(void) {
}

void ui_swap_show_signing(void) {
}

__attribute__((noreturn)) void app_main(void) {
    while (1) {
    }
}

__attribute__((noreturn)) void os_lib_end(void) {
    while (1) {
    }
}

// =============================================================================
// Fixtures
// =============================================================================

extern swap_mode_t G_swap_mode;
extern uint8_t *G_swap_crosschain_hash;

static chain_config_t s_chain = {.ticker = "ETH", .chain_id = 1, .coin_type = 60};

static uint8_t s_amount[32];
static uint8_t s_fee[8];
static uint8_t s_coin_cfg[16];
static char s_addr[] = "0x1234567890abcdef1234567890abcdef12345678";

static int reset(void **state) {
    (void) state;
    memset(&strings, 0, sizeof(strings));
    memset(s_amount, 0, sizeof(s_amount));
    memset(s_fee, 0, sizeof(s_fee));
    memset(s_coin_cfg, 0, sizeof(s_coin_cfg));
    G_swap_mode = SWAP_MODE_STANDARD;
    if (G_swap_crosschain_hash != NULL) {
        free(G_swap_crosschain_hash);
        G_swap_crosschain_hash = NULL;
    }
    return 0;
}

static create_transaction_parameters_t make_params(void) {
    create_transaction_parameters_t p = {0};
    p.coin_configuration = s_coin_cfg;
    p.coin_configuration_length = sizeof(s_coin_cfg);
    p.amount = s_amount;
    p.amount_length = 4;
    p.fee_amount = s_fee;
    p.fee_amount_length = 4;
    p.destination_address = s_addr;
    p.destination_address_extra_id = NULL;
    return p;
}

// =============================================================================
// Length-bound rejects (CWE-787)
// =============================================================================

static void test_amount_length_over_32_rejected(void **state) {
    (void) state;
    create_transaction_parameters_t p = make_params();
    p.amount_length = 33;
    // parse_swap_config / amountToString MUST NOT be reached -- the
    // length-bound check fails first.
    assert_false(copy_transaction_parameters(&p, &s_chain));
}

static void test_fee_amount_length_over_8_rejected(void **state) {
    (void) state;
    create_transaction_parameters_t p = make_params();
    p.fee_amount_length = 9;
    assert_false(copy_transaction_parameters(&p, &s_chain));
}

// The "destination_address overflow" guard in the source
// (toAddress[sizeof(toAddress)-1] != '\0') is effectively dead code today:
// strlcpy always writes a NUL at dst[size-1] when size > 0. We leave the
// guard in place as defense-in-depth against a future refactor that
// swaps strlcpy for strncpy, but there is no way to exercise that branch
// from a unit test without intercepting strlcpy itself.

// =============================================================================
// parse_swap_config failure
// =============================================================================

static void test_parse_swap_config_failure_rejected(void **state) {
    (void) state;
    create_transaction_parameters_t p = make_params();
    will_return(__wrap_parse_swap_config, false);
    will_return(__wrap_parse_swap_config, "");  // ticker unused when ok=false
    assert_false(copy_transaction_parameters(&p, &s_chain));
}

// =============================================================================
// amountToString failures
// =============================================================================

static void test_amount_to_string_fees_failure_rejected(void **state) {
    (void) state;
    create_transaction_parameters_t p = make_params();
    will_return(__wrap_parse_swap_config, true);
    will_return(__wrap_parse_swap_config, "ETH");
    will_return(__wrap_amountToString, false);  // fees stringification fails
    assert_false(copy_transaction_parameters(&p, &s_chain));
}

static void test_amount_to_string_value_failure_standard_rejected(void **state) {
    (void) state;
    create_transaction_parameters_t p = make_params();
    will_return(__wrap_parse_swap_config, true);
    will_return(__wrap_parse_swap_config, "ETH");
    will_return(__wrap_amountToString, true);   // fees ok
    will_return(__wrap_amountToString, false);  // amount fails
    assert_false(copy_transaction_parameters(&p, &s_chain));
}

// =============================================================================
// Happy paths
// =============================================================================

static void test_native_swap_returns_true_and_sets_standard_mode(void **state) {
    (void) state;
    create_transaction_parameters_t p = make_params();
    // No destination_address_extra_id -> NATIVE branch -> SWAP_MODE_STANDARD.
    will_return(__wrap_parse_swap_config, true);
    will_return(__wrap_parse_swap_config, "ETH");
    will_return(__wrap_amountToString, true);
    will_return(__wrap_amountToString, true);
    will_return(__wrap_mem_utils_alloc, true);
    assert_true(copy_transaction_parameters(&p, &s_chain));
    assert_int_equal(G_swap_mode, SWAP_MODE_STANDARD);
    // crosschain hash MUST stay all-zero for native swaps.
    static const uint8_t zero[32] = {0};
    assert_non_null(G_swap_crosschain_hash);
    assert_memory_equal(G_swap_crosschain_hash, zero, 32);
}

static void test_crosschain_calldata_swap_copies_hash(void **state) {
    (void) state;
    // First byte = EXTRA_ID_TYPE_EVM_CALLDATA (1), next 32 = the hash.
    uint8_t extra_id[1 + 32];
    extra_id[0] = 1;  // EXTRA_ID_TYPE_EVM_CALLDATA
    for (int i = 0; i < 32; i++) extra_id[1 + i] = (uint8_t) (i + 1);
    create_transaction_parameters_t p = make_params();
    p.destination_address_extra_id = (char *) extra_id;
    will_return(__wrap_parse_swap_config, true);
    will_return(__wrap_parse_swap_config, "ETH");
    will_return(__wrap_amountToString, true);
    will_return(__wrap_amountToString, true);
    will_return(__wrap_mem_utils_alloc, true);
    assert_true(copy_transaction_parameters(&p, &s_chain));
    assert_int_equal(G_swap_mode, SWAP_MODE_CROSSCHAIN_PENDING_CHECK);
    // The 32-byte hash from extra_id[1..32] must land in G_swap_crosschain_hash.
    static const uint8_t expected_hash[32] = {1,  2,  3,  4,  5,  6,  7,  8,  9,  10, 11,
                                              12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22,
                                              23, 24, 25, 26, 27, 28, 29, 30, 31, 32};
    assert_non_null(G_swap_crosschain_hash);
    assert_memory_equal(G_swap_crosschain_hash, expected_hash, 32);
}

static void test_unknown_extra_id_type_sets_error_mode_but_continues(void **state) {
    (void) state;
    // First byte = some unknown value -> default case -> SWAP_MODE_ERROR but
    // no early return.
    uint8_t extra_id[1 + 32] = {0xFE};
    create_transaction_parameters_t p = make_params();
    p.destination_address_extra_id = (char *) extra_id;
    will_return(__wrap_parse_swap_config, true);
    will_return(__wrap_parse_swap_config, "ETH");
    will_return(__wrap_amountToString, true);
    will_return(__wrap_amountToString, true);
    will_return(__wrap_mem_utils_alloc, true);
    // The function does NOT bail on an unknown extra_id type -- it commits
    // SWAP_MODE_ERROR so a later screen reports the issue. Returning true
    // here is the load-bearing observation; if a future refactor adds an
    // early `return false`, the caller has no chance to display the error.
    assert_true(copy_transaction_parameters(&p, &s_chain));
    assert_int_equal(G_swap_mode, SWAP_MODE_ERROR);
}

static void test_crosschain_non_native_zero_amount_path(void **state) {
    (void) state;
    // EVM_CALLDATA extra-id but the swapped asset is a token (USDC), not
    // the chain's native ETH. The code must call amountToString once for
    // fees (in ETH) and once with the zero-amount sentinel for the
    // fullAmount (still in fees ticker), because the actual token amount
    // is moved on the destination chain.
    uint8_t extra_id[1 + 32] = {0x01};  // EVM_CALLDATA
    create_transaction_parameters_t p = make_params();
    p.destination_address_extra_id = (char *) extra_id;
    will_return(__wrap_parse_swap_config, true);
    will_return(__wrap_parse_swap_config, "USDC");  // swapped != fees ticker
    will_return(__wrap_amountToString, true);       // fees
    will_return(__wrap_amountToString, true);       // zero-amount fullAmount
    will_return(__wrap_mem_utils_alloc, true);
    assert_true(copy_transaction_parameters(&p, &s_chain));
    assert_int_equal(G_swap_mode, SWAP_MODE_CROSSCHAIN_PENDING_CHECK);
}

static void test_crosschain_non_native_zero_amount_failure_rejected(void **state) {
    (void) state;
    // EVM_CALLDATA + non-native asset: the second amountToString writes the
    // zero-amount fullAmount in the fees ticker. If THAT call fails, the
    // function must return false too -- otherwise we'd commit globals
    // around an incomplete review string.
    uint8_t extra_id[1 + 32] = {0x01};
    create_transaction_parameters_t p = make_params();
    p.destination_address_extra_id = (char *) extra_id;
    will_return(__wrap_parse_swap_config, true);
    will_return(__wrap_parse_swap_config, "USDC");
    will_return(__wrap_amountToString, true);   // fees ok
    will_return(__wrap_amountToString, false);  // zero-amount fullAmount fails
    assert_false(copy_transaction_parameters(&p, &s_chain));
}

static void test_alloc_failure_returns_false(void **state) {
    (void) state;
    create_transaction_parameters_t p = make_params();
    will_return(__wrap_parse_swap_config, true);
    will_return(__wrap_parse_swap_config, "ETH");
    will_return(__wrap_amountToString, true);
    will_return(__wrap_amountToString, true);
    will_return(__wrap_mem_utils_alloc, false);  // out-of-memory on G_swap_crosschain_hash
    assert_false(copy_transaction_parameters(&p, &s_chain));
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup(test_amount_length_over_32_rejected, reset),
        cmocka_unit_test_setup(test_fee_amount_length_over_8_rejected, reset),
        cmocka_unit_test_setup(test_parse_swap_config_failure_rejected, reset),
        cmocka_unit_test_setup(test_amount_to_string_fees_failure_rejected, reset),
        cmocka_unit_test_setup(test_amount_to_string_value_failure_standard_rejected, reset),
        cmocka_unit_test_setup(test_native_swap_returns_true_and_sets_standard_mode, reset),
        cmocka_unit_test_setup(test_crosschain_calldata_swap_copies_hash, reset),
        cmocka_unit_test_setup(test_unknown_extra_id_type_sets_error_mode_but_continues, reset),
        cmocka_unit_test_setup(test_crosschain_non_native_zero_amount_path, reset),
        cmocka_unit_test_setup(test_crosschain_non_native_zero_amount_failure_rejected, reset),
        cmocka_unit_test_setup(test_alloc_failure_returns_false, reset),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
