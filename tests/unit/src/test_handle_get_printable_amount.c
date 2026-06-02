/**
 * @file test_handle_get_printable_amount.c
 * @brief Unit tests for handle_get_printable_amount at
 *        src/swap/handle_get_printable_amount.c.
 *
 * The Ledger Exchange app calls handle_get_printable_amount when it
 * needs the Ethereum app to format an amount + ticker for display
 * (`"1.5 ETH"`, `"100 USDC"`). The handler writes into the shared
 * params->printable_amount buffer; on any failure path the buffer must
 * be left zeroed so the host doesn't display stale / wrong text.
 *
 * Pin every branch:
 *  - amount_length > 32              params->printable_amount stays zero
 *  - parse_swap_config fails         same
 *  - amountToString fails            same (the dispatcher re-zeros the
 *                                     buffer after the failed write)
 *  - happy path                      params->printable_amount holds the
 *                                     formatted string
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

void handle_get_printable_amount(get_printable_amount_parameters_t *params, chain_config_t *config);

// =============================================================================
// Wraps
// =============================================================================

bool __wrap_parse_swap_config(const uint8_t *config, uint8_t config_size, swap_context_t *ctx) {
    (void) config;
    (void) config_size;
    (void) ctx;
    return (bool) mock();
}

void __wrap_get_asset_info_on_network(bool is_fee,
                                      swap_context_t *context,
                                      chain_config_t *chain_config,
                                      char **ticker,
                                      uint8_t *decimals) {
    (void) is_fee;
    (void) context;
    (void) chain_config;
    if (ticker != NULL) {
        // Static literal: the unit under test only passes the pointer
        // through to amountToString (also wrapped) so storage lifetime
        // doesn't matter.
        static char fake[] = "ETH";
        *ticker = fake;
    }
    if (decimals != NULL) {
        *decimals = 18;
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
    bool ok = (bool) mock();
    if (ok && out_buffer != NULL && out_buffer_size > 0) {
        strlcpy(out_buffer, "1 ETH", out_buffer_size);
    }
    return ok;
}

// =============================================================================
// Fixture
// =============================================================================

static chain_config_t s_chain = {.ticker = "ETH", .chain_id = 1, .coin_type = 60};
static uint8_t s_amount[32];
static uint8_t s_coin_cfg[16];

static get_printable_amount_parameters_t make_params(void) {
    get_printable_amount_parameters_t p = {0};
    p.coin_configuration = s_coin_cfg;
    p.coin_configuration_length = sizeof(s_coin_cfg);
    p.amount = s_amount;
    p.amount_length = 4;
    p.is_fee = false;
    return p;
}

static int reset(void **state) {
    (void) state;
    memset(s_amount, 0, sizeof(s_amount));
    memset(s_coin_cfg, 0, sizeof(s_coin_cfg));
    return 0;
}

// =============================================================================
// Failure paths -- buffer must stay zero
// =============================================================================

static void test_amount_length_over_32_zeros_buffer(void **state) {
    (void) state;
    get_printable_amount_parameters_t p = make_params();
    memset(p.printable_amount, 0xCC, sizeof(p.printable_amount));  // pre-poison
    p.amount_length = 33;
    // parse_swap_config / amountToString MUST NOT be reached.
    handle_get_printable_amount(&p, &s_chain);
    static const char zero[MAX_PRINTABLE_AMOUNT_SIZE] = {0};
    assert_memory_equal(p.printable_amount, zero, sizeof(p.printable_amount));
}

static void test_parse_swap_config_failure_zeros_buffer(void **state) {
    (void) state;
    get_printable_amount_parameters_t p = make_params();
    memset(p.printable_amount, 0xCC, sizeof(p.printable_amount));
    will_return(__wrap_parse_swap_config, false);
    handle_get_printable_amount(&p, &s_chain);
    static const char zero[MAX_PRINTABLE_AMOUNT_SIZE] = {0};
    assert_memory_equal(p.printable_amount, zero, sizeof(p.printable_amount));
}

static void test_amount_to_string_failure_zeros_buffer(void **state) {
    (void) state;
    get_printable_amount_parameters_t p = make_params();
    memset(p.printable_amount, 0xCC, sizeof(p.printable_amount));
    will_return(__wrap_parse_swap_config, true);
    will_return(__wrap_amountToString, false);
    handle_get_printable_amount(&p, &s_chain);
    // The dispatcher re-zeros the buffer on amountToString failure --
    // a partial write would expose stale bytes.
    static const char zero[MAX_PRINTABLE_AMOUNT_SIZE] = {0};
    assert_memory_equal(p.printable_amount, zero, sizeof(p.printable_amount));
}

// =============================================================================
// Happy path
// =============================================================================

static void test_success_writes_formatted_amount(void **state) {
    (void) state;
    get_printable_amount_parameters_t p = make_params();
    will_return(__wrap_parse_swap_config, true);
    will_return(__wrap_amountToString, true);
    handle_get_printable_amount(&p, &s_chain);
    assert_string_equal(p.printable_amount, "1 ETH");
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup(test_amount_length_over_32_zeros_buffer, reset),
        cmocka_unit_test_setup(test_parse_swap_config_failure_zeros_buffer, reset),
        cmocka_unit_test_setup(test_amount_to_string_failure_zeros_buffer, reset),
        cmocka_unit_test_setup(test_success_writes_formatted_amount, reset),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
