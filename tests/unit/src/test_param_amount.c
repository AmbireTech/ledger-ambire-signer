/**
 * @file test_param_amount.c
 * @brief Unit tests for the AMOUNT parameter in
 *        src/features/generic_tx_parser/gtp_param_amount.c.
 *
 * Two layers are exercised:
 *   - handle_param_amount_struct() runs the per-parameter TLV parser. The
 *     handler for TAG_VERSION enforces a 1-byte payload, the handler for
 *     TAG_VALUE delegates to handle_value_struct (wrapped here). The TLV
 *     framework also enforces ENFORCE_UNIQUE_TAG so receiving the same
 *     tag twice must be rejected.
 *   - format_param_amount() iterates the parsed-value collection produced
 *     by value_get(), formats each element with amountToString() at
 *     WEI_TO_ETHER scale and pushes it to the field table. The test
 *     verifies the broadcast loop, the ticker resolution, and the early
 *     exits (NULL tx_info, value_get failure, add_to_field_table
 *     failure).
 *
 * Format follows the same conventions as the pre-existing
 * test_param_token_amount / test_param_calldata suites: value_get,
 * value_cleanup, handle_value_struct, get_current_tx_info,
 * get_displayable_ticker and add_to_field_table are all wrapped via
 * linker --wrap.
 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

#include "gtp_param_amount.h"
#include "gtp_parsed_value.h"
#include "gtp_value.h"
#include "gtp_tx_info.h"
#include "gtp_field.h"
#include "shared_context.h"
#include "network.h"

// =============================================================================
// Globals the module reads
// =============================================================================

strings_t strings;
static chain_config_t g_chainConfig = {.ticker = "ETH", .chain_id = 1, .coin_type = 60};
const chain_config_t *g_chain_config = &g_chainConfig;
const char g_unknown_ticker[] = "???";
txContext_t txContext;

// =============================================================================
// Wrapped dependencies
// =============================================================================

static int g_vg_call = 0;
static s_parsed_value_collection g_vg[1];
static bool g_vg_ret = true;

bool __wrap_value_get(const s_value *value, s_parsed_value_collection *collection) {
    (void) value;
    *collection = g_vg[g_vg_call++];
    return g_vg_ret;
}

void __wrap_value_cleanup(const s_value *value, const s_parsed_value_collection *collection) {
    (void) value;
    (void) collection;
}

// Used by the TAG_VALUE handler of handle_param_amount_struct.
static bool g_hvs_ret = true;
bool __wrap_handle_value_struct(const buffer_t *buf, s_value_context *context) {
    (void) buf;
    (void) context;
    return g_hvs_ret;
}

static const s_tx_info *g_tx_info_ret = NULL;
const s_tx_info *__wrap_get_current_tx_info(void) {
    return g_tx_info_ret;
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

// =============================================================================
// Test fixtures
// =============================================================================

static s_tx_info g_fake_tx_info;

static int reset(void **state) {
    (void) state;
    memset(&g_vg, 0, sizeof(g_vg));
    g_vg_call = 0;
    g_vg_ret = true;
    g_hvs_ret = true;
    memset(&g_fake_tx_info, 0, sizeof(g_fake_tx_info));
    g_fake_tx_info.chain_id = 1;
    g_tx_info_ret = &g_fake_tx_info;
    return 0;
}

// 1 ETH = 1e18 wei, big-endian in 32 bytes — the high bytes are zero, the
// low bytes spell out 0x0DE0B6B3A7640000 (= 10^18).
static uint8_t g_one_eth[INT256_LENGTH] = {
    0,    0,    0,    0,    0,    0,    0,    0,  //
    0,    0,    0,    0,    0,    0,    0,    0,  //
    0,    0,    0,    0,    0,    0,    0,    0,  //
    0x0D, 0xE0, 0xB6, 0xB3, 0xA7, 0x64, 0x00, 0x00,
};

// 2 ETH = 2e18 wei
static uint8_t g_two_eth[INT256_LENGTH] = {
    0,    0,    0,    0,    0,    0,    0,    0,  //
    0,    0,    0,    0,    0,    0,    0,    0,  //
    0,    0,    0,    0,    0,    0,    0,    0,  //
    0x1B, 0xC1, 0x6D, 0x67, 0x4E, 0xC8, 0x00, 0x00,
};

// =============================================================================
// format_param_amount
// =============================================================================

static void test_format_single_value_ok(void **state) {
    (void) state;

    g_vg[0].size = 1;
    g_vg[0].value[0] = (s_parsed_value){.ptr = g_one_eth,
                                        .size = INT256_LENGTH,
                                        .offset = 0,
                                        .length = INT256_LENGTH};

    expect_value(__wrap_add_to_field_table, type, PARAM_TYPE_AMOUNT);
    expect_string(__wrap_add_to_field_table, key, "Amount");
    expect_string(__wrap_add_to_field_table, value, "1 ETH");
    will_return(__wrap_add_to_field_table, true);

    s_param_amount param = {0};
    assert_true(format_param_amount(&param, "Amount"));
}

static void test_format_multiple_values_iterates(void **state) {
    (void) state;

    g_vg[0].size = 2;
    g_vg[0].value[0] = (s_parsed_value){.ptr = g_one_eth,
                                        .size = INT256_LENGTH,
                                        .offset = 0,
                                        .length = INT256_LENGTH};
    g_vg[0].value[1] = (s_parsed_value){.ptr = g_two_eth,
                                        .size = INT256_LENGTH,
                                        .offset = 0,
                                        .length = INT256_LENGTH};

    expect_value(__wrap_add_to_field_table, type, PARAM_TYPE_AMOUNT);
    expect_string(__wrap_add_to_field_table, key, "Amount");
    expect_string(__wrap_add_to_field_table, value, "1 ETH");
    will_return(__wrap_add_to_field_table, true);

    expect_value(__wrap_add_to_field_table, type, PARAM_TYPE_AMOUNT);
    expect_string(__wrap_add_to_field_table, key, "Amount");
    expect_string(__wrap_add_to_field_table, value, "2 ETH");
    will_return(__wrap_add_to_field_table, true);

    s_param_amount param = {0};
    assert_true(format_param_amount(&param, "Amount"));
}

static void test_format_value_get_failure_returns_false(void **state) {
    (void) state;
    g_vg_ret = false;
    // No add_to_field_table expected — value_get short-circuits the loop.

    s_param_amount param = {0};
    assert_false(format_param_amount(&param, "Amount"));
}

static void test_format_tx_info_null_returns_false(void **state) {
    (void) state;
    g_vg[0].size = 1;
    g_vg[0].value[0] = (s_parsed_value){.ptr = g_one_eth,
                                        .size = INT256_LENGTH,
                                        .offset = 0,
                                        .length = INT256_LENGTH};
    g_tx_info_ret = NULL;  // no current tx → cannot resolve ticker

    s_param_amount param = {0};
    assert_false(format_param_amount(&param, "Amount"));
}

static void test_format_add_to_field_table_failure_propagates(void **state) {
    (void) state;
    g_vg[0].size = 2;
    g_vg[0].value[0] = (s_parsed_value){.ptr = g_one_eth,
                                        .size = INT256_LENGTH,
                                        .offset = 0,
                                        .length = INT256_LENGTH};
    g_vg[0].value[1] = (s_parsed_value){.ptr = g_two_eth,
                                        .size = INT256_LENGTH,
                                        .offset = 0,
                                        .length = INT256_LENGTH};

    // First entry accepted, second rejected — loop must break and return false.
    expect_value(__wrap_add_to_field_table, type, PARAM_TYPE_AMOUNT);
    expect_string(__wrap_add_to_field_table, key, "Amount");
    expect_string(__wrap_add_to_field_table, value, "1 ETH");
    will_return(__wrap_add_to_field_table, true);

    expect_value(__wrap_add_to_field_table, type, PARAM_TYPE_AMOUNT);
    expect_string(__wrap_add_to_field_table, key, "Amount");
    expect_string(__wrap_add_to_field_table, value, "2 ETH");
    will_return(__wrap_add_to_field_table, false);

    s_param_amount param = {0};
    assert_false(format_param_amount(&param, "Amount"));
}

// =============================================================================
// handle_param_amount_struct (TLV parser)
// =============================================================================
//
// TLV byte layout used by tlv_library: tag(1B) | length(1B for <128) | value.
// TAG_VERSION = 0x00, TAG_VALUE = 0x01 in this parser.

static bool run_tlv(const uint8_t *bytes, size_t size, s_param_amount *param) {
    buffer_t buf = {.ptr = (uint8_t *) bytes, .size = size, .offset = 0};
    s_param_amount_context ctx = {.param = param};
    return handle_param_amount_struct(&buf, &ctx);
}

static void test_tlv_happy_path_sets_version(void **state) {
    (void) state;
    // VERSION(0x00) [len 1] [0x42], VALUE(0x01) [len 0]
    const uint8_t bytes[] = {0x00, 0x01, 0x42, 0x01, 0x00};
    s_param_amount param = {0};

    assert_true(run_tlv(bytes, sizeof(bytes), &param));
    assert_int_equal(param.version, 0x42);
}

static void test_tlv_version_wrong_size_rejected(void **state) {
    (void) state;
    // VERSION with a 2-byte payload — handle_version requires exactly 1.
    const uint8_t bytes[] = {0x00, 0x02, 0x01, 0x02, 0x01, 0x00};
    s_param_amount param = {0};

    assert_false(run_tlv(bytes, sizeof(bytes), &param));
}

static void test_tlv_value_handler_failure_propagates(void **state) {
    (void) state;
    g_hvs_ret = false;  // handle_value_struct (wrapped) refuses the payload
    const uint8_t bytes[] = {0x00, 0x01, 0x01, 0x01, 0x00};
    s_param_amount param = {0};

    assert_false(run_tlv(bytes, sizeof(bytes), &param));
}

static void test_tlv_duplicate_tag_rejected(void **state) {
    (void) state;
    // Both TAG_VERSION and TAG_VALUE are ENFORCE_UNIQUE_TAG in the parser.
    // Sending VERSION twice must be rejected.
    const uint8_t bytes[] = {
        0x00,
        0x01,
        0x01,  // VERSION = 1
        0x00,
        0x01,
        0x02,  // VERSION = 2 (duplicate)
        0x01,
        0x00,  // VALUE empty
    };
    s_param_amount param = {0};

    assert_false(run_tlv(bytes, sizeof(bytes), &param));
}

// =============================================================================
// Runner
// =============================================================================

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup(test_format_single_value_ok, reset),
        cmocka_unit_test_setup(test_format_multiple_values_iterates, reset),
        cmocka_unit_test_setup(test_format_value_get_failure_returns_false, reset),
        cmocka_unit_test_setup(test_format_tx_info_null_returns_false, reset),
        cmocka_unit_test_setup(test_format_add_to_field_table_failure_propagates, reset),
        cmocka_unit_test_setup(test_tlv_happy_path_sets_version, reset),
        cmocka_unit_test_setup(test_tlv_version_wrong_size_rejected, reset),
        cmocka_unit_test_setup(test_tlv_value_handler_failure_propagates, reset),
        cmocka_unit_test_setup(test_tlv_duplicate_tag_rejected, reset),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
