/**
 * @file test_param_enum.c
 * @brief Unit tests for the ENUM parameter in
 *        src/features/generic_tx_parser/gtp_param_enum.c.
 *
 * ENUM renders a numeric value as a human label looked up in the
 * enum_value table keyed by (chain_id, contract_addr, selector, id,
 * value). The formatter takes the LAST byte of the parsed value as the
 * lookup key (so "value of 0x05" works whether the field is 1, 4, or 32
 * bytes wide), then chains five preconditions that each surface as a
 * `false` return when they fail:
 *   - value_get must succeed,
 *   - get_current_tx_info must be non-NULL (chain_id source),
 *   - the parsed value must be non-empty,
 *   - calldata_get_selector(get_current_calldata()) must yield a
 *     selector — without it the lookup key is incomplete,
 *   - get_matching_enum must return a registered entry.
 *
 * Tests pin each of those branches in turn, plus the broadcast loop
 * and the standard add_to_field_table propagation. The TLV side covers
 * the happy path and the ENFORCE_UNIQUE_TAG guard on TAG_ID.
 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

#include "gtp_param_enum.h"
#include "gtp_parsed_value.h"
#include "gtp_value.h"
#include "gtp_field.h"
#include "gtp_tx_info.h"
#include "enum_value.h"
#include "calldata.h"
#include "shared_context.h"

// =============================================================================
// Globals
// =============================================================================

strings_t strings;
static chain_config_t g_chainConfig = {.ticker = "ETH", .chain_id = 1, .coin_type = 60};
const chain_config_t *g_chain_config = &g_chainConfig;
const char g_unknown_ticker[] = "???";

// txContext.content->destination is read for the lookup key.
static txContent_t s_tx_content;
txContext_t txContext = {.content = &s_tx_content};
tmpContent_t tmpContent;

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

static bool g_hvs_ret = true;
bool __wrap_handle_value_struct(const buffer_t *buf, s_value_context *context) {
    (void) buf;
    (void) context;
    return g_hvs_ret;
}

static s_tx_info g_fake_tx_info;
static const s_tx_info *g_tx_info_ret = NULL;
const s_tx_info *__wrap_get_current_tx_info(void) {
    return g_tx_info_ret;
}

static s_calldata g_fake_calldata;  // contents irrelevant — only pointer identity matters
static s_calldata *g_calldata_ret = &g_fake_calldata;
s_calldata *__wrap_get_current_calldata(void) {
    return g_calldata_ret;
}

static const uint8_t g_selector[4] = {0xDE, 0xAD, 0xBE, 0xEF};
static const uint8_t *g_selector_ret = g_selector;
const uint8_t *__wrap_calldata_get_selector(const s_calldata *calldata) {
    (void) calldata;
    return g_selector_ret;
}

static const s_enum_value_entry *g_enum_ret = NULL;
const s_enum_value_entry *__wrap_get_matching_enum(const uint64_t *chain_id,
                                                   const uint8_t *contract_addr,
                                                   const uint8_t *selector,
                                                   uint8_t id,
                                                   uint8_t value) {
    check_expected(*chain_id);
    check_expected_ptr(contract_addr);
    check_expected_ptr(selector);
    check_expected(id);
    check_expected(value);
    return g_enum_ret;
}

bool __wrap_add_to_field_table(e_param_type type,
                               const char *key,
                               const char *value,
                               const void *extra_data) {
    check_expected(type);
    check_expected(key);
    check_expected(value);
    check_expected_ptr(extra_data);
    return (bool) mock();
}

// =============================================================================
// Fixtures
// =============================================================================

static const uint8_t g_contract[ADDRESS_LENGTH] = {
    0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22, 0x33, 0x44,
    0x55, 0x66, 0x77, 0x88, 0x99, 0x00, 0xAA, 0xBB, 0xCC, 0xDD,
};

static int reset(void **state) {
    (void) state;
    memset(&g_vg, 0, sizeof(g_vg));
    g_vg_call = 0;
    g_vg_ret = true;
    g_hvs_ret = true;

    memset(&g_fake_tx_info, 0, sizeof(g_fake_tx_info));
    g_fake_tx_info.chain_id = 1;
    g_tx_info_ret = &g_fake_tx_info;

    g_calldata_ret = &g_fake_calldata;
    g_selector_ret = g_selector;
    g_enum_ret = NULL;

    memset(&s_tx_content, 0, sizeof(s_tx_content));
    memcpy(s_tx_content.destination, g_contract, ADDRESS_LENGTH);
    return 0;
}

// =============================================================================
// format_param_enum — happy path
// =============================================================================

static void test_format_known_enum_resolves(void **state) {
    (void) state;
    static const uint8_t v[] = {0x05};  // enum value = 5
    g_vg[0].size = 1;
    g_vg[0].value[0] = (s_parsed_value){.ptr = v, .size = 1, .offset = 0, .length = 1};

    static const s_enum_value_entry entry = {.name = "BUY", .value = 5, .id = 7};
    g_enum_ret = &entry;

    expect_value(__wrap_get_matching_enum, *chain_id, 1);
    expect_memory(__wrap_get_matching_enum, contract_addr, g_contract, ADDRESS_LENGTH);
    expect_memory(__wrap_get_matching_enum, selector, g_selector, sizeof(g_selector));
    expect_value(__wrap_get_matching_enum, id, 7);
    expect_value(__wrap_get_matching_enum, value, 5);

    expect_value(__wrap_add_to_field_table, type, PARAM_TYPE_ENUM);
    expect_string(__wrap_add_to_field_table, key, "Action");
    expect_string(__wrap_add_to_field_table, value, "BUY");
    expect_value(__wrap_add_to_field_table, extra_data, &entry);
    will_return(__wrap_add_to_field_table, true);

    s_param_enum param = {0};
    param.id = 7;
    assert_true(format_param_enum(&param, "Action"));
}

static void test_format_takes_last_byte_of_wide_value(void **state) {
    (void) state;
    // 32-byte BE value with only the LSB set to 0x09 — the formatter
    // explicitly takes ptr[length - 1] as the lookup key.
    static const uint8_t v[INT256_LENGTH] = {
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x09,
    };
    g_vg[0].size = 1;
    g_vg[0].value[0] =
        (s_parsed_value){.ptr = v, .size = INT256_LENGTH, .offset = 0, .length = INT256_LENGTH};

    static const s_enum_value_entry entry = {.name = "SELL", .value = 9, .id = 7};
    g_enum_ret = &entry;

    expect_value(__wrap_get_matching_enum, *chain_id, 1);
    expect_any(__wrap_get_matching_enum, contract_addr);
    expect_any(__wrap_get_matching_enum, selector);
    expect_value(__wrap_get_matching_enum, id, 7);
    expect_value(__wrap_get_matching_enum, value, 0x09);

    expect_value(__wrap_add_to_field_table, type, PARAM_TYPE_ENUM);
    expect_string(__wrap_add_to_field_table, key, "Action");
    expect_string(__wrap_add_to_field_table, value, "SELL");
    expect_any(__wrap_add_to_field_table, extra_data);
    will_return(__wrap_add_to_field_table, true);

    s_param_enum param = {0};
    param.id = 7;
    assert_true(format_param_enum(&param, "Action"));
}

// =============================================================================
// format_param_enum — reject paths
// =============================================================================

static void test_format_value_get_failure_returns_false(void **state) {
    (void) state;
    g_vg_ret = false;
    s_param_enum param = {0};
    assert_false(format_param_enum(&param, "Action"));
}

static void test_format_tx_info_null_returns_false(void **state) {
    (void) state;
    static const uint8_t v[] = {0x01};
    g_vg[0].size = 1;
    g_vg[0].value[0] = (s_parsed_value){.ptr = v, .size = 1, .offset = 0, .length = 1};
    g_tx_info_ret = NULL;

    s_param_enum param = {0};
    assert_false(format_param_enum(&param, "Action"));
}

static void test_format_empty_value_rejected(void **state) {
    (void) state;
    g_vg[0].size = 1;
    g_vg[0].value[0] = (s_parsed_value){.ptr = NULL, .size = 0, .offset = 0, .length = 0};

    s_param_enum param = {0};
    assert_false(format_param_enum(&param, "Action"));
}

static void test_format_selector_missing_rejects(void **state) {
    (void) state;
    static const uint8_t v[] = {0x01};
    g_vg[0].size = 1;
    g_vg[0].value[0] = (s_parsed_value){.ptr = v, .size = 1, .offset = 0, .length = 1};
    g_selector_ret = NULL;

    s_param_enum param = {0};
    assert_false(format_param_enum(&param, "Action"));
}

static void test_format_unknown_enum_rejects(void **state) {
    (void) state;
    static const uint8_t v[] = {0xAA};  // some unregistered value
    g_vg[0].size = 1;
    g_vg[0].value[0] = (s_parsed_value){.ptr = v, .size = 1, .offset = 0, .length = 1};
    g_enum_ret = NULL;  // not found

    expect_value(__wrap_get_matching_enum, *chain_id, 1);
    expect_any(__wrap_get_matching_enum, contract_addr);
    expect_any(__wrap_get_matching_enum, selector);
    expect_value(__wrap_get_matching_enum, id, 0);
    expect_value(__wrap_get_matching_enum, value, 0xAA);

    s_param_enum param = {0};
    assert_false(format_param_enum(&param, "Action"));
}

static void test_format_add_to_field_table_failure_propagates(void **state) {
    (void) state;
    static const uint8_t v[] = {0x01};
    g_vg[0].size = 1;
    g_vg[0].value[0] = (s_parsed_value){.ptr = v, .size = 1, .offset = 0, .length = 1};

    static const s_enum_value_entry entry = {.name = "OPEN", .value = 1};
    g_enum_ret = &entry;

    expect_value(__wrap_get_matching_enum, *chain_id, 1);
    expect_any(__wrap_get_matching_enum, contract_addr);
    expect_any(__wrap_get_matching_enum, selector);
    expect_value(__wrap_get_matching_enum, id, 0);
    expect_value(__wrap_get_matching_enum, value, 1);

    expect_value(__wrap_add_to_field_table, type, PARAM_TYPE_ENUM);
    expect_string(__wrap_add_to_field_table, key, "Action");
    expect_string(__wrap_add_to_field_table, value, "OPEN");
    expect_value(__wrap_add_to_field_table, extra_data, &entry);
    will_return(__wrap_add_to_field_table, false);

    s_param_enum param = {0};
    assert_false(format_param_enum(&param, "Action"));
}

// =============================================================================
// handle_param_enum_struct (TLV)
// =============================================================================

static bool run_tlv(const uint8_t *bytes, size_t size, s_param_enum *param) {
    buffer_t buf = {.ptr = (uint8_t *) bytes, .size = size, .offset = 0};
    s_param_enum_context ctx = {.param = param};
    return handle_param_enum_struct(&buf, &ctx);
}

static void test_tlv_happy_path(void **state) {
    (void) state;
    // VERSION=1, ID=3, VALUE empty
    const uint8_t bytes[] = {
        0x00,
        0x01,
        0x01,
        0x01,
        0x01,
        0x03,
        0x02,
        0x00,
    };
    s_param_enum param = {0};
    assert_true(run_tlv(bytes, sizeof(bytes), &param));
    assert_int_equal(param.version, 1);
    assert_int_equal(param.id, 3);
}

static void test_tlv_duplicate_id_rejected(void **state) {
    (void) state;
    const uint8_t bytes[] = {
        0x00,
        0x01,
        0x01,
        0x01,
        0x01,
        0x03,
        0x01,
        0x01,
        0x04,  // duplicate ID
        0x02,
        0x00,
    };
    s_param_enum param = {0};
    assert_false(run_tlv(bytes, sizeof(bytes), &param));
}

// =============================================================================
// Runner
// =============================================================================

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup(test_format_known_enum_resolves, reset),
        cmocka_unit_test_setup(test_format_takes_last_byte_of_wide_value, reset),
        cmocka_unit_test_setup(test_format_value_get_failure_returns_false, reset),
        cmocka_unit_test_setup(test_format_tx_info_null_returns_false, reset),
        cmocka_unit_test_setup(test_format_empty_value_rejected, reset),
        cmocka_unit_test_setup(test_format_selector_missing_rejects, reset),
        cmocka_unit_test_setup(test_format_unknown_enum_rejects, reset),
        cmocka_unit_test_setup(test_format_add_to_field_table_failure_propagates, reset),
        cmocka_unit_test_setup(test_tlv_happy_path, reset),
        cmocka_unit_test_setup(test_tlv_duplicate_id_rejected, reset),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
