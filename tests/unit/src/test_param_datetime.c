/**
 * @file test_param_datetime.c
 * @brief Unit tests for the DATETIME parameter in
 *        src/features/generic_tx_parser/gtp_param_datetime.c.
 *
 * The parameter has two render modes, picked at TLV time via TAG_TYPE:
 *   - DT_UNIX (0):       interprets the value as a uint64 timestamp and
 *                        formats it as UTC, with an "Unlimited" sentinel
 *                        when the bytes are all 0xFF (capped allowance).
 *   - DT_BLOCKHEIGHT (1): renders the value as a plain decimal block
 *                         number through uint256_to_decimal.
 *
 * Tests cover both rendering branches, the sentinel detection, multi-
 * iteration broadcast over a value collection, and the TLV parser
 * (VERSION, VALUE, TYPE — all ENFORCE_UNIQUE_TAG, TYPE additionally
 * checked against the enum so unknown values are rejected).
 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

#include "gtp_param_datetime.h"
#include "gtp_parsed_value.h"
#include "gtp_value.h"
#include "gtp_field.h"
#include "shared_context.h"

// =============================================================================
// Globals
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

static bool g_hvs_ret = true;
bool __wrap_handle_value_struct(const buffer_t *buf, s_value_context *context) {
    (void) buf;
    (void) context;
    return g_hvs_ret;
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
// Fixtures
// =============================================================================

static int reset(void **state) {
    (void) state;
    memset(&g_vg, 0, sizeof(g_vg));
    g_vg_call = 0;
    g_vg_ret = true;
    g_hvs_ret = true;
    return 0;
}

// =============================================================================
// format_param_datetime — DT_UNIX branch
// =============================================================================

static void test_format_unix_timestamp_rendered_as_utc(void **state) {
    (void) state;
    // 2024-01-01 00:00:00 UTC = 1704067200 = 0x6592_0080 (big-endian)
    static uint8_t ts[] = {0x65, 0x92, 0x00, 0x80};
    g_vg[0].size = 1;
    g_vg[0].value[0] = (s_parsed_value){.ptr = ts, .size = 4, .offset = 0, .length = 4};

    // Per time_format_to_utc(), hour 0 renders as "12 AM"
    expect_value(__wrap_add_to_field_table, type, PARAM_TYPE_DATETIME);
    expect_string(__wrap_add_to_field_table, key, "Date");
    expect_string(__wrap_add_to_field_table, value, "2024-01-01\n12:00:00 AM UTC");
    will_return(__wrap_add_to_field_table, true);

    s_param_datetime param = {0};
    param.type = DT_UNIX;
    param.value.type_size = 4;
    assert_true(format_param_datetime(&param, "Date"));
}

static void test_format_unix_maxint_renders_unlimited(void **state) {
    (void) state;
    // 4-byte all-0xFF triggers the "Unlimited" sentinel branch.
    static uint8_t maxint4[] = {0xFF, 0xFF, 0xFF, 0xFF};
    g_vg[0].size = 1;
    g_vg[0].value[0] = (s_parsed_value){.ptr = maxint4, .size = 4, .offset = 0, .length = 4};

    expect_value(__wrap_add_to_field_table, type, PARAM_TYPE_DATETIME);
    expect_string(__wrap_add_to_field_table, key, "Until");
    expect_string(__wrap_add_to_field_table, value, "Unlimited");
    will_return(__wrap_add_to_field_table, true);

    s_param_datetime param = {0};
    param.type = DT_UNIX;
    // Sentinel only triggers when value.length >= param.value.type_size; here
    // type_size == length so the >= check is satisfied.
    param.value.type_size = 4;
    assert_true(format_param_datetime(&param, "Until"));
}

// =============================================================================
// format_param_datetime — DT_BLOCKHEIGHT branch
// =============================================================================

static void test_format_blockheight_rendered_decimal(void **state) {
    (void) state;
    // 19_000_000 = 0x0121_EAC0
    static uint8_t height[] = {0x01, 0x21, 0xEA, 0xC0};
    g_vg[0].size = 1;
    g_vg[0].value[0] = (s_parsed_value){.ptr = height, .size = 4, .offset = 0, .length = 4};

    expect_value(__wrap_add_to_field_table, type, PARAM_TYPE_DATETIME);
    expect_string(__wrap_add_to_field_table, key, "Block");
    expect_string(__wrap_add_to_field_table, value, "19000000");
    will_return(__wrap_add_to_field_table, true);

    s_param_datetime param = {0};
    param.type = DT_BLOCKHEIGHT;
    assert_true(format_param_datetime(&param, "Block"));
}

// =============================================================================
// format_param_datetime — iteration / error paths
// =============================================================================

static void test_format_multiple_blockheights_iterates(void **state) {
    (void) state;
    static uint8_t b1[] = {0x00, 0x0A};  // 10
    static uint8_t b2[] = {0x00, 0x14};  // 20
    g_vg[0].size = 2;
    g_vg[0].value[0] = (s_parsed_value){.ptr = b1, .size = 2, .offset = 0, .length = 2};
    g_vg[0].value[1] = (s_parsed_value){.ptr = b2, .size = 2, .offset = 0, .length = 2};

    expect_value(__wrap_add_to_field_table, type, PARAM_TYPE_DATETIME);
    expect_string(__wrap_add_to_field_table, key, "Block");
    expect_string(__wrap_add_to_field_table, value, "10");
    will_return(__wrap_add_to_field_table, true);

    expect_value(__wrap_add_to_field_table, type, PARAM_TYPE_DATETIME);
    expect_string(__wrap_add_to_field_table, key, "Block");
    expect_string(__wrap_add_to_field_table, value, "20");
    will_return(__wrap_add_to_field_table, true);

    s_param_datetime param = {0};
    param.type = DT_BLOCKHEIGHT;
    assert_true(format_param_datetime(&param, "Block"));
}

static void test_format_value_get_failure_returns_false(void **state) {
    (void) state;
    g_vg_ret = false;
    s_param_datetime param = {0};
    param.type = DT_UNIX;
    assert_false(format_param_datetime(&param, "Date"));
}

static void test_format_add_to_field_table_failure_propagates(void **state) {
    (void) state;
    static uint8_t b1[] = {0x00, 0x01};
    static uint8_t b2[] = {0x00, 0x02};
    g_vg[0].size = 2;
    g_vg[0].value[0] = (s_parsed_value){.ptr = b1, .size = 2, .offset = 0, .length = 2};
    g_vg[0].value[1] = (s_parsed_value){.ptr = b2, .size = 2, .offset = 0, .length = 2};

    expect_value(__wrap_add_to_field_table, type, PARAM_TYPE_DATETIME);
    expect_string(__wrap_add_to_field_table, key, "Block");
    expect_string(__wrap_add_to_field_table, value, "1");
    will_return(__wrap_add_to_field_table, true);

    expect_value(__wrap_add_to_field_table, type, PARAM_TYPE_DATETIME);
    expect_string(__wrap_add_to_field_table, key, "Block");
    expect_string(__wrap_add_to_field_table, value, "2");
    will_return(__wrap_add_to_field_table, false);

    s_param_datetime param = {0};
    param.type = DT_BLOCKHEIGHT;
    assert_false(format_param_datetime(&param, "Block"));
}

// =============================================================================
// handle_param_datetime_struct (TLV)
// =============================================================================

static bool run_tlv(const uint8_t *bytes, size_t size, s_param_datetime *param) {
    buffer_t buf = {.ptr = (uint8_t *) bytes, .size = size, .offset = 0};
    s_param_datetime_context ctx = {.param = param};
    return handle_param_datetime_struct(&buf, &ctx);
}

static void test_tlv_happy_path_unix(void **state) {
    (void) state;
    // VERSION(0) len 1 [1], VALUE(1) len 0, TYPE(2) len 1 [DT_UNIX]
    const uint8_t bytes[] = {
        0x00,
        0x01,
        0x01,  // VERSION = 1
        0x01,
        0x00,  // VALUE empty
        0x02,
        0x01,
        DT_UNIX,  // TYPE = UNIX
    };
    s_param_datetime param = {0};
    assert_true(run_tlv(bytes, sizeof(bytes), &param));
    assert_int_equal(param.version, 1);
    assert_int_equal(param.type, DT_UNIX);
}

static void test_tlv_happy_path_blockheight(void **state) {
    (void) state;
    const uint8_t bytes[] = {
        0x00,
        0x01,
        0x01,
        0x01,
        0x00,
        0x02,
        0x01,
        DT_BLOCKHEIGHT,
    };
    s_param_datetime param = {0};
    assert_true(run_tlv(bytes, sizeof(bytes), &param));
    assert_int_equal(param.type, DT_BLOCKHEIGHT);
}

static void test_tlv_invalid_type_rejected(void **state) {
    (void) state;
    // TYPE = 0x99 — not in the {DT_UNIX, DT_BLOCKHEIGHT} switch.
    const uint8_t bytes[] = {
        0x00,
        0x01,
        0x01,
        0x01,
        0x00,
        0x02,
        0x01,
        0x99,
    };
    s_param_datetime param = {0};
    assert_false(run_tlv(bytes, sizeof(bytes), &param));
}

static void test_tlv_duplicate_type_rejected(void **state) {
    (void) state;
    // ENFORCE_UNIQUE_TAG: sending TYPE twice must fail.
    const uint8_t bytes[] = {
        0x00,
        0x01,
        0x01,
        0x01,
        0x00,
        0x02,
        0x01,
        DT_UNIX,
        0x02,
        0x01,
        DT_BLOCKHEIGHT,
    };
    s_param_datetime param = {0};
    assert_false(run_tlv(bytes, sizeof(bytes), &param));
}

// =============================================================================
// Runner
// =============================================================================

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup(test_format_unix_timestamp_rendered_as_utc, reset),
        cmocka_unit_test_setup(test_format_unix_maxint_renders_unlimited, reset),
        cmocka_unit_test_setup(test_format_blockheight_rendered_decimal, reset),
        cmocka_unit_test_setup(test_format_multiple_blockheights_iterates, reset),
        cmocka_unit_test_setup(test_format_value_get_failure_returns_false, reset),
        cmocka_unit_test_setup(test_format_add_to_field_table_failure_propagates, reset),
        cmocka_unit_test_setup(test_tlv_happy_path_unix, reset),
        cmocka_unit_test_setup(test_tlv_happy_path_blockheight, reset),
        cmocka_unit_test_setup(test_tlv_invalid_type_rejected, reset),
        cmocka_unit_test_setup(test_tlv_duplicate_type_rejected, reset),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
