/**
 * @file test_param_duration.c
 * @brief Unit tests for the DURATION parameter in
 *        src/features/generic_tx_parser/gtp_param_duration.c.
 *
 * DURATION converts an unsigned-seconds value into a "1d02h03m04s" style
 * string, with each component dropped when its count is zero AND at least
 * one larger component is already in the buffer. The seconds component is
 * the exception: if the value is exactly zero, the buffer is empty, so
 * the formatter writes "00s" instead of returning an empty string.
 *
 * The non-obvious behaviors covered:
 *   - 0 seconds → "00s" (off==0 fallback so the field is never empty),
 *   - 60 seconds → "01m" (seconds==0 silently skipped because a larger
 *     unit was already written),
 *   - 1d / 1h / 1m on their own keep that single component without
 *     trailing zeros,
 *   - composite 1d02h03m04s exercises all four components in order.
 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

#include "gtp_param_duration.h"
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

// Helper: build a single-value collection from a BE byte buffer.
static void set_single_value(const uint8_t *bytes, size_t len) {
    g_vg[0].size = 1;
    g_vg[0].value[0] = (s_parsed_value){.ptr = bytes,
                                        .size = (uint16_t) len,
                                        .offset = 0,
                                        .length = (uint16_t) len};
}

// =============================================================================
// format_param_duration — each component on its own
// =============================================================================

static void test_format_zero_renders_00s(void **state) {
    (void) state;
    static const uint8_t zero[] = {0x00};
    set_single_value(zero, sizeof(zero));

    expect_value(__wrap_add_to_field_table, type, PARAM_TYPE_DURATION);
    expect_string(__wrap_add_to_field_table, key, "Period");
    expect_string(__wrap_add_to_field_table, value, "00s");
    will_return(__wrap_add_to_field_table, true);

    s_param_duration param = {0};
    assert_true(format_param_duration(&param, "Period"));
}

static void test_format_thirty_seconds(void **state) {
    (void) state;
    static const uint8_t thirty[] = {0x1E};  // 30
    set_single_value(thirty, sizeof(thirty));

    expect_value(__wrap_add_to_field_table, type, PARAM_TYPE_DURATION);
    expect_string(__wrap_add_to_field_table, key, "Period");
    expect_string(__wrap_add_to_field_table, value, "30s");
    will_return(__wrap_add_to_field_table, true);

    s_param_duration param = {0};
    assert_true(format_param_duration(&param, "Period"));
}

static void test_format_one_minute_drops_zero_seconds(void **state) {
    (void) state;
    static const uint8_t sixty[] = {0x3C};  // 60
    set_single_value(sixty, sizeof(sixty));

    expect_value(__wrap_add_to_field_table, type, PARAM_TYPE_DURATION);
    expect_string(__wrap_add_to_field_table, key, "Period");
    expect_string(__wrap_add_to_field_table, value, "01m");
    will_return(__wrap_add_to_field_table, true);

    s_param_duration param = {0};
    assert_true(format_param_duration(&param, "Period"));
}

static void test_format_one_hour(void **state) {
    (void) state;
    // 3600 = 0x0E10
    static const uint8_t hour[] = {0x0E, 0x10};
    set_single_value(hour, sizeof(hour));

    expect_value(__wrap_add_to_field_table, type, PARAM_TYPE_DURATION);
    expect_string(__wrap_add_to_field_table, key, "Period");
    expect_string(__wrap_add_to_field_table, value, "01h");
    will_return(__wrap_add_to_field_table, true);

    s_param_duration param = {0};
    assert_true(format_param_duration(&param, "Period"));
}

static void test_format_one_day(void **state) {
    (void) state;
    // 86400 = 0x015180
    static const uint8_t day[] = {0x01, 0x51, 0x80};
    set_single_value(day, sizeof(day));

    expect_value(__wrap_add_to_field_table, type, PARAM_TYPE_DURATION);
    expect_string(__wrap_add_to_field_table, key, "Period");
    expect_string(__wrap_add_to_field_table, value, "1d");
    will_return(__wrap_add_to_field_table, true);

    s_param_duration param = {0};
    assert_true(format_param_duration(&param, "Period"));
}

// =============================================================================
// format_param_duration — composite value
// =============================================================================

static void test_format_composite_d_h_m_s(void **state) {
    (void) state;
    // 1d 2h 3m 4s = 86400 + 7200 + 180 + 4 = 93784 = 0x016E58
    static const uint8_t v[] = {0x01, 0x6E, 0x58};
    set_single_value(v, sizeof(v));

    expect_value(__wrap_add_to_field_table, type, PARAM_TYPE_DURATION);
    expect_string(__wrap_add_to_field_table, key, "Period");
    expect_string(__wrap_add_to_field_table, value, "1d02h03m04s");
    will_return(__wrap_add_to_field_table, true);

    s_param_duration param = {0};
    assert_true(format_param_duration(&param, "Period"));
}

// =============================================================================
// format_param_duration — error paths
// =============================================================================

static void test_format_value_get_failure_returns_false(void **state) {
    (void) state;
    g_vg_ret = false;
    s_param_duration param = {0};
    assert_false(format_param_duration(&param, "Period"));
}

static void test_format_add_to_field_table_failure_propagates(void **state) {
    (void) state;
    static const uint8_t a[] = {0x1E};  // 30s
    static const uint8_t b[] = {0x3C};  // 60s → "01m"
    g_vg[0].size = 2;
    g_vg[0].value[0] = (s_parsed_value){.ptr = a, .size = 1, .offset = 0, .length = 1};
    g_vg[0].value[1] = (s_parsed_value){.ptr = b, .size = 1, .offset = 0, .length = 1};

    expect_value(__wrap_add_to_field_table, type, PARAM_TYPE_DURATION);
    expect_string(__wrap_add_to_field_table, key, "Period");
    expect_string(__wrap_add_to_field_table, value, "30s");
    will_return(__wrap_add_to_field_table, true);

    expect_value(__wrap_add_to_field_table, type, PARAM_TYPE_DURATION);
    expect_string(__wrap_add_to_field_table, key, "Period");
    expect_string(__wrap_add_to_field_table, value, "01m");
    will_return(__wrap_add_to_field_table, false);

    s_param_duration param = {0};
    assert_false(format_param_duration(&param, "Period"));
}

// =============================================================================
// handle_param_duration_struct (TLV)
// =============================================================================

static bool run_tlv(const uint8_t *bytes, size_t size, s_param_duration *param) {
    buffer_t buf = {.ptr = (uint8_t *) bytes, .size = size, .offset = 0};
    s_param_duration_context ctx = {.param = param};
    return handle_param_duration_struct(&buf, &ctx);
}

static void test_tlv_happy_path(void **state) {
    (void) state;
    const uint8_t bytes[] = {
        0x00,
        0x01,
        0x07,  // VERSION = 7
        0x01,
        0x00,  // VALUE empty (handle_value_struct wrapped)
    };
    s_param_duration param = {0};
    assert_true(run_tlv(bytes, sizeof(bytes), &param));
    assert_int_equal(param.version, 7);
}

static void test_tlv_duplicate_version_rejected(void **state) {
    (void) state;
    const uint8_t bytes[] = {
        0x00,
        0x01,
        0x01,  // VERSION = 1
        0x00,
        0x01,
        0x02,  // VERSION = 2 (duplicate)
        0x01,
        0x00,
    };
    s_param_duration param = {0};
    assert_false(run_tlv(bytes, sizeof(bytes), &param));
}

// =============================================================================
// Runner
// =============================================================================

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup(test_format_zero_renders_00s, reset),
        cmocka_unit_test_setup(test_format_thirty_seconds, reset),
        cmocka_unit_test_setup(test_format_one_minute_drops_zero_seconds, reset),
        cmocka_unit_test_setup(test_format_one_hour, reset),
        cmocka_unit_test_setup(test_format_one_day, reset),
        cmocka_unit_test_setup(test_format_composite_d_h_m_s, reset),
        cmocka_unit_test_setup(test_format_value_get_failure_returns_false, reset),
        cmocka_unit_test_setup(test_format_add_to_field_table_failure_propagates, reset),
        cmocka_unit_test_setup(test_tlv_happy_path, reset),
        cmocka_unit_test_setup(test_tlv_duplicate_version_rejected, reset),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
