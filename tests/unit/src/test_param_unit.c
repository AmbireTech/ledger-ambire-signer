/**
 * @file test_param_unit.c
 * @brief Unit tests for the UNIT parameter in
 *        src/features/generic_tx_parser/gtp_param_unit.c.
 *
 * UNIT renders a numeric value with a unit suffix, e.g. "1000 USDC" or
 * "10.00 USDC", after rescaling the input by param->decimals. The
 * formatter has three guards beyond the usual value-collection iteration:
 *   - uint256_to_decimal must succeed (caps at INT256_LENGTH input),
 *   - adjustDecimals must succeed (caps at the destination buffer size),
 *   - param->base must be non-empty — an empty unit suffix is treated
 *     as a malformed parameter rather than rendered with no suffix.
 *
 * The TLV side has an additional handler per tag compared to amount /
 * duration: TAG_BASE copies a NUL-terminated string (rejecting payloads
 * >= 11 bytes so the trailing NUL always fits) and TAG_PREFIX validates
 * the payload size even though the field is currently unused.
 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

#include "gtp_param_unit.h"
#include "gtp_parsed_value.h"
#include "gtp_value.h"
#include "gtp_field.h"
#include "shared_context.h"

// =============================================================================
// Globals
// =============================================================================

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
// format_param_unit — happy paths
// =============================================================================

static void test_format_no_decimals(void **state) {
    (void) state;
    // 1000 decimal = 0x03E8
    static const uint8_t v[] = {0x03, 0xE8};
    set_single_value(v, sizeof(v));

    expect_value(__wrap_add_to_field_table, type, PARAM_TYPE_UNIT);
    expect_string(__wrap_add_to_field_table, key, "Stake");
    expect_string(__wrap_add_to_field_table, value, "1000 USDC");
    will_return(__wrap_add_to_field_table, true);

    s_param_unit param = {0};
    strlcpy(param.base, "USDC", sizeof(param.base));
    param.decimals = 0;
    assert_true(format_param_unit(&param, "Stake"));
}

static void test_format_with_decimals(void **state) {
    (void) state;
    // 1000 with decimals=2 → "10" (trailing fractional zeros are trimmed)
    static const uint8_t v[] = {0x03, 0xE8};
    set_single_value(v, sizeof(v));

    expect_value(__wrap_add_to_field_table, type, PARAM_TYPE_UNIT);
    expect_string(__wrap_add_to_field_table, key, "Stake");
    expect_string(__wrap_add_to_field_table, value, "10 USDC");
    will_return(__wrap_add_to_field_table, true);

    s_param_unit param = {0};
    strlcpy(param.base, "USDC", sizeof(param.base));
    param.decimals = 2;
    assert_true(format_param_unit(&param, "Stake"));
}

static void test_format_fractional_with_decimals(void **state) {
    (void) state;
    // 1234 with decimals=2 → "12.34"
    static const uint8_t v[] = {0x04, 0xD2};
    set_single_value(v, sizeof(v));

    expect_value(__wrap_add_to_field_table, type, PARAM_TYPE_UNIT);
    expect_string(__wrap_add_to_field_table, key, "Stake");
    expect_string(__wrap_add_to_field_table, value, "12.34 USDC");
    will_return(__wrap_add_to_field_table, true);

    s_param_unit param = {0};
    strlcpy(param.base, "USDC", sizeof(param.base));
    param.decimals = 2;
    assert_true(format_param_unit(&param, "Stake"));
}

static void test_format_iterates_multiple_values(void **state) {
    (void) state;
    static const uint8_t a[] = {0x01};
    static const uint8_t b[] = {0x02};
    g_vg[0].size = 2;
    g_vg[0].value[0] = (s_parsed_value){.ptr = a, .size = 1, .offset = 0, .length = 1};
    g_vg[0].value[1] = (s_parsed_value){.ptr = b, .size = 1, .offset = 0, .length = 1};

    expect_value(__wrap_add_to_field_table, type, PARAM_TYPE_UNIT);
    expect_string(__wrap_add_to_field_table, key, "Stake");
    expect_string(__wrap_add_to_field_table, value, "1 PT");
    will_return(__wrap_add_to_field_table, true);

    expect_value(__wrap_add_to_field_table, type, PARAM_TYPE_UNIT);
    expect_string(__wrap_add_to_field_table, key, "Stake");
    expect_string(__wrap_add_to_field_table, value, "2 PT");
    will_return(__wrap_add_to_field_table, true);

    s_param_unit param = {0};
    strlcpy(param.base, "PT", sizeof(param.base));
    param.decimals = 0;
    assert_true(format_param_unit(&param, "Stake"));
}

// =============================================================================
// format_param_unit — failure paths
// =============================================================================

static void test_format_value_get_failure_returns_false(void **state) {
    (void) state;
    g_vg_ret = false;
    s_param_unit param = {0};
    strlcpy(param.base, "USDC", sizeof(param.base));
    assert_false(format_param_unit(&param, "Stake"));
}

static void test_format_empty_base_rejected(void **state) {
    (void) state;
    static const uint8_t v[] = {0x01};
    set_single_value(v, sizeof(v));
    // base[0] == '\0' triggers the explicit reject branch BEFORE
    // add_to_field_table — no add_* expectations.

    s_param_unit param = {0};
    // param.base stays all-NUL from the {0} initializer
    assert_false(format_param_unit(&param, "Stake"));
}

static void test_format_add_to_field_table_failure_propagates(void **state) {
    (void) state;
    static const uint8_t a[] = {0x01};
    static const uint8_t b[] = {0x02};
    g_vg[0].size = 2;
    g_vg[0].value[0] = (s_parsed_value){.ptr = a, .size = 1, .offset = 0, .length = 1};
    g_vg[0].value[1] = (s_parsed_value){.ptr = b, .size = 1, .offset = 0, .length = 1};

    expect_value(__wrap_add_to_field_table, type, PARAM_TYPE_UNIT);
    expect_string(__wrap_add_to_field_table, key, "Stake");
    expect_string(__wrap_add_to_field_table, value, "1 PT");
    will_return(__wrap_add_to_field_table, true);

    expect_value(__wrap_add_to_field_table, type, PARAM_TYPE_UNIT);
    expect_string(__wrap_add_to_field_table, key, "Stake");
    expect_string(__wrap_add_to_field_table, value, "2 PT");
    will_return(__wrap_add_to_field_table, false);

    s_param_unit param = {0};
    strlcpy(param.base, "PT", sizeof(param.base));
    param.decimals = 0;
    assert_false(format_param_unit(&param, "Stake"));
}

// =============================================================================
// handle_param_unit_struct (TLV)
// =============================================================================

static bool run_tlv(const uint8_t *bytes, size_t size, s_param_unit *param) {
    buffer_t buf = {.ptr = (uint8_t *) bytes, .size = size, .offset = 0};
    s_param_unit_context ctx = {.param = param};
    return handle_param_unit_struct(&buf, &ctx);
}

static void test_tlv_happy_path(void **state) {
    (void) state;
    // VERSION=1, VALUE empty, BASE="USDC", DECIMALS=6, PREFIX=true
    const uint8_t bytes[] = {
        0x00,
        0x01,
        0x01,
        0x01,
        0x00,
        0x02,
        0x04,
        'U',
        'S',
        'D',
        'C',
        0x03,
        0x01,
        0x06,
        0x04,
        0x01,
        0x01,
    };
    s_param_unit param = {0};
    assert_true(run_tlv(bytes, sizeof(bytes), &param));
    assert_int_equal(param.version, 1);
    assert_string_equal(param.base, "USDC");
    assert_int_equal(param.decimals, 6);
}

static void test_tlv_base_too_long_rejected(void **state) {
    (void) state;
    // BASE_STR_SIZE == 11 → handle_base rejects payloads >= 11 (need
    // room for the trailing NUL). Send an 11-byte payload.
    const uint8_t bytes[] = {
        0x00, 0x01, 0x01, 0x01, 0x00, 0x02, 0x0B, 'A',  'B',  'C',  'D',
        'E',  'F',  'G',  'H',  'I',  'J',  'K',  0x03, 0x01, 0x00,
    };
    s_param_unit param = {0};
    assert_false(run_tlv(bytes, sizeof(bytes), &param));
}

static void test_tlv_prefix_wrong_size_rejected(void **state) {
    (void) state;
    // PREFIX must be exactly sizeof(bool) bytes — usually 1.
    const uint8_t bytes[] = {
        0x00,
        0x01,
        0x01,
        0x01,
        0x00,
        0x02,
        0x02,
        'B',
        'B',
        0x03,
        0x01,
        0x00,
        0x04,
        0x02,
        0x00,
        0x01,
    };
    s_param_unit param = {0};
    assert_false(run_tlv(bytes, sizeof(bytes), &param));
}

static void test_tlv_duplicate_base_rejected(void **state) {
    (void) state;
    const uint8_t bytes[] = {
        0x00,
        0x01,
        0x01,
        0x01,
        0x00,
        0x02,
        0x02,
        'A',
        'B',
        0x02,
        0x02,
        'C',
        'D',  // duplicate BASE
        0x03,
        0x01,
        0x00,
    };
    s_param_unit param = {0};
    assert_false(run_tlv(bytes, sizeof(bytes), &param));
}

// =============================================================================
// Runner
// =============================================================================

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup(test_format_no_decimals, reset),
        cmocka_unit_test_setup(test_format_with_decimals, reset),
        cmocka_unit_test_setup(test_format_fractional_with_decimals, reset),
        cmocka_unit_test_setup(test_format_iterates_multiple_values, reset),
        cmocka_unit_test_setup(test_format_value_get_failure_returns_false, reset),
        cmocka_unit_test_setup(test_format_empty_base_rejected, reset),
        cmocka_unit_test_setup(test_format_add_to_field_table_failure_propagates, reset),
        cmocka_unit_test_setup(test_tlv_happy_path, reset),
        cmocka_unit_test_setup(test_tlv_base_too_long_rejected, reset),
        cmocka_unit_test_setup(test_tlv_prefix_wrong_size_rejected, reset),
        cmocka_unit_test_setup(test_tlv_duplicate_base_rejected, reset),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
