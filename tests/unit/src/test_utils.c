/**
 * @file test_utils.c
 * @brief Unit tests for the app-level string / buffer helpers in src/utils.c.
 *
 * utils.c is tiny but every helper is on a path that touches user-visible
 * data:
 *   - format_signed_int_be is what the GCS / EIP-712 layers call to render
 *     int8/16/.../256 fields. The signed branch picks between int64,
 *     uint128, and uint256 formatters based on type_size, so each width
 *     gets a dedicated case.
 *   - str_cpy_explicit_trunc decides whether a string is shown intact or
 *     truncated with "..." — the truncation marker placement is what makes
 *     the helper non-trivial.
 *   - buf_shrink_expand is used to right-align BE values into fixed-width
 *     slots; getting the zero-pad direction wrong silently corrupts amounts.
 *   - reverseString underpins every tostringNNN call.
 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "utils.h"

// =============================================================================
// reverseString
// =============================================================================

static void test_reverseString_even_length(void **state) {
    (void) state;
    char s[] = "abcdef";
    reverseString(s, 6);
    assert_string_equal(s, "fedcba");
}

static void test_reverseString_odd_length(void **state) {
    (void) state;
    char s[] = "12345";
    reverseString(s, 5);
    assert_string_equal(s, "54321");
}

static void test_reverseString_partial_length(void **state) {
    (void) state;
    // length argument is what gets reversed; the rest of the string is left alone.
    char s[] = "ABCDxyz";
    reverseString(s, 4);
    assert_string_equal(s, "DCBAxyz");
}

static void test_reverseString_single_char(void **state) {
    (void) state;
    char s[] = "Q";
    reverseString(s, 1);
    assert_string_equal(s, "Q");
}

// =============================================================================
// buf_shrink_expand
// =============================================================================

static void test_buf_shrink_expand_expand_left_zero_pads(void **state) {
    (void) state;
    const uint8_t src[] = {0xAA, 0xBB, 0xCC};
    uint8_t dst[8];
    memset(dst, 0xFF, sizeof(dst));
    buf_shrink_expand(src, sizeof(src), dst, sizeof(dst));
    const uint8_t expected[] = {0, 0, 0, 0, 0, 0xAA, 0xBB, 0xCC};
    assert_memory_equal(dst, expected, sizeof(dst));
}

static void test_buf_shrink_expand_shrink_drops_msb(void **state) {
    (void) state;
    const uint8_t src[] = {0x11, 0x22, 0x33, 0xAA, 0xBB, 0xCC};
    uint8_t dst[3];
    buf_shrink_expand(src, sizeof(src), dst, sizeof(dst));
    const uint8_t expected[] = {0xAA, 0xBB, 0xCC};
    assert_memory_equal(dst, expected, sizeof(dst));
}

static void test_buf_shrink_expand_equal_size(void **state) {
    (void) state;
    const uint8_t src[] = {0x01, 0x02, 0x03, 0x04};
    uint8_t dst[4];
    memset(dst, 0xFF, sizeof(dst));
    buf_shrink_expand(src, sizeof(src), dst, sizeof(dst));
    assert_memory_equal(dst, src, sizeof(dst));
}

// =============================================================================
// str_cpy_explicit_trunc
// =============================================================================

static void test_str_cpy_trunc_fits(void **state) {
    (void) state;
    char dst[16] = {0};
    str_cpy_explicit_trunc("hello", 5, dst, sizeof(dst));
    assert_string_equal(dst, "hello");
}

static void test_str_cpy_trunc_appends_ellipsis(void **state) {
    (void) state;
    // "Hello, world" (12 bytes) won't fit in a 9-byte buffer (8 chars + NUL):
    // we expect 5 source chars + "...\0" = 9 bytes total.
    char dst[9];
    memset(dst, 'X', sizeof(dst));
    str_cpy_explicit_trunc("Hello, world", 12, dst, sizeof(dst));
    assert_string_equal(dst, "Hello...");
}

static void test_str_cpy_trunc_exact_marker_size_empties(void **state) {
    (void) state;
    // dst_size == sizeof("...") (== 4 bytes) cannot represent any truncation
    // because there'd be no room for even a single source character before
    // "...", so the helper just NUL-terminates.
    char dst[4];
    memset(dst, 'X', sizeof(dst));
    str_cpy_explicit_trunc("Hello", 5, dst, sizeof(dst));
    assert_int_equal(dst[0], '\0');
}

static void test_str_cpy_trunc_zero_dst_is_noop(void **state) {
    (void) state;
    char canary = 'Z';
    str_cpy_explicit_trunc("Hello", 5, &canary, 0);
    assert_int_equal(canary, 'Z');
}

static void test_str_cpy_trunc_exact_fit_terminates(void **state) {
    (void) state;
    // dst is exactly src + NUL (5 + 1 = 6 bytes). Should fit without "...".
    char dst[6];
    memset(dst, 'X', sizeof(dst));
    str_cpy_explicit_trunc("Hello", 5, dst, sizeof(dst));
    assert_string_equal(dst, "Hello");
}

// =============================================================================
// format_signed_int_be
// =============================================================================
//
// Branch matrix:
//                          length=0  length>type   MSB clear   MSB set
//   any                    false     false         unsigned    signed
// And the signed branch dispatches on type_size:
//   type_size <= 8         → int64 (format_i64)
//   type_size <= 16        → int128 (tostring128_signed)
//   type_size <= 32        → int256 (tostring256_signed)
//   type_size  > 32        → false

static void test_format_signed_int_be_length_zero_rejected(void **state) {
    (void) state;
    uint8_t data[] = {0x42};
    char out[40];
    assert_false(format_signed_int_be(data, 0, 32, out, sizeof(out)));
}

static void test_format_signed_int_be_length_exceeds_type_rejected(void **state) {
    (void) state;
    uint8_t data[] = {0, 0, 0, 0, 0, 0, 0, 0, 0xFF};  // 9 bytes
    char out[40];
    assert_false(format_signed_int_be(data, 9, 8, out, sizeof(out)));
}

static void test_format_signed_int_be_short_value_treated_unsigned(void **state) {
    (void) state;
    // length < type_size → always unsigned, regardless of MSB
    uint8_t data[] = {0xFF};
    char out[40] = {0};
    assert_true(format_signed_int_be(data, 1, 4, out, sizeof(out)));
    assert_string_equal(out, "255");
}

static void test_format_signed_int_be_full_width_msb_clear_unsigned(void **state) {
    (void) state;
    // int8 = 0x7F → +127
    uint8_t data[] = {0x7F};
    char out[40] = {0};
    assert_true(format_signed_int_be(data, 1, 1, out, sizeof(out)));
    assert_string_equal(out, "127");
}

static void test_format_signed_int_be_int8_negative(void **state) {
    (void) state;
    // int8 = 0xFF → -1
    uint8_t data[] = {0xFF};
    char out[40] = {0};
    assert_true(format_signed_int_be(data, 1, 1, out, sizeof(out)));
    assert_string_equal(out, "-1");
}

static void test_format_signed_int_be_int64_negative(void **state) {
    (void) state;
    // int64 = 0xFFFFFFFFFFFFFFFF → -1
    uint8_t data[8];
    memset(data, 0xFF, sizeof(data));
    char out[40] = {0};
    assert_true(format_signed_int_be(data, 8, 8, out, sizeof(out)));
    assert_string_equal(out, "-1");
}

static void test_format_signed_int_be_int64_min(void **state) {
    (void) state;
    // int64 min = 0x80...00
    uint8_t data[8] = {0x80, 0, 0, 0, 0, 0, 0, 0};
    char out[40] = {0};
    assert_true(format_signed_int_be(data, 8, 8, out, sizeof(out)));
    assert_string_equal(out, "-9223372036854775808");
}

static void test_format_signed_int_be_int128_negative(void **state) {
    (void) state;
    // int128 = all 0xFF → -1
    uint8_t data[16];
    memset(data, 0xFF, sizeof(data));
    char out[60] = {0};
    assert_true(format_signed_int_be(data, 16, 16, out, sizeof(out)));
    assert_string_equal(out, "-1");
}

static void test_format_signed_int_be_int256_negative(void **state) {
    (void) state;
    // int256 = all 0xFF → -1
    uint8_t data[32];
    memset(data, 0xFF, sizeof(data));
    char out[100] = {0};
    assert_true(format_signed_int_be(data, 32, 32, out, sizeof(out)));
    assert_string_equal(out, "-1");
}

static void test_format_signed_int_be_oversize_type_rejected(void **state) {
    (void) state;
    // type_size > 32 falls through every branch and returns false.
    uint8_t data[40];
    memset(data, 0xFF, sizeof(data));
    char out[100] = {0};
    assert_false(format_signed_int_be(data, 33, 33, out, sizeof(out)));
}

// =============================================================================
// Runner
// =============================================================================

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_reverseString_even_length),
        cmocka_unit_test(test_reverseString_odd_length),
        cmocka_unit_test(test_reverseString_partial_length),
        cmocka_unit_test(test_reverseString_single_char),
        cmocka_unit_test(test_buf_shrink_expand_expand_left_zero_pads),
        cmocka_unit_test(test_buf_shrink_expand_shrink_drops_msb),
        cmocka_unit_test(test_buf_shrink_expand_equal_size),
        cmocka_unit_test(test_str_cpy_trunc_fits),
        cmocka_unit_test(test_str_cpy_trunc_appends_ellipsis),
        cmocka_unit_test(test_str_cpy_trunc_exact_marker_size_empties),
        cmocka_unit_test(test_str_cpy_trunc_zero_dst_is_noop),
        cmocka_unit_test(test_str_cpy_trunc_exact_fit_terminates),
        cmocka_unit_test(test_format_signed_int_be_length_zero_rejected),
        cmocka_unit_test(test_format_signed_int_be_length_exceeds_type_rejected),
        cmocka_unit_test(test_format_signed_int_be_short_value_treated_unsigned),
        cmocka_unit_test(test_format_signed_int_be_full_width_msb_clear_unsigned),
        cmocka_unit_test(test_format_signed_int_be_int8_negative),
        cmocka_unit_test(test_format_signed_int_be_int64_negative),
        cmocka_unit_test(test_format_signed_int_be_int64_min),
        cmocka_unit_test(test_format_signed_int_be_int128_negative),
        cmocka_unit_test(test_format_signed_int_be_int256_negative),
        cmocka_unit_test(test_format_signed_int_be_oversize_type_rejected),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
