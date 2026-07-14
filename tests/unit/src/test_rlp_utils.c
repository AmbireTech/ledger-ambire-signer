/**
 * @file test_rlp_utils.c
 * @brief Unit tests for RLP length-prefix decoding helpers.
 *
 * Covers `rlp_can_decode()` and `rlp_decode_length()` from
 * `src/features/sign_tx/rlp_utils.c`. Both helpers parse the leading byte(s)
 * of an RLP-encoded field and need to behave safely on truncated input — the
 * fix in commit ad3fb1fc made `rlp_decode_length()` self-bounded after a
 * security review.
 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "rlp_utils.h"

// =============================================================================
// rlp_can_decode — bufferLength sanity for the long-string/long-list cases
// =============================================================================
//
// rlp_can_decode() dereferences *buffer unconditionally, so its contract
// requires bufferLength >= 1. We respect that here.

static void test_can_decode_single_byte(void **state) {
    (void) state;
    uint8_t buf[] = {0x00};
    bool valid = false;
    assert_true(rlp_can_decode(buf, sizeof(buf), &valid));
    assert_true(valid);

    buf[0] = 0x7f;
    valid = false;
    assert_true(rlp_can_decode(buf, sizeof(buf), &valid));
    assert_true(valid);
}

static void test_can_decode_short_string(void **state) {
    (void) state;
    uint8_t buf[] = {0x80};
    bool valid = false;
    assert_true(rlp_can_decode(buf, sizeof(buf), &valid));
    assert_true(valid);

    buf[0] = 0xb7;
    valid = false;
    assert_true(rlp_can_decode(buf, sizeof(buf), &valid));
    assert_true(valid);
}

static void test_can_decode_short_list(void **state) {
    (void) state;
    uint8_t buf[] = {0xc0};
    bool valid = false;
    assert_true(rlp_can_decode(buf, sizeof(buf), &valid));
    assert_true(valid);

    buf[0] = 0xf7;
    valid = false;
    assert_true(rlp_can_decode(buf, sizeof(buf), &valid));
    assert_true(valid);
}

static void test_can_decode_long_string_truncated_returns_false(void **state) {
    (void) state;
    // 0xb8 announces 1 byte of length to follow → need 2 bytes total.
    uint8_t buf[] = {0xb8};
    bool valid = true;
    assert_false(rlp_can_decode(buf, sizeof(buf), &valid));

    // 0xbb announces 4 bytes of length → need 5 bytes total.
    uint8_t buf2[] = {0xbb, 0x00, 0x00, 0x00};
    valid = true;
    assert_false(rlp_can_decode(buf2, sizeof(buf2), &valid));
}

static void test_can_decode_long_string_complete_returns_valid(void **state) {
    (void) state;
    uint8_t buf[] = {0xb8, 0x10};  // length = 16
    bool valid = false;
    assert_true(rlp_can_decode(buf, sizeof(buf), &valid));
    assert_true(valid);

    uint8_t buf2[] = {0xbb, 0x01, 0x02, 0x03, 0x04};
    valid = false;
    assert_true(rlp_can_decode(buf2, sizeof(buf2), &valid));
    assert_true(valid);
}

static void test_can_decode_long_string_over_4_bytes_flags_invalid(void **state) {
    (void) state;
    // 0xbc would announce 5 bytes of length — over the app's 32-bit limit.
    uint8_t buf[] = {0xbc, 0, 0, 0, 0, 0};
    bool valid = true;
    assert_true(rlp_can_decode(buf, sizeof(buf), &valid));
    assert_false(valid);

    uint8_t buf2[] = {0xbf, 0, 0, 0, 0, 0, 0, 0, 0};
    valid = true;
    assert_true(rlp_can_decode(buf2, sizeof(buf2), &valid));
    assert_false(valid);
}

static void test_can_decode_long_list_truncated_returns_false(void **state) {
    (void) state;
    uint8_t buf[] = {0xf8};
    bool valid = true;
    assert_false(rlp_can_decode(buf, sizeof(buf), &valid));

    uint8_t buf2[] = {0xfb, 0x00, 0x00, 0x00};
    valid = true;
    assert_false(rlp_can_decode(buf2, sizeof(buf2), &valid));
}

static void test_can_decode_long_list_over_4_bytes_flags_invalid(void **state) {
    (void) state;
    uint8_t buf[] = {0xfc, 0, 0, 0, 0, 0};
    bool valid = true;
    assert_true(rlp_can_decode(buf, sizeof(buf), &valid));
    assert_false(valid);

    uint8_t buf2[] = {0xff, 0, 0, 0, 0, 0, 0, 0, 0};
    valid = true;
    assert_true(rlp_can_decode(buf2, sizeof(buf2), &valid));
    assert_false(valid);
}

// =============================================================================
// rlp_decode_length — happy paths
// =============================================================================

static void test_decode_single_byte(void **state) {
    (void) state;
    uint8_t buf[] = {0x00};
    uint32_t field_length = 0xDEAD;
    uint32_t offset = 0xDEAD;
    bool list = true;

    assert_true(rlp_decode_length(buf, sizeof(buf), &field_length, &offset, &list));
    assert_int_equal(offset, 0);
    assert_int_equal(field_length, 1);
    assert_false(list);

    buf[0] = 0x7f;
    assert_true(rlp_decode_length(buf, sizeof(buf), &field_length, &offset, &list));
    assert_int_equal(offset, 0);
    assert_int_equal(field_length, 1);
    assert_false(list);
}

static void test_decode_short_string(void **state) {
    (void) state;
    // 0x80 → empty string, length 0
    uint8_t buf[] = {0x80};
    uint32_t field_length = 0xDEAD;
    uint32_t offset = 0xDEAD;
    bool list = true;
    assert_true(rlp_decode_length(buf, sizeof(buf), &field_length, &offset, &list));
    assert_int_equal(offset, 1);
    assert_int_equal(field_length, 0);
    assert_false(list);

    // 0xb7 → 55-byte string
    buf[0] = 0xb7;
    assert_true(rlp_decode_length(buf, sizeof(buf), &field_length, &offset, &list));
    assert_int_equal(offset, 1);
    assert_int_equal(field_length, 0x37);
    assert_false(list);
}

static void test_decode_long_string_1_byte_length(void **state) {
    (void) state;
    uint8_t buf[] = {0xb8, 0xAB};
    uint32_t field_length = 0;
    uint32_t offset = 0;
    bool list = true;

    assert_true(rlp_decode_length(buf, sizeof(buf), &field_length, &offset, &list));
    assert_int_equal(offset, 2);
    assert_int_equal(field_length, 0xAB);
    assert_false(list);
}

static void test_decode_long_string_2_byte_length(void **state) {
    (void) state;
    uint8_t buf[] = {0xb9, 0x12, 0x34};
    uint32_t field_length = 0;
    uint32_t offset = 0;
    bool list = true;

    assert_true(rlp_decode_length(buf, sizeof(buf), &field_length, &offset, &list));
    assert_int_equal(offset, 3);
    assert_int_equal(field_length, 0x1234);
    assert_false(list);
}

static void test_decode_long_string_3_byte_length(void **state) {
    (void) state;
    uint8_t buf[] = {0xba, 0x12, 0x34, 0x56};
    uint32_t field_length = 0;
    uint32_t offset = 0;
    bool list = true;

    assert_true(rlp_decode_length(buf, sizeof(buf), &field_length, &offset, &list));
    assert_int_equal(offset, 4);
    assert_int_equal(field_length, 0x123456);
    assert_false(list);
}

static void test_decode_long_string_4_byte_length(void **state) {
    (void) state;
    // Use the high bit to verify uint32 promotion (no sign extension bug).
    uint8_t buf[] = {0xbb, 0x80, 0x00, 0x00, 0x01};
    uint32_t field_length = 0;
    uint32_t offset = 0;
    bool list = true;

    assert_true(rlp_decode_length(buf, sizeof(buf), &field_length, &offset, &list));
    assert_int_equal(offset, 5);
    assert_int_equal(field_length, 0x80000001u);
    assert_false(list);
}

static void test_decode_short_list(void **state) {
    (void) state;
    uint8_t buf[] = {0xc0};
    uint32_t field_length = 0xDEAD;
    uint32_t offset = 0xDEAD;
    bool list = false;
    assert_true(rlp_decode_length(buf, sizeof(buf), &field_length, &offset, &list));
    assert_int_equal(offset, 1);
    assert_int_equal(field_length, 0);
    assert_true(list);

    buf[0] = 0xf7;
    assert_true(rlp_decode_length(buf, sizeof(buf), &field_length, &offset, &list));
    assert_int_equal(offset, 1);
    assert_int_equal(field_length, 0x37);
    assert_true(list);
}

static void test_decode_long_list_1_byte_length(void **state) {
    (void) state;
    uint8_t buf[] = {0xf8, 0xCD};
    uint32_t field_length = 0;
    uint32_t offset = 0;
    bool list = false;

    assert_true(rlp_decode_length(buf, sizeof(buf), &field_length, &offset, &list));
    assert_int_equal(offset, 2);
    assert_int_equal(field_length, 0xCD);
    assert_true(list);
}

static void test_decode_long_list_4_byte_length(void **state) {
    (void) state;
    uint8_t buf[] = {0xfb, 0xFF, 0xFF, 0xFF, 0xFE};
    uint32_t field_length = 0;
    uint32_t offset = 0;
    bool list = false;

    assert_true(rlp_decode_length(buf, sizeof(buf), &field_length, &offset, &list));
    assert_int_equal(offset, 5);
    assert_int_equal(field_length, 0xFFFFFFFEu);
    assert_true(list);
}

// =============================================================================
// rlp_decode_length — bound checks (regression for fix ad3fb1fc)
// =============================================================================

static void test_decode_empty_buffer_rejected(void **state) {
    (void) state;
    // The fix's most important invariant: never deref buffer when bufferLength == 0.
    uint8_t buf[1] = {0};
    uint32_t field_length = 0;
    uint32_t offset = 0;
    bool list = false;

    assert_false(rlp_decode_length(buf, 0, &field_length, &offset, &list));
}

static void test_decode_long_string_truncated_rejected(void **state) {
    (void) state;
    uint32_t field_length = 0;
    uint32_t offset = 0;
    bool list = false;

    // 0xb8 needs 2 bytes, only 1 provided
    uint8_t buf1[] = {0xb8};
    assert_false(rlp_decode_length(buf1, sizeof(buf1), &field_length, &offset, &list));

    // 0xb9 needs 3 bytes, only 2 provided
    uint8_t buf2[] = {0xb9, 0x00};
    assert_false(rlp_decode_length(buf2, sizeof(buf2), &field_length, &offset, &list));

    // 0xba needs 4 bytes, only 3 provided
    uint8_t buf3[] = {0xba, 0x00, 0x00};
    assert_false(rlp_decode_length(buf3, sizeof(buf3), &field_length, &offset, &list));

    // 0xbb needs 5 bytes, only 4 provided
    uint8_t buf4[] = {0xbb, 0x00, 0x00, 0x00};
    assert_false(rlp_decode_length(buf4, sizeof(buf4), &field_length, &offset, &list));
}

static void test_decode_long_list_truncated_rejected(void **state) {
    (void) state;
    uint32_t field_length = 0;
    uint32_t offset = 0;
    bool list = false;

    uint8_t buf1[] = {0xf8};
    assert_false(rlp_decode_length(buf1, sizeof(buf1), &field_length, &offset, &list));

    uint8_t buf2[] = {0xf9, 0x00};
    assert_false(rlp_decode_length(buf2, sizeof(buf2), &field_length, &offset, &list));

    uint8_t buf3[] = {0xfa, 0x00, 0x00};
    assert_false(rlp_decode_length(buf3, sizeof(buf3), &field_length, &offset, &list));

    uint8_t buf4[] = {0xfb, 0x00, 0x00, 0x00};
    assert_false(rlp_decode_length(buf4, sizeof(buf4), &field_length, &offset, &list));
}

static void test_decode_invalid_long_string_prefix_rejected(void **state) {
    (void) state;
    // 0xbc..0xbf would require > 4 length bytes — the app caps at 32 bits.
    uint32_t field_length = 0;
    uint32_t offset = 0;
    bool list = false;
    for (uint8_t prefix = 0xbc; prefix <= 0xbf; ++prefix) {
        uint8_t buf[16] = {0};
        buf[0] = prefix;
        assert_false(rlp_decode_length(buf, sizeof(buf), &field_length, &offset, &list));
    }
}

static void test_decode_invalid_long_list_prefix_rejected(void **state) {
    (void) state;
    uint32_t field_length = 0;
    uint32_t offset = 0;
    bool list = false;
    for (uint16_t prefix = 0xfc; prefix <= 0xff; ++prefix) {
        uint8_t buf[16] = {0};
        buf[0] = (uint8_t) prefix;
        assert_false(rlp_decode_length(buf, sizeof(buf), &field_length, &offset, &list));
    }
}

// =============================================================================
// Test runner
// =============================================================================

int main(void) {
    const struct CMUnitTest tests[] = {
        // rlp_can_decode
        cmocka_unit_test(test_can_decode_single_byte),
        cmocka_unit_test(test_can_decode_short_string),
        cmocka_unit_test(test_can_decode_short_list),
        cmocka_unit_test(test_can_decode_long_string_truncated_returns_false),
        cmocka_unit_test(test_can_decode_long_string_complete_returns_valid),
        cmocka_unit_test(test_can_decode_long_string_over_4_bytes_flags_invalid),
        cmocka_unit_test(test_can_decode_long_list_truncated_returns_false),
        cmocka_unit_test(test_can_decode_long_list_over_4_bytes_flags_invalid),
        // rlp_decode_length — happy paths
        cmocka_unit_test(test_decode_single_byte),
        cmocka_unit_test(test_decode_short_string),
        cmocka_unit_test(test_decode_long_string_1_byte_length),
        cmocka_unit_test(test_decode_long_string_2_byte_length),
        cmocka_unit_test(test_decode_long_string_3_byte_length),
        cmocka_unit_test(test_decode_long_string_4_byte_length),
        cmocka_unit_test(test_decode_short_list),
        cmocka_unit_test(test_decode_long_list_1_byte_length),
        cmocka_unit_test(test_decode_long_list_4_byte_length),
        // rlp_decode_length — bound checks
        cmocka_unit_test(test_decode_empty_buffer_rejected),
        cmocka_unit_test(test_decode_long_string_truncated_rejected),
        cmocka_unit_test(test_decode_long_list_truncated_rejected),
        cmocka_unit_test(test_decode_invalid_long_string_prefix_rejected),
        cmocka_unit_test(test_decode_invalid_long_list_prefix_rejected),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
