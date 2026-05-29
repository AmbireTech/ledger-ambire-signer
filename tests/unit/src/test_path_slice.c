/**
 * @file test_path_slice.c
 * @brief Unit tests for the slice-path TLV parser at
 *        src/features/generic_tx_parser/gtp_path_slice.c.
 *
 * Slice paths cap a dynamic-array path to a [start, end) sub-range. The
 * TLV carries:
 *   - TAG_START (0x01): inclusive start index, 2 bytes minimum,
 *                       marked present via has_start,
 *   - TAG_END   (0x02): exclusive end index, 2 bytes minimum,
 *                       marked present via has_end.
 * Both tags are optional and ENFORCE_UNIQUE_TAG; either end can be
 * omitted to mean "unbounded on that side".
 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

#include "gtp_path_slice.h"

static bool run_tlv(const uint8_t *bytes, size_t size, s_slice_args *args) {
    buffer_t buf = {.ptr = (uint8_t *) bytes, .size = size, .offset = 0};
    s_path_slice_context ctx = {.args = args};
    return handle_slice_struct(&buf, &ctx);
}

static void test_tlv_start_end_populated(void **state) {
    (void) state;
    const uint8_t bytes[] = {
        0x01,
        0x02,
        0x00,
        0x05,  // START = 5
        0x02,
        0x02,
        0x00,
        0x0A,  // END   = 10
    };
    s_slice_args args = {0};
    assert_true(run_tlv(bytes, sizeof(bytes), &args));
    assert_true(args.has_start);
    assert_int_equal(args.start, 5);
    assert_true(args.has_end);
    assert_int_equal(args.end, 10);
}

static void test_tlv_only_start(void **state) {
    (void) state;
    const uint8_t bytes[] = {0x01, 0x02, 0x00, 0x03};
    s_slice_args args = {0};
    assert_true(run_tlv(bytes, sizeof(bytes), &args));
    assert_true(args.has_start);
    assert_int_equal(args.start, 3);
    assert_false(args.has_end);
}

static void test_tlv_only_end(void **state) {
    (void) state;
    const uint8_t bytes[] = {0x02, 0x02, 0x00, 0x07};
    s_slice_args args = {0};
    assert_true(run_tlv(bytes, sizeof(bytes), &args));
    assert_false(args.has_start);
    assert_true(args.has_end);
    assert_int_equal(args.end, 7);
}

static void test_tlv_empty_buffer_accepted(void **state) {
    (void) state;
    s_slice_args args = {0};
    assert_true(run_tlv(NULL, 0, &args));
    assert_false(args.has_start);
    assert_false(args.has_end);
}

static void test_tlv_start_end_read_big_endian(void **state) {
    (void) state;
    const uint8_t bytes[] = {
        0x01,
        0x02,
        0x12,
        0x34,
        0x02,
        0x02,
        0xAB,
        0xCD,
    };
    s_slice_args args = {0};
    assert_true(run_tlv(bytes, sizeof(bytes), &args));
    assert_int_equal(args.start, 0x1234);
    // 0xABCD interpreted as signed int16 = -21555
    assert_int_equal(args.end, (int16_t) 0xABCD);
}

static void test_tlv_start_one_byte_payload_rejected(void **state) {
    (void) state;
    const uint8_t bytes[] = {0x01, 0x01, 0xAA};
    s_slice_args args = {0};
    assert_false(run_tlv(bytes, sizeof(bytes), &args));
    assert_false(args.has_start);
}

static void test_tlv_end_one_byte_payload_rejected(void **state) {
    (void) state;
    const uint8_t bytes[] = {0x02, 0x01, 0xBB};
    s_slice_args args = {0};
    assert_false(run_tlv(bytes, sizeof(bytes), &args));
    assert_false(args.has_end);
}

static void test_tlv_duplicate_start_rejected(void **state) {
    (void) state;
    const uint8_t bytes[] = {
        0x01,
        0x02,
        0x00,
        0x01,
        0x01,
        0x02,
        0x00,
        0x02,
    };
    s_slice_args args = {0};
    assert_false(run_tlv(bytes, sizeof(bytes), &args));
}

static void test_tlv_duplicate_end_rejected(void **state) {
    (void) state;
    const uint8_t bytes[] = {
        0x02,
        0x02,
        0x00,
        0x01,
        0x02,
        0x02,
        0x00,
        0x02,
    };
    s_slice_args args = {0};
    assert_false(run_tlv(bytes, sizeof(bytes), &args));
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_tlv_start_end_populated),
        cmocka_unit_test(test_tlv_only_start),
        cmocka_unit_test(test_tlv_only_end),
        cmocka_unit_test(test_tlv_empty_buffer_accepted),
        cmocka_unit_test(test_tlv_start_end_read_big_endian),
        cmocka_unit_test(test_tlv_start_one_byte_payload_rejected),
        cmocka_unit_test(test_tlv_end_one_byte_payload_rejected),
        cmocka_unit_test(test_tlv_duplicate_start_rejected),
        cmocka_unit_test(test_tlv_duplicate_end_rejected),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
