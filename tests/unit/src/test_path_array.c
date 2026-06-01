/**
 * @file test_path_array.c
 * @brief Unit tests for the array-path TLV parser at
 *        src/features/generic_tx_parser/gtp_path_array.c.
 *
 * Array paths describe how to index into an ABI-encoded array when the
 * field referenced by a GCS parameter lives behind a dynamic-array
 * indirection. The TLV carries:
 *   - TAG_WEIGHT  (0x01): per-element size, 1 byte minimum,
 *   - TAG_START   (0x02): inclusive start index, 2 bytes minimum,
 *                          marked present via has_start,
 *   - TAG_END     (0x03): exclusive end index, 2 bytes minimum,
 *                          marked present via has_end.
 *
 * Each handler enforces a strict minimum payload size (`size <
 * sizeof(field)` is rejected) and the framework enforces tag
 * uniqueness. WEIGHT is the only mandatory-shaped tag; the caller may
 * leave START / END absent to mean "whole array", which is conveyed
 * via the has_start / has_end booleans.
 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

#include "gtp_path_array.h"

// =============================================================================
// Helpers
// =============================================================================

static bool run_tlv(const uint8_t *bytes, size_t size, s_array_args *args) {
    buffer_t buf = {.ptr = (uint8_t *) bytes, .size = size, .offset = 0};
    s_path_array_context ctx = {.args = args};
    return handle_array_struct(&buf, &ctx);
}

// =============================================================================
// Happy paths
// =============================================================================

static void test_tlv_weight_start_end_populated(void **state) {
    (void) state;
    const uint8_t bytes[] = {
        0x01,
        0x01,
        0x20,  // WEIGHT  = 0x20
        0x02,
        0x02,
        0x00,
        0x05,  // START   = 5  (BE u16)
        0x03,
        0x02,
        0x00,
        0x0A,  // END     = 10
    };
    s_array_args args = {0};
    assert_true(run_tlv(bytes, sizeof(bytes), &args));
    assert_int_equal(args.weight, 0x20);
    assert_true(args.has_start);
    assert_int_equal(args.start, 5);
    assert_true(args.has_end);
    assert_int_equal(args.end, 10);
}

static void test_tlv_only_weight_keeps_has_start_end_false(void **state) {
    (void) state;
    const uint8_t bytes[] = {0x01, 0x01, 0x42};
    s_array_args args = {0};
    assert_true(run_tlv(bytes, sizeof(bytes), &args));
    assert_int_equal(args.weight, 0x42);
    assert_false(args.has_start);
    assert_false(args.has_end);
}

static void test_tlv_empty_buffer_accepted(void **state) {
    (void) state;
    // The parser does not require any specific tag presence — an empty
    // payload leaves the args at their pre-init values (zero / false).
    s_array_args args = {0};
    args.weight = 0xCC;  // Detectable canary
    args.has_start = false;
    assert_true(run_tlv(NULL, 0, &args));
    // No tag handler ran, so the canary remains.
    assert_int_equal(args.weight, 0xCC);
    assert_false(args.has_start);
    assert_false(args.has_end);
}

static void test_tlv_extra_weight_bytes_keeps_first_byte(void **state) {
    (void) state;
    // The handler only reads ptr[0] for weight, so passing 4 bytes
    // succeeds and the first byte wins.
    const uint8_t bytes[] = {0x01, 0x04, 0x33, 0xAA, 0xBB, 0xCC};
    s_array_args args = {0};
    assert_true(run_tlv(bytes, sizeof(bytes), &args));
    assert_int_equal(args.weight, 0x33);
}

static void test_tlv_start_end_read_big_endian(void **state) {
    (void) state;
    const uint8_t bytes[] = {
        0x02,
        0x02,
        0x12,
        0x34,  // START = 0x1234
        0x03,
        0x02,
        0xAB,
        0xCD,  // END   = 0xABCD (stored as int16 → -21555 after cast)
    };
    s_array_args args = {0};
    assert_true(run_tlv(bytes, sizeof(bytes), &args));
    assert_true(args.has_start);
    assert_int_equal(args.start, 0x1234);
    assert_true(args.has_end);
    // 0xABCD interpreted as signed int16 = -21555
    assert_int_equal(args.end, (int16_t) 0xABCD);
}

// =============================================================================
// Rejections — short payload
// =============================================================================

static void test_tlv_weight_empty_payload_rejected(void **state) {
    (void) state;
    const uint8_t bytes[] = {0x01, 0x00};  // WEIGHT with size=0
    s_array_args args = {0};
    assert_false(run_tlv(bytes, sizeof(bytes), &args));
}

static void test_tlv_start_one_byte_payload_rejected(void **state) {
    (void) state;
    const uint8_t bytes[] = {0x02, 0x01, 0xAA};  // START needs 2 bytes
    s_array_args args = {0};
    assert_false(run_tlv(bytes, sizeof(bytes), &args));
    assert_false(args.has_start);  // never marked present
}

static void test_tlv_end_one_byte_payload_rejected(void **state) {
    (void) state;
    const uint8_t bytes[] = {0x03, 0x01, 0xBB};
    s_array_args args = {0};
    assert_false(run_tlv(bytes, sizeof(bytes), &args));
    assert_false(args.has_end);
}

// =============================================================================
// Rejections — tag uniqueness
// =============================================================================

static void test_tlv_duplicate_weight_rejected(void **state) {
    (void) state;
    const uint8_t bytes[] = {
        0x01,
        0x01,
        0x10,
        0x01,
        0x01,
        0x20,  // duplicate WEIGHT
    };
    s_array_args args = {0};
    assert_false(run_tlv(bytes, sizeof(bytes), &args));
}

static void test_tlv_duplicate_start_rejected(void **state) {
    (void) state;
    const uint8_t bytes[] = {
        0x02,
        0x02,
        0x00,
        0x05,
        0x02,
        0x02,
        0x00,
        0x06,
    };
    s_array_args args = {0};
    assert_false(run_tlv(bytes, sizeof(bytes), &args));
}

// =============================================================================
// Runner
// =============================================================================

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_tlv_weight_start_end_populated),
        cmocka_unit_test(test_tlv_only_weight_keeps_has_start_end_false),
        cmocka_unit_test(test_tlv_empty_buffer_accepted),
        cmocka_unit_test(test_tlv_extra_weight_bytes_keeps_first_byte),
        cmocka_unit_test(test_tlv_start_end_read_big_endian),
        cmocka_unit_test(test_tlv_weight_empty_payload_rejected),
        cmocka_unit_test(test_tlv_start_one_byte_payload_rejected),
        cmocka_unit_test(test_tlv_end_one_byte_payload_rejected),
        cmocka_unit_test(test_tlv_duplicate_weight_rejected),
        cmocka_unit_test(test_tlv_duplicate_start_rejected),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
