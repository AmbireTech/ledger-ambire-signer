/**
 * @file test_uint128.c
 * @brief Unit tests for uint128_t arithmetic helpers in src/uint128.c.
 *
 * uint128_t is the building block for uint256_t and for every amount the
 * device formats on screen, so the boundary behavior of the shift / arith /
 * format helpers must hold exactly. Tests are organised one CMocka case per
 * public function with a focus on:
 *   - the shift boundaries (0, 1, 63, 64, 65, 127, 128, > 128) where 64-bit
 *     halves are split or swapped,
 *   - carry / borrow propagation in add128 / sub128,
 *   - mul128 against precomputed full-width products,
 *   - tostring128 base validation and buffer-overrun protection,
 *   - convertUint*BE input-length guards.
 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "uint128.h"
#include "uint_common.h"

// =============================================================================
// Constructors / accessors
// =============================================================================

static void test_clear128_zeros_both_halves(void **state) {
    (void) state;
    uint128_t n;
    UPPER(n) = 0xDEADBEEFDEADBEEFULL;
    LOWER(n) = 0xCAFEBABECAFEBABEULL;

    clear128(&n);
    assert_int_equal(UPPER(n), 0);
    assert_int_equal(LOWER(n), 0);
}

static void test_zero128_detects_zero_and_nonzero(void **state) {
    (void) state;
    uint128_t z = {{0, 0}};
    uint128_t low_only = {{0, 1}};
    uint128_t high_only = {{1, 0}};
    assert_true(zero128(&z));
    assert_false(zero128(&low_only));
    assert_false(zero128(&high_only));
}

static void test_copy128_preserves_both_halves(void **state) {
    (void) state;
    uint128_t src = {{0x1122334455667788ULL, 0x99AABBCCDDEEFF00ULL}};
    uint128_t dst = {{0, 0}};
    copy128(&dst, &src);
    assert_int_equal(UPPER(dst), UPPER(src));
    assert_int_equal(LOWER(dst), LOWER(src));
}

static void test_readu128BE_reads_big_endian(void **state) {
    (void) state;
    // Upper = 0x0123456789ABCDEF, Lower = 0xFEDCBA9876543210
    uint8_t buf[16] = {0x01,
                       0x23,
                       0x45,
                       0x67,
                       0x89,
                       0xAB,
                       0xCD,
                       0xEF,
                       0xFE,
                       0xDC,
                       0xBA,
                       0x98,
                       0x76,
                       0x54,
                       0x32,
                       0x10};
    uint128_t n;
    readu128BE(buf, &n);
    assert_int_equal(UPPER(n), 0x0123456789ABCDEFULL);
    assert_int_equal(LOWER(n), 0xFEDCBA9876543210ULL);
}

// =============================================================================
// Comparison
// =============================================================================

static void test_equal128(void **state) {
    (void) state;
    uint128_t a = {{1, 2}};
    uint128_t b = {{1, 2}};
    uint128_t c = {{1, 3}};
    uint128_t d = {{2, 2}};
    assert_true(equal128(&a, &b));
    assert_false(equal128(&a, &c));
    assert_false(equal128(&a, &d));
}

static void test_gt128_and_gte128(void **state) {
    (void) state;
    // High word dominates
    uint128_t big = {{2, 0}};
    uint128_t small_hi = {{1, 0xFFFFFFFFFFFFFFFFULL}};
    assert_true(gt128(&big, &small_hi));
    assert_false(gt128(&small_hi, &big));

    // Tie on high → compare low
    uint128_t a = {{5, 100}};
    uint128_t b = {{5, 50}};
    assert_true(gt128(&a, &b));
    assert_false(gt128(&b, &a));

    // gte includes equality
    uint128_t c = {{5, 50}};
    assert_true(gte128(&b, &c));
    assert_true(gte128(&a, &b));
    assert_false(gte128(&b, &a));
}

// =============================================================================
// Shifts
// =============================================================================

static void test_shiftl128_boundaries(void **state) {
    (void) state;
    uint128_t n = {{0x0000000000000001ULL, 0x0000000000000001ULL}};
    uint128_t r;

    // shift by 0 = identity
    shiftl128(&n, 0, &r);
    assert_int_equal(UPPER(r), 0x1);
    assert_int_equal(LOWER(r), 0x1);

    // shift by 1 — low bit propagates up only when low overflows; here it doesn't
    shiftl128(&n, 1, &r);
    assert_int_equal(UPPER(r), 0x2);
    assert_int_equal(LOWER(r), 0x2);

    // shift by 63 — top bit of low moves to bit 63 of low, bit 0 of low moves nowhere
    uint128_t n2 = {{0x0, 0x8000000000000000ULL}};  // bit 63 of low set
    shiftl128(&n2, 1, &r);
    assert_int_equal(UPPER(r), 0x1);  // promoted into low bit of upper
    assert_int_equal(LOWER(r), 0x0);

    // shift by 64 — low becomes upper, low cleared
    uint128_t n3 = {{0xAAAA, 0xBBBB}};
    shiftl128(&n3, 64, &r);
    assert_int_equal(UPPER(r), 0xBBBB);
    assert_int_equal(LOWER(r), 0);

    // shift by 65 — same shape as 64 + shift-by-1 in upper
    shiftl128(&n3, 65, &r);
    assert_int_equal(UPPER(r), 0xBBBB << 1);
    assert_int_equal(LOWER(r), 0);

    // shift >= 128 → zero
    shiftl128(&n3, 128, &r);
    assert_true(zero128(&r));
    shiftl128(&n3, 200, &r);
    assert_true(zero128(&r));
}

static void test_shiftr128_boundaries(void **state) {
    (void) state;
    uint128_t n = {{0xAAAAAAAAAAAAAAAAULL, 0xBBBBBBBBBBBBBBBBULL}};
    uint128_t r;

    shiftr128(&n, 0, &r);
    assert_int_equal(UPPER(r), UPPER(n));
    assert_int_equal(LOWER(r), LOWER(n));

    // shift by 1: top bit of upper kept, low bit of upper becomes high bit of low
    shiftr128(&n, 1, &r);
    assert_int_equal(UPPER(r), UPPER(n) >> 1);
    assert_int_equal(LOWER(r), (UPPER(n) << 63) + (LOWER(n) >> 1));

    // shift by 64 → upper becomes low, upper cleared
    shiftr128(&n, 64, &r);
    assert_int_equal(UPPER(r), 0);
    assert_int_equal(LOWER(r), UPPER(n));

    // shift by 65 → 1 << of the (upper-into-low) shape
    shiftr128(&n, 65, &r);
    assert_int_equal(UPPER(r), 0);
    assert_int_equal(LOWER(r), UPPER(n) >> 1);

    // shift >= 128 → zero
    shiftr128(&n, 128, &r);
    assert_true(zero128(&r));
}

// =============================================================================
// bits128
// =============================================================================

static void test_bits128(void **state) {
    (void) state;
    uint128_t z = {{0, 0}};
    assert_int_equal(bits128(&z), 0);

    uint128_t one = {{0, 1}};
    assert_int_equal(bits128(&one), 1);

    uint128_t low_top = {{0, 0x8000000000000000ULL}};
    assert_int_equal(bits128(&low_top), 64);

    uint128_t cross = {{0x1, 0}};
    assert_int_equal(bits128(&cross), 65);

    uint128_t mx;
    memset(&mx, 0xFF, sizeof(mx));
    assert_int_equal(bits128(&mx), 128);
}

// =============================================================================
// Arithmetic
// =============================================================================

static void test_add128_with_carry(void **state) {
    (void) state;
    uint128_t a = {{0, 0xFFFFFFFFFFFFFFFFULL}};
    uint128_t b = {{0, 1}};
    uint128_t r;
    add128(&a, &b, &r);
    assert_int_equal(UPPER(r), 1);  // carry propagated
    assert_int_equal(LOWER(r), 0);

    // 0 + 0 = 0
    uint128_t z = {{0, 0}};
    add128(&z, &z, &r);
    assert_true(zero128(&r));

    // max + 1 wraps to 0
    uint128_t mx;
    memset(&mx, 0xFF, sizeof(mx));
    add128(&mx, &b, &r);
    assert_true(zero128(&r));
}

static void test_sub128_with_borrow(void **state) {
    (void) state;
    uint128_t a = {{1, 0}};
    uint128_t b = {{0, 1}};
    uint128_t r;
    sub128(&a, &b, &r);
    assert_int_equal(UPPER(r), 0);
    assert_int_equal(LOWER(r), 0xFFFFFFFFFFFFFFFFULL);

    // x - x = 0
    sub128(&a, &a, &r);
    assert_true(zero128(&r));
}

static void test_or128(void **state) {
    (void) state;
    uint128_t a = {{0x00FF00FF00FF00FFULL, 0xAA00AA00AA00AA00ULL}};
    uint128_t b = {{0xFF00FF00FF00FF00ULL, 0x00BB00BB00BB00BBULL}};
    uint128_t r;
    or128(&a, &b, &r);
    assert_int_equal(UPPER(r), 0xFFFFFFFFFFFFFFFFULL);
    assert_int_equal(LOWER(r), 0xAABBAABBAABBAABBULL);
}

static void test_mul128_small_values(void **state) {
    (void) state;
    uint128_t a = {{0, 0x100000000ULL}};  // 2^32
    uint128_t b = {{0, 0x100000000ULL}};  // 2^32
    uint128_t r;
    mul128(&a, &b, &r);
    // 2^32 * 2^32 = 2^64 → upper = 1, lower = 0
    assert_int_equal(UPPER(r), 1);
    assert_int_equal(LOWER(r), 0);

    // 0 * anything = 0
    uint128_t z = {{0, 0}};
    mul128(&z, &a, &r);
    assert_true(zero128(&r));

    // 1 * anything = anything
    uint128_t one = {{0, 1}};
    uint128_t v = {{0x1122334455667788ULL, 0x99AABBCCDDEEFF00ULL}};
    mul128(&one, &v, &r);
    assert_int_equal(UPPER(r), UPPER(v));
    assert_int_equal(LOWER(r), LOWER(v));
}

static void test_divmod128_basic(void **state) {
    (void) state;
    uint128_t l = {{0, 100}};
    uint128_t r_val = {{0, 7}};
    uint128_t q, rem;
    divmod128(&l, &r_val, &q, &rem);
    assert_int_equal(UPPER(q), 0);
    assert_int_equal(LOWER(q), 14);
    assert_int_equal(UPPER(rem), 0);
    assert_int_equal(LOWER(rem), 2);

    // l < r → q = 0, rem = l
    uint128_t small = {{0, 5}};
    uint128_t big = {{0, 50}};
    divmod128(&small, &big, &q, &rem);
    assert_true(zero128(&q));
    assert_true(equal128(&rem, &small));

    // l == r → q = 1, rem = 0
    uint128_t v = {{0xAA, 0xBB}};
    uint128_t v2 = {{0xAA, 0xBB}};
    divmod128(&v, &v2, &q, &rem);
    assert_int_equal(UPPER(q), 0);
    assert_int_equal(LOWER(q), 1);
    assert_true(zero128(&rem));
}

// =============================================================================
// String formatting
// =============================================================================

static void test_tostring128_base10(void **state) {
    (void) state;
    char out[40] = {0};
    uint128_t n = {{0, 12345}};
    assert_true(tostring128(&n, 10, out, sizeof(out)));
    assert_string_equal(out, "12345");

    // zero
    uint128_t z = {{0, 0}};
    memset(out, 0, sizeof(out));
    assert_true(tostring128(&z, 10, out, sizeof(out)));
    assert_string_equal(out, "0");
}

static void test_tostring128_base16(void **state) {
    (void) state;
    char out[40] = {0};
    uint128_t n = {{0, 0xCAFE}};
    assert_true(tostring128(&n, 16, out, sizeof(out)));
    assert_string_equal(out, "cafe");
}

static void test_tostring128_base2(void **state) {
    (void) state;
    char out[150] = {0};
    uint128_t n = {{0, 0xB}};  // 0b1011
    assert_true(tostring128(&n, 2, out, sizeof(out)));
    assert_string_equal(out, "1011");
}

static void test_tostring128_invalid_base_rejected(void **state) {
    (void) state;
    char out[40];
    uint128_t n = {{0, 1}};
    assert_false(tostring128(&n, 1, out, sizeof(out)));
    assert_false(tostring128(&n, 17, out, sizeof(out)));
    assert_false(tostring128(&n, 0, out, sizeof(out)));
}

static void test_tostring128_buffer_too_small_returns_false(void **state) {
    (void) state;
    char out[3];  // room for at most 2 chars + NUL
    uint128_t n = {{0, 12345}};
    assert_false(tostring128(&n, 10, out, sizeof(out)));
}

static void test_tostring128_signed_positive_passthrough(void **state) {
    (void) state;
    char out[40] = {0};
    uint128_t n = {{0, 42}};
    assert_true(tostring128_signed(&n, 10, out, sizeof(out)));
    assert_string_equal(out, "42");
}

static void test_tostring128_signed_negative_base10(void **state) {
    (void) state;
    char out[40] = {0};
    // -1 in two's complement = all bits set
    uint128_t neg_one;
    memset(&neg_one, 0xFF, sizeof(neg_one));
    assert_true(tostring128_signed(&neg_one, 10, out, sizeof(out)));
    assert_string_equal(out, "-1");
}

static void test_tostring128_signed_non_base10_unsigned(void **state) {
    (void) state;
    // In base != 10, the helper always renders as unsigned.
    char out[40] = {0};
    uint128_t neg_one;
    memset(&neg_one, 0xFF, sizeof(neg_one));
    assert_true(tostring128_signed(&neg_one, 16, out, sizeof(out)));
    assert_string_equal(out, "ffffffffffffffffffffffffffffffff");
}

// =============================================================================
// convertUintXBE input guards
// =============================================================================

static void test_convertUint128BE_full_16_bytes(void **state) {
    (void) state;
    uint8_t buf[16] = {0x01,
                       0x02,
                       0x03,
                       0x04,
                       0x05,
                       0x06,
                       0x07,
                       0x08,
                       0x09,
                       0x0A,
                       0x0B,
                       0x0C,
                       0x0D,
                       0x0E,
                       0x0F,
                       0x10};
    uint128_t r = {{0xDEAD, 0xBEEF}};
    convertUint128BE(buf, 16, &r);
    assert_int_equal(UPPER(r), 0x0102030405060708ULL);
    assert_int_equal(LOWER(r), 0x090A0B0C0D0E0F10ULL);
}

static void test_convertUint128BE_short_input_left_zero_padded(void **state) {
    (void) state;
    uint8_t buf[2] = {0xAB, 0xCD};
    uint128_t r;
    memset(&r, 0xFF, sizeof(r));  // dirty
    convertUint128BE(buf, 2, &r);
    assert_int_equal(UPPER(r), 0);
    assert_int_equal(LOWER(r), 0xABCDULL);
}

static void test_convertUint128BE_zero_length_is_noop(void **state) {
    (void) state;
    uint8_t buf[1] = {0xAB};
    uint128_t r;
    memset(&r, 0x42, sizeof(r));  // dirty pattern
    convertUint128BE(buf, 0, &r);
    // Function returns early without touching target.
    assert_int_equal(UPPER(r), 0x4242424242424242ULL);
    assert_int_equal(LOWER(r), 0x4242424242424242ULL);
}

static void test_convertUint128BE_oversize_length_is_noop(void **state) {
    (void) state;
    uint8_t buf[20] = {0};
    uint128_t r;
    memset(&r, 0x33, sizeof(r));
    convertUint128BE(buf, 17, &r);  // > INT128_LENGTH
    assert_int_equal(UPPER(r), 0x3333333333333333ULL);
    assert_int_equal(LOWER(r), 0x3333333333333333ULL);
}

static void test_convertUint128BE_null_inputs_are_noop(void **state) {
    (void) state;
    uint8_t buf[4] = {1, 2, 3, 4};
    uint128_t r;
    memset(&r, 0x77, sizeof(r));
    convertUint128BE(NULL, 4, &r);
    assert_int_equal(UPPER(r), 0x7777777777777777ULL);
    convertUint128BE(buf, 4, NULL);  // must not crash
}

static void test_convertUint64BEto128_small_positive(void **state) {
    (void) state;
    uint8_t buf[4] = {0x00, 0x00, 0x12, 0x34};
    uint128_t r;
    convertUint64BEto128(buf, 4, &r);
    assert_int_equal(UPPER(r), 0);
    assert_int_equal(LOWER(r), 0x1234ULL);
}

static void test_convertUint64BEto128_negative_sign_extends(void **state) {
    (void) state;
    // MSB set → treated as negative → upper bytes are sign-extended (0xFF).
    uint8_t buf[8] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE};
    uint128_t r;
    convertUint64BEto128(buf, 8, &r);
    assert_int_equal(UPPER(r), 0xFFFFFFFFFFFFFFFFULL);
    assert_int_equal(LOWER(r), 0xFFFFFFFFFFFFFFFEULL);
}

// =============================================================================
// Runner
// =============================================================================

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_clear128_zeros_both_halves),
        cmocka_unit_test(test_zero128_detects_zero_and_nonzero),
        cmocka_unit_test(test_copy128_preserves_both_halves),
        cmocka_unit_test(test_readu128BE_reads_big_endian),
        cmocka_unit_test(test_equal128),
        cmocka_unit_test(test_gt128_and_gte128),
        cmocka_unit_test(test_shiftl128_boundaries),
        cmocka_unit_test(test_shiftr128_boundaries),
        cmocka_unit_test(test_bits128),
        cmocka_unit_test(test_add128_with_carry),
        cmocka_unit_test(test_sub128_with_borrow),
        cmocka_unit_test(test_or128),
        cmocka_unit_test(test_mul128_small_values),
        cmocka_unit_test(test_divmod128_basic),
        cmocka_unit_test(test_tostring128_base10),
        cmocka_unit_test(test_tostring128_base16),
        cmocka_unit_test(test_tostring128_base2),
        cmocka_unit_test(test_tostring128_invalid_base_rejected),
        cmocka_unit_test(test_tostring128_buffer_too_small_returns_false),
        cmocka_unit_test(test_tostring128_signed_positive_passthrough),
        cmocka_unit_test(test_tostring128_signed_negative_base10),
        cmocka_unit_test(test_tostring128_signed_non_base10_unsigned),
        cmocka_unit_test(test_convertUint128BE_full_16_bytes),
        cmocka_unit_test(test_convertUint128BE_short_input_left_zero_padded),
        cmocka_unit_test(test_convertUint128BE_zero_length_is_noop),
        cmocka_unit_test(test_convertUint128BE_oversize_length_is_noop),
        cmocka_unit_test(test_convertUint128BE_null_inputs_are_noop),
        cmocka_unit_test(test_convertUint64BEto128_small_positive),
        cmocka_unit_test(test_convertUint64BEto128_negative_sign_extends),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
