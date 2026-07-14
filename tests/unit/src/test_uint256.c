/**
 * @file test_uint256.c
 * @brief Unit tests for uint256_t arithmetic helpers in src/uint256.c.
 *
 * uint256_t is the canonical EVM amount, used everywhere the device
 * formats a balance, fee, or token quantity for display. The helpers
 * stack on top of uint128_t (already covered by test_uint128.c) so this
 * suite focuses on the 256-bit-specific bookkeeping:
 *   - the shift / arith routines that have to propagate carry/borrow
 *     across the 128-bit halves,
 *   - tostring256 output-buffer-too-small behavior (prints "..." instead
 *     of overrunning),
 *   - mul256 byte-marshalling and error propagation, both verified with
 *     a linker --wrap on cx_math_mult_no_throw.
 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "uint256.h"
#include "uint_common.h"

// =============================================================================
// __wrap stubs for cx_math_mult_no_throw
// =============================================================================
//
// mul256() converts both inputs to 32-byte BE buffers, asks the SDK to
// multiply them, and reads back the lower 256 bits of the 64-byte BE result.
// To verify the byte plumbing without depending on the SDK, the wrap returns
// pre-canned 64-byte buffers selected by the test via `mock()`.

#define CX_OK                0
#define CX_INVALID_PARAMETER 0xFFFF

uint32_t __wrap_cx_math_mult_no_throw(uint8_t *r, const uint8_t *a, const uint8_t *b, size_t len) {
    check_expected(len);
    check_expected_ptr(a);
    check_expected_ptr(b);
    uint32_t ret = (uint32_t) mock();
    const uint8_t *canned = (const uint8_t *) mock();
    if (canned != NULL) {
        memcpy(r, canned, 2 * len);
    }
    return ret;
}

// Helper to skip the byte-content checks when the test doesn't care.
#define EXPECT_MULT_ANY(input_len)                                    \
    do {                                                              \
        expect_value(__wrap_cx_math_mult_no_throw, len, (input_len)); \
        expect_any(__wrap_cx_math_mult_no_throw, a);                  \
        expect_any(__wrap_cx_math_mult_no_throw, b);                  \
    } while (0)

// =============================================================================
// Constructors / accessors
// =============================================================================

static void test_clear256_zeros_all_four_limbs(void **state) {
    (void) state;
    uint256_t n;
    memset(&n, 0xCC, sizeof(n));
    clear256(&n);
    assert_true(zero256(&n));
}

static void test_zero256_detects_zero_and_nonzero(void **state) {
    (void) state;
    uint256_t z;
    clear256(&z);
    assert_true(zero256(&z));

    uint256_t low_only;
    clear256(&low_only);
    LOWER(LOWER(low_only)) = 1;
    assert_false(zero256(&low_only));

    uint256_t high_only;
    clear256(&high_only);
    UPPER(UPPER(high_only)) = 1;
    assert_false(zero256(&high_only));
}

static void test_copy256_preserves_all_four_limbs(void **state) {
    (void) state;
    uint256_t src;
    uint256_t dst;
    UPPER(UPPER(src)) = 0x1111111111111111ULL;
    LOWER(UPPER(src)) = 0x2222222222222222ULL;
    UPPER(LOWER(src)) = 0x3333333333333333ULL;
    LOWER(LOWER(src)) = 0x4444444444444444ULL;
    clear256(&dst);
    copy256(&dst, &src);
    assert_true(equal256(&dst, &src));
}

static void test_readu256BE_reads_big_endian(void **state) {
    (void) state;
    uint8_t buf[32];
    for (size_t i = 0; i < 32; i++) {
        buf[i] = (uint8_t) (i + 1);
    }
    uint256_t n;
    readu256BE(buf, &n);
    assert_int_equal(UPPER(UPPER(n)), 0x0102030405060708ULL);
    assert_int_equal(LOWER(UPPER(n)), 0x090A0B0C0D0E0F10ULL);
    assert_int_equal(UPPER(LOWER(n)), 0x1112131415161718ULL);
    assert_int_equal(LOWER(LOWER(n)), 0x191A1B1C1D1E1F20ULL);
}

// =============================================================================
// Comparison
// =============================================================================

static void test_equal256_and_ordering(void **state) {
    (void) state;
    uint256_t a;
    uint256_t b;
    clear256(&a);
    clear256(&b);
    UPPER(UPPER(a)) = 1;
    UPPER(UPPER(b)) = 1;
    assert_true(equal256(&a, &b));

    LOWER(LOWER(b)) = 1;
    assert_false(equal256(&a, &b));
    assert_true(gt256(&b, &a));
    assert_true(gte256(&b, &a));
    assert_false(gt256(&a, &b));

    // High-limb dominance: even with high LOWER, the higher UPPER wins.
    uint256_t big;
    uint256_t small;
    clear256(&big);
    clear256(&small);
    UPPER(UPPER(big)) = 2;
    UPPER(UPPER(small)) = 1;
    LOWER(LOWER(small)) = 0xFFFFFFFFFFFFFFFFULL;
    assert_true(gt256(&big, &small));
}

// =============================================================================
// Shifts — boundaries are 0, 1, 127, 128, 129, 255, 256, > 256
// =============================================================================

static void test_shiftl256_boundaries(void **state) {
    (void) state;
    uint256_t n;
    uint256_t r;
    clear256(&n);
    LOWER(LOWER(n)) = 1;  // 256-bit value "1"

    // shift by 0 = identity
    shiftl256(&n, 0, &r);
    assert_true(equal256(&r, &n));

    // shift by 1 = 2
    shiftl256(&n, 1, &r);
    assert_int_equal(LOWER(LOWER(r)), 2);
    assert_int_equal(UPPER(LOWER(r)), 0);

    // shift by 128 — low-128 moves into upper-128
    clear256(&n);
    LOWER(LOWER(n)) = 0xAAAAAAAAAAAAAAAAULL;
    UPPER(LOWER(n)) = 0xBBBBBBBBBBBBBBBBULL;
    shiftl256(&n, 128, &r);
    assert_int_equal(LOWER(UPPER(r)), 0xAAAAAAAAAAAAAAAAULL);
    assert_int_equal(UPPER(UPPER(r)), 0xBBBBBBBBBBBBBBBBULL);
    assert_int_equal(LOWER(LOWER(r)), 0);
    assert_int_equal(UPPER(LOWER(r)), 0);

    // shift by 256 = clear
    shiftl256(&n, 256, &r);
    assert_true(zero256(&r));

    // shift > 256 = clear
    shiftl256(&n, 300, &r);
    assert_true(zero256(&r));
}

static void test_shiftr256_boundaries(void **state) {
    (void) state;
    uint256_t n;
    uint256_t r;
    memset(&n, 0xFF, sizeof(n));  // all ones

    // shift by 0 = identity
    shiftr256(&n, 0, &r);
    assert_true(equal256(&r, &n));

    // shift by 128 — upper-128 moves into lower-128
    shiftr256(&n, 128, &r);
    assert_int_equal(UPPER(UPPER(r)), 0);
    assert_int_equal(LOWER(UPPER(r)), 0);
    assert_int_equal(UPPER(LOWER(r)), 0xFFFFFFFFFFFFFFFFULL);
    assert_int_equal(LOWER(LOWER(r)), 0xFFFFFFFFFFFFFFFFULL);

    // shift by 255 — only the MSB survives in bit 0
    shiftr256(&n, 255, &r);
    assert_int_equal(LOWER(LOWER(r)), 1);
    assert_int_equal(UPPER(LOWER(r)), 0);
    assert_true(zero128(&UPPER(r)));

    // shift >= 256 = clear
    shiftr256(&n, 256, &r);
    assert_true(zero256(&r));
}

// =============================================================================
// bits256
// =============================================================================

static void test_bits256(void **state) {
    (void) state;
    uint256_t z;
    clear256(&z);
    assert_int_equal(bits256(&z), 0);

    uint256_t one;
    clear256(&one);
    LOWER(LOWER(one)) = 1;
    assert_int_equal(bits256(&one), 1);

    uint256_t low_top;
    clear256(&low_top);
    UPPER(LOWER(low_top)) = 0x8000000000000000ULL;
    assert_int_equal(bits256(&low_top), 128);

    uint256_t cross;
    clear256(&cross);
    LOWER(UPPER(cross)) = 1;
    assert_int_equal(bits256(&cross), 129);

    uint256_t mx;
    memset(&mx, 0xFF, sizeof(mx));
    assert_int_equal(bits256(&mx), 256);
}

// =============================================================================
// Arithmetic — focus on cross-128 carry/borrow
// =============================================================================

static void test_add256_carries_across_128_boundary(void **state) {
    (void) state;
    uint256_t a;
    uint256_t b;
    uint256_t r;
    clear256(&a);
    clear256(&b);
    // a = 2^128 - 1, b = 1 → r = 2^128 (carry propagates across the boundary)
    UPPER(LOWER(a)) = 0xFFFFFFFFFFFFFFFFULL;
    LOWER(LOWER(a)) = 0xFFFFFFFFFFFFFFFFULL;
    LOWER(LOWER(b)) = 1;
    add256(&a, &b, &r);
    assert_int_equal(LOWER(LOWER(r)), 0);
    assert_int_equal(UPPER(LOWER(r)), 0);
    assert_int_equal(LOWER(UPPER(r)), 1);
    assert_int_equal(UPPER(UPPER(r)), 0);

    // max + 1 wraps to zero
    uint256_t mx;
    memset(&mx, 0xFF, sizeof(mx));
    add256(&mx, &b, &r);
    assert_true(zero256(&r));
}

static void test_sub256_borrows_across_128_boundary(void **state) {
    (void) state;
    uint256_t a;
    uint256_t b;
    uint256_t r;
    clear256(&a);
    clear256(&b);
    LOWER(UPPER(a)) = 1;  // a = 2^128
    LOWER(LOWER(b)) = 1;  // b = 1
    sub256(&a, &b, &r);
    // r should be 2^128 - 1: lower-128 all ones, upper-128 zero
    assert_int_equal(LOWER(LOWER(r)), 0xFFFFFFFFFFFFFFFFULL);
    assert_int_equal(UPPER(LOWER(r)), 0xFFFFFFFFFFFFFFFFULL);
    assert_true(zero128(&UPPER(r)));
}

static void test_or256(void **state) {
    (void) state;
    uint256_t a;
    uint256_t b;
    uint256_t r;
    clear256(&a);
    clear256(&b);
    UPPER(UPPER(a)) = 0xAAAA;
    LOWER(LOWER(b)) = 0xBBBB;
    or256(&a, &b, &r);
    assert_int_equal(UPPER(UPPER(r)), 0xAAAA);
    assert_int_equal(LOWER(LOWER(r)), 0xBBBB);
}

static void test_divmod256_basic(void **state) {
    (void) state;
    uint256_t l;
    uint256_t r_val;
    uint256_t q;
    uint256_t rem;
    clear256(&l);
    clear256(&r_val);
    LOWER(LOWER(l)) = 100;
    LOWER(LOWER(r_val)) = 7;
    divmod256(&l, &r_val, &q, &rem);
    assert_int_equal(LOWER(LOWER(q)), 14);
    assert_true(zero128(&UPPER(q)));
    assert_int_equal(LOWER(LOWER(rem)), 2);

    // l < r → q = 0, rem = l
    uint256_t big;
    clear256(&big);
    LOWER(LOWER(big)) = 50;
    uint256_t small;
    clear256(&small);
    LOWER(LOWER(small)) = 5;
    divmod256(&small, &big, &q, &rem);
    assert_true(zero256(&q));
    assert_true(equal256(&rem, &small));

    // l == r → q = 1, rem = 0
    divmod256(&l, &l, &q, &rem);
    assert_int_equal(LOWER(LOWER(q)), 1);
    assert_true(zero256(&rem));
}

// =============================================================================
// String formatting
// =============================================================================

static void test_tostring256_base10(void **state) {
    (void) state;
    char out[80] = {0};
    uint256_t n;
    clear256(&n);
    LOWER(LOWER(n)) = 1234567890ULL;
    assert_true(tostring256(&n, 10, out, sizeof(out)));
    assert_string_equal(out, "1234567890");
}

static void test_tostring256_zero(void **state) {
    (void) state;
    char out[80] = {0};
    uint256_t z;
    clear256(&z);
    assert_true(tostring256(&z, 10, out, sizeof(out)));
    assert_string_equal(out, "0");
}

static void test_tostring256_base16_max(void **state) {
    (void) state;
    char out[80] = {0};
    uint256_t mx;
    memset(&mx, 0xFF, sizeof(mx));
    assert_true(tostring256(&mx, 16, out, sizeof(out)));
    // 2^256 - 1 = 64 'f' characters
    assert_int_equal(strlen(out), 64);
    for (size_t i = 0; i < 64; i++) {
        assert_int_equal(out[i], 'f');
    }
}

static void test_tostring256_invalid_base_rejected(void **state) {
    (void) state;
    char out[80];
    uint256_t n;
    clear256(&n);
    LOWER(LOWER(n)) = 1;
    assert_false(tostring256(&n, 1, out, sizeof(out)));
    assert_false(tostring256(&n, 17, out, sizeof(out)));
    assert_false(tostring256(&n, 0, out, sizeof(out)));
}

static void test_tostring256_zero_outlength_rejected(void **state) {
    (void) state;
    char out[1];
    uint256_t n;
    clear256(&n);
    LOWER(LOWER(n)) = 1;
    assert_false(tostring256(&n, 10, out, 0));
}

static void test_tostring256_buffer_too_small_writes_ellipsis(void **state) {
    (void) state;
    // The number prints "12345" (5 digits + NUL = 6 bytes) but the buffer is
    // only 5. The function should fail AND leave "..." in the buffer as a
    // visible signal — that's the contract.
    char out[5];
    memset(out, 'X', sizeof(out));
    uint256_t n;
    clear256(&n);
    LOWER(LOWER(n)) = 12345;
    assert_false(tostring256(&n, 10, out, sizeof(out)));
    assert_string_equal(out, "...");
}

static void test_tostring256_tiny_buffer_clears(void **state) {
    (void) state;
    // outLength <= 3 → no room for "..." either, just terminate empty.
    char out[3] = {'X', 'X', 'X'};
    uint256_t n;
    clear256(&n);
    LOWER(LOWER(n)) = 12345;
    assert_false(tostring256(&n, 10, out, sizeof(out)));
    assert_int_equal(out[0], '\0');
}

static void test_tostring256_signed_positive_passthrough(void **state) {
    (void) state;
    char out[80] = {0};
    uint256_t n;
    clear256(&n);
    LOWER(LOWER(n)) = 42;
    assert_true(tostring256_signed(&n, 10, out, sizeof(out)));
    assert_string_equal(out, "42");
}

static void test_tostring256_signed_negative_one(void **state) {
    (void) state;
    char out[80] = {0};
    uint256_t neg_one;
    memset(&neg_one, 0xFF, sizeof(neg_one));
    assert_true(tostring256_signed(&neg_one, 10, out, sizeof(out)));
    assert_string_equal(out, "-1");
}

static void test_tostring256_signed_non_base10_unsigned(void **state) {
    (void) state;
    char out[80] = {0};
    uint256_t neg_one;
    memset(&neg_one, 0xFF, sizeof(neg_one));
    assert_true(tostring256_signed(&neg_one, 16, out, sizeof(out)));
    // In base 16 the value is rendered as 2^256 - 1, i.e. 64 'f's, regardless of sign.
    assert_int_equal(strlen(out), 64);
}

// =============================================================================
// convertUint256BE input guards
// =============================================================================

static void test_convertUint256BE_full_32_bytes(void **state) {
    (void) state;
    uint8_t buf[32];
    for (size_t i = 0; i < 32; i++) {
        buf[i] = (uint8_t) i;
    }
    uint256_t r;
    memset(&r, 0xDD, sizeof(r));
    convertUint256BE(buf, 32, &r);
    assert_int_equal(UPPER(UPPER(r)), 0x0001020304050607ULL);
    assert_int_equal(LOWER(LOWER(r)), 0x18191A1B1C1D1E1FULL);
}

static void test_convertUint256BE_short_input_left_zero_padded(void **state) {
    (void) state;
    uint8_t buf[2] = {0xAB, 0xCD};
    uint256_t r;
    memset(&r, 0xFF, sizeof(r));
    convertUint256BE(buf, 2, &r);
    assert_int_equal(LOWER(LOWER(r)), 0xABCDULL);
    assert_true(zero128(&UPPER(r)));
    assert_int_equal(UPPER(LOWER(r)), 0);
}

static void test_convertUint256BE_zero_length_is_noop(void **state) {
    (void) state;
    uint8_t buf[1] = {0xAB};
    uint256_t r;
    memset(&r, 0x42, sizeof(r));
    convertUint256BE(buf, 0, &r);
    // every byte still 0x42
    for (size_t i = 0; i < sizeof(r); i++) {
        assert_int_equal(((uint8_t *) &r)[i], 0x42);
    }
}

static void test_convertUint256BE_oversize_length_is_noop(void **state) {
    (void) state;
    uint8_t buf[40] = {0};
    uint256_t r;
    memset(&r, 0x77, sizeof(r));
    convertUint256BE(buf, 33, &r);
    for (size_t i = 0; i < sizeof(r); i++) {
        assert_int_equal(((uint8_t *) &r)[i], 0x77);
    }
}

static void test_convertUint256BE_null_inputs_are_noop(void **state) {
    (void) state;
    uint8_t buf[4] = {1, 2, 3, 4};
    uint256_t r;
    memset(&r, 0x77, sizeof(r));
    convertUint256BE(NULL, 4, &r);
    assert_int_equal(((uint8_t *) &r)[0], 0x77);
    convertUint256BE(buf, 4, NULL);  // must not crash
}

// =============================================================================
// mul256 — byte marshalling & error propagation (wrapped SDK call)
// =============================================================================

static void test_mul256_success_marshals_lower_half(void **state) {
    (void) state;
    // Pre-canned 64-byte BE result: lower 32 bytes = 0x...000001
    static uint8_t canned[64];
    memset(canned, 0, sizeof(canned));
    canned[63] = 1;

    uint256_t a;
    uint256_t b;
    uint256_t r;
    memset(&a, 0xAA, sizeof(a));
    memset(&b, 0xBB, sizeof(b));
    clear256(&r);

    EXPECT_MULT_ANY(32);
    will_return(__wrap_cx_math_mult_no_throw, CX_OK);
    will_return(__wrap_cx_math_mult_no_throw, canned);

    assert_true(mul256(&a, &b, &r));
    // mul256 reads result[32..63] back as BE → only LOWER(LOWER(r)) = 1
    assert_int_equal(LOWER(LOWER(r)), 1);
    assert_int_equal(UPPER(LOWER(r)), 0);
    assert_true(zero128(&UPPER(r)));
}

static void test_mul256_returns_false_on_sdk_error(void **state) {
    (void) state;
    uint256_t a;
    uint256_t b;
    uint256_t r;
    clear256(&a);
    clear256(&b);
    clear256(&r);

    EXPECT_MULT_ANY(32);
    will_return(__wrap_cx_math_mult_no_throw, CX_INVALID_PARAMETER);
    will_return(__wrap_cx_math_mult_no_throw, NULL);  // canned buffer not used

    assert_false(mul256(&a, &b, &r));
}

// =============================================================================
// Runner
// =============================================================================

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_clear256_zeros_all_four_limbs),
        cmocka_unit_test(test_zero256_detects_zero_and_nonzero),
        cmocka_unit_test(test_copy256_preserves_all_four_limbs),
        cmocka_unit_test(test_readu256BE_reads_big_endian),
        cmocka_unit_test(test_equal256_and_ordering),
        cmocka_unit_test(test_shiftl256_boundaries),
        cmocka_unit_test(test_shiftr256_boundaries),
        cmocka_unit_test(test_bits256),
        cmocka_unit_test(test_add256_carries_across_128_boundary),
        cmocka_unit_test(test_sub256_borrows_across_128_boundary),
        cmocka_unit_test(test_or256),
        cmocka_unit_test(test_divmod256_basic),
        cmocka_unit_test(test_tostring256_base10),
        cmocka_unit_test(test_tostring256_zero),
        cmocka_unit_test(test_tostring256_base16_max),
        cmocka_unit_test(test_tostring256_invalid_base_rejected),
        cmocka_unit_test(test_tostring256_zero_outlength_rejected),
        cmocka_unit_test(test_tostring256_buffer_too_small_writes_ellipsis),
        cmocka_unit_test(test_tostring256_tiny_buffer_clears),
        cmocka_unit_test(test_tostring256_signed_positive_passthrough),
        cmocka_unit_test(test_tostring256_signed_negative_one),
        cmocka_unit_test(test_tostring256_signed_non_base10_unsigned),
        cmocka_unit_test(test_convertUint256BE_full_32_bytes),
        cmocka_unit_test(test_convertUint256BE_short_input_left_zero_padded),
        cmocka_unit_test(test_convertUint256BE_zero_length_is_noop),
        cmocka_unit_test(test_convertUint256BE_oversize_length_is_noop),
        cmocka_unit_test(test_convertUint256BE_null_inputs_are_noop),
        cmocka_unit_test(test_mul256_success_marshals_lower_half),
        cmocka_unit_test(test_mul256_returns_false_on_sdk_error),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
