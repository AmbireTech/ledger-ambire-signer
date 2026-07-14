/**
 * @file test_hash_bytes.c
 * @brief Unit tests for hash_nbytes / hash_byte / finalize_hash at
 *        src/hash_bytes.c.
 *
 * Thin wrappers over cx_hash_no_throw that the descriptor-verification
 * layer uses (proxy / trusted-name / network / safe / enum-value): all
 * of them feed bytes into a running SHA-256 context, then finalise to
 * the digest that check_signature_with_pubkey verifies against the
 * Ledger backend signature. Failure to update the running hash, or a
 * silent finalize_hash() return value, would let a forged descriptor
 * pass the signature gate.
 *
 * Pin:
 *  - hash_nbytes forwards (in, n, hash_ctx) to cx_hash_no_throw with mode=0
 *  - hash_byte routes through hash_nbytes (size 1)
 *  - finalize_hash returns true on CX_OK, false otherwise; CX_LAST flag
 *    is set so cx_hash_no_throw emits the final digest
 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

#include "hash_bytes.h"

// =============================================================================
// Wraps
// =============================================================================
// Capture mode + in + len so the tests can assert the exact argument shape
// the wrapper forwards.

static struct {
    int calls;
    uint32_t last_mode;
    const uint8_t *last_in;
    size_t last_in_len;
    uint8_t *last_out;
    size_t last_out_len;
} g_cap;

cx_err_t __wrap_cx_hash_no_throw(cx_hash_t *hash,
                                 uint32_t mode,
                                 const uint8_t *in,
                                 size_t in_len,
                                 uint8_t *out,
                                 size_t out_len) {
    (void) hash;
    g_cap.calls++;
    g_cap.last_mode = mode;
    g_cap.last_in = in;
    g_cap.last_in_len = in_len;
    g_cap.last_out = out;
    g_cap.last_out_len = out_len;
    return (cx_err_t) mock();
}

static int reset(void **state) {
    (void) state;
    memset(&g_cap, 0, sizeof(g_cap));
    return 0;
}

// =============================================================================
// hash_nbytes
// =============================================================================

static void test_hash_nbytes_forwards_arguments_with_mode_zero(void **state) {
    (void) state;
    uint8_t data[5] = {1, 2, 3, 4, 5};
    will_return(__wrap_cx_hash_no_throw, CX_OK);
    hash_nbytes(data, sizeof(data), (cx_hash_t *) 0xDEAD);
    assert_int_equal(g_cap.calls, 1);
    // mode == 0 (CX_HASH_DEFAULT) -- not a finalising call.
    assert_int_equal(g_cap.last_mode, 0);
    assert_ptr_equal(g_cap.last_in, data);
    assert_int_equal(g_cap.last_in_len, sizeof(data));
    assert_null(g_cap.last_out);
    assert_int_equal(g_cap.last_out_len, 0);
}

// =============================================================================
// hash_byte
// =============================================================================

static void test_hash_byte_passes_single_byte_with_len_one(void **state) {
    (void) state;
    will_return(__wrap_cx_hash_no_throw, CX_OK);
    hash_byte(0x42, (cx_hash_t *) 0xBEEF);
    assert_int_equal(g_cap.calls, 1);
    assert_int_equal(g_cap.last_in_len, 1);
    // hash_byte forwards the byte by address-of a local; the value must
    // round-trip correctly.
    assert_non_null(g_cap.last_in);
    assert_int_equal(g_cap.last_in[0], 0x42);
}

// =============================================================================
// finalize_hash
// =============================================================================

static void test_finalize_hash_success_returns_true_with_cx_last_flag(void **state) {
    (void) state;
    uint8_t digest[32] = {0};
    will_return(__wrap_cx_hash_no_throw, CX_OK);
    assert_true(finalize_hash((cx_hash_t *) 0xCAFE, digest, sizeof(digest)));
    // CX_LAST flag must be set on the underlying call so the SDK emits
    // the final digest rather than treating this as another update.
    assert_int_equal(g_cap.last_mode, CX_LAST);
    assert_ptr_equal(g_cap.last_out, digest);
    assert_int_equal(g_cap.last_out_len, sizeof(digest));
}

static void test_finalize_hash_failure_returns_false(void **state) {
    (void) state;
    uint8_t digest[32] = {0};
    will_return(__wrap_cx_hash_no_throw, CX_INVALID_PARAMETER);
    assert_false(finalize_hash((cx_hash_t *) 0xCAFE, digest, sizeof(digest)));
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup(test_hash_nbytes_forwards_arguments_with_mode_zero, reset),
        cmocka_unit_test_setup(test_hash_byte_passes_single_byte_with_len_one, reset),
        cmocka_unit_test_setup(test_finalize_hash_success_returns_true_with_cx_last_flag, reset),
        cmocka_unit_test_setup(test_finalize_hash_failure_returns_false, reset),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
