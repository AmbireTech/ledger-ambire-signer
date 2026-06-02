/**
 * @file test_cmd_get_challenge.c
 * @brief Unit tests for the challenge anti-replay primitive at
 *        src/features/get_challenge/cmd_get_challenge.c.
 *
 * The challenge is a single 32-bit nonce rolled from the SE RNG. The
 * host calls GET_CHALLENGE before each privileged provide_* command
 * (trusted name, proxy info, safe account, ...). The device echoes the
 * challenge inside the signed payload; `check_challenge` then rejects
 * any payload whose echoed challenge does not match the current value.
 *
 * The guarantees the unit tests pin (CWE-294 anti-replay):
 *  - `roll_challenge` overwrites the stored challenge with whatever the
 *    RNG produced (i.e. it does NOT reuse the previous value),
 *  - `check_challenge` accepts the current challenge and rejects any
 *    other value, including 0,
 *  - once `roll_challenge` is called again, the previously valid
 *    challenge no longer matches — that's the entire point of the
 *    primitive,
 *  - `handle_get_challenge` writes the challenge big-endian into the
 *    APDU TX buffer and bumps the response length.
 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

#include "challenge.h"
#include "apdu_constants.h"

// =============================================================================
// Controllable RNG wrap
// =============================================================================

static uint32_t g_rng_sequence[8] = {0xDEADBEEF,
                                     0xCAFEBABE,
                                     0xF00DBABE,
                                     0x12345678,
                                     0x00000001,
                                     0xFFFFFFFF,
                                     0x11111111,
                                     0x22222222};
static int g_rng_idx = 0;

// cx_rng_u32 is a `static inline` in the SDK that delegates to
// cx_rng_no_throw. Wrap the underlying primitive so we control the
// 32 bits the source ends up reading.
uint32_t __wrap_cx_rng_no_throw(uint8_t *buf, size_t len) {
    uint32_t v = g_rng_sequence[g_rng_idx % (int) (sizeof(g_rng_sequence) / sizeof(uint32_t))];
    g_rng_idx++;
    if (buf != NULL && len >= sizeof(uint32_t)) {
        memcpy(buf, &v, sizeof(uint32_t));
    }
    return 0;
}

static int reset(void **state) {
    (void) state;
    g_rng_idx = 0;
    memset(G_io_tx_buffer, 0, sizeof(G_io_tx_buffer));
    // Drain the internal state to a known value (the first sequence
    // element) so individual tests start from a deterministic point.
    roll_challenge();
    return 0;
}

// =============================================================================
// Tests
// =============================================================================

static void test_roll_seeds_challenge_from_rng(void **state) {
    (void) state;
    // reset() already rolled once and consumed g_rng_sequence[0].
    assert_int_equal(get_challenge(), 0xDEADBEEF);
}

static void test_get_challenge_returns_current_value(void **state) {
    (void) state;
    uint32_t a = get_challenge();
    uint32_t b = get_challenge();
    assert_int_equal(a, b);  // get_challenge must NOT mutate state.
    assert_int_equal(a, 0xDEADBEEF);
}

static void test_check_accepts_current_challenge(void **state) {
    (void) state;
    assert_true(check_challenge(0xDEADBEEF));
}

static void test_check_rejects_off_by_one(void **state) {
    (void) state;
    assert_false(check_challenge(0xDEADBEEE));
    assert_false(check_challenge(0xDEADBEF0));
}

static void test_check_rejects_zero(void **state) {
    (void) state;
    // Zero is the default value of an uninitialised challenge field on
    // the host side — if the device accepted it the gate would be a
    // no-op for any host that simply forgot to echo the value.
    assert_false(check_challenge(0));
}

static void test_check_rejects_unrelated_value(void **state) {
    (void) state;
    assert_false(check_challenge(0xFFFFFFFF));
    assert_false(check_challenge(0x12345678));
}

static void test_roll_replaces_previous_challenge(void **state) {
    (void) state;
    assert_int_equal(get_challenge(), 0xDEADBEEF);
    roll_challenge();
    assert_int_equal(get_challenge(), 0xCAFEBABE);
}

static void test_after_roll_old_challenge_is_rejected(void **state) {
    (void) state;
    // This is the anti-replay invariant: once the device rolls a new
    // challenge, a payload echoing the OLD challenge must be rejected.
    // Without this, the host could replay an already-signed descriptor
    // any number of times against the same device.
    uint32_t old = get_challenge();
    roll_challenge();
    assert_false(check_challenge(old));
    assert_true(check_challenge(get_challenge()));
}

static void test_check_does_not_mutate_state(void **state) {
    (void) state;
    uint32_t before = get_challenge();
    (void) check_challenge(0xBADBEEF1);  // wrong
    (void) check_challenge(before);      // correct
    (void) check_challenge(0);
    assert_int_equal(get_challenge(), before);
}

static void test_handle_writes_big_endian(void **state) {
    (void) state;
    // Force a known challenge by re-rolling until we land on a value
    // with all four bytes distinct so we can pin the byte order.
    while (get_challenge() != 0xDEADBEEF) {
        roll_challenge();
    }
    // Pre-fill the buffer with a sentinel to detect over-write.
    memset(G_io_tx_buffer, 0x55, 8);
    unsigned int tx = 0;
    uint16_t sw = handle_get_challenge(&tx);
    assert_int_equal(sw, SWO_SUCCESS);
    assert_int_equal(tx, 4);
    assert_int_equal(G_io_tx_buffer[0], 0xDE);
    assert_int_equal(G_io_tx_buffer[1], 0xAD);
    assert_int_equal(G_io_tx_buffer[2], 0xBE);
    assert_int_equal(G_io_tx_buffer[3], 0xEF);
    // Bytes past the encoded challenge must be untouched (we wrote 4,
    // the caller's sentinel must still be intact at offset 4..7).
    assert_int_equal(G_io_tx_buffer[4], 0x55);
}

static void test_handle_increments_existing_tx(void **state) {
    (void) state;
    // The caller passes the current response length; handle_get_challenge
    // must increment by 4, not overwrite.
    unsigned int tx = 7;
    (void) handle_get_challenge(&tx);
    assert_int_equal(tx, 11);
}

static void test_handle_reflects_current_challenge_after_reroll(void **state) {
    (void) state;
    roll_challenge();  // → 0xCAFEBABE
    unsigned int tx = 0;
    (void) handle_get_challenge(&tx);
    assert_int_equal(G_io_tx_buffer[0], 0xCA);
    assert_int_equal(G_io_tx_buffer[1], 0xFE);
    assert_int_equal(G_io_tx_buffer[2], 0xBA);
    assert_int_equal(G_io_tx_buffer[3], 0xBE);
}

// =============================================================================
// Runner
// =============================================================================

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup(test_roll_seeds_challenge_from_rng, reset),
        cmocka_unit_test_setup(test_get_challenge_returns_current_value, reset),
        cmocka_unit_test_setup(test_check_accepts_current_challenge, reset),
        cmocka_unit_test_setup(test_check_rejects_off_by_one, reset),
        cmocka_unit_test_setup(test_check_rejects_zero, reset),
        cmocka_unit_test_setup(test_check_rejects_unrelated_value, reset),
        cmocka_unit_test_setup(test_roll_replaces_previous_challenge, reset),
        cmocka_unit_test_setup(test_after_roll_old_challenge_is_rejected, reset),
        cmocka_unit_test_setup(test_check_does_not_mutate_state, reset),
        cmocka_unit_test_setup(test_handle_writes_big_endian, reset),
        cmocka_unit_test_setup(test_handle_increments_existing_tx, reset),
        cmocka_unit_test_setup(test_handle_reflects_current_challenge_after_reroll, reset),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
