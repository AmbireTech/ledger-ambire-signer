/**
 * @file test_cmd_trusted_name.c
 * @brief Unit tests for handle_trusted_name at
 *        src/features/provide_trusted_name/cmd_trusted_name.c.
 *
 * cmd_trusted_name is the APDU framing around the trusted-name registry
 * (TRUSTED_NAME APDU). The host streams a TLV blob (one or more chunks);
 * the device parses it via handle_trusted_name_tlv_payload, verifies the
 * Ledger backend signature via verify_trusted_name_struct, and finally
 * advances the per-session challenge nonce via roll_challenge so a
 * replay of the same payload is rejected.
 *
 * The TLV parser and verifier are pinned by test_trusted_name. This file
 * only covers the APDU framing:
 *
 *  - p1 == P1_FIRST_CHUNK -> first_chunk=true forwarded to tlv_from_apdu
 *  - p1 != P1_FIRST_CHUNK -> first_chunk=false
 *  - tlv_from_apdu returns TLV_APDU_ERROR   -> SWO_INCORRECT_DATA
 *  - tlv_from_apdu returns TLV_APDU_PENDING -> SWO_SUCCESS (more chunks)
 *  - tlv_from_apdu returns TLV_APDU_SUCCESS -> SWO_SUCCESS
 *  - inner callback path runs parser + verifier; roll_challenge MUST be
 *    called after verify regardless of its outcome (CWE-294 anti-replay).
 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

#include "shared_context.h"
#include "apdu_constants.h"
#include "tlv_apdu.h"
#include "cmd_trusted_name.h"
#include "trusted_name.h"
#include "wraps.h"

// =============================================================================
// Wraps
// =============================================================================

bool __wrap_handle_trusted_name_tlv_payload(const buffer_t *buf, s_trusted_name_ctx *ctx) {
    (void) buf;
    (void) ctx;
    return (bool) mock();
}

bool __wrap_verify_trusted_name_struct(const s_trusted_name_ctx *ctx) {
    (void) ctx;
    return (bool) mock();
}

static int g_roll_calls = 0;
void __wrap_roll_challenge(void) {
    g_roll_calls++;
}

// =============================================================================
// Fixture
// =============================================================================

static int reset(void **state) {
    (void) state;
    g_tlv_from_apdu_invoke_handler = false;
    g_tlv_from_apdu_first_chunk = false;
    g_tlv_from_apdu_lc = 0;
    g_tlv_from_apdu_ret = TLV_APDU_SUCCESS;
    g_roll_calls = 0;
    return 0;
}

// =============================================================================
// APDU framing -- p1 -> first_chunk dispatch
// =============================================================================

static void test_p1_first_chunk_forwards_true(void **state) {
    (void) state;
    g_tlv_from_apdu_ret = TLV_APDU_SUCCESS;
    uint16_t sw = handle_trusted_name(P1_FIRST_CHUNK, (uint8_t *) "", 32);
    assert_int_equal(sw, SWO_SUCCESS);
    assert_true(g_tlv_from_apdu_first_chunk);
    assert_int_equal(g_tlv_from_apdu_lc, 32);
}

static void test_p1_not_first_chunk_forwards_false(void **state) {
    (void) state;
    g_tlv_from_apdu_ret = TLV_APDU_SUCCESS;
    uint16_t sw = handle_trusted_name(P1_FOLLOWING_CHUNK, (uint8_t *) "", 16);
    assert_int_equal(sw, SWO_SUCCESS);
    assert_false(g_tlv_from_apdu_first_chunk);
}

// =============================================================================
// tlv_from_apdu return value propagates to SW
// =============================================================================

static void test_tlv_apdu_error_returns_incorrect_data(void **state) {
    (void) state;
    g_tlv_from_apdu_ret = TLV_APDU_ERROR;
    uint16_t sw = handle_trusted_name(P1_FIRST_CHUNK, (uint8_t *) "", 32);
    assert_int_equal(sw, SWO_INCORRECT_DATA);
}

static void test_tlv_apdu_pending_returns_success(void **state) {
    (void) state;
    g_tlv_from_apdu_ret = TLV_APDU_PENDING;
    uint16_t sw = handle_trusted_name(P1_FIRST_CHUNK, (uint8_t *) "", 32);
    assert_int_equal(sw, SWO_SUCCESS);
}

static void test_tlv_apdu_success_returns_success(void **state) {
    (void) state;
    g_tlv_from_apdu_ret = TLV_APDU_SUCCESS;
    uint16_t sw = handle_trusted_name(P1_FIRST_CHUNK, (uint8_t *) "", 32);
    assert_int_equal(sw, SWO_SUCCESS);
}

// =============================================================================
// Inner handle_tlv_payload callback
// =============================================================================

static void test_inner_callback_runs_payload_then_verify_then_roll(void **state) {
    (void) state;
    g_tlv_from_apdu_invoke_handler = true;
    will_return(__wrap_handle_trusted_name_tlv_payload, true);
    will_return(__wrap_verify_trusted_name_struct, true);
    g_tlv_from_apdu_ret = TLV_APDU_SUCCESS;
    uint16_t sw = handle_trusted_name(P1_FIRST_CHUNK, (uint8_t *) "", 32);
    assert_int_equal(sw, SWO_SUCCESS);
    // roll_challenge MUST be called after verify on the success path to
    // burn the challenge nonce -- otherwise the host could replay the
    // same signed payload across sessions (CWE-294).
    assert_int_equal(g_roll_calls, 1);
}

static void test_inner_callback_rolls_challenge_even_on_verify_failure(void **state) {
    (void) state;
    // CRITICAL: the design rolls the challenge AFTER verify regardless of
    // the result, so a brute-force attacker can't probe many candidate
    // signatures against the same nonce. If a future refactor short-
    // circuits roll_challenge on verify-failure, this test catches it.
    g_tlv_from_apdu_invoke_handler = true;
    will_return(__wrap_handle_trusted_name_tlv_payload, true);
    will_return(__wrap_verify_trusted_name_struct, false);
    g_tlv_from_apdu_ret = TLV_APDU_ERROR;
    uint16_t sw = handle_trusted_name(P1_FIRST_CHUNK, (uint8_t *) "", 32);
    assert_int_equal(sw, SWO_INCORRECT_DATA);
    assert_int_equal(g_roll_calls, 1);
}

static void test_inner_callback_short_circuits_on_payload_failure(void **state) {
    (void) state;
    // Parser failure short-circuits BEFORE verify, so roll_challenge MUST
    // NOT fire here -- the challenge can still be used on the next
    // genuine attempt.
    g_tlv_from_apdu_invoke_handler = true;
    will_return(__wrap_handle_trusted_name_tlv_payload, false);
    g_tlv_from_apdu_ret = TLV_APDU_ERROR;
    uint16_t sw = handle_trusted_name(P1_FIRST_CHUNK, (uint8_t *) "", 32);
    assert_int_equal(sw, SWO_INCORRECT_DATA);
    assert_int_equal(g_roll_calls, 0);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup(test_p1_first_chunk_forwards_true, reset),
        cmocka_unit_test_setup(test_p1_not_first_chunk_forwards_false, reset),
        cmocka_unit_test_setup(test_tlv_apdu_error_returns_incorrect_data, reset),
        cmocka_unit_test_setup(test_tlv_apdu_pending_returns_success, reset),
        cmocka_unit_test_setup(test_tlv_apdu_success_returns_success, reset),
        cmocka_unit_test_setup(test_inner_callback_runs_payload_then_verify_then_roll, reset),
        cmocka_unit_test_setup(test_inner_callback_rolls_challenge_even_on_verify_failure, reset),
        cmocka_unit_test_setup(test_inner_callback_short_circuits_on_payload_failure, reset),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
