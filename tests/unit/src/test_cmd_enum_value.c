/**
 * @file test_cmd_enum_value.c
 * @brief Unit tests for handle_enum_value at
 *        src/features/provide_enum_value/cmd_enum_value.c.
 *
 * cmd_enum_value is the APDU framing around the enum-value registry
 * (PROVIDE_ENUM_VALUE APDU). The host streams a TLV-encoded mapping
 * `(chain_id, contract, selector, enum_id, value) -> display string` --
 * what the user actually sees when the contract returns an integer status
 * (e.g. AAVE health-factor band, Compound interest-rate mode). A bug
 * here lets the host display arbitrary strings against a real enum tag.
 *
 * The TLV parser + verifier are pinned by test_enum_value. This file
 * only covers the APDU framing:
 *
 *  - p1 == P1_FIRST_CHUNK -> first_chunk=true forwarded to tlv_from_apdu
 *  - p1 != P1_FIRST_CHUNK -> first_chunk=false
 *  - tlv_from_apdu returns TLV_APDU_ERROR   -> SWO_INCORRECT_DATA
 *  - tlv_from_apdu returns TLV_APDU_PENDING -> SWO_SUCCESS (more chunks)
 *  - tlv_from_apdu returns TLV_APDU_SUCCESS -> SWO_SUCCESS
 *  - inner callback path: payload-parse failure short-circuits before
 *    verify; verify failure also returns false.
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
#include "cmd_enum_value.h"
#include "enum_value.h"

// =============================================================================
// Wraps
// =============================================================================

static bool g_invoke_handler = false;
static bool g_capture_first_chunk = false;
static uint8_t g_capture_lc = 0;

e_tlv_apdu_ret __wrap_tlv_from_apdu(bool first_chunk,
                                    uint8_t lc,
                                    const uint8_t *payload,
                                    f_tlv_payload_handler handler) {
    (void) payload;
    g_capture_first_chunk = first_chunk;
    g_capture_lc = lc;
    if (g_invoke_handler && handler != NULL) {
        buffer_t buf = {.ptr = NULL, .size = 0, .offset = 0};
        (void) handler(&buf);
    }
    return (e_tlv_apdu_ret) mock();
}

bool __wrap_handle_enum_value_tlv_payload(const buffer_t *buf, s_enum_value_ctx *ctx) {
    (void) buf;
    (void) ctx;
    return (bool) mock();
}

bool __wrap_verify_enum_value_struct(const s_enum_value_ctx *ctx) {
    (void) ctx;
    return (bool) mock();
}

// =============================================================================
// Fixture
// =============================================================================

static int reset(void **state) {
    (void) state;
    g_invoke_handler = false;
    g_capture_first_chunk = false;
    g_capture_lc = 0;
    return 0;
}

// =============================================================================
// APDU framing
// =============================================================================

static void test_p1_first_chunk_forwards_true(void **state) {
    (void) state;
    will_return(__wrap_tlv_from_apdu, TLV_APDU_SUCCESS);
    uint16_t sw = handle_enum_value(P1_FIRST_CHUNK, /*p2*/ 0, /*lc*/ 24, (uint8_t *) "");
    assert_int_equal(sw, SWO_SUCCESS);
    assert_true(g_capture_first_chunk);
    assert_int_equal(g_capture_lc, 24);
}

static void test_p1_not_first_chunk_forwards_false(void **state) {
    (void) state;
    will_return(__wrap_tlv_from_apdu, TLV_APDU_SUCCESS);
    uint16_t sw = handle_enum_value(P1_FOLLOWING_CHUNK, 0, 16, (uint8_t *) "");
    assert_int_equal(sw, SWO_SUCCESS);
    assert_false(g_capture_first_chunk);
}

// =============================================================================
// tlv_from_apdu return value propagates to SW
// =============================================================================

static void test_tlv_apdu_error_returns_incorrect_data(void **state) {
    (void) state;
    will_return(__wrap_tlv_from_apdu, TLV_APDU_ERROR);
    uint16_t sw = handle_enum_value(P1_FIRST_CHUNK, 0, 32, (uint8_t *) "");
    assert_int_equal(sw, SWO_INCORRECT_DATA);
}

static void test_tlv_apdu_pending_returns_success(void **state) {
    (void) state;
    will_return(__wrap_tlv_from_apdu, TLV_APDU_PENDING);
    uint16_t sw = handle_enum_value(P1_FIRST_CHUNK, 0, 32, (uint8_t *) "");
    assert_int_equal(sw, SWO_SUCCESS);
}

static void test_tlv_apdu_success_returns_success(void **state) {
    (void) state;
    will_return(__wrap_tlv_from_apdu, TLV_APDU_SUCCESS);
    uint16_t sw = handle_enum_value(P1_FIRST_CHUNK, 0, 32, (uint8_t *) "");
    assert_int_equal(sw, SWO_SUCCESS);
}

// =============================================================================
// Inner handle_tlv_payload callback
// =============================================================================

static void test_inner_callback_runs_payload_then_verify(void **state) {
    (void) state;
    g_invoke_handler = true;
    will_return(__wrap_handle_enum_value_tlv_payload, true);
    will_return(__wrap_verify_enum_value_struct, true);
    will_return(__wrap_tlv_from_apdu, TLV_APDU_SUCCESS);
    uint16_t sw = handle_enum_value(P1_FIRST_CHUNK, 0, 32, (uint8_t *) "");
    assert_int_equal(sw, SWO_SUCCESS);
}

static void test_inner_callback_short_circuits_on_payload_failure(void **state) {
    (void) state;
    g_invoke_handler = true;
    will_return(__wrap_handle_enum_value_tlv_payload, false);
    // verify_enum_value_struct MUST NOT be reached.
    will_return(__wrap_tlv_from_apdu, TLV_APDU_ERROR);
    uint16_t sw = handle_enum_value(P1_FIRST_CHUNK, 0, 32, (uint8_t *) "");
    assert_int_equal(sw, SWO_INCORRECT_DATA);
}

static void test_inner_callback_rejects_when_verify_fails(void **state) {
    (void) state;
    g_invoke_handler = true;
    will_return(__wrap_handle_enum_value_tlv_payload, true);
    will_return(__wrap_verify_enum_value_struct, false);
    will_return(__wrap_tlv_from_apdu, TLV_APDU_ERROR);
    uint16_t sw = handle_enum_value(P1_FIRST_CHUNK, 0, 32, (uint8_t *) "");
    assert_int_equal(sw, SWO_INCORRECT_DATA);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup(test_p1_first_chunk_forwards_true, reset),
        cmocka_unit_test_setup(test_p1_not_first_chunk_forwards_false, reset),
        cmocka_unit_test_setup(test_tlv_apdu_error_returns_incorrect_data, reset),
        cmocka_unit_test_setup(test_tlv_apdu_pending_returns_success, reset),
        cmocka_unit_test_setup(test_tlv_apdu_success_returns_success, reset),
        cmocka_unit_test_setup(test_inner_callback_runs_payload_then_verify, reset),
        cmocka_unit_test_setup(test_inner_callback_short_circuits_on_payload_failure, reset),
        cmocka_unit_test_setup(test_inner_callback_rejects_when_verify_fails, reset),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
