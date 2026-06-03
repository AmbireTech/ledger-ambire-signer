/**
 * @file test_cmd_proxy_info.c
 * @brief Unit tests for handle_proxy_info at
 *        src/features/provide_proxy_info/cmd_proxy_info.c.
 *
 * cmd_proxy_info is the wire-format APDU handler that the host calls to
 * register a (chain_id, proxy_address) -> implementation_address mapping.
 * The mapping is later consulted by the GCS dispatcher: when the user
 * signs a transaction targeting <proxy>, the device looks up the registered
 * <implementation> so the plugin / trusted-name layer can show the user
 * which contract is actually invoked through the proxy.
 *
 * The TLV body itself is parsed (handle_proxy_info_tlv_payload) and the
 * signature is verified (verify_proxy_info_struct) by code already covered
 * by test_proxy_info -- this file pins only the APDU framing:
 *
 *  - p1 == P1_FIRST_CHUNK is forwarded as first_chunk=true to tlv_from_apdu
 *  - p1 != P1_FIRST_CHUNK is forwarded as first_chunk=false
 *  - tlv_from_apdu returns TLV_APDU_ERROR -> SWO_INCORRECT_DATA + proxy_cleanup
 *  - tlv_from_apdu returns TLV_APDU_PENDING -> SWO_SUCCESS (no cleanup, more
 *    chunks expected)
 *  - tlv_from_apdu returns TLV_APDU_SUCCESS -> SWO_SUCCESS
 *  - the in-callback path runs handle_proxy_info_tlv_payload + verify; both
 *    must succeed for the callback to return true. Each leaf failure
 *    propagates as a false callback return.
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
#include "cmd_proxy_info.h"
#include "proxy_info.h"
#include "wraps.h"

// =============================================================================
// Wraps
// =============================================================================
// __wrap_tlv_from_apdu lives in mocks/mock.c and captures (first_chunk,
// lc, handler) into g_tlv_from_apdu_*. g_tlv_from_apdu_invoke_handler
// toggles the in-callback path so the in-test assertions can either
// stop at tlv_from_apdu (framing only) or run the inner
// handle_proxy_info_tlv_payload + verify_proxy_info_struct chain.

bool __wrap_handle_proxy_info_tlv_payload(const buffer_t *buf, s_proxy_info_ctx *ctx) {
    (void) buf;
    (void) ctx;
    return (bool) mock();
}

bool __wrap_verify_proxy_info_struct(const s_proxy_info_ctx *ctx) {
    (void) ctx;
    return (bool) mock();
}

static int g_cleanup_calls = 0;
void __wrap_proxy_cleanup(void) {
    g_cleanup_calls++;
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
    g_cleanup_calls = 0;
    return 0;
}

// =============================================================================
// APDU framing -- p1 -> first_chunk dispatch
// =============================================================================

static void test_p1_first_chunk_forwards_true(void **state) {
    (void) state;
    g_tlv_from_apdu_ret = TLV_APDU_SUCCESS;
    uint16_t sw = handle_proxy_info(P1_FIRST_CHUNK, /*p2*/ 0, /*lc*/ 32, (uint8_t *) "");
    assert_int_equal(sw, SWO_SUCCESS);
    assert_true(g_tlv_from_apdu_first_chunk);
    assert_int_equal(g_tlv_from_apdu_lc, 32);
}

static void test_p1_not_first_chunk_forwards_false(void **state) {
    (void) state;
    g_tlv_from_apdu_ret = TLV_APDU_SUCCESS;
    uint16_t sw = handle_proxy_info(P1_FOLLOWING_CHUNK, 0, 16, (uint8_t *) "");
    assert_int_equal(sw, SWO_SUCCESS);
    assert_false(g_tlv_from_apdu_first_chunk);
    assert_int_equal(g_tlv_from_apdu_lc, 16);
}

// =============================================================================
// tlv_from_apdu return value propagates to SW
// =============================================================================

static void test_tlv_apdu_error_returns_incorrect_data_and_cleans_up(void **state) {
    (void) state;
    g_tlv_from_apdu_ret = TLV_APDU_ERROR;
    uint16_t sw = handle_proxy_info(P1_FIRST_CHUNK, 0, 32, (uint8_t *) "");
    assert_int_equal(sw, SWO_INCORRECT_DATA);
    // proxy_cleanup() MUST be called on error so a half-parsed proxy entry
    // doesn't linger in the global registry across APDU sequences.
    assert_int_equal(g_cleanup_calls, 1);
}

static void test_tlv_apdu_pending_returns_success_without_cleanup(void **state) {
    (void) state;
    // PENDING signals "more chunks coming". The dispatcher must report
    // SWO_SUCCESS upstream so the host keeps streaming, and MUST NOT
    // run cleanup -- that would wipe the in-flight parser state.
    g_tlv_from_apdu_ret = TLV_APDU_PENDING;
    uint16_t sw = handle_proxy_info(P1_FIRST_CHUNK, 0, 32, (uint8_t *) "");
    assert_int_equal(sw, SWO_SUCCESS);
    assert_int_equal(g_cleanup_calls, 0);
}

static void test_tlv_apdu_success_returns_success(void **state) {
    (void) state;
    g_tlv_from_apdu_ret = TLV_APDU_SUCCESS;
    uint16_t sw = handle_proxy_info(P1_FIRST_CHUNK, 0, 32, (uint8_t *) "");
    assert_int_equal(sw, SWO_SUCCESS);
    assert_int_equal(g_cleanup_calls, 0);
}

// =============================================================================
// Inner handle_tlv_payload callback -- payload then verify
// =============================================================================

static void test_inner_callback_runs_payload_then_verify(void **state) {
    (void) state;
    // Drive the static handle_tlv_payload through tlv_from_apdu: payload
    // parser returns true, verifier returns true -> callback's overall
    // outcome is true (observable indirectly through the cleanup count
    // and the queue staying empty on exit).
    g_tlv_from_apdu_invoke_handler = true;
    will_return(__wrap_handle_proxy_info_tlv_payload, true);
    will_return(__wrap_verify_proxy_info_struct, true);
    g_tlv_from_apdu_ret = TLV_APDU_SUCCESS;
    uint16_t sw = handle_proxy_info(P1_FIRST_CHUNK, 0, 32, (uint8_t *) "");
    assert_int_equal(sw, SWO_SUCCESS);
    // proxy_cleanup is called from the callback prelude (before parser).
    assert_int_equal(g_cleanup_calls, 1);
}

static void test_inner_callback_short_circuits_on_payload_failure(void **state) {
    (void) state;
    g_tlv_from_apdu_invoke_handler = true;
    will_return(__wrap_handle_proxy_info_tlv_payload, false);
    // verify_proxy_info_struct MUST NOT be reached -- a failed parse
    // means there's nothing to verify. Leaving its queue empty is the
    // safety check.
    g_tlv_from_apdu_ret = TLV_APDU_ERROR;
    uint16_t sw = handle_proxy_info(P1_FIRST_CHUNK, 0, 32, (uint8_t *) "");
    assert_int_equal(sw, SWO_INCORRECT_DATA);
    assert_int_equal(g_cleanup_calls, 2);  // once in callback, once on error
}

static void test_inner_callback_rejects_when_verify_fails(void **state) {
    (void) state;
    g_tlv_from_apdu_invoke_handler = true;
    will_return(__wrap_handle_proxy_info_tlv_payload, true);
    will_return(__wrap_verify_proxy_info_struct, false);
    g_tlv_from_apdu_ret = TLV_APDU_ERROR;
    uint16_t sw = handle_proxy_info(P1_FIRST_CHUNK, 0, 32, (uint8_t *) "");
    assert_int_equal(sw, SWO_INCORRECT_DATA);
    assert_int_equal(g_cleanup_calls, 2);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup(test_p1_first_chunk_forwards_true, reset),
        cmocka_unit_test_setup(test_p1_not_first_chunk_forwards_false, reset),
        cmocka_unit_test_setup(test_tlv_apdu_error_returns_incorrect_data_and_cleans_up, reset),
        cmocka_unit_test_setup(test_tlv_apdu_pending_returns_success_without_cleanup, reset),
        cmocka_unit_test_setup(test_tlv_apdu_success_returns_success, reset),
        cmocka_unit_test_setup(test_inner_callback_runs_payload_then_verify, reset),
        cmocka_unit_test_setup(test_inner_callback_short_circuits_on_payload_failure, reset),
        cmocka_unit_test_setup(test_inner_callback_rejects_when_verify_fails, reset),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
