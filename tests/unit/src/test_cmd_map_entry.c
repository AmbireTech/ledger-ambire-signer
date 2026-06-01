/**
 * @file test_cmd_map_entry.c
 * @brief Unit tests for the INS_PROVIDE_MAP_ENTRY APDU entry point at
 *        src/features/provide_map_entry/cmd_map_entry.c.
 *
 * The deep parsing path (handle_map_entry_tlv_payload +
 * verify_map_entry_struct) is already covered by test_provide_map_entry;
 * this slice pins the entry-point guards added by commit 092cba0c:
 *   - P1 must be either P1_FIRST_CHUNK or P1_FOLLOWING_CHUNK,
 *     anything else returns SWO_WRONG_P1_P2,
 *   - P2 must be 0, anything else returns SWO_WRONG_P1_P2,
 * plus the standard tlv_from_apdu success / failure mapping to
 * SWO_SUCCESS / SWO_INCORRECT_DATA.
 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

#include "cmd_map_entry.h"
#include "apdu_constants.h"
#include "status_words.h"
#include "tlv_apdu.h"

// =============================================================================
// Wraps
// =============================================================================

static e_tlv_apdu_ret g_tlv_ret = TLV_APDU_SUCCESS;
static bool g_invoke_handler = false;
static bool g_handler_returned = false;
e_tlv_apdu_ret __wrap_tlv_from_apdu(bool first_chunk,
                                    uint8_t lc,
                                    const uint8_t *payload,
                                    f_tlv_payload_handler handler) {
    (void) first_chunk;
    (void) lc;
    (void) payload;
    if (g_invoke_handler && handler != NULL) {
        buffer_t buf = {.ptr = NULL, .size = 0, .offset = 0};
        g_handler_returned = handler(&buf);
    }
    return g_tlv_ret;
}

// The static handle_tlv_payload helpers reference these symbols; the
// invoke-handler tests below drive their return values to exercise
// each branch in cmd_map_entry's static handle_tlv_payload.
static bool g_handle_payload_ret = true;
static bool g_verify_ret = true;
bool handle_map_entry_tlv_payload(const void *buf, void *ctx) {
    (void) buf;
    (void) ctx;
    return g_handle_payload_ret;
}
bool verify_map_entry_struct(const void *ctx) {
    (void) ctx;
    return g_verify_ret;
}
// cx_sha256_init_no_throw is the underlying call cx_sha256_init wraps.
// Linker needs the symbol even though the static handle_tlv_payload
// that calls it is never reached (tlv_from_apdu is wrapped).
cx_err_t cx_sha256_init_no_throw(cx_sha256_t *hash) {
    (void) hash;
    return CX_OK;
}

// =============================================================================
// Fixture
// =============================================================================

static int reset(void **state) {
    (void) state;
    g_tlv_ret = TLV_APDU_SUCCESS;
    g_invoke_handler = false;
    g_handler_returned = false;
    g_handle_payload_ret = true;
    g_verify_ret = true;
    return 0;
}

// =============================================================================
// P1 validation (commit 092cba0c)
// =============================================================================

static void test_p1_first_chunk_accepted(void **state) {
    (void) state;
    assert_int_equal(handle_map_entry(P1_FIRST_CHUNK, 0, 0, NULL), SWO_SUCCESS);
}

static void test_p1_following_chunk_accepted(void **state) {
    (void) state;
    assert_int_equal(handle_map_entry(P1_FOLLOWING_CHUNK, 0, 0, NULL), SWO_SUCCESS);
}

static void test_p1_reserved_value_rejected(void **state) {
    (void) state;
    // 0x02 is reserved (only 0x00 = FOLLOWING and 0x01 = FIRST are valid).
    assert_int_equal(handle_map_entry(0x02, 0, 0, NULL), SWO_WRONG_P1_P2);
}

static void test_p1_junk_value_rejected(void **state) {
    (void) state;
    assert_int_equal(handle_map_entry(0x42, 0, 0, NULL), SWO_WRONG_P1_P2);
    assert_int_equal(handle_map_entry(0xFF, 0, 0, NULL), SWO_WRONG_P1_P2);
}

// =============================================================================
// P2 validation (commit 092cba0c)
// =============================================================================

static void test_p2_nonzero_rejected_even_with_valid_p1(void **state) {
    (void) state;
    // P1 is valid but P2 is non-zero — must still reject.
    assert_int_equal(handle_map_entry(P1_FIRST_CHUNK, 0x01, 0, NULL), SWO_WRONG_P1_P2);
    assert_int_equal(handle_map_entry(P1_FOLLOWING_CHUNK, 0xFF, 0, NULL), SWO_WRONG_P1_P2);
}

// =============================================================================
// tlv_from_apdu integration
// =============================================================================

static void test_tlv_failure_returns_incorrect_data(void **state) {
    (void) state;
    g_tlv_ret = TLV_APDU_ERROR;
    assert_int_equal(handle_map_entry(P1_FIRST_CHUNK, 0, 0, NULL), SWO_INCORRECT_DATA);
}

static void test_tlv_success_returns_success(void **state) {
    (void) state;
    g_tlv_ret = TLV_APDU_SUCCESS;
    assert_int_equal(handle_map_entry(P1_FOLLOWING_CHUNK, 0, 0, NULL), SWO_SUCCESS);
}

// =============================================================================
// Internal handle_tlv_payload — exercised through the wrap
// =============================================================================

static void test_handler_happy_path(void **state) {
    (void) state;
    g_invoke_handler = true;
    handle_map_entry(P1_FIRST_CHUNK, 0, 0, NULL);
    assert_true(g_handler_returned);
}

static void test_handler_payload_failure(void **state) {
    (void) state;
    g_invoke_handler = true;
    g_handle_payload_ret = false;
    handle_map_entry(P1_FIRST_CHUNK, 0, 0, NULL);
    assert_false(g_handler_returned);
}

static void test_handler_verify_failure(void **state) {
    (void) state;
    g_invoke_handler = true;
    g_verify_ret = false;
    handle_map_entry(P1_FIRST_CHUNK, 0, 0, NULL);
    assert_false(g_handler_returned);
}

// =============================================================================
// Runner
// =============================================================================

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup(test_p1_first_chunk_accepted, reset),
        cmocka_unit_test_setup(test_p1_following_chunk_accepted, reset),
        cmocka_unit_test_setup(test_p1_reserved_value_rejected, reset),
        cmocka_unit_test_setup(test_p1_junk_value_rejected, reset),
        cmocka_unit_test_setup(test_p2_nonzero_rejected_even_with_valid_p1, reset),
        cmocka_unit_test_setup(test_tlv_failure_returns_incorrect_data, reset),
        cmocka_unit_test_setup(test_tlv_success_returns_success, reset),
        cmocka_unit_test_setup(test_handler_happy_path, reset),
        cmocka_unit_test_setup(test_handler_payload_failure, reset),
        cmocka_unit_test_setup(test_handler_verify_failure, reset),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
