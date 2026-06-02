/**
 * @file test_cmd_safe_account.c
 * @brief Unit tests for handle_safe_account / clear_safe_account at
 *        src/features/provide_safe_account/cmd_safe_account.c.
 *
 * The Safe Account APDU sequence is the host's way of saying "this
 * transaction is a Gnosis Safe execTransaction; here is the Safe
 * descriptor and the signer list". It's a small state machine:
 *
 *   1. P2 = SAFE_DESCRIPTOR (0x00): first APDU sets SAFE_DESC. Refused if
 *      SAFE_DESC already exists (anti-replay across the same review).
 *   2. P2 = SIGNER_DESCRIPTOR (0x01): subsequent APDUs set the signer list.
 *      Refused if SAFE_DESC is missing (state mismatch) or if
 *      SIGNER_DESC.data is already populated (one set only).
 *   3. When SIGNER_DESC.is_valid flips true after parsing, the review
 *      screen is shown synchronously and the handler returns
 *      SWO_NO_RESPONSE (the UI thread will reply later).
 *
 * Pin every reject / accept branch plus the small clear_safe_account
 * helper. The TLV parsing itself is pinned by test_safe_descriptors.
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
#include "cmd_safe_account.h"
#include "safe_descriptor.h"
#include "signer_descriptor.h"

// =============================================================================
// Globals the unit under test reads
// =============================================================================
// SAFE_DESC and SIGNER_DESC are declared `extern` in safe_descriptor.h /
// signer_descriptor.h. We're not linking the real .c files, so provide
// storage here.
safe_descriptor_t *SAFE_DESC;
signers_descriptor_t SIGNER_DESC;

// =============================================================================
// Wraps
// =============================================================================

static bool g_capture_first_chunk = false;
static uint8_t g_capture_lc = 0;
static f_tlv_payload_handler g_captured_handler = NULL;

bool __wrap_tlv_from_apdu(bool first_chunk,
                          uint8_t lc,
                          const uint8_t *payload,
                          f_tlv_payload_handler handler) {
    (void) payload;
    g_capture_first_chunk = first_chunk;
    g_capture_lc = lc;
    g_captured_handler = handler;
    return (bool) mock();
}

bool __wrap_handle_safe_tlv_payload(const buffer_t *payload) {
    (void) payload;
    return (bool) mock();
}

bool __wrap_handle_signer_tlv_payload(const buffer_t *payload) {
    (void) payload;
    return (bool) mock();
}

static int g_ui_display_calls = 0;
void __wrap_ui_display_safe_account(void) {
    g_ui_display_calls++;
}

static int g_clear_safe_calls = 0;
void __wrap_clear_safe_descriptor(void) {
    g_clear_safe_calls++;
    SAFE_DESC = NULL;
}

static int g_clear_signer_calls = 0;
void __wrap_clear_signer_descriptor(void) {
    g_clear_signer_calls++;
    memset(&SIGNER_DESC, 0, sizeof(SIGNER_DESC));
}

// =============================================================================
// Fixture
// =============================================================================

// Backing storage for the SAFE_DESC pointer when a test wants to simulate
// "already-existing descriptor".
static safe_descriptor_t s_safe_storage;

static int reset(void **state) {
    (void) state;
    SAFE_DESC = NULL;
    memset(&SIGNER_DESC, 0, sizeof(SIGNER_DESC));
    memset(&s_safe_storage, 0, sizeof(s_safe_storage));
    g_capture_first_chunk = false;
    g_capture_lc = 0;
    g_captured_handler = NULL;
    g_ui_display_calls = 0;
    g_clear_safe_calls = 0;
    g_clear_signer_calls = 0;
    return 0;
}

// =============================================================================
// p1 / p2 sanity rejects (no TLV path entered)
// =============================================================================

static void test_invalid_p1_rejected(void **state) {
    (void) state;
    // tlv_from_apdu MUST NOT be reached -- the queue is intentionally empty.
    uint16_t sw = handle_safe_account(/*p1*/ 0xFF, /*p2*/ 0, (uint8_t *) "", 32);
    assert_int_equal(sw, SWO_WRONG_P1_P2);
}

static void test_invalid_p2_rejected(void **state) {
    (void) state;
    uint16_t sw = handle_safe_account(P1_FIRST_CHUNK, /*p2*/ 0xEE, (uint8_t *) "", 32);
    assert_int_equal(sw, SWO_WRONG_P1_P2);
}

// =============================================================================
// State-machine rejects -- order-of-operations matters
// =============================================================================

static void test_safe_already_exists_rejected(void **state) {
    (void) state;
    // SAFE_DESC is already populated -- re-posting a SAFE_DESCRIPTOR APDU
    // would silently replace it. Refuse.
    SAFE_DESC = &s_safe_storage;
    uint16_t sw = handle_safe_account(P1_FIRST_CHUNK, /*p2*/ 0, (uint8_t *) "", 32);
    assert_int_equal(sw, SWO_FILE_ALREADY_EXISTS);
}

static void test_signer_without_safe_rejected(void **state) {
    (void) state;
    // Posting SIGNER_DESCRIPTOR before SAFE_DESCRIPTOR is a state-machine
    // violation -- without a Safe descriptor we have no contract address
    // to bind the signers to.
    SAFE_DESC = NULL;
    uint16_t sw = handle_safe_account(P1_FIRST_CHUNK, /*p2*/ 1, (uint8_t *) "", 32);
    assert_int_equal(sw, SWO_COMMAND_NOT_ALLOWED);
}

static void test_signer_already_exists_rejected(void **state) {
    (void) state;
    SAFE_DESC = &s_safe_storage;
    // Mark SIGNER_DESC.data as already populated. Any non-NULL value
    // triggers the guard.
    static signer_data_t fake;
    SIGNER_DESC.data = &fake;
    uint16_t sw = handle_safe_account(P1_FIRST_CHUNK, /*p2*/ 1, (uint8_t *) "", 32);
    assert_int_equal(sw, SWO_FILE_ALREADY_EXISTS);
}

// =============================================================================
// Happy / sad TLV paths
// =============================================================================

static void test_safe_descriptor_tlv_failure_returns_incorrect_data(void **state) {
    (void) state;
    will_return(__wrap_tlv_from_apdu, false);
    uint16_t sw = handle_safe_account(P1_FIRST_CHUNK, /*p2*/ 0, (uint8_t *) "", 32);
    assert_int_equal(sw, SWO_INCORRECT_DATA);
    assert_true(g_capture_first_chunk);
    assert_ptr_equal(g_captured_handler, &handle_safe_tlv_payload);
}

static void test_safe_descriptor_tlv_success_returns_success(void **state) {
    (void) state;
    // First chunk of a SAFE_DESCRIPTOR; tlv_from_apdu accepts it but
    // SIGNER_DESC.is_valid stays false (no signer posted yet), so the
    // handler returns SWO_SUCCESS without showing the UI.
    will_return(__wrap_tlv_from_apdu, true);
    uint16_t sw = handle_safe_account(P1_FIRST_CHUNK, /*p2*/ 0, (uint8_t *) "", 32);
    assert_int_equal(sw, SWO_SUCCESS);
    assert_int_equal(g_ui_display_calls, 0);
}

static void test_signer_descriptor_tlv_failure_returns_incorrect_data(void **state) {
    (void) state;
    SAFE_DESC = &s_safe_storage;
    will_return(__wrap_tlv_from_apdu, false);
    uint16_t sw = handle_safe_account(P1_FOLLOWING_CHUNK, /*p2*/ 1, (uint8_t *) "", 32);
    assert_int_equal(sw, SWO_INCORRECT_DATA);
    assert_false(g_capture_first_chunk);
    assert_ptr_equal(g_captured_handler, &handle_signer_tlv_payload);
}

static void test_signer_complete_triggers_ui_and_no_response(void **state) {
    (void) state;
    // SAFE_DESC posted; SIGNER_DESC.data is NULL (not yet posted); after
    // tlv_from_apdu the parser flips SIGNER_DESC.is_valid true (last
    // chunk arrived). The dispatcher MUST show the UI synchronously and
    // report SWO_NO_RESPONSE so the foreground waits for user confirmation.
    SAFE_DESC = &s_safe_storage;
    will_return(__wrap_tlv_from_apdu, true);
    // Simulate the parser flipping is_valid by post-hooking the mock.
    SIGNER_DESC.is_valid = true;
    uint16_t sw = handle_safe_account(P1_FOLLOWING_CHUNK, /*p2*/ 1, (uint8_t *) "", 32);
    assert_int_equal(sw, SWO_NO_RESPONSE);
    assert_int_equal(g_ui_display_calls, 1);
}

static void test_signer_incomplete_still_returns_success_no_ui(void **state) {
    (void) state;
    // Multi-chunk SIGNER stream: a non-last chunk parses successfully but
    // SIGNER_DESC.is_valid stays false -- the dispatcher reports SWO_SUCCESS
    // and the host keeps streaming.
    SAFE_DESC = &s_safe_storage;
    will_return(__wrap_tlv_from_apdu, true);
    SIGNER_DESC.is_valid = false;
    uint16_t sw = handle_safe_account(P1_FOLLOWING_CHUNK, /*p2*/ 1, (uint8_t *) "", 32);
    assert_int_equal(sw, SWO_SUCCESS);
    assert_int_equal(g_ui_display_calls, 0);
}

// =============================================================================
// clear_safe_account -- bundles the two underlying clears
// =============================================================================

static void test_clear_safe_account_clears_both(void **state) {
    (void) state;
    clear_safe_account();
    assert_int_equal(g_clear_safe_calls, 1);
    assert_int_equal(g_clear_signer_calls, 1);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup(test_invalid_p1_rejected, reset),
        cmocka_unit_test_setup(test_invalid_p2_rejected, reset),
        cmocka_unit_test_setup(test_safe_already_exists_rejected, reset),
        cmocka_unit_test_setup(test_signer_without_safe_rejected, reset),
        cmocka_unit_test_setup(test_signer_already_exists_rejected, reset),
        cmocka_unit_test_setup(test_safe_descriptor_tlv_failure_returns_incorrect_data, reset),
        cmocka_unit_test_setup(test_safe_descriptor_tlv_success_returns_success, reset),
        cmocka_unit_test_setup(test_signer_descriptor_tlv_failure_returns_incorrect_data, reset),
        cmocka_unit_test_setup(test_signer_complete_triggers_ui_and_no_response, reset),
        cmocka_unit_test_setup(test_signer_incomplete_still_returns_success_no_ui, reset),
        cmocka_unit_test_setup(test_clear_safe_account_clears_both, reset),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
