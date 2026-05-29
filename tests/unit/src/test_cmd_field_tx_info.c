/**
 * @file test_cmd_field_tx_info.c
 * @brief Unit tests for the two GCS APDU command entry points at
 *        src/features/generic_tx_parser/cmd_field.c and
 *        src/features/generic_tx_parser/cmd_tx_info.c.
 *
 * Both commands are thin wrappers around the deeper parsing layers:
 * each one gates on appState (must be SIGNING_TX or SIGNING_EIP712),
 * cmd_field additionally requires that a current tx_info has been
 * registered, then both delegate to tlv_from_apdu() which streams the
 * TLV payload into the static handle_tlv_payload.
 *
 * The deep parsing path is already covered by test_tx_info /
 * test_field_validation / test_tx_ctx; this slice focuses on the
 * entry-point glue: status-word returns on guard failures and on
 * tlv_from_apdu success / failure.
 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

#include "cmd_field.h"
#include "cmd_tx_info.h"
#include "gtp_tx_info.h"
#include "gtp_field.h"
#include "tx_ctx.h"
#include "apdu_constants.h"
#include "shared_context.h"
#include "status_words.h"
#include "tlv_apdu.h"
#include "cx.h"

// =============================================================================
// Globals
// =============================================================================

strings_t strings;
static chain_config_t g_chainConfig = {.ticker = "ETH", .chain_id = 1, .coin_type = 60};
const chain_config_t *g_chain_config = &g_chainConfig;
const char g_unknown_ticker[] = "???";
txContext_t txContext;
tmpContent_t tmpContent;
uint8_t appState = APP_STATE_IDLE;

// =============================================================================
// Wraps
// =============================================================================

// tlv_from_apdu is the seam — control its return value per test.
// Caller treats return as a bool (`if (!tlv_from_apdu(...))`), so
// TLV_APDU_ERROR == 0 means "fail" and any non-zero (PENDING, SUCCESS)
// is "ok".
static e_tlv_apdu_ret g_tlv_from_apdu_ret = TLV_APDU_SUCCESS;
e_tlv_apdu_ret __wrap_tlv_from_apdu(bool first_chunk,
                                    uint8_t lc,
                                    const uint8_t *payload,
                                    f_tlv_payload_handler handler) {
    (void) first_chunk;
    (void) lc;
    (void) payload;
    (void) handler;
    return g_tlv_from_apdu_ret;
}

// cmd_field reads from get_current_tx_info — control it via a wrap.
static const s_tx_info *g_tx_info_ret = NULL;
const s_tx_info *__wrap_get_current_tx_info(void) {
    return g_tx_info_ret;
}

// cmd_field calls gcs_cleanup on the no-tx-info path — count calls.
static int g_gcs_cleanup_calls = 0;
void __wrap_gcs_cleanup(void) {
    g_gcs_cleanup_calls++;
}

// The static handle_tlv_payload helpers pull these symbols in at link
// time. None of them are reached by these tests because we stub
// tlv_from_apdu to never invoke the handler — but the linker still
// needs definitions matching the real signatures.
bool handle_field_struct(const buffer_t *buf, s_field_ctx *ctx) {
    (void) buf;
    (void) ctx;
    return true;
}
void cleanup_field(s_field *field) {
    (void) field;
}
cx_hash_t *get_fields_hash_ctx(void) {
    return NULL;
}
cx_err_t cx_hash_no_throw(cx_hash_t *hash,
                          uint32_t mode,
                          const uint8_t *in,
                          size_t l,
                          uint8_t *out,
                          size_t ol) {
    (void) hash;
    (void) mode;
    (void) in;
    (void) l;
    (void) out;
    (void) ol;
    return CX_OK;
}
bool verify_field_struct(const s_field_ctx *ctx) {
    (void) ctx;
    return true;
}
bool format_field(s_field *f, uint8_t depth) {
    (void) f;
    (void) depth;
    return true;
}
bool process_empty_txs_after(void) {
    return true;
}
bool process_empty_txs_before(void) {
    return true;
}
void tx_ctx_pop(void) {
}
bool tx_ctx_is_root(void) {
    return true;
}
bool validate_instruction_hash(void) {
    return false;
}
bool handle_tx_info_struct(const buffer_t *buf, s_tx_info_ctx *ctx) {
    (void) buf;
    (void) ctx;
    return true;
}
bool verify_tx_info_struct(const s_tx_info_ctx *ctx) {
    (void) ctx;
    return true;
}
bool find_matching_tx_ctx(const uint8_t *a, const uint8_t *s, const uint64_t *c) {
    (void) a;
    (void) s;
    (void) c;
    return true;
}
bool set_tx_info_into_tx_ctx(s_tx_info *info) {
    (void) info;
    return true;
}
cx_err_t cx_sha256_init_no_throw(cx_sha256_t *hash) {
    (void) hash;
    return CX_OK;
}

// =============================================================================
// Fixture
// =============================================================================

static int reset(void **state) {
    (void) state;
    appState = APP_STATE_IDLE;
    g_tlv_from_apdu_ret = TLV_APDU_SUCCESS;
    g_tx_info_ret = NULL;
    g_gcs_cleanup_calls = 0;
    return 0;
}

// =============================================================================
// handle_field — appState guard
// =============================================================================

static void test_field_wrong_appstate_rejected(void **state) {
    (void) state;
    appState = APP_STATE_IDLE;  // not SIGNING_TX / SIGNING_EIP712
    assert_int_equal(handle_field(P1_FIRST_CHUNK, 0, 0, NULL), SWO_COMMAND_NOT_ALLOWED);
}

static void test_field_signing_message_state_rejected(void **state) {
    (void) state;
    // Other signing states (MESSAGE, EIP7702) also do not allow field cmds.
    appState = APP_STATE_SIGNING_MESSAGE;
    assert_int_equal(handle_field(P1_FIRST_CHUNK, 0, 0, NULL), SWO_COMMAND_NOT_ALLOWED);
}

// =============================================================================
// handle_field — no current tx_info
// =============================================================================

static void test_field_no_tx_info_triggers_cleanup(void **state) {
    (void) state;
    appState = APP_STATE_SIGNING_TX;
    g_tx_info_ret = NULL;
    assert_int_equal(handle_field(P1_FIRST_CHUNK, 0, 0, NULL), SWO_COMMAND_NOT_ALLOWED);
    // The "no tx_info" branch invokes gcs_cleanup to drop any half-built
    // state before refusing the APDU.
    assert_int_equal(g_gcs_cleanup_calls, 1);
}

// =============================================================================
// handle_field — happy path delegates to tlv_from_apdu
// =============================================================================

static void test_field_tlv_failure_returns_incorrect_data(void **state) {
    (void) state;
    static const s_tx_info dummy = {0};
    g_tx_info_ret = &dummy;
    appState = APP_STATE_SIGNING_TX;
    g_tlv_from_apdu_ret = TLV_APDU_ERROR;
    assert_int_equal(handle_field(P1_FIRST_CHUNK, 0, 0, NULL), SWO_INCORRECT_DATA);
    // gcs_cleanup is NOT called on this path — only on the no-tx-info
    // branch.
    assert_int_equal(g_gcs_cleanup_calls, 0);
}

static void test_field_tlv_success_returns_success(void **state) {
    (void) state;
    static const s_tx_info dummy = {0};
    g_tx_info_ret = &dummy;
    appState = APP_STATE_SIGNING_TX;
    g_tlv_from_apdu_ret = TLV_APDU_SUCCESS;
    assert_int_equal(handle_field(P1_FIRST_CHUNK, 0, 0, NULL), SWO_SUCCESS);
}

static void test_field_signing_eip712_allowed(void **state) {
    (void) state;
    static const s_tx_info dummy = {0};
    g_tx_info_ret = &dummy;
    appState = APP_STATE_SIGNING_EIP712;
    g_tlv_from_apdu_ret = TLV_APDU_SUCCESS;
    assert_int_equal(handle_field(P1_FIRST_CHUNK, 0, 0, NULL), SWO_SUCCESS);
}

// =============================================================================
// handle_tx_info — appState guard
// =============================================================================

static void test_tx_info_wrong_appstate_rejected(void **state) {
    (void) state;
    appState = APP_STATE_IDLE;
    assert_int_equal(handle_tx_info(P1_FIRST_CHUNK, 0, 0, NULL), SWO_COMMAND_NOT_ALLOWED);
}

static void test_tx_info_signing_message_state_rejected(void **state) {
    (void) state;
    appState = APP_STATE_SIGNING_MESSAGE;
    assert_int_equal(handle_tx_info(P1_FIRST_CHUNK, 0, 0, NULL), SWO_COMMAND_NOT_ALLOWED);
}

// =============================================================================
// handle_tx_info — tlv_from_apdu paths
// =============================================================================

static void test_tx_info_tlv_failure_returns_incorrect_data(void **state) {
    (void) state;
    appState = APP_STATE_SIGNING_TX;
    g_tlv_from_apdu_ret = TLV_APDU_ERROR;
    assert_int_equal(handle_tx_info(P1_FIRST_CHUNK, 0, 0, NULL), SWO_INCORRECT_DATA);
}

static void test_tx_info_tlv_success_returns_success(void **state) {
    (void) state;
    appState = APP_STATE_SIGNING_TX;
    g_tlv_from_apdu_ret = TLV_APDU_SUCCESS;
    assert_int_equal(handle_tx_info(P1_FIRST_CHUNK, 0, 0, NULL), SWO_SUCCESS);
}

static void test_tx_info_eip712_signing_allowed(void **state) {
    (void) state;
    appState = APP_STATE_SIGNING_EIP712;
    g_tlv_from_apdu_ret = TLV_APDU_SUCCESS;
    assert_int_equal(handle_tx_info(P1_FIRST_CHUNK, 0, 0, NULL), SWO_SUCCESS);
}

// =============================================================================
// Runner
// =============================================================================

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup(test_field_wrong_appstate_rejected, reset),
        cmocka_unit_test_setup(test_field_signing_message_state_rejected, reset),
        cmocka_unit_test_setup(test_field_no_tx_info_triggers_cleanup, reset),
        cmocka_unit_test_setup(test_field_tlv_failure_returns_incorrect_data, reset),
        cmocka_unit_test_setup(test_field_tlv_success_returns_success, reset),
        cmocka_unit_test_setup(test_field_signing_eip712_allowed, reset),
        cmocka_unit_test_setup(test_tx_info_wrong_appstate_rejected, reset),
        cmocka_unit_test_setup(test_tx_info_signing_message_state_rejected, reset),
        cmocka_unit_test_setup(test_tx_info_tlv_failure_returns_incorrect_data, reset),
        cmocka_unit_test_setup(test_tx_info_tlv_success_returns_success, reset),
        cmocka_unit_test_setup(test_tx_info_eip712_signing_allowed, reset),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
