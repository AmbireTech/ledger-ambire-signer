/**
 * @file test_commands_7702.c
 * @brief Unit tests for the EIP-7702 authorization-signing command at
 *        src/features/sign_authorization_eip7702/commands_7702.c.
 *
 * EIP-7702 lets an EOA temporarily delegate authority to contract
 * code. The handler runs in two halves:
 *   - handle_sign_eip7702_authorization() — the APDU entry point. On
 *     the first chunk it locks appState to APP_STATE_SIGNING_EIP7702
 *     after parsing the BIP32 path, on follow-up chunks it refuses
 *     anything outside that state. Both paths funnel the payload to
 *     tlv_from_apdu() with handle_auth7702_tlv as the handler.
 *   - handle_auth7702_tlv() — runs the TLV-parsed auth struct
 *     against the whitelist, recomputes the RLP-hashed authorization
 *     digest, and triggers the review UI.
 *
 * This slice covers the entry-point dispatcher (the appState lock,
 * the parseBip32 guard, the tlv_from_apdu success/failure paths).
 * The internal handle_auth7702_tlv is reachable only indirectly
 * through tlv_from_apdu and requires the full RLP/crypto/UI stack —
 * out of scope for this first commit.
 *
 * The appState lock is the load-bearing defense: without it a hostile
 * host could overwrite tmpCtx.authSigningContext7702.bip32 during a
 * pending review and trick the user into signing with a path that
 * differs from the one shown on screen.
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
#include "commands_7702.h"
#include "tlv_apdu.h"

// =============================================================================
// Globals the module reads — provide storage here.
// =============================================================================

strings_t strings;
static chain_config_t g_chainConfig = {.ticker = "ETH", .chain_id = 1, .coin_type = 60};
const chain_config_t *g_chain_config = &g_chainConfig;
const char g_unknown_ticker[] = "???";
txContext_t txContext;
tmpContent_t tmpContent;
tmpCtx_t tmpCtx;
dataContext_t dataContext;
uint8_t appState = APP_STATE_IDLE;
const internalStorage_t N_storage_real = {.eip7702_enable = true};

// =============================================================================
// Controllable stubs
// =============================================================================

// parseBip32 is a real function in main.c (not linked). Provide a
// controllable stub: when g_parsebip32_ok is true, returns dataBuffer
// (i.e. consumes nothing); when false, returns NULL.
static bool g_parsebip32_ok = true;
const uint8_t *parseBip32(const uint8_t *dataBuffer, uint8_t *dataLength, bip32_path_t *bip32) {
    (void) bip32;
    if (!g_parsebip32_ok) return NULL;
    // Real parseBip32 consumes 1 + 4*len bytes; for the tests we let
    // the entire buffer through unchanged so tlv_from_apdu sees the
    // same bytes the test passed.
    (void) dataLength;
    return dataBuffer;
}

// reset_app_context is implemented in main.c. Provide a minimal stub
// that just rewinds appState — that's the only field the tests
// observe.
void reset_app_context(void) {
    appState = APP_STATE_IDLE;
}

// tlv_from_apdu is the seam — we control its return through a flag.
// The handler argument is never invoked from these tests (handle_auth7702_tlv
// is exercised in a follow-up commit with the full RLP/UI stack).
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

// =============================================================================
// SDK / app-side stubs — none of these are invoked on the entry-point
// path (tlv_from_apdu is stubbed and the handler is never called) but
// the linker resolves them through this TU.
// =============================================================================

uint32_t cx_keccak_init_no_throw(cx_sha3_t *hash, size_t size) {
    (void) hash;
    (void) size;
    return 0;  // CX_OK
}
uint32_t cx_hash_no_throw(cx_hash_t *hash,
                          uint32_t mode,
                          const uint8_t *in,
                          size_t in_len,
                          uint8_t *out,
                          size_t out_len) {
    (void) hash;
    (void) mode;
    (void) in;
    (void) in_len;
    (void) out;
    (void) out_len;
    return 0;
}
bool __wrap_finalize_hash(cx_hash_t *hash_ctx, uint8_t *out, size_t out_len) {
    (void) hash_ctx;
    (void) out;
    (void) out_len;
    return true;
}

uint32_t get_public_key_string(bip32_path_t *bip32,
                               uint8_t *publicKey,
                               char *address,
                               uint8_t *chainCode,
                               uint64_t chainId) {
    (void) bip32;
    (void) publicKey;
    (void) address;
    (void) chainCode;
    (void) chainId;
    return 0;
}

const char *get_network_name_from_chain_id(const uint64_t *chain_id) {
    (void) chain_id;
    return NULL;
}

bool is_zeroes_buffer(const void *buf, size_t n) {
    const uint8_t *p = (const uint8_t *) buf;
    for (size_t i = 0; i < n; ++i) {
        if (p[i] != 0) return false;
    }
    return true;
}

void hash_nbytes(const uint8_t *bytes, size_t n, cx_hash_t *hash_ctx) {
    (void) bytes;
    (void) n;
    (void) hash_ctx;
}

// UI hooks — never reached on the entry-point path.
void ui_error_no_7702(void) {
}
void ui_error_no_7702_whitelist(void) {
}
void ui_sign_7702_auth(void) {
}
void ui_sign_7702_revocation(void) {
}

// =============================================================================
// Fixture
// =============================================================================

static int reset(void **state) {
    (void) state;
    appState = APP_STATE_IDLE;
    g_parsebip32_ok = true;
    g_tlv_from_apdu_ret = TLV_APDU_SUCCESS;
    memset(&tmpCtx, 0, sizeof(tmpCtx));
    return 0;
}

// =============================================================================
// Entry-point dispatch tests
// =============================================================================

static void test_first_chunk_when_not_idle_rejected(void **state) {
    (void) state;
    // The appState lock — a non-IDLE state at first-chunk arrival
    // means another flow is already running, so refuse.
    appState = APP_STATE_SIGNING_TX;
    uint8_t payload[16] = {0};
    uint16_t sw = handle_sign_eip7702_authorization(P1_FIRST_CHUNK, payload, sizeof(payload));
    assert_int_equal(sw, SWO_COMMAND_NOT_ALLOWED);
    // appState must not have been clobbered by the rejected attempt.
    assert_int_equal(appState, APP_STATE_SIGNING_TX);
}

static void test_first_chunk_parseBip32_failure_resets_app_context(void **state) {
    (void) state;
    g_parsebip32_ok = false;
    uint8_t payload[16] = {0};
    uint16_t sw = handle_sign_eip7702_authorization(P1_FIRST_CHUNK, payload, sizeof(payload));
    assert_int_equal(sw, SWO_INCORRECT_DATA);
    // reset_app_context() walked back to IDLE.
    assert_int_equal(appState, APP_STATE_IDLE);
}

static void test_first_chunk_happy_path_locks_app_state(void **state) {
    (void) state;
    g_parsebip32_ok = true;
    g_tlv_from_apdu_ret = TLV_APDU_SUCCESS;
    uint8_t payload[16] = {0};
    uint16_t sw = handle_sign_eip7702_authorization(P1_FIRST_CHUNK, payload, sizeof(payload));
    assert_int_equal(sw, SWO_NO_RESPONSE);
    // The appState lock is now engaged — a concurrent first-chunk
    // would now be rejected by the previous test's path.
    assert_int_equal(appState, APP_STATE_SIGNING_EIP7702);
}

static void test_first_chunk_tlv_from_apdu_failure_returns_default_sw(void **state) {
    (void) state;
    g_parsebip32_ok = true;
    g_tlv_from_apdu_ret = TLV_APDU_ERROR;
    uint8_t payload[16] = {0};
    uint16_t sw = handle_sign_eip7702_authorization(P1_FIRST_CHUNK, payload, sizeof(payload));
    // Since the wrapped tlv_from_apdu never invokes handle_auth7702_tlv,
    // g_7702_sw stays at its initial value (SWO_PARAMETER_ERROR_NO_INFO).
    assert_int_equal(sw, SWO_PARAMETER_ERROR_NO_INFO);
    // reset_app_context() unwound the appState lock.
    assert_int_equal(appState, APP_STATE_IDLE);
}

static void test_continuation_chunk_outside_session_rejected(void **state) {
    (void) state;
    // A non-first chunk while appState is not SIGNING_EIP7702 means
    // the host is talking to us with stale state. Refuse.
    appState = APP_STATE_IDLE;
    uint8_t payload[16] = {0};
    uint16_t sw = handle_sign_eip7702_authorization(0x00, payload, sizeof(payload));
    assert_int_equal(sw, SWO_COMMAND_NOT_ALLOWED);
}

static void test_continuation_chunk_in_session_dispatches(void **state) {
    (void) state;
    appState = APP_STATE_SIGNING_EIP7702;
    g_tlv_from_apdu_ret = TLV_APDU_SUCCESS;
    uint8_t payload[16] = {0};
    uint16_t sw = handle_sign_eip7702_authorization(0x00, payload, sizeof(payload));
    assert_int_equal(sw, SWO_NO_RESPONSE);
    // Session remains active.
    assert_int_equal(appState, APP_STATE_SIGNING_EIP7702);
}

// =============================================================================
// Runner
// =============================================================================

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup(test_first_chunk_when_not_idle_rejected, reset),
        cmocka_unit_test_setup(test_first_chunk_parseBip32_failure_resets_app_context, reset),
        cmocka_unit_test_setup(test_first_chunk_happy_path_locks_app_state, reset),
        cmocka_unit_test_setup(test_first_chunk_tlv_from_apdu_failure_returns_default_sw, reset),
        cmocka_unit_test_setup(test_continuation_chunk_outside_session_rejected, reset),
        cmocka_unit_test_setup(test_continuation_chunk_in_session_dispatches, reset),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
