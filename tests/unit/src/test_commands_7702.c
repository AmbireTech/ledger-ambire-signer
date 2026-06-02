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
 *   - handle_auth7702_tlv() (static) — TLV-parses the auth struct,
 *     runs the delegate through the chain-bound whitelist, recomputes
 *     the RLP-hashed authorization digest, and triggers the review UI.
 *
 * Coverage drives both halves end-to-end through real tlv_apdu.c +
 * real auth_7702.c + real rlp_encode.c + real whitelist_7702.c. The
 * SDK crypto primitives, get_public_key_string, and the UI hooks are
 * stubbed.
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
#include "shared_7702.h"
#include "wraps.h"

// =============================================================================
// Globals the module reads — provide storage here.
// =============================================================================

// N_storage_real is declared `const` in shared_context.h and lives in
// NVM in production. Tests need to flip eip7702_enable, so we provide
// the storage non-const and tell GCC the type mismatch with the
// extern declaration is intentional. Use cast through (uintptr_t) so
// the assignments below don't have to litter cast-away-const at every
// call site.

// =============================================================================
// Controllable stubs
// =============================================================================

static bool g_parsebip32_ok = true;
const uint8_t *parseBip32(const uint8_t *dataBuffer, uint8_t *dataLength, bip32_path_t *bip32) {
    (void) bip32;
    if (!g_parsebip32_ok) return NULL;
    (void) dataLength;
    return dataBuffer;
}

void reset_app_context(void) {
    appState = APP_STATE_IDLE;
}

// =============================================================================
// SDK / app-side stubs invoked inside handle_auth7702_tlv.
// =============================================================================

uint32_t cx_keccak_init_no_throw(cx_sha3_t *hash, size_t size) {
    (void) hash;
    (void) size;
    return 0;
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
    (void) chainCode;
    (void) chainId;
    if (address != NULL) address[0] = '\0';
    return 0;
}

const char *get_network_name_from_chain_id(const uint64_t *chain_id) {
    (void) chain_id;
    return NULL;
}

void hash_nbytes(const uint8_t *bytes, size_t n, cx_hash_t *hash_ctx) {
    (void) bytes;
    (void) n;
    (void) hash_ctx;
}

// UI hooks — counted so tests can pin which review screen fired.
static int g_ui_auth_calls = 0;
static int g_ui_revocation_calls = 0;
static int g_ui_error_no_7702_calls = 0;
static int g_ui_error_whitelist_calls = 0;
void ui_error_no_7702(void) {
    g_ui_error_no_7702_calls++;
}
void ui_error_no_7702_whitelist(void) {
    g_ui_error_whitelist_calls++;
}
void ui_sign_7702_auth(void) {
    g_ui_auth_calls++;
}
void ui_sign_7702_revocation(void) {
    g_ui_revocation_calls++;
}

// =============================================================================
// Whitelist data — must match src/features/sign_authorization_eip7702/whitelist_7702.c.
// =============================================================================

static const uint8_t g_simple7702_account[ADDRESS_LENGTH] = {
    0x4C, 0xd2, 0x41, 0xE8, 0xd1, 0x51, 0x0e, 0x30, 0xb2, 0x07,
    0x63, 0x97, 0xaf, 0xc7, 0x50, 0x8A, 0xe5, 0x9C, 0x66, 0xc9,
};

// =============================================================================
// Fixture
// =============================================================================

static int reset(void **state) {
    (void) state;
    appState = APP_STATE_IDLE;
    g_parsebip32_ok = true;
    g_ui_auth_calls = 0;
    g_ui_revocation_calls = 0;
    g_ui_error_no_7702_calls = 0;
    g_ui_error_whitelist_calls = 0;
    memset(&tmpCtx, 0, sizeof(tmpCtx));
    memset(&strings, 0, sizeof(strings));
    g_n_storage_writable.eip7702_enable = true;
    // tlv_apdu carries internal state across calls — clear it.
    tlv_from_apdu(false, 0, NULL, NULL);
    return 0;
}

// =============================================================================
// TLV payload builder
// =============================================================================

// 4-tag minimum payload: VERSION + DELEGATE_ADDR + CHAIN_ID + NONCE.
// The first 2 bytes are the BE16 length prefix that tlv_apdu strips.
static size_t build_tlv_payload(uint8_t *out,
                                size_t out_size,
                                uint8_t version,
                                const uint8_t *delegate,
                                uint64_t chain_id,
                                uint8_t nonce) {
    uint8_t tlv[64];
    size_t off = 0;
    tlv[off++] = 0x00;  // TAG_STRUCT_VERSION
    tlv[off++] = 0x01;
    tlv[off++] = version;
    tlv[off++] = 0x01;  // TAG_DELEGATE_ADDR
    tlv[off++] = ADDRESS_LENGTH;
    memcpy(tlv + off, delegate, ADDRESS_LENGTH);
    off += ADDRESS_LENGTH;
    tlv[off++] = 0x02;  // TAG_CHAIN_ID
    tlv[off++] = 0x01;
    tlv[off++] = (uint8_t) (chain_id & 0xFF);  // single byte chain_id (sufficient for tests)
    tlv[off++] = 0x03;                         // TAG_NONCE
    tlv[off++] = 0x01;
    tlv[off++] = nonce;

    assert_true(out_size >= off + 2);
    out[0] = (uint8_t) (off >> 8);
    out[1] = (uint8_t) (off & 0xFF);
    memcpy(out + 2, tlv, off);
    return off + 2;
}

// =============================================================================
// Entry-point dispatch tests
// =============================================================================

static void test_first_chunk_when_not_idle_rejected(void **state) {
    (void) state;
    appState = APP_STATE_SIGNING_TX;
    uint8_t payload[16] = {0};
    uint16_t sw = handle_sign_eip7702_authorization(P1_FIRST_CHUNK, payload, sizeof(payload));
    assert_int_equal(sw, SWO_COMMAND_NOT_ALLOWED);
    assert_int_equal(appState, APP_STATE_SIGNING_TX);
}

static void test_first_chunk_parseBip32_failure_resets_app_context(void **state) {
    (void) state;
    g_parsebip32_ok = false;
    uint8_t payload[16] = {0};
    uint16_t sw = handle_sign_eip7702_authorization(P1_FIRST_CHUNK, payload, sizeof(payload));
    assert_int_equal(sw, SWO_INCORRECT_DATA);
    assert_int_equal(appState, APP_STATE_IDLE);
}

static void test_continuation_chunk_outside_session_rejected(void **state) {
    (void) state;
    appState = APP_STATE_IDLE;
    uint8_t payload[16] = {0};
    uint16_t sw = handle_sign_eip7702_authorization(0x00, payload, sizeof(payload));
    assert_int_equal(sw, SWO_COMMAND_NOT_ALLOWED);
}

// =============================================================================
// handle_auth7702_tlv branches (driven through real tlv_apdu)
// =============================================================================

static void test_happy_path_drives_auth_review(void **state) {
    (void) state;
    uint8_t payload[80];
    size_t len = build_tlv_payload(payload,
                                   sizeof(payload),
                                   /*version=*/0x01,
                                   /*delegate=*/g_simple7702_account,
                                   /*chain_id=*/1,
                                   /*nonce=*/0x07);
    uint16_t sw = handle_sign_eip7702_authorization(P1_FIRST_CHUNK, payload, (uint8_t) len);
    assert_int_equal(sw, SWO_NO_RESPONSE);
    assert_int_equal(g_ui_auth_calls, 1);
    assert_int_equal(g_ui_revocation_calls, 0);
    // Delegate name (Simple7702Account) was copied to the review buffer.
    assert_string_equal(strings.common.toAddress, "Simple7702Account");
}

static void test_revocation_path_drives_revocation_review(void **state) {
    (void) state;
    // Delegate = 20 zero bytes triggers the revocation branch (no
    // whitelist lookup — the user is revoking the active delegation).
    static const uint8_t zero_delegate[ADDRESS_LENGTH] = {0};
    uint8_t payload[80];
    size_t len = build_tlv_payload(payload, sizeof(payload), 0x01, zero_delegate, 1, 0x00);
    uint16_t sw = handle_sign_eip7702_authorization(P1_FIRST_CHUNK, payload, (uint8_t) len);
    assert_int_equal(sw, SWO_NO_RESPONSE);
    assert_int_equal(g_ui_revocation_calls, 1);
    assert_int_equal(g_ui_auth_calls, 0);
}

static void test_eip7702_disabled_rejected(void **state) {
    (void) state;
    g_n_storage_writable.eip7702_enable = false;
    uint8_t payload[80];
    size_t len = build_tlv_payload(payload, sizeof(payload), 0x01, g_simple7702_account, 1, 0x00);
    uint16_t sw = handle_sign_eip7702_authorization(P1_FIRST_CHUNK, payload, (uint8_t) len);
    assert_int_equal(sw, SWO_COMMAND_NOT_ALLOWED);
    assert_int_equal(g_ui_error_no_7702_calls, 1);
    assert_int_equal(g_ui_auth_calls, 0);
}

static void test_delegate_not_in_whitelist_rejected(void **state) {
    (void) state;
    // An address that's not Simple7702Account and not all zeros must
    // be rejected via ui_error_no_7702_whitelist.
    static const uint8_t random_delegate[ADDRESS_LENGTH] = {
        0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD,
        0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF,
    };
    uint8_t payload[80];
    size_t len = build_tlv_payload(payload, sizeof(payload), 0x01, random_delegate, 1, 0x00);
    uint16_t sw = handle_sign_eip7702_authorization(P1_FIRST_CHUNK, payload, (uint8_t) len);
    assert_int_equal(sw, SWO_COMMAND_NOT_ALLOWED);
    assert_int_equal(g_ui_error_whitelist_calls, 1);
    assert_int_equal(g_ui_auth_calls, 0);
}

static void test_invalid_version_rejected(void **state) {
    (void) state;
    // The auth_7702 parser enforces STRUCT_VERSION == 0x01.
    uint8_t payload[80];
    size_t len = build_tlv_payload(payload,
                                   sizeof(payload),
                                   /*version=*/0x07,
                                   g_simple7702_account,
                                   1,
                                   0x00);
    uint16_t sw = handle_sign_eip7702_authorization(P1_FIRST_CHUNK, payload, (uint8_t) len);
    assert_int_equal(sw, SWO_INCORRECT_DATA);
    assert_int_equal(g_ui_auth_calls, 0);
}

static void test_chain_id_all_uses_wildcard_display(void **state) {
    (void) state;
    // CHAIN_ID_ALL (= 0) lands on the "All" wildcard label rather
    // than calling get_network_name_from_chain_id / format_u64.
    uint8_t payload[80];
    size_t len =
        build_tlv_payload(payload, sizeof(payload), 0x01, g_simple7702_account, CHAIN_ID_ALL, 0x00);
    uint16_t sw = handle_sign_eip7702_authorization(P1_FIRST_CHUNK, payload, (uint8_t) len);
    assert_int_equal(sw, SWO_NO_RESPONSE);
    assert_string_equal(strings.common.network_name, "All");
}

// =============================================================================
// Runner
// =============================================================================

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup(test_first_chunk_when_not_idle_rejected, reset),
        cmocka_unit_test_setup(test_first_chunk_parseBip32_failure_resets_app_context, reset),
        cmocka_unit_test_setup(test_continuation_chunk_outside_session_rejected, reset),
        cmocka_unit_test_setup(test_happy_path_drives_auth_review, reset),
        cmocka_unit_test_setup(test_revocation_path_drives_revocation_review, reset),
        cmocka_unit_test_setup(test_eip7702_disabled_rejected, reset),
        cmocka_unit_test_setup(test_delegate_not_in_whitelist_rejected, reset),
        cmocka_unit_test_setup(test_invalid_version_rejected, reset),
        cmocka_unit_test_setup(test_chain_id_all_uses_wildcard_display, reset),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
