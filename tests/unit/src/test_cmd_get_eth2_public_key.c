/**
 * @file test_cmd_get_eth2_public_key.c
 * @brief Unit tests for handle_get_eth2_public_key + get_eth2_public_key at
 *        src/features/get_eth2_public_key/cmd_get_eth2_public_key.c.
 *
 * Beacon-Chain (ETH2) validator key derivation. The host streams a BIP-32
 * path; the device derives an EIP-2333 BLS12-381 G1 private scalar,
 * generates the matching public point, compresses it to 48 bytes with the
 * standard y-parity flag, and shows it on screen for confirmation. A
 * regression here disconnects the on-screen address from what the host
 * will commit to in the deposit contract -- the user thinks they staked
 * to validator X but the deposit goes to validator Y.
 *
 * Tests pin handle_get_eth2_public_key (APDU dispatcher) only:
 *
 *    - wrong P1 (not CONFIRM / NON_CONFIRM)        SWO_WRONG_P1_P2
 *    - wrong P2 (not 0)                            SWO_WRONG_P1_P2
 *    - parseBip32 returns NULL                     SWO_INCORRECT_DATA
 *    - P1_NON_CONFIRM happy path                   SWO_SUCCESS + tx set
 *    - P1_CONFIRM happy path                       0 (deferred reply via UI)
 *    - G_called_from_swap=false  -> reset_app_context() called once
 *    - G_called_from_swap=true   -> reset_app_context() NOT called
 *
 * get_eth2_public_key itself (the BLS pipeline) lives in the same
 * translation unit as the dispatcher; the linker can't redirect intra-TU
 * calls with --wrap, so the dispatcher genuinely runs the real BLS body.
 * The SDK side-effects (os_perso_derive_eip2333, cx_ecfp_*_no_throw,
 * cx_math_*_no_throw) are stubbed at link time to return CX_OK so the
 * happy paths complete deterministically. Failure propagation through
 * the BLS chain isn't pinned -- exercising it cleanly would require
 * mocking the SDK try/catch stack (os_derive_eip2333_no_throw is a
 * `static inline` in the SDK), which is outside the scope of a Tier L
 * coverage pass.
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
#include "feature_get_eth2_public_key.h"

// =============================================================================
// Wraps for handle_get_eth2_public_key
// =============================================================================

const uint8_t *__wrap_parseBip32(const uint8_t *dataBuffer, uint8_t *dataLength, void *bip32) {
    (void) dataBuffer;
    (void) dataLength;
    bip32_path_t *out = (bip32_path_t *) bip32;
    bool ok = (bool) mock();
    if (!ok) return NULL;
    out->length = 5;
    for (int i = 0; i < 5; i++) out->path[i] = (uint32_t) i;
    return dataBuffer;
}

static uint32_t g_set_result_ret = 0;
uint32_t __wrap_set_result_get_eth2_publicKey(void) {
    return g_set_result_ret;
}

static int g_ui_calls = 0;
void __wrap_ui_display_public_eth2(void) {
    g_ui_calls++;
}

static int g_reset_calls = 0;
void __wrap_reset_app_context(void) {
    g_reset_calls++;
}

void __wrap_io_seproxyhal_io_heartbeat(void) {
}

// =============================================================================
// Link-only stubs for the SDK symbols referenced by the real BLS pipeline.
// All return CX_OK so the dispatcher's CX_CHECK chain runs to completion
// and we land in the post-BLS dispatcher logic the tests pin.
// =============================================================================

void os_perso_derive_eip2333(cx_curve_t curve,
                             const uint32_t *path,
                             unsigned int path_len,
                             unsigned char *raw_privkey) {
    (void) curve;
    (void) path;
    (void) path_len;
    (void) raw_privkey;
}

cx_err_t cx_ecfp_init_private_key_no_throw(cx_curve_t curve,
                                           const uint8_t *rawkey,
                                           size_t key_len,
                                           cx_ecfp_private_key_t *key) {
    (void) curve;
    (void) rawkey;
    (void) key_len;
    (void) key;
    return CX_OK;
}

cx_err_t cx_ecfp_generate_pair_no_throw(cx_curve_t curve,
                                        cx_ecfp_public_key_t *pubkey,
                                        cx_ecfp_private_key_t *privkey,
                                        bool keepprivate) {
    (void) curve;
    (void) pubkey;
    (void) privkey;
    (void) keepprivate;
    return CX_OK;
}

cx_err_t cx_math_cmp_no_throw(const uint8_t *a, const uint8_t *b, size_t length, int *diff) {
    (void) a;
    (void) b;
    (void) length;
    if (diff != NULL) *diff = 0;
    return CX_OK;
}

// =============================================================================
// Fixture
// =============================================================================

static int reset(void **state) {
    (void) state;
    g_ui_calls = 0;
    g_reset_calls = 0;
    g_set_result_ret = 42;
    memset(&tmpCtx, 0, sizeof(tmpCtx));
    G_called_from_swap = false;
    return 0;
}

// =============================================================================
// handle_get_eth2_public_key
// =============================================================================

static void test_wrong_p1_rejected(void **state) {
    (void) state;
    unsigned int tx = 0;
    assert_int_equal(handle_get_eth2_public_key(0xFF, 0, (uint8_t *) "", 0, &tx), SWO_WRONG_P1_P2);
    assert_int_equal(g_reset_calls, 1);
}

static void test_wrong_p2_rejected(void **state) {
    (void) state;
    unsigned int tx = 0;
    assert_int_equal(handle_get_eth2_public_key(P1_CONFIRM, 1, (uint8_t *) "", 0, &tx),
                     SWO_WRONG_P1_P2);
}

static void test_parsebip32_failure_rejected(void **state) {
    (void) state;
    unsigned int tx = 0;
    will_return(__wrap_parseBip32, false);
    assert_int_equal(handle_get_eth2_public_key(P1_CONFIRM, 0, (uint8_t *) "", 0, &tx),
                     SWO_INCORRECT_DATA);
}

static void test_non_confirm_returns_success_and_sets_tx(void **state) {
    (void) state;
    unsigned int tx = 0;
    will_return(__wrap_parseBip32, true);
    g_set_result_ret = 64;
    uint16_t sw = handle_get_eth2_public_key(P1_NON_CONFIRM, 0, (uint8_t *) "", 0, &tx);
    assert_int_equal(sw, SWO_SUCCESS);
    assert_int_equal(tx, 64);
    // UI MUST NOT fire for the non-interactive read path.
    assert_int_equal(g_ui_calls, 0);
}

static void test_confirm_defers_reply_via_ui(void **state) {
    (void) state;
    unsigned int tx = 0;
    will_return(__wrap_parseBip32, true);
    uint16_t sw = handle_get_eth2_public_key(P1_CONFIRM, 0, (uint8_t *) "", 0, &tx);
    // Deferred reply: the dispatcher returns 0 and the UI thread will
    // emit the final SW after the user confirms.
    assert_int_equal(sw, 0);
    assert_int_equal(g_ui_calls, 1);
}

static void test_called_from_swap_skips_reset_app_context(void **state) {
    (void) state;
    unsigned int tx = 0;
    G_called_from_swap = true;
    // Drive to a quick SWO_WRONG_P1_P2 path so the reset-check is the
    // only thing under observation.
    handle_get_eth2_public_key(0xFF, 0, (uint8_t *) "", 0, &tx);
    assert_int_equal(g_reset_calls, 0);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup(test_wrong_p1_rejected, reset),
        cmocka_unit_test_setup(test_wrong_p2_rejected, reset),
        cmocka_unit_test_setup(test_parsebip32_failure_rejected, reset),
        cmocka_unit_test_setup(test_non_confirm_returns_success_and_sets_tx, reset),
        cmocka_unit_test_setup(test_confirm_defers_reply_via_ui, reset),
        cmocka_unit_test_setup(test_called_from_swap_skips_reset_app_context, reset),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
