/**
 * @file test_ledger_pki.c
 * @brief Unit tests for check_signature_with_pubkey at src/ledger_pki.c.
 *
 * check_signature_with_pubkey is THE crypto gate behind every host-supplied
 * descriptor that affects what the user sees on screen: trusted-name
 * resolution, proxy-info, safe-account, plugin registrations, gating
 * payloads, network metadata, tx-simulation descriptors. A regression here
 * is a CWE-347 (improper signature verification) by silent failure --
 * fake "Uniswap.eth" / fake plugin name / fake risk score reaches the user.
 *
 * The function is a thin dispatcher:
 *
 *   check_signature_with_pki(...) -> status_t
 *     CHECK_SIGNATURE_WITH_PKI_SUCCESS                  -> return true
 *     CHECK_SIGNATURE_WITH_PKI_MISSING_CERTIFICATE      \  legacy ECDSA path:
 *     CHECK_SIGNATURE_WITH_PKI_WRONG_CERTIFICATE_USAGE  /  init + verify
 *     CHECK_SIGNATURE_WITH_PKI_WRONG_CERTIFICATE_CURVE  -> return false
 *     CHECK_SIGNATURE_WITH_PKI_WRONG_SIGNATURE          -> return false
 *     (default)                                         -> return false
 *
 * Tests pin every status_t branch plus the two failure modes of the
 * legacy fallback (key-init failure, ECDSA-verify failure). The SDK
 * lib_pki/ledger_pki.c is NOT linked into this target -- we provide
 * check_signature_with_pki directly so cmocka's mock() can drive the
 * outcome per test case.
 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

#include "buffer.h"
#include "ledger_pki.h"   // SDK lib_pki header: status enum + check_signature_with_pki proto
#include "public_keys.h"  // check_signature_with_pubkey prototype

// =============================================================================
// Stubs / wraps
// =============================================================================

// SDK lib_pki entry point. Each test pushes its desired return value via
// will_return().
check_signature_with_pki_status_t check_signature_with_pki(const buffer_t hash,
                                                           const uint8_t *expected_key_usage,
                                                           const cx_curve_t *expected_curve,
                                                           const buffer_t signature) {
    (void) hash;
    (void) expected_key_usage;
    (void) expected_curve;
    (void) signature;
    return (check_signature_with_pki_status_t) mock();
}

// lib_cxng init + verify -- the legacy fallback path.
cx_err_t cx_ecfp_init_public_key_no_throw(cx_curve_t curve,
                                          const uint8_t *rawkey,
                                          size_t key_len,
                                          cx_ecfp_public_key_t *key) {
    (void) curve;
    (void) rawkey;
    (void) key_len;
    (void) key;
    return (cx_err_t) mock();
}

bool cx_ecdsa_verify_no_throw(const cx_ecfp_public_key_t *pukey,
                              const uint8_t *hash,
                              size_t hash_len,
                              const uint8_t *sig,
                              size_t sig_len) {
    (void) pukey;
    (void) hash;
    (void) hash_len;
    (void) sig;
    (void) sig_len;
    return (bool) mock();
}

// =============================================================================
// Test fixtures -- valid-looking arguments. Bodies don't matter; the wrapped
// helpers ignore them. Sized to plausibly-real values (32-byte hash,
// uncompressed P-256K1 pubkey 65 bytes, DER-encoded ECDSA signature ~71 bytes)
// so the function-under-test sees the same shape it would on-device.
// =============================================================================

static uint8_t g_hash[32];
static uint8_t g_pubkey[65];
static uint8_t g_sig[71];

#define KEY_USAGE_TRUSTED_NAME 0x01

static int reset(void **state) {
    (void) state;
    memset(g_hash, 0xAA, sizeof(g_hash));
    memset(g_pubkey, 0xBB, sizeof(g_pubkey));
    memset(g_sig, 0xCC, sizeof(g_sig));
    return 0;
}

static bool call_check(void) {
    return check_signature_with_pubkey(g_hash,
                                       sizeof(g_hash),
                                       g_pubkey,
                                       sizeof(g_pubkey),
                                       KEY_USAGE_TRUSTED_NAME,
                                       g_sig,
                                       sizeof(g_sig));
}

// =============================================================================
// PKI success short-circuits the legacy path
// =============================================================================

static void test_pki_success_returns_true(void **state) {
    (void) state;
    will_return(check_signature_with_pki, CHECK_SIGNATURE_WITH_PKI_SUCCESS);
    // Legacy stubs MUST NOT be reached. cmocka will fail the test if any
    // unconsumed will_return remains queued, so leaving them empty here
    // proves the short-circuit.
    assert_true(call_check());
}

// =============================================================================
// Missing/Wrong certificate -> legacy ECDSA fallback
// =============================================================================

static void test_pki_missing_cert_legacy_verify_succeeds(void **state) {
    (void) state;
    will_return(check_signature_with_pki, CHECK_SIGNATURE_WITH_PKI_MISSING_CERTIFICATE);
    will_return(cx_ecfp_init_public_key_no_throw, CX_OK);
    will_return(cx_ecdsa_verify_no_throw, true);
    assert_true(call_check());
}

static void test_pki_missing_cert_legacy_verify_fails(void **state) {
    (void) state;
    will_return(check_signature_with_pki, CHECK_SIGNATURE_WITH_PKI_MISSING_CERTIFICATE);
    will_return(cx_ecfp_init_public_key_no_throw, CX_OK);
    will_return(cx_ecdsa_verify_no_throw, false);
    assert_false(call_check());
}

static void test_pki_missing_cert_key_init_fails_returns_false(void **state) {
    (void) state;
    will_return(check_signature_with_pki, CHECK_SIGNATURE_WITH_PKI_MISSING_CERTIFICATE);
    will_return(cx_ecfp_init_public_key_no_throw, CX_INVALID_PARAMETER);
    // cx_ecdsa_verify MUST NOT be reached after a failed key init.
    assert_false(call_check());
}

// CHECK_SIGNATURE_WITH_PKI_WRONG_CERTIFICATE_USAGE falls into the same legacy
// path as CHECK_SIGNATURE_WITH_PKI_MISSING_CERTIFICATE; pin a representative
// happy case so a future refactor doesn't accidentally split the two branches.
static void test_pki_wrong_usage_falls_back_to_legacy(void **state) {
    (void) state;
    will_return(check_signature_with_pki, CHECK_SIGNATURE_WITH_PKI_WRONG_CERTIFICATE_USAGE);
    will_return(cx_ecfp_init_public_key_no_throw, CX_OK);
    will_return(cx_ecdsa_verify_no_throw, true);
    assert_true(call_check());
}

// =============================================================================
// Hard-fail PKI statuses -- legacy path NOT entered
// =============================================================================

static void test_pki_wrong_curve_returns_false(void **state) {
    (void) state;
    will_return(check_signature_with_pki, CHECK_SIGNATURE_WITH_PKI_WRONG_CERTIFICATE_CURVE);
    // Legacy stubs MUST NOT be reached -- a wrong-curve certificate is a
    // strong refusal, NOT an invitation to retry with the raw pubkey
    // (which is the whole point of CWE-347 in this module).
    assert_false(call_check());
}

static void test_pki_wrong_signature_returns_false(void **state) {
    (void) state;
    will_return(check_signature_with_pki, CHECK_SIGNATURE_WITH_PKI_WRONG_SIGNATURE);
    // Same as above: a signature that doesn't verify under the loaded
    // certificate must not silently fall back to the raw-pubkey path.
    assert_false(call_check());
}

static void test_pki_unknown_status_returns_false(void **state) {
    (void) state;
    // Push a value outside the defined enum range to exercise the `default:`
    // fall-through. The function MUST fail closed.
    will_return(check_signature_with_pki, 0xFF);
    assert_false(call_check());
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup(test_pki_success_returns_true, reset),
        cmocka_unit_test_setup(test_pki_missing_cert_legacy_verify_succeeds, reset),
        cmocka_unit_test_setup(test_pki_missing_cert_legacy_verify_fails, reset),
        cmocka_unit_test_setup(test_pki_missing_cert_key_init_fails_returns_false, reset),
        cmocka_unit_test_setup(test_pki_wrong_usage_falls_back_to_legacy, reset),
        cmocka_unit_test_setup(test_pki_wrong_curve_returns_false, reset),
        cmocka_unit_test_setup(test_pki_wrong_signature_returns_false, reset),
        cmocka_unit_test_setup(test_pki_unknown_status_returns_false, reset),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
