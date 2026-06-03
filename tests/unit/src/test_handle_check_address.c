/**
 * @file test_handle_check_address.c
 * @brief Unit tests for handle_check_address at src/swap/handle_check_address.c.
 *
 * The Ledger Exchange app calls handle_check_address before initiating a
 * swap: "this swap will send funds to <addr> -- confirm that <addr> is
 * derived from <bip32_path> on this device". A bug here lets an attacker
 * trick the Exchange app into thinking they own a destination address
 * they don't, and the user ends up sending coins to the attacker.
 *
 * Output is a single bit `params->result` (0 = mismatch / error, 1 = match).
 * Tests pin every branch of the validator:
 *
 *  1. address_to_check == NULL          -> result stays 0
 *  2. address_parameters == NULL        -> result stays 0
 *  3. address_parameters_length == 0    -> result stays 0
 *  4. bip32_path_read fails             -> result stays 0
 *  5. get_public_key_string fails       -> result stays 0
 *  6. derived address differs           -> result stays 0
 *  7. derived address matches           -> result = 1
 *  8. address_to_check has "0x" prefix  -> the prefix is stripped before compare
 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

#include "shared_context.h"
#include "swap_lib_calls.h"
#include "chain_config.h"
#include "handle_check_address.h"

// =============================================================================
// Wraps / stubs
// =============================================================================

// Each test pushes a desired bip32_path_read return value (and optionally a
// length-clamp behavior) via cmocka.
bool __wrap_bip32_path_read(const uint8_t *in, size_t in_len, uint32_t *out, size_t out_len) {
    (void) in;
    (void) in_len;
    (void) out;
    (void) out_len;
    return (bool) mock();
}

// get_public_key_string writes the ASCII checksummed address into `address`.
// Tests push the desired sw + address payload through cmocka.
uint16_t __wrap_get_public_key_string(bip32_path_t *bip32,
                                      uint8_t *pubKey,
                                      char *address,
                                      uint8_t *chainCode,
                                      uint64_t chainId) {
    (void) bip32;
    (void) pubKey;
    (void) chainCode;
    (void) chainId;
    uint16_t sw = (uint16_t) mock();
    const char *out = (const char *) mock();
    if (out != NULL && address != NULL) {
        strcpy(address, out);
    }
    return sw;
}

// =============================================================================
// Fixture
// =============================================================================

static check_address_parameters_t s_params;
static chain_config_t s_chain = {.ticker = "ETH", .chain_id = 1, .coin_type = 60};

// Plausibly-shaped address_parameters: one byte for the path length, then
// the serialised BIP32 indices. Content doesn't matter because
// bip32_path_read is wrapped.
static uint8_t s_addr_params[1 + 5 * 4];

static int reset(void **state) {
    (void) state;
    memset(&s_params, 0, sizeof(s_params));
    s_addr_params[0] = 5;  // 5-level path (e.g. 44'/60'/0'/0/0)
    memset(s_addr_params + 1, 0xAB, sizeof(s_addr_params) - 1);
    s_params.address_parameters = s_addr_params;
    s_params.address_parameters_length = sizeof(s_addr_params);
    return 0;
}

// =============================================================================
// Empty / NULL inputs -- result stays 0
// =============================================================================

static void test_null_address_to_check_returns_zero(void **state) {
    (void) state;
    s_params.address_to_check = NULL;
    // bip32_path_read / get_public_key_string MUST NOT be reached.
    handle_check_address(&s_params, &s_chain);
    assert_int_equal(s_params.result, 0);
}

static void test_null_address_parameters_returns_zero(void **state) {
    (void) state;
    char addr[] = "0xdeadbeef";
    s_params.address_to_check = addr;
    s_params.address_parameters = NULL;
    s_params.address_parameters_length = sizeof(s_addr_params);
    handle_check_address(&s_params, &s_chain);
    assert_int_equal(s_params.result, 0);
}

static void test_zero_length_address_parameters_returns_zero(void **state) {
    (void) state;
    char addr[] = "0xdeadbeef";
    s_params.address_to_check = addr;
    s_params.address_parameters_length = 0;
    handle_check_address(&s_params, &s_chain);
    assert_int_equal(s_params.result, 0);
}

// =============================================================================
// Derivation failures -- result stays 0
// =============================================================================

static void test_bip32_path_read_failure_returns_zero(void **state) {
    (void) state;
    char addr[] = "0xdeadbeef";
    s_params.address_to_check = addr;
    will_return(__wrap_bip32_path_read, false);
    // get_public_key_string MUST NOT be reached after a bad path.
    handle_check_address(&s_params, &s_chain);
    assert_int_equal(s_params.result, 0);
}

static void test_get_public_key_failure_returns_zero(void **state) {
    (void) state;
    char addr[] = "0xdeadbeef";
    s_params.address_to_check = addr;
    will_return(__wrap_bip32_path_read, true);
    will_return(__wrap_get_public_key_string, 0x6A80);  // SWO_APD_DAT_GENERIC
    will_return(__wrap_get_public_key_string, NULL);    // no address payload
    handle_check_address(&s_params, &s_chain);
    assert_int_equal(s_params.result, 0);
}

// =============================================================================
// Compare paths
// =============================================================================

static void test_address_mismatch_returns_zero(void **state) {
    (void) state;
    char addr[] = "0xabc1234567890abcdef1234567890abcdef123456";
    s_params.address_to_check = addr;
    will_return(__wrap_bip32_path_read, true);
    will_return(__wrap_get_public_key_string, CX_OK);
    will_return(__wrap_get_public_key_string,
                "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef");  // derived address differs
    handle_check_address(&s_params, &s_chain);
    assert_int_equal(s_params.result, 0);
}

static void test_address_match_sets_result_one(void **state) {
    (void) state;
    // address_to_check has no 0x prefix; expect raw compare against the
    // derived address.
    char addr[] = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef";
    s_params.address_to_check = addr;
    will_return(__wrap_bip32_path_read, true);
    will_return(__wrap_get_public_key_string, CX_OK);
    will_return(__wrap_get_public_key_string, "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef");
    handle_check_address(&s_params, &s_chain);
    assert_int_equal(s_params.result, 1);
}

static void test_address_match_strips_0x_prefix(void **state) {
    (void) state;
    // The 0x prefix on address_to_check must be skipped before strcmp;
    // get_public_key_string returns the lowercase hex without prefix.
    char addr[] = "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef";
    s_params.address_to_check = addr;
    will_return(__wrap_bip32_path_read, true);
    will_return(__wrap_get_public_key_string, CX_OK);
    will_return(__wrap_get_public_key_string, "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef");
    handle_check_address(&s_params, &s_chain);
    assert_int_equal(s_params.result, 1);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup(test_null_address_to_check_returns_zero, reset),
        cmocka_unit_test_setup(test_null_address_parameters_returns_zero, reset),
        cmocka_unit_test_setup(test_zero_length_address_parameters_returns_zero, reset),
        cmocka_unit_test_setup(test_bip32_path_read_failure_returns_zero, reset),
        cmocka_unit_test_setup(test_get_public_key_failure_returns_zero, reset),
        cmocka_unit_test_setup(test_address_mismatch_returns_zero, reset),
        cmocka_unit_test_setup(test_address_match_sets_result_one, reset),
        cmocka_unit_test_setup(test_address_match_strips_0x_prefix, reset),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
