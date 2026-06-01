/**
 * @file test_proxy_info.c
 * @brief Unit tests for the proxy-info backend descriptor at
 *        src/features/provide_proxy_info/proxy_info.c.
 *
 * proxy_info caches the (chain_id, proxy_address -> implementation_address)
 * mapping signed by the backend so the device, when later parsing a
 * transaction whose `to` looks like a proxy, can resolve the actual
 * implementation contract and render the right plugin/UI for it.
 *
 * Two security gates carry the load:
 *   - verify_proxy_info_struct(): finalize the running keccak hash
 *     over every non-SIGNATURE TLV, then run check_signature_with_pubkey
 *     against the backend's CERTIFICATE_PUBLIC_KEY_USAGE_TRUSTED_NAME.
 *     Only on success is g_proxy_info populated with the descriptor
 *     contents — otherwise a hostile host could whisper any
 *     (proxy -> impl) mapping it wants.
 *   - check_proxy_params(): on lookup, the requested (chain_id, addr,
 *     selector) must match the registered descriptor exactly. A
 *     regression here would let a registered proxy resolution leak
 *     onto a different chain or a different selector — the user
 *     reviews "interact with $known_dapp" while signing for an
 *     attacker contract.
 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

#include "shared_context.h"
#include "proxy_info.h"

// =============================================================================
// Globals the module reads
// =============================================================================

strings_t strings;
static chain_config_t g_chainConfig = {.ticker = "ETH", .chain_id = 1, .coin_type = 60};
const chain_config_t *g_chain_config = &g_chainConfig;
const char g_unknown_ticker[] = "???";
txContext_t txContext;
tmpContent_t tmpContent;

// =============================================================================
// Controllable stubs
// =============================================================================

static bool g_sig_check_ret = true;
bool __wrap_check_signature_with_pubkey(uint8_t *buffer,
                                        const uint8_t bufLen,
                                        const uint8_t *PubKey,
                                        const uint8_t keyLen,
                                        const uint8_t keyUsageExp,
                                        const uint8_t *signature,
                                        const uint8_t sigLen) {
    (void) buffer;
    (void) bufLen;
    (void) PubKey;
    (void) keyLen;
    (void) keyUsageExp;
    (void) signature;
    (void) sigLen;
    return g_sig_check_ret;
}

static bool g_finalize_hash_ret = true;
bool __wrap_finalize_hash(cx_hash_t *hash_ctx, uint8_t *out, size_t out_len) {
    (void) hash_ctx;
    memset(out, 0, out_len);
    return g_finalize_hash_ret;
}

static int g_roll_challenge_calls = 0;
void roll_challenge(void) {
    g_roll_challenge_calls++;
}

// Real hash_nbytes is in main code; stub here so the per-tag common
// handler is a no-op (we don't care about the actual hash, just the
// signature check that follows).
void __wrap_hash_nbytes(const uint8_t *bytes, size_t n, cx_hash_t *hash_ctx) {
    (void) bytes;
    (void) n;
    (void) hash_ctx;
}

uint32_t cx_sha256_init_no_throw(cx_sha256_t *hash) {
    (void) hash;
    return 0;
}

// =============================================================================
// Fixture
// =============================================================================

// Concrete test data
static const uint8_t g_proxy_addr[ADDRESS_LENGTH] = {
    0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
    0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
};
static const uint8_t g_impl_addr[ADDRESS_LENGTH] = {
    0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB,
    0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB,
};
static const uint8_t g_selector[CALLDATA_SELECTOR_SIZE] = {0xDE, 0xAD, 0xBE, 0xEF};

static int reset(void **state) {
    (void) state;
    proxy_cleanup();
    g_sig_check_ret = true;
    g_finalize_hash_ret = true;
    g_roll_challenge_calls = 0;
    return 0;
}

// =============================================================================
// TLV payload builder. Each tag fits short-form (length < 128).
// =============================================================================
//
// Layout:
//   0x01 STRUCT_TYPE        len=1, value=0x26
//   0x02 STRUCT_VERSION     len=1, value=0x01
//   0x12 CHALLENGE          len=4, value=BE32
//   0x22 ADDRESS            len=20, proxy address
//   0x23 CHAIN_ID           len=1, chain_id LSB
//   0x41 SELECTOR           len=4, selector (optional — driven by include_selector)
//   0x42 IMPLEM_ADDRESS     len=20, impl address
//   0x43 DELEGATION_TYPE    len=1, value=delegation_type
//   0x15 SIGNATURE          len=sig_size, sig bytes (mock'd check)
//
// The minimum-valid signature size is CX_ECDSA_SHA256_SIG_MIN_ASN1_LENGTH = 8.

static size_t build_tlv(uint8_t *out,
                        size_t out_size,
                        uint8_t struct_type,
                        uint8_t version,
                        uint8_t chain_id,
                        const uint8_t *addr,
                        const uint8_t *impl,
                        bool include_selector,
                        uint8_t delegation_type,
                        uint8_t sig_len) {
    size_t off = 0;
    out[off++] = 0x01;
    out[off++] = 0x01;
    out[off++] = struct_type;
    out[off++] = 0x02;
    out[off++] = 0x01;
    out[off++] = version;
    out[off++] = 0x12;
    out[off++] = 0x04;
    out[off++] = 0xDE;
    out[off++] = 0xAD;
    out[off++] = 0xBE;
    out[off++] = 0xEF;  // CHALLENGE (mock check_challenge OK)
    out[off++] = 0x22;
    out[off++] = ADDRESS_LENGTH;
    memcpy(out + off, addr, ADDRESS_LENGTH);
    off += ADDRESS_LENGTH;
    out[off++] = 0x23;
    out[off++] = 0x01;
    out[off++] = chain_id;
    if (include_selector) {
        out[off++] = 0x41;
        out[off++] = CALLDATA_SELECTOR_SIZE;
        memcpy(out + off, g_selector, CALLDATA_SELECTOR_SIZE);
        off += CALLDATA_SELECTOR_SIZE;
    }
    out[off++] = 0x42;
    out[off++] = ADDRESS_LENGTH;
    memcpy(out + off, impl, ADDRESS_LENGTH);
    off += ADDRESS_LENGTH;
    out[off++] = 0x43;
    out[off++] = 0x01;
    out[off++] = delegation_type;
    out[off++] = 0x15;
    out[off++] = sig_len;
    memset(out + off, 0x42, sig_len);
    off += sig_len;
    assert_true(off <= out_size);
    return off;
}

static bool run_parse_and_verify(const uint8_t *tlv, size_t len, s_proxy_info_ctx *ctx) {
    buffer_t buf = {.ptr = (uint8_t *) tlv, .size = len, .offset = 0};
    if (!handle_proxy_info_tlv_payload(&buf, ctx)) return false;
    return verify_proxy_info_struct(ctx);
}

// =============================================================================
// Tests
// =============================================================================

static void test_happy_path_registers_descriptor(void **state) {
    (void) state;
    uint8_t tlv[256];
    size_t len = build_tlv(tlv,
                           sizeof(tlv),
                           0x26,
                           0x01,
                           1,
                           g_proxy_addr,
                           g_impl_addr,
                           /*include_selector=*/true,
                           0 /*PROXY*/,
                           16);
    s_proxy_info_ctx ctx = {0};
    assert_true(run_parse_and_verify(tlv, len, &ctx));
    // roll_challenge ran exactly once — anti-replay anchor.
    assert_int_equal(g_roll_challenge_calls, 1);
    // Lookups now resolve: get_implem_contract returns the impl address
    // when queried with the matching (chain, proxy_addr, selector).
    uint64_t chain = 1;
    const uint8_t *impl = get_implem_contract(&chain, g_proxy_addr, g_selector);
    assert_non_null(impl);
    assert_memory_equal(impl, g_impl_addr, ADDRESS_LENGTH);
    // Reverse lookup: get_proxy_contract(impl_addr) -> proxy_addr.
    const uint8_t *proxy = get_proxy_contract(&chain, g_impl_addr, g_selector);
    assert_non_null(proxy);
    assert_memory_equal(proxy, g_proxy_addr, ADDRESS_LENGTH);
}

static void test_lookups_without_registered_descriptor_return_null(void **state) {
    (void) state;
    // After proxy_cleanup (called in reset) g_proxy_info is NULL —
    // both lookups must short-circuit to NULL.
    uint64_t chain = 1;
    assert_null(get_implem_contract(&chain, g_proxy_addr, g_selector));
    assert_null(get_proxy_contract(&chain, g_impl_addr, g_selector));
}

static void test_signature_check_failure_rejects(void **state) {
    (void) state;
    uint8_t tlv[256];
    size_t len = build_tlv(tlv, sizeof(tlv), 0x26, 0x01, 1, g_proxy_addr, g_impl_addr, true, 0, 16);
    g_sig_check_ret = false;
    s_proxy_info_ctx ctx = {0};
    assert_false(run_parse_and_verify(tlv, len, &ctx));
    // No descriptor must have been registered.
    uint64_t chain = 1;
    assert_null(get_implem_contract(&chain, g_proxy_addr, g_selector));
}

static void test_finalize_hash_failure_rejects(void **state) {
    (void) state;
    uint8_t tlv[256];
    size_t len = build_tlv(tlv, sizeof(tlv), 0x26, 0x01, 1, g_proxy_addr, g_impl_addr, true, 0, 16);
    g_finalize_hash_ret = false;
    s_proxy_info_ctx ctx = {0};
    assert_false(run_parse_and_verify(tlv, len, &ctx));
}

static void test_invalid_struct_type_rejected(void **state) {
    (void) state;
    uint8_t tlv[256];
    // Send STRUCT_TYPE = 0xFF (not 0x26 = TYPE_PROXY_INFO).
    size_t len = build_tlv(tlv, sizeof(tlv), 0xFF, 0x01, 1, g_proxy_addr, g_impl_addr, true, 0, 16);
    s_proxy_info_ctx ctx = {0};
    buffer_t buf = {.ptr = tlv, .size = len, .offset = 0};
    assert_false(handle_proxy_info_tlv_payload(&buf, &ctx));
}

static void test_invalid_struct_version_rejected(void **state) {
    (void) state;
    uint8_t tlv[256];
    size_t len = build_tlv(tlv, sizeof(tlv), 0x26, 0x05, 1, g_proxy_addr, g_impl_addr, true, 0, 16);
    s_proxy_info_ctx ctx = {0};
    buffer_t buf = {.ptr = tlv, .size = len, .offset = 0};
    assert_false(handle_proxy_info_tlv_payload(&buf, &ctx));
}

static void test_delegation_type_out_of_range_rejected(void **state) {
    (void) state;
    uint8_t tlv[256];
    // DELEGATION_TYPE_MAX = 3, so any value >= 3 must be rejected.
    size_t len =
        build_tlv(tlv, sizeof(tlv), 0x26, 0x01, 1, g_proxy_addr, g_impl_addr, true, 0x7F, 16);
    s_proxy_info_ctx ctx = {0};
    buffer_t buf = {.ptr = tlv, .size = len, .offset = 0};
    assert_false(handle_proxy_info_tlv_payload(&buf, &ctx));
}

static void test_signature_too_short_rejected(void **state) {
    (void) state;
    uint8_t tlv[256];
    // sig_len = 4 < CX_ECDSA_SHA256_SIG_MIN_ASN1_LENGTH (8).
    size_t len = build_tlv(tlv, sizeof(tlv), 0x26, 0x01, 1, g_proxy_addr, g_impl_addr, true, 0, 4);
    s_proxy_info_ctx ctx = {0};
    buffer_t buf = {.ptr = tlv, .size = len, .offset = 0};
    assert_false(handle_proxy_info_tlv_payload(&buf, &ctx));
}

static void test_lookup_chain_id_mismatch_returns_null(void **state) {
    (void) state;
    uint8_t tlv[256];
    size_t len = build_tlv(tlv, sizeof(tlv), 0x26, 0x01, 1, g_proxy_addr, g_impl_addr, true, 0, 16);
    s_proxy_info_ctx ctx = {0};
    assert_true(run_parse_and_verify(tlv, len, &ctx));
    // Wrong chain_id must yield NULL even when address+selector match.
    uint64_t wrong_chain = 137;
    assert_null(get_implem_contract(&wrong_chain, g_proxy_addr, g_selector));
}

static void test_lookup_address_mismatch_returns_null(void **state) {
    (void) state;
    uint8_t tlv[256];
    size_t len = build_tlv(tlv, sizeof(tlv), 0x26, 0x01, 1, g_proxy_addr, g_impl_addr, true, 0, 16);
    s_proxy_info_ctx ctx = {0};
    assert_true(run_parse_and_verify(tlv, len, &ctx));
    uint8_t wrong_addr[ADDRESS_LENGTH];
    memset(wrong_addr, 0xCC, ADDRESS_LENGTH);
    uint64_t chain = 1;
    assert_null(get_implem_contract(&chain, wrong_addr, g_selector));
}

static void test_lookup_selector_mismatch_returns_null(void **state) {
    (void) state;
    uint8_t tlv[256];
    size_t len = build_tlv(tlv, sizeof(tlv), 0x26, 0x01, 1, g_proxy_addr, g_impl_addr, true, 0, 16);
    s_proxy_info_ctx ctx = {0};
    assert_true(run_parse_and_verify(tlv, len, &ctx));
    static const uint8_t wrong_selector[CALLDATA_SELECTOR_SIZE] = {0xCA, 0xFE, 0xBA, 0xBE};
    uint64_t chain = 1;
    assert_null(get_implem_contract(&chain, g_proxy_addr, wrong_selector));
}

static void test_lookup_without_selector_in_descriptor_ignores_caller_selector(void **state) {
    (void) state;
    // When the registered descriptor has no selector (has_selector=false),
    // the runtime check skips the selector comparison. Any caller selector
    // is then accepted.
    uint8_t tlv[256];
    size_t len = build_tlv(tlv,
                           sizeof(tlv),
                           0x26,
                           0x01,
                           1,
                           g_proxy_addr,
                           g_impl_addr,
                           /*include_selector=*/false,
                           0,
                           16);
    s_proxy_info_ctx ctx = {0};
    assert_true(run_parse_and_verify(tlv, len, &ctx));
    static const uint8_t any_selector[CALLDATA_SELECTOR_SIZE] = {0xCA, 0xFE, 0xBA, 0xBE};
    uint64_t chain = 1;
    const uint8_t *impl = get_implem_contract(&chain, g_proxy_addr, any_selector);
    assert_non_null(impl);
}

static void test_proxy_cleanup_releases_registration(void **state) {
    (void) state;
    uint8_t tlv[256];
    size_t len = build_tlv(tlv, sizeof(tlv), 0x26, 0x01, 1, g_proxy_addr, g_impl_addr, true, 0, 16);
    s_proxy_info_ctx ctx = {0};
    assert_true(run_parse_and_verify(tlv, len, &ctx));
    uint64_t chain = 1;
    assert_non_null(get_implem_contract(&chain, g_proxy_addr, g_selector));

    proxy_cleanup();
    // After cleanup, both lookups go back to NULL.
    assert_null(get_implem_contract(&chain, g_proxy_addr, g_selector));
    assert_null(get_proxy_contract(&chain, g_impl_addr, g_selector));
}

// =============================================================================
// Runner
// =============================================================================

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup(test_happy_path_registers_descriptor, reset),
        cmocka_unit_test_setup(test_lookups_without_registered_descriptor_return_null, reset),
        cmocka_unit_test_setup(test_signature_check_failure_rejects, reset),
        cmocka_unit_test_setup(test_finalize_hash_failure_rejects, reset),
        cmocka_unit_test_setup(test_invalid_struct_type_rejected, reset),
        cmocka_unit_test_setup(test_invalid_struct_version_rejected, reset),
        cmocka_unit_test_setup(test_delegation_type_out_of_range_rejected, reset),
        cmocka_unit_test_setup(test_signature_too_short_rejected, reset),
        cmocka_unit_test_setup(test_lookup_chain_id_mismatch_returns_null, reset),
        cmocka_unit_test_setup(test_lookup_address_mismatch_returns_null, reset),
        cmocka_unit_test_setup(test_lookup_selector_mismatch_returns_null, reset),
        cmocka_unit_test_setup(test_lookup_without_selector_in_descriptor_ignores_caller_selector,
                               reset),
        cmocka_unit_test_setup(test_proxy_cleanup_releases_registration, reset),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
