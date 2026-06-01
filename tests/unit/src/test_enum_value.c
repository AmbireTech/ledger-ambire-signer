/**
 * @file test_enum_value.c
 * @brief Unit tests for the enum-value backend descriptor at
 *        src/features/provide_enum_value/enum_value.c.
 *
 * An enum-value descriptor is the backend-signed mapping that says
 * "for contract X on chain Y, parameter slot ID, when the on-the-wire
 * value is N, display the label NAME". The device uses this to render
 * a meaningful name where it would otherwise display a raw uint8.
 *
 * A bug in the parser or lookup lets an attacker put any name in
 * front of any value/contract combination — e.g. "Standard execution"
 * could be displayed for a value that actually means "Delegate call
 * via $attacker_module". The signature gate against
 * CERTIFICATE_PUBLIC_KEY_USAGE_CALLDATA is the load-bearing defense.
 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

#include "shared_context.h"
#include "enum_value.h"

// =============================================================================
// Globals
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

void __wrap_hash_nbytes(const uint8_t *bytes, size_t n, cx_hash_t *hash_ctx) {
    (void) bytes;
    (void) n;
    (void) hash_ctx;
}

uint32_t cx_sha256_init_no_throw(cx_sha256_t *hash) {
    (void) hash;
    return 0;
}

// get_implem_contract is the proxy resolver. is_matching_enum consults
// it to remap a proxy address to its implementation before comparing
// against the registered contract_addr.
static const uint8_t *g_implem_contract_ret = NULL;
const uint8_t *__wrap_get_implem_contract(const uint64_t *chain_id,
                                          const uint8_t *addr,
                                          const uint8_t *selector) {
    (void) chain_id;
    (void) addr;
    (void) selector;
    return g_implem_contract_ret;
}

// =============================================================================
// Test data
// =============================================================================

static const uint8_t g_contract_addr[ADDRESS_LENGTH] = {
    0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
    0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
};
static const uint8_t g_selector[SELECTOR_SIZE] = {0xDE, 0xAD, 0xBE, 0xEF};

// =============================================================================
// TLV builder
// =============================================================================

typedef struct {
    uint8_t version;
    uint8_t chain_id;
    const uint8_t *contract_addr;
    const uint8_t *selector;
    uint8_t id;
    uint8_t value;
    const char *name;
    uint8_t sig_len;
    bool omit_id;
} s_opts;

static size_t build_tlv(uint8_t *out, size_t out_size, s_opts opts) {
    size_t off = 0;
    // 0x00 VERSION
    out[off++] = 0x00;
    out[off++] = 0x01;
    out[off++] = opts.version;
    // 0x01 CHAIN_ID
    out[off++] = 0x01;
    out[off++] = 0x01;
    out[off++] = opts.chain_id;
    // 0x02 CONTRACT_ADDR
    out[off++] = 0x02;
    out[off++] = ADDRESS_LENGTH;
    memcpy(out + off, opts.contract_addr, ADDRESS_LENGTH);
    off += ADDRESS_LENGTH;
    // 0x03 SELECTOR
    out[off++] = 0x03;
    out[off++] = SELECTOR_SIZE;
    memcpy(out + off, opts.selector, SELECTOR_SIZE);
    off += SELECTOR_SIZE;
    if (!opts.omit_id) {
        // 0x04 ID
        out[off++] = 0x04;
        out[off++] = 0x01;
        out[off++] = opts.id;
    }
    // 0x05 VALUE
    out[off++] = 0x05;
    out[off++] = 0x01;
    out[off++] = opts.value;
    // 0x06 NAME
    size_t name_len = strlen(opts.name);
    out[off++] = 0x06;
    out[off++] = (uint8_t) name_len;
    memcpy(out + off, opts.name, name_len);
    off += name_len;
    // 0xFF SIGNATURE — DER long-form for tag ≥ 0x80
    out[off++] = 0x81;
    out[off++] = 0xFF;
    out[off++] = opts.sig_len;
    memset(out + off, 0x42, opts.sig_len);
    off += opts.sig_len;
    assert_true(off <= out_size);
    return off;
}

static bool run(const uint8_t *tlv, size_t len) {
    s_enum_value_ctx ctx = {0};
    buffer_t buf = {.ptr = (uint8_t *) tlv, .size = len, .offset = 0};
    if (!handle_enum_value_tlv_payload(&buf, &ctx)) return false;
    return verify_enum_value_struct(&ctx);
}

// =============================================================================
// Fixture
// =============================================================================

static int reset(void **state) {
    (void) state;
    enum_value_cleanup();
    g_sig_check_ret = true;
    g_finalize_hash_ret = true;
    g_implem_contract_ret = NULL;
    return 0;
}

// =============================================================================
// Tests
// =============================================================================

static void test_happy_path_registers_entry(void **state) {
    (void) state;
    uint8_t tlv[256];
    s_opts opts = {.version = 0x01,
                   .chain_id = 1,
                   .contract_addr = g_contract_addr,
                   .selector = g_selector,
                   .id = 5,
                   .value = 2,
                   .name = "Standard",
                   .sig_len = 16};
    size_t len = build_tlv(tlv, sizeof(tlv), opts);
    assert_true(run(tlv, len));
    uint64_t chain = 1;
    const s_enum_value_entry *e = get_matching_enum(&chain, g_contract_addr, g_selector, 5, 2);
    assert_non_null(e);
    assert_string_equal(e->name, "Standard");
}

static void test_lookup_no_registration_returns_null(void **state) {
    (void) state;
    uint64_t chain = 1;
    assert_null(get_matching_enum(&chain, g_contract_addr, g_selector, 0, 0));
}

static void test_invalid_version_rejected(void **state) {
    (void) state;
    uint8_t tlv[256];
    s_opts opts = {.version = 0x07,  // not STRUCT_VERSION
                   .chain_id = 1,
                   .contract_addr = g_contract_addr,
                   .selector = g_selector,
                   .id = 5,
                   .value = 2,
                   .name = "X",
                   .sig_len = 16};
    size_t len = build_tlv(tlv, sizeof(tlv), opts);
    assert_false(run(tlv, len));
}

static void test_signature_failure_rejects(void **state) {
    (void) state;
    g_sig_check_ret = false;
    uint8_t tlv[256];
    s_opts opts = {.version = 0x01,
                   .chain_id = 1,
                   .contract_addr = g_contract_addr,
                   .selector = g_selector,
                   .id = 5,
                   .value = 2,
                   .name = "X",
                   .sig_len = 16};
    size_t len = build_tlv(tlv, sizeof(tlv), opts);
    assert_false(run(tlv, len));
    uint64_t chain = 1;
    assert_null(get_matching_enum(&chain, g_contract_addr, g_selector, 5, 2));
}

static void test_finalize_hash_failure_rejects(void **state) {
    (void) state;
    g_finalize_hash_ret = false;
    uint8_t tlv[256];
    s_opts opts = {.version = 0x01,
                   .chain_id = 1,
                   .contract_addr = g_contract_addr,
                   .selector = g_selector,
                   .id = 5,
                   .value = 2,
                   .name = "X",
                   .sig_len = 16};
    size_t len = build_tlv(tlv, sizeof(tlv), opts);
    assert_false(run(tlv, len));
}

static void test_signature_too_short_rejected(void **state) {
    (void) state;
    uint8_t tlv[256];
    s_opts opts = {.version = 0x01,
                   .chain_id = 1,
                   .contract_addr = g_contract_addr,
                   .selector = g_selector,
                   .id = 5,
                   .value = 2,
                   .name = "X",
                   .sig_len = 4};  // < CX_ECDSA_SHA256_SIG_MIN_ASN1_LENGTH
    size_t len = build_tlv(tlv, sizeof(tlv), opts);
    assert_false(run(tlv, len));
}

static void test_missing_required_field_rejected(void **state) {
    (void) state;
    uint8_t tlv[256];
    s_opts opts = {.version = 0x01,
                   .chain_id = 1,
                   .contract_addr = g_contract_addr,
                   .selector = g_selector,
                   .value = 2,
                   .name = "X",
                   .omit_id = true,  // missing TAG_ID
                   .sig_len = 16};
    size_t len = build_tlv(tlv, sizeof(tlv), opts);
    assert_false(run(tlv, len));
}

static void test_lookup_chain_mismatch_returns_null(void **state) {
    (void) state;
    uint8_t tlv[256];
    s_opts opts = {.version = 0x01,
                   .chain_id = 1,
                   .contract_addr = g_contract_addr,
                   .selector = g_selector,
                   .id = 5,
                   .value = 2,
                   .name = "Standard",
                   .sig_len = 16};
    size_t len = build_tlv(tlv, sizeof(tlv), opts);
    assert_true(run(tlv, len));
    uint64_t wrong_chain = 137;
    assert_null(get_matching_enum(&wrong_chain, g_contract_addr, g_selector, 5, 2));
}

static void test_lookup_address_mismatch_returns_null(void **state) {
    (void) state;
    uint8_t tlv[256];
    s_opts opts = {.version = 0x01,
                   .chain_id = 1,
                   .contract_addr = g_contract_addr,
                   .selector = g_selector,
                   .id = 5,
                   .value = 2,
                   .name = "Standard",
                   .sig_len = 16};
    size_t len = build_tlv(tlv, sizeof(tlv), opts);
    assert_true(run(tlv, len));
    uint8_t wrong_addr[ADDRESS_LENGTH];
    memset(wrong_addr, 0xCC, ADDRESS_LENGTH);
    uint64_t chain = 1;
    assert_null(get_matching_enum(&chain, wrong_addr, g_selector, 5, 2));
}

static void test_lookup_id_value_mismatch_returns_null(void **state) {
    (void) state;
    uint8_t tlv[256];
    s_opts opts = {.version = 0x01,
                   .chain_id = 1,
                   .contract_addr = g_contract_addr,
                   .selector = g_selector,
                   .id = 5,
                   .value = 2,
                   .name = "Standard",
                   .sig_len = 16};
    size_t len = build_tlv(tlv, sizeof(tlv), opts);
    assert_true(run(tlv, len));
    uint64_t chain = 1;
    // Right (contract, selector, chain) but wrong (id, value).
    assert_null(get_matching_enum(&chain, g_contract_addr, g_selector, 99, 2));
    assert_null(get_matching_enum(&chain, g_contract_addr, g_selector, 5, 99));
}

static void test_lookup_consults_proxy_resolver(void **state) {
    (void) state;
    // Register an entry for the *implementation* address. Looking up
    // with the *proxy* address triggers get_implem_contract which
    // remaps to impl — the match must succeed.
    uint8_t tlv[256];
    s_opts opts = {.version = 0x01,
                   .chain_id = 1,
                   .contract_addr = g_contract_addr,
                   .selector = g_selector,
                   .id = 5,
                   .value = 2,
                   .name = "Standard",
                   .sig_len = 16};
    size_t len = build_tlv(tlv, sizeof(tlv), opts);
    assert_true(run(tlv, len));

    // Map (any_proxy, selector, chain) -> g_contract_addr.
    g_implem_contract_ret = g_contract_addr;
    uint8_t proxy_addr[ADDRESS_LENGTH] = {0xCC};
    uint64_t chain = 1;
    const s_enum_value_entry *e = get_matching_enum(&chain, proxy_addr, g_selector, 5, 2);
    assert_non_null(e);
}

static void test_two_entries_lookup_returns_matching_one(void **state) {
    (void) state;
    uint8_t tlv[256];
    s_opts a = {.version = 0x01,
                .chain_id = 1,
                .contract_addr = g_contract_addr,
                .selector = g_selector,
                .id = 5,
                .value = 0,
                .name = "Zero",
                .sig_len = 16};
    s_opts b = {.version = 0x01,
                .chain_id = 1,
                .contract_addr = g_contract_addr,
                .selector = g_selector,
                .id = 5,
                .value = 1,
                .name = "One",
                .sig_len = 16};
    size_t len = build_tlv(tlv, sizeof(tlv), a);
    assert_true(run(tlv, len));
    len = build_tlv(tlv, sizeof(tlv), b);
    assert_true(run(tlv, len));
    uint64_t chain = 1;
    const s_enum_value_entry *e0 = get_matching_enum(&chain, g_contract_addr, g_selector, 5, 0);
    const s_enum_value_entry *e1 = get_matching_enum(&chain, g_contract_addr, g_selector, 5, 1);
    assert_non_null(e0);
    assert_non_null(e1);
    assert_string_equal(e0->name, "Zero");
    assert_string_equal(e1->name, "One");
}

static void test_enum_value_cleanup_releases_list(void **state) {
    (void) state;
    uint8_t tlv[256];
    s_opts opts = {.version = 0x01,
                   .chain_id = 1,
                   .contract_addr = g_contract_addr,
                   .selector = g_selector,
                   .id = 5,
                   .value = 2,
                   .name = "Standard",
                   .sig_len = 16};
    size_t len = build_tlv(tlv, sizeof(tlv), opts);
    assert_true(run(tlv, len));
    uint64_t chain = 1;
    assert_non_null(get_matching_enum(&chain, g_contract_addr, g_selector, 5, 2));
    enum_value_cleanup();
    assert_null(get_matching_enum(&chain, g_contract_addr, g_selector, 5, 2));
}

// =============================================================================
// Runner
// =============================================================================

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup(test_happy_path_registers_entry, reset),
        cmocka_unit_test_setup(test_lookup_no_registration_returns_null, reset),
        cmocka_unit_test_setup(test_invalid_version_rejected, reset),
        cmocka_unit_test_setup(test_signature_failure_rejects, reset),
        cmocka_unit_test_setup(test_finalize_hash_failure_rejects, reset),
        cmocka_unit_test_setup(test_signature_too_short_rejected, reset),
        cmocka_unit_test_setup(test_missing_required_field_rejected, reset),
        cmocka_unit_test_setup(test_lookup_chain_mismatch_returns_null, reset),
        cmocka_unit_test_setup(test_lookup_address_mismatch_returns_null, reset),
        cmocka_unit_test_setup(test_lookup_id_value_mismatch_returns_null, reset),
        cmocka_unit_test_setup(test_lookup_consults_proxy_resolver, reset),
        cmocka_unit_test_setup(test_two_entries_lookup_returns_matching_one, reset),
        cmocka_unit_test_setup(test_enum_value_cleanup_releases_list, reset),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
