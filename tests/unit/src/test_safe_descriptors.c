/**
 * @file test_safe_descriptors.c
 * @brief Unit tests for the Gnosis-Safe descriptor backend at
 *        src/features/provide_safe_account/{safe,signer}_descriptor.c.
 *
 * A Safe account is rendered by the device using two paired backend-
 * signed payloads:
 *   - safe_descriptor: identifies the Safe by (address, threshold,
 *     signers_count, role-of-current-user). Signed by the LES_MULTISIG
 *     backend.
 *   - signer_descriptor: lists the actual signer addresses (count must
 *     match SAFE_DESC->signers_count). Also signed by LES_MULTISIG.
 *
 * The two descriptors must arrive in order: safe first, then signer.
 * Both share a CHALLENGE TLV; roll_challenge is called at distinct
 * points to invalidate the captured pair against later replays
 * (CWE-294 mitigation).
 *
 * Coverage drives both files end-to-end through real tlv_apdu /
 * tlv_utils stack with the SDK crypto / signature-verification calls
 * wrapped.
 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

#include "shared_context.h"
#include "safe_descriptor.h"
#include "signer_descriptor.h"

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

static int g_roll_challenge_calls = 0;
void roll_challenge(void) {
    g_roll_challenge_calls++;
}

bool is_zeroes_buffer(const void *buf, size_t n) {
    const uint8_t *p = (const uint8_t *) buf;
    for (size_t i = 0; i < n; ++i) {
        if (p[i] != 0) return false;
    }
    return true;
}

// =============================================================================
// Test data
// =============================================================================

static const uint8_t g_safe_addr[ADDRESS_LENGTH] = {
    0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
    0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
};
static const uint8_t g_signer1[ADDRESS_LENGTH] = {
    0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB,
    0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB,
};
static const uint8_t g_signer2[ADDRESS_LENGTH] = {
    0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
    0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
};

// =============================================================================
// TLV builders
// =============================================================================

typedef struct {
    uint8_t struct_type;
    uint8_t struct_version;
    const uint8_t *address;
    uint16_t threshold;
    uint16_t signers_count;
    uint8_t role;
    uint8_t sig_len;
    bool omit_address;
    bool omit_threshold;
} s_safe_opts;

static size_t build_safe_tlv(uint8_t *out, size_t out_size, s_safe_opts opts) {
    size_t off = 0;
    out[off++] = 0x01;
    out[off++] = 0x01;
    out[off++] = opts.struct_type;
    out[off++] = 0x02;
    out[off++] = 0x01;
    out[off++] = opts.struct_version;
    out[off++] = 0x12;
    out[off++] = 0x04;
    out[off++] = 0xDE;
    out[off++] = 0xAD;
    out[off++] = 0xBE;
    out[off++] = 0xEF;
    if (!opts.omit_address) {
        out[off++] = 0x22;
        out[off++] = ADDRESS_LENGTH;
        memcpy(out + off, opts.address, ADDRESS_LENGTH);
        off += ADDRESS_LENGTH;
    }
    // tag 0xa0 = THRESHOLD ≥ 0x80 needs DER long-form (0x81 0xa0)
    if (!opts.omit_threshold) {
        out[off++] = 0x81;
        out[off++] = 0xa0;
        out[off++] = 0x02;
        out[off++] = (uint8_t) (opts.threshold >> 8);
        out[off++] = (uint8_t) (opts.threshold & 0xFF);
    }
    // 0xa1 SIGNERS_COUNT
    out[off++] = 0x81;
    out[off++] = 0xa1;
    out[off++] = 0x02;
    out[off++] = (uint8_t) (opts.signers_count >> 8);
    out[off++] = (uint8_t) (opts.signers_count & 0xFF);
    // 0xa2 ROLE
    out[off++] = 0x81;
    out[off++] = 0xa2;
    out[off++] = 0x01;
    out[off++] = opts.role;
    // 0x15 SIGNATURE
    out[off++] = 0x15;
    out[off++] = opts.sig_len;
    memset(out + off, 0x42, opts.sig_len);
    off += opts.sig_len;
    assert_true(off <= out_size);
    return off;
}

typedef struct {
    uint8_t struct_type;
    uint8_t struct_version;
    const uint8_t *addresses[4];
    uint8_t address_count;
    uint8_t sig_len;
} s_signer_opts;

static size_t build_signer_tlv(uint8_t *out, size_t out_size, s_signer_opts opts) {
    size_t off = 0;
    out[off++] = 0x01;
    out[off++] = 0x01;
    out[off++] = opts.struct_type;
    out[off++] = 0x02;
    out[off++] = 0x01;
    out[off++] = opts.struct_version;
    out[off++] = 0x12;
    out[off++] = 0x04;
    out[off++] = 0xDE;
    out[off++] = 0xAD;
    out[off++] = 0xBE;
    out[off++] = 0xEF;
    for (int i = 0; i < opts.address_count; ++i) {
        out[off++] = 0x22;
        out[off++] = ADDRESS_LENGTH;
        memcpy(out + off, opts.addresses[i], ADDRESS_LENGTH);
        off += ADDRESS_LENGTH;
    }
    out[off++] = 0x15;
    out[off++] = opts.sig_len;
    memset(out + off, 0x42, opts.sig_len);
    off += opts.sig_len;
    assert_true(off <= out_size);
    return off;
}

// =============================================================================
// Fixture
// =============================================================================

static int reset(void **state) {
    (void) state;
    clear_safe_descriptor();
    clear_signer_descriptor();
    g_sig_check_ret = true;
    g_finalize_hash_ret = true;
    g_roll_challenge_calls = 0;
    return 0;
}

static bool run_safe(const uint8_t *bytes, size_t len) {
    buffer_t buf = {.ptr = (uint8_t *) bytes, .size = len, .offset = 0};
    return handle_safe_tlv_payload(&buf);
}

static bool run_signer(const uint8_t *bytes, size_t len) {
    buffer_t buf = {.ptr = (uint8_t *) bytes, .size = len, .offset = 0};
    return handle_signer_tlv_payload(&buf);
}

// =============================================================================
// safe_descriptor tests
// =============================================================================

static void test_safe_happy_path_registers(void **state) {
    (void) state;
    uint8_t tlv[200];
    s_safe_opts opts = {.struct_type = 0x27,
                        .struct_version = 0x01,
                        .address = g_safe_addr,
                        .threshold = 2,
                        .signers_count = 3,
                        .role = ROLE_SIGNER,
                        .sig_len = 16};
    size_t len = build_safe_tlv(tlv, sizeof(tlv), opts);
    assert_true(run_safe(tlv, len));
    assert_non_null(SAFE_DESC);
    assert_int_equal(SAFE_DESC->threshold, 2);
    assert_int_equal(SAFE_DESC->signers_count, 3);
    assert_int_equal(SAFE_DESC->role, ROLE_SIGNER);
    // Happy path does NOT roll the challenge — the signer descriptor
    // that follows is signed against the same challenge.
    assert_int_equal(g_roll_challenge_calls, 0);
}

static void test_safe_invalid_struct_type_rejected(void **state) {
    (void) state;
    uint8_t tlv[200];
    s_safe_opts opts = {.struct_type = 0xFF,  // not TYPE_LESM_ACCOUNT_INFO
                        .struct_version = 0x01,
                        .address = g_safe_addr,
                        .threshold = 2,
                        .signers_count = 3,
                        .role = ROLE_SIGNER,
                        .sig_len = 16};
    size_t len = build_safe_tlv(tlv, sizeof(tlv), opts);
    assert_false(run_safe(tlv, len));
    assert_null(SAFE_DESC);
    // Failure path rolls the challenge (replay defense).
    assert_int_equal(g_roll_challenge_calls, 1);
}

static void test_safe_invalid_struct_version_rejected(void **state) {
    (void) state;
    uint8_t tlv[200];
    s_safe_opts opts = {.struct_type = 0x27,
                        .struct_version = 0x05,
                        .address = g_safe_addr,
                        .threshold = 2,
                        .signers_count = 3,
                        .role = ROLE_SIGNER,
                        .sig_len = 16};
    size_t len = build_safe_tlv(tlv, sizeof(tlv), opts);
    assert_false(run_safe(tlv, len));
}

static void test_safe_address_all_zeros_rejected(void **state) {
    (void) state;
    static const uint8_t zero_addr[ADDRESS_LENGTH] = {0};
    uint8_t tlv[200];
    s_safe_opts opts = {.struct_type = 0x27,
                        .struct_version = 0x01,
                        .address = zero_addr,
                        .threshold = 2,
                        .signers_count = 3,
                        .role = ROLE_SIGNER,
                        .sig_len = 16};
    size_t len = build_safe_tlv(tlv, sizeof(tlv), opts);
    assert_false(run_safe(tlv, len));
}

static void test_safe_threshold_zero_rejected(void **state) {
    (void) state;
    uint8_t tlv[200];
    s_safe_opts opts = {.struct_type = 0x27,
                        .struct_version = 0x01,
                        .address = g_safe_addr,
                        .threshold = 0,  // below min 1
                        .signers_count = 3,
                        .role = ROLE_SIGNER,
                        .sig_len = 16};
    size_t len = build_safe_tlv(tlv, sizeof(tlv), opts);
    assert_false(run_safe(tlv, len));
}

static void test_safe_threshold_above_max_rejected(void **state) {
    (void) state;
    uint8_t tlv[200];
    s_safe_opts opts = {.struct_type = 0x27,
                        .struct_version = 0x01,
                        .address = g_safe_addr,
                        .threshold = 101,  // above MAX_THRESHOLD=100
                        .signers_count = 3,
                        .role = ROLE_SIGNER,
                        .sig_len = 16};
    size_t len = build_safe_tlv(tlv, sizeof(tlv), opts);
    assert_false(run_safe(tlv, len));
}

static void test_safe_signers_count_zero_rejected(void **state) {
    (void) state;
    uint8_t tlv[200];
    s_safe_opts opts = {.struct_type = 0x27,
                        .struct_version = 0x01,
                        .address = g_safe_addr,
                        .threshold = 2,
                        .signers_count = 0,
                        .role = ROLE_SIGNER,
                        .sig_len = 16};
    size_t len = build_safe_tlv(tlv, sizeof(tlv), opts);
    assert_false(run_safe(tlv, len));
}

static void test_safe_role_out_of_range_rejected(void **state) {
    (void) state;
    uint8_t tlv[200];
    s_safe_opts opts = {.struct_type = 0x27,
                        .struct_version = 0x01,
                        .address = g_safe_addr,
                        .threshold = 2,
                        .signers_count = 3,
                        .role = 0x7F,  // outside [0, ROLE_MAX=2]
                        .sig_len = 16};
    size_t len = build_safe_tlv(tlv, sizeof(tlv), opts);
    assert_false(run_safe(tlv, len));
}

static void test_safe_signature_check_failure_rejects(void **state) {
    (void) state;
    g_sig_check_ret = false;
    uint8_t tlv[200];
    s_safe_opts opts = {.struct_type = 0x27,
                        .struct_version = 0x01,
                        .address = g_safe_addr,
                        .threshold = 2,
                        .signers_count = 3,
                        .role = ROLE_SIGNER,
                        .sig_len = 16};
    size_t len = build_safe_tlv(tlv, sizeof(tlv), opts);
    assert_false(run_safe(tlv, len));
    assert_null(SAFE_DESC);
}

static void test_safe_signature_too_short_rejected(void **state) {
    (void) state;
    uint8_t tlv[200];
    s_safe_opts opts = {.struct_type = 0x27,
                        .struct_version = 0x01,
                        .address = g_safe_addr,
                        .threshold = 2,
                        .signers_count = 3,
                        .role = ROLE_SIGNER,
                        .sig_len = 4};  // < MIN=8
    size_t len = build_safe_tlv(tlv, sizeof(tlv), opts);
    assert_false(run_safe(tlv, len));
}

static void test_safe_missing_threshold_rejected(void **state) {
    (void) state;
    uint8_t tlv[200];
    s_safe_opts opts = {.struct_type = 0x27,
                        .struct_version = 0x01,
                        .address = g_safe_addr,
                        .signers_count = 3,
                        .role = ROLE_SIGNER,
                        .omit_threshold = true,
                        .sig_len = 16};
    size_t len = build_safe_tlv(tlv, sizeof(tlv), opts);
    assert_false(run_safe(tlv, len));
}

// =============================================================================
// signer_descriptor tests — require a registered safe_descriptor.
// =============================================================================

static void register_safe_for_signer_tests(uint16_t signers_count) {
    uint8_t tlv[200];
    s_safe_opts opts = {.struct_type = 0x27,
                        .struct_version = 0x01,
                        .address = g_safe_addr,
                        .threshold = 2,
                        .signers_count = signers_count,
                        .role = ROLE_SIGNER,
                        .sig_len = 16};
    size_t len = build_safe_tlv(tlv, sizeof(tlv), opts);
    assert_true(run_safe(tlv, len));
}

static void test_signer_without_safe_rejected(void **state) {
    (void) state;
    // No prior safe_descriptor — SAFE_DESC is NULL.
    assert_null(SAFE_DESC);
    uint8_t tlv[200];
    s_signer_opts opts = {.struct_type = 0x0A,
                          .struct_version = 0x01,
                          .addresses = {g_signer1, g_signer2},
                          .address_count = 2,
                          .sig_len = 16};
    size_t len = build_signer_tlv(tlv, sizeof(tlv), opts);
    assert_false(run_signer(tlv, len));
}

static void test_signer_duplicate_rejected(void **state) {
    (void) state;
    register_safe_for_signer_tests(2);
    uint8_t tlv[200];
    s_signer_opts opts = {.struct_type = 0x0A,
                          .struct_version = 0x01,
                          .addresses = {g_signer1, g_signer2},
                          .address_count = 2,
                          .sig_len = 16};
    size_t len = build_signer_tlv(tlv, sizeof(tlv), opts);
    assert_true(run_signer(tlv, len));
    // Second invocation with SIGNER_DESC.data already set must reject.
    assert_false(run_signer(tlv, len));
}

static void test_signer_happy_path_registers(void **state) {
    (void) state;
    register_safe_for_signer_tests(2);
    g_roll_challenge_calls = 0;  // ignore safe-registration
    uint8_t tlv[200];
    s_signer_opts opts = {.struct_type = 0x0A,
                          .struct_version = 0x01,
                          .addresses = {g_signer1, g_signer2},
                          .address_count = 2,
                          .sig_len = 16};
    size_t len = build_signer_tlv(tlv, sizeof(tlv), opts);
    assert_true(run_signer(tlv, len));
    assert_true(SIGNER_DESC.is_valid);
    // Signer-descriptor consumption always rolls the challenge
    // (CWE-294 mitigation, success and failure alike).
    assert_int_equal(g_roll_challenge_calls, 1);
}

static void test_signer_invalid_struct_type_rejected(void **state) {
    (void) state;
    register_safe_for_signer_tests(2);
    uint8_t tlv[200];
    s_signer_opts opts = {.struct_type = 0xFF,
                          .struct_version = 0x01,
                          .addresses = {g_signer1, g_signer2},
                          .address_count = 2,
                          .sig_len = 16};
    size_t len = build_signer_tlv(tlv, sizeof(tlv), opts);
    assert_false(run_signer(tlv, len));
}

static void test_signer_address_all_zeros_rejected(void **state) {
    (void) state;
    register_safe_for_signer_tests(2);
    static const uint8_t zero_addr[ADDRESS_LENGTH] = {0};
    uint8_t tlv[200];
    s_signer_opts opts = {.struct_type = 0x0A,
                          .struct_version = 0x01,
                          .addresses = {g_signer1, zero_addr},  // 2nd is zero
                          .address_count = 2,
                          .sig_len = 16};
    size_t len = build_signer_tlv(tlv, sizeof(tlv), opts);
    assert_false(run_signer(tlv, len));
}

static void test_signer_too_few_addresses_rejected(void **state) {
    (void) state;
    register_safe_for_signer_tests(3);  // SAFE expects 3
    uint8_t tlv[200];
    s_signer_opts opts = {.struct_type = 0x0A,
                          .struct_version = 0x01,
                          .addresses = {g_signer1, g_signer2},  // only 2
                          .address_count = 2,
                          .sig_len = 16};
    size_t len = build_signer_tlv(tlv, sizeof(tlv), opts);
    assert_false(run_signer(tlv, len));
}

static void test_signer_too_many_addresses_rejected(void **state) {
    (void) state;
    register_safe_for_signer_tests(1);  // SAFE expects 1
    uint8_t tlv[200];
    s_signer_opts opts = {.struct_type = 0x0A,
                          .struct_version = 0x01,
                          .addresses = {g_signer1, g_signer2},
                          .address_count = 2,  // but we send 2
                          .sig_len = 16};
    size_t len = build_signer_tlv(tlv, sizeof(tlv), opts);
    assert_false(run_signer(tlv, len));
}

static void test_signer_signature_check_failure_rejects(void **state) {
    (void) state;
    register_safe_for_signer_tests(2);
    g_sig_check_ret = false;
    uint8_t tlv[200];
    s_signer_opts opts = {.struct_type = 0x0A,
                          .struct_version = 0x01,
                          .addresses = {g_signer1, g_signer2},
                          .address_count = 2,
                          .sig_len = 16};
    size_t len = build_signer_tlv(tlv, sizeof(tlv), opts);
    assert_false(run_signer(tlv, len));
}

static void test_clear_safe_and_signer_releases(void **state) {
    (void) state;
    register_safe_for_signer_tests(2);
    uint8_t tlv[200];
    s_signer_opts opts = {.struct_type = 0x0A,
                          .struct_version = 0x01,
                          .addresses = {g_signer1, g_signer2},
                          .address_count = 2,
                          .sig_len = 16};
    size_t len = build_signer_tlv(tlv, sizeof(tlv), opts);
    assert_true(run_signer(tlv, len));
    assert_non_null(SAFE_DESC);
    assert_non_null(SIGNER_DESC.data);
    clear_signer_descriptor();
    assert_null(SIGNER_DESC.data);
    clear_safe_descriptor();
    assert_null(SAFE_DESC);
}

// =============================================================================
// Runner
// =============================================================================

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup(test_safe_happy_path_registers, reset),
        cmocka_unit_test_setup(test_safe_invalid_struct_type_rejected, reset),
        cmocka_unit_test_setup(test_safe_invalid_struct_version_rejected, reset),
        cmocka_unit_test_setup(test_safe_address_all_zeros_rejected, reset),
        cmocka_unit_test_setup(test_safe_threshold_zero_rejected, reset),
        cmocka_unit_test_setup(test_safe_threshold_above_max_rejected, reset),
        cmocka_unit_test_setup(test_safe_signers_count_zero_rejected, reset),
        cmocka_unit_test_setup(test_safe_role_out_of_range_rejected, reset),
        cmocka_unit_test_setup(test_safe_signature_check_failure_rejects, reset),
        cmocka_unit_test_setup(test_safe_signature_too_short_rejected, reset),
        cmocka_unit_test_setup(test_safe_missing_threshold_rejected, reset),
        cmocka_unit_test_setup(test_signer_without_safe_rejected, reset),
        cmocka_unit_test_setup(test_signer_duplicate_rejected, reset),
        cmocka_unit_test_setup(test_signer_happy_path_registers, reset),
        cmocka_unit_test_setup(test_signer_invalid_struct_type_rejected, reset),
        cmocka_unit_test_setup(test_signer_address_all_zeros_rejected, reset),
        cmocka_unit_test_setup(test_signer_too_few_addresses_rejected, reset),
        cmocka_unit_test_setup(test_signer_too_many_addresses_rejected, reset),
        cmocka_unit_test_setup(test_signer_signature_check_failure_rejects, reset),
        cmocka_unit_test_setup(test_clear_safe_and_signer_releases, reset),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
