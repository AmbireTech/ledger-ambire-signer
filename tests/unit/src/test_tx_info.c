/**
 * @file test_tx_info.c
 * @brief Unit tests for the top-level GCS tx_info struct at
 *        src/features/generic_tx_parser/gtp_tx_info.c.
 *
 * tx_info carries the metadata the device shows for a GCS-driven
 * transaction (operation type, creator name / url, contract name,
 * deploy date) plus the (chain_id, contract_addr, selector,
 * fields_hash) tuple used to bind the signed payload to a concrete
 * call. The module exposes:
 *   - per-tag TLV handlers (covered through handle_tx_info_struct),
 *   - verify_tx_info_struct: enforces version + mandatory tag presence
 *     + signature validity,
 *   - seven getters that all share the same (NULL ? NULL : (empty ?
 *     NULL : field)) shape.
 *
 * Tests focus on:
 *   - the getters' NULL / empty short-circuits,
 *   - happy-path TLV parsing populating every field correctly,
 *   - handle_selector: the security-critical match against the parked
 *     calldata selector (CWE-345-style binding),
 *   - handle_fields_hash / handle_deploy_date size guards,
 *   - verify_tx_info_struct: rejection on missing version, unsupported
 *     version, signature failure, and the happy path.
 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

#include "gtp_tx_info.h"
#include "shared_context.h"
#include "tx_ctx.h"
#include "calldata.h"

// =============================================================================
// Globals the module reads
// =============================================================================

strings_t strings;
static chain_config_t g_chainConfig = {.ticker = "ETH", .chain_id = 1, .coin_type = 60};
const chain_config_t *g_chain_config = &g_chainConfig;
const char g_unknown_ticker[] = "???";
txContext_t txContext;
tmpContent_t tmpContent;
s_calldata *g_parked_calldata = NULL;

// =============================================================================
// Wrapped collaborators
// =============================================================================

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

static uint16_t g_tx_ctx_count = 0;
uint16_t __wrap_get_tx_ctx_count(void) {
    return g_tx_ctx_count;
}

static const uint8_t *g_selector_ret = NULL;
const uint8_t *__wrap_calldata_get_selector(const s_calldata *calldata) {
    (void) calldata;
    return g_selector_ret;
}

// =============================================================================
// Fixtures
// =============================================================================

static int reset(void **state) {
    (void) state;
    g_finalize_hash_ret = true;
    g_sig_check_ret = true;
    g_tx_ctx_count = 1;  // Skip the selector-match by default; tests that
                         // want to exercise the match set it to 0.
    g_selector_ret = NULL;
    return 0;
}

// =============================================================================
// Getters — NULL guard + empty-string guard
// =============================================================================

static void test_getters_null_tx_info_returns_null(void **state) {
    (void) state;
    assert_null(get_operation_type(NULL));
    assert_null(get_creator_name(NULL));
    assert_null(get_creator_legal_name(NULL));
    assert_null(get_creator_url(NULL));
    assert_null(get_contract_name(NULL));
    assert_null(get_deploy_date(NULL));
    assert_null(get_contract_addr(NULL));
}

static void test_getters_empty_string_returns_null(void **state) {
    (void) state;
    s_tx_info info = {0};
    assert_null(get_operation_type(&info));
    assert_null(get_creator_name(&info));
    assert_null(get_creator_legal_name(&info));
    assert_null(get_creator_url(&info));
    assert_null(get_contract_name(&info));
    assert_null(get_deploy_date(&info));
    // get_contract_addr only NULL-guards on tx_info, not on the address
    // bytes — it returns the (possibly zero) address as-is.
    assert_ptr_equal(get_contract_addr(&info), info.contract_addr);
}

static void test_getters_return_populated_fields(void **state) {
    (void) state;
    s_tx_info info = {0};
    strlcpy(info.operation_type, "Approve", sizeof(info.operation_type));
    strlcpy(info.creator_name, "Aave", sizeof(info.creator_name));
    strlcpy(info.creator_legal_name, "Aave DAO", sizeof(info.creator_legal_name));
    strlcpy(info.creator_url, "aave.com", sizeof(info.creator_url));
    strlcpy(info.contract_name, "Pool", sizeof(info.contract_name));
    strlcpy(info.deploy_date, "2024-01-01", sizeof(info.deploy_date));

    assert_string_equal(get_operation_type(&info), "Approve");
    assert_string_equal(get_creator_name(&info), "Aave");
    assert_string_equal(get_creator_legal_name(&info), "Aave DAO");
    assert_string_equal(get_creator_url(&info), "aave.com");
    assert_string_equal(get_contract_name(&info), "Pool");
    assert_string_equal(get_deploy_date(&info), "2024-01-01");
}

// =============================================================================
// handle_tx_info_struct — happy path
// =============================================================================
//
// TLV byte layout: tag(1B) | length(1B for <128) | value.

static bool run_tlv(const uint8_t *bytes, size_t size, s_tx_info_ctx *ctx) {
    buffer_t buf = {.ptr = (uint8_t *) bytes, .size = size, .offset = 0};
    return handle_tx_info_struct(&buf, ctx);
}

static void test_tlv_happy_path_populates_fields(void **state) {
    (void) state;
    s_tx_info info = {0};
    s_tx_info_ctx ctx = {.tx_info = &info};

    // Skip the selector match path
    g_tx_ctx_count = 1;

    const uint8_t bytes[] = {
        0x00,
        0x01,
        0x01,  // VERSION = 1
        0x01,
        0x02,
        0x00,
        0x01,  // CHAIN_ID = 1
        // CONTRACT_ADDR (20 bytes)
        0x02,
        0x14,
        0xAA,
        0xBB,
        0xCC,
        0xDD,
        0xEE,
        0xFF,
        0x11,
        0x22,
        0x33,
        0x44,
        0x55,
        0x66,
        0x77,
        0x88,
        0x99,
        0x00,
        0xAA,
        0xBB,
        0xCC,
        0xDD,
        // SELECTOR (4 bytes)
        0x03,
        0x04,
        0xDE,
        0xAD,
        0xBE,
        0xEF,
        // FIELDS_HASH (32 bytes) — only first 4 set for brevity, helper
        // left-pads with zeros via buf_shrink_expand.
        0x04,
        0x04,
        0x01,
        0x02,
        0x03,
        0x04,
        // OPERATION_TYPE
        0x05,
        0x07,
        'A',
        'p',
        'p',
        'r',
        'o',
        'v',
        'e',
        // CREATOR_NAME
        0x06,
        0x04,
        'A',
        'a',
        'v',
        'e',
        // CONTRACT_NAME
        0x09,
        0x04,
        'P',
        'o',
        'o',
        'l',
        // DEPLOY_DATE (4-byte BE timestamp = 1704067200 = 2024-01-01)
        0x0A,
        0x04,
        0x65,
        0x92,
        0x00,
        0x80,
        // SIGNATURE — any bytes, length is captured for the verify step
        0x81,
        0xFF,
        0x03,
        0xAA,
        0xBB,
        0xCC,  // DER long-form for tag 0xFF
    };
    assert_true(run_tlv(bytes, sizeof(bytes), &ctx));
    assert_int_equal(info.version, 1);
    assert_int_equal(info.chain_id, 1);
    static const uint8_t expected_addr[ADDRESS_LENGTH] = {
        0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22, 0x33, 0x44,
        0x55, 0x66, 0x77, 0x88, 0x99, 0x00, 0xAA, 0xBB, 0xCC, 0xDD,
    };
    assert_memory_equal(info.contract_addr, expected_addr, ADDRESS_LENGTH);
    static const uint8_t expected_selector[4] = {0xDE, 0xAD, 0xBE, 0xEF};
    assert_memory_equal(info.selector, expected_selector, sizeof(expected_selector));
    assert_string_equal(info.operation_type, "Approve");
    assert_string_equal(info.creator_name, "Aave");
    assert_string_equal(info.contract_name, "Pool");
    assert_string_equal(info.deploy_date, "2024-01-01");
    assert_int_equal(info.signature_len, 3);
}

// =============================================================================
// handle_selector — security-critical match against parked calldata
// =============================================================================

static void test_tlv_selector_match_against_parked_calldata(void **state) {
    (void) state;
    s_tx_info info = {0};
    s_tx_info_ctx ctx = {.tx_info = &info};

    // Force the match path: ctx_count==0 → handle_selector must compare
    // against calldata_get_selector(g_parked_calldata).
    g_tx_ctx_count = 0;
    static const uint8_t parked[4] = {0xDE, 0xAD, 0xBE, 0xEF};
    g_selector_ret = parked;

    const uint8_t bytes[] = {
        0x03,
        0x04,
        0xDE,
        0xAD,
        0xBE,
        0xEF,  // matching selector
    };
    assert_true(run_tlv(bytes, sizeof(bytes), &ctx));
    assert_memory_equal(info.selector, parked, sizeof(parked));
}

static void test_tlv_selector_mismatch_rejected(void **state) {
    (void) state;
    s_tx_info info = {0};
    s_tx_info_ctx ctx = {.tx_info = &info};
    g_tx_ctx_count = 0;
    static const uint8_t parked[4] = {0xDE, 0xAD, 0xBE, 0xEF};
    g_selector_ret = parked;

    const uint8_t bytes[] = {
        0x03,
        0x04,
        0xCA,
        0xFE,
        0xBA,
        0xBE,  // does NOT match parked
    };
    assert_false(run_tlv(bytes, sizeof(bytes), &ctx));
}

static void test_tlv_selector_no_parked_calldata_rejected(void **state) {
    (void) state;
    s_tx_info info = {0};
    s_tx_info_ctx ctx = {.tx_info = &info};
    g_tx_ctx_count = 0;
    g_selector_ret = NULL;  // no parked calldata at all

    const uint8_t bytes[] = {
        0x03,
        0x04,
        0xDE,
        0xAD,
        0xBE,
        0xEF,
    };
    assert_false(run_tlv(bytes, sizeof(bytes), &ctx));
}

// =============================================================================
// Size guards
// =============================================================================

static void test_tlv_fields_hash_oversized_rejected(void **state) {
    (void) state;
    s_tx_info info = {0};
    s_tx_info_ctx ctx = {.tx_info = &info};
    g_tx_ctx_count = 1;

    // FIELDS_HASH > 32 bytes is rejected.
    uint8_t bytes[2 + 33];
    bytes[0] = 0x04;
    bytes[1] = 33;
    memset(&bytes[2], 0xAA, 33);
    assert_false(run_tlv(bytes, sizeof(bytes), &ctx));
}

static void test_tlv_deploy_date_oversized_rejected(void **state) {
    (void) state;
    s_tx_info info = {0};
    s_tx_info_ctx ctx = {.tx_info = &info};
    g_tx_ctx_count = 1;

    // DEPLOY_DATE > 4 bytes is rejected.
    uint8_t bytes[2 + 5];
    bytes[0] = 0x0A;
    bytes[1] = 5;
    memset(&bytes[2], 0, 5);
    assert_false(run_tlv(bytes, sizeof(bytes), &ctx));
}

// =============================================================================
// verify_tx_info_struct
// =============================================================================

// Build a fully-valid TLV that hits every required tag for version 1.
static const uint8_t g_valid_v1_tlv[] = {
    0x00, 0x01, 0x01,  // VERSION = 1
    0x01, 0x02, 0x00, 0x01, 0x02, 0x14, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22,
    0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x00, 0xAA, 0xBB, 0xCC, 0xDD, 0x03, 0x04,
    0xDE, 0xAD, 0xBE, 0xEF, 0x04, 0x04, 0x01, 0x02, 0x03, 0x04, 0x05, 0x07, 'A',  'p',
    'p',  'r',  'o',  'v',  'e',  0x81, 0xFF, 0x03, 0xAA, 0xBB, 0xCC,  // SIGNATURE (DER long-form
                                                                       // for tag 0xFF)
};

static void test_verify_missing_version_rejected(void **state) {
    (void) state;
    s_tx_info info = {0};
    s_tx_info_ctx ctx = {.tx_info = &info};
    // Empty TLV → no tag set → TAG_VERSION not received.
    assert_true(run_tlv(NULL, 0, &ctx));
    assert_false(verify_tx_info_struct(&ctx));
}

static void test_verify_unsupported_version_rejected(void **state) {
    (void) state;
    s_tx_info info = {0};
    s_tx_info_ctx ctx = {.tx_info = &info};
    g_tx_ctx_count = 1;
    const uint8_t bytes[] = {0x00, 0x01, 0x99};  // VERSION = 0x99 (not 1)
    assert_true(run_tlv(bytes, sizeof(bytes), &ctx));
    assert_false(verify_tx_info_struct(&ctx));
}

static void test_verify_happy_path(void **state) {
    (void) state;
    s_tx_info info = {0};
    s_tx_info_ctx ctx = {.tx_info = &info};
    g_tx_ctx_count = 1;
    assert_true(run_tlv(g_valid_v1_tlv, sizeof(g_valid_v1_tlv), &ctx));
    assert_true(verify_tx_info_struct(&ctx));
}

static void test_verify_signature_check_failure_rejected(void **state) {
    (void) state;
    s_tx_info info = {0};
    s_tx_info_ctx ctx = {.tx_info = &info};
    g_tx_ctx_count = 1;
    assert_true(run_tlv(g_valid_v1_tlv, sizeof(g_valid_v1_tlv), &ctx));
    g_sig_check_ret = false;
    assert_false(verify_tx_info_struct(&ctx));
}

static void test_verify_finalize_hash_failure_rejected(void **state) {
    (void) state;
    s_tx_info info = {0};
    s_tx_info_ctx ctx = {.tx_info = &info};
    g_tx_ctx_count = 1;
    assert_true(run_tlv(g_valid_v1_tlv, sizeof(g_valid_v1_tlv), &ctx));
    g_finalize_hash_ret = false;
    assert_false(verify_tx_info_struct(&ctx));
}

// =============================================================================
// Runner
// =============================================================================

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup(test_getters_null_tx_info_returns_null, reset),
        cmocka_unit_test_setup(test_getters_empty_string_returns_null, reset),
        cmocka_unit_test_setup(test_getters_return_populated_fields, reset),
        cmocka_unit_test_setup(test_tlv_happy_path_populates_fields, reset),
        cmocka_unit_test_setup(test_tlv_selector_match_against_parked_calldata, reset),
        cmocka_unit_test_setup(test_tlv_selector_mismatch_rejected, reset),
        cmocka_unit_test_setup(test_tlv_selector_no_parked_calldata_rejected, reset),
        cmocka_unit_test_setup(test_tlv_fields_hash_oversized_rejected, reset),
        cmocka_unit_test_setup(test_tlv_deploy_date_oversized_rejected, reset),
        cmocka_unit_test_setup(test_verify_missing_version_rejected, reset),
        cmocka_unit_test_setup(test_verify_unsupported_version_rejected, reset),
        cmocka_unit_test_setup(test_verify_happy_path, reset),
        cmocka_unit_test_setup(test_verify_signature_check_failure_rejected, reset),
        cmocka_unit_test_setup(test_verify_finalize_hash_failure_rejected, reset),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
