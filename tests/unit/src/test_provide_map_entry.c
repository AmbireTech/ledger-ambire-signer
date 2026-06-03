/**
 * @file test_provide_map_entry.c
 * @brief Unit tests for MAP_ENTRY TLV parsing, verification, and lookup
 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>

// Module under test
#include "map_entry.h"

// Headers for mocked functions
#include "public_keys.h"
#include "hash_bytes.h"
#include "shared_context.h"
#include "eth_ustream.h"
#include "tx_ctx.h"
#include "calldata.h"
#include "proxy_info.h"
#include "utils.h"
#include "common_utils.h"
#include "wraps.h"  // extern g_tx_content

// =============================================================================
// Global stubs
// =============================================================================

// Contract address used in all TLV payloads — must match CONTRACT_ADDR_BYTES below
static const uint8_t s_contract_addr[ADDRESS_LENGTH] = {
    0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22, 0x33, 0x44,
    0x55, 0x66, 0x77, 0x88, 0x99, 0x00, 0xAA, 0xBB, 0xCC, 0xDD,
};

// =============================================================================
// Mock functions
// =============================================================================

bool __wrap_finalize_hash(cx_hash_t *hash_ctx, uint8_t *out, size_t out_len) {
    (void) hash_ctx;
    memset(out, 0, out_len);
    return (bool) mock();
}

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
    return (bool) mock();
}

const s_tx_info *__wrap_get_current_tx_info(void) {
    return (const s_tx_info *) mock();
}

s_calldata *__wrap_get_current_calldata(void) {
    return (s_calldata *) mock();
}

const uint8_t *__wrap_calldata_get_selector(const s_calldata *calldata) {
    (void) calldata;
    return (const uint8_t *) mock();
}

const uint8_t *__wrap_get_implem_contract(const uint64_t *chain_id,
                                          const uint8_t *contract_addr,
                                          const uint8_t *selector) {
    (void) chain_id;
    (void) contract_addr;
    (void) selector;
    return (const uint8_t *) mock();
}

// =============================================================================
// Test data
// =============================================================================

#define CONTRACT_ADDR_BYTES                                                                   \
    0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, \
        0x00, 0xAA, 0xBB, 0xCC, 0xDD
#define SELECTOR_BYTES 0xAB, 0xCD, 0xEF, 0x01
#define KEY_BYTES      0xFF, 0xEE, 0xDD
#define VALUE_BYTES    'H', 'e', 'l', 'l', 'o'

// clang-format off
// Tag 0xff is DER-encoded as 0x81 0xff (long form, since 0xff >= 0x80)
static const uint8_t s_valid_payload[] = {
    0x00, 0x01, 0x01,                      // VERSION = 1
    0x01, 0x01, 0x01,                      // CHAIN_ID = 1 (1 byte, minimal encoding)
    0x02, 0x14, CONTRACT_ADDR_BYTES,       // CONTRACT_ADDR (20 bytes)
    0x03, 0x04, SELECTOR_BYTES,            // SELECTOR (4 bytes)
    0x04, 0x01, 0x02,                      // ID = 2
    0x05, 0x03, KEY_BYTES,                 // KEY (3 bytes)
    0x06, 0x05, VALUE_BYTES,               // VALUE (5 bytes "Hello")
    0x81, 0xff, 0x0a,                      // SIGNATURE tag (DER: 0x81 0xff), len=10
    0x00, 0x00, 0x00, 0x00, 0x00,          // fake signature bytes
    0x00, 0x00, 0x00, 0x00, 0x00,
};

static const uint8_t s_payload_no_value[] = {
    0x00, 0x01, 0x01,                      // VERSION
    0x01, 0x01, 0x01,                      // CHAIN_ID
    0x02, 0x14, CONTRACT_ADDR_BYTES,       // CONTRACT_ADDR
    0x03, 0x04, SELECTOR_BYTES,            // SELECTOR
    0x04, 0x01, 0x02,                      // ID
    0x05, 0x03, KEY_BYTES,                 // KEY
    // VALUE (0x06) missing
    0x81, 0xff, 0x0a, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  // SIGNATURE (DER tag)
};
// clang-format on

// =============================================================================
// Helpers
// =============================================================================

static int setup_empty_list(void **state) {
    (void) state;
    map_entry_cleanup();
    return 0;
}

// Register one valid entry into the global list (with mocked signature success).
static void register_entry(void) {
    s_map_entry_ctx ctx = {0};
    buffer_t buf = {.ptr = (uint8_t *) s_valid_payload,
                    .size = sizeof(s_valid_payload),
                    .offset = 0};

    assert_true(handle_map_entry_tlv_payload(&buf, &ctx));
    will_return(__wrap_finalize_hash, true);
    will_return(__wrap_check_signature_with_pubkey, true);
    assert_true(verify_map_entry_struct(&ctx));
}

// =============================================================================
// Test cases — TLV parsing
// =============================================================================

static void test_map_entry_parse_valid(void **state) {
    (void) state;

    s_map_entry_ctx ctx = {0};
    buffer_t buf = {.ptr = (uint8_t *) s_valid_payload,
                    .size = sizeof(s_valid_payload),
                    .offset = 0};

    assert_true(handle_map_entry_tlv_payload(&buf, &ctx));

    assert_int_equal(ctx.entry.chain_id, 1);
    assert_memory_equal(ctx.entry.contract_addr, s_contract_addr, ADDRESS_LENGTH);
    assert_memory_equal(ctx.entry.selector, ((uint8_t[]){SELECTOR_BYTES}), SELECTOR_SIZE);
    assert_int_equal(ctx.entry.id, 2);
    assert_int_equal(ctx.entry.key_size, 3);
    assert_memory_equal(ctx.entry.key, ((uint8_t[]){KEY_BYTES}), 3);
    assert_int_equal(ctx.entry.value_size, 5);
    assert_memory_equal(ctx.entry.value, "Hello", 5);
}

// =============================================================================
// Test cases — signature verification
// =============================================================================

static void test_map_entry_verify_valid(void **state) {
    (void) state;

    s_map_entry_ctx ctx = {0};
    buffer_t buf = {.ptr = (uint8_t *) s_valid_payload,
                    .size = sizeof(s_valid_payload),
                    .offset = 0};

    assert_true(handle_map_entry_tlv_payload(&buf, &ctx));

    will_return(__wrap_finalize_hash, true);
    will_return(__wrap_check_signature_with_pubkey, true);
    assert_true(verify_map_entry_struct(&ctx));
}

static void test_map_entry_verify_bad_sig(void **state) {
    (void) state;

    s_map_entry_ctx ctx = {0};
    buffer_t buf = {.ptr = (uint8_t *) s_valid_payload,
                    .size = sizeof(s_valid_payload),
                    .offset = 0};

    assert_true(handle_map_entry_tlv_payload(&buf, &ctx));

    will_return(__wrap_finalize_hash, true);
    will_return(__wrap_check_signature_with_pubkey, false);
    assert_false(verify_map_entry_struct(&ctx));
}

static void test_map_entry_verify_missing_mandatory_tag(void **state) {
    (void) state;

    // VALUE tag is absent → verify_fields() fails inside verify_map_entry_struct()
    s_map_entry_ctx ctx = {0};
    buffer_t buf = {.ptr = (uint8_t *) s_payload_no_value,
                    .size = sizeof(s_payload_no_value),
                    .offset = 0};

    assert_true(handle_map_entry_tlv_payload(&buf, &ctx));
    assert_false(verify_map_entry_struct(&ctx));
}

// =============================================================================
// Test cases — lookup
// =============================================================================

static void test_map_entry_lookup_no_tx_info(void **state) {
    (void) state;

    will_return(__wrap_get_current_tx_info, NULL);

    uint8_t key[] = {KEY_BYTES};
    assert_null(get_matching_map_entry(2, key, sizeof(key)));
}

static void test_map_entry_lookup_no_selector(void **state) {
    (void) state;

    static const s_tx_info tx_info = {.chain_id = 1};

    will_return(__wrap_get_current_tx_info, &tx_info);
    will_return(__wrap_get_current_calldata, NULL);
    will_return(__wrap_calldata_get_selector, NULL);

    uint8_t key[] = {KEY_BYTES};
    assert_null(get_matching_map_entry(2, key, sizeof(key)));
}

static void test_map_entry_lookup_found(void **state) {
    (void) state;

    static const s_tx_info tx_info = {.chain_id = 1};
    static const uint8_t selector[] = {SELECTOR_BYTES};

    // Set txContext.content->destination to the registered contract address
    memcpy(g_tx_content.destination, s_contract_addr, ADDRESS_LENGTH);
    txContext.content = &g_tx_content;

    register_entry();

    will_return(__wrap_get_current_tx_info, &tx_info);
    will_return(__wrap_get_current_calldata, NULL);
    will_return(__wrap_calldata_get_selector, selector);
    will_return(__wrap_get_implem_contract, NULL);  // no proxy

    uint8_t key[] = {KEY_BYTES};
    const s_map_entry *entry = get_matching_map_entry(2, key, sizeof(key));
    assert_non_null(entry);
    assert_int_equal(entry->value_size, 5);
    assert_memory_equal(entry->value, "Hello", 5);
}

static void test_map_entry_lookup_wrong_key(void **state) {
    (void) state;

    static const s_tx_info tx_info = {.chain_id = 1};
    static const uint8_t selector[] = {SELECTOR_BYTES};

    memcpy(g_tx_content.destination, s_contract_addr, ADDRESS_LENGTH);
    txContext.content = &g_tx_content;

    register_entry();

    will_return(__wrap_get_current_tx_info, &tx_info);
    will_return(__wrap_get_current_calldata, NULL);
    will_return(__wrap_calldata_get_selector, selector);
    will_return(__wrap_get_implem_contract, NULL);

    uint8_t wrong_key[] = {0x11, 0x22, 0x33};
    assert_null(get_matching_map_entry(2, wrong_key, sizeof(wrong_key)));
}

static void test_map_entry_lookup_wrong_id(void **state) {
    (void) state;

    static const s_tx_info tx_info = {.chain_id = 1};
    static const uint8_t selector[] = {SELECTOR_BYTES};

    memcpy(g_tx_content.destination, s_contract_addr, ADDRESS_LENGTH);
    txContext.content = &g_tx_content;

    register_entry();

    will_return(__wrap_get_current_tx_info, &tx_info);
    will_return(__wrap_get_current_calldata, NULL);
    will_return(__wrap_calldata_get_selector, selector);
    will_return(__wrap_get_implem_contract, NULL);

    uint8_t key[] = {KEY_BYTES};
    assert_null(get_matching_map_entry(99, key, sizeof(key)));  // wrong id
}

static void test_map_entry_cleanup(void **state) {
    (void) state;

    register_entry();

    map_entry_cleanup();

    // List is now empty: get_matching_map_entry returns NULL immediately
    will_return(__wrap_get_current_tx_info, NULL);
    uint8_t key[] = {KEY_BYTES};
    assert_null(get_matching_map_entry(2, key, sizeof(key)));
}

// =============================================================================
// Test runner
// =============================================================================

int main(void) {
    const struct CMUnitTest tests[] = {
        // Parsing
        cmocka_unit_test_setup_teardown(test_map_entry_parse_valid,
                                        setup_empty_list,
                                        setup_empty_list),

        // Signature verification
        cmocka_unit_test_setup_teardown(test_map_entry_verify_valid,
                                        setup_empty_list,
                                        setup_empty_list),
        cmocka_unit_test_setup_teardown(test_map_entry_verify_bad_sig,
                                        setup_empty_list,
                                        setup_empty_list),
        cmocka_unit_test_setup_teardown(test_map_entry_verify_missing_mandatory_tag,
                                        setup_empty_list,
                                        setup_empty_list),

        // Lookup
        cmocka_unit_test_setup_teardown(test_map_entry_lookup_no_tx_info,
                                        setup_empty_list,
                                        setup_empty_list),
        cmocka_unit_test_setup_teardown(test_map_entry_lookup_no_selector,
                                        setup_empty_list,
                                        setup_empty_list),
        cmocka_unit_test_setup_teardown(test_map_entry_lookup_found,
                                        setup_empty_list,
                                        setup_empty_list),
        cmocka_unit_test_setup_teardown(test_map_entry_lookup_wrong_key,
                                        setup_empty_list,
                                        setup_empty_list),
        cmocka_unit_test_setup_teardown(test_map_entry_lookup_wrong_id,
                                        setup_empty_list,
                                        setup_empty_list),
        cmocka_unit_test_setup_teardown(test_map_entry_cleanup, setup_empty_list, setup_empty_list),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
