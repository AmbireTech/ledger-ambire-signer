/**
 * @file test_param_calldata.c
 * @brief Unit tests for CALLDATA parameter formatting, focusing on
 *        §3.1.8 iteration broadcast (contract_addr of size 1 repeated
 *        across all calldata iterations).
 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

#include "gtp_param_calldata.h"
#include "gtp_parsed_value.h"
#include "gtp_value.h"
#include "tx_ctx.h"
#include "calldata.h"
#include "shared_context.h"
#include "eth_ustream.h"

// Required globals
txContext_t txContext;
static chain_config_t g_chainConfig = {.ticker = "ETH", .chain_id = 1, .coin_type = 60};
const chain_config_t *g_chain_config = &g_chainConfig;
const char g_unknown_ticker[] = "???";

// ===========================================================================
// value_get / value_cleanup mock
// ===========================================================================

static int g_vg_call = 0;
static s_parsed_value_collection g_vg[2];

bool __wrap_value_get(const s_value *value, s_parsed_value_collection *collection) {
    (void) value;
    *collection = g_vg[g_vg_call++];
    return true;
}

void __wrap_value_cleanup(const s_value *value, const s_parsed_value_collection *collection) {
    (void) value;
    (void) collection;
}

// ===========================================================================
// handle_value_struct stub — TLV parse handlers reference it but are never
// called by format_param_calldata; only needed for linkage.
// ===========================================================================

bool __wrap_handle_value_struct(const buffer_t *buf, s_value_context *context) {
    (void) buf;
    (void) context;
    return true;
}

// ===========================================================================
// Calldata stubs — only needed for linkage; never called with empty calldata
// ===========================================================================

s_calldata *__wrap_calldata_init(size_t size, const uint8_t *selector) {
    (void) size;
    (void) selector;
    return NULL;
}

bool __wrap_calldata_append(s_calldata *calldata, const uint8_t *data, size_t length) {
    (void) calldata;
    (void) data;
    (void) length;
    return true;
}

void __wrap_calldata_delete(s_calldata *calldata) {
    (void) calldata;
}

// ===========================================================================
// tx_ctx_init mock
// ===========================================================================

bool __wrap_tx_ctx_init(s_calldata *calldata,
                        const uint8_t *from,
                        const uint8_t *to,
                        const uint8_t *amount,
                        const uint64_t *chain_id) {
    (void) calldata;
    (void) from;
    (void) to;
    (void) amount;
    (void) chain_id;
    return (bool) mock();
}

// ===========================================================================
// Test data
// ===========================================================================

// Fake contract address (20 bytes) — single entry to be broadcast
static uint8_t g_contract_addr[ADDRESS_LENGTH] = {
    0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD,
    0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF,
};

// ===========================================================================
// Tests
// ===========================================================================

/**
 * Broadcast: calldata collection has 2 elements (both empty, length=0),
 * contract_addr collection has 1 element — broadcast to both iterations.
 * Expected: format_param_calldata returns true and tx_ctx_init is called twice.
 */
static void test_calldata_broadcast_ok(void **state) {
    (void) state;

    // Primary collection: two empty calldatas (length=0 skips calldata_init)
    g_vg[0].size = 2;
    g_vg[0].value[0] = (s_parsed_value){.ptr = NULL, .size = 0, .offset = 0, .length = 0};
    g_vg[0].value[1] = (s_parsed_value){.ptr = NULL, .size = 0, .offset = 0, .length = 0};

    // Secondary (contract_addr) collection: one address — broadcast
    g_vg[1].size = 1;
    g_vg[1].value[0] = (s_parsed_value){
        .ptr = g_contract_addr,
        .size = ADDRESS_LENGTH,
        .offset = 0,
        .length = ADDRESS_LENGTH,
    };

    g_vg_call = 0;
    memset(&txContext, 0, sizeof(txContext));

    // tx_ctx_init called once per calldata iteration (2 iterations)
    will_return(__wrap_tx_ctx_init, true);
    will_return(__wrap_tx_ctx_init, true);

    s_param_calldata param;
    memset(&param, 0, sizeof(param));
    param.version = 1;

    assert_true(format_param_calldata(&param, "Destination"));

    // batch_nb_tx incremented by calldatas.size (2) since size > 1
    assert_int_equal(txContext.batch_nb_tx, 2);
    assert_int_equal(txContext.current_batch_size, 2);
}

/**
 * Mismatch rejection: calldata collection has 2 elements,
 * contract_addr collection has 3 — neither equals 1 nor matches calldatas.size.
 * check_param must return false; tx_ctx_init must NOT be called.
 */
static void test_calldata_size_mismatch_rejected(void **state) {
    (void) state;

    // Primary collection: 2 calldatas
    g_vg[0].size = 2;

    // Secondary (contract_addr) collection: 3 — mismatched
    g_vg[1].size = 3;

    g_vg_call = 0;
    memset(&txContext, 0, sizeof(txContext));

    s_param_calldata param;
    memset(&param, 0, sizeof(param));
    param.version = 1;

    // format_param_calldata must return false; tx_ctx_init is NOT called
    assert_false(format_param_calldata(&param, "Destination"));
}

// ===========================================================================
// Test runner
// ===========================================================================

// ===========================================================================
// TLV tag-handler tests — drive handle_param_calldata_struct with
// hand-crafted TLV buffers. The wrapped handle_value_struct ignores its
// inner buffer, so VALUE / CALLEE / CHAIN_ID / SELECTOR / AMOUNT /
// SPENDER tags all reduce to a "did the dispatch route here?" check via
// the has_X side-effects.
//
// All tags are < 0x80 so short-form encoding is used.
// ===========================================================================

static void test_handle_calldata_struct_all_tags_ok(void **state) {
    (void) state;
    uint8_t buf_bytes[] = {
        0x00,
        0x01,
        0x01,  // VERSION = 1
        0x01,
        0x00,  // VALUE
        0x02,
        0x00,  // CALLEE
        0x03,
        0x00,  // CHAIN_ID
        0x04,
        0x00,  // SELECTOR
        0x05,
        0x00,  // AMOUNT
        0x06,
        0x00,  // SPENDER
    };
    buffer_t buf = {.ptr = buf_bytes, .size = sizeof(buf_bytes), .offset = 0};

    s_param_calldata param;
    memset(&param, 0, sizeof(param));
    s_param_calldata_context ctx = {.param = &param};
    assert_true(handle_param_calldata_struct(&buf, &ctx));
    assert_int_equal(param.version, 1);
    assert_true(param.has_chain_id);
    assert_true(param.has_selector);
    assert_true(param.has_amount);
    assert_true(param.has_spender);
}

static void test_handle_calldata_struct_version_only_ok(void **state) {
    (void) state;
    // Optional tags are all... optional. has_X flags must remain false.
    uint8_t buf_bytes[] = {
        0x00,
        0x01,
        0x03,  // VERSION = 3
    };
    buffer_t buf = {.ptr = buf_bytes, .size = sizeof(buf_bytes), .offset = 0};

    s_param_calldata param;
    memset(&param, 0, sizeof(param));
    s_param_calldata_context ctx = {.param = &param};
    assert_true(handle_param_calldata_struct(&buf, &ctx));
    assert_int_equal(param.version, 3);
    assert_false(param.has_chain_id);
    assert_false(param.has_selector);
    assert_false(param.has_amount);
    assert_false(param.has_spender);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_calldata_broadcast_ok),
        cmocka_unit_test(test_calldata_size_mismatch_rejected),
        cmocka_unit_test(test_handle_calldata_struct_all_tags_ok),
        cmocka_unit_test(test_handle_calldata_struct_version_only_ok),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
