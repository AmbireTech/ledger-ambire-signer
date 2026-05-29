/**
 * @file test_tx_ctx.c
 * @brief Unit tests for the GCS transaction-context module at
 *        src/features/generic_tx_parser/tx_ctx.c.
 *
 * tx_ctx tracks the per-transaction state that survives across the
 * APDU stream: a doubly-linked list of s_tx_ctx nodes (one per outer
 * tx + optional inner sub-calls for proxy resolution), the
 * "current" pointer the parsers read through, and the parked
 * calldata buffer that hops from PROVIDE_CALLDATA into the node
 * created by tx_ctx_init().
 *
 * Tests focus on:
 *   - getter NULL-guards before any tx_ctx_init,
 *   - tx_ctx_init lifecycle: first call populates from/to/amount/
 *     chain_id, second call inherits from / chain_id from the
 *     previous tail, calldata ownership transfers (g_parked_calldata
 *     is cleared by the call),
 *   - tx_ctx_pop unlinks the current node and rewinds current,
 *   - find_matching_tx_ctx with selector + contract_addr + chain_id
 *     match,
 *   - validate_instruction_hash: real (mocked) hash compared against
 *     the stored fields_hash,
 *   - gcs_cleanup tears the whole state down.
 *
 * Out of scope: process_empty_txs_before / process_empty_txs_after
 * pull in too many display-layer dependencies (ticker lookup,
 * amountToString, trusted-name resolution, getEthDisplayableAddress)
 * for the scope of this slice.
 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

#include "tx_ctx.h"
#include "gtp_field_table.h"
#include "trusted_name.h"
#include "shared_context.h"

// =============================================================================
// Globals
// =============================================================================

strings_t strings;
static chain_config_t g_chainConfig = {.ticker = "ETH", .chain_id = 1, .coin_type = 60};
const chain_config_t *g_chain_config = &g_chainConfig;
const char g_unknown_ticker[] = "???";
txContext_t txContext;
tmpContent_t tmpContent;
uint8_t appState = APP_STATE_IDLE;

// =============================================================================
// Wraps / stubs for collaborators
// =============================================================================

// get_public_key writes ADDRESS_LENGTH bytes to its output buffer.
// We use a static "self" address for tests.
static const uint8_t g_self_addr[ADDRESS_LENGTH] = {
    0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10,
    0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10,
};
// cx_sha3_init_no_throw is a SDK syscall — we never use the resulting
// hash context except to feed finalize_hash (also wrapped), so a plain
// CX_OK stub is enough.
uint32_t cx_sha3_init_no_throw(cx_sha3_t *hash, size_t size) {
    (void) hash;
    (void) size;
    return 0;  // CX_OK
}

// process_empty_tx is a static helper inside tx_ctx.c that drags display-
// layer symbols into the link even though our tests don't exercise it.
// Provide minimal stubs so the link resolves; these are NEVER called by
// the test cases below.
bool set_intent_field(const char *value) {
    (void) value;
    return true;
}
const char *get_displayable_ticker(const uint64_t *chain_id,
                                   const chain_config_t *cfg,
                                   bool mainnet) {
    (void) chain_id;
    (void) cfg;
    (void) mainnet;
    return "ETH";
}
bool amountToString(const uint8_t *amount,
                    uint8_t amount_len,
                    uint8_t decimals,
                    const char *ticker,
                    char *out_buffer,
                    size_t out_buffer_size) {
    (void) amount;
    (void) amount_len;
    (void) decimals;
    (void) ticker;
    (void) out_buffer;
    (void) out_buffer_size;
    return true;
}
bool add_to_field_table(e_param_type type, const char *key, const char *value, const void *extra) {
    (void) type;
    (void) key;
    (void) value;
    (void) extra;
    return true;
}
uint64_t get_tx_chain_id(void) {
    return 1;
}
const s_trusted_name *get_trusted_name(uint8_t type_count,
                                       const e_name_type *types,
                                       uint8_t source_count,
                                       const e_name_source *sources,
                                       const uint64_t *chain_id,
                                       const uint8_t *addr) {
    (void) type_count;
    (void) types;
    (void) source_count;
    (void) sources;
    (void) chain_id;
    (void) addr;
    return NULL;
}
bool getEthDisplayableAddress(const uint8_t *addr, char *out, size_t out_size, uint64_t chain_id) {
    (void) addr;
    (void) out;
    (void) out_size;
    (void) chain_id;
    return true;
}

// EIP-712 calldata-info helpers — only reached when appState ==
// APP_STATE_SIGNING_EIP712, which our tests never set.
void *get_current_calldata_info(void) {
    return NULL;
}
bool calldata_info_all_received(const void *info) {
    (void) info;
    return false;
}

bool __wrap_get_public_key(uint8_t *buf, uint8_t size) {
    if (size != ADDRESS_LENGTH) return false;
    memcpy(buf, g_self_addr, ADDRESS_LENGTH);
    return true;
}

// finalize_hash: tests set the bytes to inject via g_finalize_hash_out.
static uint8_t g_finalize_hash_out[INT256_LENGTH];
static bool g_finalize_hash_ret = true;
bool __wrap_finalize_hash(cx_hash_t *hash_ctx, uint8_t *out, size_t out_len) {
    (void) hash_ctx;
    memcpy(out,
           g_finalize_hash_out,
           out_len < sizeof(g_finalize_hash_out) ? out_len : sizeof(g_finalize_hash_out));
    return g_finalize_hash_ret;
}

// ui / cleanup stubs
void __wrap_ui_gcs_cleanup(void) {
}
void __wrap_delete_tx_info(s_tx_info *node) {
    free(node);
}
bool __wrap_field_table_init(void) {
    return true;
}
void __wrap_field_table_cleanup(void) {
}

// find_matching_tx_ctx uses get_implem_contract for proxy resolution.
static const uint8_t *g_implem_contract_ret = NULL;
const uint8_t *__wrap_get_implem_contract(const uint64_t *chain_id,
                                          const uint8_t *to,
                                          const uint8_t *selector) {
    (void) chain_id;
    (void) to;
    (void) selector;
    return g_implem_contract_ret;
}

// =============================================================================
// Fixture
// =============================================================================

static int reset(void **state) {
    (void) state;
    gcs_cleanup();
    appState = APP_STATE_IDLE;
    memset(g_finalize_hash_out, 0, sizeof(g_finalize_hash_out));
    g_finalize_hash_ret = true;
    g_implem_contract_ret = NULL;
    return 0;
}

// Helper: set up a node and force g_tx_ctx_current to point at it by
// going through find_matching_tx_ctx. Returns the matched ctx through
// the getter side-effects.
static const uint8_t g_match_selector[CALLDATA_SELECTOR_SIZE] = {0xDE, 0xAD, 0xBE, 0xEF};

static s_calldata *make_complete_calldata(const uint8_t *selector) {
    s_calldata *cd = calldata_init(CALLDATA_CHUNK_SIZE, selector);
    uint8_t buf[CALLDATA_CHUNK_SIZE] = {0};
    calldata_append(cd, buf, CALLDATA_CHUNK_SIZE);
    return cd;
}

// Test data
static const uint8_t g_addr_a[ADDRESS_LENGTH] = {
    0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
    0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
};
static const uint8_t g_addr_b[ADDRESS_LENGTH] = {
    0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB,
    0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB,
};
static const uint8_t g_amount_1eth[INT256_LENGTH] = {
    0, 0, 0, 0, 0, 0, 0, 0, 0,    0,    0,    0,    0,    0,    0,    0,
    0, 0, 0, 0, 0, 0, 0, 0, 0x0D, 0xE0, 0xB6, 0xB3, 0xA7, 0x64, 0x00, 0x00,
};

// =============================================================================
// Getters — NULL-guard behavior on an empty list
// =============================================================================

static void test_getters_on_empty_list_return_null_or_zero(void **state) {
    (void) state;
    assert_false(tx_ctx_is_root());
    assert_int_equal(get_tx_ctx_count(), 0);
    assert_null(get_current_tx_info());
    assert_null(get_root_tx_info());
    assert_null(get_current_calldata());
    assert_null(get_root_calldata());
    assert_null(get_current_tx_from());
    assert_null(get_current_tx_to());
    assert_null(get_current_tx_amount());
    assert_int_equal(get_current_tx_chain_id(), 0);
}

// =============================================================================
// tx_ctx_init
// =============================================================================
// Note: tx_ctx_init pushes a new node but does NOT set g_tx_ctx_current.
// The current pointer is only set by find_matching_tx_ctx (or tx_ctx_pop
// rewinding to a previous current). So immediately after tx_ctx_init the
// getters still report empty even though the list has nodes.

static void test_init_adds_to_list_but_current_stays_null(void **state) {
    (void) state;
    uint64_t chain = 137;
    assert_true(tx_ctx_init(NULL, g_addr_a, g_addr_b, g_amount_1eth, &chain));
    assert_int_equal(get_tx_ctx_count(), 1);
    // Current is not set yet — getters still NULL.
    assert_false(tx_ctx_is_root());
    assert_null(get_current_tx_from());
    assert_null(get_current_tx_to());
    assert_null(get_current_tx_amount());
    assert_int_equal(get_current_tx_chain_id(), 0);
}

static void test_init_then_find_matching_exposes_fields(void **state) {
    (void) state;
    uint64_t chain = 137;
    s_calldata *cd = make_complete_calldata(g_match_selector);
    assert_true(tx_ctx_init(cd, g_addr_a, g_addr_b, g_amount_1eth, &chain));

    // Use find_matching_tx_ctx to set current onto the new node.
    assert_true(find_matching_tx_ctx(g_addr_b, g_match_selector, &chain));
    assert_true(tx_ctx_is_root());
    assert_memory_equal(get_current_tx_from(), g_addr_a, ADDRESS_LENGTH);
    assert_memory_equal(get_current_tx_to(), g_addr_b, ADDRESS_LENGTH);
    assert_memory_equal(get_current_tx_amount(), g_amount_1eth, INT256_LENGTH);
    assert_int_equal(get_current_tx_chain_id(), 137);
}

static void test_init_first_call_with_null_from_uses_self(void **state) {
    (void) state;
    // get_public_key (wrapped) populates from when the caller passes NULL.
    uint64_t chain = 1;
    s_calldata *cd = make_complete_calldata(g_match_selector);
    assert_true(tx_ctx_init(cd, NULL, g_addr_b, NULL, &chain));
    assert_true(find_matching_tx_ctx(g_addr_b, g_match_selector, &chain));
    assert_memory_equal(get_current_tx_from(), g_self_addr, ADDRESS_LENGTH);
}

static void test_init_second_call_inherits_from_and_chain(void **state) {
    (void) state;
    // First push sets from=addr_a, chain=56.
    uint64_t chain1 = 56;
    s_calldata *cd1 = make_complete_calldata(g_match_selector);
    assert_true(tx_ctx_init(cd1, g_addr_a, g_addr_a, NULL, &chain1));

    // Second push omits from / chain_id → must inherit from tail.
    // To then find_matching the second node we need a *different* selector
    // OR a different `to` since the matcher walks from head and returns
    // the first match.
    static const uint8_t selector2[CALLDATA_SELECTOR_SIZE] = {0xCA, 0xFE, 0xBA, 0xBE};
    s_calldata *cd2 = make_complete_calldata(selector2);
    assert_true(tx_ctx_init(cd2, NULL, g_addr_b, NULL, NULL));
    assert_int_equal(get_tx_ctx_count(), 2);
    // The second node's chain_id was inherited; use it for the match.
    uint64_t chain_lookup = 56;
    assert_true(find_matching_tx_ctx(g_addr_b, selector2, &chain_lookup));
    assert_memory_equal(get_current_tx_from(), g_addr_a, ADDRESS_LENGTH);
    assert_int_equal(get_current_tx_chain_id(), 56);
    // The matched node is the second one — not the root.
    assert_false(tx_ctx_is_root());
}

static void test_init_clears_parked_calldata_pointer(void **state) {
    (void) state;
    // Simulate the host having parked a calldata buffer.
    s_calldata *cd = make_complete_calldata(g_match_selector);
    g_parked_calldata = cd;
    uint64_t chain = 1;
    assert_true(tx_ctx_init(cd, g_addr_a, g_addr_b, NULL, &chain));
    // tx_ctx_init takes ownership and clears the global so the host
    // cannot double-free.
    assert_null(g_parked_calldata);
}

// =============================================================================
// tx_ctx_pop
// =============================================================================

static void test_pop_unlinks_current_node(void **state) {
    (void) state;
    uint64_t chain1 = 1;
    s_calldata *cd1 = make_complete_calldata(g_match_selector);
    assert_true(tx_ctx_init(cd1, g_addr_a, g_addr_a, NULL, &chain1));

    static const uint8_t selector2[CALLDATA_SELECTOR_SIZE] = {0xCA, 0xFE, 0xBA, 0xBE};
    s_calldata *cd2 = make_complete_calldata(selector2);
    assert_true(tx_ctx_init(cd2, NULL, g_addr_b, NULL, NULL));
    assert_int_equal(get_tx_ctx_count(), 2);

    // Match the second node to set current = tail.
    uint64_t chain_lookup = 1;
    assert_true(find_matching_tx_ctx(g_addr_b, selector2, &chain_lookup));
    assert_false(tx_ctx_is_root());

    // Pop rewinds current to the previous node (the root).
    tx_ctx_pop();
    assert_int_equal(get_tx_ctx_count(), 1);
    assert_true(tx_ctx_is_root());
    assert_memory_equal(get_current_tx_from(), g_addr_a, ADDRESS_LENGTH);
}

// =============================================================================
// find_matching_tx_ctx
// =============================================================================

static void test_find_matching_tx_ctx_happy(void **state) {
    (void) state;
    // Two contexts at different addresses; only the second matches the
    // search.
    uint64_t chain = 1;
    static const uint8_t selector[CALLDATA_SELECTOR_SIZE] = {0xDE, 0xAD, 0xBE, 0xEF};
    s_calldata *cd_a = calldata_init(CALLDATA_CHUNK_SIZE, selector);
    s_calldata *cd_b = calldata_init(CALLDATA_CHUNK_SIZE, selector);
    // Mark both calldatas complete so calldata->selector is readable.
    uint8_t buf[CALLDATA_CHUNK_SIZE] = {0};
    calldata_append(cd_a, buf, CALLDATA_CHUNK_SIZE);
    calldata_append(cd_b, buf, CALLDATA_CHUNK_SIZE);

    assert_true(tx_ctx_init(cd_a, g_addr_a, g_addr_a, NULL, &chain));
    assert_true(tx_ctx_init(cd_b, NULL, g_addr_b, NULL, &chain));
    assert_int_equal(get_tx_ctx_count(), 2);

    assert_true(find_matching_tx_ctx(g_addr_b, selector, &chain));
    // current must now point at the second node — to=g_addr_b.
    assert_memory_equal(get_current_tx_to(), g_addr_b, ADDRESS_LENGTH);
}

static void test_find_matching_tx_ctx_no_match_keeps_current(void **state) {
    (void) state;
    uint64_t chain = 1;
    static const uint8_t selector[CALLDATA_SELECTOR_SIZE] = {0xDE, 0xAD, 0xBE, 0xEF};
    s_calldata *cd = calldata_init(CALLDATA_CHUNK_SIZE, selector);
    uint8_t buf[CALLDATA_CHUNK_SIZE] = {0};
    calldata_append(cd, buf, CALLDATA_CHUNK_SIZE);
    assert_true(tx_ctx_init(cd, g_addr_a, g_addr_a, NULL, &chain));

    // Search for an unrelated address.
    assert_false(find_matching_tx_ctx(g_addr_b, selector, &chain));
}

// =============================================================================
// validate_instruction_hash
// =============================================================================

static void test_validate_instruction_hash_matches(void **state) {
    (void) state;
    uint64_t chain = 1;
    s_calldata *cd = make_complete_calldata(g_match_selector);
    assert_true(tx_ctx_init(cd, g_addr_a, g_addr_b, NULL, &chain));
    assert_true(find_matching_tx_ctx(g_addr_b, g_match_selector, &chain));

    s_tx_info *heap_info = malloc(sizeof(s_tx_info));
    memset(heap_info, 0, sizeof(*heap_info));
    heap_info->fields_hash[0] = 0x11;
    heap_info->fields_hash[31] = 0xFF;

    // set_tx_info_into_tx_ctx at root with appState=IDLE skips both the
    // intent-field write and the auto-pop, so it only attaches the info.
    appState = APP_STATE_IDLE;
    assert_true(set_tx_info_into_tx_ctx(heap_info));

    // Now make finalize_hash return the exact fields_hash so the
    // validator returns true.
    memcpy(g_finalize_hash_out, heap_info->fields_hash, sizeof(heap_info->fields_hash));
    assert_true(validate_instruction_hash());
}

static void test_validate_instruction_hash_mismatch(void **state) {
    (void) state;
    uint64_t chain = 1;
    s_calldata *cd = make_complete_calldata(g_match_selector);
    assert_true(tx_ctx_init(cd, g_addr_a, g_addr_b, NULL, &chain));
    assert_true(find_matching_tx_ctx(g_addr_b, g_match_selector, &chain));

    s_tx_info *heap_info = malloc(sizeof(s_tx_info));
    memset(heap_info, 0, sizeof(*heap_info));
    heap_info->fields_hash[0] = 0xFE;
    appState = APP_STATE_IDLE;
    assert_true(set_tx_info_into_tx_ctx(heap_info));

    memset(g_finalize_hash_out, 0xCC, sizeof(g_finalize_hash_out));
    assert_false(validate_instruction_hash());
}

static void test_validate_instruction_hash_no_current_returns_false(void **state) {
    (void) state;
    assert_false(validate_instruction_hash());
}

// =============================================================================
// gcs_cleanup
// =============================================================================

static void test_gcs_cleanup_empties_list(void **state) {
    (void) state;
    uint64_t chain = 1;
    assert_true(tx_ctx_init(NULL, g_addr_a, g_addr_b, NULL, &chain));
    assert_true(tx_ctx_init(NULL, NULL, g_addr_b, NULL, NULL));
    assert_int_equal(get_tx_ctx_count(), 2);
    gcs_cleanup();
    assert_int_equal(get_tx_ctx_count(), 0);
    assert_null(g_parked_calldata);
}

static void test_gcs_cleanup_frees_parked_calldata(void **state) {
    (void) state;
    g_parked_calldata = calldata_init(0, NULL);
    gcs_cleanup();
    assert_null(g_parked_calldata);
}

// =============================================================================
// Runner
// =============================================================================

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup(test_getters_on_empty_list_return_null_or_zero, reset),
        cmocka_unit_test_setup(test_init_adds_to_list_but_current_stays_null, reset),
        cmocka_unit_test_setup(test_init_then_find_matching_exposes_fields, reset),
        cmocka_unit_test_setup(test_init_first_call_with_null_from_uses_self, reset),
        cmocka_unit_test_setup(test_init_second_call_inherits_from_and_chain, reset),
        cmocka_unit_test_setup(test_init_clears_parked_calldata_pointer, reset),
        cmocka_unit_test_setup(test_pop_unlinks_current_node, reset),
        cmocka_unit_test_setup(test_find_matching_tx_ctx_happy, reset),
        cmocka_unit_test_setup(test_find_matching_tx_ctx_no_match_keeps_current, reset),
        cmocka_unit_test_setup(test_validate_instruction_hash_matches, reset),
        cmocka_unit_test_setup(test_validate_instruction_hash_mismatch, reset),
        cmocka_unit_test_setup(test_validate_instruction_hash_no_current_returns_false, reset),
        cmocka_unit_test_setup(test_gcs_cleanup_empties_list, reset),
        cmocka_unit_test_setup(test_gcs_cleanup_frees_parked_calldata, reset),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
