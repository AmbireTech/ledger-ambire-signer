/**
 * @file test_field_table.c
 * @brief Unit tests for the GCS field table at
 *        src/features/generic_tx_parser/gtp_field_table.c.
 *
 * The field table is the in-memory buffer of (type, key, value,
 * extra_data) entries the parser hands to the UI layer to render a
 * transaction. Every gtp_param_* formatter ends in a call to
 * add_to_field_table(), so this module sits squarely on the critical
 * path for what the user sees.
 *
 * Behaviors covered:
 *   - field_table_init / cleanup lifecycle (and the dirty-init rejection
 *     that catches a forgotten cleanup),
 *   - add_to_field_table NULL-pointer guards,
 *   - happy-path append: heap-allocated copies of key/value, type
 *     stored verbatim for most entries, end_intent flag fed from
 *     validate_instruction_hash,
 *   - special types: PARAM_TYPE_INTENT and PARAM_TYPE_SEPARATOR both
 *     rewrite the stored type to PARAM_TYPE_RAW after raising the
 *     corresponding flag,
 *   - EIP-712 short-circuit: when appState == APP_STATE_SIGNING_EIP712
 *     the call routes through ui_712_set_* helpers instead of growing
 *     the table,
 *   - set_intent_field rewrites the type based on
 *     txContext.current_batch_size,
 *   - get_from_field_table returns entries in insertion order.
 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

#include "gtp_field_table.h"
#include "gtp_field.h"
#include "shared_context.h"
#include "tx_ctx.h"

// =============================================================================
// Globals the module reads
// =============================================================================

// =============================================================================
// Stubs for collaborators
// =============================================================================

static bool g_validate_hash_ret = false;
bool validate_instruction_hash(void) {
    return g_validate_hash_ret;
}

static int g_ui_712_intent_calls = 0;
static int g_ui_712_title_calls = 0;
static int g_ui_712_value_calls = 0;
static char g_ui_712_last_title[64] = {0};
static char g_ui_712_last_value[64] = {0};

void ui_712_set_intent(void) {
    g_ui_712_intent_calls++;
}

void ui_712_set_title(const char *str, size_t length) {
    g_ui_712_title_calls++;
    size_t copy =
        length < sizeof(g_ui_712_last_title) - 1 ? length : sizeof(g_ui_712_last_title) - 1;
    memcpy(g_ui_712_last_title, str, copy);
    g_ui_712_last_title[copy] = '\0';
}

void ui_712_set_value(const char *str, size_t length) {
    g_ui_712_value_calls++;
    size_t copy =
        length < sizeof(g_ui_712_last_value) - 1 ? length : sizeof(g_ui_712_last_value) - 1;
    memcpy(g_ui_712_last_value, str, copy);
    g_ui_712_last_value[copy] = '\0';
}

// =============================================================================
// Fixture: every test starts with an empty table
// =============================================================================

static int reset(void **state) {
    (void) state;
    field_table_cleanup();
    appState = APP_STATE_IDLE;
    memset(&txContext, 0, sizeof(txContext));
    g_validate_hash_ret = false;
    g_ui_712_intent_calls = 0;
    g_ui_712_title_calls = 0;
    g_ui_712_value_calls = 0;
    g_ui_712_last_title[0] = '\0';
    g_ui_712_last_value[0] = '\0';
    return 0;
}

// =============================================================================
// field_table_init lifecycle
// =============================================================================

static void test_init_on_clean_succeeds(void **state) {
    (void) state;
    assert_true(field_table_init());
    assert_int_equal(field_table_size(), 0);
}

static void test_init_when_dirty_cleans_and_rejects(void **state) {
    (void) state;
    assert_true(add_to_field_table(PARAM_TYPE_RAW, "k", "v", NULL));
    assert_int_equal(field_table_size(), 1);
    // Init on a non-empty table must reject AND clean up (next call to
    // size confirms the table is empty).
    assert_false(field_table_init());
    assert_int_equal(field_table_size(), 0);
}

// =============================================================================
// add_to_field_table — guards
// =============================================================================

static void test_add_null_key_rejected(void **state) {
    (void) state;
    assert_false(add_to_field_table(PARAM_TYPE_RAW, NULL, "v", NULL));
    assert_int_equal(field_table_size(), 0);
}

static void test_add_null_value_rejected(void **state) {
    (void) state;
    assert_false(add_to_field_table(PARAM_TYPE_RAW, "k", NULL, NULL));
    assert_int_equal(field_table_size(), 0);
}

// =============================================================================
// add_to_field_table — happy paths
// =============================================================================

static void test_add_stores_copies_and_type(void **state) {
    (void) state;
    int sentinel = 42;
    assert_true(add_to_field_table(PARAM_TYPE_AMOUNT, "Amount", "1 ETH", &sentinel));
    assert_int_equal(field_table_size(), 1);

    const s_field_table_entry *e = get_from_field_table(0);
    assert_non_null(e);
    assert_int_equal(e->type, PARAM_TYPE_AMOUNT);
    assert_string_equal(e->key, "Amount");
    assert_string_equal(e->value, "1 ETH");
    assert_ptr_equal(e->extra_data, &sentinel);
    assert_false(e->start_intent);
    assert_false(e->is_separator);
    assert_false(e->end_intent);

    // Returned key/value pointers MUST be heap copies (not the caller's
    // string literals) — flipping the byte through the entry's pointer
    // would corrupt the read-only segment if they were the same.
    assert_ptr_not_equal(e->key, (void *) "Amount");
    assert_ptr_not_equal(e->value, (void *) "1 ETH");
}

static void test_add_multiple_preserves_order(void **state) {
    (void) state;
    assert_true(add_to_field_table(PARAM_TYPE_RAW, "k1", "v1", NULL));
    assert_true(add_to_field_table(PARAM_TYPE_RAW, "k2", "v2", NULL));
    assert_true(add_to_field_table(PARAM_TYPE_RAW, "k3", "v3", NULL));
    assert_int_equal(field_table_size(), 3);
    assert_string_equal(get_from_field_table(0)->key, "k1");
    assert_string_equal(get_from_field_table(1)->key, "k2");
    assert_string_equal(get_from_field_table(2)->key, "k3");
}

static void test_add_end_intent_set_from_validator(void **state) {
    (void) state;
    g_validate_hash_ret = true;  // validate_instruction_hash returns true
    assert_true(add_to_field_table(PARAM_TYPE_RAW, "k", "v", NULL));
    const s_field_table_entry *e = get_from_field_table(0);
    assert_true(e->end_intent);

    g_validate_hash_ret = false;
    assert_true(add_to_field_table(PARAM_TYPE_RAW, "k2", "v2", NULL));
    assert_false(get_from_field_table(1)->end_intent);
}

// =============================================================================
// add_to_field_table — special types
// =============================================================================

static void test_add_intent_raises_flag_and_rewrites_type(void **state) {
    (void) state;
    assert_true(add_to_field_table(PARAM_TYPE_INTENT, "TxKind", "Approve", NULL));
    const s_field_table_entry *e = get_from_field_table(0);
    assert_true(e->start_intent);
    // The stored type must be RAW even though the caller passed INTENT.
    assert_int_equal(e->type, PARAM_TYPE_RAW);
}

static void test_add_separator_raises_flag_and_rewrites_type(void **state) {
    (void) state;
    assert_true(add_to_field_table(PARAM_TYPE_SEPARATOR, "section", "", NULL));
    const s_field_table_entry *e = get_from_field_table(0);
    assert_true(e->is_separator);
    assert_int_equal(e->type, PARAM_TYPE_RAW);
}

// =============================================================================
// add_to_field_table — EIP-712 short-circuit
// =============================================================================

static void test_add_in_eip712_routes_to_ui_helpers(void **state) {
    (void) state;
    appState = APP_STATE_SIGNING_EIP712;
    assert_true(add_to_field_table(PARAM_TYPE_RAW, "From", "0xabc", NULL));
    // Table must NOT grow.
    assert_int_equal(field_table_size(), 0);
    // ui_712 helpers got the strings.
    assert_int_equal(g_ui_712_title_calls, 1);
    assert_int_equal(g_ui_712_value_calls, 1);
    assert_string_equal(g_ui_712_last_title, "From");
    assert_string_equal(g_ui_712_last_value, "0xabc");
    // ui_712_set_intent only fires for INTENT + batch > 1
    assert_int_equal(g_ui_712_intent_calls, 0);
}

static void test_add_intent_in_eip712_with_batch_calls_set_intent(void **state) {
    (void) state;
    appState = APP_STATE_SIGNING_EIP712;
    txContext.current_batch_size = 2;
    assert_true(add_to_field_table(PARAM_TYPE_INTENT, "TxKind", "Approve", NULL));
    assert_int_equal(g_ui_712_intent_calls, 1);
}

static void test_add_intent_in_eip712_single_batch_skips_set_intent(void **state) {
    (void) state;
    appState = APP_STATE_SIGNING_EIP712;
    txContext.current_batch_size = 1;
    assert_true(add_to_field_table(PARAM_TYPE_INTENT, "TxKind", "Approve", NULL));
    assert_int_equal(g_ui_712_intent_calls, 0);
}

// =============================================================================
// set_intent_field — picks INTENT vs RAW based on batch size
// =============================================================================

static void test_set_intent_field_single_batch_uses_raw_type(void **state) {
    (void) state;
    txContext.current_batch_size = 1;
    assert_true(set_intent_field("approve()"));
    const s_field_table_entry *e = get_from_field_table(0);
    assert_string_equal(e->key, "Transaction type");
    assert_string_equal(e->value, "approve()");
    // PARAM_TYPE_RAW means start_intent stays false (the RAW branch in
    // add_to_field_table does not raise it).
    assert_false(e->start_intent);
    assert_int_equal(e->type, PARAM_TYPE_RAW);
}

static void test_set_intent_field_multi_batch_marks_intent(void **state) {
    (void) state;
    txContext.current_batch_size = 3;
    assert_true(set_intent_field("approve()"));
    const s_field_table_entry *e = get_from_field_table(0);
    assert_true(e->start_intent);
    assert_int_equal(e->type, PARAM_TYPE_RAW);  // INTENT gets remapped to RAW
}

// =============================================================================
// Cleanup / get_from_field_table
// =============================================================================

static void test_cleanup_empties_table(void **state) {
    (void) state;
    add_to_field_table(PARAM_TYPE_RAW, "k", "v", NULL);
    add_to_field_table(PARAM_TYPE_RAW, "k2", "v2", NULL);
    assert_int_equal(field_table_size(), 2);
    field_table_cleanup();
    assert_int_equal(field_table_size(), 0);
}

// =============================================================================
// Runner
// =============================================================================

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup(test_init_on_clean_succeeds, reset),
        cmocka_unit_test_setup(test_init_when_dirty_cleans_and_rejects, reset),
        cmocka_unit_test_setup(test_add_null_key_rejected, reset),
        cmocka_unit_test_setup(test_add_null_value_rejected, reset),
        cmocka_unit_test_setup(test_add_stores_copies_and_type, reset),
        cmocka_unit_test_setup(test_add_multiple_preserves_order, reset),
        cmocka_unit_test_setup(test_add_end_intent_set_from_validator, reset),
        cmocka_unit_test_setup(test_add_intent_raises_flag_and_rewrites_type, reset),
        cmocka_unit_test_setup(test_add_separator_raises_flag_and_rewrites_type, reset),
        cmocka_unit_test_setup(test_add_in_eip712_routes_to_ui_helpers, reset),
        cmocka_unit_test_setup(test_add_intent_in_eip712_with_batch_calls_set_intent, reset),
        cmocka_unit_test_setup(test_add_intent_in_eip712_single_batch_skips_set_intent, reset),
        cmocka_unit_test_setup(test_set_intent_field_single_batch_uses_raw_type, reset),
        cmocka_unit_test_setup(test_set_intent_field_multi_batch_marks_intent, reset),
        cmocka_unit_test_setup(test_cleanup_empties_table, reset),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
