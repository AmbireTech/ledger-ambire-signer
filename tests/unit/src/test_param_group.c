/**
 * @file test_param_group.c
 * @brief Unit tests for PARAM_GROUP formatting (iteration order, failure propagation)
 *
 * format_field is mocked so these tests exercise only GROUP-level logic:
 * sequential iteration, BUNDLED fallback, empty groups, and sub-field failure.
 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

#include "gtp_field.h"
#include "gtp_param_group.h"

// =============================================================================
// Mock functions
// =============================================================================

bool __wrap_format_field(s_field *field) {
    check_expected(field->name);
    return (bool) mock();
}

// Stubs for gtp_field.c symbols referenced by gtp_param_group.c
// but not exercised in these tests (TLV parsing path, cleanup path).
bool __wrap_handle_field_struct(const buffer_t *buf, s_field_ctx *ctx) {
    (void) buf;
    (void) ctx;
    return true;
}

bool __wrap_verify_field_struct(const s_field_ctx *ctx) {
    (void) ctx;
    return true;
}

void __wrap_cleanup_field(s_field *field) {
    (void) field;
}

void __wrap_cleanup_field_constraints(s_field *field) {
    (void) field;
}

// =============================================================================
// Helpers
// =============================================================================

// Build a minimal s_field with name and param_type (other fields zeroed).
#define MAKE_FIELD(var, field_name, ptype) \
    s_field var;                           \
    memset(&(var), 0, sizeof(var));        \
    (var).version = 1;                     \
    (var).param_type = (ptype);            \
    strncpy((var).name, (field_name), sizeof((var).name) - 1);

// Build a s_group_field_node on the stack linking to next_node (or NULL).
#define MAKE_NODE(var, field_ptr, next_node_ptr)        \
    s_group_field_node var;                             \
    memset(&(var), 0, sizeof(var));                     \
    (var).node.next = (flist_node_t *) (next_node_ptr); \
    (var).field = (field_ptr);

// Build a top-level s_field wrapping a s_param_group.
static s_field make_group_field(e_group_iteration_type iter, s_group_field_node *head) {
    s_field outer;
    memset(&outer, 0, sizeof(outer));
    outer.version = 1;
    outer.param_type = PARAM_TYPE_GROUP;
    outer.param_group.version = 1;
    outer.param_group.iteration_type = iter;
    outer.param_group.fields = head;
    return outer;
}

// =============================================================================
// Test cases
// =============================================================================

static void test_group_empty(void **state) {
    (void) state;
    s_field outer = make_group_field(GROUP_ITER_SEQUENTIAL, NULL);
    // No sub-fields: format_field must never be called.
    assert_true(format_param_group(&outer));
}

static void test_group_sequential_one_subfield(void **state) {
    (void) state;
    MAKE_FIELD(sub, "Amount", PARAM_TYPE_RAW);
    MAKE_NODE(node, &sub, NULL);
    s_field outer = make_group_field(GROUP_ITER_SEQUENTIAL, &node);

    expect_string(__wrap_format_field, field->name, "Amount");
    will_return(__wrap_format_field, true);

    assert_true(format_param_group(&outer));
}

static void test_group_sequential_two_subfields(void **state) {
    (void) state;
    MAKE_FIELD(sub2, "Value", PARAM_TYPE_RAW);
    MAKE_NODE(node2, &sub2, NULL);
    MAKE_FIELD(sub1, "Token ID", PARAM_TYPE_RAW);
    MAKE_NODE(node1, &sub1, &node2);
    s_field outer = make_group_field(GROUP_ITER_SEQUENTIAL, &node1);

    // Both sub-fields called in declaration order.
    expect_string(__wrap_format_field, field->name, "Token ID");
    will_return(__wrap_format_field, true);
    expect_string(__wrap_format_field, field->name, "Value");
    will_return(__wrap_format_field, true);

    assert_true(format_param_group(&outer));
}

/**
 * BUNDLED iteration is not yet implemented; the group falls back to SEQUENTIAL.
 * Verify the output order is identical to SEQUENTIAL.
 */
static void test_group_bundled_falls_back_to_sequential(void **state) {
    (void) state;
    MAKE_FIELD(sub2, "Value", PARAM_TYPE_RAW);
    MAKE_NODE(node2, &sub2, NULL);
    MAKE_FIELD(sub1, "Token ID", PARAM_TYPE_RAW);
    MAKE_NODE(node1, &sub1, &node2);
    s_field outer = make_group_field(GROUP_ITER_BUNDLED, &node1);

    expect_string(__wrap_format_field, field->name, "Token ID");
    will_return(__wrap_format_field, true);
    expect_string(__wrap_format_field, field->name, "Value");
    will_return(__wrap_format_field, true);

    assert_true(format_param_group(&outer));
}

static void test_group_subfield_failure_propagates(void **state) {
    (void) state;
    MAKE_FIELD(sub2, "Value", PARAM_TYPE_RAW);
    MAKE_NODE(node2, &sub2, NULL);
    MAKE_FIELD(sub1, "Token ID", PARAM_TYPE_RAW);
    MAKE_NODE(node1, &sub1, &node2);
    s_field outer = make_group_field(GROUP_ITER_SEQUENTIAL, &node1);

    // First sub-field fails; second must never be called.
    expect_string(__wrap_format_field, field->name, "Token ID");
    will_return(__wrap_format_field, false);

    assert_false(format_param_group(&outer));
}

// =============================================================================
// Test runner
// =============================================================================

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_group_empty),
        cmocka_unit_test(test_group_sequential_one_subfield),
        cmocka_unit_test(test_group_sequential_two_subfields),
        cmocka_unit_test(test_group_bundled_falls_back_to_sequential),
        cmocka_unit_test(test_group_subfield_failure_propagates),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
