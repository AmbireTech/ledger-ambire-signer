/**
 * @file test_field_validation.c
 * @brief Unit tests for field struct validation rules
 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <string.h>
#include <stdint.h>
#include <cmocka.h>

#include "gtp_field.h"
#include "shared_context.h"
#include "buffer.h"
#include "tlv_library.h"

// External dependencies
strings_t strings;
static chain_config_t chainConfig_storage = {.ticker = "ETH", .chain_id = 1, .coin_type = 60};
const chain_config_t *g_chain_config = &chainConfig_storage;

// =============================================================================
// Test Cases
// =============================================================================

/**
 * @brief Test that CONSTRAINT without VISIBLE is rejected
 *
 * According to handle_param_constraint(), a constraint cannot be added
 * if the VISIBLE field has not been set yet.
 */
static void test_constraint_without_visible_rejected(void **state) {
    (void) state;

    s_field field = {0};
    s_field_ctx context = {.field = &field};

    // Simulate a CONSTRAINT tag with some data (e.g., a 4-byte value)
    // TLV format: tag(1 byte) + length(1 byte) + value(4 bytes)
    uint8_t tlv_data[] = {0x05, 0x04, 0x11, 0x22, 0x33, 0x44};  // TAG_CONSTRAINT
    buffer_t buf = {.ptr = tlv_data, .size = sizeof(tlv_data), .offset = 0};

    // Call handle_field_struct with CONSTRAINT but no VISIBLE set
    // This should fail because visibility must be set before constraints
    bool result = handle_field_struct(&buf, &context);

    // Should return false (constraint rejected)
    assert_false(result);

    // Verify no constraint was added
    assert_null(field.constraints);

    // Cleanup
    cleanup_field_constraints(&field);
}

/**
 * @brief Test that CONSTRAINT with VISIBLE=ALWAYS is rejected
 *
 * Constraints are only valid with MUST_BE or IF_NOT_IN visibility.
 */
static void test_constraint_with_always_visibility_rejected(void **state) {
    (void) state;

    s_field field = {0};
    s_field_ctx context = {.field = &field};

    // First, set VISIBLE to ALWAYS
    // TLV format: tag(0x04) + length(1) + value(0x00 = PARAM_VISIBILITY_ALWAYS)
    uint8_t visible_tlv[] = {0x04, 0x01, 0x00};
    buffer_t visible_buf = {.ptr = visible_tlv, .size = sizeof(visible_tlv), .offset = 0};

    bool result = handle_field_struct(&visible_buf, &context);
    assert_true(result);
    assert_int_equal(field.visibility, 0);  // PARAM_VISIBILITY_ALWAYS

    // Now try to add a CONSTRAINT
    uint8_t constraint_tlv[] = {0x05, 0x04, 0x11, 0x22, 0x33, 0x44};  // TAG_CONSTRAINT
    buffer_t constraint_buf = {.ptr = constraint_tlv, .size = sizeof(constraint_tlv), .offset = 0};

    result = handle_field_struct(&constraint_buf, &context);

    // Should return false (constraint not allowed with ALWAYS visibility)
    assert_false(result);

    // Verify no constraint was added
    assert_null(field.constraints);

    // Cleanup
    cleanup_field_constraints(&field);
}

/**
 * @brief Test that CONSTRAINT with VISIBLE=MUST_BE is accepted
 *
 * Constraints are valid with MUST_BE visibility.
 */
static void test_constraint_with_must_be_visibility_accepted(void **state) {
    (void) state;

    s_field field = {0};
    s_field_ctx context = {.field = &field};

    // Send both VISIBLE and CONSTRAINT in one TLV buffer
    // TLV format: VISIBLE + CONSTRAINT concatenated
    uint8_t tlv_data[] = {
        0x04,
        0x01,
        0x01,  // TAG_VISIBLE = PARAM_VISIBILITY_MUST_BE
        0x05,
        0x04,
        0x11,
        0x22,
        0x33,
        0x44  // TAG_CONSTRAINT with 4 bytes
    };
    buffer_t buf = {.ptr = tlv_data, .size = sizeof(tlv_data), .offset = 0};

    bool result = handle_field_struct(&buf, &context);

    // Should return true (both tags accepted)
    assert_true(result);
    assert_int_equal(field.visibility, 1);  // PARAM_VISIBILITY_MUST_BE

    // Verify constraint was added
    uint8_t expected_value[] = {0x11, 0x22, 0x33, 0x44};
    assert_non_null(field.constraints);
    assert_memory_equal(field.constraints->value, expected_value, 4);

    // Cleanup
    cleanup_field_constraints(&field);
}

/**
 * @brief Test that CONSTRAINT with VISIBLE=IF_NOT_IN is accepted
 *
 * Constraints are valid with IF_NOT_IN visibility.
 */
static void test_constraint_with_if_not_in_visibility_accepted(void **state) {
    (void) state;

    s_field field = {0};
    s_field_ctx context = {.field = &field};

    // Send both VISIBLE and CONSTRAINT in one TLV buffer
    uint8_t tlv_data[] = {
        0x04,
        0x01,
        0x02,  // TAG_VISIBLE = PARAM_VISIBILITY_IF_NOT_IN
        0x05,
        0x04,
        0x11,
        0x22,
        0x33,
        0x44  // TAG_CONSTRAINT with 4 bytes
    };
    buffer_t buf = {.ptr = tlv_data, .size = sizeof(tlv_data), .offset = 0};

    bool result = handle_field_struct(&buf, &context);

    // Should return true (both tags accepted)
    assert_true(result);
    assert_int_equal(field.visibility, 2);  // PARAM_VISIBILITY_IF_NOT_IN

    // Verify constraint was added
    uint8_t expected_value[] = {0x11, 0x22, 0x33, 0x44};
    assert_non_null(field.constraints);
    assert_memory_equal(field.constraints->value, expected_value, 4);

    // Cleanup
    cleanup_field_constraints(&field);
}

/**
 * @brief Test multiple constraints can be added
 */
static void test_multiple_constraints_accepted(void **state) {
    (void) state;

    s_field field = {0};
    s_field_ctx context = {.field = &field};

    // Send VISIBLE + 2 CONSTRAINTs in one TLV buffer
    uint8_t tlv_data[] = {
        0x04,
        0x01,
        0x02,  // TAG_VISIBLE = PARAM_VISIBILITY_IF_NOT_IN
        0x05,
        0x04,
        0x11,
        0x22,
        0x33,
        0x44,  // TAG_CONSTRAINT 1
        0x05,
        0x04,
        0x55,
        0x66,
        0x77,
        0x88  // TAG_CONSTRAINT 2
    };
    buffer_t buf = {.ptr = tlv_data, .size = sizeof(tlv_data), .offset = 0};

    assert_true(handle_field_struct(&buf, &context));

    // Verify both constraints were added
    uint8_t constraint1_value[] = {0x11, 0x22, 0x33, 0x44};
    uint8_t constraint2_value[] = {0x55, 0x66, 0x77, 0x88};

    assert_non_null(field.constraints);
    assert_memory_equal(field.constraints->value, constraint1_value, 4);

    s_field_constraint *second = (s_field_constraint *) field.constraints->node.next;
    assert_non_null(second);
    assert_memory_equal(second->value, constraint2_value, 4);

    // Cleanup
    cleanup_field_constraints(&field);
}

// =============================================================================
// Per-tag dispatch tests — pin the type / visibility / param-ordering
// rules that gtp_field.c enforces on attacker-controlled GCS field
// descriptors.
// =============================================================================

// Drive handle_field_struct with a single tag at a time so failures
// are easy to attribute.
static bool run_field_tlv(const uint8_t *bytes, size_t size, s_field_ctx *ctx) {
    buffer_t buf = {.ptr = (uint8_t *) bytes, .size = size, .offset = 0};
    return handle_field_struct(&buf, ctx);
}

// Build the minimum required TLV envelope: VERSION + NAME + PARAM_TYPE
// + PARAM. The PARAM payload is empty — the corresponding stub returns
// true, so the dispatch lands on a no-op.
static const uint8_t g_minimal_required_tlv[] = {
    0x00,
    0x01,
    0x01,  // VERSION = 1
    0x01,
    0x04,
    'A',
    'm',
    'o',
    'u',  // NAME = "Amou"
    0x02,
    0x01,
    0x00,  // PARAM_TYPE = PARAM_TYPE_RAW
    0x03,
    0x00,  // PARAM (empty payload)
};

static void test_verify_field_happy_path_with_defaulted_visibility(void **state) {
    (void) state;
    s_field field = {0};
    s_field_ctx ctx = {.field = &field};
    assert_true(run_field_tlv(g_minimal_required_tlv, sizeof(g_minimal_required_tlv), &ctx));
    assert_true(verify_field_struct(&ctx));
    // VISIBLE not set → must default to ALWAYS.
    assert_int_equal(field.visibility, 0);  // PARAM_VISIBILITY_ALWAYS
    cleanup_field_constraints(&field);
}

static void test_verify_field_missing_version_rejected(void **state) {
    (void) state;
    s_field field = {0};
    s_field_ctx ctx = {.field = &field};
    // Empty TLV: no VERSION received → verify rejects.
    assert_true(run_field_tlv(NULL, 0, &ctx));
    assert_false(verify_field_struct(&ctx));
}

static void test_verify_field_unsupported_version_rejected(void **state) {
    (void) state;
    s_field field = {0};
    s_field_ctx ctx = {.field = &field};
    const uint8_t bytes[] = {0x00, 0x01, 0x07};  // VERSION = 7 (unsupported)
    assert_true(run_field_tlv(bytes, sizeof(bytes), &ctx));
    assert_false(verify_field_struct(&ctx));
}

static void test_verify_field_missing_name_rejected(void **state) {
    (void) state;
    s_field field = {0};
    s_field_ctx ctx = {.field = &field};
    // VERSION + PARAM_TYPE + PARAM but no NAME.
    const uint8_t bytes[] = {0x00, 0x01, 0x01, 0x02, 0x01, 0x00, 0x03, 0x00};
    assert_true(run_field_tlv(bytes, sizeof(bytes), &ctx));
    assert_false(verify_field_struct(&ctx));
}

static void test_handle_param_type_unsupported_rejected(void **state) {
    (void) state;
    s_field field = {0};
    s_field_ctx ctx = {.field = &field};
    // PARAM_TYPE = 0xFF — outside every case branch.
    const uint8_t bytes[] = {0x02, 0x01, 0xFF};
    assert_false(run_field_tlv(bytes, sizeof(bytes), &ctx));
}

static void test_handle_param_visible_out_of_range_rejected(void **state) {
    (void) state;
    s_field field = {0};
    s_field_ctx ctx = {.field = &field};
    // VISIBLE >= PARAM_VISIBILITY_MAX must be rejected — otherwise a
    // host-controlled value could land in a downstream switch default
    // and silently change display behavior.
    const uint8_t bytes[] = {0x04, 0x01, 0xFF};
    assert_false(run_field_tlv(bytes, sizeof(bytes), &ctx));
}

static void test_handle_param_without_param_type_rejected(void **state) {
    (void) state;
    s_field field = {0};
    s_field_ctx ctx = {.field = &field};
    // PARAM tag arrives before PARAM_TYPE → must be rejected so the
    // dispatch can't land on whichever default-zero param_type is sitting
    // in the struct.
    const uint8_t bytes[] = {0x03, 0x00};
    assert_false(run_field_tlv(bytes, sizeof(bytes), &ctx));
}

static void test_constraint_empty_value_rejected(void **state) {
    (void) state;
    s_field field = {0};
    s_field_ctx ctx = {.field = &field};
    const uint8_t bytes[] = {
        0x04,
        0x01,
        0x01,  // VISIBLE = MUST_BE
        0x05,
        0x00,  // CONSTRAINT with empty value
    };
    assert_false(run_field_tlv(bytes, sizeof(bytes), &ctx));
    assert_null(field.constraints);
}

// =============================================================================
// Main Test Runner
// =============================================================================

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_constraint_without_visible_rejected),
        cmocka_unit_test(test_constraint_with_always_visibility_rejected),
        cmocka_unit_test(test_constraint_with_must_be_visibility_accepted),
        cmocka_unit_test(test_constraint_with_if_not_in_visibility_accepted),
        cmocka_unit_test(test_multiple_constraints_accepted),
        cmocka_unit_test(test_verify_field_happy_path_with_defaulted_visibility),
        cmocka_unit_test(test_verify_field_missing_version_rejected),
        cmocka_unit_test(test_verify_field_unsupported_version_rejected),
        cmocka_unit_test(test_verify_field_missing_name_rejected),
        cmocka_unit_test(test_handle_param_type_unsupported_rejected),
        cmocka_unit_test(test_handle_param_visible_out_of_range_rejected),
        cmocka_unit_test(test_handle_param_without_param_type_rejected),
        cmocka_unit_test(test_constraint_empty_value_rejected),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
