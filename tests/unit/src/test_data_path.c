/**
 * @file test_data_path.c
 * @brief Unit tests for the calldata-path engine at
 *        src/features/generic_tx_parser/gtp_data_path.c.
 *
 * The data path describes how to walk ABI-encoded calldata to reach a
 * field. It is built from five element types — TUPLE, ARRAY, REF,
 * LEAF, SLICE — and is consumed in two phases:
 *   - handle_data_path_struct(): TLV-parses the path description into
 *     an s_data_path of (type, args) elements, capped at
 *     PATH_MAX_SIZE,
 *   - data_path_get(): walks the path against the live calldata and
 *     produces a parsed-value collection that downstream GCS
 *     formatters render.
 *
 * Tests cover:
 *   - TLV happy paths and the size limit at the common handler,
 *   - REF/LEAF payload guards (REF must be empty; LEAF must carry a
 *     valid e_path_leaf_type),
 *   - data_path_get on simple LEAF(STATIC) and SLICE shapes against a
 *     stubbed calldata,
 *   - path_slice boundary check (start >= end rejected),
 *   - data_path_cleanup frees the per-element ptr.
 *
 * The path_array runtime (with iteration count tracking) and path_ref
 * (with offset dereferencing) are deeper concerns and will get their
 * own coverage if needed — exercising them properly requires a
 * multi-chunk calldata fixture beyond this slice.
 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>

#include "gtp_data_path.h"
#include "gtp_path_array.h"
#include "gtp_path_slice.h"
#include "gtp_parsed_value.h"
#include "calldata.h"

// =============================================================================
// is_zeroes_buffer stub
// =============================================================================
// The path engine uses it to validate that the high bytes of a chunk are
// zero (offsets/lengths fit in a u16, the remaining 30 bytes must be 0).
// Provide a real implementation here so the tests exercise the same logic
// as the firmware does at runtime.

bool is_zeroes_buffer(const void *buf, size_t n) {
    const uint8_t *p = (const uint8_t *) buf;
    for (size_t i = 0; i < n; ++i) {
        if (p[i] != 0) return false;
    }
    return true;
}

// =============================================================================
// Wrapped collaborators — calldata_get_chunk / get_current_calldata
// =============================================================================

static s_calldata g_fake_calldata;
s_calldata *__wrap_get_current_calldata(void) {
    return &g_fake_calldata;
}

// Test fixture: an array of CHUNK_SIZE chunks indexed by idx. Tests set
// up the chunks they need before running.
#define MAX_FIXTURE_CHUNKS 8
static uint8_t g_chunks[MAX_FIXTURE_CHUNKS][CALLDATA_CHUNK_SIZE];
static bool g_chunk_present[MAX_FIXTURE_CHUNKS];

const uint8_t *__wrap_calldata_get_chunk(s_calldata *calldata, uint32_t idx) {
    (void) calldata;
    if (idx >= MAX_FIXTURE_CHUNKS || !g_chunk_present[idx]) {
        return NULL;
    }
    return g_chunks[idx];
}

// =============================================================================
// Fixtures
// =============================================================================

static int reset(void **state) {
    (void) state;
    memset(g_chunks, 0, sizeof(g_chunks));
    memset(g_chunk_present, 0, sizeof(g_chunk_present));
    return 0;
}

static void set_chunk(uint32_t idx, const uint8_t *bytes, size_t len) {
    assert_true(idx < MAX_FIXTURE_CHUNKS);
    assert_true(len <= CALLDATA_CHUNK_SIZE);
    memset(g_chunks[idx], 0, CALLDATA_CHUNK_SIZE);
    memcpy(g_chunks[idx] + (CALLDATA_CHUNK_SIZE - len), bytes, len);
    g_chunk_present[idx] = true;
}

static bool run_tlv(const uint8_t *bytes, size_t size, s_data_path *path) {
    buffer_t buf = {.ptr = (uint8_t *) bytes, .size = size, .offset = 0};
    s_data_path_context ctx = {.data_path = path};
    return handle_data_path_struct(&buf, &ctx);
}

// =============================================================================
// TLV layer
// =============================================================================

static void test_tlv_happy_path_all_five_element_types(void **state) {
    (void) state;
    const uint8_t bytes[] = {
        0x00,
        0x01,
        0x01,  // VERSION = 1
        0x01,
        0x02,
        0x00,
        0x20,  // TUPLE (value = 32)
        // ARRAY (delegated to path_array parser — TLV-empty so has_start/end stay false)
        0x02,
        0x00,
        0x03,
        0x00,  // REF — must be empty
        0x04,
        0x01,
        0x03,  // LEAF type = LEAF_TYPE_STATIC
        0x05,
        0x00,  // SLICE (delegated — empty)
    };
    s_data_path path = {0};
    assert_true(run_tlv(bytes, sizeof(bytes), &path));
    assert_int_equal(path.version, 1);
    assert_int_equal(path.size, 5);
    assert_int_equal(path.elements[0].type, ELEMENT_TYPE_TUPLE);
    assert_int_equal(path.elements[0].tuple.value, 32);
    assert_int_equal(path.elements[1].type, ELEMENT_TYPE_ARRAY);
    assert_int_equal(path.elements[2].type, ELEMENT_TYPE_REF);
    assert_int_equal(path.elements[3].type, ELEMENT_TYPE_LEAF);
    assert_int_equal(path.elements[3].leaf.type, LEAF_TYPE_STATIC);
    assert_int_equal(path.elements[4].type, ELEMENT_TYPE_SLICE);
}

static void test_tlv_ref_with_payload_rejected(void **state) {
    (void) state;
    // REF must have an empty payload; any byte is a hard reject.
    const uint8_t bytes[] = {0x03, 0x01, 0x00};
    s_data_path path = {0};
    assert_false(run_tlv(bytes, sizeof(bytes), &path));
}

static void test_tlv_leaf_invalid_type_rejected(void **state) {
    (void) state;
    // 0x99 is not one of LEAF_TYPE_{ARRAY,TUPLE,STATIC,DYNAMIC}
    const uint8_t bytes[] = {0x04, 0x01, 0x99};
    s_data_path path = {0};
    assert_false(run_tlv(bytes, sizeof(bytes), &path));
}

static void test_tlv_leaf_each_valid_type_accepted(void **state) {
    (void) state;
    const uint8_t types[] = {LEAF_TYPE_ARRAY, LEAF_TYPE_TUPLE, LEAF_TYPE_STATIC, LEAF_TYPE_DYNAMIC};
    for (size_t i = 0; i < sizeof(types); ++i) {
        s_data_path path = {0};
        const uint8_t bytes[] = {0x04, 0x01, types[i]};
        assert_true(run_tlv(bytes, sizeof(bytes), &path));
        assert_int_equal(path.size, 1);
        assert_int_equal(path.elements[0].leaf.type, types[i]);
    }
}

static void test_tlv_path_max_size_enforced(void **state) {
    (void) state;
    // Build PATH_MAX_SIZE + 1 = 17 TUPLE entries — the common handler
    // must reject the last one.
    uint8_t bytes[64];
    size_t off = 0;
    for (int i = 0; i <= PATH_MAX_SIZE; ++i) {
        bytes[off++] = 0x01;
        bytes[off++] = 0x02;
        bytes[off++] = 0x00;
        bytes[off++] = 0x01;
    }
    s_data_path path = {0};
    assert_false(run_tlv(bytes, off, &path));
}

// =============================================================================
// data_path_get — simple shapes
// =============================================================================

static void test_data_path_get_empty_path_returns_true(void **state) {
    (void) state;
    s_data_path path = {0};  // size == 0
    s_parsed_value_collection collec = {0};
    assert_true(data_path_get(&path, &collec));
    assert_int_equal(collec.size, 0);
}

static void test_data_path_get_static_leaf_copies_chunk(void **state) {
    (void) state;
    // The path is a single LEAF(STATIC). data_path_get must allocate
    // CALLDATA_CHUNK_SIZE bytes and copy chunk[0] into them.
    static const uint8_t chunk[] = {0xCA, 0xFE, 0xBA, 0xBE};
    set_chunk(0, chunk, sizeof(chunk));

    s_data_path path = {0};
    path.size = 1;
    path.elements[0].type = ELEMENT_TYPE_LEAF;
    path.elements[0].leaf.type = LEAF_TYPE_STATIC;

    s_parsed_value_collection collec = {0};
    assert_true(data_path_get(&path, &collec));
    assert_int_equal(collec.size, 1);
    assert_int_equal(collec.value[0].length, CALLDATA_CHUNK_SIZE);
    // Right-aligned: last 4 bytes match `chunk`, the rest is zero.
    static const uint8_t expected[CALLDATA_CHUNK_SIZE] = {
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,    0,    0,    0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xCA, 0xFE, 0xBA, 0xBE,
    };
    assert_memory_equal(collec.value[0].ptr, expected, CALLDATA_CHUNK_SIZE);
    data_path_cleanup(&collec);
}

static void test_data_path_get_slice_trims_collection(void **state) {
    (void) state;
    // LEAF(STATIC) → 32-byte value. Then SLICE [4, 12) → length=8, ptr
    // advanced by 4, offset=4.
    static const uint8_t bytes[CALLDATA_CHUNK_SIZE] = {
        0, 0, 0, 0, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22, 0, 0, 0, 0,
        0, 0, 0, 0, 0,    0,    0,    0,    0,    0,    0,    0,    0, 0, 0, 0,
    };
    memcpy(g_chunks[0], bytes, CALLDATA_CHUNK_SIZE);
    g_chunk_present[0] = true;

    s_data_path path = {0};
    path.size = 2;
    path.elements[0].type = ELEMENT_TYPE_LEAF;
    path.elements[0].leaf.type = LEAF_TYPE_STATIC;
    path.elements[1].type = ELEMENT_TYPE_SLICE;
    path.elements[1].slice.has_start = true;
    path.elements[1].slice.start = 4;
    path.elements[1].slice.has_end = true;
    path.elements[1].slice.end = 12;

    s_parsed_value_collection collec = {0};
    assert_true(data_path_get(&path, &collec));
    assert_int_equal(collec.size, 1);
    assert_int_equal(collec.value[0].length, 8);
    assert_int_equal(collec.value[0].offset, 4);
    static const uint8_t expected[8] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22};
    assert_memory_equal(collec.value[0].ptr, expected, 8);
    data_path_cleanup(&collec);
}

static void test_data_path_get_slice_start_ge_end_rejected(void **state) {
    (void) state;
    static const uint8_t chunk[] = {0};
    set_chunk(0, chunk, sizeof(chunk));

    s_data_path path = {0};
    path.size = 2;
    path.elements[0].type = ELEMENT_TYPE_LEAF;
    path.elements[0].leaf.type = LEAF_TYPE_STATIC;
    path.elements[1].type = ELEMENT_TYPE_SLICE;
    path.elements[1].slice.has_start = true;
    path.elements[1].slice.start = 10;
    path.elements[1].slice.has_end = true;
    path.elements[1].slice.end = 10;  // start == end → reject

    s_parsed_value_collection collec = {0};
    assert_false(data_path_get(&path, &collec));
}

static void test_data_path_get_leaf_missing_chunk_returns_false(void **state) {
    (void) state;
    // Path asks for LEAF(DYNAMIC) but the calldata stub has no chunk
    // at offset 0 → must propagate false without dereferencing.
    s_data_path path = {0};
    path.size = 1;
    path.elements[0].type = ELEMENT_TYPE_LEAF;
    path.elements[0].leaf.type = LEAF_TYPE_DYNAMIC;

    s_parsed_value_collection collec = {0};
    assert_false(data_path_get(&path, &collec));
}

static void test_data_path_get_leaf_invalid_type_rejected_at_runtime(void **state) {
    (void) state;
    // LEAF_TYPE_TUPLE / LEAF_TYPE_ARRAY are accepted by the TLV layer
    // but not yet implemented at runtime — they fall into the default
    // case of path_leaf.
    s_data_path path = {0};
    path.size = 1;
    path.elements[0].type = ELEMENT_TYPE_LEAF;
    path.elements[0].leaf.type = LEAF_TYPE_TUPLE;

    s_parsed_value_collection collec = {0};
    assert_false(data_path_get(&path, &collec));
}

// =============================================================================
// data_path_cleanup — frees allocated leaves
// =============================================================================

static void test_data_path_cleanup_frees_allocated_ptr(void **state) {
    (void) state;
    // Allocate a buffer matching the convention used by path_leaf and
    // assert that cleanup does not crash. The malloc/free contract is
    // exercised via the existing mem_utils wrapper in mock.c.
    s_parsed_value_collection collec = {0};
    collec.size = 1;
    collec.value[0].ptr = (uint8_t *) malloc(16);
    collec.value[0].length = 16;
    collec.value[0].offset = 0;
    data_path_cleanup(&collec);
    // No leak / crash → test passes implicitly.
}

// =============================================================================
// Runner
// =============================================================================

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup(test_tlv_happy_path_all_five_element_types, reset),
        cmocka_unit_test_setup(test_tlv_ref_with_payload_rejected, reset),
        cmocka_unit_test_setup(test_tlv_leaf_invalid_type_rejected, reset),
        cmocka_unit_test_setup(test_tlv_leaf_each_valid_type_accepted, reset),
        cmocka_unit_test_setup(test_tlv_path_max_size_enforced, reset),
        cmocka_unit_test_setup(test_data_path_get_empty_path_returns_true, reset),
        cmocka_unit_test_setup(test_data_path_get_static_leaf_copies_chunk, reset),
        cmocka_unit_test_setup(test_data_path_get_slice_trims_collection, reset),
        cmocka_unit_test_setup(test_data_path_get_slice_start_ge_end_rejected, reset),
        cmocka_unit_test_setup(test_data_path_get_leaf_missing_chunk_returns_false, reset),
        cmocka_unit_test_setup(test_data_path_get_leaf_invalid_type_rejected_at_runtime, reset),
        cmocka_unit_test_setup(test_data_path_cleanup_frees_allocated_ptr, reset),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
