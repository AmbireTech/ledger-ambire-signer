/**
 * @file test_eth_ustream_helpers.c
 * @brief Unit tests for the low-level helpers in src/features/sign_tx/eth_ustream.c.
 *
 * This first suite focuses on the two helpers that everything else in the
 * RLP tx parser builds on:
 *   - init_tx() — zeros the context, hooks the sha3/content pointers, and
 *     calls cx_keccak_init_no_throw. If the SDK refuses (HSM seed not
 *     loaded, OOM, etc.) every later call must fail safely.
 *   - copy_tx_data() — consumes `length` bytes from the work buffer into
 *     either an output slot or /dev/null, hashes them into the running
 *     sha3 unless the current field is a self-encoded RLP single byte,
 *     and bumps every position counter exactly once.
 *
 * Later commits will cover the per-field process_* dispatchers and the
 * full state machine; the helpers in scope here have no dependency on
 * the dispatcher so they can be exercised in isolation.
 *
 * SDK crypto primitives are stubbed via fields in a static `s_sdk` table
 * that each test can poke before the call to force success or failure.
 * Every other symbol eth_ustream.c references is satisfied with the
 * lightest stub that makes the linker happy — none of them are reached
 * by the helpers exercised here.
 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "shared_context.h"
#include "eth_ustream.h"
#include "feature_sign_tx.h"
#include "network.h"  // network_info_t
#include "tx_ctx.h"
#include "calldata.h"

// =============================================================================
// Globals the module reads — provide storage here.
// =============================================================================

strings_t strings;
network_info_t *g_dynamic_network_list = NULL;
static chain_config_t s_chain_cfg = {.chain_id = 1, .ticker = "ETH", .coin_type = 60};
const chain_config_t *g_chain_config = &s_chain_cfg;
txContext_t txContext;
tmpContent_t tmpContent;

// eth_ustream.c declares s_calldata *g_parked_calldata in tx_ctx.h.
s_calldata *g_parked_calldata = NULL;

// =============================================================================
// SDK crypto stubs — configurable failure injection
// =============================================================================
//
// eth_ustream.c calls two SDK primitives:
//   - cx_keccak_init_no_throw() in init_tx
//   - cx_hash_no_throw() in read_tx_byte / copy_tx_data
// Each test resets s_sdk so the default is success.

// CX_OK is defined by cx_errors.h (pulled in via eth_ustream.h)
#define CX_INTERNAL_ERR 0x1234

static struct {
    uint32_t keccak_init_ret;
    uint32_t hash_ret;
    // Optional capture of the most recent cx_hash_no_throw input — used by
    // copy_tx_data tests to assert what got hashed.
    uint8_t hash_capture[64];
    size_t hash_capture_len;
    int hash_call_count;
} s_sdk;

uint32_t cx_keccak_init_no_throw(cx_sha3_t *sha3, size_t size) {
    (void) sha3;
    (void) size;
    return s_sdk.keccak_init_ret;
}

uint32_t cx_hash_no_throw(cx_hash_t *hash,
                          uint32_t mode,
                          const uint8_t *in,
                          size_t in_len,
                          uint8_t *out,
                          size_t out_len) {
    (void) hash;
    (void) mode;
    (void) out;
    (void) out_len;
    if (in && in_len <= sizeof(s_sdk.hash_capture)) {
        memcpy(s_sdk.hash_capture, in, in_len);
        s_sdk.hash_capture_len = in_len;
    }
    s_sdk.hash_call_count++;
    return s_sdk.hash_ret;
}

// =============================================================================
// Stubs for every other eth_ustream.c dependency — unreached by these tests
// =============================================================================

customStatus_e custom_processor(txContext_t *context) {
    (void) context;
    return CUSTOM_NOT_HANDLED;
}

bool tx_ctx_init(s_calldata *calldata,
                 const uint8_t *from,
                 const uint8_t *to,
                 const uint8_t *amount,
                 const uint64_t *chain_id) {
    (void) calldata;
    (void) from;
    (void) to;
    (void) amount;
    (void) chain_id;
    return true;
}

s_calldata *calldata_init(size_t size, const uint8_t *selector) {
    (void) size;
    (void) selector;
    return NULL;
}

bool calldata_append(s_calldata *calldata, const uint8_t *buffer, size_t size) {
    (void) calldata;
    (void) buffer;
    (void) size;
    return true;
}

void calldata_delete(s_calldata *node) {
    (void) node;
}

uint64_t get_tx_chain_id(void) {
    return 0;
}

// =============================================================================
// Test fixture
// =============================================================================

static int reset(void **state) {
    (void) state;
    memset(&txContext, 0, sizeof(txContext));
    memset(&tmpContent, 0, sizeof(tmpContent));
    memset(&s_sdk, 0, sizeof(s_sdk));
    s_sdk.keccak_init_ret = CX_OK;
    s_sdk.hash_ret = CX_OK;
    g_parked_calldata = NULL;
    return 0;
}

// =============================================================================
// init_tx
// =============================================================================

static void test_init_tx_zeros_context_and_sets_pointers(void **state) {
    (void) state;
    txContext_t ctx;
    cx_sha3_t sha3 = {0};
    txContent_t content = {0};

    // Dirty the context to make sure init_tx zeroes it
    memset(&ctx, 0xAA, sizeof(ctx));

    assert_true(init_tx(&ctx, &sha3, &content, /*store_calldata=*/false));

    assert_ptr_equal(ctx.sha3, &sha3);
    assert_ptr_equal(ctx.content, &content);
    assert_int_equal(ctx.currentField, RLP_NONE + 1);
    assert_false(ctx.store_calldata);
    // Other fields should all be zeroed
    assert_int_equal(ctx.rlpBufferPos, 0);
    assert_int_equal(ctx.currentFieldLength, 0);
    assert_int_equal(ctx.commandLength, 0);
    assert_int_equal(ctx.txType, 0);
}

static void test_init_tx_propagates_store_calldata_flag(void **state) {
    (void) state;
    txContext_t ctx;
    cx_sha3_t sha3 = {0};
    txContent_t content = {0};

    assert_true(init_tx(&ctx, &sha3, &content, /*store_calldata=*/true));
    assert_true(ctx.store_calldata);
}

static void test_init_tx_returns_false_on_keccak_init_failure(void **state) {
    (void) state;
    txContext_t ctx;
    cx_sha3_t sha3 = {0};
    txContent_t content = {0};

    s_sdk.keccak_init_ret = CX_INTERNAL_ERR;
    assert_false(init_tx(&ctx, &sha3, &content, false));
}

// =============================================================================
// copy_tx_data — happy paths
// =============================================================================

static void test_copy_tx_data_copies_and_advances(void **state) {
    (void) state;
    const uint8_t src[] = {0x11, 0x22, 0x33, 0x44, 0x55};
    txContext.workBuffer = src;
    txContext.commandLength = sizeof(src);
    txContext.processingField = false;
    txContext.fieldSingleByte = false;

    uint8_t dst[3] = {0};
    assert_true(copy_tx_data(&txContext, dst, sizeof(dst)));

    // Copied
    const uint8_t expected[] = {0x11, 0x22, 0x33};
    assert_memory_equal(dst, expected, sizeof(dst));
    // Bookkeeping
    assert_ptr_equal(txContext.workBuffer, src + 3);
    assert_int_equal(txContext.commandLength, 2);
    // currentFieldPos only moves when processingField is true → here it stays
    assert_int_equal(txContext.currentFieldPos, 0);
    // Hash got fed
    assert_int_equal(s_sdk.hash_call_count, 1);
    assert_int_equal(s_sdk.hash_capture_len, 3);
    assert_memory_equal(s_sdk.hash_capture, expected, 3);
}

static void test_copy_tx_data_null_out_consumes_without_copying(void **state) {
    (void) state;
    const uint8_t src[] = {0xAB, 0xCD, 0xEF};
    txContext.workBuffer = src;
    txContext.commandLength = sizeof(src);

    assert_true(copy_tx_data(&txContext, NULL, 2));
    // Still advances over the consumed bytes
    assert_ptr_equal(txContext.workBuffer, src + 2);
    assert_int_equal(txContext.commandLength, 1);
    // And still hashes
    assert_int_equal(s_sdk.hash_call_count, 1);
    assert_int_equal(s_sdk.hash_capture_len, 2);
}

static void test_copy_tx_data_processing_field_advances_pos(void **state) {
    (void) state;
    const uint8_t src[] = {1, 2, 3, 4};
    txContext.workBuffer = src;
    txContext.commandLength = 4;
    txContext.processingField = true;
    txContext.fieldSingleByte = false;
    txContext.currentFieldPos = 5;  // any pre-existing value

    uint8_t dst[2];
    assert_true(copy_tx_data(&txContext, dst, 2));
    assert_int_equal(txContext.currentFieldPos, 5 + 2);
}

static void test_copy_tx_data_zero_length_is_noop_but_hashes(void **state) {
    (void) state;
    const uint8_t src[] = {1, 2, 3};
    txContext.workBuffer = src;
    txContext.commandLength = 3;

    // copy_tx_data(0) should pass the cmd-length check (0 <= commandLength)
    // and call cx_hash_no_throw with len=0 — the SDK accepts that, so we do
    // not assert on hash_capture_len here.
    assert_true(copy_tx_data(&txContext, NULL, 0));
    assert_ptr_equal(txContext.workBuffer, src);
    assert_int_equal(txContext.commandLength, 3);
}

// =============================================================================
// copy_tx_data — single-byte RLP optimization
// =============================================================================

static void test_copy_tx_data_single_byte_self_encoded_skips_hash(void **state) {
    (void) state;
    // When processingField && fieldSingleByte, the byte was already hashed
    // during the pre-decode walk of the RLP prefix → re-hashing would
    // double-count it. copy_tx_data must skip the cx_hash call.
    const uint8_t src[] = {0x7F};  // any single-byte RLP value
    txContext.workBuffer = src;
    txContext.commandLength = 1;
    txContext.processingField = true;
    txContext.fieldSingleByte = true;

    uint8_t dst[1];
    assert_true(copy_tx_data(&txContext, dst, 1));
    assert_int_equal(dst[0], 0x7F);
    // Crucially: no hash call.
    assert_int_equal(s_sdk.hash_call_count, 0);
}

static void test_copy_tx_data_single_byte_outside_processing_still_hashes(void **state) {
    (void) state;
    // The fieldSingleByte short-circuit only applies during processingField.
    const uint8_t src[] = {0x7F};
    txContext.workBuffer = src;
    txContext.commandLength = 1;
    txContext.processingField = false;
    txContext.fieldSingleByte = true;

    assert_true(copy_tx_data(&txContext, NULL, 1));
    assert_int_equal(s_sdk.hash_call_count, 1);
}

// =============================================================================
// copy_tx_data — failure paths
// =============================================================================

static void test_copy_tx_data_command_length_underflow_rejected(void **state) {
    (void) state;
    const uint8_t src[] = {0x11, 0x22};
    txContext.workBuffer = src;
    txContext.commandLength = 2;

    // Asking for 3 bytes when only 2 remain must reject before any
    // dereferencing / advancement.
    uint8_t dst[3] = {0xFF, 0xFF, 0xFF};
    assert_false(copy_tx_data(&txContext, dst, 3));
    // dst untouched
    assert_int_equal(dst[0], 0xFF);
    // workBuffer / commandLength unchanged
    assert_ptr_equal(txContext.workBuffer, src);
    assert_int_equal(txContext.commandLength, 2);
    // No hash call attempted
    assert_int_equal(s_sdk.hash_call_count, 0);
}

static void test_copy_tx_data_hash_failure_propagates(void **state) {
    (void) state;
    const uint8_t src[] = {0x11, 0x22};
    txContext.workBuffer = src;
    txContext.commandLength = 2;
    s_sdk.hash_ret = CX_INTERNAL_ERR;

    uint8_t dst[2];
    assert_false(copy_tx_data(&txContext, dst, 2));
    // dst was written before the hash check (memmove runs first)
    // but the function returns false to abort the caller — that's the
    // contract we care about for fault propagation.
}

// =============================================================================
// process_tx — end-to-end RLP parsing of a single transaction.
//
// Driving real RLP bytes through the public entry point exercises every
// static helper (parse_rlp, check_cmd_length, check_empty_list,
// check_fields, the per-type process_legacy_tx / process_eip1559_tx
// dispatchers, and the field-specific process_* functions). The
// alternative — calling each static helper individually — isn't
// possible from outside the TU.
//
// Coverage focus, not crypto: SDK hash/keccak primitives are stubbed
// (return CX_OK), so the running hash and signature recovery aren't
// validated here. The point is to pin the byte-pump that decides what
// goes into the signed digest in the first place.
// =============================================================================

// Build a minimal legacy transaction in RLP encoding.
//
// Plain values:
//   nonce    = 0x07
//   gasPrice = 0x04A817C800  (20 Gwei)
//   startGas = 0x5208        (21000)
//   to       = 20 * 0xAA
//   value    = 0
//   data     = (empty)
//   v        = 0x1B          (chain_id-less / pre-EIP-155 path)
//   r        = 0
//   s        = 0
//
// Inner payload size = 1 + 6 + 3 + 21 + 1 + 1 + 1 + 1 + 1 = 36 bytes.
// List prefix = 0xC0 + 36 = 0xE4.
static const uint8_t g_minimal_legacy_tx[] = {
    0xE4,                                // list, payload = 36 bytes
    0x07,                                // nonce = 7
    0x85, 0x04, 0xA8, 0x17, 0xC8, 0x00,  // gasPrice
    0x82, 0x52, 0x08,                    // startGas
    0x94,                                // 20-byte string
    0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
    0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,  // to
    0x80,                                                        // value = 0
    0x80,                                                        // data = empty
    0x1B,                                                        // v = 27 (self-encoded)
    0x80,                                                        // r = 0
    0x80,                                                        // s = 0
};

static void test_process_tx_legacy_happy_path(void **state) {
    (void) state;
    cx_sha3_t sha3;
    txContent_t content = {0};
    txContext_t ctx;
    assert_true(init_tx(&ctx, &sha3, &content, /*store_calldata=*/false));
    ctx.txType = LEGACY;  // cmd_sign_tx sets this before calling.

    parserStatus_e r = process_tx(&ctx, g_minimal_legacy_tx, sizeof(g_minimal_legacy_tx));
    assert_int_equal(r, USTREAM_FINISHED);

    // process_* helpers write to ctx->content (i.e. our local `content`).
    assert_int_equal(content.nonce.length, 1);
    assert_int_equal(content.nonce.value[0], 0x07);

    assert_int_equal(content.gasprice.length, 5);
    static const uint8_t expected_gasprice[5] = {0x04, 0xA8, 0x17, 0xC8, 0x00};
    assert_memory_equal(content.gasprice.value, expected_gasprice, 5);

    assert_int_equal(content.startgas.length, 2);
    static const uint8_t expected_startgas[2] = {0x52, 0x08};
    assert_memory_equal(content.startgas.value, expected_startgas, 2);

    assert_int_equal(content.destinationLength, ADDRESS_LENGTH);
    uint8_t expected_to[ADDRESS_LENGTH];
    memset(expected_to, 0xAA, ADDRESS_LENGTH);
    assert_memory_equal(content.destination, expected_to, ADDRESS_LENGTH);

    // value=0 → length 0, no bytes.
    assert_int_equal(content.value.length, 0);

    // v = 0x1B captured in v[0].
    assert_int_equal(content.v[0], 0x1B);
    assert_int_equal(content.vLength, 1);
}

static void test_process_tx_truncated_mid_field_returns_processing(void **state) {
    (void) state;
    // Send only the first 12 bytes — far short of the 37-byte total.
    // The parser must report USTREAM_PROCESSING (waiting for more
    // data), not USTREAM_FAULT or FINISHED. That's the contract the
    // multi-APDU chunked sign-tx flow depends on.
    cx_sha3_t sha3;
    txContent_t content = {0};
    txContext_t ctx;
    assert_true(init_tx(&ctx, &sha3, &content, /*store_calldata=*/false));
    ctx.txType = LEGACY;

    parserStatus_e r = process_tx(&ctx, g_minimal_legacy_tx, 12);
    assert_int_equal(r, USTREAM_PROCESSING);
}

static void test_process_tx_chunked_two_halves_finishes(void **state) {
    (void) state;
    // Feed the same minimal tx in two slices via process_tx +
    // continue_tx. The streamer must reassemble the field that
    // straddles the boundary without losing bytes.
    cx_sha3_t sha3;
    txContent_t content = {0};
    txContext_t ctx;
    assert_true(init_tx(&ctx, &sha3, &content, /*store_calldata=*/false));
    ctx.txType = LEGACY;

    const size_t mid = sizeof(g_minimal_legacy_tx) / 2;
    parserStatus_e r = process_tx(&ctx, g_minimal_legacy_tx, mid);
    assert_int_equal(r, USTREAM_PROCESSING);

    // Second slice — process_tx with the remainder.
    r = process_tx(&ctx, g_minimal_legacy_tx + mid, sizeof(g_minimal_legacy_tx) - mid);
    assert_int_equal(r, USTREAM_FINISHED);
    assert_int_equal(content.destinationLength, ADDRESS_LENGTH);
}

static void test_process_tx_unsupported_tx_type_returns_fault(void **state) {
    (void) state;
    // Force an out-of-range txType — the process_tx_internal default
    // branch must reject rather than fall through to a wrong dispatcher.
    cx_sha3_t sha3;
    txContent_t content = {0};
    txContext_t ctx;
    assert_true(init_tx(&ctx, &sha3, &content, false));
    ctx.txType = 0x7F;  // not LEGACY/EIP2930/EIP1559/EIP7702

    parserStatus_e r = process_tx(&ctx, g_minimal_legacy_tx, sizeof(g_minimal_legacy_tx));
    assert_int_equal(r, USTREAM_FAULT);
}

// =============================================================================
// EIP-1559 / EIP-2930 / EIP-7702 RLP parsing — typed-transaction
// envelopes. The wire format prepends a single txType byte (0x01 /
// 0x02 / 0x04) to a list whose layout differs from legacy. The
// parser doesn't see the type byte (cmd_sign_tx strips it and sets
// ctx.txType before dispatching), so the test feeds only the inner
// list and forces the type explicitly.
//
// Coverage focus: every per-type dispatcher
// (process_eip1559_tx / process_eip2930_tx / process_eip7702_tx)
// plus the field handlers that legacy doesn't reach (process_chain_id,
// process_access_list, process_auth_list).
// =============================================================================

// EIP-1559 inner list: [chainId, nonce, maxPriorityFee, maxFee,
//                       gasLimit, to, value, data, accessList]
// 9 fields, payload = 36 bytes, list prefix = 0xC0 + 36 = 0xE4.
static const uint8_t g_minimal_eip1559_tx[] = {
    0xE4,                                // list, payload = 36 bytes
    0x01,                                // chainId = 1
    0x07,                                // nonce = 7
    0x05,                                // maxPriorityFee = 5
    0x85, 0x04, 0xA8, 0x17, 0xC8, 0x00,  // maxFee
    0x82, 0x52, 0x08,                    // gasLimit
    0x94,                                // 20-byte string
    0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
    0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,  // to
    0x80,                                                        // value = 0
    0x80,                                                        // data = empty
    0xC0,                                                        // accessList = empty list
};

static void test_process_tx_eip1559_happy_path(void **state) {
    (void) state;
    cx_sha3_t sha3;
    txContent_t content = {0};
    txContext_t ctx;
    assert_true(init_tx(&ctx, &sha3, &content, /*store_calldata=*/false));
    ctx.txType = EIP1559;

    parserStatus_e r = process_tx(&ctx, g_minimal_eip1559_tx, sizeof(g_minimal_eip1559_tx));
    assert_int_equal(r, USTREAM_FINISHED);

    assert_int_equal(content.chainID.length, 1);
    assert_int_equal(content.chainID.value[0], 0x01);
    assert_int_equal(content.nonce.length, 1);
    assert_int_equal(content.nonce.value[0], 0x07);
    // maxFee lands in gasprice (alias) for EIP-1559.
    assert_int_equal(content.gasprice.length, 5);
    assert_int_equal(content.startgas.length, 2);
    assert_int_equal(content.destinationLength, ADDRESS_LENGTH);
    // No v in the unsigned RLP — vLength stays 0.
    assert_int_equal(content.vLength, 0);
}

// EIP-2930 inner list: [chainId, nonce, gasPrice, gasLimit, to, value,
//                       data, accessList]
// 8 fields, payload = 35 bytes, list prefix = 0xC0 + 35 = 0xE3.
static const uint8_t g_minimal_eip2930_tx[] = {
    0xE3,                                // list, payload = 35 bytes
    0x01,                                // chainId = 1
    0x07,                                // nonce = 7
    0x85, 0x04, 0xA8, 0x17, 0xC8, 0x00,  // gasPrice
    0x82, 0x52, 0x08,                    // gasLimit
    0x94, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
    0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,  // to
    0x80,                                                        // value = 0
    0x80,                                                        // data = empty
    0xC0,                                                        // accessList = empty list
};

static void test_process_tx_eip2930_happy_path(void **state) {
    (void) state;
    cx_sha3_t sha3;
    txContent_t content = {0};
    txContext_t ctx;
    assert_true(init_tx(&ctx, &sha3, &content, false));
    ctx.txType = EIP2930;

    parserStatus_e r = process_tx(&ctx, g_minimal_eip2930_tx, sizeof(g_minimal_eip2930_tx));
    assert_int_equal(r, USTREAM_FINISHED);
    assert_int_equal(content.chainID.value[0], 0x01);
    assert_int_equal(content.destinationLength, ADDRESS_LENGTH);
}

// EIP-7702 inner list: [chainId, nonce, maxPriorityFee, maxFee,
//                       gasLimit, to, value, data, accessList, authList]
// EIP-7702 is the highest-risk tx type: authList delegates EOA authority
// to contract code, so a parser bug that lets bytes drift between the
// signature and the rendered display is a permanent-account-compromise
// vector. Pin the happy path so the dispatcher and process_auth_list
// are exercised.
//
// 10 fields, payload = 37 bytes, list prefix = 0xC0 + 37 = 0xE5.
static const uint8_t g_minimal_eip7702_tx[] = {
    0xE5,                                // list, payload = 37 bytes
    0x01,                                // chainId = 1
    0x07,                                // nonce = 7
    0x05,                                // maxPriorityFee = 5
    0x85, 0x04, 0xA8, 0x17, 0xC8, 0x00,  // maxFee
    0x82, 0x52, 0x08,                    // gasLimit
    0x94, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
    0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,  // to
    0x80,                                                        // value = 0
    0x80,                                                        // data = empty
    0xC0,                                                        // accessList = empty
    0xC0,                                                        // authList = empty
};

static void test_process_tx_eip7702_happy_path(void **state) {
    (void) state;
    cx_sha3_t sha3;
    txContent_t content = {0};
    txContext_t ctx;
    assert_true(init_tx(&ctx, &sha3, &content, false));
    ctx.txType = EIP7702;

    parserStatus_e r = process_tx(&ctx, g_minimal_eip7702_tx, sizeof(g_minimal_eip7702_tx));
    assert_int_equal(r, USTREAM_FINISHED);
    assert_int_equal(content.chainID.value[0], 0x01);
    assert_int_equal(content.destinationLength, ADDRESS_LENGTH);
}

// process_chain_id explicitly rejects values that don't fit in a
// uint64_t — the comment in eth_ustream.c flags this as CWE-197
// hardening (signature covers one chain, display shows the truncated
// 64-bit prefix). Pin the rejection.
static void test_process_tx_eip1559_chainid_overflow_rejected(void **state) {
    (void) state;
    cx_sha3_t sha3;
    txContent_t content = {0};
    txContext_t ctx;
    assert_true(init_tx(&ctx, &sha3, &content, false));
    ctx.txType = EIP1559;

    // 9-byte chainId — exceeds sizeof(uint64_t)=8. The 9-byte string
    // prefix is 0x80 + 9 = 0x89. Just feed the chainId prefix + bytes;
    // the parser must fault before reaching the rest of the envelope.
    const uint8_t bytes[] = {
        0xEC,                                                        // list, payload = 44 bytes
        0x89, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,  // 9-byte chainId
        0x07,                                                        // nonce
        0x05,                                                        // maxPriorityFee
        0x85, 0x04, 0xA8, 0x17, 0xC8, 0x00,                          // maxFee
        0x82, 0x52, 0x08,                                            // gasLimit
        0x94, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
        0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,  // to
        0x80, 0x80, 0xC0,                                            // value, data, accessList
    };
    parserStatus_e r = process_tx(&ctx, bytes, sizeof(bytes));
    assert_int_equal(r, USTREAM_FAULT);
}

// =============================================================================
// Runner
// =============================================================================

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup(test_init_tx_zeros_context_and_sets_pointers, reset),
        cmocka_unit_test_setup(test_init_tx_propagates_store_calldata_flag, reset),
        cmocka_unit_test_setup(test_init_tx_returns_false_on_keccak_init_failure, reset),
        cmocka_unit_test_setup(test_copy_tx_data_copies_and_advances, reset),
        cmocka_unit_test_setup(test_copy_tx_data_null_out_consumes_without_copying, reset),
        cmocka_unit_test_setup(test_copy_tx_data_processing_field_advances_pos, reset),
        cmocka_unit_test_setup(test_copy_tx_data_zero_length_is_noop_but_hashes, reset),
        cmocka_unit_test_setup(test_copy_tx_data_single_byte_self_encoded_skips_hash, reset),
        cmocka_unit_test_setup(test_copy_tx_data_single_byte_outside_processing_still_hashes,
                               reset),
        cmocka_unit_test_setup(test_copy_tx_data_command_length_underflow_rejected, reset),
        cmocka_unit_test_setup(test_copy_tx_data_hash_failure_propagates, reset),
        cmocka_unit_test_setup(test_process_tx_legacy_happy_path, reset),
        cmocka_unit_test_setup(test_process_tx_truncated_mid_field_returns_processing, reset),
        cmocka_unit_test_setup(test_process_tx_chunked_two_halves_finishes, reset),
        cmocka_unit_test_setup(test_process_tx_unsupported_tx_type_returns_fault, reset),
        cmocka_unit_test_setup(test_process_tx_eip1559_happy_path, reset),
        cmocka_unit_test_setup(test_process_tx_eip2930_happy_path, reset),
        cmocka_unit_test_setup(test_process_tx_eip7702_happy_path, reset),
        cmocka_unit_test_setup(test_process_tx_eip1559_chainid_overflow_rejected, reset),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
