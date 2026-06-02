/**
 * @file test_cmd_get_gating.c
 * @brief Unit tests for the backend-signed gated-signing descriptor at
 *        src/features/provide_gating/cmd_get_gating.c.
 *
 * The gated-signing descriptor lets the backend nudge the user toward a
 * safer alternative when the current sign request is blind. The
 * descriptor binds:
 *   - the chain_id (for SignTx flows),
 *   - the contract address (must match the active tx),
 *   - the function selector or EIP-712 schema hash,
 *   - the intro message + tiny URL that show up on the prelude screen.
 *
 * After verify_signature succeeds against
 * CERTIFICATE_PUBLIC_KEY_USAGE_GATED_SIGNING, the device must still
 * cross-check that the descriptor binds to the *same* transaction the
 * user is reviewing (type / chain_id / address / selector). A bug in
 * either gate lets a malicious backend hide the gating prelude (or
 * worse, render it for the wrong tx).
 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>

#include "shared_context.h"
#include "cmd_get_gating.h"
#include "apdu_constants.h"
#include "tlv_apdu.h"
#include "context_712.h"
#include "nbgl_use_case.h"
#include "nbgl_types.h"
#include "wraps.h"

// `warning` is referenced by set_gating_ui_screen; the real symbol
// lives in libNbgl which we don't link here, so provide local storage.

// =============================================================================
// Globals required by linked translation units
// =============================================================================

s_eip712_context g_eip712_storage;
s_eip712_context *eip712_context = NULL;

// ui_icons.h pulls in ICON_LEDGER → C_ledger_14px (no SCREEN_SIZE_WALLET
// in the test build). Stub the symbol so set_gating_ui_screen links.
const nbgl_icon_details_t C_ledger_14px;

// =============================================================================
// Controllable stubs
// =============================================================================

// check_signature_with_pubkey / finalize_hash / hash_nbytes /
// get_tx_chain_id are wrapped in mocks/mock.c; their state is driven
// through g_sig_check_ret / g_finalize_hash_ret / g_tx_chain_id
// from wraps.h.

static bool g_compute_schema_hash_ret = true;
bool __wrap_compute_schema_hash(void) {
    return g_compute_schema_hash_ret;
}

// Proxy lookup wraps — return NULL by default (no proxy).
static const uint8_t *g_implem_contract_ret = NULL;
static const uint8_t *g_proxy_contract_ret = NULL;
const uint8_t *__wrap_get_implem_contract(const uint64_t *chain_id,
                                          const uint8_t *contract,
                                          const uint8_t *selector) {
    (void) chain_id;
    (void) contract;
    (void) selector;
    return g_implem_contract_ret;
}
const uint8_t *__wrap_get_proxy_contract(const uint64_t *chain_id,
                                         const uint8_t *implem,
                                         const uint8_t *selector) {
    (void) chain_id;
    (void) implem;
    (void) selector;
    return g_proxy_contract_ret;
}

// nvm_write wrap — capture the value the source pushes into the
// gating_counter slot so tests can verify the counter cadence.
static uint8_t g_captured_counter = 0;
static int g_nvm_write_calls = 0;
void __wrap_nvm_write(void *dst, void *src, unsigned int len) {
    (void) dst;
    if (len == 1 && src != NULL) {
        g_captured_counter = *(uint8_t *) src;
    }
    g_nvm_write_calls++;
    // Reflect the write back into N_storage_real so subsequent calls
    // see the bumped counter.
    g_n_storage_writable.gating_counter = g_captured_counter;
}

// =============================================================================
// TLV builder for GATING descriptor
// =============================================================================
//
// Tags ≥ 0x80 need DER long-form (0x81 <tag>).
//   0x01 STRUCTURE_TYPE      = 0x0D
//   0x02 STRUCTURE_VERSION   = 0x01
//   0x22 ADDRESS             = 20 bytes
//   0x23 CHAIN_ID            = 1+ bytes
//   0x40 HASH_SELECTOR       = 4 bytes (Tx) or 28 bytes (EIP-712)
//   0x82 INTRO_MSG           = string (long-form)
//   0x83 TINY_URL            = string (long-form)
//   0x84 TX_TYPE             = 1 byte (long-form): 0=Tx, 1=TypedData
//   0x15 DER_SIGNATURE       = N bytes

#define ECDSA_SIG_MIN 67
#define ECDSA_SIG_MAX 72

typedef struct {
    uint8_t struct_type;
    uint8_t struct_version;
    uint8_t chain_id;
    bool include_chain_id;
    bool include_hash_selector;
    bool include_address;
    bool include_intro_msg;
    bool include_tiny_url;
    bool include_tx_type;
    bool include_signature;
    bool address_zero;
    uint8_t hash_selector_size;
    uint8_t tx_type;
    uint8_t address_byte;
    uint8_t selector_byte;
    uint8_t sig_len;
} s_opts;

static s_opts default_tx_opts(void) {
    s_opts o = {.struct_type = 0x0D,
                .struct_version = 0x01,
                .chain_id = 1,
                .include_chain_id = true,
                .include_hash_selector = true,
                .include_address = true,
                .include_intro_msg = true,
                .include_tiny_url = true,
                .include_tx_type = true,
                .include_signature = true,
                .hash_selector_size = 4,  // SignTx = selector
                .tx_type = 0,             // TX_TYPE_TRANSACTION (0 in wire, +1 in struct)
                .address_byte = 0xAA,
                .selector_byte = 0xCC,
                .sig_len = ECDSA_SIG_MIN};
    return o;
}

static s_opts default_eip712_opts(void) {
    s_opts o = default_tx_opts();
    o.include_chain_id = false;
    o.hash_selector_size = 28;  // CX_SHA224_SIZE
    o.tx_type = 1;              // TX_TYPE_TYPED_DATA wire value
    return o;
}

static void w(uint8_t *out, size_t *off, uint8_t b) {
    out[(*off)++] = b;
}

static size_t build_tlv(uint8_t *out, size_t out_size, s_opts opts) {
    size_t off = 0;
    // STRUCTURE_TYPE
    w(out, &off, 0x01);
    w(out, &off, 0x01);
    w(out, &off, opts.struct_type);
    // STRUCTURE_VERSION
    w(out, &off, 0x02);
    w(out, &off, 0x01);
    w(out, &off, opts.struct_version);
    // ADDRESS
    if (opts.include_address) {
        w(out, &off, 0x22);
        w(out, &off, ADDRESS_LENGTH);
        memset(out + off, opts.address_zero ? 0 : opts.address_byte, ADDRESS_LENGTH);
        off += ADDRESS_LENGTH;
    }
    // CHAIN_ID
    if (opts.include_chain_id) {
        w(out, &off, 0x23);
        w(out, &off, 0x01);
        w(out, &off, opts.chain_id);
    }
    // HASH_SELECTOR
    if (opts.include_hash_selector) {
        w(out, &off, 0x40);
        w(out, &off, opts.hash_selector_size);
        memset(out + off, opts.selector_byte, opts.hash_selector_size);
        off += opts.hash_selector_size;
    }
    // INTRO_MSG (tag 0x82 needs long-form)
    if (opts.include_intro_msg) {
        w(out, &off, 0x81);
        w(out, &off, 0x82);
        w(out, &off, 0x05);
        memcpy(out + off, "hello", 5);
        off += 5;
    }
    // TINY_URL (tag 0x83 needs long-form)
    if (opts.include_tiny_url) {
        w(out, &off, 0x81);
        w(out, &off, 0x83);
        w(out, &off, 0x04);
        memcpy(out + off, "http", 4);
        off += 4;
    }
    // TX_TYPE (tag 0x84 needs long-form)
    if (opts.include_tx_type) {
        w(out, &off, 0x81);
        w(out, &off, 0x84);
        w(out, &off, 0x01);
        w(out, &off, opts.tx_type);
    }
    // SIGNATURE
    if (opts.include_signature) {
        w(out, &off, 0x15);
        w(out, &off, opts.sig_len);
        // DER-shape stub: 0x30 LEN 0x02 .. 0x02 ..  (parser only checks size range)
        out[off] = 0x30;
        out[off + 1] = opts.sig_len - 2;
        for (size_t i = 2; i < opts.sig_len; i++) {
            out[off + i] = 0x42;
        }
        off += opts.sig_len;
    }
    assert_true(off <= out_size);
    return off;
}

static bool send_descriptor(const uint8_t *tlv, size_t len) {
    // Prepend the BE16 length prefix tlv_apdu expects on the first chunk.
    uint8_t framed[600];
    framed[0] = (uint8_t) (len >> 8);
    framed[1] = (uint8_t) (len & 0xFF);
    assert_true(len + 2 <= sizeof(framed));
    memcpy(framed + 2, tlv, len);
    uint16_t sw = handle_gating(/*p1=*/P1_FIRST_CHUNK, /*p2=*/0x00, framed, (uint8_t) (len + 2));
    return sw == SWO_SUCCESS;
}

// =============================================================================
// Fixture
// =============================================================================

static int reset(void **state) {
    (void) state;
    clear_gating();
    memset(&g_n_storage_writable, 0, sizeof(g_n_storage_writable));
    memset(&g_eip712_storage, 0, sizeof(g_eip712_storage));
    eip712_context = NULL;
    g_sig_check_ret = true;
    g_finalize_hash_ret = true;
    g_compute_schema_hash_ret = true;
    g_implem_contract_ret = NULL;
    g_proxy_contract_ret = NULL;
    g_captured_counter = 0;
    g_nvm_write_calls = 0;
    g_tx_chain_id = 1;
    memset(&txContext, 0, sizeof(txContext));
    memset(&tmpContent, 0, sizeof(tmpContent));
    appState = APP_STATE_SIGNING_TX;
    tlv_from_apdu(false, 0, NULL, NULL);
    return 0;
}

// =============================================================================
// Tests — entry-point dispatcher
// =============================================================================

static void test_p2_unknown_rejected(void **state) {
    (void) state;
    uint8_t data[1] = {0};
    uint16_t sw = handle_gating(/*p1=*/0x00, /*p2=*/0xFF, data, 1);
    assert_int_equal(sw, SWO_WRONG_P1_P2);
}

// =============================================================================
// TLV happy path + validation gates
// =============================================================================

static void test_happy_path_transaction(void **state) {
    (void) state;
    uint8_t tlv[500];
    s_opts opts = default_tx_opts();
    size_t len = build_tlv(tlv, sizeof(tlv), opts);
    assert_true(send_descriptor(tlv, len));
}

static void test_happy_path_typed_data(void **state) {
    (void) state;
    appState = APP_STATE_SIGNING_EIP712;
    uint8_t tlv[500];
    s_opts opts = default_eip712_opts();
    size_t len = build_tlv(tlv, sizeof(tlv), opts);
    assert_true(send_descriptor(tlv, len));
}

static void test_invalid_struct_type_rejected(void **state) {
    (void) state;
    uint8_t tlv[500];
    s_opts opts = default_tx_opts();
    opts.struct_type = 0xFF;
    size_t len = build_tlv(tlv, sizeof(tlv), opts);
    assert_false(send_descriptor(tlv, len));
}

static void test_invalid_struct_version_rejected(void **state) {
    (void) state;
    uint8_t tlv[500];
    s_opts opts = default_tx_opts();
    opts.struct_version = 0x05;
    size_t len = build_tlv(tlv, sizeof(tlv), opts);
    assert_false(send_descriptor(tlv, len));
}

static void test_address_all_zeros_rejected(void **state) {
    (void) state;
    uint8_t tlv[500];
    s_opts opts = default_tx_opts();
    opts.address_zero = true;
    size_t len = build_tlv(tlv, sizeof(tlv), opts);
    assert_false(send_descriptor(tlv, len));
}

static void test_hash_selector_too_big_rejected(void **state) {
    (void) state;
    uint8_t tlv[500];
    s_opts opts = default_tx_opts();
    opts.hash_selector_size = 32;  // > CX_SHA224_SIZE
    size_t len = build_tlv(tlv, sizeof(tlv), opts);
    assert_false(send_descriptor(tlv, len));
}

static void test_tx_type_out_of_range_rejected(void **state) {
    (void) state;
    uint8_t tlv[500];
    s_opts opts = default_tx_opts();
    opts.tx_type = 0x05;  // beyond TX_TYPE_TYPED_DATA wire value
    size_t len = build_tlv(tlv, sizeof(tlv), opts);
    assert_false(send_descriptor(tlv, len));
}

static void test_signtx_without_chain_id_rejected(void **state) {
    (void) state;
    uint8_t tlv[500];
    s_opts opts = default_tx_opts();
    opts.include_chain_id = false;
    size_t len = build_tlv(tlv, sizeof(tlv), opts);
    assert_false(send_descriptor(tlv, len));
}

static void test_typed_data_without_hash_selector_rejected(void **state) {
    (void) state;
    uint8_t tlv[500];
    s_opts opts = default_eip712_opts();
    opts.include_hash_selector = false;
    size_t len = build_tlv(tlv, sizeof(tlv), opts);
    assert_false(send_descriptor(tlv, len));
}

static void test_missing_address_rejected(void **state) {
    (void) state;
    uint8_t tlv[500];
    s_opts opts = default_tx_opts();
    opts.include_address = false;
    size_t len = build_tlv(tlv, sizeof(tlv), opts);
    assert_false(send_descriptor(tlv, len));
}

static void test_missing_intro_msg_rejected(void **state) {
    (void) state;
    uint8_t tlv[500];
    s_opts opts = default_tx_opts();
    opts.include_intro_msg = false;
    size_t len = build_tlv(tlv, sizeof(tlv), opts);
    assert_false(send_descriptor(tlv, len));
}

static void test_missing_tiny_url_rejected(void **state) {
    (void) state;
    uint8_t tlv[500];
    s_opts opts = default_tx_opts();
    opts.include_tiny_url = false;
    size_t len = build_tlv(tlv, sizeof(tlv), opts);
    assert_false(send_descriptor(tlv, len));
}

static void test_missing_signature_rejected(void **state) {
    (void) state;
    uint8_t tlv[500];
    s_opts opts = default_tx_opts();
    opts.include_signature = false;
    size_t len = build_tlv(tlv, sizeof(tlv), opts);
    assert_false(send_descriptor(tlv, len));
}

static void test_signature_check_failure_clears_gating(void **state) {
    (void) state;
    g_sig_check_ret = false;
    uint8_t tlv[500];
    s_opts opts = default_tx_opts();
    size_t len = build_tlv(tlv, sizeof(tlv), opts);
    assert_false(send_descriptor(tlv, len));
    // After a failed verify_signature, set_gating_warning must report
    // no descriptor is active.
    assert_true(set_gating_warning());
    assert_int_equal(g_nvm_write_calls, 0);
}

static void test_clear_gating_wipes_descriptor(void **state) {
    (void) state;
    uint8_t tlv[500];
    s_opts opts = default_tx_opts();
    size_t len = build_tlv(tlv, sizeof(tlv), opts);
    assert_true(send_descriptor(tlv, len));
    clear_gating();
    // No GATING means set_gating_warning short-circuits to true.
    assert_true(set_gating_warning());
    assert_int_equal(g_nvm_write_calls, 0);
}

// =============================================================================
// set_gating_warning — UI cross-check
// =============================================================================

// Prime a SignTx descriptor and arm the active-tx state so that
// check_tx_gating_params would succeed without further tweaks.
static void prime_tx_descriptor(void) {
    uint8_t tlv[500];
    s_opts opts = default_tx_opts();
    size_t len = build_tlv(tlv, sizeof(tlv), opts);
    assert_true(send_descriptor(tlv, len));
    appState = APP_STATE_SIGNING_TX;
    g_tx_chain_id = 1;
    memset(tmpContent.txContent.destination, 0xAA, ADDRESS_LENGTH);
    memset(txContext.selector_bytes, 0xCC, SELECTOR_SIZE);
}

static void test_set_warning_no_descriptor_returns_true(void **state) {
    (void) state;
    // GATING is NULL (reset cleared it) — must be permissive.
    assert_true(set_gating_warning());
    assert_int_equal(g_nvm_write_calls, 0);
}

static void test_set_warning_happy_path_bumps_counter(void **state) {
    (void) state;
    prime_tx_descriptor();
    assert_true(set_gating_warning());
    // 0 + 1 = 1, and 1 % 10 == 1 → screen shown, prelude wired up.
    assert_int_equal(g_captured_counter, 1);
    assert_non_null(warning.prelude);
}

static void test_set_warning_type_mismatch_returns_false(void **state) {
    (void) state;
    prime_tx_descriptor();
    appState = APP_STATE_SIGNING_EIP712;  // descriptor.type = TX
    assert_false(set_gating_warning());
    assert_int_equal(g_nvm_write_calls, 0);
}

static void test_set_warning_chain_id_mismatch_returns_false(void **state) {
    (void) state;
    prime_tx_descriptor();
    g_tx_chain_id = 137;  // descriptor signed for chain 1
    assert_false(set_gating_warning());
    assert_int_equal(g_nvm_write_calls, 0);
}

static void test_set_warning_address_mismatch_returns_false(void **state) {
    (void) state;
    prime_tx_descriptor();
    memset(tmpContent.txContent.destination, 0x77, ADDRESS_LENGTH);
    assert_false(set_gating_warning());
    assert_int_equal(g_nvm_write_calls, 0);
}

static void test_set_warning_selector_mismatch_returns_false(void **state) {
    (void) state;
    prime_tx_descriptor();
    memset(txContext.selector_bytes, 0x99, SELECTOR_SIZE);
    assert_false(set_gating_warning());
    assert_int_equal(g_nvm_write_calls, 0);
}

static void test_set_warning_counter_skips_non_modulo(void **state) {
    (void) state;
    prime_tx_descriptor();
    // Pretend we already showed the prelude once (counter=1) — next call
    // bumps to 2, which is not 1 mod 10, so warning.prelude must NOT be
    // rewritten but the call must still succeed.
    g_n_storage_writable.gating_counter = 1;
    warning.prelude = NULL;
    assert_true(set_gating_warning());
    assert_int_equal(g_captured_counter, 2);
    assert_null(warning.prelude);
}

static void test_set_warning_counter_wrap_reanchors_to_one(void **state) {
    (void) state;
    prime_tx_descriptor();
    // Counter at 0xFF wraps to 0; the source must re-anchor to 1 so
    // the cadence stays aligned across the wrap.
    g_n_storage_writable.gating_counter = 0xFF;
    warning.prelude = NULL;
    assert_true(set_gating_warning());
    assert_int_equal(g_captured_counter, 1);
    assert_non_null(warning.prelude);
}

static void test_set_warning_proxy_implementation_match(void **state) {
    (void) state;
    prime_tx_descriptor();
    // Pretend the active tx hits a proxy that resolves to the descriptor
    // address. The proxy lookup returns a contract address that matches
    // the tx destination — gate must accept.
    static const uint8_t implem[ADDRESS_LENGTH] = {0xAA};
    static const uint8_t proxy[ADDRESS_LENGTH] = {0xAA};
    g_implem_contract_ret = implem;
    g_proxy_contract_ret = proxy;
    // Implementation must equal GATING->address (0xAA pattern). Make the
    // returned proxy address equal tmpContent.txContent.destination so the
    // final memcmp passes.
    static uint8_t proxy_full[ADDRESS_LENGTH];
    memset(proxy_full, 0xAA, sizeof(proxy_full));
    static uint8_t implem_full[ADDRESS_LENGTH];
    memset(implem_full, 0xAA, sizeof(implem_full));
    g_implem_contract_ret = implem_full;
    g_proxy_contract_ret = proxy_full;
    memset(tmpContent.txContent.destination, 0xAA, ADDRESS_LENGTH);
    assert_true(set_gating_warning());
}

static void test_set_warning_proxy_implementation_mismatch(void **state) {
    (void) state;
    prime_tx_descriptor();
    // Proxy lookup says the implementation is some unrelated address ⇒
    // gate must reject regardless of the descriptor signature.
    static uint8_t implem_full[ADDRESS_LENGTH];
    memset(implem_full, 0x55, sizeof(implem_full));
    g_implem_contract_ret = implem_full;
    assert_false(set_gating_warning());
}

static void test_set_warning_typed_data_happy_path(void **state) {
    (void) state;
    appState = APP_STATE_SIGNING_EIP712;
    eip712_context = &g_eip712_storage;
    g_eip712_storage.chain_id = 1;
    memset(g_eip712_storage.contract_addr, 0xAA, ADDRESS_LENGTH);
    memset(g_eip712_storage.schema_hash, 0xCC, sizeof(g_eip712_storage.schema_hash));

    uint8_t tlv[500];
    s_opts opts = default_eip712_opts();
    size_t len = build_tlv(tlv, sizeof(tlv), opts);
    assert_true(send_descriptor(tlv, len));

    assert_true(set_gating_warning());
    assert_int_equal(g_captured_counter, 1);
}

static void test_set_warning_typed_data_schema_hash_mismatch(void **state) {
    (void) state;
    appState = APP_STATE_SIGNING_EIP712;
    eip712_context = &g_eip712_storage;
    g_eip712_storage.chain_id = 1;
    memset(g_eip712_storage.contract_addr, 0xAA, ADDRESS_LENGTH);
    memset(g_eip712_storage.schema_hash, 0x33, sizeof(g_eip712_storage.schema_hash));  // mismatch

    uint8_t tlv[500];
    s_opts opts = default_eip712_opts();
    size_t len = build_tlv(tlv, sizeof(tlv), opts);
    assert_true(send_descriptor(tlv, len));

    assert_false(set_gating_warning());
}

static void test_set_warning_typed_data_compute_schema_failure(void **state) {
    (void) state;
    appState = APP_STATE_SIGNING_EIP712;
    eip712_context = &g_eip712_storage;
    g_eip712_storage.chain_id = 1;
    memset(g_eip712_storage.contract_addr, 0xAA, ADDRESS_LENGTH);
    g_compute_schema_hash_ret = false;

    uint8_t tlv[500];
    s_opts opts = default_eip712_opts();
    size_t len = build_tlv(tlv, sizeof(tlv), opts);
    assert_true(send_descriptor(tlv, len));

    assert_false(set_gating_warning());
}

// =============================================================================
// Runner
// =============================================================================

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup(test_p2_unknown_rejected, reset),
        cmocka_unit_test_setup(test_happy_path_transaction, reset),
        cmocka_unit_test_setup(test_happy_path_typed_data, reset),
        cmocka_unit_test_setup(test_invalid_struct_type_rejected, reset),
        cmocka_unit_test_setup(test_invalid_struct_version_rejected, reset),
        cmocka_unit_test_setup(test_address_all_zeros_rejected, reset),
        cmocka_unit_test_setup(test_hash_selector_too_big_rejected, reset),
        cmocka_unit_test_setup(test_tx_type_out_of_range_rejected, reset),
        cmocka_unit_test_setup(test_signtx_without_chain_id_rejected, reset),
        cmocka_unit_test_setup(test_typed_data_without_hash_selector_rejected, reset),
        cmocka_unit_test_setup(test_missing_address_rejected, reset),
        cmocka_unit_test_setup(test_missing_intro_msg_rejected, reset),
        cmocka_unit_test_setup(test_missing_tiny_url_rejected, reset),
        cmocka_unit_test_setup(test_missing_signature_rejected, reset),
        cmocka_unit_test_setup(test_signature_check_failure_clears_gating, reset),
        cmocka_unit_test_setup(test_clear_gating_wipes_descriptor, reset),
        cmocka_unit_test_setup(test_set_warning_no_descriptor_returns_true, reset),
        cmocka_unit_test_setup(test_set_warning_happy_path_bumps_counter, reset),
        cmocka_unit_test_setup(test_set_warning_type_mismatch_returns_false, reset),
        cmocka_unit_test_setup(test_set_warning_chain_id_mismatch_returns_false, reset),
        cmocka_unit_test_setup(test_set_warning_address_mismatch_returns_false, reset),
        cmocka_unit_test_setup(test_set_warning_selector_mismatch_returns_false, reset),
        cmocka_unit_test_setup(test_set_warning_counter_skips_non_modulo, reset),
        cmocka_unit_test_setup(test_set_warning_counter_wrap_reanchors_to_one, reset),
        cmocka_unit_test_setup(test_set_warning_proxy_implementation_match, reset),
        cmocka_unit_test_setup(test_set_warning_proxy_implementation_mismatch, reset),
        cmocka_unit_test_setup(test_set_warning_typed_data_happy_path, reset),
        cmocka_unit_test_setup(test_set_warning_typed_data_schema_hash_mismatch, reset),
        cmocka_unit_test_setup(test_set_warning_typed_data_compute_schema_failure, reset),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
