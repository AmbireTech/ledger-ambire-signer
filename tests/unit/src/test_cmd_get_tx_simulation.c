/**
 * @file test_cmd_get_tx_simulation.c
 * @brief Unit tests for the backend-signed transaction-simulation
 *        descriptor at src/features/provide_tx_simulation/cmd_get_tx_simulation.c.
 *
 * The TX-simulation descriptor lets the backend warn the device's
 * user that the transaction they are about to sign is malicious /
 * suspicious / benign. The descriptor binds:
 *   - the transaction hash (the bytes the user is about to sign),
 *   - the from-address (must match the device's signing key),
 *   - the chain_id (for normal transactions),
 *   - the domain_hash (for EIP-712 typed-data flows),
 *   - the risk score + category + provider message + tiny URL.
 *
 * After verify_signature succeeds against
 * CERTIFICATE_PUBLIC_KEY_USAGE_TX_SIMU_SIGNER, the device must still
 * cross-check that:
 *   - the descriptor binds to the *same* transaction the user is
 *     reviewing (tx_hash + chain_id + from_address),
 *   - the descriptor type matches the active signing flow.
 *
 * A bug in either gate lets a malicious backend whisper a "BENIGN"
 * verdict for an attacker transaction the user is about to sign.
 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

#include "shared_context.h"
#include "cmd_get_tx_simulation.h"
#include "apdu_constants.h"
#include "tlv_apdu.h"
#include "nbgl_use_case.h"
#include "wraps.h"

// `warning` is referenced by set_tx_simulation_warning; the real symbol
// lives in libNbgl which we don't link here, so provide local storage.

// =============================================================================
// Globals
// =============================================================================

// N_storage_real aliased to a writable shadow — the test toggles
// tx_check_enable and tx_check_opt_in.

// =============================================================================
// Controllable stubs
// =============================================================================

// check_signature_with_pubkey / finalize_hash / hash_nbytes are
// wrapped in mocks/mock.c; state via g_sig_check_ret /
// g_finalize_hash_ret from wraps.h.

// os_pki_get_info wrap — returns 0 (success) and an empty trusted
// name by default; tests can flip it to fail.
static int g_os_pki_ret = 0;
static const char *g_os_pki_name = "";
uint32_t __wrap_os_pki_get_info(uint8_t *key_usage,
                                uint8_t *trusted_name,
                                size_t *trusted_name_len,
                                void *public_key) {
    (void) key_usage;
    (void) public_key;
    size_t n = strlen(g_os_pki_name);
    if (n > 0 && trusted_name != NULL) {
        memcpy(trusted_name, g_os_pki_name, n);
    }
    if (trusted_name_len != NULL) {
        *trusted_name_len = n;
    }
    return g_os_pki_ret;
}

// io_seproxyhal_send_status — count invocations.
static int g_send_status_calls = 0;
uint16_t io_seproxyhal_send_status(uint16_t sw, uint32_t tx, bool reset, bool idle) {
    (void) sw;
    (void) tx;
    (void) reset;
    (void) idle;
    g_send_status_calls++;
    return 0;
}

// UI hook — count invocations.
static int g_ui_opt_in_calls = 0;
static bool g_ui_opt_in_response_expected = false;
void ui_tx_simulation_opt_in(bool response_expected) {
    g_ui_opt_in_calls++;
    g_ui_opt_in_response_expected = response_expected;
}

// get_public_key wrap — write a controllable address into the buffer.
static uint8_t g_pubkey_addr[ADDRESS_LENGTH];
uint16_t __wrap_get_public_key(uint8_t *out, uint8_t out_size) {
    if (out_size < ADDRESS_LENGTH) return SWO_INCORRECT_DATA;
    memcpy(out, g_pubkey_addr, ADDRESS_LENGTH);
    return SWO_SUCCESS;
}

// get_tx_chain_id is wrapped in mocks/mock.c; state via g_tx_chain_id
// from wraps.h.

// =============================================================================
// TLV builder for TX_SIMULATION descriptor
// =============================================================================
//
// Tags ≥ 0x80 need DER long-form (0x81 prefix).
//   0x01 STRUCTURE_TYPE        = 0x09
//   0x02 STRUCTURE_VERSION     = 0x01
//   0x22 ADDRESS               = 20 bytes
//   0x23 CHAIN_ID              = 1+ bytes
//   0x27 TX_HASH               = 32 bytes
//   0x28 DOMAIN_HASH           = 32 bytes (V2 TYPED_DATA)
//   0x80 NORMALIZED_RISK       = 1 byte (long-form)
//   0x81 NORMALIZED_CATEGORY   = 1 byte (long-form)
//   0x82 PROVIDER_MSG          = string (long-form)
//   0x83 TINY_URL              = string (long-form)
//   0x84 SIMU_TYPE             = 1 byte (long-form)
//   0x15 DER_SIGNATURE         = N bytes

typedef struct {
    uint8_t struct_type;
    uint8_t struct_version;
    uint8_t chain_id;
    bool include_chain_id;
    bool include_domain_hash;
    bool tx_hash_zero;
    bool domain_hash_zero;
    bool address_zero;
    uint8_t risk;
    uint8_t category;
    uint8_t type;
    bool omit_tx_hash;
    bool include_additional_data;
    uint8_t sig_len;
} s_opts;

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
    w(out, &off, 0x22);
    w(out, &off, ADDRESS_LENGTH);
    if (opts.address_zero) {
        memset(out + off, 0, ADDRESS_LENGTH);
    } else {
        memset(out + off, 0xAA, ADDRESS_LENGTH);
    }
    off += ADDRESS_LENGTH;
    // CHAIN_ID (optional)
    if (opts.include_chain_id) {
        w(out, &off, 0x23);
        w(out, &off, 0x01);
        w(out, &off, opts.chain_id);
    }
    // TX_HASH
    if (!opts.omit_tx_hash) {
        w(out, &off, 0x27);
        w(out, &off, 32);
        if (opts.tx_hash_zero) {
            memset(out + off, 0, 32);
        } else {
            memset(out + off, 0xBB, 32);
        }
        off += 32;
    }
    // DOMAIN_HASH (optional)
    if (opts.include_domain_hash) {
        w(out, &off, 0x28);
        w(out, &off, 32);
        if (opts.domain_hash_zero) {
            memset(out + off, 0, 32);
        } else {
            memset(out + off, 0xCC, 32);
        }
        off += 32;
    }
    // NORMALIZED_RISK (tag 0x80, DER long-form)
    w(out, &off, 0x81);
    w(out, &off, 0x80);
    w(out, &off, 0x01);
    w(out, &off, opts.risk);
    // NORMALIZED_CATEGORY (tag 0x81)
    w(out, &off, 0x81);
    w(out, &off, 0x81);
    w(out, &off, 0x01);
    w(out, &off, opts.category);
    // TINY_URL (tag 0x83)
    w(out, &off, 0x81);
    w(out, &off, 0x83);
    w(out, &off, 0x04);
    memcpy(out + off, "http", 4);
    off += 4;
    // SIMU_TYPE (tag 0x84)
    w(out, &off, 0x81);
    w(out, &off, 0x84);
    w(out, &off, 0x01);
    w(out, &off, opts.type);
    if (opts.include_additional_data) {
        // ADDITIONAL_DATA (tag 0x85) — must be rejected
        w(out, &off, 0x81);
        w(out, &off, 0x85);
        w(out, &off, 0x00);
    }
    // SIGNATURE
    w(out, &off, 0x15);
    w(out, &off, opts.sig_len);
    memset(out + off, 0x42, opts.sig_len);
    off += opts.sig_len;
    assert_true(off <= out_size);
    return off;
}

static bool send_first(const uint8_t *tlv, size_t len) {
    // Prepend the BE16 length prefix that tlv_apdu expects on the
    // first chunk.
    uint8_t framed[600];
    framed[0] = (uint8_t) (len >> 8);
    framed[1] = (uint8_t) (len & 0xFF);
    assert_true(len + 2 <= sizeof(framed));
    memcpy(framed + 2, tlv, len);
    uint16_t sw =
        handle_tx_simulation(/*p1=*/0x00, /*p2=*/P1_FIRST_CHUNK, framed, (uint8_t) (len + 2));
    return sw == SWO_SUCCESS;
}

// =============================================================================
// Fixture
// =============================================================================

static int reset(void **state) {
    (void) state;
    clear_tx_simulation();
    memset(&g_n_storage_writable, 0, sizeof(g_n_storage_writable));
    g_n_storage_writable.tx_check_enable = true;
    g_n_storage_writable.tx_check_opt_in = true;
    g_sig_check_ret = true;
    g_finalize_hash_ret = true;
    g_os_pki_ret = 0;
    g_os_pki_name = "";
    g_send_status_calls = 0;
    g_ui_opt_in_calls = 0;
    g_ui_opt_in_response_expected = false;
    g_tx_chain_id = 1;
    memset(g_pubkey_addr, 0xAA, ADDRESS_LENGTH);
    appState = APP_STATE_SIGNING_TX;
    // tlv_apdu carries internal state across calls — clear it.
    tlv_from_apdu(false, 0, NULL, NULL);
    return 0;
}

// =============================================================================
// Tests — entry-point dispatcher
// =============================================================================

static void test_p1_unknown_rejected(void **state) {
    (void) state;
    uint8_t data[1] = {0};
    uint16_t sw = handle_tx_simulation(/*p1=*/0xFF, /*p2=*/0, data, 1);
    assert_int_equal(sw, SWO_WRONG_P1_P2);
}

static void test_p1_data_when_checks_disabled_returns_not_supported(void **state) {
    (void) state;
    g_n_storage_writable.tx_check_enable = false;
    uint8_t data[1] = {0};
    uint16_t sw = handle_tx_simulation(/*p1=*/0x00, /*p2=*/P1_FIRST_CHUNK, data, 1);
    assert_int_equal(sw, SWO_COMMAND_CODE_NOT_SUPPORTED);
}

static void test_p1_opt_in_already_optin_short_circuits(void **state) {
    (void) state;
    g_n_storage_writable.tx_check_opt_in = true;
    g_n_storage_writable.tx_check_enable = true;
    uint8_t data[1] = {0};
    uint16_t sw = handle_tx_simulation(/*p1=*/0x01, /*p2=*/0, data, 1);
    // Per the source, returns SWO_NO_RESPONSE after the io_seproxyhal_send_status side-effect.
    assert_int_equal(sw, SWO_NO_RESPONSE);
    assert_int_equal(g_send_status_calls, 1);
    assert_int_equal(g_ui_opt_in_calls, 0);
}

static void test_p1_opt_in_not_yet_optin_calls_ui(void **state) {
    (void) state;
    g_n_storage_writable.tx_check_opt_in = false;
    uint8_t data[1] = {0};
    uint16_t sw = handle_tx_simulation(/*p1=*/0x01, /*p2=*/0, data, 1);
    assert_int_equal(sw, SWO_NO_RESPONSE);
    assert_int_equal(g_ui_opt_in_calls, 1);
    assert_true(g_ui_opt_in_response_expected);
}

// =============================================================================
// TLV happy path + validation gates
// =============================================================================

static void test_happy_path_transaction_registers(void **state) {
    (void) state;
    g_os_pki_name = "Provider";
    uint8_t tlv[500];
    s_opts opts = {.struct_type = 0x09,
                   .struct_version = 0x01,
                   .chain_id = 1,
                   .include_chain_id = true,
                   .risk = TX_SIMULATION_RISK_BENIGN,
                   .category = TX_SIMULATION_CATEGORY_OTHERS,
                   .type = TX_SIMULATION_TYPE_TRANSACTION,
                   .sig_len = 16};
    size_t len = build_tlv(tlv, sizeof(tlv), opts);
    assert_true(send_first(tlv, len));
    assert_int_equal(TX_SIMULATION.chain_id, 1);
    assert_int_equal(TX_SIMULATION.risk, TX_SIMULATION_RISK_BENIGN);
    assert_int_equal(TX_SIMULATION.type, TX_SIMULATION_TYPE_TRANSACTION);
    // Partner copied from certificate trusted name.
    assert_memory_equal(TX_SIMULATION.partner, "Provider", strlen("Provider"));
}

static void test_happy_path_typed_data_registers(void **state) {
    (void) state;
    uint8_t tlv[500];
    s_opts opts = {.struct_type = 0x09,
                   .struct_version = 0x01,
                   .include_domain_hash = true,
                   .risk = TX_SIMULATION_RISK_WARNING,
                   .category = TX_SIMULATION_CATEGORY_DAPP,
                   .type = TX_SIMULATION_TYPE_TYPED_DATA,
                   .sig_len = 16};
    size_t len = build_tlv(tlv, sizeof(tlv), opts);
    assert_true(send_first(tlv, len));
    assert_int_equal(TX_SIMULATION.type, TX_SIMULATION_TYPE_TYPED_DATA);
}

static void test_invalid_struct_type_rejected(void **state) {
    (void) state;
    uint8_t tlv[500];
    s_opts opts = {.struct_type = 0xFF,
                   .struct_version = 0x01,
                   .chain_id = 1,
                   .include_chain_id = true,
                   .type = TX_SIMULATION_TYPE_TRANSACTION,
                   .sig_len = 16};
    size_t len = build_tlv(tlv, sizeof(tlv), opts);
    assert_false(send_first(tlv, len));
}

static void test_invalid_struct_version_rejected(void **state) {
    (void) state;
    uint8_t tlv[500];
    s_opts opts = {.struct_type = 0x09,
                   .struct_version = 0x05,
                   .chain_id = 1,
                   .include_chain_id = true,
                   .type = TX_SIMULATION_TYPE_TRANSACTION,
                   .sig_len = 16};
    size_t len = build_tlv(tlv, sizeof(tlv), opts);
    assert_false(send_first(tlv, len));
}

static void test_tx_hash_all_zeros_rejected(void **state) {
    (void) state;
    uint8_t tlv[500];
    s_opts opts = {.struct_type = 0x09,
                   .struct_version = 0x01,
                   .chain_id = 1,
                   .include_chain_id = true,
                   .tx_hash_zero = true,
                   .type = TX_SIMULATION_TYPE_TRANSACTION,
                   .sig_len = 16};
    size_t len = build_tlv(tlv, sizeof(tlv), opts);
    assert_false(send_first(tlv, len));
}

static void test_address_all_zeros_rejected(void **state) {
    (void) state;
    uint8_t tlv[500];
    s_opts opts = {.struct_type = 0x09,
                   .struct_version = 0x01,
                   .chain_id = 1,
                   .include_chain_id = true,
                   .address_zero = true,
                   .type = TX_SIMULATION_TYPE_TRANSACTION,
                   .sig_len = 16};
    size_t len = build_tlv(tlv, sizeof(tlv), opts);
    assert_false(send_first(tlv, len));
}

static void test_risk_out_of_range_rejected(void **state) {
    (void) state;
    uint8_t tlv[500];
    s_opts opts = {.struct_type = 0x09,
                   .struct_version = 0x01,
                   .chain_id = 1,
                   .include_chain_id = true,
                   .risk = TX_SIMULATION_RISK_UNKNOWN,  // internal — not allowed as input
                   .type = TX_SIMULATION_TYPE_TRANSACTION,
                   .sig_len = 16};
    size_t len = build_tlv(tlv, sizeof(tlv), opts);
    assert_false(send_first(tlv, len));
}

static void test_category_out_of_range_rejected(void **state) {
    (void) state;
    uint8_t tlv[500];
    s_opts opts = {.struct_type = 0x09,
                   .struct_version = 0x01,
                   .chain_id = 1,
                   .include_chain_id = true,
                   .category = TX_SIMULATION_CATEGORY_COUNT,
                   .type = TX_SIMULATION_TYPE_TRANSACTION,
                   .sig_len = 16};
    size_t len = build_tlv(tlv, sizeof(tlv), opts);
    assert_false(send_first(tlv, len));
}

static void test_type_out_of_range_rejected(void **state) {
    (void) state;
    uint8_t tlv[500];
    s_opts opts = {.struct_type = 0x09,
                   .struct_version = 0x01,
                   .chain_id = 1,
                   .include_chain_id = true,
                   .type = TX_SIMULATION_TYPE_COUNT,
                   .sig_len = 16};
    size_t len = build_tlv(tlv, sizeof(tlv), opts);
    assert_false(send_first(tlv, len));
}

static void test_transaction_without_chain_id_rejected(void **state) {
    (void) state;
    uint8_t tlv[500];
    s_opts opts = {.struct_type = 0x09,
                   .struct_version = 0x01,
                   .include_chain_id = false,  // missing
                   .type = TX_SIMULATION_TYPE_TRANSACTION,
                   .sig_len = 16};
    size_t len = build_tlv(tlv, sizeof(tlv), opts);
    assert_false(send_first(tlv, len));
}

static void test_typed_data_without_domain_hash_rejected(void **state) {
    (void) state;
    uint8_t tlv[500];
    s_opts opts = {.struct_type = 0x09,
                   .struct_version = 0x01,
                   .include_domain_hash = false,
                   .type = TX_SIMULATION_TYPE_TYPED_DATA,
                   .sig_len = 16};
    size_t len = build_tlv(tlv, sizeof(tlv), opts);
    assert_false(send_first(tlv, len));
}

static void test_additional_data_tag_rejected(void **state) {
    (void) state;
    uint8_t tlv[500];
    s_opts opts = {.struct_type = 0x09,
                   .struct_version = 0x01,
                   .chain_id = 1,
                   .include_chain_id = true,
                   .type = TX_SIMULATION_TYPE_TRANSACTION,
                   .include_additional_data = true,  // not allowed
                   .sig_len = 16};
    size_t len = build_tlv(tlv, sizeof(tlv), opts);
    assert_false(send_first(tlv, len));
}

static void test_signature_check_failure_rejects(void **state) {
    (void) state;
    g_sig_check_ret = false;
    uint8_t tlv[500];
    s_opts opts = {.struct_type = 0x09,
                   .struct_version = 0x01,
                   .chain_id = 1,
                   .include_chain_id = true,
                   .type = TX_SIMULATION_TYPE_TRANSACTION,
                   .sig_len = 16};
    size_t len = build_tlv(tlv, sizeof(tlv), opts);
    assert_false(send_first(tlv, len));
    // The descriptor must have been wiped.
    assert_int_equal(TX_SIMULATION.chain_id, 0);
}

static void test_os_pki_get_info_failure_rejects(void **state) {
    (void) state;
    g_os_pki_ret = 1;  // non-zero = failure
    uint8_t tlv[500];
    s_opts opts = {.struct_type = 0x09,
                   .struct_version = 0x01,
                   .chain_id = 1,
                   .include_chain_id = true,
                   .type = TX_SIMULATION_TYPE_TRANSACTION,
                   .sig_len = 16};
    size_t len = build_tlv(tlv, sizeof(tlv), opts);
    assert_false(send_first(tlv, len));
}

// =============================================================================
// Getters / cleanup
// =============================================================================

static void test_get_risk_str_for_each_value(void **state) {
    (void) state;
    TX_SIMULATION.risk = TX_SIMULATION_RISK_BENIGN;
    assert_string_equal(get_tx_simulation_risk_str(), "BENIGN");
    TX_SIMULATION.risk = TX_SIMULATION_RISK_WARNING;
    assert_string_equal(get_tx_simulation_risk_str(), "RISK (WARNING)");
    TX_SIMULATION.risk = TX_SIMULATION_RISK_MALICIOUS;
    assert_string_equal(get_tx_simulation_risk_str(), "THREAT (MALICIOUS)");
    TX_SIMULATION.risk = TX_SIMULATION_RISK_UNKNOWN;
    assert_string_equal(get_tx_simulation_risk_str(), "UNKNOWN (Transaction Check Issue)");
    TX_SIMULATION.risk = (tx_simulation_score_t) 0x7F;  // out of range
    assert_string_equal(get_tx_simulation_risk_str(), "INVALID");
}

static void test_get_category_str_warning_branches(void **state) {
    (void) state;
    TX_SIMULATION.risk = TX_SIMULATION_RISK_WARNING;
    TX_SIMULATION.category = TX_SIMULATION_CATEGORY_ADDRESS;
    assert_string_equal(get_tx_simulation_category_str(),
                        "This transaction involves a suspicious address. "
                        "It might not be safe to continue.");
    TX_SIMULATION.category = TX_SIMULATION_CATEGORY_DAPP;
    assert_string_equal(get_tx_simulation_category_str(),
                        "This transaction involves a suspicious dApp. "
                        "It might not be safe to continue.");
    TX_SIMULATION.category = TX_SIMULATION_CATEGORY_LOSING_OPERATION;
    assert_string_equal(get_tx_simulation_category_str(),
                        "This transaction could end in a loss. "
                        "Check transaction details carefully before signing.");
}

static void test_get_category_str_malicious_branches(void **state) {
    (void) state;
    TX_SIMULATION.risk = TX_SIMULATION_RISK_MALICIOUS;
    TX_SIMULATION.category = TX_SIMULATION_CATEGORY_ADDRESS;
    assert_string_equal(get_tx_simulation_category_str(),
                        "This transaction involves a malicious address. "
                        "Your assets will most likely be stolen.");
    TX_SIMULATION.category = TX_SIMULATION_CATEGORY_DAPP;
    assert_string_equal(get_tx_simulation_category_str(),
                        "This dApp is linked to a scammer. "
                        "Your assets will most likely be stolen.");
}

static void test_clear_tx_simulation_zeroes_struct(void **state) {
    (void) state;
    TX_SIMULATION.chain_id = 42;
    TX_SIMULATION.risk = TX_SIMULATION_RISK_WARNING;
    clear_tx_simulation();
    assert_int_equal(TX_SIMULATION.chain_id, 0);
    assert_int_equal(TX_SIMULATION.risk, TX_SIMULATION_RISK_BENIGN);
}

// =============================================================================
// set_tx_simulation_warning — Web3 Checks UI gate
// =============================================================================
//
// The descriptor parser accepts a backend-signed risk score, but the
// device must still cross-check that the descriptor describes the *same*
// transaction the user is reviewing (chain_id / tx_hash / from_address).
// If any cross-check fails, the warning must be downgraded to UNKNOWN so
// the user sees the W3C_ISSUE banner instead of trusting the backend.

// Ingest a happy-path descriptor and prime the per-tx state so that
// check_tx_simulation_params would succeed without further tweaks.
static void prime_for_warning(tx_simulation_score_t risk) {
    g_os_pki_name = "Provider";
    uint8_t tlv[500];
    s_opts opts = {.struct_type = 0x09,
                   .struct_version = 0x01,
                   .chain_id = 1,
                   .include_chain_id = true,
                   .risk = risk,
                   .category = TX_SIMULATION_CATEGORY_OTHERS,
                   .type = TX_SIMULATION_TYPE_TRANSACTION,
                   .sig_len = 16};
    size_t len = build_tlv(tlv, sizeof(tlv), opts);
    assert_true(send_first(tlv, len));
    // tx_hash in the descriptor is 0xBB-filled (see build_tlv); mirror
    // the same bytes into the active signing context.
    memset(tmpCtx.transactionContext.hash, 0xBB, INT256_LENGTH);
    appState = APP_STATE_SIGNING_TX;
    g_tx_chain_id = 1;
    memset(g_pubkey_addr, 0xAA, ADDRESS_LENGTH);
}

static void test_set_warning_disabled_returns_early(void **state) {
    (void) state;
    prime_for_warning(TX_SIMULATION_RISK_MALICIOUS);
    warning.predefinedSet = 0;
    g_n_storage_writable.tx_check_enable = false;
    set_tx_simulation_warning();
    // Nothing must have been written when checks are disabled.
    assert_int_equal(warning.predefinedSet, 0);
    assert_null(warning.reportProvider);
}

static void test_set_warning_risk_benign_sets_no_threat_bit(void **state) {
    (void) state;
    prime_for_warning(TX_SIMULATION_RISK_BENIGN);
    warning.predefinedSet = 0;
    set_tx_simulation_warning();
    assert_int_equal(warning.predefinedSet, 1U << W3C_NO_THREAT_WARN);
}

static void test_set_warning_risk_warning_sets_risk_bit(void **state) {
    (void) state;
    prime_for_warning(TX_SIMULATION_RISK_WARNING);
    warning.predefinedSet = 0;
    set_tx_simulation_warning();
    assert_int_equal(warning.predefinedSet, 1U << W3C_RISK_DETECTED_WARN);
}

static void test_set_warning_risk_malicious_sets_threat_bit(void **state) {
    (void) state;
    prime_for_warning(TX_SIMULATION_RISK_MALICIOUS);
    warning.predefinedSet = 0;
    set_tx_simulation_warning();
    assert_int_equal(warning.predefinedSet, 1U << W3C_THREAT_DETECTED_WARN);
}

static void test_set_warning_address_mismatch_forces_unknown(void **state) {
    (void) state;
    prime_for_warning(TX_SIMULATION_RISK_BENIGN);
    // Backend signed a BENIGN verdict, but the active signer address
    // differs from the one the verdict binds to — must downgrade to
    // UNKNOWN so the user sees the W3C_ISSUE banner.
    memset(g_pubkey_addr, 0x77, ADDRESS_LENGTH);
    warning.predefinedSet = 0;
    set_tx_simulation_warning();
    assert_int_equal(warning.predefinedSet, 1U << W3C_ISSUE_WARN);
    assert_int_equal(TX_SIMULATION.risk, TX_SIMULATION_RISK_UNKNOWN);
}

static void test_set_warning_tx_hash_mismatch_forces_unknown(void **state) {
    (void) state;
    prime_for_warning(TX_SIMULATION_RISK_BENIGN);
    memset(tmpCtx.transactionContext.hash, 0x99, INT256_LENGTH);
    warning.predefinedSet = 0;
    set_tx_simulation_warning();
    assert_int_equal(warning.predefinedSet, 1U << W3C_ISSUE_WARN);
}

static void test_set_warning_chain_id_mismatch_forces_unknown(void **state) {
    (void) state;
    prime_for_warning(TX_SIMULATION_RISK_BENIGN);
    g_tx_chain_id = 137;  // descriptor signed for chain 1
    warning.predefinedSet = 0;
    set_tx_simulation_warning();
    assert_int_equal(warning.predefinedSet, 1U << W3C_ISSUE_WARN);
}

static void test_set_warning_wrong_app_state_forces_unknown(void **state) {
    (void) state;
    prime_for_warning(TX_SIMULATION_RISK_BENIGN);
    // Descriptor.type=TRANSACTION but app is in EIP712 flow — invalid.
    appState = APP_STATE_SIGNING_EIP712;
    warning.predefinedSet = 0;
    set_tx_simulation_warning();
    assert_int_equal(warning.predefinedSet, 1U << W3C_ISSUE_WARN);
}

// =============================================================================
// Runner
// =============================================================================

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup(test_p1_unknown_rejected, reset),
        cmocka_unit_test_setup(test_p1_data_when_checks_disabled_returns_not_supported, reset),
        cmocka_unit_test_setup(test_p1_opt_in_already_optin_short_circuits, reset),
        cmocka_unit_test_setup(test_p1_opt_in_not_yet_optin_calls_ui, reset),
        cmocka_unit_test_setup(test_happy_path_transaction_registers, reset),
        cmocka_unit_test_setup(test_happy_path_typed_data_registers, reset),
        cmocka_unit_test_setup(test_invalid_struct_type_rejected, reset),
        cmocka_unit_test_setup(test_invalid_struct_version_rejected, reset),
        cmocka_unit_test_setup(test_tx_hash_all_zeros_rejected, reset),
        cmocka_unit_test_setup(test_address_all_zeros_rejected, reset),
        cmocka_unit_test_setup(test_risk_out_of_range_rejected, reset),
        cmocka_unit_test_setup(test_category_out_of_range_rejected, reset),
        cmocka_unit_test_setup(test_type_out_of_range_rejected, reset),
        cmocka_unit_test_setup(test_transaction_without_chain_id_rejected, reset),
        cmocka_unit_test_setup(test_typed_data_without_domain_hash_rejected, reset),
        cmocka_unit_test_setup(test_additional_data_tag_rejected, reset),
        cmocka_unit_test_setup(test_signature_check_failure_rejects, reset),
        cmocka_unit_test_setup(test_os_pki_get_info_failure_rejects, reset),
        cmocka_unit_test_setup(test_get_risk_str_for_each_value, reset),
        cmocka_unit_test_setup(test_get_category_str_warning_branches, reset),
        cmocka_unit_test_setup(test_get_category_str_malicious_branches, reset),
        cmocka_unit_test_setup(test_clear_tx_simulation_zeroes_struct, reset),
        cmocka_unit_test_setup(test_set_warning_disabled_returns_early, reset),
        cmocka_unit_test_setup(test_set_warning_risk_benign_sets_no_threat_bit, reset),
        cmocka_unit_test_setup(test_set_warning_risk_warning_sets_risk_bit, reset),
        cmocka_unit_test_setup(test_set_warning_risk_malicious_sets_threat_bit, reset),
        cmocka_unit_test_setup(test_set_warning_address_mismatch_forces_unknown, reset),
        cmocka_unit_test_setup(test_set_warning_tx_hash_mismatch_forces_unknown, reset),
        cmocka_unit_test_setup(test_set_warning_chain_id_mismatch_forces_unknown, reset),
        cmocka_unit_test_setup(test_set_warning_wrong_app_state_forces_unknown, reset),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
