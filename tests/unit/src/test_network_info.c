/**
 * @file test_network_info.c
 * @brief Unit tests for the dynamic-network backend descriptor at
 *        src/features/provide_network_info/network_info.c.
 *
 * A network_info descriptor lets the backend extend the device's
 * (chain_id -> name + ticker + icon-hash) registry at runtime. The
 * device renders dynamically-added networks the same way it does the
 * hardcoded ones, so a bug in the parser/signature gate lets an
 * attacker register a fake network entry (e.g. "Ethereum" / "ETH" for
 * an attacker chain_id) and trick the user into approving cross-chain
 * transfers blind.
 *
 * The signature gate uses CERTIFICATE_PUBLIC_KEY_USAGE_NETWORK; the
 * descriptor binds the icon by hash so a separate icon-bitmap APDU
 * can be matched against the registered hash later.
 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

#include "shared_context.h"
#include "network_info.h"

// =============================================================================
// Globals
// =============================================================================

strings_t strings;
static chain_config_t g_chainConfig = {.ticker = "ETH", .chain_id = 1, .coin_type = 60};
const chain_config_t *g_chain_config = &g_chainConfig;
const char g_unknown_ticker[] = "???";
txContext_t txContext;
tmpContent_t tmpContent;

// =============================================================================
// Controllable stubs
// =============================================================================

static bool g_sig_check_ret = true;
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
    return g_sig_check_ret;
}

static bool g_finalize_hash_ret = true;
bool __wrap_finalize_hash(cx_hash_t *hash_ctx, uint8_t *out, size_t out_len) {
    (void) hash_ctx;
    memset(out, 0, out_len);
    return g_finalize_hash_ret;
}

void __wrap_hash_nbytes(const uint8_t *bytes, size_t n, cx_hash_t *hash_ctx) {
    (void) bytes;
    (void) n;
    (void) hash_ctx;
}

uint32_t cx_sha256_init_no_throw(cx_sha256_t *hash) {
    (void) hash;
    return 0;
}

bool is_zeroes_buffer(const void *buf, size_t n) {
    const uint8_t *p = (const uint8_t *) buf;
    for (size_t i = 0; i < n; ++i) {
        if (p[i] != 0) return false;
    }
    return true;
}

// find_dynamic_network_by_chain_id lives in src/network.c; wrap so we
// can drive the "already-registered" branch in append_network_info.
static network_info_t *g_existing_network_ret = NULL;
network_info_t *__wrap_find_dynamic_network_by_chain_id(uint64_t chain_id) {
    (void) chain_id;
    return g_existing_network_ret;
}

// clear_icon lives in network_icon.c — stub it out (the icon side is
// out of scope for this slice).
void clear_icon(void) {
}

// =============================================================================
// TLV payload builder
// =============================================================================
//
// Layout (tags ≥ 0x80 need DER long-form 0x81-prefix):
//   0x01 STRUCTURE_TYPE    = 0x08 (TYPE_DYNAMIC_NETWORK)
//   0x02 STRUCTURE_VERSION = 0x01
//   0x51 BLOCKCHAIN_FAMILY = 0x01 (ETHEREUM) — long form
//   0x23 CHAIN_ID          = 1 byte
//   0x52 NETWORK_NAME      = string — long form (tag = 0x52 < 0x80 → short form actually)
//   0x24 TICKER            = string
//   0x53 NETWORK_ICON_HASH = 32 bytes — long form
//   0x15 DER_SIGNATURE     = N bytes
//
// All tags < 0x80 use short form (single byte for the tag).

typedef struct {
    uint8_t struct_type;
    uint8_t struct_version;
    uint8_t blockchain_family;
    uint8_t chain_id;
    const char *name;
    const char *ticker;
    bool include_icon_hash;
    bool icon_hash_all_zeros;
    uint8_t sig_len;
    bool omit_name;
    bool omit_signature;
} s_opts;

static void w_byte(uint8_t *out, size_t *off, uint8_t b) {
    out[(*off)++] = b;
}

static size_t build_tlv(uint8_t *out, size_t out_size, s_opts opts) {
    size_t off = 0;
    w_byte(out, &off, 0x01);
    w_byte(out, &off, 0x01);
    w_byte(out, &off, opts.struct_type);
    w_byte(out, &off, 0x02);
    w_byte(out, &off, 0x01);
    w_byte(out, &off, opts.struct_version);
    // 0x51 BLOCKCHAIN_FAMILY (tag < 0x80 → short form)
    w_byte(out, &off, 0x51);
    w_byte(out, &off, 0x01);
    w_byte(out, &off, opts.blockchain_family);
    // 0x23 CHAIN_ID
    w_byte(out, &off, 0x23);
    w_byte(out, &off, 0x01);
    w_byte(out, &off, opts.chain_id);
    if (!opts.omit_name) {
        // 0x52 NETWORK_NAME
        size_t name_len = strlen(opts.name);
        assert_true(name_len <= 127);
        w_byte(out, &off, 0x52);
        w_byte(out, &off, (uint8_t) name_len);
        memcpy(out + off, opts.name, name_len);
        off += name_len;
    }
    // 0x24 TICKER
    size_t ticker_len = strlen(opts.ticker);
    w_byte(out, &off, 0x24);
    w_byte(out, &off, (uint8_t) ticker_len);
    memcpy(out + off, opts.ticker, ticker_len);
    off += ticker_len;
    if (opts.include_icon_hash) {
        // 0x53 NETWORK_ICON_HASH = 32 bytes
        w_byte(out, &off, 0x53);
        w_byte(out, &off, 32);
        if (opts.icon_hash_all_zeros) {
            memset(out + off, 0, 32);
        } else {
            memset(out + off, 0xAB, 32);
        }
        off += 32;
    }
    if (!opts.omit_signature) {
        // 0x15 DER_SIGNATURE
        w_byte(out, &off, 0x15);
        w_byte(out, &off, opts.sig_len);
        memset(out + off, 0x42, opts.sig_len);
        off += opts.sig_len;
    }
    assert_true(off <= out_size);
    return off;
}

static bool run(const uint8_t *tlv, size_t len) {
    buffer_t buf = {.ptr = (uint8_t *) tlv, .size = len, .offset = 0};
    return handle_network_tlv_payload(&buf);
}

// =============================================================================
// Fixture
// =============================================================================

static int reset(void **state) {
    (void) state;
    network_info_cleanup(NULL);
    g_sig_check_ret = true;
    g_finalize_hash_ret = true;
    g_existing_network_ret = NULL;
    return 0;
}

// =============================================================================
// Tests
// =============================================================================

static void test_happy_path_registers_network(void **state) {
    (void) state;
    uint8_t tlv[300];
    s_opts opts = {.struct_type = 0x08,
                   .struct_version = 0x01,
                   .blockchain_family = 0x01,
                   .chain_id = 137,
                   .name = "Polygon",
                   .ticker = "MATIC",
                   .include_icon_hash = true,
                   .sig_len = 16};
    size_t len = build_tlv(tlv, sizeof(tlv), opts);
    assert_true(run(tlv, len));
    assert_non_null(g_last_added_network);
    assert_string_equal(g_last_added_network->name, "Polygon");
    assert_string_equal(g_last_added_network->ticker, "MATIC");
    assert_int_equal(g_last_added_network->chain_id, 137);
    // Icon hash was non-zero → expected-hash buffer was allocated.
    assert_non_null(g_network_icon_hash);
}

static void test_happy_path_without_icon_hash_registers_network(void **state) {
    (void) state;
    uint8_t tlv[300];
    s_opts opts = {.struct_type = 0x08,
                   .struct_version = 0x01,
                   .blockchain_family = 0x01,
                   .chain_id = 137,
                   .name = "Polygon",
                   .ticker = "MATIC",
                   .include_icon_hash = false,
                   .sig_len = 16};
    size_t len = build_tlv(tlv, sizeof(tlv), opts);
    assert_true(run(tlv, len));
    assert_non_null(g_last_added_network);
}

static void test_invalid_struct_type_rejected(void **state) {
    (void) state;
    uint8_t tlv[300];
    s_opts opts = {.struct_type = 0xFF,  // not TYPE_DYNAMIC_NETWORK
                   .struct_version = 0x01,
                   .blockchain_family = 0x01,
                   .chain_id = 137,
                   .name = "X",
                   .ticker = "X",
                   .include_icon_hash = true,
                   .sig_len = 16};
    size_t len = build_tlv(tlv, sizeof(tlv), opts);
    assert_false(run(tlv, len));
}

static void test_invalid_struct_version_rejected(void **state) {
    (void) state;
    uint8_t tlv[300];
    s_opts opts = {.struct_type = 0x08,
                   .struct_version = 0x05,
                   .blockchain_family = 0x01,
                   .chain_id = 137,
                   .name = "X",
                   .ticker = "X",
                   .include_icon_hash = true,
                   .sig_len = 16};
    size_t len = build_tlv(tlv, sizeof(tlv), opts);
    assert_false(run(tlv, len));
}

static void test_invalid_blockchain_family_rejected(void **state) {
    (void) state;
    // Anything other than BLOCKCHAIN_FAMILY_ETHEREUM (0x01).
    uint8_t tlv[300];
    s_opts opts = {.struct_type = 0x08,
                   .struct_version = 0x01,
                   .blockchain_family = 0x07,
                   .chain_id = 137,
                   .name = "X",
                   .ticker = "X",
                   .include_icon_hash = true,
                   .sig_len = 16};
    size_t len = build_tlv(tlv, sizeof(tlv), opts);
    assert_false(run(tlv, len));
}

static void test_icon_hash_all_zeros_rejected(void **state) {
    (void) state;
    uint8_t tlv[300];
    s_opts opts = {.struct_type = 0x08,
                   .struct_version = 0x01,
                   .blockchain_family = 0x01,
                   .chain_id = 137,
                   .name = "X",
                   .ticker = "X",
                   .include_icon_hash = true,
                   .icon_hash_all_zeros = true,
                   .sig_len = 16};
    size_t len = build_tlv(tlv, sizeof(tlv), opts);
    assert_false(run(tlv, len));
}

static void test_signature_check_failure_rejects(void **state) {
    (void) state;
    g_sig_check_ret = false;
    uint8_t tlv[300];
    s_opts opts = {.struct_type = 0x08,
                   .struct_version = 0x01,
                   .blockchain_family = 0x01,
                   .chain_id = 137,
                   .name = "Polygon",
                   .ticker = "MATIC",
                   .include_icon_hash = true,
                   .sig_len = 16};
    size_t len = build_tlv(tlv, sizeof(tlv), opts);
    assert_false(run(tlv, len));
    assert_null(g_last_added_network);
}

static void test_finalize_hash_failure_rejects(void **state) {
    (void) state;
    g_finalize_hash_ret = false;
    uint8_t tlv[300];
    s_opts opts = {.struct_type = 0x08,
                   .struct_version = 0x01,
                   .blockchain_family = 0x01,
                   .chain_id = 137,
                   .name = "Polygon",
                   .ticker = "MATIC",
                   .include_icon_hash = true,
                   .sig_len = 16};
    size_t len = build_tlv(tlv, sizeof(tlv), opts);
    assert_false(run(tlv, len));
}

static void test_signature_too_short_rejected(void **state) {
    (void) state;
    uint8_t tlv[300];
    s_opts opts = {.struct_type = 0x08,
                   .struct_version = 0x01,
                   .blockchain_family = 0x01,
                   .chain_id = 137,
                   .name = "Polygon",
                   .ticker = "MATIC",
                   .include_icon_hash = true,
                   .sig_len = 4};  // < MIN=8
    size_t len = build_tlv(tlv, sizeof(tlv), opts);
    assert_false(run(tlv, len));
}

static void test_missing_required_field_rejected(void **state) {
    (void) state;
    uint8_t tlv[300];
    s_opts opts = {.struct_type = 0x08,
                   .struct_version = 0x01,
                   .blockchain_family = 0x01,
                   .chain_id = 137,
                   .name = "X",
                   .ticker = "X",
                   .include_icon_hash = true,
                   .omit_name = true,  // missing NETWORK_NAME
                   .sig_len = 16};
    size_t len = build_tlv(tlv, sizeof(tlv), opts);
    assert_false(run(tlv, len));
}

// A descriptor for a chain_id that's already registered must replace
// the previous entry (no duplicates accumulating).
static void test_duplicate_chain_id_replaces_existing(void **state) {
    (void) state;
    uint8_t tlv[300];
    s_opts opts = {.struct_type = 0x08,
                   .struct_version = 0x01,
                   .blockchain_family = 0x01,
                   .chain_id = 137,
                   .name = "Polygon",
                   .ticker = "MATIC",
                   .include_icon_hash = false,
                   .sig_len = 16};
    size_t len = build_tlv(tlv, sizeof(tlv), opts);
    assert_true(run(tlv, len));
    network_info_t *first = g_last_added_network;
    assert_non_null(first);

    // Configure find_dynamic_network_by_chain_id to return the
    // existing entry — this drives the dedup path in append_network_info.
    g_existing_network_ret = first;

    opts.name = "Polygon (renamed)";
    opts.ticker = "POL";
    len = build_tlv(tlv, sizeof(tlv), opts);
    assert_true(run(tlv, len));
    // The newly added entry replaced the previous one.
    assert_non_null(g_last_added_network);
    assert_string_equal(g_last_added_network->name, "Polygon (renamed)");
    assert_string_equal(g_last_added_network->ticker, "POL");
}

static void test_network_info_cleanup_releases_all(void **state) {
    (void) state;
    uint8_t tlv[300];
    s_opts opts = {.struct_type = 0x08,
                   .struct_version = 0x01,
                   .blockchain_family = 0x01,
                   .chain_id = 137,
                   .name = "Polygon",
                   .ticker = "MATIC",
                   .include_icon_hash = false,
                   .sig_len = 16};
    size_t len = build_tlv(tlv, sizeof(tlv), opts);
    assert_true(run(tlv, len));
    assert_non_null(g_dynamic_network_list);
    network_info_cleanup(NULL);
    assert_null(g_dynamic_network_list);
    assert_null(g_last_added_network);
}

// =============================================================================
// Runner
// =============================================================================

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup(test_happy_path_registers_network, reset),
        cmocka_unit_test_setup(test_happy_path_without_icon_hash_registers_network, reset),
        cmocka_unit_test_setup(test_invalid_struct_type_rejected, reset),
        cmocka_unit_test_setup(test_invalid_struct_version_rejected, reset),
        cmocka_unit_test_setup(test_invalid_blockchain_family_rejected, reset),
        cmocka_unit_test_setup(test_icon_hash_all_zeros_rejected, reset),
        cmocka_unit_test_setup(test_signature_check_failure_rejects, reset),
        cmocka_unit_test_setup(test_finalize_hash_failure_rejects, reset),
        cmocka_unit_test_setup(test_signature_too_short_rejected, reset),
        cmocka_unit_test_setup(test_missing_required_field_rejected, reset),
        cmocka_unit_test_setup(test_duplicate_chain_id_replaces_existing, reset),
        cmocka_unit_test_setup(test_network_info_cleanup_releases_all, reset),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
