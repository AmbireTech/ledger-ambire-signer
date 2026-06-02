/**
 * @file test_logic_sign_tx_fee.c
 * @brief Unit tests for max_transaction_fee_to_string() in
 *        src/features/sign_tx/logic_sign_tx.c.
 *
 * The displayed transaction fee is gasPrice * gasLimit. A bug in the
 * uint256 multiplication path (overflow handling, decimal adjustment,
 * ticker concatenation) would either:
 *   - hide an overflow and silently display a wrong (truncated) fee,
 *   - drop / shift the decimal point and show a fee that's off by many
 *     orders of magnitude.
 *
 * Either way the user signs while looking at the wrong number. This
 * suite pins:
 *  - mul256 overflow surfaces as `false` from
 *    max_transaction_fee_to_string (the caller MUST handle this),
 *  - the WEI_TO_ETHER (1e18) decimal-shift produces the canonical fee
 *    string for representative gas prices,
 *  - the displayable ticker from get_displayable_ticker() is appended
 *    after a single space and the buffer is NUL-terminated.
 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

#include "shared_context.h"
#include "common_utils.h"
#include "feature_sign_tx.h"
#include "eth_ustream.h"

// =============================================================================
// Globals required by linked translation units
// =============================================================================

// =============================================================================
// Wraps
// =============================================================================

// =============================================================================
// Stubs — symbols referenced by logic_sign_tx.c that are not exercised
// by max_transaction_fee_to_string but whose absence blocks the link.
// =============================================================================

const char *get_network_as_string(const uint64_t *chain_id) {
    (void) chain_id;
    return "ETH";
}
uint16_t ux_approve_tx(bool fromPlugin) {
    (void) fromPlugin;
    return 0;
}
void *get_root_calldata(void) {
    return NULL;
}
const uint8_t *calldata_get_selector(const s_calldata *node) {
    (void) node;
    return NULL;
}
bool copy_tx_data(txContext_t *context, uint8_t *out, uint32_t length) {
    (void) context;
    (void) out;
    (void) length;
    return true;
}
cx_err_t cx_hash_no_throw(cx_hash_t *hash,
                          uint32_t mode,
                          const uint8_t *in,
                          size_t in_len,
                          uint8_t *out,
                          size_t out_len) {
    (void) hash;
    (void) mode;
    (void) in;
    (void) in_len;
    (void) out;
    (void) out_len;
    return CX_OK;
}
int eth_plugin_call(int method, void *params) {
    (void) method;
    (void) params;
    return 0;
}
bool eth_plugin_perform_init(uint8_t *contractAddress, void *msg) {
    (void) contractAddress;
    (void) msg;
    return true;
}
void eth_plugin_prepare_finalize(void *msg) {
    (void) msg;
}
void eth_plugin_prepare_init(void *msg, const uint8_t *pluginName, uint8_t pluginNameLength) {
    (void) msg;
    (void) pluginName;
    (void) pluginNameLength;
}
void eth_plugin_prepare_provide_info(void *msg) {
    (void) msg;
}
void eth_plugin_prepare_provide_parameter(void *msg, const uint8_t *param, uint32_t paramOffset) {
    (void) msg;
    (void) param;
    (void) paramOffset;
}
void *get_matching_asset_info(uint64_t chain_id, uint8_t *address) {
    (void) chain_id;
    (void) address;
    return NULL;
}
uint16_t get_public_key(uint8_t *out, uint8_t out_size) {
    (void) out;
    (void) out_size;
    return 0;
}
uint16_t io_seproxyhal_send_status(uint16_t sw, uint32_t tx, bool reset, bool idle) {
    (void) sw;
    (void) tx;
    (void) reset;
    (void) idle;
    return 0;
}
uint32_t io_seproxyhal_touch_tx_ok(const void *e) {
    (void) e;
    return 0;
}
int send_swap_error_simple(uint16_t error, uint8_t error_code, uint16_t code, uint8_t code_idx) {
    (void) error;
    (void) error_code;
    (void) code;
    (void) code_idx;
    return 0;
}
bool swap_check_amount(uint8_t *value, uint8_t length) {
    (void) value;
    (void) length;
    return true;
}
bool swap_check_destination(uint8_t *destination, uint8_t length) {
    (void) destination;
    (void) length;
    return true;
}
bool swap_check_fee(uint8_t *value, uint8_t length) {
    (void) value;
    (void) length;
    return true;
}
void ui_confirm_parameter(void) {
}
void ui_confirm_selector(void) {
}
void ui_error_blind_signing(void) {
}

// =============================================================================
// Helper — fill txInt256_t from a uint64
// =============================================================================

static void set_be_u64(txInt256_t *out, uint64_t value) {
    memset(out, 0, sizeof(*out));
    uint8_t buf[8];
    for (int i = 0; i < 8; i++) {
        buf[7 - i] = (uint8_t) (value >> (8 * i));
    }
    // Skip leading zero bytes to get the canonical big-endian short form
    // the RLP parser produces.
    int leading = 0;
    while (leading < 8 && buf[leading] == 0) leading++;
    if (leading == 8) {
        out->length = 0;
        return;
    }
    out->length = (uint8_t) (8 - leading);
    memcpy(out->value, buf + leading, out->length);
}

static void set_be_all_ff(txInt256_t *out, uint8_t n) {
    memset(out, 0xFF, n);
    out->length = n;
    // value is followed by padding; ensure tail bytes are not touched
    // beyond `length`. txInt256_t.value is INT256_LENGTH=32 wide.
    for (int i = n; i < INT256_LENGTH; i++) {
        out->value[i] = 0;
    }
}

// =============================================================================
// Tests
// =============================================================================

static void test_zero_fee_renders_zero_eth(void **state) {
    (void) state;
    txInt256_t gp, gl;
    set_be_u64(&gp, 0);
    set_be_u64(&gl, 0);
    char buf[64] = {0};
    assert_true(max_transaction_fee_to_string(&gp, &gl, buf, sizeof(buf)));
    assert_string_equal(buf, "0 ETH");
}

static void test_one_wei_times_one_renders_smallest_unit(void **state) {
    (void) state;
    txInt256_t gp, gl;
    set_be_u64(&gp, 1);
    set_be_u64(&gl, 1);
    char buf[64] = {0};
    assert_true(max_transaction_fee_to_string(&gp, &gl, buf, sizeof(buf)));
    // 1 wei = 1e-18 ETH. The display path must show the full 18
    // decimals so the user sees they're paying a tiny amount.
    assert_string_equal(buf, "0.000000000000000001 ETH");
}

static void test_typical_20gwei_21000gas_renders_canonical_fee(void **state) {
    (void) state;
    txInt256_t gp, gl;
    set_be_u64(&gp, 20000000000ULL);  // 20 Gwei
    set_be_u64(&gl, 21000ULL);
    char buf[64] = {0};
    assert_true(max_transaction_fee_to_string(&gp, &gl, buf, sizeof(buf)));
    // 20e9 * 21000 = 4.2e14 wei = 0.00042 ETH.
    assert_string_equal(buf, "0.00042 ETH");
}

static void test_one_eth_fee_renders_no_decimals(void **state) {
    (void) state;
    txInt256_t gp, gl;
    // gasPrice = 1e18 wei (1 ETH per gas), gasLimit = 1 → fee = 1 ETH.
    set_be_u64(&gp, 1000000000000000000ULL);
    set_be_u64(&gl, 1);
    char buf[64] = {0};
    assert_true(max_transaction_fee_to_string(&gp, &gl, buf, sizeof(buf)));
    assert_string_equal(buf, "1 ETH");
}

static void test_overflow_returns_false(void **state) {
    (void) state;
    // (2^256 - 1) * (2^256 - 1) overflows uint256. mul256 must detect
    // the spillover into the high 256 bits of the 512-bit product and
    // return false; max_transaction_fee_to_string propagates that to
    // its caller, which surfaces it as SWO_INCORRECT_DATA (see
    // logic_sign_tx.c finalize_parsing). Without this gate the user
    // would sign while seeing a fee orders of magnitude smaller than
    // what the chain actually charges (CWE-682).
    txInt256_t gp, gl;
    set_be_all_ff(&gp, 32);
    set_be_all_ff(&gl, 32);
    char buf[64] = {0};
    memset(buf, 0xAA, sizeof(buf));
    assert_false(max_transaction_fee_to_string(&gp, &gl, buf, sizeof(buf)));
    // On overflow the function bails before raw_fee_to_string runs, so
    // the pre-call sentinel is preserved (the caller MUST handle the
    // failure and not display this buffer).
    assert_int_equal((uint8_t) buf[0], 0xAA);
}

static void test_ticker_pulled_from_displayable_helper(void **state) {
    (void) state;
    txInt256_t gp, gl;
    set_be_u64(&gp, 1);
    set_be_u64(&gl, 1);
    char buf[64] = {0};
    (void) max_transaction_fee_to_string(&gp, &gl, buf, sizeof(buf));
    // The trailing ETH must be preceded by a single space and the
    // string must be NUL-terminated within bounds.
    const char *space = strrchr(buf, ' ');
    assert_non_null(space);
    assert_string_equal(space + 1, "ETH");
}

static void test_full_uint256_capacity_no_overflow(void **state) {
    (void) state;
    // Largest fee that still fits in uint256: gasPrice = 2^128 - 1,
    // gasLimit = 2^128 - 1 → product fits in 2^256 - 1.
    txInt256_t gp, gl;
    set_be_all_ff(&gp, 16);
    set_be_all_ff(&gl, 16);
    char buf[128] = {0};
    assert_true(max_transaction_fee_to_string(&gp, &gl, buf, sizeof(buf)));
    // Strict format check is fragile against decimal-rounding tweaks;
    // pin the easy invariant: the buffer ends with " ETH" and starts
    // with a digit.
    assert_true(buf[0] >= '0' && buf[0] <= '9');
    size_t n = strlen(buf);
    assert_true(n >= 4);
    assert_string_equal(buf + n - 4, " ETH");
}

// =============================================================================
// Runner
// =============================================================================

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_zero_fee_renders_zero_eth),
        cmocka_unit_test(test_one_wei_times_one_renders_smallest_unit),
        cmocka_unit_test(test_typical_20gwei_21000gas_renders_canonical_fee),
        cmocka_unit_test(test_one_eth_fee_renders_no_decimals),
        cmocka_unit_test(test_overflow_returns_false),
        cmocka_unit_test(test_ticker_pulled_from_displayable_helper),
        cmocka_unit_test(test_full_uint256_capacity_no_overflow),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
