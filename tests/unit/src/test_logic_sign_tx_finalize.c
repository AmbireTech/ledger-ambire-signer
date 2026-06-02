/**
 * @file test_logic_sign_tx_finalize.c
 * @brief Unit tests for finalize_parsing() and its (static) helper
 *        finalize_parsing_helper() in src/features/sign_tx/logic_sign_tx.c.
 *
 * finalize_parsing is the gate every signed Ethereum transaction passes
 * through after RLP parsing completes: it verifies the chain-id binding,
 * commits the transaction hash, finalises the plugin (if any), formats
 * the on-screen fields, and starts the review UI. A wrong branch here
 * is the difference between the user signing what they reviewed and the
 * user signing what an attacker shaped.
 *
 * The helper is `static __attribute__((noinline))` so we can't linker-
 * wrap it -- the tests exercise the real body and pin the externally-
 * observable side-effects (return SW, strings written, app_exit
 * triggered, ux_approve_tx fired) by controlling every SDK leaf and
 * every app-side helper through a wrap or a global.
 *
 * The noreturn helpers (app_exit, app_quit, send_swap_error_simple) are
 * caught with a setjmp/longjmp pair so the test process survives.
 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

#include "shared_context.h"
#include "common_utils.h"
#include "feature_sign_tx.h"
#include "eth_ustream.h"
#include "tx_ctx.h"
#include "eth_swap_utils.h"
#include "wraps.h"

// =============================================================================
// Wraps + globals
// =============================================================================
// Most external helpers consulted by finalize_parsing_helper are now WEAK
// in mocks/mock.c driven through wraps.h globals:
//
//   get_tx_chain_id           -> g_tx_chain_id
//   get_displayable_ticker    -> g_displayable_ticker
//   get_public_key            -> g_get_public_key_ret
//   getEthDisplayableAddress  -> g_getEthDisplayableAddress_ret
//   amountToString            -> g_amountToString_ret
//   get_network_as_string     -> g_get_network_as_string_ret
//   app_exit                  -> g_noreturn_armed + g_noreturn_calls
//   app_quit                  -> g_noreturn_calls (returns normally,
//                                                  per the production
//                                                  contract)
//   send_swap_error_simple    -> g_noreturn_armed + g_noreturn_calls
//
// The wraps below are unique to this test (plugin / swap / IO seph
// helpers + cx_hash_no_throw) -- no central default would carry the
// same intent.

static cx_err_t g_cx_hash_ret = CX_OK;
cx_err_t __wrap_cx_hash_no_throw(cx_hash_t *hash,
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
    return g_cx_hash_ret;
}

// eth_plugin_call: drive the per-method return value via a small table.
// The two methods finalize_parsing_helper consults are FINALIZE and
// PROVIDE_INFO. Other methods aren't reached on the paths we test.
static int g_plugin_call_finalize_ret = ETH_PLUGIN_RESULT_FALLBACK;
static int g_plugin_call_provide_info_ret = ETH_PLUGIN_RESULT_SUCCESSFUL;
static int g_plugin_call_calls = 0;
int __wrap_eth_plugin_call(int method, void *params) {
    (void) params;
    g_plugin_call_calls++;
    if (method == ETH_PLUGIN_FINALIZE) {
        return g_plugin_call_finalize_ret;
    }
    if (method == ETH_PLUGIN_PROVIDE_INFO) {
        return g_plugin_call_provide_info_ret;
    }
    return ETH_PLUGIN_RESULT_FALLBACK;
}

static int g_send_status_calls = 0;
static uint16_t g_send_status_last_sw = 0;
uint16_t __wrap_io_seproxyhal_send_status(uint16_t sw, uint32_t tx, bool reset, bool idle) {
    (void) tx;
    (void) reset;
    (void) idle;
    g_send_status_calls++;
    g_send_status_last_sw = sw;
    return 0;
}

static int g_touch_tx_ok_calls = 0;
uint32_t __wrap_io_seproxyhal_touch_tx_ok(const void *e) {
    (void) e;
    g_touch_tx_ok_calls++;
    return 0;
}

static int g_blind_signing_calls = 0;
void __wrap_ui_error_blind_signing(void) {
    g_blind_signing_calls++;
}

static int g_ux_approve_calls = 0;
static bool g_ux_approve_last_from_plugin = false;
uint16_t __wrap_ux_approve_tx(bool fromPlugin) {
    g_ux_approve_calls++;
    g_ux_approve_last_from_plugin = fromPlugin;
    return 0;
}

static bool g_swap_check_destination_ret = true;
bool __wrap_swap_check_destination(char *destination) {
    (void) destination;
    return g_swap_check_destination_ret;
}

static bool g_swap_check_amount_ret = true;
bool __wrap_swap_check_amount(char *amount) {
    (void) amount;
    return g_swap_check_amount_ret;
}

static bool g_swap_check_fee_ret = true;
bool __wrap_swap_check_fee(char *fee) {
    (void) fee;
    return g_swap_check_fee_ret;
}

// mem_utils_free_and_null is reused from app_globals.c default (free). The
// wrap here just no-ops the pointer so tests stay deterministic.
void __wrap_mem_utils_free_and_null(void **ptr_storage, const char *file, int line) {
    (void) file;
    (void) line;
    if (ptr_storage != NULL) {
        *ptr_storage = NULL;
    }
}

// =============================================================================
// Strong stubs for symbols referenced but not exercised on the paths
// under test.
// =============================================================================

s_calldata *get_root_calldata(void) {
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
bool eth_plugin_perform_init(uint8_t *contractAddress, void *msg) {
    (void) contractAddress;
    (void) msg;
    return true;
}
void *get_matching_asset_info(const uint64_t *chain_id, const uint8_t *address) {
    (void) chain_id;
    (void) address;
    return NULL;
}
void ui_confirm_parameter(void) {
}
void ui_confirm_selector(void) {
}

// =============================================================================
// Fixture
// =============================================================================

static txContext_t s_ctx;
static cx_sha3_t s_hash_ctx;

static int reset(void **state) {
    (void) state;
    memset(&s_ctx, 0, sizeof(s_ctx));
    s_ctx.txType = LEGACY;

    g_cx_hash_ret = CX_OK;
    g_get_public_key_ret = SWO_SUCCESS;
    g_getEthDisplayableAddress_ret = true;
    g_amountToString_ret = true;
    g_get_network_as_string_ret = true;
    g_plugin_call_finalize_ret = ETH_PLUGIN_RESULT_FALLBACK;
    g_plugin_call_provide_info_ret = ETH_PLUGIN_RESULT_SUCCESSFUL;
    g_plugin_call_calls = 0;
    g_send_status_calls = 0;
    g_send_status_last_sw = 0;
    g_touch_tx_ok_calls = 0;
    g_blind_signing_calls = 0;
    g_ux_approve_calls = 0;
    g_ux_approve_last_from_plugin = false;
    g_swap_check_destination_ret = true;
    g_swap_check_amount_ret = true;
    g_swap_check_fee_ret = true;

    g_tx_chain_id = 1;
    g_displayable_ticker = "ETH";
    g_chainConfig.chain_id = 1;

    memset(&tmpContent, 0, sizeof(tmpContent));
    memset(&tmpCtx, 0, sizeof(tmpCtx));
    memset(&dataContext, 0, sizeof(dataContext));
    memset(&strings, 0, sizeof(strings));
    pluginType = PLUGIN_TYPE_NONE;
    G_called_from_swap = false;
    G_swap_mode = SWAP_MODE_STANDARD;
    G_swap_response_ready = false;
    G_swap_checked = false;
    g_n_storage_writable.dataAllowed = true;
    g_n_storage_writable.contractDetails = false;

    // Default: hash ctx allocated so most tests bypass the early
    // SWO_INSUFFICIENT_MEMORY exit. v == 1 so we're past EIP-155.
    g_tx_hash_ctx = &s_hash_ctx;
    tmpContent.txContent.vLength = 1;
    tmpContent.txContent.v[0] = 0x25;

    // Plausible defaults for a 0-value transfer to a known address.
    tmpContent.txContent.destinationLength = ADDRESS_LENGTH;
    memset(tmpContent.txContent.destination, 0xCD, ADDRESS_LENGTH);
    tmpContent.txContent.value.length = 1;
    tmpContent.txContent.value.value[0] = 0;
    tmpContent.txContent.gasprice.length = 1;
    tmpContent.txContent.gasprice.value[0] = 1;
    tmpContent.txContent.startgas.length = 1;
    tmpContent.txContent.startgas.value[0] = 1;
    tmpContent.txContent.nonce.length = 1;
    tmpContent.txContent.nonce.value[0] = 0;

    g_noreturn_armed = false;
    g_noreturn_calls = 0;
    return 0;
}

// =============================================================================
// chain_id / pre-EIP155 gate
// =============================================================================

static void test_chain_id_mismatch_non_mainnet_returns_no_response(void **state) {
    (void) state;
    g_chainConfig.chain_id = 137;  // app expects Polygon
    g_tx_chain_id = 1;             // tx claims mainnet
    uint16_t sw = finalize_parsing(&s_ctx);
    assert_int_equal(sw, SWO_NO_RESPONSE);
    // The error helper also calls io_seproxyhal_send_status(SWO_INCORRECT_DATA).
    assert_int_equal(g_send_status_last_sw, SWO_INCORRECT_DATA);
}

static void test_pre_eip155_legacy_rejected(void **state) {
    (void) state;
    // LEGACY transaction with empty V field -> no chain_id binding ->
    // replay vulnerability across EVM chains. MUST refuse.
    s_ctx.txType = LEGACY;
    tmpContent.txContent.vLength = 0;
    uint16_t sw = finalize_parsing(&s_ctx);
    assert_int_equal(sw, SWO_NO_RESPONSE);
    assert_int_equal(g_send_status_last_sw, SWO_INCORRECT_DATA);
}

static void test_post_eip155_legacy_passes_chain_gate(void **state) {
    (void) state;
    // Same setup but vLength != 0 -> the chain-binding gate lets it
    // through. The function proceeds and ultimately delegates to
    // start_signature_flow, whose return is ux_approve_tx's return
    // (stubbed to 0 = noreply / deferred).
    s_ctx.txType = LEGACY;
    tmpContent.txContent.vLength = 1;
    assert_int_equal(finalize_parsing(&s_ctx), 0);
    assert_int_equal(g_ux_approve_calls, 1);
}

// =============================================================================
// Hash / pubkey / address-format failures
// =============================================================================

static void test_null_hash_ctx_returns_insufficient_memory(void **state) {
    (void) state;
    g_tx_hash_ctx = NULL;
    assert_int_equal(finalize_parsing(&s_ctx), SWO_INSUFFICIENT_MEMORY);
}

static void test_cx_hash_failure_propagates(void **state) {
    (void) state;
    // finalize_parsing returns uint16_t, so the cx_err_t (32-bit) is
    // truncated to its low 16 bits.
    g_cx_hash_ret = CX_INVALID_PARAMETER;
    assert_int_equal(finalize_parsing(&s_ctx), (uint16_t) CX_INVALID_PARAMETER);
}

static void test_get_public_key_failure_propagates(void **state) {
    (void) state;
    g_get_public_key_ret = 0x6700;  // generic SW_WRONG_LENGTH from the SDK
    assert_int_equal(finalize_parsing(&s_ctx), 0x6700);
}

static void test_address_format_failure_returns_parameter_error(void **state) {
    (void) state;
    // The sender address is formatted first; force it to fail.
    g_getEthDisplayableAddress_ret = false;
    assert_int_equal(finalize_parsing(&s_ctx), SWO_PARAMETER_ERROR_NO_INFO);
}

// =============================================================================
// Plugin chain-id binding + finalize failure
// =============================================================================

static void test_plugin_chain_id_mismatch_returns_no_response(void **state) {
    (void) state;
    dataContext.tokenContext.pluginStatus = ETH_PLUGIN_RESULT_SUCCESSFUL;
    dataContext.tokenContext.pluginChainId = 137;  // plugin registered for Polygon
    g_tx_chain_id = 1;                             // tx is on mainnet
    g_chainConfig.chain_id = 1;
    assert_int_equal(finalize_parsing(&s_ctx), SWO_NO_RESPONSE);
    assert_int_equal(g_send_status_last_sw, SWO_INCORRECT_DATA);
}

static void test_plugin_finalize_failure_returns_no_response(void **state) {
    (void) state;
    dataContext.tokenContext.pluginStatus = ETH_PLUGIN_RESULT_SUCCESSFUL;
    dataContext.tokenContext.pluginChainId = PLUGIN_CHAIN_ID_ANY;
    g_plugin_call_finalize_ret = ETH_PLUGIN_RESULT_ERROR;
    assert_int_equal(finalize_parsing(&s_ctx), SWO_NO_RESPONSE);
}

// =============================================================================
// network-as-string failure (last gate before start_signature_flow)
// =============================================================================

static void test_get_network_as_string_failure_returns_incorrect_data(void **state) {
    (void) state;
    g_get_network_as_string_ret = false;
    assert_int_equal(finalize_parsing(&s_ctx), SWO_INCORRECT_DATA);
}

// =============================================================================
// Blind-signing gate
// =============================================================================

static void test_data_present_without_data_allowed_rejected(void **state) {
    (void) state;
    tmpContent.txContent.dataPresent = true;
    g_n_storage_writable.dataAllowed = false;
    assert_int_equal(finalize_parsing(&s_ctx), SWO_NO_RESPONSE);
    assert_int_equal(g_blind_signing_calls, 1);
}

// =============================================================================
// Happy path: no plugin, no swap -> start_signature_flow -> ux_approve_tx
// =============================================================================

static void test_happy_path_no_plugin_no_swap_starts_review(void **state) {
    (void) state;
    // finalize_parsing returns whatever start_signature_flow returns,
    // which is ux_approve_tx's return value (here stubbed to 0).
    pluginType = PLUGIN_TYPE_NONE;
    G_called_from_swap = false;
    assert_int_equal(finalize_parsing(&s_ctx), 0);
    assert_int_equal(g_ux_approve_calls, 1);
    assert_false(g_ux_approve_last_from_plugin);
    // Display fields populated.
    assert_string_equal(strings.common.fromAddress, "0xdeadbeef");
    assert_string_equal(strings.common.toAddress, "0xdeadbeef");
    assert_string_equal(strings.common.fullAmount, "1.5");
}

static void test_happy_path_with_plugin_passes_from_plugin_true(void **state) {
    (void) state;
    // pluginStatus stays UNAVAILABLE so the plugin branch inside the
    // helper is skipped (otherwise we hit the uninitialised pluginFinalize
    // path). pluginType is what start_signature_flow looks at to decide
    // ux_approve_tx(true vs false).
    pluginType = PLUGIN_TYPE_EXTERNAL;
    G_called_from_swap = false;
    assert_int_equal(finalize_parsing(&s_ctx), 0);
    assert_true(g_ux_approve_last_from_plugin);
}

// =============================================================================
// store_calldata branches
// =============================================================================

static void test_store_calldata_without_calldata_returns_incorrect_data(void **state) {
    (void) state;
    s_ctx.store_calldata = true;
    // get_root_calldata stub returns NULL -> selector check fails.
    assert_int_equal(finalize_parsing(&s_ctx), SWO_INCORRECT_DATA);
    // UI MUST NOT fire on the store-only path.
    assert_int_equal(g_ux_approve_calls, 0);
}

// =============================================================================
// Swap branches
// =============================================================================

static void test_swap_standard_success_calls_touch_tx_ok(void **state) {
    (void) state;
    G_called_from_swap = true;
    G_swap_mode = SWAP_MODE_STANDARD;
    pluginType = PLUGIN_TYPE_NONE;
    assert_int_equal(finalize_parsing(&s_ctx), SWO_SUCCESS);
    assert_int_equal(g_touch_tx_ok_calls, 1);
    // No UI review in swap success mode.
    assert_int_equal(g_ux_approve_calls, 0);
}

static void test_swap_double_sign_safety_triggers_app_quit(void **state) {
    (void) state;
    G_called_from_swap = true;
    G_swap_response_ready = true;  // already-replied flag
    pluginType = PLUGIN_TYPE_NONE;
    // app_quit is *not* noreturn in production (shared_context.h declares
    // it `void app_quit(void)` -- callers wrap it in `while(1);` as a
    // defence in depth). The mock returns; we just count the call.
    g_noreturn_calls = 0;
    finalize_parsing(&s_ctx);
    assert_int_equal(g_noreturn_calls, 1);
}

static void test_swap_unexpected_plugin_type_triggers_app_exit(void **state) {
    (void) state;
    G_called_from_swap = true;
    G_swap_mode = SWAP_MODE_STANDARD;
    // pluginType is neither NONE, OLD_INTERNAL, nor SWAP_WITH_CALLDATA
    // -> swap-error + app_exit. Keep pluginStatus UNAVAILABLE so the
    // helper's plugin-finalize block is skipped (the swap-error gate
    // is what we want to hit).
    pluginType = PLUGIN_TYPE_EXTERNAL;
    dataContext.tokenContext.pluginStatus = ETH_PLUGIN_RESULT_UNAVAILABLE;
    EXPECT_NORETURN(finalize_parsing(&s_ctx));
}

static void test_swap_crosschain_wrong_mode_triggers_app_exit(void **state) {
    (void) state;
    G_called_from_swap = true;
    // PENDING_CHECK is neither STANDARD nor CROSSCHAIN_SUCCESS at the
    // mode-validation gate -> swap-error + app_exit.
    G_swap_mode = SWAP_MODE_CROSSCHAIN_PENDING_CHECK;
    pluginType = PLUGIN_TYPE_NONE;
    EXPECT_NORETURN(finalize_parsing(&s_ctx));
}

// =============================================================================
// Tests already pinned in test_logic_sign_tx_fee.c remain there; this
// file deliberately doesn't re-cover max_transaction_fee_to_string.
// =============================================================================

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup(test_chain_id_mismatch_non_mainnet_returns_no_response, reset),
        cmocka_unit_test_setup(test_pre_eip155_legacy_rejected, reset),
        cmocka_unit_test_setup(test_post_eip155_legacy_passes_chain_gate, reset),
        cmocka_unit_test_setup(test_null_hash_ctx_returns_insufficient_memory, reset),
        cmocka_unit_test_setup(test_cx_hash_failure_propagates, reset),
        cmocka_unit_test_setup(test_get_public_key_failure_propagates, reset),
        cmocka_unit_test_setup(test_address_format_failure_returns_parameter_error, reset),
        cmocka_unit_test_setup(test_plugin_chain_id_mismatch_returns_no_response, reset),
        cmocka_unit_test_setup(test_plugin_finalize_failure_returns_no_response, reset),
        cmocka_unit_test_setup(test_get_network_as_string_failure_returns_incorrect_data, reset),
        cmocka_unit_test_setup(test_data_present_without_data_allowed_rejected, reset),
        cmocka_unit_test_setup(test_happy_path_no_plugin_no_swap_starts_review, reset),
        cmocka_unit_test_setup(test_happy_path_with_plugin_passes_from_plugin_true, reset),
        cmocka_unit_test_setup(test_store_calldata_without_calldata_returns_incorrect_data, reset),
        cmocka_unit_test_setup(test_swap_standard_success_calls_touch_tx_ok, reset),
        cmocka_unit_test_setup(test_swap_double_sign_safety_triggers_app_quit, reset),
        cmocka_unit_test_setup(test_swap_unexpected_plugin_type_triggers_app_exit, reset),
        cmocka_unit_test_setup(test_swap_crosschain_wrong_mode_triggers_app_exit, reset),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
