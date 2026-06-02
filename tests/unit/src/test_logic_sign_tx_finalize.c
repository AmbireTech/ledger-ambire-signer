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

// custom_processor wraps. The default lets the plugin path run "as
// installed"; tests that need a specific outcome flip the *_ret global.
static eth_plugin_result_t g_perform_init_ret = ETH_PLUGIN_RESULT_UNAVAILABLE;
eth_plugin_result_t __wrap_eth_plugin_perform_init(uint8_t *contract_address, void *init) {
    (void) contract_address;
    (void) init;
    return g_perform_init_ret;
}

static bool g_copy_tx_data_ret = true;
bool __wrap_copy_tx_data(txContext_t *context, uint8_t *out, uint32_t length) {
    (void) context;
    (void) length;
    // Fill the destination so the inner format_hex on the selector path
    // has something deterministic to consume.
    if (g_copy_tx_data_ret && out != NULL) {
        memset(out, 0xAA, length);
    }
    return g_copy_tx_data_ret;
}

static int g_ui_confirm_selector_calls = 0;
void __wrap_ui_confirm_selector(void) {
    g_ui_confirm_selector_calls++;
}

static int g_ui_confirm_parameter_calls = 0;
void __wrap_ui_confirm_parameter(void) {
    g_ui_confirm_parameter_calls++;
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
    g_perform_init_ret = ETH_PLUGIN_RESULT_UNAVAILABLE;
    g_copy_tx_data_ret = true;
    g_ui_confirm_selector_calls = 0;
    g_ui_confirm_parameter_calls = 0;

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
// custom_processor -- per-chunk RLP DATA dispatcher
// =============================================================================
// custom_processor is what eth_ustream calls for every RLP DATA chunk
// during the parse. It decides whether to:
//   - skip the chunk entirely (CUSTOM_NOT_HANDLED, no calldata handling)
//   - dispatch to a plugin (CUSTOM_HANDLED / CUSTOM_SUSPENDED)
//   - reject the transaction (CUSTOM_FAULT, e.g. blind-signing forbidden)
//
// A bug here either skips a plugin parameter (the review shows partial
// info) or accepts data that should have been rejected as blind
// signing. The fixture sets up a "valid first chunk on LEGACY RLP DATA"
// baseline; each test perturbs one field.

static void cp_setup_first_chunk(void) {
    // Default: LEGACY tx, first chunk of an 8-byte data field, plugin
    // unavailable, no contractDetails, data allowed.
    memset(&s_ctx, 0, sizeof(s_ctx));
    s_ctx.txType = LEGACY;
    s_ctx.currentField = LEGACY_RLP_DATA;
    s_ctx.currentFieldLength = 8;
    s_ctx.currentFieldPos = 0;
    s_ctx.commandLength = 8;
    s_ctx.store_calldata = false;
    // context->content is dereferenced on the first `dataPresent = true`
    // -- point it at the app-globals tmpContent so the test process
    // doesn't segfault.
    s_ctx.content = &tmpContent.txContent;
    tmpContent.txContent.destinationLength = ADDRESS_LENGTH;
    g_n_storage_writable.dataAllowed = true;
    g_n_storage_writable.contractDetails = false;
    G_called_from_swap = false;
}

// --- outer gates ---------------------------------------------------------

static void test_cp_not_rlp_data_field_returns_not_handled(void **state) {
    (void) state;
    cp_setup_first_chunk();
    s_ctx.currentField = LEGACY_RLP_DATA + 1;  // any non-DATA field
    assert_int_equal(custom_processor(&s_ctx), CUSTOM_NOT_HANDLED);
    // dataPresent MUST NOT be flipped on a non-DATA field.
    assert_false(tmpContent.txContent.dataPresent);
}

static void test_cp_empty_field_returns_not_handled(void **state) {
    (void) state;
    cp_setup_first_chunk();
    s_ctx.currentFieldLength = 0;
    assert_int_equal(custom_processor(&s_ctx), CUSTOM_NOT_HANDLED);
    assert_false(tmpContent.txContent.dataPresent);
}

static void test_cp_new_contract_skips_plugin_dispatch(void **state) {
    (void) state;
    cp_setup_first_chunk();
    tmpContent.txContent.destinationLength = 0;  // contract creation
    assert_int_equal(custom_processor(&s_ctx), CUSTOM_NOT_HANDLED);
    // dataPresent flips even though we don't dispatch -- the user must
    // still see "Contract creation: data attached".
    assert_true(tmpContent.txContent.dataPresent);
}

static void test_cp_short_field_returns_not_handled(void **state) {
    (void) state;
    cp_setup_first_chunk();
    s_ctx.currentFieldLength = 3;  // shorter than CALLDATA_SELECTOR_SIZE
    assert_int_equal(custom_processor(&s_ctx), CUSTOM_NOT_HANDLED);
    assert_true(tmpContent.txContent.dataPresent);
}

// --- first chunk -- plugin path -----------------------------------------

static void test_cp_first_chunk_short_command_returns_fault(void **state) {
    (void) state;
    cp_setup_first_chunk();
    s_ctx.commandLength = 3;  // can't even read the selector -- corrupt frame
    assert_int_equal(custom_processor(&s_ctx), CUSTOM_FAULT);
}

static void test_cp_plugin_init_error_returns_fault(void **state) {
    (void) state;
    cp_setup_first_chunk();
    g_n_storage_writable.contractDetails = false;  // trigger plugin path
    g_perform_init_ret = ETH_PLUGIN_RESULT_ERROR;
    assert_int_equal(custom_processor(&s_ctx), CUSTOM_FAULT);
}

static void test_cp_plugin_success_selector_only_returns_not_handled(void **state) {
    (void) state;
    cp_setup_first_chunk();
    s_ctx.currentFieldLength = 4;  // only the selector, no params
    s_ctx.commandLength = 4;
    g_perform_init_ret = ETH_PLUGIN_RESULT_SUCCESSFUL;
    assert_int_equal(custom_processor(&s_ctx), CUSTOM_NOT_HANDLED);
}

static void test_cp_plugin_success_selector_copy_failure_returns_fault(void **state) {
    (void) state;
    cp_setup_first_chunk();
    g_perform_init_ret = ETH_PLUGIN_RESULT_SUCCESSFUL;
    g_copy_tx_data_ret = false;  // selector copy fails
    assert_int_equal(custom_processor(&s_ctx), CUSTOM_FAULT);
}

// --- first chunk -- no plugin / blind signing gate ----------------------

static void test_cp_first_chunk_data_forbidden_returns_fault(void **state) {
    (void) state;
    cp_setup_first_chunk();
    g_n_storage_writable.dataAllowed = false;  // blind signing forbidden
    // pluginStatus stays UNAVAILABLE -> we fall through to the no-plugin
    // path which checks dataAllowed.
    assert_int_equal(custom_processor(&s_ctx), CUSTOM_FAULT);
    assert_int_equal(g_blind_signing_calls, 1);
}

static void test_cp_first_chunk_store_calldata_returns_not_handled(void **state) {
    (void) state;
    cp_setup_first_chunk();
    s_ctx.store_calldata = true;  // host asked us to buffer the calldata
    assert_int_equal(custom_processor(&s_ctx), CUSTOM_NOT_HANDLED);
}

static void test_cp_first_chunk_no_contract_details_returns_not_handled(void **state) {
    (void) state;
    cp_setup_first_chunk();
    g_n_storage_writable.contractDetails = false;
    // pluginStatus stays UNAVAILABLE, dataAllowed=true -> falls to the
    // `store_calldata || !contractDetails` gate -> NOT_HANDLED.
    assert_int_equal(custom_processor(&s_ctx), CUSTOM_NOT_HANDLED);
}

// --- first chunk -- contractDetails on -> selector confirm UI -----------

static void test_cp_first_chunk_contract_details_shows_selector(void **state) {
    (void) state;
    cp_setup_first_chunk();
    g_n_storage_writable.contractDetails = true;  // user wants to see selector
    // perform_init NOT called when contractDetails is on AND
    // G_called_from_swap is false (early return guard). pluginStatus
    // stays UNAVAILABLE -> falls to the no-plugin path.
    // blockSize=4, copySize=4 -> SUSPENDED with ui_confirm_selector.
    assert_int_equal(custom_processor(&s_ctx), CUSTOM_SUSPENDED);
    assert_int_equal(g_ui_confirm_selector_calls, 1);
    assert_int_equal(g_ui_confirm_parameter_calls, 0);
}

// --- continuation chunks (currentFieldPos > 0) --------------------------

static void test_cp_continuation_store_calldata_returns_not_handled(void **state) {
    (void) state;
    cp_setup_first_chunk();
    s_ctx.currentFieldPos = 4;  // already past the selector
    s_ctx.currentFieldLength = 36;
    s_ctx.commandLength = 32;
    s_ctx.store_calldata = true;
    assert_int_equal(custom_processor(&s_ctx), CUSTOM_NOT_HANDLED);
}

static void test_cp_continuation_no_plugin_no_details_returns_not_handled(void **state) {
    (void) state;
    cp_setup_first_chunk();
    s_ctx.currentFieldPos = 4;
    s_ctx.currentFieldLength = 36;
    s_ctx.commandLength = 32;
    g_n_storage_writable.contractDetails = false;
    dataContext.tokenContext.pluginStatus = ETH_PLUGIN_RESULT_UNAVAILABLE;
    assert_int_equal(custom_processor(&s_ctx), CUSTOM_NOT_HANDLED);
}

static void test_cp_continuation_plugin_provide_param_success_returns_handled(void **state) {
    (void) state;
    cp_setup_first_chunk();
    s_ctx.currentFieldPos = 4;
    s_ctx.currentFieldLength = 4 + CALLDATA_CHUNK_SIZE;  // selector + 1 param
    s_ctx.commandLength = CALLDATA_CHUNK_SIZE;
    dataContext.tokenContext.pluginStatus = ETH_PLUGIN_RESULT_SUCCESSFUL;
    // eth_plugin_call(PROVIDE_PARAMETER) defaults to FALLBACK which is
    // > ETH_PLUGIN_RESULT_ERROR; the source uses `if (!eth_plugin_call(...))`
    // so any non-zero return is "ok". g_plugin_call_finalize_ret is the
    // FINALIZE method; PROVIDE_PARAMETER isn't routed through it.
    assert_int_equal(custom_processor(&s_ctx), CUSTOM_HANDLED);
    // fieldIndex bumps after a successful PROVIDE_PARAMETER round.
    assert_int_equal(dataContext.tokenContext.fieldIndex, 1);
}

static void test_cp_continuation_plugin_partial_block_returns_handled(void **state) {
    (void) state;
    cp_setup_first_chunk();
    s_ctx.currentFieldPos = 4;
    s_ctx.currentFieldLength = 4 + CALLDATA_CHUNK_SIZE;
    s_ctx.commandLength = 10;  // less than blockSize -> partial copy
    dataContext.tokenContext.pluginStatus = ETH_PLUGIN_RESULT_SUCCESSFUL;
    assert_int_equal(custom_processor(&s_ctx), CUSTOM_HANDLED);
    // No PROVIDE_PARAMETER on partial block; fieldOffset advanced.
    assert_int_equal(dataContext.tokenContext.fieldOffset, 10);
}

static void test_cp_continuation_copy_failure_returns_fault(void **state) {
    (void) state;
    cp_setup_first_chunk();
    s_ctx.currentFieldPos = 4;
    s_ctx.currentFieldLength = 4 + CALLDATA_CHUNK_SIZE;
    s_ctx.commandLength = CALLDATA_CHUNK_SIZE;
    dataContext.tokenContext.pluginStatus = ETH_PLUGIN_RESULT_SUCCESSFUL;
    g_copy_tx_data_ret = false;
    assert_int_equal(custom_processor(&s_ctx), CUSTOM_FAULT);
}

// --- continuation chunk -- contractDetails, full block -> parameter UI ---

static void test_cp_continuation_contract_details_shows_parameter(void **state) {
    (void) state;
    cp_setup_first_chunk();
    s_ctx.currentFieldPos = 4;
    s_ctx.currentFieldLength = 4 + CALLDATA_CHUNK_SIZE;
    s_ctx.commandLength = CALLDATA_CHUNK_SIZE;
    g_n_storage_writable.contractDetails = true;
    dataContext.tokenContext.pluginStatus = ETH_PLUGIN_RESULT_UNAVAILABLE;
    assert_int_equal(custom_processor(&s_ctx), CUSTOM_SUSPENDED);
    assert_int_equal(g_ui_confirm_parameter_calls, 1);
    assert_int_equal(g_ui_confirm_selector_calls, 0);
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
        cmocka_unit_test_setup(test_cp_not_rlp_data_field_returns_not_handled, reset),
        cmocka_unit_test_setup(test_cp_empty_field_returns_not_handled, reset),
        cmocka_unit_test_setup(test_cp_new_contract_skips_plugin_dispatch, reset),
        cmocka_unit_test_setup(test_cp_short_field_returns_not_handled, reset),
        cmocka_unit_test_setup(test_cp_first_chunk_short_command_returns_fault, reset),
        cmocka_unit_test_setup(test_cp_plugin_init_error_returns_fault, reset),
        cmocka_unit_test_setup(test_cp_plugin_success_selector_only_returns_not_handled, reset),
        cmocka_unit_test_setup(test_cp_plugin_success_selector_copy_failure_returns_fault, reset),
        cmocka_unit_test_setup(test_cp_first_chunk_data_forbidden_returns_fault, reset),
        cmocka_unit_test_setup(test_cp_first_chunk_store_calldata_returns_not_handled, reset),
        cmocka_unit_test_setup(test_cp_first_chunk_no_contract_details_returns_not_handled, reset),
        cmocka_unit_test_setup(test_cp_first_chunk_contract_details_shows_selector, reset),
        cmocka_unit_test_setup(test_cp_continuation_store_calldata_returns_not_handled, reset),
        cmocka_unit_test_setup(test_cp_continuation_no_plugin_no_details_returns_not_handled,
                               reset),
        cmocka_unit_test_setup(test_cp_continuation_plugin_provide_param_success_returns_handled,
                               reset),
        cmocka_unit_test_setup(test_cp_continuation_plugin_partial_block_returns_handled, reset),
        cmocka_unit_test_setup(test_cp_continuation_copy_failure_returns_fault, reset),
        cmocka_unit_test_setup(test_cp_continuation_contract_details_shows_parameter, reset),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
