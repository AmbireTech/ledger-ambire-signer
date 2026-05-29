/**
 * @file test_eth_plugin_handler.c
 * @brief Unit tests for the plugin-handler orchestrator at
 *        src/plugins/eth_plugin_handler.c.
 *
 * This slice covers the safer entry points:
 *   - the six eth_plugin_prepare_* helpers that initialise the per-
 *     message structs the dispatcher hands to each plugin,
 *   - the chain_id mismatch defense inside
 *     eth_plugin_perform_init_default(): when the plugin was
 *     registered for a different chain than the tx is signing on,
 *     pluginStatus must be set to UNAVAILABLE without falling
 *     through to the contract / selector memcmp paths (which would
 *     app_exit() on mismatch).
 *
 * The full dispatcher in eth_plugin_call is out of scope here — it
 * pulls every internal plugin and the SDK exception macros (BEGIN_TRY
 * / TRY / CATCH_OTHER). It is exercised end-to-end by
 * test_erc20_plugin from the plugin's own perspective.
 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

#include "eth_plugin_handler.h"
#include "eth_plugin_internal.h"
#include "eth_plugin_interface.h"
#include "erc20_plugin.h"
#include "eip7002_plugin.h"
#include "eip7251_plugin.h"
#include "shared_context.h"

// =============================================================================
// Globals
// =============================================================================

strings_t strings;
static chain_config_t g_chainConfig = {.ticker = "ETH", .chain_id = 1, .coin_type = 60};
const chain_config_t *g_chain_config = &g_chainConfig;
const char g_unknown_ticker[] = "???";
txContext_t txContext;
tmpContent_t tmpContent;
tmpCtx_t tmpCtx;
dataContext_t dataContext;
pluginType_t pluginType = PLUGIN_TYPE_NONE;
volatile bool G_called_from_swap = false;
bool G_swap_checked = false;

// =============================================================================
// Wraps
// =============================================================================

static uint64_t g_tx_chain_id = 1;
uint64_t __wrap_get_tx_chain_id(void) {
    return g_tx_chain_id;
}

static const char *g_displayable_ticker = "ETH";
const char *__wrap_get_displayable_ticker(const uint64_t *chain_id,
                                          const chain_config_t *config,
                                          bool mainnet_only) {
    (void) chain_id;
    (void) config;
    (void) mainnet_only;
    return g_displayable_ticker;
}

static union extraInfo_t *g_asset_info_ret = NULL;
union extraInfo_t *__wrap_get_matching_asset_info(const uint64_t *chain_id,
                                                  const uint8_t *address) {
    (void) chain_id;
    (void) address;
    return g_asset_info_ret;
}

// =============================================================================
// Stubs for internal plugin _call functions (never reached by these tests).
// The dispatcher in eth_plugin_call references them at link time.
// =============================================================================
void erc20_plugin_call(eth_plugin_msg_t message, void *parameters) {
    (void) message;
    (void) parameters;
}
void eth2_plugin_call(eth_plugin_msg_t message, void *parameters) {
    (void) message;
    (void) parameters;
}
void erc721_plugin_call(eth_plugin_msg_t message, void *parameters) {
    (void) message;
    (void) parameters;
}
void erc1155_plugin_call(eth_plugin_msg_t message, void *parameters) {
    (void) message;
    (void) parameters;
}
void swap_with_calldata_plugin_call(eth_plugin_msg_t message, void *parameters) {
    (void) message;
    (void) parameters;
}
void eip7002_plugin_call(eth_plugin_msg_t message, void *parameters) {
    (void) message;
    (void) parameters;
}
void eip7251_plugin_call(eth_plugin_msg_t message, void *parameters) {
    (void) message;
    (void) parameters;
}

// app_exit is noreturn; we never reach it in our tests but the linker
// needs a symbol. If reached unexpectedly, abort the test process.
__attribute__((noreturn)) void app_exit(void) {
    fail_msg("app_exit() reached unexpectedly");
    while (1) {
    }
}

// SDK exception primitives referenced by the PLUGIN_TYPE_EXTERNAL
// dispatch branch (BEGIN_TRY / TRY / CATCH_OTHER macros). Stubs are
// sufficient since our tests don't exercise the external-plugin path.
try_context_t *try_context_get(void) {
    return NULL;
}
try_context_t *try_context_set(try_context_t *ctx) {
    (void) ctx;
    return NULL;
}
__attribute__((noreturn)) void os_longjmp(unsigned int e) {
    (void) e;
    fail_msg("os_longjmp() reached unexpectedly");
    while (1) {
    }
}
void os_lib_call(unsigned int *params) {
    (void) params;
}

// Plugin selectors referenced by INTERNAL_ETH_PLUGINS. Pulled in here so the
// linker resolves them — production headers declare them extern.
const uint8_t *const ERC20_SELECTORS[NUM_ERC20_SELECTORS] = {NULL, NULL};
#ifdef HAVE_ETH2
const uint8_t *const ETH2_SELECTORS[NUM_ETH2_SELECTORS] = {NULL};
const uint8_t *const ETH2_ADDRESSES[NUM_ETH2_ADDRESSES] = {NULL};
#endif
const uint8_t *const EIP7002_ADDRESSES[NUM_EIP7002_ADDRESSES] = {NULL};
const uint8_t *const EIP7251_ADDRESSES[NUM_EIP7251_ADDRESSES] = {NULL};

// =============================================================================
// Fixture
// =============================================================================

static int reset(void **state) {
    (void) state;
    memset(&dataContext, 0, sizeof(dataContext));
    memset(&tmpCtx, 0, sizeof(tmpCtx));
    memset(&tmpContent, 0, sizeof(tmpContent));
    pluginType = PLUGIN_TYPE_NONE;
    g_tx_chain_id = 1;
    g_asset_info_ret = NULL;
    return 0;
}

// =============================================================================
// eth_plugin_prepare_* helpers
// =============================================================================

static void test_prepare_init_populates_struct(void **state) {
    (void) state;
    ethPluginInitContract_t init;
    memset(&init, 0xFF, sizeof(init));  // pre-pollute
    const uint8_t selector[CALLDATA_SELECTOR_SIZE] = {0xDE, 0xAD, 0xBE, 0xEF};

    eth_plugin_prepare_init(&init, selector, 1234);
    assert_ptr_equal(init.selector, selector);
    assert_int_equal(init.dataSize, 1234);
    // Other fields should be zeroed by the explicit_bzero up front.
    assert_int_equal(init.result, 0);
    assert_null(init.bip32);
}

static void test_prepare_provide_parameter_populates_struct(void **state) {
    (void) state;
    ethPluginProvideParameter_t msg;
    memset(&msg, 0xFF, sizeof(msg));
    uint8_t param[32] = {0xAA};

    eth_plugin_prepare_provide_parameter(&msg, param, 36, 32);
    assert_ptr_equal(msg.parameter, param);
    assert_int_equal(msg.parameterOffset, 36);
    assert_int_equal(msg.parameter_size, 32);
    assert_int_equal(msg.result, 0);
}

static void test_prepare_finalize_zeroes_struct(void **state) {
    (void) state;
    ethPluginFinalize_t msg;
    memset(&msg, 0xFF, sizeof(msg));

    eth_plugin_prepare_finalize(&msg);
    assert_null(msg.tokenLookup1);
    assert_null(msg.tokenLookup2);
    assert_int_equal(msg.result, 0);
    assert_int_equal(msg.uiType, 0);
}

static void test_prepare_provide_info_zeroes_struct(void **state) {
    (void) state;
    ethPluginProvideInfo_t msg;
    memset(&msg, 0xFF, sizeof(msg));

    eth_plugin_prepare_provide_info(&msg);
    assert_null(msg.item1);
    assert_null(msg.item2);
    assert_int_equal(msg.result, 0);
}

static void test_prepare_query_contract_id_populates_struct(void **state) {
    (void) state;
    ethQueryContractID_t msg;
    memset(&msg, 0xFF, sizeof(msg));
    char name[16], version[16];

    eth_plugin_prepare_query_contract_id(&msg, name, sizeof(name), version, sizeof(version));
    assert_ptr_equal(msg.name, name);
    assert_int_equal(msg.nameLength, sizeof(name));
    assert_ptr_equal(msg.version, version);
    assert_int_equal(msg.versionLength, sizeof(version));
    assert_int_equal(msg.result, 0);
}

static void test_prepare_query_contract_ui_resolves_chain_and_assets(void **state) {
    (void) state;
    ethQueryContractUI_t msg;
    memset(&msg, 0xFF, sizeof(msg));
    char title[16], msg_buf[64];

    g_tx_chain_id = 137;  // Polygon
    g_displayable_ticker = "POL";
    static union extraInfo_t fake1;
    g_asset_info_ret = &fake1;  // both lookup calls return the same pointer

    eth_plugin_prepare_query_contract_ui(&msg, 2, title, sizeof(title), msg_buf, sizeof(msg_buf));
    assert_int_equal(msg.screenIndex, 2);
    assert_ptr_equal(msg.title, title);
    assert_ptr_equal(msg.msg, msg_buf);
    assert_int_equal(msg.titleLength, sizeof(title));
    assert_int_equal(msg.msgLength, sizeof(msg_buf));
    assert_string_equal(msg.network_ticker, "POL");
    assert_ptr_equal(msg.item1, &fake1);
    assert_ptr_equal(msg.item2, &fake1);
}

// =============================================================================
// eth_plugin_perform_init — chain_id mismatch defense
// =============================================================================

static void test_perform_init_default_chain_mismatch_marks_unavailable(void **state) {
    (void) state;
    // External plugin registered for chain 1, transaction is on chain 137.
    // The mismatch path must set pluginStatus = UNAVAILABLE and return
    // WITHOUT reaching the contract / selector memcmp branches (which
    // would abort the app on disagreement).
    dataContext.tokenContext.pluginChainId = 1;  // not PLUGIN_CHAIN_ID_ANY
    g_tx_chain_id = 137;
    dataContext.tokenContext.pluginStatus = ETH_PLUGIN_RESULT_OK;  // pre-existing
    pluginType = PLUGIN_TYPE_EXTERNAL;

    uint8_t contract[ADDRESS_LENGTH] = {0xAA};
    const uint8_t selector[CALLDATA_SELECTOR_SIZE] = {0xDE, 0xAD, 0xBE, 0xEF};
    ethPluginInitContract_t init = {.selector = selector};
    eth_plugin_perform_init(contract, &init);

    assert_int_equal(dataContext.tokenContext.pluginStatus, ETH_PLUGIN_RESULT_UNAVAILABLE);
}

static void test_perform_init_default_chain_any_bypasses_check(void **state) {
    (void) state;
    // When pluginChainId == PLUGIN_CHAIN_ID_ANY (0), the mismatch
    // check is skipped — the registration is chain-unbound. The contract
    // matches what's in tokenContext, so the path proceeds to the eth_
    // plugin_call which our stub leaves with the default UNAVAILABLE
    // status — that's fine for this assertion.
    dataContext.tokenContext.pluginChainId = PLUGIN_CHAIN_ID_ANY;
    g_tx_chain_id = 137;
    pluginType = PLUGIN_TYPE_EXTERNAL;

    uint8_t contract[ADDRESS_LENGTH] = {0xAA};
    memcpy(dataContext.tokenContext.contractAddress, contract, ADDRESS_LENGTH);
    const uint8_t selector[CALLDATA_SELECTOR_SIZE] = {0xDE, 0xAD, 0xBE, 0xEF};
    memcpy(dataContext.tokenContext.methodSelector, selector, CALLDATA_SELECTOR_SIZE);
    ethPluginInitContract_t init = {.selector = selector};
    // Just checking the call doesn't abort via app_exit — return value
    // depends on the (unstubbed) external plugin call.
    eth_plugin_perform_init(contract, &init);
}

static void test_perform_init_default_unresolved_tx_chain_defers_check(void **state) {
    (void) state;
    // When tx_chain_id == 0 (LEGACY tx, chain_id only known after V is
    // parsed), the mismatch check is deferred. The path falls through
    // to the contract/selector match.
    dataContext.tokenContext.pluginChainId = 1;
    g_tx_chain_id = 0;  // unresolved
    pluginType = PLUGIN_TYPE_EXTERNAL;

    uint8_t contract[ADDRESS_LENGTH] = {0xAA};
    memcpy(dataContext.tokenContext.contractAddress, contract, ADDRESS_LENGTH);
    const uint8_t selector[CALLDATA_SELECTOR_SIZE] = {0xDE, 0xAD, 0xBE, 0xEF};
    memcpy(dataContext.tokenContext.methodSelector, selector, CALLDATA_SELECTOR_SIZE);
    ethPluginInitContract_t init = {.selector = selector};
    eth_plugin_perform_init(contract, &init);

    // Did not get marked UNAVAILABLE by the chain check — it was deferred.
    // (The contract/selector match succeeded so the OK status is set
    // before dispatching to the external plugin.)
    assert_int_equal(dataContext.tokenContext.pluginStatus, ETH_PLUGIN_RESULT_OK);
}

// =============================================================================
// Runner
// =============================================================================

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup(test_prepare_init_populates_struct, reset),
        cmocka_unit_test_setup(test_prepare_provide_parameter_populates_struct, reset),
        cmocka_unit_test_setup(test_prepare_finalize_zeroes_struct, reset),
        cmocka_unit_test_setup(test_prepare_provide_info_zeroes_struct, reset),
        cmocka_unit_test_setup(test_prepare_query_contract_id_populates_struct, reset),
        cmocka_unit_test_setup(test_prepare_query_contract_ui_resolves_chain_and_assets, reset),
        cmocka_unit_test_setup(test_perform_init_default_chain_mismatch_marks_unavailable, reset),
        cmocka_unit_test_setup(test_perform_init_default_chain_any_bypasses_check, reset),
        cmocka_unit_test_setup(test_perform_init_default_unresolved_tx_chain_defers_check, reset),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
