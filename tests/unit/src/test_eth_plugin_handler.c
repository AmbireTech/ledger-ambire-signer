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
// Stubs for internal plugin _call functions. The dispatch tests below
// configure the result value the stub writes back via msg->result so
// every plugin call site is observable from the test.
// =============================================================================
static eth_plugin_result_t g_plugin_result = ETH_PLUGIN_RESULT_OK;
static int g_erc20_calls = 0;
static int g_erc721_calls = 0;
static int g_erc1155_calls = 0;
static int g_swap_with_calldata_calls = 0;

static void set_plugin_result(eth_plugin_msg_t message, void *parameters) {
    switch (message) {
        case ETH_PLUGIN_INIT_CONTRACT:
            ((ethPluginInitContract_t *) parameters)->result = g_plugin_result;
            break;
        case ETH_PLUGIN_PROVIDE_PARAMETER:
            ((ethPluginProvideParameter_t *) parameters)->result = g_plugin_result;
            break;
        case ETH_PLUGIN_FINALIZE:
            ((ethPluginFinalize_t *) parameters)->result = g_plugin_result;
            break;
        case ETH_PLUGIN_PROVIDE_INFO:
            ((ethPluginProvideInfo_t *) parameters)->result = g_plugin_result;
            break;
        case ETH_PLUGIN_QUERY_CONTRACT_ID:
            ((ethQueryContractID_t *) parameters)->result = g_plugin_result;
            break;
        case ETH_PLUGIN_QUERY_CONTRACT_UI:
            ((ethQueryContractUI_t *) parameters)->result = g_plugin_result;
            break;
        default:
            break;
    }
}

void erc20_plugin_call(eth_plugin_msg_t message, void *parameters) {
    g_erc20_calls++;
    set_plugin_result(message, parameters);
}
void eth2_plugin_call(eth_plugin_msg_t message, void *parameters) {
    (void) message;
    (void) parameters;
}
void erc721_plugin_call(eth_plugin_msg_t message, void *parameters) {
    g_erc721_calls++;
    set_plugin_result(message, parameters);
}
void erc1155_plugin_call(eth_plugin_msg_t message, void *parameters) {
    g_erc1155_calls++;
    set_plugin_result(message, parameters);
}
void swap_with_calldata_plugin_call(eth_plugin_msg_t message, void *parameters) {
    g_swap_with_calldata_calls++;
    set_plugin_result(message, parameters);
}
void eip7002_plugin_call(eth_plugin_msg_t message, void *parameters) {
    (void) message;
    (void) parameters;
}
void eip7251_plugin_call(eth_plugin_msg_t message, void *parameters) {
    (void) message;
    (void) parameters;
}

// app_exit is noreturn. Most tests must NEVER reach it (silent
// fall-through to app_exit would be a security bug). The defensive-
// guard tests below set g_expect_app_exit + a jmp_buf so the noreturn
// contract can be unwound back to the test body.
static bool g_expect_app_exit = false;
static bool g_app_exit_reached = false;
static jmp_buf g_app_exit_jmp;
__attribute__((noreturn)) void app_exit(void) {
    if (g_expect_app_exit) {
        g_app_exit_reached = true;
        longjmp(g_app_exit_jmp, 1);
    }
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

// Plugin selectors / addresses referenced by INTERNAL_ETH_PLUGINS.
// Production code links these against the actual plugin .c files; here
// we provide concrete byte arrays so the matching_selector /
// matching_address loops inside eth_plugin_perform_init_old_internal
// don't memcmp against NULL pointers (UB).
static const uint8_t g_erc20_transfer_selector[4] = {0xA9, 0x05, 0x9C, 0xBB};
static const uint8_t g_erc20_approve_selector[4] = {0x09, 0x5E, 0xA7, 0xB3};
const uint8_t *const ERC20_SELECTORS[NUM_ERC20_SELECTORS] = {
    g_erc20_transfer_selector,
    g_erc20_approve_selector,
};
#ifdef HAVE_ETH2
static const uint8_t g_eth2_selector[4] = {0x22, 0x89, 0x51, 0x18};
static const uint8_t g_eth2_address[ADDRESS_LENGTH] = {0xE2};
const uint8_t *const ETH2_SELECTORS[NUM_ETH2_SELECTORS] = {g_eth2_selector};
const uint8_t *const ETH2_ADDRESSES[NUM_ETH2_ADDRESSES] = {g_eth2_address};
#endif
static const uint8_t g_eip7002_address[ADDRESS_LENGTH] = {0x70};
static const uint8_t g_eip7251_address[ADDRESS_LENGTH] = {0x72};
const uint8_t *const EIP7002_ADDRESSES[NUM_EIP7002_ADDRESSES] = {g_eip7002_address};
const uint8_t *const EIP7251_ADDRESSES[NUM_EIP7251_ADDRESSES] = {g_eip7251_address};

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
    g_plugin_result = ETH_PLUGIN_RESULT_OK;
    g_erc20_calls = 0;
    g_erc721_calls = 0;
    g_erc1155_calls = 0;
    g_swap_with_calldata_calls = 0;
    // Default: cached plugin available, so eth_plugin_call doesn't bail
    // on the "cached but unavailable" early-return at the top of the
    // function.
    dataContext.tokenContext.pluginStatus = ETH_PLUGIN_RESULT_OK;
    g_expect_app_exit = false;
    g_app_exit_reached = false;
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
// Defensive panics — these guards (app_exit) are the *last line of
// defense* against state-corruption between the plugin INIT phase
// and the eth_plugin_perform_init() entry. A silent fall-through
// would let a registered plugin be invoked on the wrong contract /
// selector, so we must confirm they actually trip.
// =============================================================================

static void test_perform_init_default_contract_mismatch_panics(void **state) {
    (void) state;
    // Plugin was registered for contract A; the transaction now claims
    // contract B. app_exit must fire — anything else lets the wrong
    // plugin take over the rendering.
    dataContext.tokenContext.pluginChainId = PLUGIN_CHAIN_ID_ANY;
    pluginType = PLUGIN_TYPE_EXTERNAL;
    const uint8_t registered_contract[ADDRESS_LENGTH] = {[0] = 0xAA};
    const uint8_t selector[CALLDATA_SELECTOR_SIZE] = {0xDE, 0xAD, 0xBE, 0xEF};
    memcpy(dataContext.tokenContext.contractAddress, registered_contract, ADDRESS_LENGTH);
    memcpy(dataContext.tokenContext.methodSelector, selector, CALLDATA_SELECTOR_SIZE);

    uint8_t observed_contract[ADDRESS_LENGTH] = {[0] = 0xBB};  // different
    ethPluginInitContract_t init = {.selector = selector};

    g_expect_app_exit = true;
    if (setjmp(g_app_exit_jmp) == 0) {
        eth_plugin_perform_init(observed_contract, &init);
        fail_msg("app_exit not reached on contract mismatch");
    }
    assert_true(g_app_exit_reached);
}

static void test_perform_init_default_selector_mismatch_panics(void **state) {
    (void) state;
    // Plugin registered for selector X; tx now uses selector Y.
    dataContext.tokenContext.pluginChainId = PLUGIN_CHAIN_ID_ANY;
    pluginType = PLUGIN_TYPE_EXTERNAL;
    uint8_t contract[ADDRESS_LENGTH] = {[0] = 0xAA};
    const uint8_t registered_selector[CALLDATA_SELECTOR_SIZE] = {0xDE, 0xAD, 0xBE, 0xEF};
    memcpy(dataContext.tokenContext.contractAddress, contract, ADDRESS_LENGTH);
    memcpy(dataContext.tokenContext.methodSelector, registered_selector, CALLDATA_SELECTOR_SIZE);

    const uint8_t observed_selector[CALLDATA_SELECTOR_SIZE] = {0xCA, 0xFE, 0xBA, 0xBE};
    ethPluginInitContract_t init = {.selector = observed_selector};

    g_expect_app_exit = true;
    if (setjmp(g_app_exit_jmp) == 0) {
        eth_plugin_perform_init(contract, &init);
        fail_msg("app_exit not reached on selector mismatch");
    }
    assert_true(g_app_exit_reached);
}

static void test_perform_init_unsupported_plugin_type_panics(void **state) {
    (void) state;
    // pluginType outside every case → default branch must app_exit.
    pluginType = (pluginType_t) 0x7F;  // arbitrary unknown value

    uint8_t contract[ADDRESS_LENGTH] = {0};
    const uint8_t selector[CALLDATA_SELECTOR_SIZE] = {0};
    ethPluginInitContract_t init = {.selector = selector};

    g_expect_app_exit = true;
    if (setjmp(g_app_exit_jmp) == 0) {
        eth_plugin_perform_init(contract, &init);
        fail_msg("app_exit not reached on unsupported pluginType");
    }
    assert_true(g_app_exit_reached);
}

// =============================================================================
// eth_plugin_call — dispatcher per pluginType + per method + result check
// =============================================================================

static void test_call_cached_unavailable_short_circuits(void **state) {
    (void) state;
    // When the cached pluginStatus is UNAVAILABLE, the call must return
    // that status immediately without dispatching to any plugin.
    dataContext.tokenContext.pluginStatus = ETH_PLUGIN_RESULT_UNAVAILABLE;
    ethPluginInitContract_t msg = {0};
    eth_plugin_result_t r = eth_plugin_call(ETH_PLUGIN_INIT_CONTRACT, &msg);
    assert_int_equal(r, ETH_PLUGIN_RESULT_UNAVAILABLE);
    assert_int_equal(g_erc20_calls, 0);
}

static void test_call_unknown_method_returns_unavailable(void **state) {
    (void) state;
    pluginType = PLUGIN_TYPE_OLD_INTERNAL;
    // Some method outside the switch cases.
    eth_plugin_result_t r = eth_plugin_call((eth_plugin_msg_t) 0xFFFF, NULL);
    assert_int_equal(r, ETH_PLUGIN_RESULT_UNAVAILABLE);
}

static void test_call_erc721_dispatches(void **state) {
    (void) state;
    pluginType = PLUGIN_TYPE_ERC721;
    ethPluginInitContract_t msg = {0};
    eth_plugin_call(ETH_PLUGIN_INIT_CONTRACT, &msg);
    assert_int_equal(g_erc721_calls, 1);
    assert_int_equal(g_erc20_calls, 0);
}

static void test_call_erc1155_dispatches(void **state) {
    (void) state;
    pluginType = PLUGIN_TYPE_ERC1155;
    ethPluginInitContract_t msg = {0};
    eth_plugin_call(ETH_PLUGIN_INIT_CONTRACT, &msg);
    assert_int_equal(g_erc1155_calls, 1);
}

static void test_call_swap_with_calldata_dispatches(void **state) {
    (void) state;
    pluginType = PLUGIN_TYPE_SWAP_WITH_CALLDATA;
    ethPluginInitContract_t msg = {0};
    eth_plugin_call(ETH_PLUGIN_INIT_CONTRACT, &msg);
    assert_int_equal(g_swap_with_calldata_calls, 1);
}

static void test_call_old_internal_routes_by_alias(void **state) {
    (void) state;
    pluginType = PLUGIN_TYPE_OLD_INTERNAL;
    strlcpy(dataContext.tokenContext.pluginName,
            "-erc20",
            sizeof(dataContext.tokenContext.pluginName));
    ethPluginInitContract_t msg = {0};
    eth_plugin_call(ETH_PLUGIN_INIT_CONTRACT, &msg);
    assert_int_equal(g_erc20_calls, 1);
}

static void test_call_unsupported_plugin_type_returns_error(void **state) {
    (void) state;
    pluginType = (pluginType_t) 0xFF;
    ethPluginInitContract_t msg = {0};
    eth_plugin_result_t r = eth_plugin_call(ETH_PLUGIN_INIT_CONTRACT, &msg);
    assert_int_equal(r, ETH_PLUGIN_RESULT_ERROR);
}

// --- Result-check matrix ---

static void test_call_init_error_result_propagates(void **state) {
    (void) state;
    pluginType = PLUGIN_TYPE_ERC721;
    g_plugin_result = ETH_PLUGIN_RESULT_ERROR;
    ethPluginInitContract_t msg = {0};
    eth_plugin_result_t r = eth_plugin_call(ETH_PLUGIN_INIT_CONTRACT, &msg);
    assert_int_equal(r, ETH_PLUGIN_RESULT_ERROR);
}

static void test_call_init_unknown_result_returns_unavailable(void **state) {
    (void) state;
    pluginType = PLUGIN_TYPE_ERC721;
    g_plugin_result = ETH_PLUGIN_RESULT_FALLBACK;  // not OK/ERROR for INIT
    ethPluginInitContract_t msg = {0};
    eth_plugin_result_t r = eth_plugin_call(ETH_PLUGIN_INIT_CONTRACT, &msg);
    assert_int_equal(r, ETH_PLUGIN_RESULT_UNAVAILABLE);
}

static void test_call_provide_parameter_fallback_passes(void **state) {
    (void) state;
    pluginType = PLUGIN_TYPE_ERC721;
    g_plugin_result = ETH_PLUGIN_RESULT_FALLBACK;
    ethPluginProvideParameter_t msg = {0};
    // For PROVIDE_PARAMETER, FALLBACK is accepted as OK by the
    // dispatcher (it's treated the same as OK at the return point).
    eth_plugin_result_t r = eth_plugin_call(ETH_PLUGIN_PROVIDE_PARAMETER, &msg);
    assert_int_equal(r, ETH_PLUGIN_RESULT_OK);
}

static void test_call_finalize_ok(void **state) {
    (void) state;
    pluginType = PLUGIN_TYPE_ERC721;
    ethPluginFinalize_t msg = {0};
    eth_plugin_result_t r = eth_plugin_call(ETH_PLUGIN_FINALIZE, &msg);
    assert_int_equal(r, ETH_PLUGIN_RESULT_OK);
}

static void test_call_provide_info_error_propagates(void **state) {
    (void) state;
    pluginType = PLUGIN_TYPE_ERC721;
    g_plugin_result = ETH_PLUGIN_RESULT_ERROR;
    ethPluginProvideInfo_t msg = {0};
    eth_plugin_result_t r = eth_plugin_call(ETH_PLUGIN_PROVIDE_INFO, &msg);
    assert_int_equal(r, ETH_PLUGIN_RESULT_ERROR);
}

static void test_call_query_contract_id_error_propagates(void **state) {
    (void) state;
    pluginType = PLUGIN_TYPE_ERC721;
    g_plugin_result = ETH_PLUGIN_RESULT_ERROR;
    ethQueryContractID_t msg = {0};
    eth_plugin_result_t r = eth_plugin_call(ETH_PLUGIN_QUERY_CONTRACT_ID, &msg);
    assert_int_equal(r, ETH_PLUGIN_RESULT_ERROR);
}

static void test_call_query_contract_ui_ok(void **state) {
    (void) state;
    pluginType = PLUGIN_TYPE_ERC721;
    g_plugin_result = ETH_PLUGIN_RESULT_OK;
    ethQueryContractUI_t msg = {0};
    eth_plugin_result_t r = eth_plugin_call(ETH_PLUGIN_QUERY_CONTRACT_UI, &msg);
    assert_int_equal(r, ETH_PLUGIN_RESULT_OK);
}

// =============================================================================
// eth_plugin_perform_init — PLUGIN_TYPE_NONE path (old_internal lookup)
// =============================================================================

static void test_perform_init_swap_with_calldata_sets_ok(void **state) {
    (void) state;
    pluginType = PLUGIN_TYPE_SWAP_WITH_CALLDATA;
    uint8_t contract[ADDRESS_LENGTH] = {0xAA};
    const uint8_t selector[CALLDATA_SELECTOR_SIZE] = {0xDE, 0xAD, 0xBE, 0xEF};
    ethPluginInitContract_t init = {.selector = selector};
    eth_plugin_perform_init(contract, &init);
    // The swap_with_calldata branch immediately marks the plugin OK.
    // The function returns OK without calling the plugin's init.
    assert_int_equal(dataContext.tokenContext.pluginStatus, ETH_PLUGIN_RESULT_OK);
}

// =============================================================================
// eth_plugin_perform_init_old_internal — INTERNAL_ETH_PLUGINS lookup.
//
// The PLUGIN_TYPE_NONE path walks INTERNAL_ETH_PLUGINS trying every
// registered plugin's (address-list, selector-list) tuple. A regression
// that returned true unconditionally would let any contract / selector
// claim the ERC-20 alias — these tests pin the actual match contract.
// =============================================================================

static void test_perform_init_none_matches_erc20_transfer(void **state) {
    (void) state;
    // ERC-20 plugin entry has addresses=NULL (any contract) and
    // selectors={transfer, approve}. Match the first selector.
    pluginType = PLUGIN_TYPE_NONE;
    uint8_t contract[ADDRESS_LENGTH] = {0};
    contract[0] = 0xAB;
    ethPluginInitContract_t init = {.selector = g_erc20_transfer_selector};

    eth_plugin_perform_init(contract, &init);

    // The function copies the plugin alias into tokenContext.pluginName
    // and switches pluginType to OLD_INTERNAL.
    assert_int_equal(pluginType, PLUGIN_TYPE_OLD_INTERNAL);
    assert_string_equal(dataContext.tokenContext.pluginName, "-erc20");
    assert_int_equal(dataContext.tokenContext.pluginStatus, ETH_PLUGIN_RESULT_OK);
}

static void test_perform_init_none_matches_eip7002_by_address(void **state) {
    (void) state;
    // EIP-7002 entry has addresses={g_eip7002_address} (constraint),
    // selectors=NULL (any selector → matching_selector returns true).
    pluginType = PLUGIN_TYPE_NONE;
    uint8_t contract[ADDRESS_LENGTH];
    memcpy(contract, g_eip7002_address, ADDRESS_LENGTH);
    const uint8_t unrelated_selector[CALLDATA_SELECTOR_SIZE] = {0xCA, 0xFE, 0xBA, 0xBE};
    ethPluginInitContract_t init = {.selector = unrelated_selector};

    eth_plugin_perform_init(contract, &init);

    assert_int_equal(pluginType, PLUGIN_TYPE_OLD_INTERNAL);
    assert_string_equal(dataContext.tokenContext.pluginName, "-eip7002");
}

static void test_perform_init_none_no_match_unavailable(void **state) {
    (void) state;
    // Contract not in any address-bound plugin, selector not in any
    // selector-bound plugin → old_internal returns false. Then
    // contract_address != NULL and G_called_from_swap=false → returns
    // ETH_PLUGIN_RESULT_UNAVAILABLE without disturbing pluginType.
    pluginType = PLUGIN_TYPE_NONE;
    G_called_from_swap = false;
    uint8_t contract[ADDRESS_LENGTH];
    memset(contract, 0xCD, ADDRESS_LENGTH);  // matches no plugin address
    const uint8_t selector[CALLDATA_SELECTOR_SIZE] = {0xCA, 0xFE, 0xBA, 0xBE};
    ethPluginInitContract_t init = {.selector = selector};

    eth_plugin_perform_init(contract, &init);

    // Stayed NONE (no match overwrote it), default status UNAVAILABLE.
    assert_int_equal(pluginType, PLUGIN_TYPE_NONE);
    assert_int_equal(dataContext.tokenContext.pluginStatus, ETH_PLUGIN_RESULT_UNAVAILABLE);
}

static void test_perform_init_none_no_match_swap_mode_returns_error(void **state) {
    (void) state;
    // Same as above but under swap mode. The post-switch block must
    // reject explicitly (RESULT_ERROR) instead of returning UNAVAILABLE:
    // swap flows can't fall back to a generic "I don't know this
    // contract" rendering — the user is then signing a contract
    // call blind during an exchange and that path is unsafe.
    pluginType = PLUGIN_TYPE_NONE;
    G_called_from_swap = true;
    uint8_t contract[ADDRESS_LENGTH];
    memset(contract, 0xCD, ADDRESS_LENGTH);
    const uint8_t selector[CALLDATA_SELECTOR_SIZE] = {0xCA, 0xFE, 0xBA, 0xBE};
    ethPluginInitContract_t init = {.selector = selector};

    eth_plugin_result_t r = eth_plugin_perform_init(contract, &init);
    assert_int_equal(r, ETH_PLUGIN_RESULT_ERROR);

    // Restore for next test.
    G_called_from_swap = false;
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
        cmocka_unit_test_setup(test_perform_init_default_contract_mismatch_panics, reset),
        cmocka_unit_test_setup(test_perform_init_default_selector_mismatch_panics, reset),
        cmocka_unit_test_setup(test_perform_init_unsupported_plugin_type_panics, reset),
        // Dispatcher tests
        cmocka_unit_test_setup(test_call_cached_unavailable_short_circuits, reset),
        cmocka_unit_test_setup(test_call_unknown_method_returns_unavailable, reset),
        cmocka_unit_test_setup(test_call_erc721_dispatches, reset),
        cmocka_unit_test_setup(test_call_erc1155_dispatches, reset),
        cmocka_unit_test_setup(test_call_swap_with_calldata_dispatches, reset),
        cmocka_unit_test_setup(test_call_old_internal_routes_by_alias, reset),
        cmocka_unit_test_setup(test_call_unsupported_plugin_type_returns_error, reset),
        cmocka_unit_test_setup(test_call_init_error_result_propagates, reset),
        cmocka_unit_test_setup(test_call_init_unknown_result_returns_unavailable, reset),
        cmocka_unit_test_setup(test_call_provide_parameter_fallback_passes, reset),
        cmocka_unit_test_setup(test_call_finalize_ok, reset),
        cmocka_unit_test_setup(test_call_provide_info_error_propagates, reset),
        cmocka_unit_test_setup(test_call_query_contract_id_error_propagates, reset),
        cmocka_unit_test_setup(test_call_query_contract_ui_ok, reset),
        cmocka_unit_test_setup(test_perform_init_swap_with_calldata_sets_ok, reset),
        cmocka_unit_test_setup(test_perform_init_none_matches_erc20_transfer, reset),
        cmocka_unit_test_setup(test_perform_init_none_matches_eip7002_by_address, reset),
        cmocka_unit_test_setup(test_perform_init_none_no_match_unavailable, reset),
        cmocka_unit_test_setup(test_perform_init_none_no_match_swap_mode_returns_error, reset),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
