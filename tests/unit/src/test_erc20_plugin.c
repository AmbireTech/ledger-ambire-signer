/**
 * @file test_erc20_plugin.c
 * @brief Unit tests for the ERC-20 plugin at
 *        src/plugins/erc20/erc20_plugin.c.
 *
 * The plugin dispatches on eth_plugin_msg_t and walks the standard
 * Ethereum-app plugin lifecycle (INIT → PROVIDE_PARAMETER ×N →
 * FINALIZE → PROVIDE_INFO → QUERY_CONTRACT_ID / QUERY_CONTRACT_UI).
 *
 * Two recent security fixes drive parts of this suite:
 *   - 816010e4 ("Zero ERC-20 plugin context and require both ABI
 *     fields before review") — INIT now explicit_bzeroes the whole
 *     context, and FINALIZE refuses unless BOTH destination_parsed
 *     and amount_parsed are true. Regression tests pin both.
 *   - PR #1038 ("ERC20 swap flow accepts approve() as a valid
 *     transfer") — title is slightly misleading: in swap mode the
 *     plugin now REJECTS approve() and any extra_data. Two
 *     regression tests pin both rejections.
 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

#include "erc20_plugin.h"
#include "eth_plugin_interface.h"
#include "eth_plugin_internal.h"
#include "shared_context.h"
#include "token_info.h"
#include "eth_swap_utils.h"
#include "wraps.h"

// =============================================================================
// erc20_parameters_t mirror
// =============================================================================
// The real struct is declared `static`-equivalent inside erc20_plugin.c (no
// public header). Mirror its layout here so the tests can poke fields by
// name. If the production struct ever changes, this declaration must be
// updated in lockstep — there is no compile-time guard against drift.

#define MAX_CONTRACT_NAME_LEN_TEST 15
#define MAX_EXTRA_DATA_CHUNKS_TEST 2

typedef struct {
    uint8_t selectorIndex;
    uint8_t destinationAddress[ADDRESS_LENGTH];
    uint8_t amount[INT256_LENGTH];
    char ticker[MAX_TICKER_LEN];
    uint8_t decimals;
    char contract_name[MAX_CONTRACT_NAME_LEN_TEST];
    char extra_data[MAX_EXTRA_DATA_CHUNKS_TEST * CALLDATA_CHUNK_SIZE];
    uint8_t extra_data_len;
    bool destination_parsed;
    bool amount_parsed;
} erc20_parameters_t;

// =============================================================================
// Globals the module reads
// =============================================================================

pluginType_t pluginType = PLUGIN_TYPE_OLD_INTERNAL;

// =============================================================================
// Wraps
// =============================================================================

// get_tx_chain_id is wrapped in mocks/mock.c; state via g_tx_chain_id
// from wraps.h.

static const s_token_info *g_token_info_ret = NULL;
const s_token_info *__wrap_get_matching_token_info(const uint64_t *chain_id, const uint8_t *addr) {
    (void) chain_id;
    (void) addr;
    return g_token_info_ret;
}

// swap_check_* abort the app on mismatch. For tests we want them to be
// observable no-ops so the FINALIZE swap branch can be exercised end-
// to-end without hitting app_exit().
static int g_swap_check_dest_calls = 0;
static int g_swap_check_amount_calls = 0;
bool __wrap_swap_check_destination(const char *destination) {
    (void) destination;
    g_swap_check_dest_calls++;
    return true;
}
bool __wrap_swap_check_amount(const char *amount) {
    (void) amount;
    g_swap_check_amount_calls++;
    return true;
}

// =============================================================================
// Fixtures
// =============================================================================

static erc20_parameters_t g_ctx;

// Selectors copied from erc20_plugin.c (a duplicate but the source is private).
static const uint8_t TRANSFER_SEL[CALLDATA_SELECTOR_SIZE] = {0xa9, 0x05, 0x9c, 0xbb};
static const uint8_t APPROVE_SEL[CALLDATA_SELECTOR_SIZE] = {0x09, 0x5e, 0xa7, 0xb3};
static const uint8_t UNKNOWN_SEL[CALLDATA_SELECTOR_SIZE] = {0xDE, 0xAD, 0xBE, 0xEF};

static int reset(void **state) {
    (void) state;
    memset(&g_tx_content, 0, sizeof(g_tx_content));
    memset(&g_ctx, 0, sizeof(g_ctx));
    memset(&strings, 0, sizeof(strings));
    G_called_from_swap = false;
    G_swap_checked = false;
    g_tx_chain_id = 1;
    g_token_info_ret = NULL;
    g_swap_check_dest_calls = 0;
    g_swap_check_amount_calls = 0;
    return 0;
}

static void init_with_selector(const uint8_t *selector) {
    ethPluginInitContract_t msg = {0};
    msg.txContent = &g_tx_content;
    msg.selector = selector;
    msg.pluginContext = (uint8_t *) &g_ctx;
    erc20_plugin_call(ETH_PLUGIN_INIT_CONTRACT, &msg);
}

// =============================================================================
// ETH_PLUGIN_INIT_CONTRACT
// =============================================================================

static void test_init_transfer_selector_ok(void **state) {
    (void) state;
    // 816010e4 defense — pre-pollute the context to verify INIT wipes it
    memset(g_ctx.destinationAddress, 0xAA, ADDRESS_LENGTH);
    memset(g_ctx.amount, 0xBB, INT256_LENGTH);
    g_ctx.destination_parsed = true;
    g_ctx.amount_parsed = true;

    ethPluginInitContract_t msg = {0};
    msg.txContent = &g_tx_content;
    msg.selector = TRANSFER_SEL;
    msg.pluginContext = (uint8_t *) &g_ctx;
    erc20_plugin_call(ETH_PLUGIN_INIT_CONTRACT, &msg);

    assert_int_equal(msg.result, ETH_PLUGIN_RESULT_OK);
    assert_int_equal(g_ctx.selectorIndex, 0);  // ERC20_TRANSFER
    // The pre-existing pollution must be gone.
    static const uint8_t zero_addr[ADDRESS_LENGTH] = {0};
    assert_memory_equal(g_ctx.destinationAddress, zero_addr, ADDRESS_LENGTH);
    assert_false(g_ctx.destination_parsed);
    assert_false(g_ctx.amount_parsed);
}

static void test_init_approve_selector_ok(void **state) {
    (void) state;
    init_with_selector(APPROVE_SEL);
    // selectorIndex = 1 after wipe + match on APPROVE.
    // result is set on the local msg, so we re-call with explicit msg here:
    ethPluginInitContract_t msg = {0};
    msg.txContent = &g_tx_content;
    msg.selector = APPROVE_SEL;
    msg.pluginContext = (uint8_t *) &g_ctx;
    erc20_plugin_call(ETH_PLUGIN_INIT_CONTRACT, &msg);
    assert_int_equal(msg.result, ETH_PLUGIN_RESULT_OK);
    assert_int_equal(g_ctx.selectorIndex, 1);  // ERC20_APPROVE
}

static void test_init_unknown_selector_rejected(void **state) {
    (void) state;
    ethPluginInitContract_t msg = {0};
    msg.txContent = &g_tx_content;
    msg.selector = UNKNOWN_SEL;
    msg.pluginContext = (uint8_t *) &g_ctx;
    erc20_plugin_call(ETH_PLUGIN_INIT_CONTRACT, &msg);
    assert_int_equal(msg.result, ETH_PLUGIN_RESULT_ERROR);
}

static void test_init_nonzero_tx_value_rejected(void **state) {
    (void) state;
    // The plugin enforces ETH amount == 0 (an ERC-20 call should never
    // also send native value).
    g_tx_content.value.value[31] = 0x01;
    ethPluginInitContract_t msg = {0};
    msg.txContent = &g_tx_content;
    msg.selector = TRANSFER_SEL;
    msg.pluginContext = (uint8_t *) &g_ctx;
    erc20_plugin_call(ETH_PLUGIN_INIT_CONTRACT, &msg);
    assert_int_equal(msg.result, ETH_PLUGIN_RESULT_ERROR);
}

// =============================================================================
// ETH_PLUGIN_PROVIDE_PARAMETER
// =============================================================================

static void test_provide_destination_parameter(void **state) {
    (void) state;
    ethPluginProvideParameter_t msg = {0};
    uint8_t param[CALLDATA_CHUNK_SIZE] = {0};
    // Address is right-aligned in the 32-byte param chunk.
    for (int i = 0; i < ADDRESS_LENGTH; ++i) {
        param[CALLDATA_CHUNK_SIZE - ADDRESS_LENGTH + i] = (uint8_t) (i + 0x10);
    }
    msg.parameter = param;
    msg.parameterOffset = CALLDATA_SELECTOR_SIZE;
    msg.parameter_size = CALLDATA_CHUNK_SIZE;
    msg.pluginContext = (uint8_t *) &g_ctx;
    erc20_plugin_call(ETH_PLUGIN_PROVIDE_PARAMETER, &msg);

    assert_int_equal(msg.result, ETH_PLUGIN_RESULT_OK);
    assert_true(g_ctx.destination_parsed);
    for (int i = 0; i < ADDRESS_LENGTH; ++i) {
        assert_int_equal(g_ctx.destinationAddress[i], (uint8_t) (i + 0x10));
    }
}

static void test_provide_amount_parameter(void **state) {
    (void) state;
    ethPluginProvideParameter_t msg = {0};
    uint8_t param[CALLDATA_CHUNK_SIZE];
    for (int i = 0; i < CALLDATA_CHUNK_SIZE; ++i) param[i] = (uint8_t) i;
    msg.parameter = param;
    msg.parameterOffset = CALLDATA_SELECTOR_SIZE + CALLDATA_CHUNK_SIZE;
    msg.parameter_size = CALLDATA_CHUNK_SIZE;
    msg.pluginContext = (uint8_t *) &g_ctx;
    erc20_plugin_call(ETH_PLUGIN_PROVIDE_PARAMETER, &msg);

    assert_int_equal(msg.result, ETH_PLUGIN_RESULT_OK);
    assert_true(g_ctx.amount_parsed);
    assert_memory_equal(g_ctx.amount, param, CALLDATA_CHUNK_SIZE);
}

static void test_provide_extra_data_parameter(void **state) {
    (void) state;
    ethPluginProvideParameter_t msg = {0};
    uint8_t param[CALLDATA_CHUNK_SIZE];
    for (int i = 0; i < CALLDATA_CHUNK_SIZE; ++i) param[i] = (uint8_t) (i + 0x40);
    msg.parameter = param;
    msg.parameterOffset = CALLDATA_SELECTOR_SIZE + (CALLDATA_CHUNK_SIZE * 2);
    msg.parameter_size = CALLDATA_CHUNK_SIZE;
    msg.pluginContext = (uint8_t *) &g_ctx;
    erc20_plugin_call(ETH_PLUGIN_PROVIDE_PARAMETER, &msg);

    assert_int_equal(msg.result, ETH_PLUGIN_RESULT_OK);
    assert_int_equal(g_ctx.extra_data_len, CALLDATA_CHUNK_SIZE);
    assert_memory_equal(g_ctx.extra_data, param, CALLDATA_CHUNK_SIZE);
}

static void test_provide_extra_data_overflow_rejected(void **state) {
    (void) state;
    ethPluginProvideParameter_t msg = {0};
    uint8_t param[CALLDATA_CHUNK_SIZE] = {0};
    // Offset just past the MAX_EXTRA_DATA_CHUNKS (2) window.
    msg.parameter = param;
    msg.parameterOffset = CALLDATA_SELECTOR_SIZE + CALLDATA_CHUNK_SIZE + (3 * CALLDATA_CHUNK_SIZE);
    msg.parameter_size = CALLDATA_CHUNK_SIZE;
    msg.pluginContext = (uint8_t *) &g_ctx;
    g_ctx.extra_data_len = 5;  // pre-existing
    erc20_plugin_call(ETH_PLUGIN_PROVIDE_PARAMETER, &msg);

    assert_int_equal(msg.result, ETH_PLUGIN_RESULT_ERROR);
    // The plugin resets extra_data_len when it refuses the overflow.
    assert_int_equal(g_ctx.extra_data_len, 0);
}

// =============================================================================
// ETH_PLUGIN_FINALIZE — 816010e4 "both required" guard
// =============================================================================

static void test_finalize_missing_destination_rejected(void **state) {
    (void) state;
    g_ctx.amount_parsed = true;
    // destination_parsed stays false
    ethPluginFinalize_t msg = {0};
    msg.txContent = &g_tx_content;
    msg.pluginContext = (uint8_t *) &g_ctx;
    erc20_plugin_call(ETH_PLUGIN_FINALIZE, &msg);
    assert_int_equal(msg.result, ETH_PLUGIN_RESULT_ERROR);
}

static void test_finalize_missing_amount_rejected(void **state) {
    (void) state;
    g_ctx.destination_parsed = true;
    ethPluginFinalize_t msg = {0};
    msg.txContent = &g_tx_content;
    msg.pluginContext = (uint8_t *) &g_ctx;
    erc20_plugin_call(ETH_PLUGIN_FINALIZE, &msg);
    assert_int_equal(msg.result, ETH_PLUGIN_RESULT_ERROR);
}

static void test_finalize_both_present_non_swap_ok(void **state) {
    (void) state;
    g_ctx.destination_parsed = true;
    g_ctx.amount_parsed = true;
    G_called_from_swap = false;

    ethPluginFinalize_t msg = {0};
    msg.txContent = &g_tx_content;
    msg.pluginContext = (uint8_t *) &g_ctx;
    erc20_plugin_call(ETH_PLUGIN_FINALIZE, &msg);

    assert_int_equal(msg.result, ETH_PLUGIN_RESULT_OK);
    assert_int_equal(msg.uiType, ETH_UI_TYPE_GENERIC);
    assert_int_equal(msg.numScreens, 2);
    assert_ptr_equal(msg.tokenLookup1, g_tx_content.destination);
}

static void test_finalize_with_extra_data_bumps_numscreens(void **state) {
    (void) state;
    g_ctx.destination_parsed = true;
    g_ctx.amount_parsed = true;
    g_ctx.extra_data_len = 10;

    ethPluginFinalize_t msg = {0};
    msg.txContent = &g_tx_content;
    msg.pluginContext = (uint8_t *) &g_ctx;
    erc20_plugin_call(ETH_PLUGIN_FINALIZE, &msg);
    assert_int_equal(msg.result, ETH_PLUGIN_RESULT_OK);
    assert_int_equal(msg.numScreens, 3);
}

// =============================================================================
// ETH_PLUGIN_FINALIZE — PR #1038 swap-mode restrictions
// =============================================================================

static void test_finalize_swap_approve_rejected(void **state) {
    (void) state;
    g_ctx.destination_parsed = true;
    g_ctx.amount_parsed = true;
    g_ctx.selectorIndex = 1;  // ERC20_APPROVE
    G_called_from_swap = true;

    ethPluginFinalize_t msg = {0};
    msg.txContent = &g_tx_content;
    msg.pluginContext = (uint8_t *) &g_ctx;
    erc20_plugin_call(ETH_PLUGIN_FINALIZE, &msg);
    assert_int_equal(msg.result, ETH_PLUGIN_RESULT_ERROR);
    // swap_check_destination must not have been called — the early
    // selector reject runs first.
    assert_int_equal(g_swap_check_dest_calls, 0);
}

static void test_finalize_swap_with_extra_data_rejected(void **state) {
    (void) state;
    g_ctx.destination_parsed = true;
    g_ctx.amount_parsed = true;
    g_ctx.selectorIndex = 0;   // ERC20_TRANSFER
    g_ctx.extra_data_len = 4;  // any non-zero
    G_called_from_swap = true;

    ethPluginFinalize_t msg = {0};
    msg.txContent = &g_tx_content;
    msg.pluginContext = (uint8_t *) &g_ctx;
    erc20_plugin_call(ETH_PLUGIN_FINALIZE, &msg);
    assert_int_equal(msg.result, ETH_PLUGIN_RESULT_ERROR);
    assert_int_equal(g_swap_check_dest_calls, 0);
}

static void test_finalize_swap_transfer_no_extra_runs_swap_checks(void **state) {
    (void) state;
    g_ctx.destination_parsed = true;
    g_ctx.amount_parsed = true;
    g_ctx.selectorIndex = 0;  // ERC20_TRANSFER
    g_ctx.extra_data_len = 0;
    G_called_from_swap = true;

    // token_info lookup must succeed for amountToString to run.
    static s_token_info info = {.decimals = 6, .chain_id = 1};
    strlcpy(info.ticker, "USDC", sizeof(info.ticker));
    g_token_info_ret = &info;

    ethPluginFinalize_t msg = {0};
    msg.txContent = &g_tx_content;
    msg.pluginContext = (uint8_t *) &g_ctx;
    erc20_plugin_call(ETH_PLUGIN_FINALIZE, &msg);

    assert_int_equal(msg.result, ETH_PLUGIN_RESULT_OK);
    assert_int_equal(g_swap_check_dest_calls, 1);
    assert_int_equal(g_swap_check_amount_calls, 1);
    assert_true(G_swap_checked);
}

static void test_finalize_swap_token_info_missing_rejected(void **state) {
    (void) state;
    g_ctx.destination_parsed = true;
    g_ctx.amount_parsed = true;
    g_ctx.selectorIndex = 0;
    G_called_from_swap = true;
    g_token_info_ret = NULL;

    ethPluginFinalize_t msg = {0};
    msg.txContent = &g_tx_content;
    msg.pluginContext = (uint8_t *) &g_ctx;
    erc20_plugin_call(ETH_PLUGIN_FINALIZE, &msg);
    assert_int_equal(msg.result, ETH_PLUGIN_RESULT_ERROR);
    // swap_check_destination was called first (it precedes the lookup),
    // swap_check_amount was NOT reached.
    assert_int_equal(g_swap_check_dest_calls, 1);
    assert_int_equal(g_swap_check_amount_calls, 0);
}

// =============================================================================
// ETH_PLUGIN_PROVIDE_INFO
// =============================================================================

static void test_provide_info_item1_ok(void **state) {
    (void) state;
    static const tokenDefinition_t token = {.ticker = "DAI", .decimals = 18};
    static union extraInfo_t item;
    memcpy(&item.token, &token, sizeof(token));

    ethPluginProvideInfo_t msg = {0};
    msg.item1 = &item;
    msg.pluginContext = (uint8_t *) &g_ctx;
    erc20_plugin_call(ETH_PLUGIN_PROVIDE_INFO, &msg);

    assert_int_equal(msg.result, ETH_PLUGIN_RESULT_OK);
    assert_string_equal(g_ctx.ticker, "DAI");
    assert_int_equal(g_ctx.decimals, 18);
}

static void test_provide_info_item1_null_falls_back(void **state) {
    (void) state;
    ethPluginProvideInfo_t msg = {0};
    msg.item1 = NULL;
    msg.pluginContext = (uint8_t *) &g_ctx;
    erc20_plugin_call(ETH_PLUGIN_PROVIDE_INFO, &msg);
    assert_int_equal(msg.result, ETH_PLUGIN_RESULT_FALLBACK);
}

// =============================================================================
// ETH_PLUGIN_QUERY_CONTRACT_ID
// =============================================================================

static void test_query_contract_id_transfer(void **state) {
    (void) state;
    char name[32] = {0};
    char version[32] = {0};
    g_ctx.selectorIndex = 0;  // ERC20_TRANSFER

    ethQueryContractID_t msg = {0};
    msg.name = name;
    msg.version = version;
    msg.nameLength = sizeof(name);
    msg.versionLength = sizeof(version);
    msg.pluginContext = (uint8_t *) &g_ctx;
    erc20_plugin_call(ETH_PLUGIN_QUERY_CONTRACT_ID, &msg);
    assert_int_equal(msg.result, ETH_PLUGIN_RESULT_OK);
    assert_string_equal(name, "ERC20 token");
    assert_string_equal(version, "Send");
}

static void test_query_contract_id_approve(void **state) {
    (void) state;
    char name[32] = {0};
    char version[32] = {0};
    g_ctx.selectorIndex = 1;  // ERC20_APPROVE

    ethQueryContractID_t msg = {0};
    msg.name = name;
    msg.version = version;
    msg.nameLength = sizeof(name);
    msg.versionLength = sizeof(version);
    msg.pluginContext = (uint8_t *) &g_ctx;
    erc20_plugin_call(ETH_PLUGIN_QUERY_CONTRACT_ID, &msg);
    assert_string_equal(version, "Approve");
}

// =============================================================================
// ETH_PLUGIN_QUERY_CONTRACT_UI — screen 0 (amount/title)
// =============================================================================

static void test_query_ui_screen0_transfer_amount(void **state) {
    (void) state;
    char title[16] = {0};
    char msgbuf[64] = {0};
    g_ctx.selectorIndex = 0;
    g_ctx.amount[31] = 0x05;  // small amount 5
    g_ctx.decimals = 0;
    strlcpy(g_ctx.ticker, "USDC", sizeof(g_ctx.ticker));

    ethQueryContractUI_t msg = {0};
    msg.screenIndex = 0;
    msg.title = title;
    msg.msg = msgbuf;
    msg.titleLength = sizeof(title);
    msg.msgLength = sizeof(msgbuf);
    msg.pluginContext = (uint8_t *) &g_ctx;
    erc20_plugin_call(ETH_PLUGIN_QUERY_CONTRACT_UI, &msg);

    assert_int_equal(msg.result, ETH_PLUGIN_RESULT_OK);
    assert_string_equal(title, "Send");
    assert_string_equal(msgbuf, "5 USDC");
}

static void test_query_ui_screen0_approve_unlimited(void **state) {
    (void) state;
    char title[16] = {0};
    char msgbuf[64] = {0};
    g_ctx.selectorIndex = 1;                           // APPROVE
    memset(g_ctx.amount, 0xFF, sizeof(g_ctx.amount));  // max-int → "Unlimited"
    strlcpy(g_ctx.ticker, "DAI", sizeof(g_ctx.ticker));

    ethQueryContractUI_t msg = {0};
    msg.screenIndex = 0;
    msg.title = title;
    msg.msg = msgbuf;
    msg.titleLength = sizeof(title);
    msg.msgLength = sizeof(msgbuf);
    msg.pluginContext = (uint8_t *) &g_ctx;
    erc20_plugin_call(ETH_PLUGIN_QUERY_CONTRACT_UI, &msg);

    assert_int_equal(msg.result, ETH_PLUGIN_RESULT_OK);
    assert_string_equal(title, "Approve");
    assert_string_equal(msgbuf, "Unlimited DAI");
}

// =============================================================================
// ETH_PLUGIN_QUERY_CONTRACT_UI — screens 1 and 2 (To / Approve to /
// Extra Data) and the FINALIZE swap-mode error paths.
//
// These paths render the destination address the user is about to
// approve a token transfer/allowance to. A regression here turns the
// approval scam vector live — the user signs whatever the plugin
// happens to put on screen.
// =============================================================================

static void test_query_ui_screen1_transfer_renders_to(void **state) {
    (void) state;
    char title[16] = {0};
    char msgbuf[64] = {0};
    g_ctx.selectorIndex = 0;  // TRANSFER
    memset(g_ctx.destinationAddress, 0xAB, ADDRESS_LENGTH);

    ethQueryContractUI_t msg = {0};
    msg.screenIndex = 1;
    msg.title = title;
    msg.msg = msgbuf;
    msg.titleLength = sizeof(title);
    msg.msgLength = sizeof(msgbuf);
    msg.pluginContext = (uint8_t *) &g_ctx;
    erc20_plugin_call(ETH_PLUGIN_QUERY_CONTRACT_UI, &msg);
    assert_int_equal(msg.result, ETH_PLUGIN_RESULT_OK);
    assert_string_equal(title, "To");
    // The mock getEthDisplayableAddress in the test environment writes
    // a checksummed hex string to msg — we only assert it's non-empty.
    assert_true(msgbuf[0] != '\0');
}

static void test_query_ui_screen1_approve_renders_approve_to(void **state) {
    (void) state;
    char title[16] = {0};
    char msgbuf[64] = {0};
    g_ctx.selectorIndex = 1;  // APPROVE
    memset(g_ctx.destinationAddress, 0xCD, ADDRESS_LENGTH);

    ethQueryContractUI_t msg = {0};
    msg.screenIndex = 1;
    msg.title = title;
    msg.msg = msgbuf;
    msg.titleLength = sizeof(title);
    msg.msgLength = sizeof(msgbuf);
    msg.pluginContext = (uint8_t *) &g_ctx;
    erc20_plugin_call(ETH_PLUGIN_QUERY_CONTRACT_UI, &msg);
    assert_int_equal(msg.result, ETH_PLUGIN_RESULT_OK);
    assert_string_equal(title, "Approve to");
}

// Screen 2 — Extra Data, ASCII-printable path.
static void test_query_ui_screen2_extra_data_printable(void **state) {
    (void) state;
    char title[16] = {0};
    char msgbuf[64] = {0};
    g_ctx.selectorIndex = 0;
    strlcpy(g_ctx.extra_data, "Hello!", sizeof(g_ctx.extra_data));
    g_ctx.extra_data_len = 6;

    ethQueryContractUI_t msg = {0};
    msg.screenIndex = 2;
    msg.title = title;
    msg.msg = msgbuf;
    msg.titleLength = sizeof(title);
    msg.msgLength = sizeof(msgbuf);
    msg.pluginContext = (uint8_t *) &g_ctx;
    erc20_plugin_call(ETH_PLUGIN_QUERY_CONTRACT_UI, &msg);
    assert_int_equal(msg.result, ETH_PLUGIN_RESULT_OK);
    assert_string_equal(title, "Extra Data");
    assert_string_equal(msgbuf, "Hello!");
}

// Screen 2 — Extra Data, non-printable path (rendered as 0x-prefixed hex).
static void test_query_ui_screen2_extra_data_hex(void **state) {
    (void) state;
    char title[16] = {0};
    char msgbuf[64] = {0};
    g_ctx.selectorIndex = 0;
    // extra_data is char[] (signed on this target); the byte values above
    // 0x7F have to be assigned through their unsigned bit-pattern via
    // memcpy to avoid -Woverflow on the implicit int->char conversion.
    static const uint8_t non_printable_bytes[] = {0x01, 0xFE, 0xAB};
    memcpy(g_ctx.extra_data, non_printable_bytes, sizeof(non_printable_bytes));
    g_ctx.extra_data_len = sizeof(non_printable_bytes);

    ethQueryContractUI_t msg = {0};
    msg.screenIndex = 2;
    msg.title = title;
    msg.msg = msgbuf;
    msg.titleLength = sizeof(title);
    msg.msgLength = sizeof(msgbuf);
    msg.pluginContext = (uint8_t *) &g_ctx;
    erc20_plugin_call(ETH_PLUGIN_QUERY_CONTRACT_UI, &msg);
    assert_int_equal(msg.result, ETH_PLUGIN_RESULT_OK);
    assert_string_equal(msgbuf, "0x01FEAB");
}

// Screen 2 with empty extra_data is rejected (the plugin should never
// reach this state — extra_data_len == 0 means no extra screen was
// allocated — but the guard exists and must trip).
static void test_query_ui_screen2_empty_extra_data_rejected(void **state) {
    (void) state;
    char title[16] = {0};
    char msgbuf[64] = {0};
    g_ctx.extra_data_len = 0;

    ethQueryContractUI_t msg = {0};
    msg.screenIndex = 2;
    msg.title = title;
    msg.msg = msgbuf;
    msg.titleLength = sizeof(title);
    msg.msgLength = sizeof(msgbuf);
    msg.pluginContext = (uint8_t *) &g_ctx;
    erc20_plugin_call(ETH_PLUGIN_QUERY_CONTRACT_UI, &msg);
    assert_int_equal(msg.result, ETH_PLUGIN_RESULT_ERROR);
}

// =============================================================================
// Runner
// =============================================================================

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup(test_init_transfer_selector_ok, reset),
        cmocka_unit_test_setup(test_init_approve_selector_ok, reset),
        cmocka_unit_test_setup(test_init_unknown_selector_rejected, reset),
        cmocka_unit_test_setup(test_init_nonzero_tx_value_rejected, reset),
        cmocka_unit_test_setup(test_provide_destination_parameter, reset),
        cmocka_unit_test_setup(test_provide_amount_parameter, reset),
        cmocka_unit_test_setup(test_provide_extra_data_parameter, reset),
        cmocka_unit_test_setup(test_provide_extra_data_overflow_rejected, reset),
        cmocka_unit_test_setup(test_finalize_missing_destination_rejected, reset),
        cmocka_unit_test_setup(test_finalize_missing_amount_rejected, reset),
        cmocka_unit_test_setup(test_finalize_both_present_non_swap_ok, reset),
        cmocka_unit_test_setup(test_finalize_with_extra_data_bumps_numscreens, reset),
        cmocka_unit_test_setup(test_finalize_swap_approve_rejected, reset),
        cmocka_unit_test_setup(test_finalize_swap_with_extra_data_rejected, reset),
        cmocka_unit_test_setup(test_finalize_swap_transfer_no_extra_runs_swap_checks, reset),
        cmocka_unit_test_setup(test_finalize_swap_token_info_missing_rejected, reset),
        cmocka_unit_test_setup(test_provide_info_item1_ok, reset),
        cmocka_unit_test_setup(test_provide_info_item1_null_falls_back, reset),
        cmocka_unit_test_setup(test_query_contract_id_transfer, reset),
        cmocka_unit_test_setup(test_query_contract_id_approve, reset),
        cmocka_unit_test_setup(test_query_ui_screen0_transfer_amount, reset),
        cmocka_unit_test_setup(test_query_ui_screen0_approve_unlimited, reset),
        cmocka_unit_test_setup(test_query_ui_screen1_transfer_renders_to, reset),
        cmocka_unit_test_setup(test_query_ui_screen1_approve_renders_approve_to, reset),
        cmocka_unit_test_setup(test_query_ui_screen2_extra_data_printable, reset),
        cmocka_unit_test_setup(test_query_ui_screen2_extra_data_hex, reset),
        cmocka_unit_test_setup(test_query_ui_screen2_empty_extra_data_rejected, reset),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
