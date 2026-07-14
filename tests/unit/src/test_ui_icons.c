/**
 * @file test_ui_icons.c
 * @brief Unit tests for get_app_icon / get_home_icon / get_tx_icon at
 *        src/nbgl/ui_icons.c.
 *
 * The icon-routing layer decides which logo flashes on the review /
 * home / transaction screens. The choice depends on:
 *   - whether a caller app is hosting Ethereum (plugin or clone)
 *   - whether the caller app shipped its own icon
 *   - the current pluginType (PLUGIN_TYPE_EXTERNAL vs internal)
 *   - the current chain (Mainnet vs other)
 *
 * A misroute is a visual spoof vector (user sees the wrong brand mark
 * on a confirmation screen). Pin every branch.
 *
 *   get_app_icon:
 *     - caller_icon=false                   -> app ICONGLYPH
 *     - caller_icon=true, g_caller_app=NULL -> app ICONGLYPH
 *     - caller_icon=true, icon=NULL         -> app ICONGLYPH (PRINTF fallback)
 *     - caller_icon=true, icon=X            -> X
 *
 *   get_home_icon:
 *     - g_caller_app=NULL                   -> app ICONHOME
 *     - g_caller_app->icon=NULL             -> app ICONHOME
 *     - g_caller_app->icon=X                -> X
 *
 *   get_tx_icon:
 *     - fromPlugin=true, EXTERNAL, name matches toAddress -> caller icon
 *     - fromPlugin=true, EXTERNAL, name doesn't match     -> NULL
 *     - fromPlugin=false, g_caller_app != NULL (clone)    -> caller icon
 *     - fromPlugin=false, NULL caller, chain == config    -> app ICONGLYPH
 *     - fromPlugin=false, NULL caller, chain != config    -> network icon
 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

#include "shared_context.h"
#include "caller_app.h"
#include "nbgl_types.h"
#include "network.h"  // find_dynamic_network_by_chain_id
#include "ui_icons.h"
#include "wraps.h"

// =============================================================================
// Storage for ICONGLYPH / ICONHOME (referenced as `test_glyph` / `test_home_glyph`
// via the DEFS line). glyphs.h declares them extern; we provide the storage.
// =============================================================================

nbgl_icon_details_t test_glyph = {.width = 64};
nbgl_icon_details_t test_home_glyph = {.width = 96};

// Caller's own icon used in several tests.
static nbgl_icon_details_t s_caller_icon = {.width = 128};

// =============================================================================
// Wraps
// =============================================================================

// get_network_icon_from_chain_id used to live in network_icons.c and was
// linker-wrappable from this test target. After the upstream merge it
// is now in the same TU as get_tx_icon -- --wrap doesn't intercept
// intra-TU calls, so we drive the real impl through its dependency:
// find_dynamic_network_by_chain_id. Tests that want the icon-found
// branch point g_dyn_net_ret at a network with a non-NULL bitmap;
// tests that want the not-found branch leave it at NULL.
static network_info_t *g_dyn_net_ret = NULL;
network_info_t *find_dynamic_network_by_chain_id(uint64_t chain_id) {
    (void) chain_id;
    return g_dyn_net_ret;
}

// =============================================================================
// Fixture
// =============================================================================

static int reset(void **state) {
    (void) state;
    g_caller_app = NULL;
    pluginType = PLUGIN_TYPE_OLD_INTERNAL;
    memset(&strings, 0, sizeof(strings));
    // g_chain_config points to g_chainConfig (in app_globals.c) with
    // chain_id == 1. Tests that need a mismatch flip g_tx_chain_id.
    g_chainConfig.chain_id = 1;
    g_tx_chain_id = 1;
    g_dyn_net_ret = NULL;
    return 0;
}

// =============================================================================
// get_app_icon
// =============================================================================

static void test_app_icon_no_caller_icon_returns_iconglyph(void **state) {
    (void) state;
    assert_ptr_equal(get_app_icon(false), &test_glyph);
}

static void test_app_icon_caller_requested_null_caller_returns_iconglyph(void **state) {
    (void) state;
    g_caller_app = NULL;
    assert_ptr_equal(get_app_icon(true), &test_glyph);
}

static void test_app_icon_caller_has_no_icon_returns_iconglyph(void **state) {
    (void) state;
    caller_app_t caller = {.name = "Plugin", .icon = NULL};
    g_caller_app = &caller;
    assert_ptr_equal(get_app_icon(true), &test_glyph);
}

static void test_app_icon_caller_has_icon_returns_caller_icon(void **state) {
    (void) state;
    caller_app_t caller = {.name = "Plugin", .icon = &s_caller_icon};
    g_caller_app = &caller;
    assert_ptr_equal(get_app_icon(true), &s_caller_icon);
}

// =============================================================================
// get_home_icon
// =============================================================================

static void test_home_icon_null_caller_returns_iconhome(void **state) {
    (void) state;
    g_caller_app = NULL;
    assert_ptr_equal(get_home_icon(), &test_home_glyph);
}

static void test_home_icon_caller_without_icon_returns_iconhome(void **state) {
    (void) state;
    caller_app_t caller = {.icon = NULL};
    g_caller_app = &caller;
    assert_ptr_equal(get_home_icon(), &test_home_glyph);
}

static void test_home_icon_caller_with_icon_returns_caller_icon(void **state) {
    (void) state;
    caller_app_t caller = {.icon = &s_caller_icon};
    g_caller_app = &caller;
    assert_ptr_equal(get_home_icon(), &s_caller_icon);
}

// =============================================================================
// get_tx_icon
// =============================================================================

static void test_tx_icon_plugin_external_matching_name_returns_caller_icon(void **state) {
    (void) state;
    caller_app_t caller = {.name = "MyPlugin", .icon = &s_caller_icon};
    g_caller_app = &caller;
    pluginType = PLUGIN_TYPE_EXTERNAL;
    strlcpy(strings.common.toAddress, "MyPlugin", sizeof(strings.common.toAddress));
    assert_ptr_equal(get_tx_icon(true), &s_caller_icon);
}

static void test_tx_icon_plugin_external_no_name_match_returns_null(void **state) {
    (void) state;
    caller_app_t caller = {.name = "MyPlugin", .icon = &s_caller_icon};
    g_caller_app = &caller;
    pluginType = PLUGIN_TYPE_EXTERNAL;
    strlcpy(strings.common.toAddress, "SomethingElse", sizeof(strings.common.toAddress));
    assert_null(get_tx_icon(true));
}

static void test_tx_icon_clone_returns_caller_icon(void **state) {
    (void) state;
    // fromPlugin=false but caller present == clone case (Ethereum running
    // under a clone app). Use the caller's icon.
    caller_app_t caller = {.icon = &s_caller_icon};
    g_caller_app = &caller;
    assert_ptr_equal(get_tx_icon(false), &s_caller_icon);
}

static void test_tx_icon_standard_matching_chain_returns_app_iconglyph(void **state) {
    (void) state;
    g_caller_app = NULL;
    g_tx_chain_id = 1;
    g_chainConfig.chain_id = 1;
    assert_ptr_equal(get_tx_icon(false), &test_glyph);
}

static void test_tx_icon_standard_other_chain_returns_network_icon(void **state) {
    (void) state;
    // No caller, chain mismatch -> get_tx_icon delegates to
    // get_network_icon_from_chain_id. Drive the latter through its
    // dynamic-network lookup: hand back a network with a non-NULL
    // bitmap so the helper returns &net.icon.
    g_caller_app = NULL;
    g_tx_chain_id = 137;
    g_chainConfig.chain_id = 1;
    static uint8_t s_bitmap_bytes[8];
    static network_info_t s_net;
    memset(&s_net, 0, sizeof(s_net));
    s_net.icon.bitmap = s_bitmap_bytes;
    s_net.icon.width = 32;
    g_dyn_net_ret = &s_net;
    assert_ptr_equal(get_tx_icon(false), &s_net.icon);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup(test_app_icon_no_caller_icon_returns_iconglyph, reset),
        cmocka_unit_test_setup(test_app_icon_caller_requested_null_caller_returns_iconglyph, reset),
        cmocka_unit_test_setup(test_app_icon_caller_has_no_icon_returns_iconglyph, reset),
        cmocka_unit_test_setup(test_app_icon_caller_has_icon_returns_caller_icon, reset),
        cmocka_unit_test_setup(test_home_icon_null_caller_returns_iconhome, reset),
        cmocka_unit_test_setup(test_home_icon_caller_without_icon_returns_iconhome, reset),
        cmocka_unit_test_setup(test_home_icon_caller_with_icon_returns_caller_icon, reset),
        cmocka_unit_test_setup(test_tx_icon_plugin_external_matching_name_returns_caller_icon,
                               reset),
        cmocka_unit_test_setup(test_tx_icon_plugin_external_no_name_match_returns_null, reset),
        cmocka_unit_test_setup(test_tx_icon_clone_returns_caller_icon, reset),
        cmocka_unit_test_setup(test_tx_icon_standard_matching_chain_returns_app_iconglyph, reset),
        cmocka_unit_test_setup(test_tx_icon_standard_other_chain_returns_network_icon, reset),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
