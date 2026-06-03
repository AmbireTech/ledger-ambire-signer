/**
 * @file test_network_icons.c
 * @brief Unit tests for get_network_icon_from_chain_id / get_clone_network_icon
 *        at src/nbgl/ui_icons.c (formerly in src/nbgl/network_icons.c
 *        before the upstream merge of the two TUs).
 *
 * The icon lookup decides which logo flashes on the review screen for a
 * given chain. The user reads "Polygon" because the icon matches Polygon's
 * brand mark, not because the underlying chain_id is 137 -- so a mis-routed
 * icon is a visual spoof vector.
 *
 * Pin the three resolution branches (Nano path, !SCREEN_SIZE_WALLET):
 *
 *  - dynamic network registered + has bitmap -> return its icon
 *  - dynamic network missing, chain_id == 1 -> fallback to app ICONGLYPH
 *  - dynamic network missing, chain_id != 1 -> NULL
 *  - dynamic network registered but bitmap == NULL -> fallback path
 *
 * Plus get_clone_network_icon's three branches:
 *  - NULL caller_app             NULL
 *  - PLUGIN type caller_app      NULL
 *  - CLONE type caller_app       return icon
 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

#include "nbgl_types.h"
#include "caller_app.h"
#include "network.h"
#include "ui_icons.h"  // get_network_icon_from_chain_id / get_clone_network_icon
#include "chain_config.h"

// =============================================================================
// Storage for the macro icons referenced by ui_icons.c. ICONGLYPH and
// ICONHOME are #defines that resolve to C_chain_N_*px symbols in
// production; in test we redirect them via DEFS to test_glyph /
// test_home_glyph and provide storage here. test_home_glyph is only
// referenced by get_home_icon, which this suite doesn't exercise, but
// the linker still needs the symbol to satisfy ui_icons.c.
// =============================================================================

nbgl_icon_details_t test_glyph = {.width = 64, .height = 64};
nbgl_icon_details_t test_home_glyph = {.width = 96, .height = 96};

// =============================================================================
// Wraps
// =============================================================================

static network_info_t *g_dyn_net_ret = NULL;
network_info_t *__wrap_find_dynamic_network_by_chain_id(uint64_t chain_id) {
    (void) chain_id;
    return g_dyn_net_ret;
}

// =============================================================================
// Fixture
// =============================================================================

static network_info_t s_net;
static uint8_t s_bitmap_data[32];

static int reset(void **state) {
    (void) state;
    memset(&s_net, 0, sizeof(s_net));
    g_dyn_net_ret = NULL;
    return 0;
}

// =============================================================================
// get_network_icon_from_chain_id
// =============================================================================

static void test_dynamic_network_with_bitmap_returns_its_icon(void **state) {
    (void) state;
    s_net.icon.bitmap = s_bitmap_data;
    s_net.icon.width = 32;
    g_dyn_net_ret = &s_net;
    uint64_t cid = 1234;
    const nbgl_icon_details_t *icon = get_network_icon_from_chain_id(&cid);
    assert_ptr_equal(icon, &s_net.icon);
}

static void test_dynamic_network_with_null_bitmap_falls_back(void **state) {
    (void) state;
    // A dynamic entry exists for this chain but its icon blob wasn't
    // streamed yet (bitmap NULL). MUST NOT crash; falls through to the
    // hardcoded path.
    s_net.icon.bitmap = NULL;
    g_dyn_net_ret = &s_net;
    uint64_t cid = 1;  // mainnet -> ICONGLYPH fallback
    const nbgl_icon_details_t *icon = get_network_icon_from_chain_id(&cid);
    assert_ptr_equal(icon, &test_glyph);
}

static void test_no_dynamic_match_mainnet_falls_back_to_iconglyph(void **state) {
    (void) state;
    g_dyn_net_ret = NULL;
    uint64_t cid = ETHEREUM_MAINNET_CHAINID;
    const nbgl_icon_details_t *icon = get_network_icon_from_chain_id(&cid);
    // Nano build path: !SCREEN_SIZE_WALLET, mainnet special case.
    assert_ptr_equal(icon, &test_glyph);
}

static void test_no_dynamic_match_non_mainnet_returns_null(void **state) {
    (void) state;
    g_dyn_net_ret = NULL;
    uint64_t cid = 137;  // Polygon, not mainnet
    assert_null(get_network_icon_from_chain_id(&cid));
}

// =============================================================================
// get_clone_network_icon
// =============================================================================

static void test_clone_icon_null_caller_returns_null(void **state) {
    (void) state;
    assert_null(get_clone_network_icon(NULL));
}

static void test_clone_icon_plugin_type_returns_null(void **state) {
    (void) state;
    caller_app_t caller = {.type = CALLER_TYPE_PLUGIN, .icon = &test_glyph};
    assert_null(get_clone_network_icon(&caller));
}

static void test_clone_icon_clone_type_returns_icon(void **state) {
    (void) state;
    caller_app_t caller = {.type = CALLER_TYPE_CLONE, .icon = &test_glyph};
    assert_ptr_equal(get_clone_network_icon(&caller), &test_glyph);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup(test_dynamic_network_with_bitmap_returns_its_icon, reset),
        cmocka_unit_test_setup(test_dynamic_network_with_null_bitmap_falls_back, reset),
        cmocka_unit_test_setup(test_no_dynamic_match_mainnet_falls_back_to_iconglyph, reset),
        cmocka_unit_test_setup(test_no_dynamic_match_non_mainnet_returns_null, reset),
        cmocka_unit_test_setup(test_clone_icon_null_caller_returns_null, reset),
        cmocka_unit_test_setup(test_clone_icon_plugin_type_returns_null, reset),
        cmocka_unit_test_setup(test_clone_icon_clone_type_returns_icon, reset),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
