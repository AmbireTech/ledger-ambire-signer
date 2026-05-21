#include "ui_nbgl.h"
#include "caller_app.h"
#include "plugins.h"
#include "network_icons.h"
#include "network.h"

/**
 * Retrieve the app icon, using the caller app icon if requested
 *
 * @param[in] caller_icon If true, use the caller app icon if available
 * @return Pointer to the icon details structure
 */
const nbgl_icon_details_t *get_app_icon(bool caller_icon) {
    // Plugin or clone case: prefer the caller app's own icon
    if (caller_icon && g_caller_app) {
        if (g_caller_app->icon) {
            return g_caller_app->icon;
        }
        PRINTF("%s: g_caller_app has no icon\n", __func__);
    }
    // Default: Ethereum app icon
    return &ICONGLYPH;
}

/**
 * Retrieve the home screen icon, using the caller app icon if available
 *
 * @return Pointer to the icon details structure
 */
const nbgl_icon_details_t *get_home_icon(void) {
    // Plugin or clone case: prefer the caller app's own icon
    if (g_caller_app) {
        if (g_caller_app->icon) {
            return g_caller_app->icon;
        }
        PRINTF("%s: g_caller_app has no icon\n", __func__);
    }
    // Default: Ethereum home icon
    return &ICONHOME;
}

/**
 * Retrieve the icon for the Transaction
 *
 * @param[in] fromPlugin If true, the data is coming from a plugin, otherwise it is a standard
 * transaction
 * @return Pointer to the icon details structure, or NULL if no icon is available
 */
const nbgl_icon_details_t *get_tx_icon(bool fromPlugin) {
    if (fromPlugin && (pluginType == PLUGIN_TYPE_EXTERNAL)) {
        if ((g_caller_app != NULL) && (g_caller_app->name != NULL)) {
            if (strcmp(strings.common.toAddress, g_caller_app->name) == 0) {
                return get_app_icon(true);
            }
        }
        // icon is NULL in this case
        // Check with Alex if this is expected or a bug
        return NULL;
    }
    if ((g_caller_app != NULL) && !fromPlugin) {
        // Clone case
        return get_app_icon(true);
    }
    // Standard transaction: use app icon if chain matches, else network icon
    uint64_t chain_id = get_tx_chain_id();
    if (chain_id == g_chain_config->chain_id) {
        return get_app_icon(false);
    }
    return get_network_icon_from_chain_id(&chain_id);
}
