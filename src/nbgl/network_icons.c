#include "os_utils.h"
#include "os_pic.h"
#include "network.h"
#include "network_info.h"
#ifdef SCREEN_SIZE_WALLET
#include "net_icons.gen.h"
#endif

/**
 * Get the network icon from a given chain ID
 *
 * Loops onto the generated \ref g_network_icons array until a chain ID matches.
 *
 * @param[in] chain_id network's chain ID
 * @return the network icon if found, \ref NULL otherwise
 */
const nbgl_icon_details_t *get_network_icon_from_chain_id(const uint64_t *chain_id) {
    // Search in dynamically loaded networks
    network_info_t *net_info = find_dynamic_network_by_chain_id(*chain_id);
    if (net_info != NULL && net_info->icon.bitmap != NULL) {
        PRINTF("[NETWORK_ICONS] - Found dynamic '%s'\n", net_info->name);
        return PIC(&net_info->icon);
    }
#ifdef SCREEN_SIZE_WALLET
    for (size_t i = 0; i < ARRAYLEN(g_network_icons); ++i) {
        if ((uint64_t) PIC(g_network_icons[i].chain_id) == *chain_id) {
            PRINTF("[NETWORK_ICONS] - Fallback on hardcoded list.\n");
            return PIC(g_network_icons[i].icon);
        }
    }
#else
    // Nano devices don't have the array of icons, fallback on the app's icon
    if (*chain_id == ETHEREUM_MAINNET_CHAINID) {
        return &ICONGLYPH;
    }
#endif
    return NULL;
}

const nbgl_icon_details_t *get_clone_network_icon(const caller_app_t *caller_app) {
    if ((caller_app == NULL) || (caller_app->type != CALLER_TYPE_CLONE)) {
        return NULL;
    }
    return caller_app->icon;
}
