#pragma once

#include <stdint.h>
#include <stdbool.h>
#include "nbgl_types.h"
#include "caller_app.h"

#ifdef SCREEN_SIZE_WALLET
#define ICON_APP_WARNING LARGE_WARNING_ICON
#define ICON_APP_REVIEW  LARGE_REVIEW_ICON
#if defined(TARGET_APEX)
#define ICON_LEDGER       C_ledger_48px
#define ICON_APP_MULTISIG C_multisig_48px
#else
#define ICON_LEDGER       C_ledger_64px
#define ICON_APP_MULTISIG C_multisig_64px
#endif
#else
#define ICON_LEDGER       C_ledger_14px
#define ICON_APP_WARNING  WARNING_ICON
#define ICON_APP_REVIEW   REVIEW_ICON
#define ICON_APP_MULTISIG C_multisig_14px
#endif

const nbgl_icon_details_t *get_app_icon(bool caller_icon);
const nbgl_icon_details_t *get_home_icon(void);
const nbgl_icon_details_t *get_tx_icon(bool fromPlugin);
const nbgl_icon_details_t *get_network_icon_from_chain_id(const uint64_t *chain_id);
const nbgl_icon_details_t *get_clone_network_icon(const caller_app_t *caller_app);
