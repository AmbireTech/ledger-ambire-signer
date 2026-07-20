#include "shared_context.h"
#include "ui_nbgl.h"
#include "ui_icons.h"
#include "nbgl_use_case.h"
#include "common_ui.h"
#include "ui_utils.h"

static void review7702Choice(bool confirm) {
    if (confirm) {
        auth_7702_ok_cb();
#ifndef FUZZ
        nbgl_useCaseReviewStatus(STATUS_TYPE_OPERATION_SIGNED, ui_idle);
#endif
    } else {
        auth_7702_cancel_cb();
#ifndef FUZZ
        nbgl_useCaseReviewStatus(STATUS_TYPE_OPERATION_REJECTED, ui_idle);
#endif
    }
    ui_pairs_cleanup();
}

bool ui_sign_7702_revocation(void) {
    int index = 0;

    // Initialize the buffers
    if (!ui_pairs_init(2)) {
        // Initialization failed, cleanup and return
        return false;
    }

    g_pairs[index].item = "Account";
    g_pairs[index++].value = strings.common.fromAddress;

    g_pairs[index].item = "Revoke on network";
    g_pairs[index++].value = strings.common.network_name;

#ifndef FUZZ
    nbgl_useCaseReview(TYPE_OPERATION,
                       g_pairsList,
                       &ICON_APP_REVIEW,
                       "Review authorization to revoke smart contract delegation?",
                       NULL,
#ifdef SCREEN_SIZE_WALLET
                       "Sign authorization to revoke smart contract delegation?",
#else
                       "Sign operation",
#endif
                       review7702Choice);
#endif
    return true;
}
