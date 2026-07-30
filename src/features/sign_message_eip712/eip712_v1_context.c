#include "eip712_v1_context.h"
#include "app_mem_utils.h"
#include "mem_utils.h"
#include "eip712_v1_ui_logic.h"
#include "eip712_v1_parse.h"
#include "typed_data.h"
#include "shared_context.h"  // reset_app_context
#include "common_ui.h"       // ui_idle

s_eip712_v1_context *eip712_v1_context = NULL;

/**
 * Initialize the EIP712 context
 *
 * @return a boolean indicating if the initialization was successful or not
 */
bool eip712_v1_context_init(void) {
    if (eip712_v1_context != NULL) {
        eip712_v1_context_deinit();
        return false;
    }

    // init global variables
    if (APP_MEM_CALLOC((void **) &eip712_v1_context, sizeof(*eip712_v1_context)) == false) {
        return false;
    }

    if (ui_712_init() == false) {
        return false;
    }

    if (td_init() == false) {
        return false;
    }

    eip712_v1_context->go_home_on_failure = true;

    return true;
}

/**
 * De-initialize the EIP712 context
 */
void eip712_v1_context_deinit(void) {
    v1_parse_deinit();
    td_deinit();
    ui_712_deinit();
    APP_MEM_FREE_AND_NULL((void **) &eip712_v1_context);
    reset_app_context();
}
