#include <string.h>
#include "common_ui.h"
#include "ui_nbgl.h"
#include "ui_icons.h"
#include "ui_message_signing.h"
#include "ui_utils.h"
#include "utils.h"  // SET_BIT
#include "app_mem_utils.h"
#include "shared_context.h"
#include "typed_data.h"
#include "typed_data_format.h"
#include "cmd_get_tx_simulation.h"
#include "cmd_get_gating.h"

// Whether the pairs currently in g_pairs were built here. V1 fills the same array with
// pointers it owns elsewhere, so the cleanup below must only run on pairs of our own making.
static bool s_owns_pairs = false;

// Each pair owns a single allocation holding its key and its value back to back, so a pair
// costs one block rather than two. item points at its start, value just past the key's NUL.
typedef struct {
    uint8_t index;  // pair being filled
    bool failed;
} s_fill_ctx;

/**
 * Count the values a tree contributes to the review
 *
 * to be used as a \ref td_f_value_visitor
 */
static bool count_leaf(const s_struct_712_value *node, void *context) {
    if (node->kind == VAL_ATOMIC) {
        *(uint16_t *) context += 1;
    }
    return true;
}

/**
 * Build one review pair out of a value
 *
 * to be used as a \ref td_f_value_visitor
 */
static bool fill_pair(const s_struct_712_value *node, void *context) {
    s_fill_ctx *ctx = context;
    const s_struct_712_field *field;
    size_t key_size;
    size_t value_size;
    char *block;

    if (node->kind != VAL_ATOMIC) {
        return true;
    }
    field = node->field;
    if ((field == NULL) || (field->key_name == NULL)) {
        ctx->failed = true;
        return false;
    }
    // a type with no text representation cannot be shown, and must not be signed unseen
    if ((value_size = td_format_value_size(field, node->length)) == 0) {
        ctx->failed = true;
        return false;
    }
    if (ctx->index >= g_pairsList->nbPairs) {
        ctx->failed = true;
        return false;
    }
    key_size = strlen(field->key_name) + 1;
    if ((block = APP_MEM_ALLOC(key_size + value_size)) == NULL) {
        ctx->failed = true;
        return false;
    }
    memcpy(block, field->key_name, key_size);
    if (!td_format_value(field, node->data, node->length, block + key_size, value_size)) {
        APP_MEM_FREE(block);
        ctx->failed = true;
        return false;
    }
    g_pairs[ctx->index].item = block;
    g_pairs[ctx->index].value = block + key_size;
    ctx->index += 1;
    return true;
}

void ui_712_v2_cleanup(void) {
    if (!s_owns_pairs) {
        return;
    }
    s_owns_pairs = false;
    if ((g_pairs == NULL) || (g_pairsList == NULL)) {
        return;
    }
    for (uint8_t i = 0; i < g_pairsList->nbPairs; i++) {
        // value points inside item's block, so freeing item releases both
        APP_MEM_FREE((void *) g_pairs[i].item);
        g_pairs[i].item = NULL;
        g_pairs[i].value = NULL;
    }
}

/**
 * Count the values both trees contribute
 *
 * @param[out] count number of pairs the review will hold
 * @return whether both trees could be walked
 */
static bool count_pairs(uint16_t *count) {
    *count = 0;
    if (!td_traverse_domain(count_leaf, count)) {
        return false;
    }
    return td_traverse_message(count_leaf, count);
}

/**
 * Fill the review pairs from both trees
 *
 * @return whether every value could be formatted
 */
static bool fill_pairs(void) {
    s_fill_ctx ctx = {0};

    td_traverse_domain(fill_pair, &ctx);
    if (!ctx.failed) {
        td_traverse_message(fill_pair, &ctx);
    }
    if (ctx.failed) {
        return false;
    }
    // a short count would leave uninitialised pairs in the list
    return ctx.index == g_pairsList->nbPairs;
}

/**
 * Enter the signing state, flagging the review as blind
 *
 * V2 has no field descriptors yet, so every value is shown raw and the user is warned about
 * it. The schema opened the flow, so the app is already out of idle and nothing is reset.
 */
static void start_blind_review(void) {
    appState = APP_STATE_SIGNING_EIP712;
    memset(&strings, 0, sizeof(strings));
    memset(&warning, 0, sizeof(nbgl_warning_t));
    warning.predefinedSet |= SET_BIT(BLIND_SIGNING_WARN);
    warning.predefinedSet |= SET_BIT(GATED_SIGNING_WARN);
}

bool ui_712_v2_review(void) {
    uint16_t count;
    uint8_t finish_len = 1;  // the NUL
#ifdef SCREEN_SIZE_WALLET
    const char *tx_check_str;
    const char *title_suffix = " typed message?";
#else
    // a Nano review has no room to spell out what is being accepted
    const char *tx_check_str = "Sign";
    const char *title_suffix = " message";
#endif

    if (!count_pairs(&count)) {
        return false;
    }
    // the whole review is built at once, so it has to fit the pair list's own counter
    if ((count == 0) || (count > UINT8_MAX)) {
        return false;
    }
    if (!ui_pairs_init((uint8_t) count)) {
        return false;
    }
    s_owns_pairs = true;
    if (!fill_pairs()) {
        return false;
    }

    start_blind_review();
    if (!set_gating_warning()) {
        return false;
    }
#ifdef HAVE_TRANSACTION_CHECKS
    set_tx_simulation_warning();
#endif
#ifdef SCREEN_SIZE_WALLET
    // reads the warnings set above, so it can only be resolved once they are all in
    tx_check_str = ui_tx_simulation_finish_str();
#endif
    finish_len += strlen(tx_check_str);
    finish_len += strlen(title_suffix);
    if (!ui_buffers_init(0, 0, finish_len)) {
        return false;
    }
    snprintf(g_finishMsg, finish_len, "%s%s", tx_check_str, title_suffix);

    nbgl_useCaseAdvancedReview(TYPE_MESSAGE | SKIPPABLE_OPERATION,
                               g_pairsList,
                               &LARGE_REVIEW_ICON,
                               "Review typed message",
                               NULL,
                               g_finishMsg,
                               NULL,
                               &warning,
                               ui_typed_message_review_choice);
    return true;
}
