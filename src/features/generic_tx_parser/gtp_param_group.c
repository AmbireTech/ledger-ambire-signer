#include <string.h>
#include "os_print.h"
#include "gtp_param_group.h"
#include "gtp_field.h"
#include "app_mem_utils.h"
#include "tlv_library.h"
#include "tlv_utils.h"

// =============================================================================
// TLV tag handlers
// =============================================================================

static bool handle_pg_version(const tlv_data_t *data, s_param_group_context *context) {
    return tlv_get_uint8_range(data, &context->param->version, 0, UINT8_MAX);
}

static bool handle_pg_iteration_type(const tlv_data_t *data, s_param_group_context *context) {
    return tlv_get_uint8_range(data,
                               (uint8_t *) &context->param->iteration_type,
                               0,
                               GROUP_ITER_MAX - 1);
}

static bool handle_pg_field(const tlv_data_t *data, s_param_group_context *context) {
    s_group_field_node *node = NULL;
    s_field *sub_field = NULL;

    if (APP_MEM_CALLOC((void **) &node, sizeof(s_group_field_node)) == false) {
        PRINTF("GROUP: failed to alloc field node\n");
        return false;
    }
    if (APP_MEM_CALLOC((void **) &sub_field, sizeof(s_field)) == false) {
        PRINTF("GROUP: failed to alloc sub-field\n");
        APP_MEM_FREE(node);
        return false;
    }
    node->field = sub_field;

    s_field_ctx sub_ctx = {0};
    sub_ctx.field = sub_field;
    if (!handle_field_struct(&data->value, &sub_ctx)) {
        PRINTF("GROUP: failed to parse sub-field\n");
        cleanup_field_constraints(sub_field);
        APP_MEM_FREE(sub_field);
        APP_MEM_FREE(node);
        return false;
    }
    if (!verify_field_struct(&sub_ctx)) {
        PRINTF("GROUP: sub-field failed verification\n");
        cleanup_field_constraints(sub_field);
        APP_MEM_FREE(sub_field);
        APP_MEM_FREE(node);
        return false;
    }
    flist_push_back((flist_node_t **) &context->param->fields, (flist_node_t *) node);
    return true;
}

// =============================================================================
// TLV parser definition
// =============================================================================

#define PARAM_GROUP_TAGS(X)                                                      \
    X(0x00, TAG_PG_VERSION, handle_pg_version, ENFORCE_UNIQUE_TAG)               \
    X(0x01, TAG_PG_ITERATION_TYPE, handle_pg_iteration_type, ENFORCE_UNIQUE_TAG) \
    X(0x02, TAG_PG_FIELD, handle_pg_field, ALLOW_MULTIPLE_TAG)

DEFINE_TLV_PARSER(PARAM_GROUP_TAGS, NULL, param_group_tlv_parser)

bool handle_param_group_struct(const buffer_t *buf, s_param_group_context *context) {
    TLV_reception_t received_tags;
    return param_group_tlv_parser(buf, context, &received_tags);
}

// =============================================================================
// Formatting
// =============================================================================

// Cap on nested PARAM_TYPE_GROUP levels to bound the recursion between
// format_field() and format_param_group() on hostile descriptors.
#define MAX_PARAM_GROUP_DEPTH 8

/**
 * @brief Render every sub-field of a PARAM_TYPE_GROUP field.
 *
 * Walks the linked list of sub-fields and dispatches each one back through
 * format_field(), which may recurse into this function for nested groups.
 *
 * @param[in] field outer field whose param_group is being rendered
 * @param[in] depth current nesting level; pass 0 from the top-level
 *                  format_field() call site (cmd_field.c). format_field()
 *                  forwards this value unchanged, so the increment happens
 *                  here when descending into sub-fields. Calls with
 *                  `depth >= MAX_PARAM_GROUP_DEPTH` are refused to bound
 *                  the worst-case stack usage on hostile descriptors.
 * @return true if every sub-field rendered, false on depth-cap, unsupported
 *         iteration type, or any sub-field failure (short-circuit)
 */
bool format_param_group(const s_field *field, uint8_t depth) {
    const s_param_group *group = &field->param_group;

    if (group->iteration_type == GROUP_ITER_BUNDLED) {
        PRINTF("GROUP: BUNDLED iteration unsupported\n");
        return false;
    }

    if (depth >= MAX_PARAM_GROUP_DEPTH) {
        PRINTF("GROUP: nesting too deep (>= %u)\n", MAX_PARAM_GROUP_DEPTH);
        return false;
    }
    for (s_group_field_node *n = group->fields; n != NULL;
         n = (s_group_field_node *) n->node.next) {
        if (!format_field(n->field, depth + 1)) {
            return false;
        }
    }
    return true;
}

// =============================================================================
// Cleanup
// =============================================================================

static void group_field_node_del(s_group_field_node *gn) {
    if (gn != NULL) {
        if (gn->field != NULL) {
            cleanup_field(gn->field);  // handles nested GROUP recursively
            APP_MEM_FREE(gn->field);
        }
        APP_MEM_FREE(gn);
    }
}

void cleanup_param_group(s_param_group *group) {
    if (group != NULL) {
        flist_clear((flist_node_t **) &group->fields, (f_list_node_del) &group_field_node_del);
    }
}
