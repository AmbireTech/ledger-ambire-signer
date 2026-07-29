#include "typed_data.h"
#include "sol_typenames.h"
#include "eip712_v1_context.h"
#include "common_utils.h"
#include "app_mem_utils.h"
#include "read.h"
#include "value_hash.h"

static s_struct_712 *g_structs = NULL;
static s_eip712_impl g_impl;

/**
 * Initialize the typed data context
 *
 * @return whether the initialization was successful
 */
bool td_init(void) {
    if (g_structs != NULL) {
        td_deinit();
        return false;
    }
    return true;
}

// to be used as a \ref f_list_node_del
static void delete_struct_field_internal(s_struct_712_field *f) {
    if (f->type == TYPE_STRUCT) {
        APP_MEM_FREE(f->struct_name);
    }
    APP_MEM_FREE(f->array_levels);
    APP_MEM_FREE(f->key_name);
    APP_MEM_FREE(f);
}

void td_delete_struct_field(s_struct_712_field *field) {
    if (field != NULL) {
        delete_struct_field_internal(field);
    }
}

// to be used as a \ref f_list_node_del
static void delete_struct(s_struct_712 *s) {
    APP_MEM_FREE(s->name);
    flist_clear((flist_node_t **) &s->fields, (f_list_node_del) &delete_struct_field_internal);
    APP_MEM_FREE(s);
}

static void delete_value(s_struct_712_value *v) {
    if (v->kind == VAL_ATOMIC) {
        APP_MEM_FREE(v->data);
    } else {
        flist_clear((flist_node_t **) &v->children, (f_list_node_del) &delete_value);
    }
    APP_MEM_FREE(v);
}

void td_deinit(void) {
    if (g_impl.domain != NULL) {
        delete_value(g_impl.domain);
        g_impl.domain = NULL;
    }
    if (g_impl.message != NULL) {
        delete_value(g_impl.message);
        g_impl.message = NULL;
    }
    flist_clear((flist_node_t **) &g_structs, (f_list_node_del) &delete_struct);
}

/**
 * Get type name from a struct field
 *
 * @param[in] field_ptr struct field pointer
 * @return type name pointer
 */
const char *td_get_struct_field_typename(const s_struct_712_field *field_ptr) {
    if (field_ptr == NULL) {
        return NULL;
    }
    if (field_ptr->type == TYPE_STRUCT) {
        return field_ptr->struct_name;
    }
    return get_struct_field_sol_typename(field_ptr);
}

/**
 * Find struct with a given name
 *
 * @param[in] name struct name
 * @return pointer to struct
 */
const s_struct_712 *td_find_struct(const char *name) {
    const s_struct_712 *struct_ptr;

    if (name == NULL) {
        return NULL;
    }
    for (struct_ptr = g_structs; struct_ptr != NULL;
         struct_ptr = (s_struct_712 *) ((flist_node_t *) struct_ptr)->next) {
        if (struct_ptr->name != NULL) {
            if (strcmp(name, struct_ptr->name) == 0) {
                return struct_ptr;
            }
        }
    }
    return NULL;
}

bool td_add_struct_def(const s_struct_712 *struct_def) {
    flist_push_back((flist_node_t **) &g_structs, (flist_node_t *) struct_def);
    return true;
}

bool td_add_struct_field_def(s_struct_712 *struct_def, const s_struct_712_field *field_def) {
    if (struct_def == NULL) {
        return false;
    }
    flist_push_back((flist_node_t **) &struct_def->fields, (flist_node_t *) field_def);
    return true;
}

bool td_set_domain(s_struct_712_value *node) {
    if (node == NULL) {
        return false;
    }
    if (g_impl.domain != NULL) {
        APP_MEM_FREE(node);
        return false;
    }
    if (node->kind != VAL_STRUCT) {
        APP_MEM_FREE(node);
        return false;
    }
    if (strcmp(node->struct_type->name, "EIP712Domain") != 0) {
        APP_MEM_FREE(node);
        return false;
    }
    g_impl.domain = node;
    return true;
}

bool td_set_message(s_struct_712_value *node) {
    if (node == NULL) {
        return false;
    }
    if (g_impl.message != NULL) {
        APP_MEM_FREE(node);
        return false;
    }
    if (node->kind != VAL_STRUCT) {
        APP_MEM_FREE(node);
        return false;
    }
    g_impl.message = node;
    return true;
}

bool td_has_domain(void) {
    return g_impl.domain != NULL;
}

bool td_has_message(void) {
    return g_impl.message != NULL;
}

/**
 * Fill @p chain_id with the chainId from the domain value tree.
 *
 * @return true if the field was found and copied into @p chain_id, false otherwise.
 */
bool td_get_domain_chain_id(uint64_t *chain_id) {
    if (g_impl.domain != NULL) {
        for (const s_struct_712_value *child = g_impl.domain->children; child != NULL;
             child = (const s_struct_712_value *) ((const flist_node_t *) child)->next) {
            if ((child->kind == VAL_ATOMIC) && (strcmp(child->field->key_name, "chainId") == 0)) {
                // reject rather than silently wrap/truncate an oversized length into u64_from_BE
                if (child->length > sizeof(*chain_id)) {
                    return false;
                }
                *chain_id = u64_from_BE(child->data, (uint8_t) child->length);
                return true;
            }
        }
    }
    return false;
}

/**
 * Fill @p addr with the verifyingContract from the domain value tree.
 *
 * @return true if the field was found and copied into @p addr, false otherwise.
 */
bool td_get_domain_contract_addr(uint8_t addr[ADDRESS_LENGTH]) {
    const char *ethermint_vc = "cosmos";

    if (g_impl.domain != NULL) {
        for (const s_struct_712_value *child = g_impl.domain->children; child != NULL;
             child = (const s_struct_712_value *) ((const flist_node_t *) child)->next) {
            if ((child->kind == VAL_ATOMIC) &&
                (strcmp(child->field->key_name, "verifyingContract") == 0)) {
                const uint8_t *data = child->data;
                uint16_t length = child->length;

                switch (child->field->type) {
                    case TYPE_SOL_ADDRESS:
                        if (length > ADDRESS_LENGTH) {
                            PRINTF("Error: verifyingContract too big\n");
                            return false;
                        }
                        break;
                    case TYPE_SOL_STRING:
                        if ((length != strlen(ethermint_vc)) ||
                            (strncmp((char *) data, ethermint_vc, length) != 0)) {
                            PRINTF("Error: non standard verifyingContract\n");
                            return false;
                        }
                        break;
                    default:
                        PRINTF("Error: unexpected type for verifyingContract (%u)!\n",
                               child->field->type);
                        return false;
                }
                memcpy(addr, data, length);
                explicit_bzero(addr + length, ADDRESS_LENGTH - length);
                return true;
            }
        }
    }
    return false;
}

/**
 * Recursive helper for tree traversal. Visits node, then recurses on children if
 * VAL_STRUCT/VAL_ARRAY.
 * @return false if visitor returned false (abort), true otherwise
 */
static bool traverse_node(const s_struct_712_value *node,
                          td_f_value_visitor visitor,
                          void *context) {
    if (node == NULL) {
        return true;
    }

    // Visit this node
    if (!visitor(node, context)) {
        return false;
    }

    // Recurse on children for composite types
    if ((node->kind == VAL_STRUCT) || (node->kind == VAL_ARRAY)) {
        for (const s_struct_712_value *child = node->children; child != NULL;
             child = (const s_struct_712_value *) ((const flist_node_t *) child)->next) {
            if (!traverse_node(child, visitor, context)) {
                return false;
            }
        }
    }

    return true;
}

/**
 * Traverse domain value tree with visitor callback.
 */
bool td_traverse_domain(td_f_value_visitor visitor, void *context) {
    if (visitor == NULL) {
        return false;
    }
    return traverse_node(g_impl.domain, visitor, context);
}

/**
 * Traverse message value tree with visitor callback.
 */
bool td_traverse_message(td_f_value_visitor visitor, void *context) {
    if (visitor == NULL) {
        return false;
    }
    return traverse_node(g_impl.message, visitor, context);
}

void td_free_leaf_data(const s_struct_712_value *node) {
    if ((node == NULL) || (node->kind != VAL_ATOMIC)) {
        return;
    }
    // s_struct_712_value is exposed as const to traversal visitors, but this
    // function's whole purpose is to mutate it; cast away constness here only.
    s_struct_712_value *mutable_node = (s_struct_712_value *) node;
    APP_MEM_FREE(mutable_node->data);
    mutable_node->data = NULL;
    mutable_node->length = 0;
}

bool td_visit_structs(td_f_struct_visitor visitor, void *context) {
    const s_struct_712 *it = g_structs;

    while (it != NULL) {
        if (!visitor(it, context)) {
            return false;
        }
        it = (const s_struct_712 *) ((const flist_node_t *) it)->next;
    }
    return true;
}

bool td_visit_struct_fields(const s_struct_712 *s,
                            td_f_struct_field_visitor visitor,
                            void *context) {
    const s_struct_712_field *it;

    if (s != NULL) {
        it = s->fields;
        while (it != NULL) {
            if (!visitor(it, context)) {
                return false;
            }
            it = (const s_struct_712_field *) ((const flist_node_t *) it)->next;
        }
    }
    return true;
}

bool td_hash_pass(void) {
    return value_hash_pass(&g_impl);
}
