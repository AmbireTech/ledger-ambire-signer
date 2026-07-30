#include "app_mem_utils.h"
#include "read.h"
#include "eip712_v1_parse.h"
#include "typed_data.h"

static s_struct_712 *g_pending_struct = NULL;

/**
 * Set struct name
 *
 * @param[in] length name length
 * @param[in] name name
 * @return whether it was successful
 */
bool v1_set_struct_name(uint8_t length, const uint8_t *name) {
    if (name == NULL) {
        return false;
    }

    if ((g_pending_struct = APP_MEM_ALLOC(sizeof(*g_pending_struct))) == NULL) {
        return false;
    }
    explicit_bzero(g_pending_struct, sizeof(*g_pending_struct));

    if ((g_pending_struct->name = APP_MEM_ALLOC(length + 1)) == NULL) {
        APP_MEM_FREE(g_pending_struct);
        g_pending_struct = NULL;
        return false;
    }
    g_pending_struct->name[length] = '\0';
    memcpy(g_pending_struct->name, name, length);

    return td_add_struct_def(g_pending_struct);
}

// TypeDesc masks
#define TYPE_MASK     (0xF)
#define ARRAY_MASK    (1 << 7)
#define TYPESIZE_MASK (1 << 6)
#define TYPENAME_ENUM (0xF)

/**
 * Set struct field TypeDesc
 *
 * @param[in] data the field data
 * @param[in] data_idx the data index
 * @return whether it was successful or not
 */
static bool v1_set_struct_field_typedesc(s_struct_712_field *field,
                                         const uint8_t *data,
                                         uint8_t *data_idx,
                                         uint8_t length,
                                         bool *is_array,
                                         bool *has_size) {
    uint8_t typedesc;

    // copy TypeDesc
    // check buffer bound
    if ((*data_idx + sizeof(typedesc)) > length) {
        return false;
    }
    typedesc = data[(*data_idx)++];
    *is_array = typedesc & ARRAY_MASK;
    *has_size = typedesc & TYPESIZE_MASK;
    field->type = typedesc & TYPE_MASK;
    return true;
}

/**
 * Set struct field custom typename
 *
 * @param[in] data the field data
 * @param[in] data_idx the data index
 * @return whether it was successful
 */
static bool v1_set_struct_field_custom_typename(s_struct_712_field *field,
                                                const uint8_t *data,
                                                uint8_t *data_idx,
                                                uint8_t length) {
    uint8_t typename_len;

    // copy custom struct name length
    // check buffer bound
    if ((*data_idx + sizeof(typename_len)) > length) {
        return false;
    }
    typename_len = data[(*data_idx)++];

    // copy name
    // check buffer bound
    if ((*data_idx + typename_len) > length) {
        return false;
    }
    if ((field->struct_name = APP_MEM_ALLOC(typename_len + 1)) == NULL) {
        return false;
    }

    field->struct_name[typename_len] = '\0';
    memmove(field->struct_name, &data[*data_idx], typename_len);
    *data_idx += typename_len;
    return true;
}

/**
 * Set struct field's array levels
 *
 * @param[in] data the field data
 * @param[in] data_idx the data index
 * @return whether it was successful
 */
static bool v1_set_struct_field_array(s_struct_712_field *field,
                                      const uint8_t *data,
                                      uint8_t *data_idx,
                                      uint8_t length) {
    // check buffer bound
    if ((*data_idx + sizeof(field->array_level_count)) > length) {
        return false;
    }
    field->array_level_count = data[(*data_idx)++];
    if ((field->array_levels =
             APP_MEM_ALLOC(sizeof(*field->array_levels) * field->array_level_count)) == NULL) {
        return false;
    }
    for (int idx = 0; idx < field->array_level_count; ++idx) {
        // check buffer bound
        if ((*data_idx + sizeof(field->array_levels[idx].type)) > length) {
            return false;
        }
        field->array_levels[idx].type = data[(*data_idx)++];
        switch (field->array_levels[idx].type) {
            case ARRAY_DYNAMIC:  // nothing to do
                break;
            case ARRAY_FIXED_SIZE:
                // check buffer bound
                if ((*data_idx + sizeof(field->array_levels[idx].size)) > length) {
                    return false;
                }
                field->array_levels[idx].size = data[(*data_idx)++];
                break;
            default:
                // should not be in here :^)
                return false;
        }
    }
    return true;
}

/**
 * Set struct field's type size
 *
 * @param[in] data the field data
 * @param[in,out] data_idx the data index
 * @return whether it was successful
 */
static bool v1_set_struct_field_typesize(s_struct_712_field *field,
                                         const uint8_t *data,
                                         uint8_t *data_idx,
                                         uint8_t length) {
    // copy TypeSize
    // check buffer bound
    if ((*data_idx + sizeof(field->type_size)) > length) {
        return false;
    }
    field->type_size = data[(*data_idx)++];
    return true;
}

/**
 * Set struct field's key name
 *
 * @param[in] data the field data
 * @param[in,out] data_idx the data index
 * @return whether it was successful
 */
static bool v1_set_struct_field_keyname(s_struct_712_field *field,
                                        const uint8_t *data,
                                        uint8_t *data_idx,
                                        uint8_t length) {
    uint8_t keyname_len;

    // copy length
    // check buffer bound
    if ((*data_idx + sizeof(keyname_len)) > length) {
        return false;
    }
    keyname_len = data[(*data_idx)++];

    // copy name
    // check buffer bound
    if ((*data_idx + keyname_len) > length) {
        return false;
    }

    if ((field->key_name = APP_MEM_ALLOC(keyname_len + 1)) == NULL) {
        return false;
    }
    field->key_name[keyname_len] = '\0';
    memmove(field->key_name, &data[*data_idx], keyname_len);
    *data_idx += keyname_len;
    return true;
}

static bool v1_set_struct_field_internal(s_struct_712_field **new_field_ptr,
                                         uint8_t length,
                                         const uint8_t *data) {
    s_struct_712_field *new_field;
    uint8_t data_idx = 0;

    if ((data == NULL) || (length == 0)) {
        return false;
    }

    if (g_pending_struct == NULL) {
        return false;
    }

    if ((new_field = APP_MEM_ALLOC(sizeof(*new_field))) == NULL) {
        return false;
    }
    *new_field_ptr = new_field;
    explicit_bzero(new_field, sizeof(*new_field));

    bool is_array;
    bool has_size;
    if (!v1_set_struct_field_typedesc(new_field, data, &data_idx, length, &is_array, &has_size)) {
        return false;
    }

    // check TypeSize flag in TypeDesc
    if (has_size) {
        // TYPESIZE and TYPE_STRUCT are mutually exclusive
        if (new_field->type == TYPE_STRUCT) {
            return false;
        }

        if (v1_set_struct_field_typesize(new_field, data, &data_idx, length) == false) {
            return false;
        }

    } else if (new_field->type == TYPE_STRUCT) {
        if (v1_set_struct_field_custom_typename(new_field, data, &data_idx, length) == false) {
            return false;
        }
    }
    if (is_array) {
        if (v1_set_struct_field_array(new_field, data, &data_idx, length) == false) {
            return false;
        }
    }

    if (v1_set_struct_field_keyname(new_field, data, &data_idx, length) == false) {
        return false;
    }

    // check that there is no more
    if (data_idx != length) {
        return false;
    }

    return td_add_struct_field_def(g_pending_struct, new_field);
}

/**
 * Set struct field
 *
 * @param[in] length data length
 * @param[in] data the field data
 * @return whether it was successful
 */
bool v1_set_struct_field(uint8_t length, const uint8_t *data) {
    s_struct_712_field *new_field = NULL;

    if (!v1_set_struct_field_internal(&new_field, length, data)) {
        td_delete_struct_field(new_field);
        return false;
    }
    return true;
}

typedef struct {
    const s_struct_712_field *next;  // next field expecting data
    s_struct_712_value *node;        // VAL_STRUCT or VAL_ARRAY being built
    uint8_t array_remaining;         // >0 = array frame; 0 = struct frame
    // remaining array dimensions to open via v1_set_array before elements are the base type
    uint8_t array_levels_remaining;
} s_build_frame;

static struct {
    s_build_frame stack[TD_MAX_DEPTH];
    uint8_t depth;
} g_build;
static struct {
    s_build_frame stack[TD_MAX_DEPTH];
    uint8_t depth;
} g_backup;
static struct {
    s_struct_712_value *leaf;
    uint16_t filled;
} g_pending_field;

// --- helpers ---

static s_struct_712_value *alloc_value(e_val_kind kind) {
    s_struct_712_value *v = NULL;

    if ((v = APP_MEM_ALLOC(sizeof(*v))) == NULL) {
        return NULL;
    }
    explicit_bzero(v, sizeof(*v));
    v->kind = kind;
    return v;
}

static void append_child(s_struct_712_value *parent, s_struct_712_value *child) {
    flist_push_back((flist_node_t **) &parent->children, (flist_node_t *) child);
}

static bool push_frame(const s_struct_712_field *next,
                       s_struct_712_value *node,
                       uint8_t array_remaining,
                       uint8_t array_levels_remaining) {
    if (g_build.depth >= TD_MAX_DEPTH) {
        return false;
    }
    g_build.stack[g_build.depth].next = next;
    g_build.stack[g_build.depth].node = node;
    g_build.stack[g_build.depth].array_remaining = array_remaining;
    g_build.stack[g_build.depth].array_levels_remaining = array_levels_remaining;
    g_build.depth++;
    return true;
}

// Auto-descend into TYPE_STRUCT fields with no array levels, skipping the need for an explicit
// P2_IMPL_ARRAY/P2_IMPL_FIELD
static bool auto_descend(void) {
    while (g_build.depth > 0) {
        s_build_frame *f = &g_build.stack[g_build.depth - 1];
        if (f->next == NULL) break;
        if (f->next->type != TYPE_STRUCT) break;
        if (f->next->array_level_count > 0) break;  // array → wait for P2_IMPL_ARRAY

        const s_struct_712 *nested = td_find_struct(f->next->struct_name);
        if (nested == NULL) {
            return false;
        }

        s_struct_712_value *node = alloc_value(VAL_STRUCT);
        if (node == NULL) {
            return false;
        }
        node->struct_type = nested;
        append_child(f->node, node);

        if (!push_frame(nested->fields, node, 0, 0)) {
            return false;
        }
    }
    return true;
}

// Advance cursor after a leaf is fully received or an array element is done.
static bool advance(void) {
    while (g_build.depth > 0) {
        s_build_frame *f = &g_build.stack[g_build.depth - 1];

        if (f->array_remaining > 0) {
            f->array_remaining--;
            if (f->array_remaining == 0) {
                // array frame exhausted — pop and let the loop advance the parent naturally
                g_build.depth--;
                continue;
            }
            // more elements: push the next one if this array's base type is reached, else wait for
            // the next P2_IMPL_ARRAY
            if ((f->array_levels_remaining == 0) && (f->next->type == TYPE_STRUCT)) {
                const s_struct_712 *nested = td_find_struct(f->next->struct_name);
                if (nested == NULL) {
                    return false;
                }
                s_struct_712_value *elem = alloc_value(VAL_STRUCT);
                if (elem == NULL) {
                    return false;
                }
                elem->struct_type = nested;
                append_child(f->node, elem);
                if (!push_frame(nested->fields, elem, 0, 0)) {
                    return false;
                }
                return auto_descend();
            }
            return true;  // next leaf/array arrives via next v1_add_field/v1_set_array call
        } else {
            f->next = (const s_struct_712_field *) ((flist_node_t *) f->next)->next;
        }

        if (g_build.depth == 0) {
            return true;
        }
        f = &g_build.stack[g_build.depth - 1];

        if (f->next == NULL) {
            // struct complete — pop and keep advancing
            g_build.depth--;
            continue;
        }

        return auto_descend();
    }
    return true;
}

// --- value tree deinit ---

bool v1_set_root(const char *name) {
    bool ret;
    const s_struct_712 *root;

    // reject if a P2_IMPL_FIELD chunk sequence is still in flight, to avoid orphaning the pending
    // leaf
    if (g_pending_field.leaf != NULL) {
        return false;
    }

    // reject switching roots before all of the previous root's fields have been provided
    if (g_build.depth != 0) {
        return false;
    }

    if ((root = td_find_struct(name)) == NULL) {
        return false;
    }

    s_struct_712_value *node = alloc_value(VAL_STRUCT);
    if (node == NULL) {
        return false;
    }
    node->struct_type = root;

    if (strcmp(name, "EIP712Domain") == 0) {
        ret = td_set_domain(node);
    } else {
        ret = td_set_message(node);
    }
    if (!ret) {
        return false;
    }

    if (!push_frame(root->fields, node, 0, 0)) {
        return false;
    }
    return auto_descend();
}

bool v1_set_array(size_t count) {
    // reject if a P2_IMPL_FIELD chunk sequence is still in flight, to avoid desyncing the pending
    // leaf's frames
    if (g_pending_field.leaf != NULL) {
        return false;
    }
    if (g_build.depth == 0) {
        return false;
    }
    s_build_frame *f = &g_build.stack[g_build.depth - 1];

    // Determines the field/remaining-dimensions for this call: continues a pending array frame's
    // next dimension, else starts a fresh field's first dimension
    const s_struct_712_field *elem_field;
    uint8_t levels_remaining_after;

    if ((elem_field = f->next) == NULL) {
        return false;
    }
    if ((f->array_remaining > 0) && (f->array_levels_remaining > 0)) {
        levels_remaining_after = f->array_levels_remaining - 1;
    } else {
        if (elem_field->array_level_count == 0) {
            return false;
        }
        levels_remaining_after = elem_field->array_level_count - 1;
    }

    // reject a count that doesn't match this dimension's declared fixed size
    uint8_t level_idx = elem_field->array_level_count - 1 - levels_remaining_after;
    const s_struct_712_field_array_level *level = &elem_field->array_levels[level_idx];
    if ((level->type == ARRAY_FIXED_SIZE) && (count != level->size)) {
        return false;
    }

    s_struct_712_value *arr = alloc_value(VAL_ARRAY);
    if (arr == NULL) {
        return false;
    }
    arr->field = elem_field;
    append_child(f->node, arr);

    if (count == 0) {
        // empty array — snapshot only struct-level frames (skip array-container frames, which would
        // duplicate prefix segments) for discarded-path checks
        g_backup.depth = 0;
        for (uint8_t i = 0; i < g_build.depth; ++i) {
            if (g_build.stack[i].array_remaining == 0) {
                g_backup.stack[g_backup.depth++] = g_build.stack[i];
            }
        }
        // advance past this field
        return advance();
    }

    if (count > UINT8_MAX) {
        return false;
    }
    if (!push_frame(elem_field, arr, (uint8_t) count, levels_remaining_after)) {
        return false;
    }

    // Only instantiate the base-type element once every array dimension has been opened, else wait
    // for the next v1_set_array call
    if ((levels_remaining_after == 0) && (elem_field->type == TYPE_STRUCT)) {
        const s_struct_712 *nested = td_find_struct(elem_field->struct_name);
        if (nested == NULL) {
            return false;
        }
        s_struct_712_value *elem = alloc_value(VAL_STRUCT);
        if (elem == NULL) {
            return false;
        }
        elem->struct_type = nested;
        append_child(arr, elem);
        if (!push_frame(nested->fields, elem, 0, 0)) {
            return false;
        }
        return auto_descend();
    }
    return true;
}

bool v1_is_complete(void) {
    return (g_build.depth == 0) && td_has_domain() && td_has_message();
}

const s_struct_712_value *v1_add_field(const uint8_t *data, size_t length, bool more) {
    if (g_build.depth == 0) {
        return NULL;
    }

    s_build_frame *f = &g_build.stack[g_build.depth - 1];

    // an array frame still awaiting inner dimensions must receive them via
    // v1_set_array(), not a leaf value, or the declared array shape would be collapsed
    if ((f->array_remaining > 0) && (f->array_levels_remaining > 0)) {
        return NULL;
    }

    if (g_pending_field.leaf == NULL) {
        // first chunk: data starts with uint16_t total_size
        if (length < sizeof(uint16_t)) {
            return NULL;
        }
        uint16_t total_size = read_u16_be(data, 0);
        data += sizeof(uint16_t);
        length -= sizeof(uint16_t);

        s_struct_712_value *leaf = alloc_value(VAL_ATOMIC);
        if (leaf == NULL) {
            return NULL;
        }

        leaf->field = f->next;
        leaf->length = total_size;

        if (total_size > 0) {
            if ((leaf->data = APP_MEM_ALLOC(total_size)) == NULL) {
                APP_MEM_FREE(leaf);
                return NULL;
            }
        }
        g_pending_field.leaf = leaf;
        g_pending_field.filled = 0;
    }

    if (g_pending_field.filled + length > g_pending_field.leaf->length) {
        return NULL;
    }
    if (length > 0) {
        memmove(g_pending_field.leaf->data + g_pending_field.filled, data, length);
        g_pending_field.filled += (uint16_t) length;
    }

    if (!more) {
        if (g_pending_field.filled != g_pending_field.leaf->length) {
            return NULL;
        }
        s_struct_712_value *completed = g_pending_field.leaf;
        append_child(f->node, completed);
        g_pending_field.leaf = NULL;
        g_pending_field.filled = 0;
        if (!advance()) {
            return NULL;
        }
        return completed;
    }
    return g_pending_field.leaf;
}

// --- path-compatible accessors (derived from build stack) ---

e_root_type v1_get_root_type(void) {
    if (!td_has_domain()) {
        return ROOT_NONE;
    }
    if (!td_has_message()) {
        return ROOT_DOMAIN;
    }
    return ROOT_MESSAGE;
}

const s_struct_712_field *v1_get_current_field(void) {
    if (g_build.depth == 0) {
        return NULL;
    }
    return g_build.stack[g_build.depth - 1].next;
}

uint8_t v1_depth_count(void) {
    uint8_t count = 0;
    for (uint8_t i = 0; i < g_build.depth; ++i) {
        if (g_build.stack[i].array_remaining == 0) count++;
    }
    return count;
}

const s_struct_712_field *v1_nth_field(uint8_t n) {
    if (n == 0) {
        return NULL;
    }
    uint8_t count = 0;
    for (uint8_t i = 0; i < g_build.depth; ++i) {
        if (g_build.stack[i].array_remaining == 0) {
            count++;
            if (count == n) {
                return g_build.stack[i].next;
            }
        }
    }
    return NULL;
}

uint8_t v1_backup_depth_count(void) {
    return g_backup.depth;
}

const s_struct_712_field *v1_backup_nth_field(uint8_t n) {
    if ((n == 0) || (n > g_backup.depth)) {
        return NULL;
    }
    return g_backup.stack[n - 1].next;
}

bool v1_backup_exists(const char *path, size_t length) {
    size_t offset = 0;
    size_t i;
    const s_struct_712_field *field_ptr;
    const char *typename;
    const s_struct_712 *struct_ptr;
    const char *key;

    if (g_backup.depth == 0) {
        return false;
    }
    field_ptr = g_backup.stack[g_backup.depth - 1].next;
    if (field_ptr == NULL) {
        return false;
    }

    while (offset < length) {
        if (((offset + 1) > length) || (memcmp(path + offset, ".", 1) != 0)) {
            return false;
        }
        offset += 1;
        if (((offset + 2) <= length) && (memcmp(path + offset, "[]", 2) == 0)) {
            if (field_ptr->array_level_count == 0) {
                return false;
            }
            offset += 2;
        } else if (offset < length) {
            for (i = 0; ((offset + i) < length) && (path[offset + i] != '.'); ++i);
            typename = td_get_struct_field_typename(field_ptr);
            if ((struct_ptr = td_find_struct(typename)) == NULL) {
                return false;
            }
            for (field_ptr = struct_ptr->fields; field_ptr != NULL;
                 field_ptr = (s_struct_712_field *) ((flist_node_t *) field_ptr)->next) {
                key = field_ptr->key_name;
                if ((strlen(key) == i) && (memcmp(key, path + offset, i) == 0)) {
                    break;
                }
            }
            if (field_ptr == NULL) {
                return false;
            }
            offset += i;
        } else {
            return false;
        }
    }
    return true;
}

void v1_parse_deinit(void) {
    g_build.depth = 0;
    g_backup.depth = 0;
    g_pending_field.leaf = NULL;
    g_pending_field.filled = 0;
    g_pending_struct = NULL;
}
