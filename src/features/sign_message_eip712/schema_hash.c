#include "schema_hash.h"
#include "typed_data.h"
#include "format_hash_field_type.h"

// the SDK does not define a SHA-224 type, define it here so it's easier
// to understand in the code
typedef cx_sha256_t cx_sha224_t;

static bool compute_schema_hash_struct_field(const s_struct_712_field *field_ptr, void *context) {
    cx_hash_t *hash_ctx = context;

    if (cx_hash_update(hash_ctx, (uint8_t *) "{\"name\":\"", 9) != CX_OK) {
        return false;
    }
    if (cx_hash_update(hash_ctx, (uint8_t *) field_ptr->key_name, strlen(field_ptr->key_name)) !=
        CX_OK) {
        return false;
    }
    if (cx_hash_update(hash_ctx, (uint8_t *) "\",\"type\":\"", 10) != CX_OK) {
        return false;
    }
    if (!format_hash_field_type(field_ptr, hash_ctx)) {
        return false;
    }
    if (cx_hash_update(hash_ctx, (uint8_t *) "\"}", 2) != CX_OK) {
        return false;
    }
    if (((flist_node_t *) field_ptr)->next != NULL) {
        if (cx_hash_update(hash_ctx, (uint8_t *) ",", 1) != CX_OK) {
            return false;
        }
    }
    return true;
}

static bool compute_schema_hash_struct(const s_struct_712 *struct_ptr, void *context) {
    cx_hash_t *hash_ctx = context;

    if (cx_hash_update(hash_ctx, (uint8_t *) "\"", 1) != CX_OK) {
        return false;
    }
    if (cx_hash_update(hash_ctx, (uint8_t *) struct_ptr->name, strlen(struct_ptr->name)) != CX_OK) {
        return false;
    }
    if (cx_hash_update(hash_ctx, (uint8_t *) "\":[", 3) != CX_OK) {
        return false;
    }
    if (!td_visit_struct_fields(struct_ptr, compute_schema_hash_struct_field, hash_ctx)) {
        return false;
    }
    if (cx_hash_update(hash_ctx, (uint8_t *) "]", 1) != CX_OK) {
        return false;
    }
    if (((flist_node_t *) struct_ptr)->next != NULL) {
        if (cx_hash_update(hash_ctx, (uint8_t *) ",", 1) != CX_OK) {
            return false;
        }
    }
    return true;
}

/**
 * Compute the schema hash
 *
 * The schema hash is the value of the root field "types" in the JSON data,
 * stripped of all its spaces and newlines. This function reconstructs the JSON syntax
 * from the stored typed data.
 *
 * @return whether the schema hash was successful or not
 */
bool compute_schema_hash(uint8_t hash[CX_SHA224_SIZE]) {
    cx_sha224_t hash_ctx;

    if (cx_sha224_init_no_throw(&hash_ctx) != CX_OK) {
        return false;
    }

    if (cx_hash_update((cx_hash_t *) &hash_ctx, (uint8_t *) "{", 1) != CX_OK) {
        return false;
    }
    if (!td_visit_structs(compute_schema_hash_struct, &hash_ctx)) {
        return false;
    }
    if (cx_hash_update((cx_hash_t *) &hash_ctx, (uint8_t *) "}", 1) != CX_OK) {
        return false;
    }

    return cx_hash_final((cx_hash_t *) &hash_ctx, hash) == CX_OK;
}
