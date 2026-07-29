#pragma once

#include <stdint.h>
#include <stdbool.h>
#include "lists.h"
#include "common_utils.h"

typedef enum { ARRAY_DYNAMIC = 0, ARRAY_FIXED_SIZE, ARRAY_TYPES_COUNT } e_array_type;

typedef enum {
    // contract defined struct
    TYPE_STRUCT = 0,
    // native types
    TYPE_SOL_INT,
    TYPE_SOL_UINT,
    TYPE_SOL_ADDRESS,
    TYPE_SOL_BOOL,
    TYPE_SOL_STRING,
    TYPE_SOL_BYTES_FIX,
    TYPE_SOL_BYTES_DYN,
    TYPES_COUNT
} e_type;

typedef struct {
    e_array_type type;
    uint8_t size;
} s_struct_712_field_array_level;

typedef struct {
    flist_node_t _list;
    union {
        char *struct_name;
        uint8_t type_size;
    };
    char *key_name;
    s_struct_712_field_array_level *array_levels;
    uint8_t array_level_count;
    e_type type;
} s_struct_712_field;

typedef struct {
    flist_node_t _list;
    char *name;
    s_struct_712_field *fields;
} s_struct_712;

typedef enum { VAL_ATOMIC, VAL_STRUCT, VAL_ARRAY } e_val_kind;

#define IS_DYN(type) (((type) == TYPE_SOL_STRING) || ((type) == TYPE_SOL_BYTES_DYN))

typedef enum { ROOT_NONE = 0, ROOT_DOMAIN, ROOT_MESSAGE } e_root_type;

typedef struct struct_712_value {
    flist_node_t _list;
    union {
        const s_struct_712_field *field;  // VAL_ATOMIC, VAL_ARRAY
        const s_struct_712 *struct_type;  // VAL_STRUCT
    };
    union {
        uint8_t *data;                      // VAL_ATOMIC
        struct struct_712_value *children;  // VAL_STRUCT, VAL_ARRAY
    };
    uint16_t length;  // VAL_ATOMIC only; unused (0) for VAL_STRUCT/VAL_ARRAY
    e_val_kind kind;
} s_struct_712_value;

typedef struct {
    s_struct_712_value *domain;   // VAL_STRUCT → EIP712Domain
    s_struct_712_value *message;  // VAL_STRUCT → primaryType
} s_eip712_impl;

#define TD_MAX_DEPTH 16

bool td_add_struct_def(const s_struct_712 *struct_def);
bool td_add_struct_field_def(s_struct_712 *struct_def, const s_struct_712_field *field_def);
void td_delete_struct_field(s_struct_712_field *field);

const char *td_get_struct_field_typename(const s_struct_712_field *ptr);
const s_struct_712 *td_find_struct(const char *name_ptr);

bool td_set_domain(s_struct_712_value *node);
bool td_set_message(s_struct_712_value *node);

bool td_has_domain(void);
bool td_has_message(void);

bool td_init(void);
void td_deinit(void);

bool td_hash_pass(void);

bool td_get_domain_chain_id(uint64_t *chain_id);
bool td_get_domain_contract_addr(uint8_t addr[ADDRESS_LENGTH]);

// Visitor callback for value tree traversal. Return false to abort traversal.
typedef bool (*td_f_value_visitor)(const s_struct_712_value *node, void *context);

bool td_traverse_domain(td_f_value_visitor visitor, void *context);
bool td_traverse_message(td_f_value_visitor visitor, void *context);

void td_free_leaf_data(const s_struct_712_value *node);

typedef bool (*td_f_struct_visitor)(const s_struct_712 *node, void *context);

bool td_visit_structs(td_f_struct_visitor visitor, void *context);

typedef bool (*td_f_struct_field_visitor)(const s_struct_712_field *node, void *context);

bool td_visit_struct_fields(const s_struct_712 *s,
                            td_f_struct_field_visitor visitor,
                            void *context);
