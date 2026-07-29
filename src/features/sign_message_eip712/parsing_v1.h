#pragma once

#include <stdbool.h>
#include <stdint.h>
#include "typed_data.h"

bool impl_set_root(const char *name);
bool impl_set_array(size_t count);
// Returns the completed leaf on final chunk, in-progress leaf on intermediate chunks, NULL on
// error.
const s_struct_712_value *impl_add_field(const uint8_t *data, size_t length, bool more);
bool impl_is_complete(void);
e_root_type impl_get_root_type(void);
const s_struct_712_field *impl_get_current_field(void);
uint8_t impl_get_depth_count(void);
const s_struct_712_field *impl_get_nth_field(uint8_t n);
uint8_t impl_backup_get_depth_count(void);
const s_struct_712_field *impl_backup_get_nth_field(uint8_t n);
bool impl_backup_exists(const char *path, size_t length);
void v1_parse_deinit(void);
