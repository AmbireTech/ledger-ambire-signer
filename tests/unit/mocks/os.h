#pragma once

#include <stddef.h>
#include <bsd/string.h>  // strlcpy, strlcat from libbsd

/**
 * @brief Array length macro (from BOLOS_SDK os_utils.h)
 */
#define ARRAYLEN(array) (sizeof(array) / sizeof(array[0]))

/**
 * @brief Hex-encode bytes as a lowercase null-terminated string.
 *        Mirrors BOLOS_SDK os_utils.h declaration; impl lives in mock.c.
 */
int bytes_to_lowercase_hex(char *out, size_t outl, const void *value, size_t len);
