#pragma once

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <bsd/string.h>  // strlcpy, strlcat from libbsd

// Mirror the SDK os.h chain: pull in the BE/LE byte helpers (U4BE, ...)
// so test units that exercise raw APDU parsers find them.
#include "os_utils.h"

/**
 * @brief Array length macro (from BOLOS_SDK os_utils.h)
 */
#define ARRAYLEN(array) (sizeof(array) / sizeof(array[0]))

/**
 * @brief Hex-encode bytes as a lowercase null-terminated string.
 *        Mirrors BOLOS_SDK os_utils.h declaration; impl lives in mock.c.
 */
int bytes_to_lowercase_hex(char *out, size_t outl, const void *value, size_t len);

/**
 * @brief All-zero buffer probe (from BOLOS_SDK os_utils.h).
 *        Tests that touch zero-buffer guards must provide an implementation.
 */
bool is_zeroes_buffer(const void *buf, size_t n);

/**
 * @brief APDU TX buffer (from BOLOS_SDK os_io.h). Tests that exercise APDU
 *        reply paths must provide storage.
 */
extern uint8_t G_io_tx_buffer[];

/**
 * @brief NVM write (from BOLOS_SDK os_nvm.h). Tests that exercise the
 *        persistent-counter path must wrap or stub this symbol.
 */
void nvm_write(void *dst, void *src, unsigned int len);
