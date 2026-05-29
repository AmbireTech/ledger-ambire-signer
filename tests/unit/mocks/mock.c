#include <stdbool.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "tlv_library.h"
#include "buffer.h"
#include "read.h"

// PIC function for SDK's tlv_library.c (identity function in test environment)
void *pic(void *addr) {
    return addr;
}

// Mirror of BOLOS_SDK os.c implementation; pulled in here so unit tests don't
// have to link the whole os.c (which drags in BSS/syscall machinery).
int bytes_to_lowercase_hex(char *out, size_t outl, const void *value, size_t len) {
    const uint8_t *bytes = (const uint8_t *) value;
    const char *hex = "0123456789abcdef";

    if (outl < 2 * len + 1) {
        *out = '\0';
        return -1;
    }
    for (size_t i = 0; i < len; i++) {
        *out++ = hex[(bytes[i] >> 4) & 0xf];
        *out++ = hex[bytes[i] & 0xf];
    }
    *out = '\0';
    return 0;
}

bool is_printable_string(const char *str, size_t len) {
    for (size_t i = 0; i < len; ++i) {
        if (str[i] < 0x20 || str[i] > 0x7E) {
            return false;
        }
    }
    return true;
}

void assert_exit(bool confirm) {
    (void) confirm;
}

uint32_t cx_keccak_256_hash_iovec(void *iovec, size_t iovec_len, uint8_t *digest) {
    (void) iovec;
    (void) iovec_len;
    (void) digest;
    return 0;  // CX_OK
}

uint32_t cx_keccak_256_hash(const uint8_t *in, size_t in_len, uint8_t *out) {
    (void) in;
    (void) in_len;
    // Fill with deterministic test data for address checksumming
    if (out) {
        for (size_t i = 0; i < 32; i++) {
            out[i] = (uint8_t) (i * 7);  // Simple deterministic pattern
        }
    }
    return 0;  // CX_OK
}

uint32_t cx_math_mult_no_throw(uint8_t *r, const uint8_t *a, const uint8_t *b, size_t len) {
    (void) r;
    (void) a;
    (void) b;
    (void) len;
    return 0;  // CX_OK
}

// The next three stubs are marked weak so test targets that link the real
// gtp_data_path.c (e.g. test_data_path) can override them without a
// multiple-definition link error.
__attribute__((weak)) bool handle_data_path_struct(const void *data, void *context) {
    (void) data;
    (void) context;
    return true;
}

bool tlv_parse(const uint8_t *payload, uint16_t size, void *handler, void *context) {
    (void) payload;
    (void) size;
    (void) handler;
    (void) context;
    return true;
}

__attribute__((weak)) void data_path_cleanup(const void *collection) {
    (void) collection;
}

__attribute__((weak)) bool data_path_get(const void *data_path, void *collection) {
    (void) data_path;
    (void) collection;
    return true;
}

// These stubs are weak so test targets that link the real tx_ctx.c
// (test_tx_ctx) can override them without a multiple-definition link
// error.
__attribute__((weak)) const uint8_t *get_current_tx_to(void) {
    return NULL;
}

__attribute__((weak)) const uint8_t *get_current_tx_from(void) {
    return NULL;
}

__attribute__((weak)) const uint8_t *get_current_tx_info(void) {
    return NULL;
}

bool check_challenge(uint32_t received_challenge) {
    (void) received_challenge;
    return true;  // Always accept challenge in tests
}

// Memory management mocks - SDK lib_alloc compatible
static void *test_heap = NULL;
static size_t test_heap_size = 0;

bool mem_utils_init(void *heap_start, size_t heap_size) {
    test_heap = heap_start;
    test_heap_size = heap_size;
    return true;
}

void *mem_utils_alloc(size_t size, bool permanent, const char *file, int line) {
    (void) permanent;
    (void) file;
    (void) line;
    return malloc(size);
}

void *mem_utils_realloc(void *ptr, size_t size, const char *file, int line) {
    (void) file;
    (void) line;
    return realloc(ptr, size);
}

void mem_utils_free(void *ptr, const char *file, int line) {
    (void) file;
    (void) line;
    free(ptr);
}

void mem_utils_free_and_null(void **buffer, const char *file, int line) {
    (void) file;
    (void) line;
    if (*buffer != NULL) {
        free(*buffer);
        *buffer = NULL;
    }
}

char *mem_utils_strdup(const char *s, const char *file, int line) {
    (void) file;
    (void) line;
    return strdup(s);
}

bool mem_utils_calloc(void **buffer, uint16_t size, bool permanent, const char *file, int line) {
    (void) permanent;
    (void) file;
    (void) line;
    // The real lib_alloc implementation does NOT pre-free *buffer; it just
    // writes a fresh pointer. Many call sites (e.g. gtp_field_table.c) pass
    // an uninitialized stack pointer, so a pre-free here would invoke
    // free() on junk.
    if (size == 0) {
        return true;
    }
    if ((*buffer = malloc(size)) == NULL) {
        return false;
    }
    memset(*buffer, 0, size);
    return true;
}

__attribute__((weak)) const uint8_t *get_current_tx_amount(void) {
    return NULL;
}

__attribute__((weak)) const void *get_matching_map_entry(uint8_t id,
                                                         const uint8_t *key,
                                                         uint8_t key_size) {
    (void) id;
    (void) key;
    (void) key_size;
    return NULL;
}
