#include "fuzz_utils.h"
#include "eip712_v1_commands.h"

int fuzzEIP712(const uint8_t *data, size_t size) {
    if (eip712_v1_context_init() == false) return 0;
    size_t len = 0;
    uint8_t p1;
    uint8_t p2;

    if (size < 2) goto eip712_end;
    p2 = *(data++);
    len = *(data++);
    size -= 2;
    if (size < len) goto eip712_end;
    handle_eip712_v1_struct_def(p2, data, len);
    size -= len;

    if (size < 3) goto eip712_end;
    p1 = *(data++);
    p2 = *(data++);
    len = *(data++);
    size -= 3;
    if (size < len) goto eip712_end;
    handle_eip712_v1_filtering(p1, p2, data, len);
    size -= len;

    if (size < 3) goto eip712_end;
    p1 = *(data++);
    p2 = *(data++);
    len = *(data++);
    size -= 3;
    if (size < len) goto eip712_end;
    handle_eip712_v1_struct_impl(p1, p2, data, len);
    size -= len;

    if (size < 1) goto eip712_end;
    len = *(data++);
    size -= 1;
    if (size < len) goto eip712_end;
    handle_eip712_v1_sign(data, len);

eip712_end:
    eip712_v1_context_deinit();
    return 0;
}

/* Main fuzzing handler called by libfuzzer */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    init_fuzzing_environment();
    reset_app_context();

    // Run the harness
    fuzzEIP712(data, size);

    return 0;
}
