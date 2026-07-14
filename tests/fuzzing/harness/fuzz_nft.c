#include "fuzz_utils.h"

int fuzzNFTInfo(const uint8_t *data, size_t size) {
    uint8_t p1, p2;
    unsigned int tx;

    if (size < 2) {
        return 0;
    }
    p1 = data[0];
    p2 = data[1];
    data += 2;
    size -= 2;
    return handle_provide_nft_information(p1, p2, size, data, &tx) != SWO_SUCCESS;
}

/* Main fuzzing handler called by libfuzzer */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    init_fuzzing_environment();

    // Run the harness
    fuzzNFTInfo(data, size);

    return 0;
}
