#include "shared_context.h"

uint32_t set_result_perform_privacy_operation() {
    for (uint8_t i = 0; i < INT256_LENGTH; i++) {
        G_io_tx_buffer[i] = tmpCtx.publicKeyContext.publicKey.W[INT256_LENGTH - i];
    }
    // Scrub the source as soon as the secret has been copied to the reply
    // buffer. For the P2_SHARED_SECRET path this is X25519 secret material;
    // we don't want it lingering in tmpCtx until the next reset (CWE-312).
    explicit_bzero(&tmpCtx.publicKeyContext, sizeof(tmpCtx.publicKeyContext));
    return INT256_LENGTH;
}
