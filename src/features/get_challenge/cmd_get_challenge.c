#include "os_io.h"
#include "cx.h"
#include "apdu_constants.h"
#include "challenge.h"

#ifdef HAVE_CHALLENGE_NO_CHECK
#warning \
    "HAVE_CHALLENGE_NO_CHECK is enabled: challenge generation is deterministic and challenge verification is bypassed. This must never reach a release build."
#endif

static uint32_t challenge;

/**
 * Generate a new challenge from the Random Number Generator
 */
void roll_challenge(void) {
#ifdef HAVE_CHALLENGE_NO_CHECK
    challenge = 0x12345678;
#else
    challenge = cx_rng_u32();
#endif
}

/**
 * Get the current challenge
 *
 * @return challenge
 */
uint32_t get_challenge(void) {
    return challenge;
}

/**
 * Check the challenge
 *
 * @return whether the received challenge matches the current one
 */
bool check_challenge(uint32_t received_challenge) {
    UNUSED(received_challenge);
#ifndef HAVE_CHALLENGE_NO_CHECK
    if (received_challenge != challenge) {
        PRINTF("Error: challenge mismatch!\n");
        return false;
    }
#endif
    return true;
}

/**
 * Send back the current challenge
 */
uint16_t handle_get_challenge(unsigned int *tx) {
    PRINTF("New challenge -> %u\n", get_challenge());
    U4BE_ENCODE(G_io_tx_buffer, 0, get_challenge());
    *tx += 4;
    return SWO_SUCCESS;
}
