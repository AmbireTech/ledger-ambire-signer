#include "status_words.h"
#include "cmd_eip712_v2_values.h"
#include "tlv_apdu.h"
#include "apdu_constants.h"
#include "eip712_v2_values.h"

uint16_t handle_eip712_v2_values(uint8_t p1, uint8_t p2, uint8_t lc, const uint8_t *payload) {
    if (appState != APP_STATE_IDLE) {
        return SWO_COMMAND_NOT_ALLOWED;
    }
    if (p2 != P2_EIP712_V2_IMPLEM) {
        return SWO_INCORRECT_P1_P2;
    }
    if (!tlv_from_apdu(p1 == P1_FIRST_CHUNK, lc, payload, &handle_eip712_v2_values_struct)) {
        return SWO_INCORRECT_DATA;
    }
    return SWO_SUCCESS;
}
