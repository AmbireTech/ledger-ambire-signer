#include "apdu_constants.h"
#include "public_keys.h"
#include "network.h"
#include "os_pki.h"
#include "token_info.h"

uint16_t handle_provide_erc20_token_information(uint8_t p1,
                                                uint8_t p2,
                                                uint8_t lc,
                                                const uint8_t *data,
                                                unsigned int *tx) {
    uint32_t offset = 0;
    uint8_t ticker_length;
    const char *ticker;
    const uint8_t *address;
    uint32_t decimals_32;
    uint32_t chain_id_32;
    uint64_t chain_id;
    uint8_t hash[INT256_LENGTH];
    int index;
    s_token_info info = {0};

    if ((p1 != 0) || (p2 != 0)) {
        return SWO_INCORRECT_P1_P2;
    }
    if ((offset + sizeof(ticker_length)) > lc) {
        return SWO_INCORRECT_DATA;
    }
    ticker_length = data[offset];
    offset += sizeof(ticker_length);

    if ((offset + ticker_length) > lc) {
        return SWO_INCORRECT_DATA;
    }
    ticker = (const char *) &data[offset];
    offset += ticker_length;

    if ((offset + ADDRESS_LENGTH) > lc) {
        return SWO_INCORRECT_DATA;
    }
    address = &data[offset];
    offset += ADDRESS_LENGTH;

    // TODO: 4 bytes for this is overkill
    if ((offset + sizeof(decimals_32)) > lc) {
        return SWO_INCORRECT_DATA;
    }
    decimals_32 = U4BE(data, offset);
    offset += sizeof(decimals_32);

    // TODO: Handle 64-bit long chain IDs
    if ((offset + sizeof(chain_id_32)) > lc) {
        return SWO_INCORRECT_DATA;
    }
    chain_id_32 = U4BE(data, offset);
    chain_id = (uint64_t) chain_id_32;
    offset += sizeof(chain_id_32);

    if (offset >= lc) {
        // no signature
        return SWO_INCORRECT_DATA;
    }

    // sanity checks
    if (decimals_32 > UINT8_MAX) {
        PRINTF("Error: decimals received does not fit on one byte!\n");
        return SWO_INCORRECT_DATA;
    }
    if ((ticker_length + 1) > sizeof(info.ticker)) {
        return SWO_INCORRECT_DATA;
    }
    if (!app_compatible_with_chain_id(&chain_id)) {
        UNSUPPORTED_CHAIN_ID_MSG(chain_id);
        return SWO_INCORRECT_DATA;
    }

    // signature is computed on everything but the ticker length
    cx_hash_sha256(&data[sizeof(ticker_length)],
                   offset - sizeof(ticker_length),
                   hash,
                   CX_SHA256_SIZE);
    if (check_signature_with_pubkey(hash,
                                    sizeof(hash),
                                    LEDGER_SIGNATURE_PUBLIC_KEY,
                                    sizeof(LEDGER_SIGNATURE_PUBLIC_KEY),
                                    CERTIFICATE_PUBLIC_KEY_USAGE_COIN_META,
                                    &data[offset],
                                    lc - offset) != true) {
        return SWO_INCORRECT_DATA;
    }

    memcpy(info.address, address, sizeof(info.address));
    memcpy(info.ticker, ticker, ticker_length);
    info.decimals = (uint8_t) decimals_32;
    info.chain_id = (uint64_t) chain_id_32;

    if ((index = set_token_info(&info)) == -1) {
        return SWO_INSUFFICIENT_MEMORY;
    }
    if (index > UINT8_MAX) {
        // Could not represent it on one byte
        return SWO_INCORRECT_DATA;
    }

    G_io_tx_buffer[0] = (uint8_t) index;
    *tx += 1;
    return SWO_SUCCESS;
}
