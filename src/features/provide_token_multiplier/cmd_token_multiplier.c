#include "cmd_token_multiplier.h"
#include "multiplier_info.h"
#include "tlv_apdu.h"
#include "tlv_utils.h"
#include "apdu_constants.h"

#define TYPE_TOKEN_MULTIPLIER 0x27
#define STRUCT_VERSION        0x01

// TODO(CUSTOM-08): the dedicated LedgerPKI key_usage for the ERC-8056 multiplier
// descriptor must be defined by Architecture/enclave and exposed by the OS SDK
// (os_pki.h). Until then we use a provisional value; it MUST be kept in sync
// with the SDK definition when it ships.
#ifndef CERTIFICATE_PUBLIC_KEY_USAGE_TOKEN_MULTIPLIER
#define CERTIFICATE_PUBLIC_KEY_USAGE_TOKEN_MULTIPLIER 0x12
#endif

// clang-format off
typedef struct {
    token_multiplier_t multiplier_info;
    uint8_t sig_size;
    const uint8_t *sig;
    cx_sha256_t hash_ctx;
    TLV_reception_t received_tags;
} s_token_multiplier_ctx;
// clang-format on

/**
 * @brief Parse the STRUCTURE_TYPE value.
 *
 * @param[in] data the tlv data
 * @param[in] context Token multiplier context
 * @return whether it was successful
 */
static bool handle_struct_type(const tlv_data_t *data, s_token_multiplier_ctx *context) {
    UNUSED(context);
    if (!tlv_enforce_u8_value(data, TYPE_TOKEN_MULTIPLIER)) {
        PRINTF("Invalid STRUCTURE_TYPE value\n");
        return false;
    }
    return true;
}

/**
 * @brief Parse the STRUCTURE_VERSION value.
 *
 * @param[in] data the tlv data
 * @param[in] context Token multiplier context
 * @return whether it was successful
 */
static bool handle_struct_version(const tlv_data_t *data, s_token_multiplier_ctx *context) {
    UNUSED(context);
    if (!tlv_enforce_u8_value(data, STRUCT_VERSION)) {
        PRINTF("Invalid STRUCTURE_VERSION value\n");
        return false;
    }
    return true;
}

/**
 * @brief Parse and check the CHALLENGE value.
 *
 * @param[in] data the tlv data
 * @param[in] context Token multiplier context
 * @return whether it was successful
 *
 * @note Anti-replay: the challenge must match the one previously returned by
 * GET_CHALLENGE, ensuring the descriptor was crafted for this signing session.
 */
static bool handle_challenge(const tlv_data_t *data, s_token_multiplier_ctx *context) {
    UNUSED(context);
    return tlv_check_challenge(data);
}

/**
 * @brief Parse the ADDRESS value.
 *
 * @param[in] data the tlv data
 * @param[in] context Token multiplier context
 * @return whether it was successful
 *
 * @note Contract address of the ERC-8056 token the multiplier applies to.
 */
static bool handle_address(const tlv_data_t *data, s_token_multiplier_ctx *context) {
    return tlv_get_address(data, context->multiplier_info.address);
}

/**
 * @brief Parse the CHAIN_ID value.
 *
 * @param[in] data the tlv data
 * @param[in] context Token multiplier context
 * @return whether it was successful
 */
static bool handle_chain_id(const tlv_data_t *data, s_token_multiplier_ctx *context) {
    return tlv_get_chain_id(data, &context->multiplier_info.chain_id);
}

/**
 * @brief Parse the MULTIPLIER value.
 *
 * @param[in] data the tlv data
 * @param[in] context Token multiplier context
 * @return whether it was successful
 *
 * @note 18-decimals fixed-point uint256, big-endian (1e18 == 1.0x), as returned
 * by the token's uiMultiplier().
 */
static bool handle_multiplier(const tlv_data_t *data, s_token_multiplier_ctx *context) {
    buffer_t field = {0};
    if (!get_buffer_from_tlv_data(data, &field, 1, INT256_LENGTH)) {
        PRINTF("MULTIPLIER: failed to extract\n");
        return false;
    }
    convertUint256BE(field.ptr, field.size, &context->multiplier_info.multiplier);
    return true;
}

/**
 * @brief Parse the SIGNATURE value.
 *
 * @param[in] data the tlv data
 * @param[in] context Token multiplier context
 * @return whether it was successful
 */
static bool handle_signature(const tlv_data_t *data, s_token_multiplier_ctx *context) {
    buffer_t sig = {0};
    if (!get_buffer_from_tlv_data(data,
                                  &sig,
                                  CX_ECDSA_SHA256_SIG_MIN_ASN1_LENGTH,
                                  CX_ECDSA_SHA256_SIG_MAX_ASN1_LENGTH)) {
        PRINTF("SIGNATURE: failed to extract\n");
        return false;
    }
    context->sig_size = sig.size;
    context->sig = sig.ptr;
    return true;
}

// Define TLV tags for the token multiplier descriptor.
#define TOKEN_MULTIPLIER_TAGS(X)                                           \
    X(0x01, TAG_STRUCT_TYPE, handle_struct_type, ENFORCE_UNIQUE_TAG)       \
    X(0x02, TAG_STRUCT_VERSION, handle_struct_version, ENFORCE_UNIQUE_TAG) \
    X(0x12, TAG_CHALLENGE, handle_challenge, ENFORCE_UNIQUE_TAG)           \
    X(0x22, TAG_ADDRESS, handle_address, ENFORCE_UNIQUE_TAG)               \
    X(0x23, TAG_CHAIN_ID, handle_chain_id, ENFORCE_UNIQUE_TAG)             \
    X(0x30, TAG_MULTIPLIER, handle_multiplier, ENFORCE_UNIQUE_TAG)         \
    X(0x15, TAG_SIGNATURE, handle_signature, ENFORCE_UNIQUE_TAG)

// Forward declaration of common handler
static bool token_multiplier_common_handler(const tlv_data_t *data,
                                            s_token_multiplier_ctx *context);

// Generate TLV parser for the token multiplier descriptor
DEFINE_TLV_PARSER(TOKEN_MULTIPLIER_TAGS,
                  &token_multiplier_common_handler,
                  token_multiplier_tlv_parser)

/**
 * @brief Common handler called for all tags to hash them (except signature).
 *
 * @param[in] data the TLV data
 * @param[out] context Token multiplier context
 * @return whether it was successful
 */
static bool token_multiplier_common_handler(const tlv_data_t *data,
                                            s_token_multiplier_ctx *context) {
    if (data->tag != TAG_SIGNATURE) {
        hash_nbytes(data->raw.ptr, data->raw.size, (cx_hash_t *) &context->hash_ctx);
    }
    return true;
}

/**
 * @brief Verify the payload signature
 *
 * Verify the SHA-256 hash of the payload against the public key
 *
 * @param[in] context Token multiplier context
 * @return whether it was successful
 */
static bool verify_signature(const s_token_multiplier_ctx *context) {
    uint8_t hash[INT256_LENGTH];

    if (finalize_hash((cx_hash_t *) &context->hash_ctx, hash, sizeof(hash)) != true) {
        PRINTF("Could not finalize struct hash!\n");
        return false;
    }
    // The challenge is single-use: burn it as soon as the descriptor is consumed.
    roll_challenge();
    if (check_signature_with_pubkey(hash,
                                    sizeof(hash),
                                    NULL,
                                    0,
                                    CERTIFICATE_PUBLIC_KEY_USAGE_TOKEN_MULTIPLIER,
                                    (uint8_t *) context->sig,
                                    context->sig_size) != true) {
        return false;
    }
    return true;
}

/**
 * @brief Verify the received fields.
 *
 * Check that all the mandatory fields are present.
 *
 * @param[in] context Token multiplier context
 * @return whether it was successful
 */
static bool verify_fields(const s_token_multiplier_ctx *context) {
    return TLV_CHECK_RECEIVED_TAGS(context->received_tags,
                                   TAG_STRUCT_TYPE,
                                   TAG_STRUCT_VERSION,
                                   TAG_CHALLENGE,
                                   TAG_ADDRESS,
                                   TAG_CHAIN_ID,
                                   TAG_MULTIPLIER,
                                   TAG_SIGNATURE);
}

/**
 * @brief Print the token multiplier parameters.
 *
 * @param[in] context Token multiplier context
 * Only for debug purpose.
 */
static void print_token_multiplier_info(const s_token_multiplier_ctx *context) {
    PRINTF("================ TOKEN MULTIPLIER ================\n");
    PRINTF("chain ID = %llu\n", context->multiplier_info.chain_id);
    PRINTF("address  = 0x%.*h\n", ADDRESS_LENGTH, context->multiplier_info.address);
}

/**
 * @brief Parse, verify and register a token multiplier TLV payload.
 *
 * @param[in] buf TLV buffer received (fully reassembled)
 * @return whether the payload was handled successfully
 */
static bool handle_tlv_payload(const buffer_t *buf) {
    s_token_multiplier_ctx ctx = {0};

    // Initialize the hash context
    cx_sha256_init(&ctx.hash_ctx);

    if (!token_multiplier_tlv_parser(buf, &ctx, &ctx.received_tags)) {
        return false;
    }
    if (!verify_fields(&ctx) || !verify_signature(&ctx)) {
        return false;
    }
    if (set_token_multiplier(&ctx.multiplier_info) == -1) {
        PRINTF("Error: failed to store token multiplier!\n");
        return false;
    }
    print_token_multiplier_info(&ctx);
    return true;
}

/**
 * @brief Handle the PROVIDE_TOKEN_MULTIPLIER APDU.
 *
 * Reassembles the (possibly chunked) TLV descriptor then hands it over to
 * @ref handle_tlv_payload for parsing and LedgerPKI verification.
 *
 * @param[in] p1 APDU parameter 1 (indicates whether this is the first chunk)
 * @param[in] p2 APDU parameter 2 (unused)
 * @param[in] lc length of the payload
 * @param[in] payload buffer received
 * @return APDU Response code
 */
uint16_t handle_token_multiplier(uint8_t p1, uint8_t p2, uint8_t lc, const uint8_t *payload) {
    uint16_t sw = SWO_PARAMETER_ERROR_NO_INFO;

    switch (p2) {
        case 0x00:
            if (!tlv_from_apdu(p1 == P1_FIRST_CHUNK, lc, payload, &handle_tlv_payload)) {
                sw = SWO_INCORRECT_DATA;
            } else {
                sw = SWO_SUCCESS;
            }
            break;
        default:
            PRINTF("Error: Unexpected P2 (%u)!\n", p2);
            sw = SWO_WRONG_P1_P2;
            break;
    }
    return sw;
}
