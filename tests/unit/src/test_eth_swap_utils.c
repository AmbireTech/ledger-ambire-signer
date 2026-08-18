/**
 * @file test_eth_swap_utils.c
 * @brief Unit tests for the swap-mode integration helpers at
 *        src/swap/eth_swap_utils.c.
 *
 * Three concerns are covered:
 *   - parse_swap_config: the binary configuration the Exchange app hands
 *     the Ethereum app at swap-init time. The buffer carries a swapped-
 *     asset ticker + decimals + 8-byte BE chain_id, and optionally a
 *     fees-asset ticker + decimals (fees decimals must equal
 *     WEI_TO_ETHER). The parser is a security boundary — it must reject
 *     malformed lengths and mismatched fees decimals.
 *   - get_asset_info_on_network: chooses between
 *     context->fees_asset_info, context->swapped_asset_info, or the
 *     displayable ticker for the chain depending on (is_fee,
 *     fees_ticker_present, chain_id) shape.
 *   - swap_check_{destination, amount, fee}: NULL-guard + match path.
 *     The mismatch path calls app_exit() on the device (noreturn) and
 *     is therefore not exercised here.
 */

#include "unity.h"
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

#include "eth_swap_utils.h"
#include "shared_context.h"
#include "wraps.h"

// =============================================================================
// Globals
// =============================================================================

// =============================================================================
// Wraps
// =============================================================================

static const char *g_displayable_ticker_ret = "ETH";
const char *get_displayable_ticker(const uint64_t *chain_id,
                                   const chain_config_t *config,
                                   bool mainnet_only) {
    (void) chain_id;
    (void) config;
    (void) mainnet_only;
    return g_displayable_ticker_ret;
}

// G_io_apdu_buffer is referenced by the send_swap_error_with_string macro
// expansion via sizeof(). Provide a global with the standard 260-byte size.
unsigned char G_io_apdu_buffer[260];

// Stubs for the abort path (not exercised by these tests — the mismatch
// branch calls app_exit() after send_swap_error_with_buffers).
void send_swap_error_with_buffers(uint16_t status_word,
                                  uint8_t common_error_code,
                                  uint8_t application_specific_error_code,
                                  void *string_buffer,
                                  uint8_t buffer_count) {
    (void) status_word;
    (void) common_error_code;
    (void) application_specific_error_code;
    (void) string_buffer;
    (void) buffer_count;
}
// app_exit is declared noreturn in the SDK. The stub must honor that
// contract — if a test ever hits the mismatch path by accident, we want
// it to abort the test process rather than silently fall through to
// unreachable code.
__attribute__((noreturn)) void app_exit(void) {
    TEST_FAIL_MESSAGE("app_exit() reached unexpectedly");
    while (1) {
    }
}

// =============================================================================
// Fixture
// =============================================================================

static void reset(void) {
    memset(&strings, 0, sizeof(strings));
    g_displayable_ticker_ret = "ETH";
}

// =============================================================================
// parse_swap_config — happy paths
// =============================================================================

void test_parse_with_asset_chain_and_fees(void) {
    // asset_ticker_len=3, "ETH", decimals=18, chain_id=1 (BE),
    // fees_ticker_len=3, "ETH", decimals=18 (WEI_TO_ETHER)
    const uint8_t config[] = {
        0x03,
        'E',
        'T',
        'H',
        0x12,  // asset
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x01,  // chain_id = 1
        0x03,
        'E',
        'T',
        'H',
        0x12,  // fees
    };
    swap_context_t ctx;
    TEST_ASSERT_TRUE(parse_swap_config(config, sizeof(config), &ctx));
    TEST_ASSERT_EQUAL_STRING(ctx.swapped_asset_info.ticker, "ETH");
    TEST_ASSERT_EQUAL(ctx.swapped_asset_info.decimals, 18);
    TEST_ASSERT_EQUAL(ctx.chain_id, 1);
    TEST_ASSERT_EQUAL_STRING(ctx.fees_asset_info.ticker, "ETH");
    TEST_ASSERT_EQUAL(ctx.fees_asset_info.decimals, 18);
}

void test_parse_without_fees_section_defaults_fees(void) {
    // No fees block — the parser leaves the default fees ticker empty
    // (so get_asset_info_on_network falls back to get_displayable_ticker)
    // and default fees decimals = WEI_TO_ETHER (set up by explicit_bzero
    // followed by an explicit assignment in the parser).
    const uint8_t config[] = {
        0x04,
        'U',
        'S',
        'D',
        'C',
        0x06,  // asset USDC, 6 dec
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x89,  // chain_id = 137
    };
    swap_context_t ctx;
    TEST_ASSERT_TRUE(parse_swap_config(config, sizeof(config), &ctx));
    TEST_ASSERT_EQUAL_STRING(ctx.swapped_asset_info.ticker, "USDC");
    TEST_ASSERT_EQUAL(ctx.swapped_asset_info.decimals, 6);
    TEST_ASSERT_EQUAL(ctx.chain_id, 137);
    TEST_ASSERT_EQUAL(ctx.fees_asset_info.ticker[0], '\0');
    TEST_ASSERT_EQUAL(ctx.fees_asset_info.decimals, 18 /* WEI_TO_ETHER */);
}

// =============================================================================
// parse_swap_config — input validation
// =============================================================================

void test_parse_null_inputs_rejected(void) {
    swap_context_t ctx;
    const uint8_t buf[1] = {0};
    TEST_ASSERT_FALSE(parse_swap_config(NULL, 1, &ctx));
    TEST_ASSERT_FALSE(parse_swap_config(buf, 0, &ctx));
    TEST_ASSERT_FALSE(parse_swap_config(buf, 1, NULL));
}

void test_parse_ticker_len_zero_rejected(void) {
    const uint8_t config[] = {0x00};
    swap_context_t ctx;
    TEST_ASSERT_FALSE(parse_swap_config(config, sizeof(config), &ctx));
}

void test_parse_ticker_len_oversized_rejected(void) {
    // MAX_TICKER_LEN == 51, the parser rejects (MAX_TICKER_LEN - 2)+ which
    // is 50+. A ticker length of 50 is also rejected per the > check.
    const uint8_t config[] = {50};
    swap_context_t ctx;
    TEST_ASSERT_FALSE(parse_swap_config(config, sizeof(config), &ctx));
}

void test_parse_truncated_ticker_rejected(void) {
    // Declares 5 bytes of ticker but only 2 actually follow.
    const uint8_t config[] = {0x05, 'A', 'B'};
    swap_context_t ctx;
    TEST_ASSERT_FALSE(parse_swap_config(config, sizeof(config), &ctx));
}

void test_parse_missing_decimals_rejected(void) {
    // Ticker is fine but no decimals byte after.
    const uint8_t config[] = {0x03, 'E', 'T', 'H'};
    swap_context_t ctx;
    TEST_ASSERT_FALSE(parse_swap_config(config, sizeof(config), &ctx));
}

void test_parse_missing_chain_id_rejected(void) {
    // Asset complete, but no 8-byte chain_id.
    const uint8_t config[] = {0x03, 'E', 'T', 'H', 0x12, 0x00, 0x00, 0x00};
    swap_context_t ctx;
    TEST_ASSERT_FALSE(parse_swap_config(config, sizeof(config), &ctx));
}

void test_parse_invalid_fees_decimals_rejected(void) {
    // Fees decimals != WEI_TO_ETHER → security reject. The Exchange app
    // is supposed to send fees in native units (18 decimals).
    const uint8_t config[] = {
        0x03,
        'E',
        'T',
        'H',
        0x12,  // asset
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x01,
        0x03,
        'E',
        'T',
        'H',
        0x06,  // fees decimals = 6 (wrong!)
    };
    swap_context_t ctx;
    TEST_ASSERT_FALSE(parse_swap_config(config, sizeof(config), &ctx));
}

// =============================================================================
// get_asset_info_on_network
// =============================================================================

void test_asset_info_non_fee_uses_swapped(void) {
    swap_context_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    strlcpy(ctx.swapped_asset_info.ticker, "USDC", sizeof(ctx.swapped_asset_info.ticker));
    ctx.swapped_asset_info.decimals = 6;

    char *ticker = NULL;
    uint8_t decimals = 0;
    get_asset_info_on_network(false, &ctx, &g_chainConfig, &ticker, &decimals);
    TEST_ASSERT_EQUAL_STRING(ticker, "USDC");
    TEST_ASSERT_EQUAL(decimals, 6);
}

void test_asset_info_fee_with_fees_ticker_uses_it(void) {
    swap_context_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    strlcpy(ctx.fees_asset_info.ticker, "MATIC", sizeof(ctx.fees_asset_info.ticker));
    ctx.fees_asset_info.decimals = 18;

    char *ticker = NULL;
    uint8_t decimals = 0;
    get_asset_info_on_network(true, &ctx, &g_chainConfig, &ticker, &decimals);
    TEST_ASSERT_EQUAL_STRING(ticker, "MATIC");
    TEST_ASSERT_EQUAL(decimals, 18);
}

void test_asset_info_fee_empty_ticker_uses_displayable(void) {
    swap_context_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.chain_id = 137;
    ctx.fees_asset_info.decimals = 18;
    g_displayable_ticker_ret = "POL";

    char *ticker = NULL;
    get_asset_info_on_network(true, &ctx, &g_chainConfig, &ticker, NULL);
    TEST_ASSERT_EQUAL_STRING(ticker, "POL");
}

void test_asset_info_fee_empty_ticker_zero_chain_id_falls_back_to_config(void) {
    swap_context_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.chain_id = 0;  // missing
    g_chainConfig.chain_id = 1;
    g_displayable_ticker_ret = "ETH";

    char *ticker = NULL;
    get_asset_info_on_network(true, &ctx, &g_chainConfig, &ticker, NULL);
    // The parser must have copied g_chainConfig.chain_id into ctx.chain_id
    // as a fallback (so subsequent calls can reuse it).
    TEST_ASSERT_EQUAL(ctx.chain_id, 1);
    TEST_ASSERT_EQUAL_STRING(ticker, "ETH");
}

// =============================================================================
// swap_check_destination / amount / fee — NULL + match
// =============================================================================

void test_swap_check_destination_null_rejected(void) {
    TEST_ASSERT_FALSE(swap_check_destination(NULL));
}

void test_swap_check_destination_match(void) {
    strlcpy(strings.common.toAddress, "0xAbC123", sizeof(strings.common.toAddress));
    // Case-insensitive via the local strcasecmp_workaround.
    TEST_ASSERT_TRUE(swap_check_destination("0xabc123"));
    TEST_ASSERT_TRUE(swap_check_destination("0xABC123"));
}

void test_swap_check_amount_null_rejected(void) {
    TEST_ASSERT_FALSE(swap_check_amount(NULL));
}

void test_swap_check_amount_match(void) {
    strlcpy(strings.common.fullAmount, "1 ETH", sizeof(strings.common.fullAmount));
    TEST_ASSERT_TRUE(swap_check_amount("1 ETH"));
}

void test_swap_check_fee_null_rejected(void) {
    TEST_ASSERT_FALSE(swap_check_fee(NULL));
}

void test_swap_check_fee_match(void) {
    strlcpy(strings.common.maxFee, "0.001 ETH", sizeof(strings.common.maxFee));
    TEST_ASSERT_TRUE(swap_check_fee("0.001 ETH"));
}

// =============================================================================
// Runner
// =============================================================================

void setUp(void) {
    reset();
}
void tearDown(void) {
}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_parse_with_asset_chain_and_fees);
    RUN_TEST(test_parse_without_fees_section_defaults_fees);
    RUN_TEST(test_parse_null_inputs_rejected);
    RUN_TEST(test_parse_ticker_len_zero_rejected);
    RUN_TEST(test_parse_ticker_len_oversized_rejected);
    RUN_TEST(test_parse_truncated_ticker_rejected);
    RUN_TEST(test_parse_missing_decimals_rejected);
    RUN_TEST(test_parse_missing_chain_id_rejected);
    RUN_TEST(test_parse_invalid_fees_decimals_rejected);
    RUN_TEST(test_asset_info_non_fee_uses_swapped);
    RUN_TEST(test_asset_info_fee_with_fees_ticker_uses_it);
    RUN_TEST(test_asset_info_fee_empty_ticker_uses_displayable);
    RUN_TEST(test_asset_info_fee_empty_ticker_zero_chain_id_falls_back_to_config);
    RUN_TEST(test_swap_check_destination_null_rejected);
    RUN_TEST(test_swap_check_destination_match);
    RUN_TEST(test_swap_check_amount_null_rejected);
    RUN_TEST(test_swap_check_amount_match);
    RUN_TEST(test_swap_check_fee_null_rejected);
    RUN_TEST(test_swap_check_fee_match);
    return UNITY_END();
}
