/**
 * @file test_cmd_network_info.c
 * @brief Unit tests for handle_network_info at
 *        src/features/provide_network_info/cmd_network_info.c.
 *
 * cmd_network_info multiplexes three sub-commands behind P2:
 *
 *   P2 = NETWORK_CONFIG (0x00) -- host streams a TLV-encoded network
 *        descriptor (name, chain_id, ticker, icon hash). The Ethereum
 *        app appends it to g_dynamic_network_list. A failed parse
 *        triggers network_info_cleanup() on the partially-added node.
 *
 *   P2 = NETWORK_ICON   (0x01) -- host streams the icon blob; handled
 *        by network_icon.c. Errors trigger cleanup on the same node.
 *
 *   P2 = GET_INFO       (0x02) -- host queries the current registry:
 *        the device fills G_io_tx_buffer with `<n_networks>` then
 *        `<chain_id_be>` for each registered network (sentinel
 *        chain_id == 0 entries are skipped) and bails out if the
 *        output buffer is about to overflow.
 *
 *   default            -- SWO_WRONG_P1_P2 plus cleanup, so an unknown
 *        P2 cannot leave a half-registered network behind.
 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

#include "shared_context.h"
#include "apdu_constants.h"
#include "tlv_apdu.h"
#include "cmd_network_info.h"
#include "network_info.h"
#include "network_icon.h"
#include "read.h"
#include "wraps.h"

// =============================================================================
// Wraps
// =============================================================================

uint16_t __wrap_handle_network_icon_chunks(uint8_t p1, const buffer_t *buf) {
    (void) p1;
    (void) buf;
    return (uint16_t) mock();
}

static int g_cleanup_calls = 0;
static network_info_t *g_cleanup_last_arg = NULL;
void __wrap_network_info_cleanup(network_info_t *network) {
    g_cleanup_calls++;
    g_cleanup_last_arg = network;
}

// Address-only reference: cmd_network_info passes &handle_network_tlv_payload
// to tlv_from_apdu. Since tlv_from_apdu is wrapped, the callback is never
// invoked -- but the linker still needs the symbol to resolve.
bool handle_network_tlv_payload(const buffer_t *buf) {
    (void) buf;
    return true;
}

// =============================================================================
// Fixture
// =============================================================================

extern network_info_t *g_dynamic_network_list;  // mocks/app_globals.c
extern network_info_t *g_last_added_network;    // mocks/app_globals.c

static int reset(void **state) {
    (void) state;
    g_dynamic_network_list = NULL;
    g_last_added_network = NULL;
    g_tlv_from_apdu_first_chunk = false;
    g_tlv_from_apdu_lc = 0;
    g_tlv_from_apdu_ret = TLV_APDU_SUCCESS;
    g_cleanup_calls = 0;
    g_cleanup_last_arg = NULL;
    memset(G_io_tx_buffer, 0, sizeof(G_io_tx_buffer));
    return 0;
}

// =============================================================================
// P2 = NETWORK_CONFIG
// =============================================================================

static void test_network_config_tlv_success_returns_success(void **state) {
    (void) state;
    unsigned int tx = 0;
    g_tlv_from_apdu_ret = TLV_APDU_SUCCESS;
    uint16_t sw = handle_network_info(P1_FIRST_CHUNK, /*p2*/ 0x00, (uint8_t *) "", 32, &tx);
    assert_int_equal(sw, SWO_SUCCESS);
    assert_int_equal(g_cleanup_calls, 0);
    assert_true(g_tlv_from_apdu_first_chunk);
    assert_int_equal(g_tlv_from_apdu_lc, 32);
}

static void test_network_config_tlv_failure_cleans_up(void **state) {
    (void) state;
    unsigned int tx = 0;
    // Simulate a half-added network so cleanup has a non-NULL arg to
    // free -- this proves the cleanup call passes the right node.
    network_info_t partial = {0};
    g_last_added_network = &partial;
    g_tlv_from_apdu_ret = TLV_APDU_ERROR;
    uint16_t sw = handle_network_info(P1_FOLLOWING_CHUNK, 0x00, (uint8_t *) "", 32, &tx);
    assert_int_equal(sw, SWO_INCORRECT_DATA);
    assert_int_equal(g_cleanup_calls, 1);
    assert_ptr_equal(g_cleanup_last_arg, &partial);
}

// =============================================================================
// P2 = NETWORK_ICON
// =============================================================================

static void test_network_icon_success_returns_success(void **state) {
    (void) state;
    unsigned int tx = 0;
    will_return(__wrap_handle_network_icon_chunks, SWO_SUCCESS);
    uint16_t sw = handle_network_info(P1_FIRST_CHUNK, /*p2*/ 0x01, (uint8_t *) "", 32, &tx);
    assert_int_equal(sw, SWO_SUCCESS);
    assert_int_equal(g_cleanup_calls, 0);
}

static void test_network_icon_failure_cleans_up(void **state) {
    (void) state;
    unsigned int tx = 0;
    network_info_t partial = {0};
    g_last_added_network = &partial;
    will_return(__wrap_handle_network_icon_chunks, SWO_INCORRECT_DATA);
    uint16_t sw = handle_network_info(P1_FOLLOWING_CHUNK, 0x01, (uint8_t *) "", 32, &tx);
    assert_int_equal(sw, SWO_INCORRECT_DATA);
    assert_int_equal(g_cleanup_calls, 1);
}

// =============================================================================
// P2 = GET_INFO
// =============================================================================

static void test_get_info_invalid_p1_rejected(void **state) {
    (void) state;
    unsigned int tx = 0;
    uint16_t sw = handle_network_info(/*p1*/ 0xFF, /*p2*/ 0x02, (uint8_t *) "", 0, &tx);
    assert_int_equal(sw, SWO_WRONG_P1_P2);
    // Cleanup MUST still fire so an in-flight network from a previous
    // sequence isn't left dangling when the host sends a bogus P1.
    assert_int_equal(g_cleanup_calls, 1);
}

static void test_get_info_empty_list_returns_zero_count(void **state) {
    (void) state;
    unsigned int tx = 0;
    g_dynamic_network_list = NULL;
    uint16_t sw = handle_network_info(/*p1*/ 0x00, /*p2*/ 0x02, (uint8_t *) "", 0, &tx);
    assert_int_equal(sw, SWO_SUCCESS);
    assert_int_equal(tx, 1);  // just the count byte
    assert_int_equal(G_io_tx_buffer[0], 0);
}

static void test_get_info_single_network_writes_chain_id_be(void **state) {
    (void) state;
    unsigned int tx = 0;
    network_info_t n = {0};
    n.chain_id = 137;  // Polygon
    g_dynamic_network_list = &n;
    uint16_t sw = handle_network_info(0x00, 0x02, (uint8_t *) "", 0, &tx);
    assert_int_equal(sw, SWO_SUCCESS);
    assert_int_equal(tx, 1 + 8);
    assert_int_equal(G_io_tx_buffer[0], 1);
    // chain_id encoded big-endian at offset 1.
    assert_int_equal(read_u64_be(G_io_tx_buffer, 1), 137);
}

static void test_get_info_walks_multi_network_list(void **state) {
    (void) state;
    unsigned int tx = 0;
    network_info_t a = {0};
    a.chain_id = 1;
    network_info_t b = {0};
    b.chain_id = 137;
    network_info_t c = {0};
    c.chain_id = 8453;  // Base
    a.node.next = (flist_node_t *) &b;
    b.node.next = (flist_node_t *) &c;
    g_dynamic_network_list = &a;
    uint16_t sw = handle_network_info(0x00, 0x02, (uint8_t *) "", 0, &tx);
    assert_int_equal(sw, SWO_SUCCESS);
    assert_int_equal(tx, 1 + 3 * 8);
    assert_int_equal(G_io_tx_buffer[0], 3);
    assert_int_equal(read_u64_be(G_io_tx_buffer, 1), 1);
    assert_int_equal(read_u64_be(G_io_tx_buffer, 9), 137);
    assert_int_equal(read_u64_be(G_io_tx_buffer, 17), 8453);
}

static void test_get_info_breaks_when_buffer_would_overflow(void **state) {
    (void) state;
    // G_io_tx_buffer is sized at OS_IO_BUFFER_SIZE + 1 (273 bytes). The
    // count byte at offset 0 plus 34 chain-ids at 8 bytes each fills it
    // exactly to 273 -- the 35th iteration's overflow check trips and
    // the walk stops. Without this guard a long dynamic-network list
    // could overrun the APDU response buffer (CWE-787).
    unsigned int tx = 0;
    static network_info_t nodes[36];
    memset(nodes, 0, sizeof(nodes));
    for (int i = 0; i < 36; i++) {
        nodes[i].chain_id = (uint64_t) (i + 1);
        if (i + 1 < 36) {
            nodes[i].node.next = (flist_node_t *) &nodes[i + 1];
        }
    }
    g_dynamic_network_list = &nodes[0];
    uint16_t sw = handle_network_info(0x00, 0x02, (uint8_t *) "", 0, &tx);
    assert_int_equal(sw, SWO_SUCCESS);
    // 34 networks fit (1 count byte + 34*8 = 273), the 35th and 36th
    // trip the overflow check.
    assert_int_equal(G_io_tx_buffer[0], 34);
    assert_int_equal(tx, 1 + 34 * 8);
}

static void test_get_info_skips_zero_chain_id_sentinel(void **state) {
    (void) state;
    // chain_id == 0 means "registration not bound to a specific chain"; the
    // dynamic-list walk skips it. The count must reflect only real entries.
    unsigned int tx = 0;
    network_info_t a = {0};
    a.chain_id = 1;
    network_info_t z = {0};
    z.chain_id = 0;  // sentinel
    network_info_t b = {0};
    b.chain_id = 137;
    a.node.next = (flist_node_t *) &z;
    z.node.next = (flist_node_t *) &b;
    g_dynamic_network_list = &a;
    uint16_t sw = handle_network_info(0x00, 0x02, (uint8_t *) "", 0, &tx);
    assert_int_equal(sw, SWO_SUCCESS);
    assert_int_equal(tx, 1 + 2 * 8);
    assert_int_equal(G_io_tx_buffer[0], 2);
    assert_int_equal(read_u64_be(G_io_tx_buffer, 1), 1);
    assert_int_equal(read_u64_be(G_io_tx_buffer, 9), 137);
}

// =============================================================================
// default branch -- unknown P2
// =============================================================================

static void test_unknown_p2_returns_wrong_p1_p2_and_cleans_up(void **state) {
    (void) state;
    unsigned int tx = 0;
    network_info_t partial = {0};
    g_last_added_network = &partial;
    uint16_t sw = handle_network_info(P1_FIRST_CHUNK, /*p2*/ 0xEE, (uint8_t *) "", 32, &tx);
    assert_int_equal(sw, SWO_WRONG_P1_P2);
    assert_int_equal(g_cleanup_calls, 1);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup(test_network_config_tlv_success_returns_success, reset),
        cmocka_unit_test_setup(test_network_config_tlv_failure_cleans_up, reset),
        cmocka_unit_test_setup(test_network_icon_success_returns_success, reset),
        cmocka_unit_test_setup(test_network_icon_failure_cleans_up, reset),
        cmocka_unit_test_setup(test_get_info_invalid_p1_rejected, reset),
        cmocka_unit_test_setup(test_get_info_empty_list_returns_zero_count, reset),
        cmocka_unit_test_setup(test_get_info_single_network_writes_chain_id_be, reset),
        cmocka_unit_test_setup(test_get_info_walks_multi_network_list, reset),
        cmocka_unit_test_setup(test_get_info_skips_zero_chain_id_sentinel, reset),
        cmocka_unit_test_setup(test_get_info_breaks_when_buffer_would_overflow, reset),
        cmocka_unit_test_setup(test_unknown_p2_returns_wrong_p1_p2_and_cleans_up, reset),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
