/**
 * @file test_cmd_set_eth2_withdrawal_index.c
 * @brief Unit tests for handle_set_eth2_withdrawal_index at
 *        src/features/set_eth2_withdrawal_index/cmd_set_eth2_withdrawal_index.c.
 *
 * Trivial APDU: the host sets the Beacon-Chain withdrawal credential index
 * (uint32 BE). Pin the three checks: data length must be exactly 4,
 * P1/P2 must both be zero, and the success path stores the BE value into
 * `eth2WithdrawalIndex`.
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
#include "withdrawal_index.h"

static int reset(void **state) {
    (void) state;
    eth2WithdrawalIndex = 0;
    return 0;
}

static void test_wrong_data_length_rejected(void **state) {
    (void) state;
    uint8_t data[3] = {0};
    assert_int_equal(handle_set_eth2_withdrawal_index(0, 0, data, 3), SWO_WRONG_DATA_LENGTH);
    assert_int_equal(handle_set_eth2_withdrawal_index(0, 0, data, 5), SWO_WRONG_DATA_LENGTH);
    // eth2WithdrawalIndex MUST stay untouched on a rejected APDU.
    assert_int_equal(eth2WithdrawalIndex, 0);
}

static void test_wrong_p1_rejected(void **state) {
    (void) state;
    uint8_t data[4] = {0xDE, 0xAD, 0xBE, 0xEF};
    assert_int_equal(handle_set_eth2_withdrawal_index(1, 0, data, 4), SWO_WRONG_P1_P2);
    assert_int_equal(eth2WithdrawalIndex, 0);
}

static void test_wrong_p2_rejected(void **state) {
    (void) state;
    uint8_t data[4] = {0xDE, 0xAD, 0xBE, 0xEF};
    assert_int_equal(handle_set_eth2_withdrawal_index(0, 1, data, 4), SWO_WRONG_P1_P2);
    assert_int_equal(eth2WithdrawalIndex, 0);
}

static void test_success_stores_be_index(void **state) {
    (void) state;
    uint8_t data[4] = {0x12, 0x34, 0x56, 0x78};
    assert_int_equal(handle_set_eth2_withdrawal_index(0, 0, data, 4), SWO_SUCCESS);
    assert_int_equal(eth2WithdrawalIndex, 0x12345678U);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup(test_wrong_data_length_rejected, reset),
        cmocka_unit_test_setup(test_wrong_p1_rejected, reset),
        cmocka_unit_test_setup(test_wrong_p2_rejected, reset),
        cmocka_unit_test_setup(test_success_stores_be_index, reset),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
