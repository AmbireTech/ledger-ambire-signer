/**
 * @file test_cmd_get_app_configuration.c
 * @brief Unit tests for handle_get_app_configuration at
 *        src/features/get_app_configuration/cmd_get_app_configuration.c.
 *
 * The host calls GET_APP_CONFIGURATION at the start of every session
 * to learn:
 *   - which user-toggleable features are on (data signing allowed,
 *     transaction checks enabled / opted-in, external token needed),
 *   - which firmware version it is talking to.
 *
 * A bug here doesn't lose funds directly but it lies to the host
 * about the device's capability — leading to flows that get rejected
 * later in a confusing way (e.g. host streams typed data while
 * dataAllowed is actually off). Pin the wire layout.
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
#include "wraps.h"

static int reset(void **state) {
    (void) state;
    memset(&g_n_storage_writable, 0, sizeof(g_n_storage_writable));
    memset(G_io_tx_buffer, 0, sizeof(G_io_tx_buffer));
    return 0;
}

static void test_all_flags_off_only_external_token_set(void **state) {
    (void) state;
    // dataAllowed = false, tx_check_enable = false, tx_check_opt_in = false.
    // APP_FLAG_EXTERNAL_TOKEN_NEEDED is unconditional.
    unsigned int tx = 0;
    uint16_t sw = handle_get_app_configuration(&tx);
    assert_int_equal(sw, SWO_SUCCESS);
    assert_int_equal(tx, 4);
    assert_int_equal(G_io_tx_buffer[0], APP_FLAG_EXTERNAL_TOKEN_NEEDED);
}

static void test_data_allowed_flag_propagated(void **state) {
    (void) state;
    g_n_storage_writable.dataAllowed = true;
    unsigned int tx = 0;
    (void) handle_get_app_configuration(&tx);
    assert_true(G_io_tx_buffer[0] & APP_FLAG_DATA_ALLOWED);
    assert_true(G_io_tx_buffer[0] & APP_FLAG_EXTERNAL_TOKEN_NEEDED);
}

#ifdef HAVE_TRANSACTION_CHECKS
static void test_tx_checks_enable_flag_propagated(void **state) {
    (void) state;
    g_n_storage_writable.tx_check_enable = true;
    unsigned int tx = 0;
    (void) handle_get_app_configuration(&tx);
    assert_true(G_io_tx_buffer[0] & APP_FLAG_TX_CHECKS_ENABLE);
}

static void test_tx_checks_opt_in_flag_propagated(void **state) {
    (void) state;
    g_n_storage_writable.tx_check_opt_in = true;
    unsigned int tx = 0;
    (void) handle_get_app_configuration(&tx);
    assert_true(G_io_tx_buffer[0] & APP_FLAG_TX_CHECKS_OPT_IN);
}

static void test_all_tx_check_flags_combine(void **state) {
    (void) state;
    g_n_storage_writable.dataAllowed = true;
    g_n_storage_writable.tx_check_enable = true;
    g_n_storage_writable.tx_check_opt_in = true;
    unsigned int tx = 0;
    (void) handle_get_app_configuration(&tx);
    assert_int_equal(G_io_tx_buffer[0],
                     APP_FLAG_DATA_ALLOWED | APP_FLAG_TX_CHECKS_ENABLE | APP_FLAG_TX_CHECKS_OPT_IN |
                         APP_FLAG_EXTERNAL_TOKEN_NEEDED);
}
#endif

static void test_version_bytes_in_response(void **state) {
    (void) state;
    unsigned int tx = 0;
    (void) handle_get_app_configuration(&tx);
    // Version triple lives at offsets 1..3.
    assert_int_equal(G_io_tx_buffer[1], MAJOR_VERSION);
    assert_int_equal(G_io_tx_buffer[2], MINOR_VERSION);
    assert_int_equal(G_io_tx_buffer[3], PATCH_VERSION);
}

static void test_response_length_is_exactly_four(void **state) {
    (void) state;
    unsigned int tx = 42;  // sentinel
    (void) handle_get_app_configuration(&tx);
    // The handler overwrites `*tx` rather than adding to it.
    assert_int_equal(tx, 4);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup(test_all_flags_off_only_external_token_set, reset),
        cmocka_unit_test_setup(test_data_allowed_flag_propagated, reset),
#ifdef HAVE_TRANSACTION_CHECKS
        cmocka_unit_test_setup(test_tx_checks_enable_flag_propagated, reset),
        cmocka_unit_test_setup(test_tx_checks_opt_in_flag_propagated, reset),
        cmocka_unit_test_setup(test_all_tx_check_flags_combine, reset),
#endif
        cmocka_unit_test_setup(test_version_bytes_in_response, reset),
        cmocka_unit_test_setup(test_response_length_is_exactly_four, reset),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
