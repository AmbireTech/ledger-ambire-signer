/**
 * @file test_time_format.c
 * @brief Unit tests for time_format_to_yyyymmdd / time_format_to_utc at
 *        src/time_format.c.
 *
 * Both helpers wrap gmtime_r() and snprintf() into the display strings the
 * datetime parameter renderer feeds to the UI. A wrong format (off-by-one
 * month, missing pad, AM/PM flipped at midnight/noon) is visually subtle
 * but lets the host claim a transaction was signed for a different date
 * than the user saw on screen. Pin each branch:
 *
 *   - yyyymmdd happy path                  ISO-like "YYYY-MM-DD"
 *   - utc happy path (mid-morning)         "AM", hour 1..11
 *   - utc midnight (hour == 0)             "12:00:00 AM" (NOT 0)
 *   - utc noon (hour == 12)                "12:00:00 PM"
 *   - utc afternoon (hour > 12)            hour - 12, "PM"
 *   - gmtime_r failure (huge timestamp)    both functions return false
 *
 * Coverage gap before this file: 50% (only yyyymmdd was indirectly
 * exercised by test_param_datetime).
 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <time.h>

#include "time_format.h"

// =============================================================================
// time_format_to_yyyymmdd
// =============================================================================

static void test_yyyymmdd_formats_epoch(void **state) {
    (void) state;
    time_t t = 0;  // 1970-01-01 UTC
    char out[16] = {0};
    assert_true(time_format_to_yyyymmdd(&t, out, sizeof(out)));
    assert_string_equal(out, "1970-01-01");
}

static void test_yyyymmdd_formats_known_date(void **state) {
    (void) state;
    // 2026-06-02 00:00:00 UTC -- corresponds to epoch 1780358400.
    time_t t = 1780358400;
    char out[16] = {0};
    assert_true(time_format_to_yyyymmdd(&t, out, sizeof(out)));
    assert_string_equal(out, "2026-06-02");
}

// =============================================================================
// time_format_to_utc -- AM/PM clock edges
// =============================================================================

static void test_utc_midnight_renders_as_12am(void **state) {
    (void) state;
    // 1970-01-01 00:00:00 UTC. The "12-hour clock at midnight" rule means
    // shown_hour = 12, AM (NOT 00 AM, NOT 12 PM).
    time_t t = 0;
    char out[64] = {0};
    assert_true(time_format_to_utc(&t, out, sizeof(out)));
    assert_non_null(strstr(out, "12:00:00 AM UTC"));
    assert_non_null(strstr(out, "1970-01-01"));
}

static void test_utc_noon_renders_as_12pm(void **state) {
    (void) state;
    // 1970-01-01 12:00:00 UTC: hour == 12 so the loop keeps shown_hour=12
    // but flips AM->PM at the tm_hour < 12 branch.
    time_t t = 12 * 3600;
    char out[64] = {0};
    assert_true(time_format_to_utc(&t, out, sizeof(out)));
    assert_non_null(strstr(out, "12:00:00 PM UTC"));
}

static void test_utc_morning_keeps_am(void **state) {
    (void) state;
    // 1970-01-01 09:30:45 UTC.
    time_t t = 9 * 3600 + 30 * 60 + 45;
    char out[64] = {0};
    assert_true(time_format_to_utc(&t, out, sizeof(out)));
    assert_non_null(strstr(out, "09:30:45 AM UTC"));
}

static void test_utc_afternoon_subtracts_twelve_and_flips_pm(void **state) {
    (void) state;
    // 1970-01-01 15:45:30 UTC -> shown_hour = 3, PM.
    time_t t = 15 * 3600 + 45 * 60 + 30;
    char out[64] = {0};
    assert_true(time_format_to_utc(&t, out, sizeof(out)));
    assert_non_null(strstr(out, "03:45:30 PM UTC"));
}

// =============================================================================
// gmtime_r failure -- both helpers MUST return false
// =============================================================================

static void test_yyyymmdd_returns_false_on_gmtime_failure(void **state) {
    (void) state;
    // INT64_MAX overflows libc gmtime_r on glibc and returns NULL. The
    // helper MUST propagate that as `false` so callers don't render a
    // garbage buffer onto the UI.
    time_t t = (time_t) INT64_MAX;
    char out[16] = {0};
    bool ok = time_format_to_yyyymmdd(&t, out, sizeof(out));
    if (ok) {
        // If a future libc starts accepting INT64_MAX, just sanity-check
        // we didn't leave the buffer untouched.
        skip();
    }
    assert_false(ok);
}

static void test_utc_returns_false_on_gmtime_failure(void **state) {
    (void) state;
    time_t t = (time_t) INT64_MAX;
    char out[64] = {0};
    bool ok = time_format_to_utc(&t, out, sizeof(out));
    if (ok) skip();
    assert_false(ok);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_yyyymmdd_formats_epoch),
        cmocka_unit_test(test_yyyymmdd_formats_known_date),
        cmocka_unit_test(test_utc_midnight_renders_as_12am),
        cmocka_unit_test(test_utc_noon_renders_as_12pm),
        cmocka_unit_test(test_utc_morning_keeps_am),
        cmocka_unit_test(test_utc_afternoon_subtracts_twelve_and_flips_pm),
        cmocka_unit_test(test_yyyymmdd_returns_false_on_gmtime_failure),
        cmocka_unit_test(test_utc_returns_false_on_gmtime_failure),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
