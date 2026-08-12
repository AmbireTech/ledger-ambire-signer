#pragma once

#include <stdint.h>
#include <stdbool.h>

// Trimmed-down stand-ins for the SDK's nbgl_contentTagValue_t /
// nbgl_contentTagValueList_t. Only the fields actually touched by app
// code in host tests are present; tests that need richer struct content
// keep their own override.
typedef struct {
    const char *item;
    const char *value;
} nbgl_contentTagValue_t;

typedef struct {
    const nbgl_contentTagValue_t *pairs;
    uint8_t nbPairs;
    bool wrapping;
} nbgl_contentTagValueList_t;

// nbgl_icon_details_t comes from the SDK's nbgl_types.h, which is
// transitively pulled in by network.h. Don't redefine it here.

// Test-only stand-in for the C_Ledger_14px icon used by LARGE_LEDGER_ICON in
// ui_icons.h (no SCREEN_SIZE_WALLET in the unit-test build). Tests link
// against a single uninitialised instance defined in the test TU.
extern const struct nbgl_icon_details_s C_Ledger_14px;

typedef enum {
    NO_TYPE_WARNING = 0,
    CENTERED_INFO_WARNING,
    QRCODE_WARNING,
    BAR_LIST_WARNING
} nbgl_genericDetailsType_t;

struct nbgl_icon_details_s;

typedef struct {
    const char *title;
    nbgl_genericDetailsType_t type;
} nbgl_genericDetails_t;

typedef struct {
    const struct nbgl_icon_details_s *icon;
    const char *title;
    const char *description;
    const char *buttonText;
    const char *footerText;
    const nbgl_genericDetails_t *details;
} nbgl_preludeDetails_t;

typedef enum {
    W3C_ISSUE_WARN = 0,
    W3C_RISK_DETECTED_WARN,
    W3C_THREAT_DETECTED_WARN,
    W3C_NO_THREAT_WARN,
    BLIND_SIGNING_WARN,
    GATED_SIGNING_WARN,
    NB_WARNING_TYPES
} nbgl_warningType_t;

typedef struct {
    uint32_t predefinedSet;
    const char *dAppProvider;
    const char *reportUrl;
    const char *reportProvider;
    const char *providerMessage;
    const void *introDetails;
    const void *reviewDetails;
    const void *info;
    const void *introTopRightIcon;
    const void *reviewTopRightIcon;
    const void *prelude;
} nbgl_warning_t;

// Storage lives in mocks/app_globals.c (weak); tests that drive the
// warning UI screens poke its fields directly.
extern nbgl_warning_t warning;
