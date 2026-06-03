#pragma once

#include <stdint.h>

#define nbgl_contentTagValue_t     char
#define nbgl_contentTagValueList_t char

// nbgl_icon_details_t comes from the SDK's nbgl_types.h, which is
// transitively pulled in by network.h. Don't redefine it here.

// Test-only stand-in for the C_ledger_14px icon used by ICON_LEDGER in
// ui_icons.h (no SCREEN_SIZE_WALLET in the unit-test build). Tests link
// against a single uninitialised instance defined in the test TU.
extern const struct nbgl_icon_details_s C_ledger_14px;

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
