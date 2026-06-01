#pragma once

#include <stdint.h>

#define nbgl_contentTagValue_t     char
#define nbgl_contentTagValueList_t char

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
