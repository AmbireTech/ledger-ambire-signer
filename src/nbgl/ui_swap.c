#include "nbgl_use_case.h"

void ui_swap_show_signing(void) {
#ifdef SCREEN_SIZE_WALLET
#ifndef FUZZ
    nbgl_useCaseSpinner("Signing");
#endif
#endif  // SCREEN_SIZE_WALLET
}
