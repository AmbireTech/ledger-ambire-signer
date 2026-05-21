#pragma once

#include <stdint.h>
#include "nbgl_types.h"
#include "caller_app.h"

const nbgl_icon_details_t *get_network_icon_from_chain_id(const uint64_t *chain_id);
const nbgl_icon_details_t *get_clone_network_icon(const caller_app_t *caller_app);
