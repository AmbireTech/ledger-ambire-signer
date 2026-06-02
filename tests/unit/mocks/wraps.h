#pragma once

#include <setjmp.h>
#include <stdbool.h>
#include <stdint.h>

// Shared state for the common __wrap_* stubs in mocks/mock.c. Tests
// flip these in setup or in dedicated failure cases. A test that
// needs richer behavior (counters, captured args, sequencing via
// cmocka mock()) can still provide a strong local __wrap_* override
// that shadows the weak version in mock.c.
extern bool g_sig_check_ret;              // __wrap_check_signature_with_pubkey
extern int g_sig_check_calls;             // incremented on every sig-check call
extern bool g_finalize_hash_ret;          // __wrap_finalize_hash
extern uint64_t g_tx_chain_id;            // __wrap_get_tx_chain_id
extern const char *g_displayable_ticker;  // __wrap_get_displayable_ticker
extern const void *g_tx_info_ret;         // __wrap_get_current_tx_info (cast on assign)
extern bool g_parsebip32_force_null;      // __wrap_parseBip32 -> NULL when true
extern uint32_t g_keccak_init_ret;        // __wrap_cx_keccak_init_no_throw

// Common-helper stubs in mocks/mock.c. The WEAK defaults return success
// with a deterministic string written into `out`; tests that need to
// drive a failure path flip the matching `*_ret` global. Tests that
// need to inspect a *specific* output content still install a strong
// local override.
extern uint16_t g_get_public_key_ret;        // SWO_SUCCESS by default
extern bool g_getEthDisplayableAddress_ret;  // true
extern bool g_amountToString_ret;            // true
extern bool g_get_network_as_string_ret;     // true

// app_exit / app_quit / send_swap_error_simple are noreturn. Their
// WEAK defaults in mock.c either while(1) (process hangs) or longjmp
// to g_noreturn_jmp if g_noreturn_armed is true. Tests that exercise
// a code path that *should* call one of them arm the jump, run the
// stmt inside a setjmp, and check g_noreturn_calls. EXPECT_NORETURN()
// below packages the boilerplate.
extern jmp_buf g_noreturn_jmp;
extern bool g_noreturn_armed;
extern int g_noreturn_calls;

#define EXPECT_NORETURN(stmt)                            \
    do {                                                 \
        g_noreturn_armed = true;                         \
        g_noreturn_calls = 0;                            \
        if (setjmp(g_noreturn_jmp) == 0) {               \
            (stmt);                                      \
            g_noreturn_armed = false;                    \
            fail_msg("expected noreturn was not taken"); \
        }                                                \
        g_noreturn_armed = false;                        \
    } while (0)

// __wrap_tlv_from_apdu in mocks/mock.c: captures the (first_chunk, lc,
// handler) trio, optionally invokes the handler with an empty buffer
// (gated by g_tlv_from_apdu_invoke_handler), and returns
// g_tlv_from_apdu_ret. Tests reset the captures in their fixture and
// assign g_tlv_from_apdu_ret before driving the APDU. The handler is
// stored as void * to keep wraps.h free of tlv_apdu.h; tests that need
// to identify which handler the dispatcher passed cast it back.
extern int g_tlv_from_apdu_calls;
extern bool g_tlv_from_apdu_first_chunk;
extern uint8_t g_tlv_from_apdu_lc;
extern void *g_tlv_from_apdu_handler;
extern bool g_tlv_from_apdu_invoke_handler;
extern int g_tlv_from_apdu_ret;  // e_tlv_apdu_ret value, plain int to avoid header

// The chain config defined in mocks/app_globals.c. A couple of tests
// (test_cmd_get_public_key, test_eth_swap_utils) mutate chain_id to
// drive multi-chain assertions; expose it through wraps.h so they
// don't have to add their own extern decl.
struct chain_config_s;
extern struct chain_config_s g_chainConfig;

// NVRAM-storage backing store for the production N_storage_real alias.
// test_commands_7702 toggles eip7702_enable to gate the auth flow.
struct internalStorage_t;
extern struct internalStorage_t g_n_storage_writable;

// NBGL warning state. The real def lives in src/nbgl/ui_home.c which is
// not linked in host tests; mocks/app_globals.c provides a zero-init
// fallback. Tests need the full type to poke its fields, so the extern
// decl is in ui_nbgl.h (production) -- include that directly from the
// test files that read warning.predefinedSet / warning.prelude.

// Backing storage for txContext.content. Three tests (test_network,
// test_param_enum, test_provide_map_entry) point txContext.content at
// this and write fields directly. Include shared_context.h (which
// pulls eth_plugin_interface.h -> tx_content.h) before referencing.
struct txContent_t;
extern struct txContent_t g_tx_content;
