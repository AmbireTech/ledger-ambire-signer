# tests_nbgl.cmake -- NBGL UI helpers (icon selection, pair-list memory).
#
# The src/nbgl/ directory mostly holds widget code that's exercised by the
# Ragger suite, but the helpers in ui_icons.c and ui_utils.c are pure
# decision / memory logic. They're worth pinning at host level so a
# regression in icon routing or allocator bookkeeping doesn't have to
# wait for a Ragger flake to surface.
#
# get_network_icon_from_chain_id and get_clone_network_icon used to live
# in network_icons.c but were folded into ui_icons.c upstream; the
# test_network_icons target still exists as a focused pin of those two
# helpers, linking ui_icons.c directly.

add_eth_unit_test(test_network_icons
  APP_SOURCES
    ${APP_DIR}/nbgl/ui_icons.c
  INCLUDES
    ${APP_DIR}/nbgl
    ${APP_DIR}/features/provide_network_info
    ${APP_DIR}/plugins
    ${BOLOS_SDK}/lib_nbgl/include
    ${BOLOS_SDK}/lib_ux_nbgl
    ${MOCK_DIR}/glyphs
  DEFS
    HAVE_NBGL
    ICONGLYPH=test_glyph
    ICONHOME=test_home_glyph
  WRAPS
    find_dynamic_network_by_chain_id
)

add_eth_unit_test(test_ui_icons
  APP_SOURCES
    ${APP_DIR}/nbgl/ui_icons.c
  INCLUDES
    ${APP_DIR}/nbgl
    ${APP_DIR}/features/provide_network_info
    ${APP_DIR}/plugins
    ${BOLOS_SDK}/lib_nbgl/include
    ${BOLOS_SDK}/lib_ux_nbgl
    ${MOCK_DIR}/glyphs
  DEFS
    HAVE_NBGL
    ICONGLYPH=test_glyph
    ICONHOME=test_home_glyph
  WRAPS
    get_tx_chain_id
)

add_eth_unit_test(test_ui_utils
  APP_SOURCES
    ${APP_DIR}/nbgl/ui_utils.c
  INCLUDES
    ${APP_DIR}/nbgl
    ${BOLOS_SDK}/lib_nbgl/include
    ${BOLOS_SDK}/lib_ux_nbgl
    ${BOLOS_SDK}/lib_alloc
    ${MOCK_DIR}/glyphs
  DEFS
    HAVE_NBGL
  WRAPS
    mem_utils_calloc
    mem_utils_free_and_null
    io_seproxyhal_send_status
)
