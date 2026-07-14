# tests_plugins.cmake -- generated test definitions

add_eth_unit_test(test_erc20_plugin
  APP_SOURCES
    ${APP_DIR}/plugins/erc20/erc20_plugin.c
    ${APP_DIR}/utils/utils.c
    ${APP_DIR}/uint128.c
    ${APP_DIR}/uint256.c
    ${PLUGIN_DIR}/common_utils.c
  INCLUDES
    ${APP_DIR}/plugins
    ${APP_DIR}/plugins/erc20
    ${APP_DIR}/swap
    ${APP_DIR}/features/sign_tx
    ${APP_DIR}/features/provide_erc20_token_information
  WRAPS
    get_tx_chain_id
    get_matching_token_info
    swap_check_destination
    swap_check_amount
  COMPILE_OPTIONS -include os_pic.h
)

add_eth_unit_test(test_erc721_plugin
  APP_SOURCES
    ${APP_DIR}/plugins/erc721/erc721_plugin.c
    ${APP_DIR}/plugins/erc721/erc721_provide_parameters.c
    ${APP_DIR}/plugins/erc721/erc721_ui.c
    ${APP_DIR}/utils/utils.c
    ${APP_DIR}/uint128.c
    ${APP_DIR}/uint256.c
    ${PLUGIN_DIR}/common_utils.c
  INCLUDES
    ${APP_DIR}/plugins
    ${APP_DIR}/plugins/erc721
  WRAPS
    getEthDisplayableAddress
  COMPILE_OPTIONS "SHELL:-include os_pic.h"
)

add_eth_unit_test(test_erc1155_plugin
  APP_SOURCES
    ${APP_DIR}/plugins/erc1155/erc1155_plugin.c
    ${APP_DIR}/plugins/erc1155/erc1155_provide_parameters.c
    ${APP_DIR}/plugins/erc1155/erc1155_ui.c
    ${APP_DIR}/utils/utils.c
    ${APP_DIR}/uint128.c
    ${APP_DIR}/uint256.c
    ${PLUGIN_DIR}/common_utils.c
  INCLUDES
    ${APP_DIR}/plugins
    ${APP_DIR}/plugins/erc1155
  WRAPS
    getEthDisplayableAddress
  COMPILE_OPTIONS "SHELL:-include os_pic.h"
)

add_eth_unit_test(test_eth2_plugin
  APP_SOURCES
    ${APP_DIR}/plugins/eth2/eth2_plugin.c
    ${APP_DIR}/utils/utils.c
    ${APP_DIR}/uint128.c
    ${APP_DIR}/uint256.c
    ${PLUGIN_DIR}/common_utils.c
  INCLUDES
    ${APP_DIR}/plugins
    ${APP_DIR}/plugins/eth2
    ${APP_DIR}/features/get_eth2_public_key
  DEFS
    HAVE_ETH2
  WRAPS
    get_eth2_public_key
    cx_hash_sha256
    amountToString
  COMPILE_OPTIONS "SHELL:-include os_pic.h"
)

add_eth_unit_test(test_eip7002_plugin
  APP_SOURCES
    ${APP_DIR}/plugins/eip7002/eip7002_plugin.c
    ${APP_DIR}/utils/utils.c
    ${APP_DIR}/uint128.c
    ${APP_DIR}/uint256.c
    ${PLUGIN_DIR}/common_utils.c
  INCLUDES
    ${APP_DIR}/plugins
    ${APP_DIR}/plugins/eip7002
  WRAPS
    get_tx_chain_id
    get_displayable_ticker
    amountToString
  COMPILE_OPTIONS "SHELL:-include os_pic.h"
)

add_eth_unit_test(test_eip7251_plugin
  APP_SOURCES
    ${APP_DIR}/plugins/eip7251/eip7251_plugin.c
    ${APP_DIR}/utils/utils.c
    ${APP_DIR}/uint128.c
    ${APP_DIR}/uint256.c
    ${PLUGIN_DIR}/common_utils.c
  INCLUDES
    ${APP_DIR}/plugins
    ${APP_DIR}/plugins/eip7251
  WRAPS
    get_tx_chain_id
    get_displayable_ticker
    amountToString
  COMPILE_OPTIONS "SHELL:-include os_pic.h"
)

add_eth_unit_test(test_swap_with_calldata_plugin
  APP_SOURCES
    ${APP_DIR}/plugins/swap_with_calldata/swap_with_calldata_plugin.c
    ${APP_DIR}/utils/utils.c
    ${APP_DIR}/uint128.c
    ${APP_DIR}/uint256.c
    ${PLUGIN_DIR}/common_utils.c
  INCLUDES
    ${APP_DIR}/plugins
    ${APP_DIR}/plugins/swap_with_calldata
    ${BOLOS_SDK}
  WRAPS
    cx_sha256_init_no_throw
    cx_sha256_update
    cx_sha256_final
  COMPILE_OPTIONS "SHELL:-include os_pic.h"
)

add_eth_unit_test(test_eth_plugin_handler
  APP_SOURCES
    ${APP_DIR}/plugins/eth_plugin_handler.c
  INCLUDES
    ${APP_DIR}/plugins
    ${APP_DIR}/plugins/erc20
    ${APP_DIR}/plugins/eth2
    ${APP_DIR}/plugins/erc721
    ${APP_DIR}/plugins/erc1155
    ${APP_DIR}/plugins/eip7002
    ${APP_DIR}/plugins/eip7251
    ${APP_DIR}/plugins/swap_with_calldata
    ${APP_DIR}/swap
    ${APP_DIR}/features/sign_tx
    ${APP_DIR}/features/set_plugin
  WRAPS
    get_tx_chain_id
    get_displayable_ticker
    get_matching_asset_info
  COMPILE_OPTIONS -include os_pic.h
)
