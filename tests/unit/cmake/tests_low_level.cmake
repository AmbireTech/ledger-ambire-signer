# tests_low_level.cmake -- generated test definitions

add_eth_unit_test(test_uint128
  APP_SOURCES
    ${APP_DIR}/uint128.c
    ${APP_DIR}/uint256.c
    ${APP_DIR}/utils/utils.c
    ${PLUGIN_DIR}/common_utils.c
  WRAPS
    cx_math_mult_no_throw
)

add_eth_unit_test(test_uint256
  APP_SOURCES
    ${APP_DIR}/uint256.c
    ${APP_DIR}/uint128.c
    ${APP_DIR}/utils/utils.c
    ${PLUGIN_DIR}/common_utils.c
  WRAPS
    cx_math_mult_no_throw
)

add_eth_unit_test(test_utils
  APP_SOURCES
    ${APP_DIR}/utils/utils.c
    ${APP_DIR}/uint128.c
    ${APP_DIR}/uint256.c
    ${PLUGIN_DIR}/common_utils.c
)

add_eth_unit_test(test_rlp_utils
  APP_SOURCES
    ${APP_DIR}/features/sign_tx/rlp_utils.c
  INCLUDES
    ${APP_DIR}/features/sign_tx
  NO_GLOBALS
)

add_eth_unit_test(test_rlp_encode
  APP_SOURCES
    ${APP_DIR}/features/sign_authorization_eip7702/rlp_encode.c
  INCLUDES
    ${APP_DIR}/features/sign_authorization_eip7702
  NO_GLOBALS
)

add_eth_unit_test(test_tlv_apdu
  APP_SOURCES
    ${APP_DIR}/tlv_apdu.c
    ${APP_DIR}/utils/mem_utils.c
  NO_GLOBALS
)

add_eth_unit_test(test_tlv_utils
  APP_SOURCES
    ${APP_DIR}/utils/tlv_utils.c
    ${APP_DIR}/utils/utils.c
    ${APP_DIR}/uint128.c
    ${APP_DIR}/uint256.c
    ${PLUGIN_DIR}/common_utils.c
)

add_eth_unit_test(test_path_array
  APP_SOURCES
    ${APP_DIR}/features/generic_tx_parser/gtp_path_array.c
  NO_GLOBALS
)

add_eth_unit_test(test_path_slice
  APP_SOURCES
    ${APP_DIR}/features/generic_tx_parser/gtp_path_slice.c
  NO_GLOBALS
)

add_eth_unit_test(test_calldata
  APP_SOURCES
    ${APP_DIR}/features/generic_tx_parser/calldata.c
    ${APP_DIR}/utils/mem_utils.c
  SDK_SOURCES
    ${BOLOS_SDK}/lib_lists/lists.c
  NO_GLOBALS
)

add_eth_unit_test(test_token_info
  APP_SOURCES
    ${APP_DIR}/features/provide_erc20_token_information/token_info.c
    ${APP_DIR}/utils/mem_utils.c
  SDK_SOURCES
    ${BOLOS_SDK}/lib_lists/lists.c
  NO_GLOBALS
)

add_eth_unit_test(test_hash_bytes
  APP_SOURCES
    ${APP_DIR}/utils/hash_bytes.c
  WRAPS
    cx_hash_no_throw
)

add_eth_unit_test(test_time_format
  APP_SOURCES
    ${APP_DIR}/utils/time_format.c
  NO_GLOBALS
)

add_eth_unit_test(test_manage_asset_info
  APP_SOURCES
    ${APP_DIR}/manage_asset_info.c
  INCLUDES
    ${APP_DIR}/features/provide_erc20_token_information
    ${APP_DIR}/features/provide_nft_information
  WRAPS
    get_matching_token_info
    get_matching_nft_info
    clear_token_infos
    clear_nft_infos
)
