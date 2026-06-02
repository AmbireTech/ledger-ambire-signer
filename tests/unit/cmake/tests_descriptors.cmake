# tests_descriptors.cmake -- generated test definitions

add_eth_unit_test(test_ledger_pki
  APP_SOURCES
    ${APP_DIR}/ledger_pki.c
  INCLUDES
    ${BOLOS_SDK}/lib_pki
  DEFS
    HAVE_SECP_CURVES
    HAVE_ECC_WEIERSTRASS
)

add_eth_unit_test(test_handle_check_address
  APP_SOURCES
    ${APP_DIR}/swap/handle_check_address.c
  INCLUDES
    ${APP_DIR}/swap
  DEFS
    HAVE_SECP_CURVES
    HAVE_ECC_WEIERSTRASS
  WRAPS
    bip32_path_read
    get_public_key_string
)

add_eth_unit_test(test_handle_swap_sign_transaction
  APP_SOURCES
    ${APP_DIR}/swap/handle_swap_sign_transaction.c
    ${APP_DIR}/mem_utils.c
  INCLUDES
    ${APP_DIR}/swap
    ${APP_DIR}/features/sign_tx
    ${APP_DIR}/features/set_plugin
  WRAPS
    parse_swap_config
    get_asset_info_on_network
    amountToString
    mem_utils_alloc
)

add_eth_unit_test(test_network
  APP_SOURCES
    ${APP_DIR}/network.c
    ${PLUGIN_DIR}/common_utils.c
  INCLUDES
    ${APP_DIR}/features/provide_network_info
    ${APP_DIR}/features/sign_tx
)

add_eth_unit_test(test_network_info
  APP_SOURCES
    ${APP_DIR}/features/provide_network_info/network_info.c
    ${APP_DIR}/tlv_utils.c
    ${APP_DIR}/utils/utils.c
    ${APP_DIR}/uint128.c
    ${APP_DIR}/uint256.c
    ${PLUGIN_DIR}/common_utils.c
  SDK_SOURCES
    ${BOLOS_SDK}/lib_lists/lists.c
  INCLUDES
    ${APP_DIR}/features/provide_network_info
  WRAPS
    check_signature_with_pubkey
    finalize_hash
    hash_nbytes
    find_dynamic_network_by_chain_id
  COMPILE_OPTIONS "SHELL:-include os_pic.h"
)

add_eth_unit_test(test_proxy_info
  APP_SOURCES
    ${APP_DIR}/features/provide_proxy_info/proxy_info.c
    ${APP_DIR}/tlv_utils.c
    ${APP_DIR}/utils/utils.c
    ${APP_DIR}/uint128.c
    ${APP_DIR}/uint256.c
    ${PLUGIN_DIR}/common_utils.c
  INCLUDES
    ${APP_DIR}/features/provide_proxy_info
  WRAPS
    check_signature_with_pubkey
    finalize_hash
    hash_nbytes
  COMPILE_OPTIONS "SHELL:-include os_pic.h"
)

add_eth_unit_test(test_trusted_name
  APP_SOURCES
    ${APP_DIR}/features/provide_trusted_name/trusted_name.c
    ${APP_DIR}/tlv_utils.c
    ${APP_DIR}/utils/utils.c
    ${APP_DIR}/uint128.c
    ${APP_DIR}/uint256.c
    ${PLUGIN_DIR}/common_utils.c
  SDK_SOURCES
    ${BOLOS_SDK}/lib_standard_app/bip32.c
    ${BOLOS_SDK}/lib_lists/lists.c
  INCLUDES
    ${APP_DIR}/features/provide_trusted_name
    ${APP_DIR}/features/provide_proxy_info
  DEFS
    HAVE_SECP_CURVES
    HAVE_ECC_WEIERSTRASS
    MAJOR_VERSION=99
    MINOR_VERSION=99
    PATCH_VERSION=99
  WRAPS
    check_signature_with_pubkey
    finalize_hash
    hash_nbytes
    chain_is_ethereum_compatible
    get_implem_contract
    bip32_derive_with_seed_get_pubkey_256
    cx_keccak_256_hash
  COMPILE_OPTIONS "SHELL:-include os_pic.h" "SHELL:-include os_seed.h"
)

add_eth_unit_test(test_safe_descriptors
  APP_SOURCES
    ${APP_DIR}/features/provide_safe_account/safe_descriptor.c
    ${APP_DIR}/features/provide_safe_account/signer_descriptor.c
    ${APP_DIR}/tlv_utils.c
    ${APP_DIR}/utils/utils.c
    ${APP_DIR}/uint128.c
    ${APP_DIR}/uint256.c
    ${PLUGIN_DIR}/common_utils.c
  INCLUDES
    ${APP_DIR}/features/provide_safe_account
  WRAPS
    check_signature_with_pubkey
    finalize_hash
    hash_nbytes
  COMPILE_OPTIONS "SHELL:-include os_pic.h"
)

add_eth_unit_test(test_cmd_get_tx_simulation
  APP_SOURCES
    ${APP_DIR}/features/provide_tx_simulation/cmd_get_tx_simulation.c
    ${APP_DIR}/tlv_apdu.c
    ${APP_DIR}/tlv_utils.c
    ${APP_DIR}/utils/utils.c
    ${APP_DIR}/uint128.c
    ${APP_DIR}/uint256.c
    ${PLUGIN_DIR}/common_utils.c
  INCLUDES
    ${APP_DIR}/features/provide_tx_simulation
  DEFS
    HAVE_LEDGER_PKI
  WRAPS
    check_signature_with_pubkey
    finalize_hash
    hash_nbytes
    os_pki_get_info
    get_public_key
    get_tx_chain_id
  COMPILE_OPTIONS "SHELL:-include os_pic.h"
)

add_eth_unit_test(test_cmd_get_gating
  APP_SOURCES
    ${APP_DIR}/features/provide_gating/cmd_get_gating.c
    ${APP_DIR}/tlv_apdu.c
    ${APP_DIR}/tlv_utils.c
    ${APP_DIR}/utils/utils.c
    ${APP_DIR}/uint128.c
    ${APP_DIR}/uint256.c
    ${PLUGIN_DIR}/common_utils.c
  INCLUDES
    ${APP_DIR}/features/provide_gating
    ${APP_DIR}/features/sign_message_eip712
    ${APP_DIR}/features/provide_proxy_info
  DEFS
    HAVE_LEDGER_PKI
  WRAPS
    check_signature_with_pubkey
    finalize_hash
    hash_nbytes
    get_tx_chain_id
    compute_schema_hash
    get_implem_contract
    get_proxy_contract
    nvm_write
  COMPILE_OPTIONS "SHELL:-include os_pic.h"
)

add_eth_unit_test(test_cmd_get_challenge
  APP_SOURCES
    ${APP_DIR}/features/get_challenge/cmd_get_challenge.c
  INCLUDES
    ${APP_DIR}/features/get_challenge
    ${BOLOS_SDK}/io_legacy/include
  DEFS
    HAVE_RNG
    OS_IO_SEPH_BUFFER_SIZE=272
  WRAPS
    cx_rng_no_throw
  COMPILE_OPTIONS "SHELL:-include os_pic.h"
)

add_eth_unit_test(test_cmd_provide_nft_info
  APP_SOURCES
    ${APP_DIR}/features/provide_nft_information/cmd_provide_nft_info.c
    ${APP_DIR}/features/provide_nft_information/nft_info.c
    ${APP_DIR}/utils/utils.c
    ${APP_DIR}/uint128.c
    ${APP_DIR}/uint256.c
    ${PLUGIN_DIR}/common_utils.c
  SDK_SOURCES
    ${BOLOS_SDK}/lib_lists/lists.c
  INCLUDES
    ${APP_DIR}/features/provide_nft_information
  DEFS
    HAVE_LEDGER_PKI
  WRAPS
    check_signature_with_pubkey
    app_compatible_with_chain_id
    cx_hash_sha256
  COMPILE_OPTIONS "SHELL:-include os_pic.h"
)

add_eth_unit_test(test_cmd_provide_token_info
  APP_SOURCES
    ${APP_DIR}/features/provide_erc20_token_information/cmd_provide_token_info.c
    ${APP_DIR}/features/provide_erc20_token_information/token_info.c
    ${APP_DIR}/tlv_apdu.c
    ${APP_DIR}/tlv_utils.c
    ${APP_DIR}/utils/utils.c
    ${APP_DIR}/uint128.c
    ${APP_DIR}/uint256.c
    ${PLUGIN_DIR}/common_utils.c
  SDK_SOURCES
    ${BOLOS_SDK}/lib_lists/lists.c
  INCLUDES
    ${APP_DIR}/features/provide_erc20_token_information
    ${BOLOS_SDK}/lib_tlv/use_cases
  DEFS
    HAVE_LEDGER_PKI
  WRAPS
    check_signature_with_pubkey
    app_compatible_with_chain_id
    cx_hash_sha256
    tlv_use_case_dynamic_descriptor
  COMPILE_OPTIONS "SHELL:-include os_pic.h"
)

add_eth_unit_test(test_cmd_set_plugin
  APP_SOURCES
    ${APP_DIR}/features/set_plugin/cmd_set_plugin.c
    ${APP_DIR}/utils/utils.c
    ${APP_DIR}/uint128.c
    ${APP_DIR}/uint256.c
    ${PLUGIN_DIR}/common_utils.c
  INCLUDES
    ${APP_DIR}/features/set_plugin
    ${APP_DIR}/plugins
  WRAPS
    check_signature_with_pubkey
    app_compatible_with_chain_id
  COMPILE_OPTIONS "SHELL:-include os_pic.h"
)

add_eth_unit_test(test_cmd_set_external_plugin
  APP_SOURCES
    ${APP_DIR}/features/set_external_plugin/cmd_set_external_plugin.c
    ${APP_DIR}/utils/utils.c
    ${APP_DIR}/uint128.c
    ${APP_DIR}/uint256.c
    ${PLUGIN_DIR}/common_utils.c
  INCLUDES
    ${APP_DIR}/features/set_external_plugin
    ${APP_DIR}/plugins
  DEFS
    HAVE_LEDGER_PKI
  WRAPS
    check_signature_with_pubkey
    cx_hash_sha256
  COMPILE_OPTIONS "SHELL:-include os_pic.h"
)
