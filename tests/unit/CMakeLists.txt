cmake_minimum_required(VERSION 3.10)

if(${CMAKE_VERSION} VERSION_LESS 3.10)
    cmake_policy(VERSION ${CMAKE_MAJOR_VERSION}.${CMAKE_MINOR_VERSION})
endif()

# project information
project(unit_tests
        VERSION 0.1
	      DESCRIPTION "Unit tests for Ledger Ethereum application"
        LANGUAGES C)

# Check for BOLOS_SDK (optional for unit tests, provides SDK headers if available)
if(NOT DEFINED BOLOS_SDK)
  set(BOLOS_SDK "/opt/ledger-secure-sdk")
  message(STATUS "BOLOS_SDK not defined, using default: ${BOLOS_SDK}")
else()
  message(STATUS "Using BOLOS_SDK: ${BOLOS_SDK}")
endif()

# guard against bad build-type strings
if (NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE "Debug")
endif()

# guard against in-source builds
if(${CMAKE_SOURCE_DIR} STREQUAL ${CMAKE_BINARY_DIR})
  message(FATAL_ERROR "In-source builds not allowed. Please make a new directory (called a build directory) and run CMake from there. You may need to remove CMakeCache.txt. ")
endif()

include(CTest)
ENABLE_TESTING()

# specify C standard
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED True)

# Find libbsd for BSD string functions (strlcpy, strlcat)
find_package(PkgConfig)
if(PkgConfig_FOUND)
  pkg_check_modules(LIBBSD libbsd)
endif()

# Fallback if pkg-config or libbsd not found via pkg-config
if(NOT LIBBSD_FOUND)
  # Try to find libbsd manually
  find_path(LIBBSD_INCLUDE_DIR bsd/string.h)
  find_library(LIBBSD_LIBRARY NAMES bsd)

  if(LIBBSD_INCLUDE_DIR AND LIBBSD_LIBRARY)
    set(LIBBSD_FOUND TRUE)
    set(LIBBSD_INCLUDE_DIRS ${LIBBSD_INCLUDE_DIR})
    set(LIBBSD_LIBRARIES ${LIBBSD_LIBRARY})
    message(STATUS "Found libbsd manually: ${LIBBSD_LIBRARY}")
  else()
    message(WARNING "libbsd not found - BSD string functions may not be available")
    set(LIBBSD_INCLUDE_DIRS "")
    set(LIBBSD_LIBRARIES "")
  endif()
endif()

add_compile_options(-Wall -Wextra -g -pedantic --coverage)
# Flag depending on the Build Type
set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -O0")
set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE}-O3")

set(GCC_COVERAGE_LINK_FLAGS "--coverage -lgcov")
set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} ${GCC_COVERAGE_LINK_FLAGS}")
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} ${GCC_COVERAGE_LINK_FLAGS}")

set(APP_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../../src")
set(SRC_DIR "${CMAKE_CURRENT_SOURCE_DIR}/src")
set(MOCK_DIR "${CMAKE_CURRENT_SOURCE_DIR}/mocks")
set(PLUGIN_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../../ethereum-plugin-sdk/src")

add_compile_definitions(TEST)

include_directories(
  ${APP_DIR}
  ${PLUGIN_DIR}
  ${APP_DIR}/features/generic_tx_parser
  ${APP_DIR}/features/provide_erc20_token_information
  ${APP_DIR}/features/provide_nft_information
  ${APP_DIR}/features/provide_trusted_name
  ${APP_DIR}/features/provide_map_entry
  ${APP_DIR}/features/provide_proxy_info
  ${APP_DIR}/features/get_public_key
  ${APP_DIR}/features/sign_tx
  ${APP_DIR}/features/get_challenge
  ${APP_DIR}/nbgl
  ${MOCK_DIR}
  ${BOLOS_SDK}/io/include
  ${BOLOS_SDK}/lib_cxng/include
  ${BOLOS_SDK}/lib_nbgl/include
  ${BOLOS_SDK}/lib_lists
  ${BOLOS_SDK}/lib_standard_app
  ${BOLOS_SDK}/lib_tlv
  ${BOLOS_SDK}/lib_alloc
  ${BOLOS_SDK}/include
  ${LIBBSD_INCLUDE_DIRS}
)

# Network parameter test
add_executable(test_param_network
  ${SRC_DIR}/test_param_network.c
  ${APP_DIR}/features/generic_tx_parser/gtp_value.c
  ${APP_DIR}/features/generic_tx_parser/gtp_param_network.c
  ${APP_DIR}/tlv_apdu.c
  ${APP_DIR}/tlv_utils.c
  ${APP_DIR}/mem_utils.c
  ${APP_DIR}/utils.c
  ${APP_DIR}/uint128.c
  ${APP_DIR}/uint256.c
  ${PLUGIN_DIR}/common_utils.c
  ${MOCK_DIR}/mock.c
  ${BOLOS_SDK}/lib_standard_app/format.c
  ${BOLOS_SDK}/lib_standard_app/read.c
  ${BOLOS_SDK}/lib_standard_app/write.c
  ${BOLOS_SDK}/lib_tlv/tlv_library.c
)

# Disable pedantic warnings for SDK's tlv_library.c (function pointer to void* conversions)
set_source_files_properties(${BOLOS_SDK}/lib_tlv/tlv_library.c PROPERTIES COMPILE_FLAGS "-Wno-pedantic")

target_compile_definitions(test_param_network PRIVATE
  HAVE_ECDSA
  HAVE_HASH
  HAVE_SHA256
  HAVE_SHA3
  HAVE_ECC
  HAVE_SPRINTF
  HAVE_MATH
)

target_link_libraries(test_param_network PUBLIC
                      cmocka
                      gcov
                      ${LIBBSD_LIBRARIES}
                      -Wl,--wrap=get_network_as_string_from_chain_id
                      -Wl,--wrap=add_to_field_table
)

add_test(test_param_network test_param_network)

# Trusted name parameter test
add_executable(test_param_trusted_name
  ${SRC_DIR}/test_param_trusted_name.c
  ${APP_DIR}/features/generic_tx_parser/gtp_value.c
  ${APP_DIR}/features/generic_tx_parser/gtp_param_trusted_name.c
  ${APP_DIR}/tlv_apdu.c
  ${APP_DIR}/tlv_utils.c
  ${APP_DIR}/mem_utils.c
  ${APP_DIR}/utils.c
  ${APP_DIR}/uint128.c
  ${APP_DIR}/uint256.c
  ${PLUGIN_DIR}/common_utils.c
  ${MOCK_DIR}/mock.c
  ${BOLOS_SDK}/lib_standard_app/format.c
  ${BOLOS_SDK}/lib_standard_app/read.c
  ${BOLOS_SDK}/lib_standard_app/write.c
  ${BOLOS_SDK}/lib_tlv/tlv_library.c
)

# Disable pedantic warnings for SDK's tlv_library.c
set_source_files_properties(${BOLOS_SDK}/lib_tlv/tlv_library.c PROPERTIES COMPILE_FLAGS "-Wno-pedantic")

# Add arraylen.h to the include path before other includes
target_include_directories(test_param_trusted_name BEFORE PRIVATE ${MOCK_DIR})

target_compile_definitions(test_param_trusted_name PRIVATE
  HAVE_ECDSA
  HAVE_HASH
  HAVE_SHA256
  HAVE_SHA3
  HAVE_ECC
  HAVE_MATH
)

target_link_libraries(test_param_trusted_name PUBLIC
                      cmocka
                      gcov
                      ${LIBBSD_LIBRARIES}
                      -Wl,--wrap=get_trusted_name
                      -Wl,--wrap=get_public_key
                      -Wl,--wrap=get_current_tx_chain_id
                      -Wl,--wrap=add_to_field_table
                      -Wl,--wrap=get_network_as_string_from_chain_id
)

add_test(test_param_trusted_name test_param_trusted_name)

# Raw parameter test
add_executable(test_param_raw
  ${SRC_DIR}/test_param_raw.c
  ${APP_DIR}/features/generic_tx_parser/gtp_value.c
  ${APP_DIR}/features/generic_tx_parser/gtp_param_raw.c
  ${APP_DIR}/tlv_apdu.c
  ${APP_DIR}/tlv_utils.c
  ${APP_DIR}/mem_utils.c
  ${APP_DIR}/uint256.c
  ${APP_DIR}/uint128.c
  ${APP_DIR}/utils.c
  ${PLUGIN_DIR}/common_utils.c
  ${MOCK_DIR}/mock.c
  ${BOLOS_SDK}/lib_standard_app/format.c
  ${BOLOS_SDK}/lib_standard_app/read.c
  ${BOLOS_SDK}/lib_standard_app/write.c
  ${BOLOS_SDK}/src/os_printf.c
  ${BOLOS_SDK}/lib_tlv/tlv_library.c
)

target_compile_definitions(test_param_raw PRIVATE
  HAVE_ECDSA
  HAVE_HASH
  HAVE_SHA256
  HAVE_SHA3
  HAVE_ECC
  HAVE_SPRINTF
  HAVE_SNPRINTF
  HAVE_SNPRINTF_FORMAT_U
  HAVE_MATH
)

target_link_libraries(test_param_raw PUBLIC
                      cmocka
                      gcov
                      ${LIBBSD_LIBRARIES}
                      -Wl,--wrap=add_to_field_table
                      -Wl,--wrap=get_matching_map_entry
)

add_test(test_param_raw test_param_raw)

# Field validation test
add_executable(test_field_validation
  ${SRC_DIR}/test_field_validation.c
  ${APP_DIR}/features/generic_tx_parser/gtp_field.c
  ${APP_DIR}/tlv_apdu.c
  ${APP_DIR}/tlv_utils.c
  ${APP_DIR}/mem_utils.c
  ${BOLOS_SDK}/lib_lists/lists.c
  ${APP_DIR}/utils.c
  ${APP_DIR}/uint256.c
  ${APP_DIR}/uint128.c
  ${PLUGIN_DIR}/common_utils.c
  ${MOCK_DIR}/mock.c
  ${MOCK_DIR}/field_validation_mocks.c
  ${BOLOS_SDK}/lib_standard_app/format.c
  ${BOLOS_SDK}/lib_standard_app/read.c
  ${BOLOS_SDK}/lib_standard_app/write.c
  ${BOLOS_SDK}/lib_tlv/tlv_library.c
)

# Disable pedantic warnings for SDK's tlv_library.c
set_source_files_properties(${BOLOS_SDK}/lib_tlv/tlv_library.c PROPERTIES COMPILE_FLAGS "-Wno-pedantic")
target_compile_definitions(test_field_validation PRIVATE
  HAVE_ECDSA
  HAVE_HASH
  HAVE_SHA256
  HAVE_SHA3
  HAVE_ECC
  HAVE_MATH
)

target_compile_options(test_field_validation PRIVATE
  -fshort-enums
)

target_link_libraries(test_field_validation PUBLIC
                      cmocka
                      gcov
                      ${LIBBSD_LIBRARIES}
)

add_test(test_field_validation test_field_validation)

# MAP_ENTRY test
add_executable(test_provide_map_entry
  ${SRC_DIR}/test_provide_map_entry.c
  ${APP_DIR}/features/provide_map_entry/map_entry.c
  ${APP_DIR}/tlv_apdu.c
  ${APP_DIR}/tlv_utils.c
  ${APP_DIR}/mem_utils.c
  ${APP_DIR}/utils.c
  ${APP_DIR}/uint256.c
  ${APP_DIR}/uint128.c
  ${PLUGIN_DIR}/common_utils.c
  ${MOCK_DIR}/mock.c
  ${BOLOS_SDK}/lib_lists/lists.c
  ${BOLOS_SDK}/lib_standard_app/format.c
  ${BOLOS_SDK}/lib_standard_app/read.c
  ${BOLOS_SDK}/lib_standard_app/write.c
  ${BOLOS_SDK}/src/os_printf.c
  ${BOLOS_SDK}/lib_tlv/tlv_library.c
)

target_compile_definitions(test_provide_map_entry PRIVATE
  HAVE_ECDSA
  HAVE_HASH
  HAVE_SHA256
  HAVE_SHA3
  HAVE_ECC
  HAVE_MATH
)

target_link_libraries(test_provide_map_entry PUBLIC
                      cmocka
                      gcov
                      ${LIBBSD_LIBRARIES}
                      -Wl,--wrap=hash_nbytes
                      -Wl,--wrap=finalize_hash
                      -Wl,--wrap=check_signature_with_pubkey
                      -Wl,--wrap=get_current_tx_info
                      -Wl,--wrap=get_current_calldata
                      -Wl,--wrap=calldata_get_selector
                      -Wl,--wrap=get_implem_contract
)

add_test(test_provide_map_entry test_provide_map_entry)

# GROUP parameter test
add_executable(test_param_group
  ${SRC_DIR}/test_param_group.c
  ${APP_DIR}/features/generic_tx_parser/gtp_param_group.c
  ${APP_DIR}/tlv_apdu.c
  ${APP_DIR}/tlv_utils.c
  ${APP_DIR}/mem_utils.c
  ${APP_DIR}/utils.c
  ${APP_DIR}/uint256.c
  ${APP_DIR}/uint128.c
  ${PLUGIN_DIR}/common_utils.c
  ${MOCK_DIR}/mock.c
  ${BOLOS_SDK}/lib_lists/lists.c
  ${BOLOS_SDK}/lib_standard_app/format.c
  ${BOLOS_SDK}/lib_standard_app/read.c
  ${BOLOS_SDK}/lib_standard_app/write.c
  ${BOLOS_SDK}/lib_tlv/tlv_library.c
)

set_source_files_properties(${BOLOS_SDK}/lib_tlv/tlv_library.c PROPERTIES COMPILE_FLAGS "-Wno-pedantic")

target_compile_definitions(test_param_group PRIVATE
  HAVE_ECDSA
  HAVE_HASH
  HAVE_SHA256
  HAVE_SHA3
  HAVE_ECC
  HAVE_MATH
)

target_link_libraries(test_param_group PUBLIC
                      cmocka
                      gcov
                      ${LIBBSD_LIBRARIES}
                      -Wl,--wrap=format_field
                      -Wl,--wrap=handle_field_struct
                      -Wl,--wrap=verify_field_struct
                      -Wl,--wrap=cleanup_field
                      -Wl,--wrap=cleanup_field_constraints
)

add_test(test_param_group test_param_group)

# TOKEN_AMOUNT parameter broadcast test
add_executable(test_param_token_amount
  ${SRC_DIR}/test_param_token_amount.c
  ${APP_DIR}/features/generic_tx_parser/gtp_param_token_amount.c
  ${APP_DIR}/features/provide_erc20_token_information/token_info.c
  ${APP_DIR}/tlv_apdu.c
  ${APP_DIR}/tlv_utils.c
  ${APP_DIR}/mem_utils.c
  ${APP_DIR}/uint256.c
  ${APP_DIR}/uint128.c
  ${APP_DIR}/utils.c
  ${PLUGIN_DIR}/common_utils.c
  ${MOCK_DIR}/mock.c
  ${BOLOS_SDK}/lib_standard_app/format.c
  ${BOLOS_SDK}/lib_standard_app/read.c
  ${BOLOS_SDK}/lib_standard_app/write.c
  ${BOLOS_SDK}/src/os_printf.c
  ${BOLOS_SDK}/lib_tlv/tlv_library.c
  ${BOLOS_SDK}/lib_lists/lists.c
)

set_source_files_properties(${BOLOS_SDK}/lib_tlv/tlv_library.c PROPERTIES COMPILE_FLAGS "-Wno-pedantic")

target_compile_definitions(test_param_token_amount PRIVATE
  HAVE_ECDSA
  HAVE_HASH
  HAVE_SHA256
  HAVE_SHA3
  HAVE_ECC
  HAVE_SPRINTF
  HAVE_SNPRINTF
  HAVE_SNPRINTF_FORMAT_U
  HAVE_MATH
)

set_source_files_properties(${BOLOS_SDK}/src/os_printf.c PROPERTIES COMPILE_FLAGS "-Wno-implicit-function-declaration")

target_link_libraries(test_param_token_amount PUBLIC
                      cmocka
                      gcov
                      ${LIBBSD_LIBRARIES}
                      -Wl,--wrap=value_get
                      -Wl,--wrap=value_cleanup
                      -Wl,--wrap=handle_value_struct
                      -Wl,--wrap=get_current_tx_info
                      -Wl,--wrap=get_matching_token_info_or_dummy
                      -Wl,--wrap=add_to_field_table
                      -Wl,--wrap=get_displayable_ticker
)

add_test(test_param_token_amount test_param_token_amount)

# CALLDATA parameter broadcast test
add_executable(test_param_calldata
  ${SRC_DIR}/test_param_calldata.c
  ${APP_DIR}/features/generic_tx_parser/gtp_param_calldata.c
  ${APP_DIR}/tlv_apdu.c
  ${APP_DIR}/tlv_utils.c
  ${APP_DIR}/mem_utils.c
  ${APP_DIR}/utils.c
  ${APP_DIR}/uint256.c
  ${APP_DIR}/uint128.c
  ${PLUGIN_DIR}/common_utils.c
  ${MOCK_DIR}/mock.c
  ${BOLOS_SDK}/lib_standard_app/format.c
  ${BOLOS_SDK}/lib_standard_app/read.c
  ${BOLOS_SDK}/lib_standard_app/write.c
  ${BOLOS_SDK}/lib_tlv/tlv_library.c
)

set_source_files_properties(${BOLOS_SDK}/lib_tlv/tlv_library.c PROPERTIES COMPILE_FLAGS "-Wno-pedantic")

target_compile_definitions(test_param_calldata PRIVATE
  HAVE_ECDSA
  HAVE_HASH
  HAVE_SHA256
  HAVE_SHA3
  HAVE_ECC
  HAVE_SPRINTF
  HAVE_SNPRINTF
  HAVE_MATH
)

target_link_libraries(test_param_calldata PUBLIC
                      cmocka
                      gcov
                      ${LIBBSD_LIBRARIES}
                      -Wl,--wrap=value_get
                      -Wl,--wrap=value_cleanup
                      -Wl,--wrap=handle_value_struct
                      -Wl,--wrap=tx_ctx_init
                      -Wl,--wrap=calldata_init
                      -Wl,--wrap=calldata_append
                      -Wl,--wrap=calldata_delete
)

add_test(test_param_calldata test_param_calldata)

# RLP utils test (sign_tx)
add_executable(test_rlp_utils
  ${SRC_DIR}/test_rlp_utils.c
  ${APP_DIR}/features/sign_tx/rlp_utils.c
)

target_include_directories(test_rlp_utils PRIVATE
  ${APP_DIR}/features/sign_tx
)

target_link_libraries(test_rlp_utils PUBLIC
                      cmocka
                      gcov
                      ${LIBBSD_LIBRARIES}
)

add_test(test_rlp_utils test_rlp_utils)

# uint128 arithmetic test
add_executable(test_uint128
  ${SRC_DIR}/test_uint128.c
  ${APP_DIR}/uint128.c
  ${APP_DIR}/uint256.c
  ${APP_DIR}/utils.c
  ${PLUGIN_DIR}/common_utils.c
  ${MOCK_DIR}/mock.c
  ${BOLOS_SDK}/lib_standard_app/format.c
  ${BOLOS_SDK}/lib_standard_app/read.c
  ${BOLOS_SDK}/lib_standard_app/write.c
)

target_compile_definitions(test_uint128 PRIVATE
  HAVE_ECDSA
  HAVE_HASH
  HAVE_SHA256
  HAVE_SHA3
  HAVE_ECC
  HAVE_MATH
)

target_link_libraries(test_uint128 PUBLIC
                      cmocka
                      gcov
                      ${LIBBSD_LIBRARIES}
)

add_test(test_uint128 test_uint128)

# uint256 arithmetic test
add_executable(test_uint256
  ${SRC_DIR}/test_uint256.c
  ${APP_DIR}/uint256.c
  ${APP_DIR}/uint128.c
  ${APP_DIR}/utils.c
  ${PLUGIN_DIR}/common_utils.c
  ${MOCK_DIR}/mock.c
  ${BOLOS_SDK}/lib_standard_app/format.c
  ${BOLOS_SDK}/lib_standard_app/read.c
  ${BOLOS_SDK}/lib_standard_app/write.c
)

target_compile_definitions(test_uint256 PRIVATE
  HAVE_ECDSA
  HAVE_HASH
  HAVE_SHA256
  HAVE_SHA3
  HAVE_ECC
  HAVE_MATH
)

target_link_libraries(test_uint256 PUBLIC
                      cmocka
                      gcov
                      ${LIBBSD_LIBRARIES}
                      -Wl,--wrap=cx_math_mult_no_throw
)

add_test(test_uint256 test_uint256)

# utils helpers test
add_executable(test_utils
  ${SRC_DIR}/test_utils.c
  ${APP_DIR}/utils.c
  ${APP_DIR}/uint128.c
  ${APP_DIR}/uint256.c
  ${PLUGIN_DIR}/common_utils.c
  ${MOCK_DIR}/mock.c
  ${BOLOS_SDK}/lib_standard_app/format.c
  ${BOLOS_SDK}/lib_standard_app/read.c
  ${BOLOS_SDK}/lib_standard_app/write.c
)

target_compile_definitions(test_utils PRIVATE
  HAVE_ECDSA
  HAVE_HASH
  HAVE_SHA256
  HAVE_SHA3
  HAVE_ECC
  HAVE_MATH
)

target_link_libraries(test_utils PUBLIC
                      cmocka
                      gcov
                      ${LIBBSD_LIBRARIES}
)

add_test(test_utils test_utils)

# network resolution test
add_executable(test_network
  ${SRC_DIR}/test_network.c
  ${APP_DIR}/network.c
  ${PLUGIN_DIR}/common_utils.c
  ${MOCK_DIR}/mock.c
  ${BOLOS_SDK}/lib_standard_app/format.c
  ${BOLOS_SDK}/lib_standard_app/read.c
  ${BOLOS_SDK}/lib_standard_app/write.c
)

target_include_directories(test_network PRIVATE
  ${APP_DIR}/features/provide_network_info
  ${APP_DIR}/features/sign_tx
)

target_compile_definitions(test_network PRIVATE
  HAVE_ECDSA
  HAVE_HASH
  HAVE_SHA256
  HAVE_SHA3
  HAVE_ECC
  HAVE_MATH
)

target_link_libraries(test_network PUBLIC
                      cmocka
                      gcov
                      ${LIBBSD_LIBRARIES}
)

add_test(test_network test_network)

# eth_ustream low-level helpers (init_tx, copy_tx_data)
add_executable(test_eth_ustream_helpers
  ${SRC_DIR}/test_eth_ustream_helpers.c
  ${APP_DIR}/features/sign_tx/eth_ustream.c
  ${APP_DIR}/features/sign_tx/rlp_utils.c
  ${APP_DIR}/utils.c
  ${APP_DIR}/uint128.c
  ${APP_DIR}/uint256.c
  ${PLUGIN_DIR}/common_utils.c
  ${MOCK_DIR}/mock.c
  ${BOLOS_SDK}/lib_standard_app/format.c
  ${BOLOS_SDK}/lib_standard_app/read.c
  ${BOLOS_SDK}/lib_standard_app/write.c
)

target_include_directories(test_eth_ustream_helpers PRIVATE
  ${APP_DIR}/features/sign_tx
  ${APP_DIR}/features/generic_tx_parser
  ${APP_DIR}/features/provide_network_info
)

target_compile_definitions(test_eth_ustream_helpers PRIVATE
  HAVE_ECDSA
  HAVE_HASH
  HAVE_SHA256
  HAVE_SHA3
  HAVE_ECC
  HAVE_MATH
)

target_link_libraries(test_eth_ustream_helpers PUBLIC
                      cmocka
                      gcov
                      ${LIBBSD_LIBRARIES}
)

add_test(test_eth_ustream_helpers test_eth_ustream_helpers)

# AMOUNT parameter test
add_executable(test_param_amount
  ${SRC_DIR}/test_param_amount.c
  ${APP_DIR}/features/generic_tx_parser/gtp_param_amount.c
  ${APP_DIR}/features/generic_tx_parser/gtp_value.c
  ${APP_DIR}/tlv_apdu.c
  ${APP_DIR}/tlv_utils.c
  ${APP_DIR}/mem_utils.c
  ${APP_DIR}/utils.c
  ${APP_DIR}/uint128.c
  ${APP_DIR}/uint256.c
  ${PLUGIN_DIR}/common_utils.c
  ${MOCK_DIR}/mock.c
  ${BOLOS_SDK}/lib_standard_app/format.c
  ${BOLOS_SDK}/lib_standard_app/read.c
  ${BOLOS_SDK}/lib_standard_app/write.c
  ${BOLOS_SDK}/lib_tlv/tlv_library.c
)

set_source_files_properties(${BOLOS_SDK}/lib_tlv/tlv_library.c
                            PROPERTIES COMPILE_FLAGS "-Wno-pedantic")

target_compile_definitions(test_param_amount PRIVATE
  HAVE_ECDSA
  HAVE_HASH
  HAVE_SHA256
  HAVE_SHA3
  HAVE_ECC
  HAVE_MATH
)

target_link_libraries(test_param_amount PUBLIC
                      cmocka
                      gcov
                      ${LIBBSD_LIBRARIES}
                      -Wl,--wrap=value_get
                      -Wl,--wrap=value_cleanup
                      -Wl,--wrap=handle_value_struct
                      -Wl,--wrap=get_current_tx_info
                      -Wl,--wrap=get_displayable_ticker
                      -Wl,--wrap=add_to_field_table
)

add_test(test_param_amount test_param_amount)

# DATETIME parameter test
add_executable(test_param_datetime
  ${SRC_DIR}/test_param_datetime.c
  ${APP_DIR}/features/generic_tx_parser/gtp_param_datetime.c
  ${APP_DIR}/features/generic_tx_parser/gtp_value.c
  ${APP_DIR}/time_format.c
  ${APP_DIR}/tlv_apdu.c
  ${APP_DIR}/tlv_utils.c
  ${APP_DIR}/mem_utils.c
  ${APP_DIR}/utils.c
  ${APP_DIR}/uint128.c
  ${APP_DIR}/uint256.c
  ${PLUGIN_DIR}/common_utils.c
  ${MOCK_DIR}/mock.c
  ${BOLOS_SDK}/lib_standard_app/format.c
  ${BOLOS_SDK}/lib_standard_app/read.c
  ${BOLOS_SDK}/lib_standard_app/write.c
  ${BOLOS_SDK}/lib_tlv/tlv_library.c
)

set_source_files_properties(${BOLOS_SDK}/lib_tlv/tlv_library.c
                            PROPERTIES COMPILE_FLAGS "-Wno-pedantic")

target_compile_definitions(test_param_datetime PRIVATE
  HAVE_ECDSA
  HAVE_HASH
  HAVE_SHA256
  HAVE_SHA3
  HAVE_ECC
  HAVE_MATH
)

target_link_libraries(test_param_datetime PUBLIC
                      cmocka
                      gcov
                      ${LIBBSD_LIBRARIES}
                      -Wl,--wrap=value_get
                      -Wl,--wrap=value_cleanup
                      -Wl,--wrap=handle_value_struct
                      -Wl,--wrap=add_to_field_table
)

add_test(test_param_datetime test_param_datetime)

# DURATION parameter test
add_executable(test_param_duration
  ${SRC_DIR}/test_param_duration.c
  ${APP_DIR}/features/generic_tx_parser/gtp_param_duration.c
  ${APP_DIR}/features/generic_tx_parser/gtp_value.c
  ${APP_DIR}/tlv_apdu.c
  ${APP_DIR}/tlv_utils.c
  ${APP_DIR}/mem_utils.c
  ${APP_DIR}/utils.c
  ${APP_DIR}/uint128.c
  ${APP_DIR}/uint256.c
  ${PLUGIN_DIR}/common_utils.c
  ${MOCK_DIR}/mock.c
  ${BOLOS_SDK}/lib_standard_app/format.c
  ${BOLOS_SDK}/lib_standard_app/read.c
  ${BOLOS_SDK}/lib_standard_app/write.c
  ${BOLOS_SDK}/lib_tlv/tlv_library.c
)

set_source_files_properties(${BOLOS_SDK}/lib_tlv/tlv_library.c
                            PROPERTIES COMPILE_FLAGS "-Wno-pedantic")

target_compile_definitions(test_param_duration PRIVATE
  HAVE_ECDSA
  HAVE_HASH
  HAVE_SHA256
  HAVE_SHA3
  HAVE_ECC
  HAVE_MATH
)

target_link_libraries(test_param_duration PUBLIC
                      cmocka
                      gcov
                      ${LIBBSD_LIBRARIES}
                      -Wl,--wrap=value_get
                      -Wl,--wrap=value_cleanup
                      -Wl,--wrap=handle_value_struct
                      -Wl,--wrap=add_to_field_table
)

add_test(test_param_duration test_param_duration)

# UNIT parameter test
add_executable(test_param_unit
  ${SRC_DIR}/test_param_unit.c
  ${APP_DIR}/features/generic_tx_parser/gtp_param_unit.c
  ${APP_DIR}/features/generic_tx_parser/gtp_value.c
  ${APP_DIR}/tlv_apdu.c
  ${APP_DIR}/tlv_utils.c
  ${APP_DIR}/mem_utils.c
  ${APP_DIR}/utils.c
  ${APP_DIR}/uint128.c
  ${APP_DIR}/uint256.c
  ${PLUGIN_DIR}/common_utils.c
  ${MOCK_DIR}/mock.c
  ${BOLOS_SDK}/lib_standard_app/format.c
  ${BOLOS_SDK}/lib_standard_app/read.c
  ${BOLOS_SDK}/lib_standard_app/write.c
  ${BOLOS_SDK}/lib_tlv/tlv_library.c
)

set_source_files_properties(${BOLOS_SDK}/lib_tlv/tlv_library.c
                            PROPERTIES COMPILE_FLAGS "-Wno-pedantic")

target_compile_definitions(test_param_unit PRIVATE
  HAVE_ECDSA
  HAVE_HASH
  HAVE_SHA256
  HAVE_SHA3
  HAVE_ECC
  HAVE_MATH
)

target_link_libraries(test_param_unit PUBLIC
                      cmocka
                      gcov
                      ${LIBBSD_LIBRARIES}
                      -Wl,--wrap=value_get
                      -Wl,--wrap=value_cleanup
                      -Wl,--wrap=handle_value_struct
                      -Wl,--wrap=add_to_field_table
)

add_test(test_param_unit test_param_unit)

# ENUM parameter test
add_executable(test_param_enum
  ${SRC_DIR}/test_param_enum.c
  ${APP_DIR}/features/generic_tx_parser/gtp_param_enum.c
  ${APP_DIR}/features/generic_tx_parser/gtp_value.c
  ${APP_DIR}/tlv_apdu.c
  ${APP_DIR}/tlv_utils.c
  ${APP_DIR}/mem_utils.c
  ${APP_DIR}/utils.c
  ${APP_DIR}/uint128.c
  ${APP_DIR}/uint256.c
  ${PLUGIN_DIR}/common_utils.c
  ${MOCK_DIR}/mock.c
  ${BOLOS_SDK}/lib_standard_app/format.c
  ${BOLOS_SDK}/lib_standard_app/read.c
  ${BOLOS_SDK}/lib_standard_app/write.c
  ${BOLOS_SDK}/lib_tlv/tlv_library.c
)

target_include_directories(test_param_enum PRIVATE
  ${APP_DIR}/features/provide_enum_value
)

set_source_files_properties(${BOLOS_SDK}/lib_tlv/tlv_library.c
                            PROPERTIES COMPILE_FLAGS "-Wno-pedantic")

target_compile_definitions(test_param_enum PRIVATE
  HAVE_ECDSA
  HAVE_HASH
  HAVE_SHA256
  HAVE_SHA3
  HAVE_ECC
  HAVE_MATH
)

target_link_libraries(test_param_enum PUBLIC
                      cmocka
                      gcov
                      ${LIBBSD_LIBRARIES}
                      -Wl,--wrap=value_get
                      -Wl,--wrap=value_cleanup
                      -Wl,--wrap=handle_value_struct
                      -Wl,--wrap=add_to_field_table
                      -Wl,--wrap=get_current_tx_info
                      -Wl,--wrap=get_current_calldata
                      -Wl,--wrap=calldata_get_selector
                      -Wl,--wrap=get_matching_enum
)

add_test(test_param_enum test_param_enum)

# TOKEN parameter test
add_executable(test_param_token
  ${SRC_DIR}/test_param_token.c
  ${APP_DIR}/features/generic_tx_parser/gtp_param_token.c
  ${APP_DIR}/features/generic_tx_parser/gtp_value.c
  ${APP_DIR}/features/provide_erc20_token_information/token_info.c
  ${APP_DIR}/tlv_apdu.c
  ${APP_DIR}/tlv_utils.c
  ${APP_DIR}/mem_utils.c
  ${APP_DIR}/utils.c
  ${APP_DIR}/uint128.c
  ${APP_DIR}/uint256.c
  ${PLUGIN_DIR}/common_utils.c
  ${MOCK_DIR}/mock.c
  ${BOLOS_SDK}/lib_standard_app/format.c
  ${BOLOS_SDK}/lib_standard_app/read.c
  ${BOLOS_SDK}/lib_standard_app/write.c
  ${BOLOS_SDK}/lib_tlv/tlv_library.c
  ${BOLOS_SDK}/lib_lists/lists.c
)

set_source_files_properties(${BOLOS_SDK}/lib_tlv/tlv_library.c
                            PROPERTIES COMPILE_FLAGS "-Wno-pedantic")

target_compile_definitions(test_param_token PRIVATE
  HAVE_ECDSA
  HAVE_HASH
  HAVE_SHA256
  HAVE_SHA3
  HAVE_ECC
  HAVE_MATH
)

target_link_libraries(test_param_token PUBLIC
                      cmocka
                      gcov
                      ${LIBBSD_LIBRARIES}
                      -Wl,--wrap=value_get
                      -Wl,--wrap=value_cleanup
                      -Wl,--wrap=handle_value_struct
                      -Wl,--wrap=add_to_field_table
                      -Wl,--wrap=get_current_tx_info
                      -Wl,--wrap=get_matching_token_info_or_dummy
                      -Wl,--wrap=get_displayable_ticker
)

add_test(test_param_token test_param_token)

# NFT parameter test
add_executable(test_param_nft
  ${SRC_DIR}/test_param_nft.c
  ${APP_DIR}/features/generic_tx_parser/gtp_param_nft.c
  ${APP_DIR}/features/generic_tx_parser/gtp_value.c
  ${APP_DIR}/tlv_apdu.c
  ${APP_DIR}/tlv_utils.c
  ${APP_DIR}/mem_utils.c
  ${APP_DIR}/utils.c
  ${APP_DIR}/uint128.c
  ${APP_DIR}/uint256.c
  ${PLUGIN_DIR}/common_utils.c
  ${MOCK_DIR}/mock.c
  ${BOLOS_SDK}/lib_standard_app/format.c
  ${BOLOS_SDK}/lib_standard_app/read.c
  ${BOLOS_SDK}/lib_standard_app/write.c
  ${BOLOS_SDK}/lib_tlv/tlv_library.c
)

target_include_directories(test_param_nft PRIVATE
  ${APP_DIR}/features/provide_nft_information
)

set_source_files_properties(${BOLOS_SDK}/lib_tlv/tlv_library.c
                            PROPERTIES COMPILE_FLAGS "-Wno-pedantic")

target_compile_definitions(test_param_nft PRIVATE
  HAVE_ECDSA
  HAVE_HASH
  HAVE_SHA256
  HAVE_SHA3
  HAVE_ECC
  HAVE_MATH
)

target_link_libraries(test_param_nft PUBLIC
                      cmocka
                      gcov
                      ${LIBBSD_LIBRARIES}
                      -Wl,--wrap=value_get
                      -Wl,--wrap=value_cleanup
                      -Wl,--wrap=handle_value_struct
                      -Wl,--wrap=add_to_field_table
                      -Wl,--wrap=get_current_tx_info
                      -Wl,--wrap=get_matching_nft_info
)

add_test(test_param_nft test_param_nft)

# path_array TLV parser test
add_executable(test_path_array
  ${SRC_DIR}/test_path_array.c
  ${APP_DIR}/features/generic_tx_parser/gtp_path_array.c
  ${MOCK_DIR}/mock.c
  ${BOLOS_SDK}/lib_standard_app/read.c
  ${BOLOS_SDK}/lib_tlv/tlv_library.c
)

set_source_files_properties(${BOLOS_SDK}/lib_tlv/tlv_library.c
                            PROPERTIES COMPILE_FLAGS "-Wno-pedantic")

target_link_libraries(test_path_array PUBLIC
                      cmocka
                      gcov
                      ${LIBBSD_LIBRARIES}
)

add_test(test_path_array test_path_array)

# path_slice TLV parser test
add_executable(test_path_slice
  ${SRC_DIR}/test_path_slice.c
  ${APP_DIR}/features/generic_tx_parser/gtp_path_slice.c
  ${MOCK_DIR}/mock.c
  ${BOLOS_SDK}/lib_standard_app/read.c
  ${BOLOS_SDK}/lib_tlv/tlv_library.c
)

set_source_files_properties(${BOLOS_SDK}/lib_tlv/tlv_library.c
                            PROPERTIES COMPILE_FLAGS "-Wno-pedantic")

target_link_libraries(test_path_slice PUBLIC
                      cmocka
                      gcov
                      ${LIBBSD_LIBRARIES}
)

add_test(test_path_slice test_path_slice)
