# add_eth_unit_test(NAME
#   [APP_SOURCES   ...]   # production sources (under ${APP_DIR}/...) to link
#   [SDK_SOURCES   ...]   # extra SDK sources beyond the default helpers
#   [INCLUDES      ...]   # per-target include directories
#   [DEFS          ...]   # per-target compile definitions (HAVE_* etc.)
#   [COMPILE_OPTIONS ...] # per-target compile flags (-include foo.h, ...)
#   [WRAPS         ...]   # symbol names to be linker-wrapped
#                         #   (expanded to -Wl,--wrap=<name> link flags)
#   [LINK_OPTIONS  ...]   # extra raw linker flags
#   [NO_GLOBALS]          # skip linking eth_tests_app_globals
#                         #   (lightweight targets that don't pull
#                         #   shared_context.h)
# )
#
# Always-on dependencies: eth_tests_mocks (mock.c), eth_tests_sdk_helpers
# (format/read/write/tlv_library -- only the .o files actually referenced
# are pulled into the final binary), cmocka, gcov, libbsd.
#
# Always-on compile defs:
#   HAVE_ECDSA HAVE_HASH HAVE_SHA256 HAVE_SHA3 HAVE_ECC HAVE_MATH
#   HAVE_TRANSACTION_CHECKS (widened to match every test's view of
#                            internalStorage_t; otherwise the storage
#                            compiled into eth_tests_app_globals would
#                            have a different layout than its callers).
function(add_eth_unit_test NAME)
  set(options NO_GLOBALS)
  set(oneValueArgs "")
  set(multiValueArgs APP_SOURCES SDK_SOURCES INCLUDES DEFS COMPILE_OPTIONS WRAPS LINK_OPTIONS)
  cmake_parse_arguments(T "${options}" "${oneValueArgs}" "${multiValueArgs}" ${ARGN})

  add_executable(${NAME}
    ${SRC_DIR}/${NAME}.c
    ${T_APP_SOURCES}
    ${T_SDK_SOURCES}
  )

  target_link_libraries(${NAME} PUBLIC
    eth_tests_mocks
    eth_tests_sdk_helpers
    cmocka
    gcov
    ${LIBBSD_LIBRARIES}
  )

  if(NOT T_NO_GLOBALS)
    target_link_libraries(${NAME} PUBLIC eth_tests_app_globals)
  endif()

  if(T_INCLUDES)
    target_include_directories(${NAME} PRIVATE ${T_INCLUDES})
  endif()

  target_compile_definitions(${NAME} PRIVATE
    HAVE_ECDSA HAVE_HASH HAVE_SHA256 HAVE_SHA3 HAVE_ECC HAVE_MATH
    HAVE_TRANSACTION_CHECKS
  )
  if(T_DEFS)
    target_compile_definitions(${NAME} PRIVATE ${T_DEFS})
  endif()

  if(T_COMPILE_OPTIONS)
    target_compile_options(${NAME} PRIVATE ${T_COMPILE_OPTIONS})
  endif()

  foreach(W ${T_WRAPS})
    target_link_options(${NAME} PRIVATE "-Wl,--wrap=${W}")
  endforeach()
  if(T_LINK_OPTIONS)
    target_link_options(${NAME} PRIVATE ${T_LINK_OPTIONS})
  endif()

  add_test(${NAME} ${NAME})
endfunction()
