# Build configuration for core identity module, CLI, and tests.
cmake_minimum_required(VERSION 3.20)
project(p2pchat_core LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(OpenSSL REQUIRED)

add_library(identity
  core/identity/src/IdentityStore.cpp
)

target_include_directories(identity
  PUBLIC
    core/identity/include
)

target_link_libraries(identity
  PRIVATE
    OpenSSL::Crypto
)

if(APPLE)
  target_link_libraries(identity PRIVATE "-framework Security" "-framework CoreFoundation")
endif()

if(WIN32)
  target_link_libraries(identity PRIVATE Crypt32)
endif()

if(UNIX AND NOT APPLE)
  find_package(PkgConfig)
  if(PKG_CONFIG_FOUND)
    pkg_check_modules(LIBSECRET QUIET libsecret-1)
    if(LIBSECRET_FOUND)
      target_include_directories(identity PRIVATE ${LIBSECRET_INCLUDE_DIRS})
      target_link_libraries(identity PRIVATE ${LIBSECRET_LIBRARIES})
    endif()
  endif()
endif()

add_executable(identity_cli
  tools/identity_cli.cpp
)

target_link_libraries(identity_cli
  PRIVATE
    identity
    OpenSSL::Crypto
)

if(APPLE)
  target_link_libraries(identity_cli PRIVATE "-framework Security" "-framework CoreFoundation")
endif()

if(WIN32)
  target_link_libraries(identity_cli PRIVATE Crypt32)
endif()

if(UNIX AND NOT APPLE)
  if(LIBSECRET_FOUND)
    target_include_directories(identity_cli PRIVATE ${LIBSECRET_INCLUDE_DIRS})
    target_link_libraries(identity_cli PRIVATE ${LIBSECRET_LIBRARIES})
  endif()
endif()

enable_testing()

add_executable(identity_tests
  tests/identity_tests.cpp
)

target_link_libraries(identity_tests
  PRIVATE
    identity
    OpenSSL::Crypto
)

if(APPLE)
  target_link_libraries(identity_tests PRIVATE "-framework Security" "-framework CoreFoundation")
endif()

if(WIN32)
  target_link_libraries(identity_tests PRIVATE Crypt32)
endif()

if(UNIX AND NOT APPLE)
  if(LIBSECRET_FOUND)
    target_include_directories(identity_tests PRIVATE ${LIBSECRET_INCLUDE_DIRS})
    target_link_libraries(identity_tests PRIVATE ${LIBSECRET_LIBRARIES})
  endif()
endif()

add_test(NAME identity_tests COMMAND identity_tests)

add_custom_target(check_phase0
  COMMAND /bin/sh ${CMAKE_CURRENT_SOURCE_DIR}/scripts/check_phase0.sh
  WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
)
