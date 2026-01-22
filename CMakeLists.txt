# Build configuration for core identity module, CLI, and tests.
cmake_minimum_required(VERSION 3.20)
project(p2pchat_core LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(OpenSSL REQUIRED)
find_package(SQLite3 REQUIRED)

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

add_library(crypto
  core/crypto/src/Primitives.cpp
  core/crypto/src/Ratchet.cpp
  core/crypto/src/X3DH.cpp
)

target_include_directories(crypto
  PUBLIC
    core/crypto/include
    core/identity/include
)

target_link_libraries(crypto
  PRIVATE
    OpenSSL::Crypto
)

add_library(storage
  core/storage/src/BloomFilter.cpp
  core/storage/src/Storage.cpp
)

target_include_directories(storage
  PUBLIC
    core/storage/include
    core/identity/include
    core/crypto/include
  PRIVATE
    ${SQLite3_INCLUDE_DIRS}
)

target_link_libraries(storage
  PRIVATE
    ${SQLite3_LIBRARIES}
    OpenSSL::Crypto
  PUBLIC
    identity
    crypto
)

add_library(transport
  core/transport/src/LoopbackTransport.cpp
)

target_include_directories(transport
  PUBLIC
    core/transport/include
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

add_executable(crypto_tests
  tests/crypto_tests.cpp
)

target_link_libraries(crypto_tests
  PRIVATE
    crypto
    OpenSSL::Crypto
)

add_executable(storage_tests
  tests/storage_tests.cpp
)

target_link_libraries(storage_tests
  PRIVATE
    storage
    identity
    crypto
    ${SQLite3_LIBRARIES}
    OpenSSL::Crypto
)

add_executable(transport_tests
  tests/transport_tests.cpp
)

target_link_libraries(transport_tests
  PRIVATE
    transport
)

target_compile_definitions(storage_tests
  PRIVATE
    P2PCHAT_SOURCE_DIR="${CMAKE_CURRENT_SOURCE_DIR}"
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
add_test(NAME crypto_tests COMMAND crypto_tests)
add_test(NAME storage_tests COMMAND storage_tests)
add_test(NAME transport_tests COMMAND transport_tests)

add_custom_target(check_phase0
  COMMAND /bin/sh ${CMAKE_CURRENT_SOURCE_DIR}/scripts/check_phase0.sh
  WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
)
