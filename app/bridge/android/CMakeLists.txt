cmake_minimum_required(VERSION 3.22.1)
project(p2pchat_bridge LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(OpenSSL REQUIRED)

add_library(p2pchat_bridge SHARED
  ${CMAKE_CURRENT_LIST_DIR}/cpp/BridgeJNI.cpp
  ${CMAKE_CURRENT_LIST_DIR}/../src/Bridge.cpp
  ${CMAKE_CURRENT_LIST_DIR}/../src/BridgeJson.cpp
  ${CMAKE_CURRENT_LIST_DIR}/../../core/core/src/Core.cpp
  ${CMAKE_CURRENT_LIST_DIR}/../../core/session/src/SessionManager.cpp
  ${CMAKE_CURRENT_LIST_DIR}/../../core/transport/src/LoopbackTransport.cpp
  ${CMAKE_CURRENT_LIST_DIR}/../../core/transport/src/DatagramTransport.cpp
  ${CMAKE_CURRENT_LIST_DIR}/../../core/transport/src/QuicTransport.cpp
  ${CMAKE_CURRENT_LIST_DIR}/../../core/transport/src/WebRtcTransport.cpp
  ${CMAKE_CURRENT_LIST_DIR}/../../core/transport/src/Ice.cpp
  ${CMAKE_CURRENT_LIST_DIR}/../../core/storage/src/BloomFilter.cpp
  ${CMAKE_CURRENT_LIST_DIR}/../../core/storage/src/Storage.cpp
  ${CMAKE_CURRENT_LIST_DIR}/../../core/crypto/src/Primitives.cpp
  ${CMAKE_CURRENT_LIST_DIR}/../../core/crypto/src/Ratchet.cpp
  ${CMAKE_CURRENT_LIST_DIR}/../../core/crypto/src/X3DH.cpp
  ${CMAKE_CURRENT_LIST_DIR}/../../core/identity/src/IdentityStore.cpp
)

target_include_directories(p2pchat_bridge
  PRIVATE
    ${CMAKE_CURRENT_LIST_DIR}/../include
    ${CMAKE_CURRENT_LIST_DIR}/../../core/core/include
    ${CMAKE_CURRENT_LIST_DIR}/../../core/session/include
    ${CMAKE_CURRENT_LIST_DIR}/../../core/transport/include
    ${CMAKE_CURRENT_LIST_DIR}/../../core/storage/include
    ${CMAKE_CURRENT_LIST_DIR}/../../core/crypto/include
    ${CMAKE_CURRENT_LIST_DIR}/../../core/identity/include
    ${CMAKE_CURRENT_LIST_DIR}/../../core/security/include
)

find_library(ANDROID_LOG_LIB log)
find_library(ANDROID_LIB android)
find_library(SQLITE3_LIB sqlite3)

target_link_libraries(p2pchat_bridge
  PRIVATE
    OpenSSL::Crypto
    ${SQLITE3_LIB}
    ${ANDROID_LOG_LIB}
    ${ANDROID_LIB}
)
