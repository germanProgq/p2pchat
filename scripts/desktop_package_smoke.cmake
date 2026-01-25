# Desktop package smoke test. Spec: docs/desktop_app.md.
cmake_minimum_required(VERSION 3.20)

if(NOT DEFINED BUILD_DIR)
  message(FATAL_ERROR "BUILD_DIR not set")
endif()

if(NOT DEFINED PACKAGE_NAME)
  set(PACKAGE_NAME "p2pchat-desktop")
endif()

if(CMAKE_HOST_WIN32)
  set(GEN "ZIP")
  set(EXT "zip")
else()
  set(GEN "TGZ")
  set(EXT "tar.gz")
endif()

find_program(CPACK_EXECUTABLE cpack)
if(NOT CPACK_EXECUTABLE)
  message(FATAL_ERROR "cpack not found")
endif()

execute_process(
  COMMAND "${CPACK_EXECUTABLE}" -G "${GEN}"
  WORKING_DIRECTORY "${BUILD_DIR}"
  RESULT_VARIABLE result
)
if(NOT result EQUAL 0)
  message(FATAL_ERROR "cpack failed")
endif()

set(package "${BUILD_DIR}/${PACKAGE_NAME}.${EXT}")
if(NOT EXISTS "${package}")
  file(GLOB matches "${BUILD_DIR}/${PACKAGE_NAME}*.${EXT}")
  list(LENGTH matches match_count)
  if(match_count GREATER 0)
    list(GET matches 0 package)
  else()
    message(FATAL_ERROR "package not found")
  endif()
endif()

set(extract_dir "${BUILD_DIR}/package_smoke_extract")
file(REMOVE_RECURSE "${extract_dir}")
file(MAKE_DIRECTORY "${extract_dir}")

execute_process(
  COMMAND "${CMAKE_COMMAND}" -E tar xf "${package}"
  WORKING_DIRECTORY "${extract_dir}"
  RESULT_VARIABLE result
)
if(NOT result EQUAL 0)
  message(FATAL_ERROR "package extract failed")
endif()

if(CMAKE_HOST_WIN32)
  file(GLOB_RECURSE bin_candidates "${extract_dir}/*/bin/p2pchat_desktop.exe")
else()
  file(GLOB_RECURSE bin_candidates "${extract_dir}/*/bin/p2pchat_desktop")
endif()
list(LENGTH bin_candidates bin_count)
if(bin_count EQUAL 0)
  message(FATAL_ERROR "packaged binary not found")
endif()
list(GET bin_candidates 0 bin_path)

file(GLOB_RECURSE schema_candidates "${extract_dir}/*/share/p2pchat/schema.sql")
list(LENGTH schema_candidates schema_count)
if(schema_count EQUAL 0)
  message(FATAL_ERROR "schema.sql not found in package")
endif()
list(GET schema_candidates 0 schema_path)

execute_process(
  COMMAND "${bin_path}" --smoke --schema "${schema_path}"
  RESULT_VARIABLE result
)
if(NOT result EQUAL 0)
  message(FATAL_ERROR "packaged binary smoke failed")
endif()
