cmake_minimum_required (VERSION 3.8...3.31)

# ################################# #
# test for Curly::getResponseCode() #
# ################################# #


# test binary for Curly::getResponseCode()
project(test_curly_status_code)

set(test_curly_status_code_sources
    ../../../libstriezel/common/StringUtils.cpp
    ../../../source/Curly.cpp
    status-code.cpp)

if (CMAKE_CXX_COMPILER_ID STREQUAL "GNU" OR CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
    add_definitions (-Wall -Wextra -Wpedantic -pedantic-errors -Wshadow -O2 -fexceptions)

    set( CMAKE_EXE_LINKER_FLAGS  "${CMAKE_EXE_LINKER_FLAGS} -s" )
endif ()
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(test_curly_status_code ${test_curly_status_code_sources})

# find cURL library
find_package (CURL)
if (CURL_FOUND)
  include_directories(${CURL_INCLUDE_DIRS})
  target_link_libraries (test_curly_status_code ${CURL_LIBRARIES})
else ()
  message ( FATAL_ERROR "cURL was not found!" )
endif (CURL_FOUND)

# add test for Curly::getResponseCode()
add_test(NAME Curly_HTTP_status_code
         COMMAND $<TARGET_FILE:test_curly_status_code>)
