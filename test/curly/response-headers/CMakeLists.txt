cmake_minimum_required (VERSION 3.8...3.31)

# ######################################### #
# tests for response headers in class Curly #
# ######################################### #

# test binary for Curly
project(test_curly_response_headers)

set(test_curly_response_headers_sources
    ../../../libstriezel/common/StringUtils.cpp
    ../../../source/Curly.cpp
    response-headers.cpp)

if (CMAKE_CXX_COMPILER_ID STREQUAL "GNU" OR CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
    add_definitions (-Wall -Wextra -Wpedantic -pedantic-errors -Wshadow -O2 -fexceptions)

    set( CMAKE_EXE_LINKER_FLAGS  "${CMAKE_EXE_LINKER_FLAGS} -s" )
endif ()
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(test_curly_response_headers ${test_curly_response_headers_sources})

# find cURL library
find_package (CURL)
if (CURL_FOUND)
  include_directories(${CURL_INCLUDE_DIRS})
  target_link_libraries (test_curly_response_headers ${CURL_LIBRARIES})
else ()
  message ( FATAL_ERROR "cURL was not found!" )
endif (CURL_FOUND)

# add test for capturing response headers in Curly class
add_test(NAME Curly_ResponseHeaders
         COMMAND $<TARGET_FILE:test_curly_response_headers>)
