# We might support earlier versions, too, but try to use a more recent one.
cmake_minimum_required (VERSION 3.8)

# ######################################### #
# tests for custom headers with class Curly #
# ######################################### #

# test binary for Curly
project(test_curly_headers)

set(test_curly_headers_sources
    ../../../source/Curly.cpp
    ../../../third-party/simdjson/simdjson.cpp
    headers.cpp)

if (CMAKE_COMPILER_IS_GNUCC)
    add_definitions (-Wall -O2 -fexceptions)
endif (CMAKE_COMPILER_IS_GNUCC)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set( CMAKE_EXE_LINKER_FLAGS  "${CMAKE_EXE_LINKER_FLAGS} -s" )

add_executable(test_curly_headers ${test_curly_headers_sources})

# find cURL library
find_package (CURL)
if (CURL_FOUND)
  include_directories(${CURL_INCLUDE_DIRS})
  target_link_libraries (test_curly_headers ${CURL_LIBRARIES})
else ()
  message ( FATAL_ERROR "cURL was not found!" )
endif (CURL_FOUND)

# add test for custom headers in Curly class
add_test(NAME Curly_CustomHeaders
         COMMAND $<TARGET_FILE:test_curly_headers>)
