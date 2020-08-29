# We might support earlier versions, too, but it's only tested with 2.8.9.
cmake_minimum_required (VERSION 2.8)

# ######################################### #
# tests for response headers in class Curly #
# ######################################### #

# test binary for Curly
project(test_curly_response_headers)

#add_definitions(-DDEFINE_CONSTANT_HERE -DANOTHER_ONE_THERE -DTHIS_IS_THE_THIRD)

set(test_curly_response_headers_sources
    ../../../libstriezel/common/StringUtils.cpp
    ../../../source/Curly.cpp
    response-headers.cpp)

if (CMAKE_COMPILER_IS_GNUCC)
    add_definitions (-Wall -O2 -fexceptions)
endif (CMAKE_COMPILER_IS_GNUCC)
add_definitions(-std=c++14)

set( CMAKE_EXE_LINKER_FLAGS  "${CMAKE_EXE_LINKER_FLAGS} -s" )

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
