# We might support earlier versions, too, but try to use a more recent one.
cmake_minimum_required (VERSION 3.8)

# ########################################## #
# test for class Curly's supported protocols #
# ########################################## #

# test binary for protocols supported by cURL in Curly
project(test_curly_protocol_support)

set(test_curly_protocol_support_sources
    ../../../source/Curly.cpp
    protocol-support.cpp)

if (CMAKE_COMPILER_IS_GNUCC)
    add_definitions (-Wall -O2 -fexceptions)
endif (CMAKE_COMPILER_IS_GNUCC)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set( CMAKE_EXE_LINKER_FLAGS  "${CMAKE_EXE_LINKER_FLAGS} -s" )

add_executable(test_curly_protocol_support ${test_curly_protocol_support_sources})

# find cURL library
find_package (CURL)
if (CURL_FOUND)
  include_directories(${CURL_INCLUDE_DIRS})
  target_link_libraries (test_curly_protocol_support ${CURL_LIBRARIES})
else ()
  message ( FATAL_ERROR "cURL was not found!" )
endif (CURL_FOUND)

# add test for Curly class
add_test(NAME Curly_ProtocolSupport
         COMMAND $<TARGET_FILE:test_curly_protocol_support>)
