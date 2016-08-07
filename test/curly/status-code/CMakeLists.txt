# We might support earlier versions, too, but it's only tested with 2.8.9.
cmake_minimum_required (VERSION 2.8)

# ################################# #
# test for Curly::getResponseCode() #
# ################################# #


# test binary for Curly::getResponseCode()
project(test_curly_status_code)

set(test_curly_status_code_sources
    ../../../libstriezel/common/StringUtils.cpp
    ../../../source/Curly.cpp
    status-code.cpp)

if (CMAKE_COMPILER_IS_GNUCC)
    add_definitions (-Wall -O2 -fexceptions)
endif (CMAKE_COMPILER_IS_GNUCC)
add_definitions(-std=c++0x)

set( CMAKE_EXE_LINKER_FLAGS  "${CMAKE_EXE_LINKER_FLAGS} -s" )

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
