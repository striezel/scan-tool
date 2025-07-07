# We might support earlier versions, too, but try to use a more recent one.
cmake_minimum_required (VERSION 3.8...3.31)

# ############################################## #
# test for class Curly's fields in POST requests #
# ############################################## #


# test binary for Curly POST requests
project(test_curly_post)

set(test_curly_post_sources
    ../../../source/Curly.cpp
    ../../../third-party/simdjson/simdjson.cpp
    post.cpp)

if (CMAKE_COMPILER_IS_GNUCC)
    add_definitions (-Wall -O2 -fexceptions)
endif (CMAKE_COMPILER_IS_GNUCC)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set( CMAKE_EXE_LINKER_FLAGS  "${CMAKE_EXE_LINKER_FLAGS} -s" )

add_executable(test_curly_post ${test_curly_post_sources})

# find cURL library
find_package (CURL)
if (CURL_FOUND)
  include_directories(${CURL_INCLUDE_DIRS})
  target_link_libraries (test_curly_post ${CURL_LIBRARIES})
else ()
  message ( FATAL_ERROR "cURL was not found!" )
endif (CURL_FOUND)

# add test for Curly class
add_test(NAME Curly_POST
         COMMAND $<TARGET_FILE:test_curly_post>)
