# We might support earlier versions, too, but it's only tested with 2.8.9.
cmake_minimum_required (VERSION 2.8)

# test binary for Curly POST request with file
project(test_curly_post_file)

set(test_curly_post_file_sources
    ../../../libstriezel/common/StringUtils.cpp
    ../../../libstriezel/filesystem/file.cpp
    ../../../source/Curly.cpp
    post-file.cpp)

if (CMAKE_COMPILER_IS_GNUCC)
    add_definitions (-Wall -O2 -fexceptions)
endif (CMAKE_COMPILER_IS_GNUCC)
add_definitions(-std=c++0x)

set( CMAKE_EXE_LINKER_FLAGS  "${CMAKE_EXE_LINKER_FLAGS} -s" )

add_executable(test_curly_post_file ${test_curly_post_file_sources})

# find cURL library
find_package (CURL)
if (CURL_FOUND)
  include_directories(${CURL_INCLUDE_DIRS})
  target_link_libraries (test_curly_post_file ${CURL_LIBRARIES})
else ()
  message ( FATAL_ERROR "cURL was not found!" )
endif (CURL_FOUND)
# find jsoncpp library
set(LibJsonCpp_DIR "../../../cmake/" )
find_package (LibJsonCpp)
if (LIBJSONCPP_FOUND)
  include_directories(${LIBJSONCPP_INCLUDE_DIRS})
  target_link_libraries (test_curly_post_file ${LIBJSONCPP_LIBRARIES})
else ()
  message ( FATAL_ERROR "libjsoncpp was not found!" )
endif (LIBJSONCPP_FOUND)


# add test for Curly class
add_test(NAME Curly_POST_with_file
         COMMAND $<TARGET_FILE:test_curly_post_file>)
