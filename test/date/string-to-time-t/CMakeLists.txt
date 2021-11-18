# Might work with earlier versions, too, but try to use a more recent one.
cmake_minimum_required (VERSION 3.8)

project(string-to-time-t-test)

set(string-to-time-t-test_sources
    ../../../libstriezel/common/StringUtils.cpp
    ../../../source/StringToTimeT.cpp
    main.cpp)

if (CMAKE_COMPILER_IS_GNUCC)
    add_definitions (-Wall -O2 -fexceptions)
endif (CMAKE_COMPILER_IS_GNUCC)
add_definitions(-std=c++14)

set( CMAKE_EXE_LINKER_FLAGS  "${CMAKE_EXE_LINKER_FLAGS} -s" )

add_executable(string-to-time-t-test ${string-to-time-t-test_sources})

# add it as test case
add_test(NAME stringToTimeT
         COMMAND $<TARGET_FILE:string-to-time-t-test>)
