# Might work with earlier versions, too, but it's only tested with 2.8.9.
cmake_minimum_required (VERSION 2.8)

project(string-to-time-t-test)

#add_definitions(-DDEFINE_CONSTANT_HERE -DANOTHER_ONE_THERE -DTHIS_IS_THE_THIRD)

set(string-to-time-t-test_sources
    ../../../libstriezel/common/StringUtils.cpp
    ../../../source/StringToTimeT.cpp
    main.cpp)

if (CMAKE_COMPILER_IS_GNUCC)
    add_definitions (-Wall -O2 -fexceptions)
endif (CMAKE_COMPILER_IS_GNUCC)
add_definitions(-std=c++0x)

set( CMAKE_EXE_LINKER_FLAGS  "${CMAKE_EXE_LINKER_FLAGS} -s" )

add_executable(string-to-time-t-test ${string-to-time-t-test_sources})

# add it as test case
add_test(NAME stringToTimeT
         COMMAND $<TARGET_FILE:string-to-time-t-test>)
