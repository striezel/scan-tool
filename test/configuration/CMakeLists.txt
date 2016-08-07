# Might work with earlier versions, too, but it's only tested with 2.8.9.
cmake_minimum_required (VERSION 2.8)

project(load-configuration-test)

#add_definitions(-DDEFINE_CONSTANT_HERE -DANOTHER_ONE_THERE -DTHIS_IS_THE_THIRD)

set(load-configuration-test_sources
    ../../libstriezel/common/StringUtils.cpp
    ../../libstriezel/filesystem/file.cpp
    ../../source/Configuration.cpp
    main.cpp)

if (CMAKE_COMPILER_IS_GNUCC)
    add_definitions (-Wall -O2 -fexceptions)
endif (CMAKE_COMPILER_IS_GNUCC)
add_definitions(-std=c++0x)

set( CMAKE_EXE_LINKER_FLAGS  "${CMAKE_EXE_LINKER_FLAGS} -s" )

add_executable(load-configuration-test ${load-configuration-test_sources})

# add it as test case
add_test(NAME load-configuration-with-apikey
         COMMAND $<TARGET_FILE:load-configuration-test> "${CMAKE_CURRENT_SOURCE_DIR}/../../script/vt-apikey.example.conf")
