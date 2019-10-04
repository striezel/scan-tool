# Might work with earlier versions, too, but it's only tested with 2.8.9.
cmake_minimum_required (VERSION 2.8)

project(parser-virustotal-v2)

set(parser-virustotal-v2_sources
    ../../../libstriezel/common/StringUtils.cpp
    ../../../libstriezel/filesystem/file.cpp
    ../../../source/Engine.cpp
    ../../../source/Report.cpp
    ../../../source/StringToTimeT.cpp
    ../../../source/virustotal/EngineV2.cpp
    ../../../source/virustotal/ReportBase.cpp
    ../../../source/virustotal/ReportV2.cpp
    main.cpp)

if (CMAKE_COMPILER_IS_GNUCC)
    add_definitions (-Wall -O2 -fexceptions)
endif (CMAKE_COMPILER_IS_GNUCC)
add_definitions(-std=c++14)

set( CMAKE_EXE_LINKER_FLAGS  "${CMAKE_EXE_LINKER_FLAGS} -s" )

add_executable(parser-virustotal-v2 ${parser-virustotal-v2_sources})

# find jsoncpp library
set(LibJsonCpp_DIR "../../../cmake/" )
find_package (LibJsonCpp)
if (LIBJSONCPP_FOUND)
  include_directories(${LIBJSONCPP_INCLUDE_DIRS})
  target_link_libraries (parser-virustotal-v2 ${LIBJSONCPP_LIBRARIES})
else ()
  message ( FATAL_ERROR "libjsoncpp was not found!" )
endif (LIBJSONCPP_FOUND)

# add it as test case
add_test(NAME Test_Parser_VirusTotal_v2
         COMMAND $<TARGET_FILE:parser-virustotal-v2> "${CMAKE_CURRENT_SOURCE_DIR}/ScanResponse.json")
