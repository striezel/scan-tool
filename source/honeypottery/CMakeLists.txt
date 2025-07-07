cmake_minimum_required (VERSION 3.8...3.31)

project(honeypottery)

set(honeypottery_sources
    ../../libstriezel/common/StringUtils.cpp
    ../../libstriezel/filesystem/file.cpp
    ../../third-party/simdjson/simdjson.cpp
    ../Configuration.cpp
    ../Curly.cpp
    ../Engine.cpp
    ../Report.cpp
    ../virustotal/ReportBase.cpp
    ../virustotal/ReportHoneypot.cpp
    ../Scanner.cpp
    ../virustotal/ScannerHoneypot.cpp
    ../StringToTimeT.cpp
    main.cpp)

if (CMAKE_CXX_COMPILER_ID STREQUAL "GNU" OR CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
    add_definitions (-Wall -Wextra -Wpedantic -pedantic-errors -Wshadow -O2 -fexceptions)

    set( CMAKE_EXE_LINKER_FLAGS  "${CMAKE_EXE_LINKER_FLAGS} -s" )
endif ()
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(honeypottery ${honeypottery_sources})

# find cURL library
find_package (CURL)
if (CURL_FOUND)
  include_directories(${CURL_INCLUDE_DIRS})
  target_link_libraries (honeypottery ${CURL_LIBRARIES})
else ()
  message ( FATAL_ERROR "cURL was not found!" )
endif (CURL_FOUND)
