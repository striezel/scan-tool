# Might work with earlier versions, too, but try to use a more recent one.
cmake_minimum_required (VERSION 3.8)

project(vt-api-request)

set(vt-api-request_sources
    ../../libstriezel/common/StringUtils.cpp
    ../../libstriezel/filesystem/directory.cpp
    ../../libstriezel/filesystem/file.cpp
    ../../libstriezel/hash/sha256/sha256.cpp
    ../../third-party/simdjson/simdjson.cpp
    ../virustotal/CacheManagerV2.cpp
    ../Configuration.cpp
    ../Curly.cpp
    ../Engine.cpp
    ../virustotal/EngineV2.cpp
    ../Report.cpp
    ../virustotal/ReportBase.cpp
    ../virustotal/ReportV2.cpp
    ../Scanner.cpp
    ../virustotal/ScannerV2.cpp
    ../StringToTimeT.cpp
    main.cpp)

if (CMAKE_COMPILER_IS_GNUCC)
    add_definitions (-Wall -O2 -fexceptions)
endif (CMAKE_COMPILER_IS_GNUCC)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set( CMAKE_EXE_LINKER_FLAGS  "${CMAKE_EXE_LINKER_FLAGS} -s" )

add_executable(vt-api-request ${vt-api-request_sources})

# find cURL library
find_package (CURL)
if (CURL_FOUND)
  include_directories(${CURL_INCLUDE_DIRS})
  target_link_libraries (vt-api-request ${CURL_LIBRARIES})
else ()
  message ( FATAL_ERROR "cURL was not found!" )
endif (CURL_FOUND)
