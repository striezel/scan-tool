# Might work with earlier versions, too, but try to use a more recent one.
cmake_minimum_required (VERSION 3.8)

project(scan-tool-cache)

#add_definitions(-DDEFINE_CONSTANT_HERE -DANOTHER_ONE_THERE -DTHIS_IS_THE_THIRD)

set(scan-tool-cache_sources
    ../../libstriezel/common/StringUtils.cpp
    ../../libstriezel/filesystem/directory.cpp
    ../../libstriezel/filesystem/file.cpp
    ../../libstriezel/hash/sha256/MessageSource.cpp
    ../../libstriezel/hash/sha256/sha256.cpp
    ../../third-party/simdjson/simdjson.cpp
    ../virustotal/CacheManagerV2.cpp
    ../virustotal/EngineV2.cpp
    ../virustotal/ReportV2.cpp
    ../virustotal/ReportBase.cpp
    ../virustotal/ScannerV2.cpp
    ../Configuration.cpp
    ../Curly.cpp
    ../Engine.cpp
    ../Report.cpp
    ../Scanner.cpp
    ../StringToTimeT.cpp
    CacheIteration.cpp
    IterationOperationStatistics.cpp
    IterationOperationUpdate.cpp
    main.cpp)

if (CMAKE_COMPILER_IS_GNUCC)
    add_definitions (-Wall -O2 -fexceptions)
endif (CMAKE_COMPILER_IS_GNUCC)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set( CMAKE_EXE_LINKER_FLAGS  "${CMAKE_EXE_LINKER_FLAGS} -s" )

add_executable(scan-tool-cache ${scan-tool-cache_sources})

# find cURL library
find_package (CURL)
if (CURL_FOUND)
  include_directories(${CURL_INCLUDE_DIRS})
  target_link_libraries (scan-tool-cache ${CURL_LIBRARIES})
else ()
  message ( FATAL_ERROR "cURL was not found!" )
endif (CURL_FOUND)
