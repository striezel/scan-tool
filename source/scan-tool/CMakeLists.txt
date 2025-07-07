# Might work with earlier versions, too, but try to use a recent version.
cmake_minimum_required (VERSION 3.8...3.31)

project(scan-tool)

#add_definitions(-DDEFINE_CONSTANT_HERE -DANOTHER_ONE_THERE -DTHIS_IS_THE_THIRD)

set(scan-tool_sources
    ../../libstriezel/archive/7z/archive.cpp
    ../../libstriezel/archive/ar/archive.cpp
    ../../libstriezel/archive/archiveLibarchive.cpp
    ../../libstriezel/archive/cab/archive.cpp
    ../../libstriezel/archive/entry.cpp
    ../../libstriezel/archive/entryLibarchive.cpp
    ../../libstriezel/archive/gzip/archive.cpp
    ../../libstriezel/archive/installshield/archive.cpp
    ../../libstriezel/archive/iso9660/archive.cpp
    ../../libstriezel/archive/rar/archive.cpp
    ../../libstriezel/archive/tar/archive.cpp
    ../../libstriezel/archive/xz/archive.cpp
    ../../libstriezel/archive/zip/archive.cpp
    ../../libstriezel/archive/zip/entry.cpp
    ../../libstriezel/common/StringUtils.cpp
    ../../libstriezel/filesystem/directory.cpp
    ../../libstriezel/filesystem/file.cpp
    ../../libstriezel/hash/sha256/FileSource.cpp
    ../../libstriezel/hash/sha256/FileSourceUtility.cpp
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
    HandlerGeneric.hpp
    HandlerGzip.cpp
    ScanStrategy.cpp
    ScanStrategyDefault.cpp
    ScanStrategyDirectScan.cpp
    ScanStrategyNoRescan.cpp
    ScanStrategyScanAndForget.cpp
    Strategies.cpp
    summary.cpp
    ZipHandler.cpp
    main.cpp)

if (CMAKE_COMPILER_IS_GNUCC)
    add_definitions (-Wall -O2 -fexceptions)
endif (CMAKE_COMPILER_IS_GNUCC)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set( CMAKE_EXE_LINKER_FLAGS  "${CMAKE_EXE_LINKER_FLAGS} -s" )

add_executable(scan-tool ${scan-tool_sources})

# find cURL library
find_package (CURL)
if (CURL_FOUND)
  include_directories(${CURL_INCLUDE_DIRS})
  target_link_libraries (scan-tool ${CURL_LIBRARIES})
else ()
  message ( FATAL_ERROR "cURL was not found!" )
endif (CURL_FOUND)

# find libzip
set(libzip_DIR "../../cmake/" )
find_package (libzip)
if (LIBZIP_FOUND)
  include_directories(${LIBZIP_INCLUDE_DIRS})
  target_link_libraries (scan-tool ${LIBZIP_LIBRARIES})
else ()
  message ( FATAL_ERROR "libzip was not found!" )
endif (LIBZIP_FOUND)

# find libarchive
find_package (LibArchive)
if (LibArchive_FOUND)
  include_directories(${LibArchive_INCLUDE_DIRS})
  target_link_libraries (scan-tool ${LibArchive_LIBRARIES})
else ()
  message ( FATAL_ERROR "libarchive was not found!" )
endif (LibArchive_FOUND)

# find libz
find_package (ZLIB)
if (ZLIB_FOUND)
  include_directories(${ZLIB_INCLUDE_DIRS})
  target_link_libraries (scan-tool ${ZLIB_LIBRARIES})
else ()
  message ( FATAL_ERROR "zlib was not found!" )
endif (ZLIB_FOUND)

# find libunshield
set(libunshield_DIR "../../libstriezel/cmake/" )
find_package (libunshield)
if (LIBUNSHIELD_FOUND)
  include_directories(${LIBUNSHIELD_INCLUDE_DIRS})
  target_link_libraries (scan-tool ${LIBUNSHIELD_LIBRARIES})
else ()
  message ( FATAL_ERROR "libunshield was not found!" )
endif (LIBUNSHIELD_FOUND)
