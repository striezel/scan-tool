# Might work with earlier versions, too, but it's only tested with 2.8.9.
cmake_minimum_required (VERSION 2.8)

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
add_definitions(-std=c++0x)

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

# find jsoncpp library
set(LibJsonCpp_DIR "../../cmake/" )
find_package (LibJsonCpp)
if (LIBJSONCPP_FOUND)
  include_directories(${LIBJSONCPP_INCLUDE_DIRS})
  target_link_libraries (scan-tool ${LIBJSONCPP_LIBRARIES})
else ()
  message ( FATAL_ERROR "libjsoncpp was not found!" )
endif (LIBJSONCPP_FOUND)

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
set(libarchive_DIR "../../libstriezel/cmake/" )
find_package (libarchive)
if (LIBARCHIVE_FOUND)
  include_directories(${LIBARCHIVE_INCLUDE_DIRS})
  target_link_libraries (scan-tool ${LIBARCHIVE_LIBRARIES})
else ()
  message ( FATAL_ERROR "libarchive was not found!" )
endif (LIBARCHIVE_FOUND)

# find libz
find_package (ZLIB)
if (ZLIB_FOUND)
  include_directories(${ZLIB_INCLUDE_DIRS})
  target_link_libraries (scan-tool ${ZLIB_LIBRARIES})
else ()
  message ( FATAL_ERROR "zlib was not found!" )
endif (ZLIB_FOUND)
