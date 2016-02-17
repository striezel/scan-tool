/*
 -------------------------------------------------------------------------------
    This file is part of scan-tool.
    Copyright (C) 2015, 2016  Thoronador

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
 -------------------------------------------------------------------------------
*/

#include "../../libthoro/common/StringUtils.h"
#include "../../libthoro/filesystem/directory.hpp"
#include "../../libthoro/filesystem/file.hpp"
#include "../../libthoro/hash/sha256/sha256.hpp"
#include "CacheManagerV2.hpp"
#include "ReportV2.hpp"

namespace scantool
{

namespace virustotal
{

CacheManagerV2::CacheManagerV2(const std::string& cacheRoot)
: m_CacheRoot(cacheRoot)
{
  /* Nobody likes accidental directory traversals via malformed input. */
  if (m_CacheRoot.find(std::string("..") + libthoro::filesystem::pathDelimiter)
      != std::string::npos)
    m_CacheRoot.clear();
  // Use default path instead of empty string.
  if (m_CacheRoot.empty())
    m_CacheRoot = getDefaultCacheDirectory();
}

std::string CacheManagerV2::getDefaultCacheDirectory()
{
  std::string homeDirectory;
  if (!libthoro::filesystem::directory::getHome(homeDirectory))
  {
    #if defined(__linux__) || defined(linux)
    //use /tmp as replacement for home directory
    homeDirectory = "/tmp/";
    #elif defined(_WIN32)
    // Use C:\Windows\Temp as temporary replacement on Windows systems.
    homeDirectory := "C:\\Windows\\Temp\\";
    #else
      #error Unknown operating system!
    #endif
  }
  // cache directory is ~/.scan-tool/vt-cache/
  return (libthoro::filesystem::slashify(homeDirectory) + ".scan-tool"
          + libthoro::filesystem::pathDelimiter + "vt-cache");
}

const std::string& CacheManagerV2::getCacheDirectory() const
{
  return m_CacheRoot;
}

bool CacheManagerV2::createCacheDirectory()
{
  if (!libthoro::filesystem::directory::exists(m_CacheRoot))
  {
    //try to create the directory (and its parent directories, if missing)
    if (!libthoro::filesystem::directory::createRecursive(m_CacheRoot))
      return false;
  } //if cache directory does not exist
  const std::vector<char> subChars = { '0', '1', '2', '3', '4', '5', '6', '7',
                                       '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
  //create sub directories
  for (const auto & charOne : subChars)
  {
    for (const auto & charTwo : subChars)
    {
      const auto subDirectory = m_CacheRoot + libthoro::filesystem::pathDelimiter
                              + std::string(1, charOne) + std::string(1, charTwo);
      if (!libthoro::filesystem::directory::exists(subDirectory))
      {
        //try to create the directory
        if (!libthoro::filesystem::directory::create(subDirectory))
          return false;
      } //if cache sub directory does not exist
    } //for (inner)
  } //for (outer)
  //Cache directory already exists. We've got nothing more to do here.
  return true;
}

std::string CacheManagerV2::getPathForCachedElement(const std::string& resourceID) const
{
  return getPathForCachedElement(resourceID, m_CacheRoot);
}

std::string CacheManagerV2::getPathForCachedElement(const std::string& resourceID, const std::string& cacheRoot)
{
  /* Only SHA256 hashes are valid resource identifiers. Hashes with timestamp,
     e.g. "4beb421019d7d2177d46d08227103a930c6ae35b2eff6d17217734ed0c8ee96f-1450132861",
     are valid for VirusTotal's API, but they are not a valid ID for the cache,
     because the cache only stores one report per hash, i.e. without timestamp.
  */
  if (!SHA256::isValidHash(resourceID))
    return std::string("");
  /* Nobody likes accidental directory traversals via malformed input. */
  if (cacheRoot.find(std::string("..") + libthoro::filesystem::pathDelimiter)
      != std::string::npos)
    return std::string("");

  /* General path for a cached element is
     ~/.scan-tool/vt-cache/<first two characters of resource ID>/<resourceID>.json,
     e.g. ~/.scan-tool/vt-cache/ab/ab16da937795be615ce4bef4e4d5337e782a7e982ff13cea1ece3e89d914678f.json
     for the resource "ab16da937795be615ce4bef4e4d5337e782a7e982ff13cea1ece3e89d914678f".
  */
  return libthoro::filesystem::slashify(cacheRoot) + resourceID.substr(0, 2)
       + libthoro::filesystem::pathDelimiter + resourceID + ".json";
}

bool CacheManagerV2::deleteCachedElement(const std::string& resourceID)
{
  return deleteCachedElement(resourceID, m_CacheRoot);
}

bool CacheManagerV2::deleteCachedElement(const std::string& resourceID, const std::string& cacheRoot)
{
  const std::string cachedFile = getPathForCachedElement(resourceID, cacheRoot);
  //An empty string indicates invalid resource ID.
  if (cachedFile.empty())
    return false;

  if (!libthoro::filesystem::file::exists(cachedFile))
    return true;
  //File exists, delete it.
  return libthoro::filesystem::file::remove(cachedFile);
}

uint_least32_t CacheManagerV2::checkIntegrity(const bool deleteCorrupted, const bool deleteUnknown) const
{
  // Does the cache exist? If not, exit.
  if (!libthoro::filesystem::directory::exists(m_CacheRoot))
    return 0;

  uint_least32_t corrupted = 0;

  const std::vector<char> subChars = { '0', '1', '2', '3', '4', '5', '6', '7',
                                       '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
  for (const auto firstChar : subChars)
  {
    for (const auto secondChar : subChars)
    {
      const std::string currentSubDirectory = libthoro::filesystem::slashify(m_CacheRoot)
                      + std::string(1, firstChar) + std::string(1, secondChar);
      if (libthoro::filesystem::directory::exists(currentSubDirectory))
      {
        const auto files = libthoro::filesystem::getDirectoryFileList(currentSubDirectory);
        #ifdef SCAN_TOOL_DEBUG
        std::clog << "Found " << files.size() << " files in "
                  << currentSubDirectory << "." << std::endl;
        #endif // SCAN_TOOL_DEBUG
        for (auto const & file : files)
        {
          if (//entry must not be a directory and file name has to end with ".json"
              !file.isDirectory && stringEndsWith(file.fileName, ".json")
              // first 64 characters must form a valid SHA256 hash
              && SHA256::isValidHash(file.fileName.substr(0, 64))
              // ... and total length has to be 69 characters
              // (that is: 64 chars from hash, 5 chars for extension ".json")
              && file.fileName.size() == 69)
          {
            const auto fileName = currentSubDirectory
                  + libthoro::filesystem::pathDelimiter + file.fileName;
            const auto fileSize = libthoro::filesystem::file::getSize64(fileName);
            //check, if file is way too large for a proper cache file
            if (fileSize >= 1024*1024*2)
            {
              //Several kilobytes are alright, but not megabytes.
              ++corrupted;
              std::clog << "Info: JSON file " << fileName
                        << " is too large for a cached response!" << std::endl;
              if (deleteCorrupted)
                libthoro::filesystem::file::remove(fileName);
            } //if file is too large
            else
            {
              std::string content = "";
              if (libthoro::filesystem::file::readIntoString(fileName, content))
              {
                Json::Value root; // will contain the root value after parsing.
                Json::Reader jsonReader;
                const bool success = jsonReader.parse(content, root, false);
                if (!success)
                {
                  std::clog << "Info: JSON data from " << fileName << " could not be parsed!" << std::endl;
                  ++corrupted;
                  if (deleteCorrupted)
                    libthoro::filesystem::file::remove(fileName);
                } //if parsing failed
                else
                {
                  ReportV2 report;
                  if (report.fromJSONRoot(root))
                  {
                    //response code zero means: file not known to VirusTotal
                    if (deleteUnknown && (report.response_code == 0))
                    {
                      std::cout << "Info: " << fileName << " contains no relevant data." << std::endl;
                      libthoro::filesystem::file::remove(fileName);
                    } //if report can be deleted
                    //check SHA256 hash
                    else if ((report.sha256 != file.fileName.substr(0, 64))
                             or (firstChar != file.fileName[0])
                             or (secondChar != file.fileName[1]))
                    {
                      std::cout << "Info: SHA256 hash of " << file.fileName
                                << " is " << report.sha256 << " and does not "
                                << " match file name." << std::endl;
                      ++corrupted;
                      if (deleteCorrupted)
                        libthoro::filesystem::file::remove(fileName);
                    } //else if SHA256 does not match
                  } //if report could be filled from JSON
                  else
                  {
                    //JSON data is probably not a report
                    ++corrupted;
                    if (deleteCorrupted)
                      libthoro::filesystem::file::remove(fileName);
                  }
                } //else (JSON parsing was successful)
              } //if file was read
              else
              {
                std::cout << "Error: Could not read file " << fileName << "!"
                          << std::endl;
              }
            } //else (file size might be OK)
          } //if JSON file with correct name
          else
          {
            if (!file.isDirectory)
            {
              std::cout << "Info: File " << file.fileName << " has incorrect naming scheme." << std::endl;
            }
          } //else (incorrect naming)
        } //for (inner)
      } //if subdirectory exists
    } //for (2nd char)
  } //for (1st char)
  return corrupted;
}

uint_least32_t CacheManagerV2::transitionOneTo256()
{
  // Does the cache exist? If not, exit.
  if (!libthoro::filesystem::directory::exists(m_CacheRoot))
    return 0;

  uint_least32_t moved_files = 0;

  const auto files = libthoro::filesystem::getDirectoryFileList(
                           libthoro::filesystem::unslashify(m_CacheRoot));
  #ifdef SCAN_TOOL_DEBUG
  std::clog << "Found " << files.size() << " files in "
            << libthoro::filesystem::unslashify(m_CacheRoot) << "." << std::endl;
  #endif // SCAN_TOOL_DEBUG
  for (auto const & file : files)
  {
    if (//entry must not be a directory and file name has to end with ".json"
        !file.isDirectory && stringEndsWith(file.fileName, ".json")
        // first 64 characters must form a valid SHA256 hash
        && SHA256::isValidHash(file.fileName.substr(0, 64))
        // ... and total length has to be 69 characters
        // (that is: 64 chars from hash, 5 chars for extension ".json")
        && file.fileName.size() == 69)
    {
      const auto fileName = libthoro::filesystem::slashify(m_CacheRoot)
                          + file.fileName;
      const auto fileSize = libthoro::filesystem::file::getSize64(fileName);
      //check, if file is way too large for a proper cache file
      if (fileSize >= 1024*1024*2)
      {
        //Several kilobytes are alright, but not megabytes.
        std::clog << "Info: JSON file " << fileName
                  << " is too large for a cached response!" << std::endl;
        libthoro::filesystem::file::remove(fileName);
      } //if file is too large
      else
      {
        std::string content = "";
        if (libthoro::filesystem::file::readIntoString(fileName, content))
        {
          Json::Value root; // will contain the root value after parsing.
          Json::Reader jsonReader;
          const bool success = jsonReader.parse(content, root, false);
          if (!success)
          {
            std::clog << "Info: JSON data from " << fileName << " could not be parsed!" << std::endl;
            libthoro::filesystem::file::remove(fileName);
          } //if parsing failed
          else
          {
            ReportV2 report;
            if (report.fromJSONRoot(root))
            {
              //response code zero means: file not known to VirusTotal
              if (report.response_code == 0)
              {
                std::cout << "Info: " << fileName << " contains no relevant data." << std::endl;
                libthoro::filesystem::file::remove(fileName);
              } //if report can be deleted
              else
              {
                const std::string newPath = getPathForCachedElement(file.fileName.substr(0, 64));
                if (libthoro::filesystem::file::rename(fileName, newPath))
                  ++moved_files;
                else
                {
                  std::cout << "Error: Could not move file " << fileName
                            << " to " << newPath << "!" << std::endl;
                }
              } //else (file contains relevant data)
            } //if report could be filled from JSON data
            else
            {
              //JSON data is probably not a report
              libthoro::filesystem::file::remove(fileName);
            }
          } //else (JSON parsing was successful)
        } //if file was read
        else
        {
          std::cout << "Error: Could not read file " << fileName << "!" << std::endl;
        }
      } //else (file size might be OK)
    } //if JSON file with correct name
    else
    {
      if (!file.isDirectory)
      {
        std::cout << "Info: File " << file.fileName << " has incorrect naming scheme." << std::endl;
      }
    }
  } //for
  return moved_files;
}

uint_least32_t CacheManagerV2::transition16To256()
{
  // Does the cache exist? If not, exit.
  if (!libthoro::filesystem::directory::exists(m_CacheRoot))
    return 0;

  uint_least32_t moved_files = 0;

  const std::vector<std::string> sub = { std::string("0"), "1", "2", "3", "4",
                        "5", "6", "7", "8", "9", "a", "b", "c", "d", "e", "f"};
  for (const auto & d : sub)
  {
    const std::string currentSubDirectory =
        libthoro::filesystem::slashify(m_CacheRoot) + d;
    if (libthoro::filesystem::directory::exists(currentSubDirectory))
    {
      const auto files = libthoro::filesystem::getDirectoryFileList(currentSubDirectory);
      #ifdef SCAN_TOOL_DEBUG
      std::clog << "Found " << files.size() << " files in "
                << currentSubDirectory << "." << std::endl;
      #endif // SCAN_TOOL_DEBUG

      for (auto const & file : files)
      {
        if (//entry must not be a directory and file name has to end with ".json"
            !file.isDirectory && stringEndsWith(file.fileName, ".json")
            // first 64 characters must form a valid SHA256 hash
            && SHA256::isValidHash(file.fileName.substr(0, 64))
            // ... and total length has to be 69 characters
            // (that is: 64 chars from hash, 5 chars for extension ".json")
            && file.fileName.size() == 69)
        {
          const auto fileName = currentSubDirectory
                + libthoro::filesystem::pathDelimiter + file.fileName;
          const auto fileSize = libthoro::filesystem::file::getSize64(fileName);
          //check, if file is way too large for a proper cache file
          if (fileSize >= 1024*1024*2)
          {
            //Several kilobytes are alright, but not megabytes.
            std::clog << "Info: JSON file " << fileName
                      << " is too large for a cached response!" << std::endl;
            libthoro::filesystem::file::remove(fileName);
          } //if file is too large
          else
          {
            std::string content = "";
            if (libthoro::filesystem::file::readIntoString(fileName, content))
            {
              Json::Value root; // will contain the root value after parsing.
              Json::Reader jsonReader;
              const bool success = jsonReader.parse(content, root, false);
              if (!success)
              {
                std::clog << "Info: JSON data from " << fileName << " could not be parsed!" << std::endl;
                libthoro::filesystem::file::remove(fileName);
              } //if parsing failed
              else
              {
                ReportV2 report;
                if (report.fromJSONRoot(root))
                {
                  //response code zero means: file not known to VirusTotal
                  if (report.response_code == 0)
                  {
                    std::cout << "Info: " << fileName << " contains no relevant data." << std::endl;
                    libthoro::filesystem::file::remove(fileName);
                  } //if report can be deleted
                  else
                  {
                    const std::string newPath = getPathForCachedElement(file.fileName.substr(0, 64));
                    if (libthoro::filesystem::file::rename(fileName, newPath))
                      ++moved_files;
                    else
                    {
                      std::cout << "Error: Could not move file " << fileName
                                << " to " << newPath << "!" << std::endl;
                    }
                  } //else (file contains relevant data)
                } //if report could be filled from JSON data
                else
                {
                  //JSON data is probably not a report
                  libthoro::filesystem::file::remove(fileName);
                }
              } //else (JSON parsing was successful)
            } //if file was read
            else
            {
              std::cout << "Error: Could not read file " << fileName << "!" << std::endl;
            }
          } //else (file size might be OK)
        } //if JSON file with correct name
        else
        {
          if (!file.isDirectory)
          {
            std::cout << "Info: File " << file.fileName << " has incorrect naming scheme." << std::endl;
          }
        } //else
      } //for (inner)
      //try to remove the directory, because it should be empty / unused by now
      if (!libthoro::filesystem::directory::remove(currentSubDirectory))
      {
        std::cout << "Warning: Could not remove directory " << currentSubDirectory
                  << ". Maybe this directory is not empty yet or you do not "
                  << "have the required permission to remove it." << std::endl;
      }
    } //if subdirectory exists
  } //for
  return moved_files;
}

} //namespace

} //namespace
