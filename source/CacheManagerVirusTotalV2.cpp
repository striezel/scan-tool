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

#include "CacheManagerVirusTotalV2.hpp"
#include "ScannerVirusTotalV2.hpp"
#include "../libthoro/common/StringUtils.h"
#include "../libthoro/filesystem/DirectoryFunctions.hpp"
#include "../libthoro/filesystem/FileFunctions.hpp"
#include "../libthoro/hash/sha256/sha256.hpp"

CacheManagerVirusTotalV2::CacheManagerVirusTotalV2(const std::string& cacheRoot)
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

std::string CacheManagerVirusTotalV2::getDefaultCacheDirectory()
{
  std::string homeDirectory;
  if (!libthoro::filesystem::Directory::getHome(homeDirectory))
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

const std::string& CacheManagerVirusTotalV2::getCacheDirectory() const
{
  return m_CacheRoot;
}

bool CacheManagerVirusTotalV2::createCacheDirectory()
{
  if (!libthoro::filesystem::Directory::exists(m_CacheRoot))
  {
    //try to create the directory (and its parent directories, if missing)
    if (!libthoro::filesystem::Directory::createRecursive(m_CacheRoot))
      return false;
  } //if cache directory does not exist
  const std::vector<std::string> sub = { std::string("0"), "1", "2", "3", "4",
                        "5", "6", "7", "8", "9", "a", "b", "c", "d", "e", "f"};

  //create sub directories
  for (const auto & d : sub)
  {
    const auto subDirectory = m_CacheRoot + libthoro::filesystem::pathDelimiter + d;
    if (!libthoro::filesystem::Directory::exists(subDirectory))
    {
      //try to create the directory
      if (!libthoro::filesystem::Directory::create(subDirectory))
        return false;
    } //if cache sub directory does not exist
  } //for
  //Cache directory already exists. We've got nothing more to do here.
  return true;
}

std::string CacheManagerVirusTotalV2::getPathForCachedElement(const std::string& resourceID) const
{
  return getPathForCachedElement(resourceID, m_CacheRoot);
}

std::string CacheManagerVirusTotalV2::getPathForCachedElement(const std::string& resourceID, const std::string& cacheRoot)
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
     ~/.scan-tool/vt-cache/<first character of resource ID>/<resourceID>.json,
     e.g. ~/.scan-tool/vt-cache/a/ab16da937795be615ce4bef4e4d5337e782a7e982ff13cea1ece3e89d914678f.json
     for the resource "ab16da937795be615ce4bef4e4d5337e782a7e982ff13cea1ece3e89d914678f".
  */
  return libthoro::filesystem::slashify(cacheRoot) + resourceID.at(0)
       + libthoro::filesystem::pathDelimiter + resourceID + ".json";
}

bool CacheManagerVirusTotalV2::deleteCachedElement(const std::string& resourceID)
{
  return deleteCachedElement(resourceID, m_CacheRoot);
}

bool CacheManagerVirusTotalV2::deleteCachedElement(const std::string& resourceID, const std::string& cacheRoot)
{
  const std::string cachedFile = getPathForCachedElement(resourceID, cacheRoot);
  //An empty string indicates invalid resource ID.
  if (cachedFile.empty())
    return false;

  if (!libthoro::filesystem::File::exists(cachedFile))
    return true;
  //File exists, delete it.
  return libthoro::filesystem::File::remove(cachedFile);
}

uint_least32_t CacheManagerVirusTotalV2::checkIntegrity(const bool deleteCorrupted, const bool deleteUnknown) const
{
  // Does the cache exist? If not, exit.
  if (!libthoro::filesystem::Directory::exists(m_CacheRoot))
    return 0;

  uint_least32_t corrupted = 0;

  const std::vector<std::string> sub = { std::string("0"), "1", "2", "3", "4",
                        "5", "6", "7", "8", "9", "a", "b", "c", "d", "e", "f"};
  for (const auto & d : sub)
  {
    const auto files = libthoro::filesystem::getDirectoryFileList(
                           libthoro::filesystem::slashify(m_CacheRoot) + d);
    #ifdef SCAN_TOOL_DEBUG
    std::clog << "Found " << files.size() << " files in "
              << libthoro::filesystem::slashify(m_CacheRoot) + d << "." << std::endl;
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
        const auto fileName = libthoro::filesystem::slashify(m_CacheRoot) + d
              + libthoro::filesystem::pathDelimiter + file.fileName;
        const auto fileSize = libthoro::filesystem::File::getSize64(fileName);
        //check, if file is way too large for a proper cache file
        if (fileSize >= 1024*1024*2)
        {
          //Several kilobytes are alright, but not megabytes.
          ++corrupted;
          std::clog << "Info: JSON file " << fileName
                    << " is too large for a cached response!" << std::endl;
          if (deleteCorrupted)
            libthoro::filesystem::File::remove(fileName);
        } //if file is too large
        else
        {
          std::string content = "";
          if (libthoro::filesystem::File::readIntoString(fileName, content))
          {
            Json::Value root; // will contain the root value after parsing.
            Json::Reader jsonReader;
            const bool success = jsonReader.parse(content, root, false);
            if (!success)
            {
              std::clog << "Info: JSON data from " << fileName << " could not be parsed!" << std::endl;
              ++corrupted;
              if (deleteCorrupted)
                libthoro::filesystem::File::remove(fileName);
            } //if parsing failed
            else
            {
              if (deleteUnknown)
              {
                const auto report = reportFromJSONRoot(root);
                //response code zero means: file not known to VirusTotal
                if ((report.response_code == 0)
                    && report.verbose_msg == "The requested resource is not among the finished, queued or pending scans")
                {
                  std::cout << "Info: " << fileName << " contains no relevant data." << std::endl;
                  libthoro::filesystem::File::remove(fileName);
                } //if report can be deleted
              } //if cached files of unknown resources shall be deleted
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
    } //for (inner)
  } //for
  return corrupted;
}
