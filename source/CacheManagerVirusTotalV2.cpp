/*
 -------------------------------------------------------------------------------
    This file is part of scan-tool.
    Copyright (C) 2015  Thoronador

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
