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

std::string CacheManagerVirusTotalV2::getCacheDirectory()
{
  std::string homeDirectory;
  if (!libthoro::filesystem::Directory::getHome(homeDirectory))
  {
    #if defined(__linux__) || defined(linux)
    //use /tmp as replacement for home directory
    homeDirectory = "/tmp/";
    #elif defined(_WIN32)
    // Use C:\Windows\Temp as temporary replacment on Windows systems.
    homeDirectory := "C:\\Windows\\Temp\\";
    #else
      #error Unknown operating system!
    #endif
  }
  // cache directory is ~/.scan-tool/vt-cache/
  return (libthoro::filesystem::slashify(homeDirectory) + ".scan-tool"
          + libthoro::filesystem::pathDelimiter + "vt-cache");
}

bool CacheManagerVirusTotalV2::createCacheDirectory()
{
  const auto cacheLocation = getCacheDirectory();
  if (!libthoro::filesystem::Directory::exists(cacheLocation))
  {
    //try to create the directory (and its parent directories, if missing)
    return libthoro::filesystem::Directory::createRecursive(cacheLocation);
  } //if cache directory does not exist
  else
  {
    //Cache directory already exists. We've got nothing more to do here.
    return true;
  }
}

bool CacheManagerVirusTotalV2::deleteCachedElement(const std::string& resourceID)
{
  /* Only SHA256 hashes are valid resource identifiers. Hashes with timestamp,
     e.g. "4beb421019d7d2177d46d08227103a930c6ae35b2eff6d17217734ed0c8ee96f-1450132861",
     are valid for VirusTotal's API, but they are not a valid ID for the cache,
     because the cache only stores one report per hash, i.e. without timestamp.
  */
  if (!SHA256::isValidHash(resourceID))
    return false;

  const std::string cachedFile = libthoro::filesystem::slashify(getCacheDirectory())
                               + resourceID + ".json";
  if (!libthoro::filesystem::File::exists(cachedFile))
    return true;
  //File exists, delete it.
  return libthoro::filesystem::File::remove(cachedFile);
}
