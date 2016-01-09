/*
 -------------------------------------------------------------------------------
    This file is part of scan-tool.
    Copyright (C) 2016  Thoronador

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

#include "cachetransition.hpp"
#include <iostream>
#include "../../libthoro/filesystem/DirectoryFunctions.hpp"
#include "../CacheManagerVirusTotalV2.hpp"
#include "../ReturnCodes.hpp"

int performTransition()
{
  CacheManagerVirusTotalV2 cacheMgr;

  if (!libthoro::filesystem::Directory::exists(cacheMgr.getCacheDirectory()))
  {
    std::cout << "Warning: The cache directory " << cacheMgr.getCacheDirectory()
              << " does not exist. Nothing to do here." << std::endl;
    return 0;
  }

  //create new cache directory structure
  if (!cacheMgr.createCacheDirectory())
  {
    std::cout << "Error: Could not create new cache directory structure!" << std::endl;
    return rcFileError;
  }

  std::cout << "Performing cache transition. This may take a while ..." << std::endl;
  //transition for very old cache files (v0.20 and v0.21)
  auto movedFiles = cacheMgr.transitionOneTo256();
  //transition for mildly old cache files (v0.22 - v0.25)
  movedFiles += cacheMgr.transition16To256();
  if (movedFiles == 0)
    std::cout << "No cached files were moved." << std::endl;
  else if (movedFiles == 1)
    std::cout << "One cached file was moved." << std::endl;
  else
    std::cout << movedFiles << " cached files were moved." << std::endl;
  return 0;
}
