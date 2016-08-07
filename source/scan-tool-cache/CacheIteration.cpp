/*
 -------------------------------------------------------------------------------
    This file is part of scan-tool.
    Copyright (C) 2016  Dirk Stolle

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

#include "CacheIteration.hpp"
#include <iostream>
#include "../../libstriezel/filesystem/directory.hpp"
#include "../../libstriezel/filesystem/file.hpp"
#include "../virustotal/CacheManagerV2.hpp"

namespace scantool
{

namespace virustotal
{

CacheIteration::CacheIteration()
{
  //empty
}

bool CacheIteration::iterate(const std::string& cacheDir, IterationOperation& op)
{
  if (cacheDir.empty())
    return false;

  //No cache directory? Nothing to do.
  if (!libstriezel::filesystem::directory::exists(cacheDir))
    return true;

  /* Note:
     The current iteration via loops should later be replaced by
     std::experimental::filesystem::directory_iterator, as soon as it is
     supported by most relevant compilers.
  */

  const std::vector<char> subChars = { '0', '1', '2', '3', '4', '5', '6', '7',
                                       '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
  for (const auto firstChar : subChars)
  {
    for (const auto secondChar : subChars)
    {
      const std::string currentSubDirectory = libstriezel::filesystem::slashify(cacheDir)
                      + std::string(1, firstChar) + std::string(1, secondChar);
      if (libstriezel::filesystem::directory::exists(currentSubDirectory))
      {
        const auto files = libstriezel::filesystem::getDirectoryFileList(currentSubDirectory);
        #ifdef SCAN_TOOL_DEBUG
        std::clog << "Debug: Found " << files.size() << " files in "
                  << currentSubDirectory << "." << std::endl;
        #endif // SCAN_TOOL_DEBUG
        for (auto const & file : files)
        {
          if (!file.isDirectory && CacheManagerV2::isCachedElementName(file.fileName))
          {
            //process file
            op.process(currentSubDirectory + libstriezel::filesystem::pathDelimiter + file.fileName);
          } //if file is a cached report
        } //for
      } //if subdirectory exists
    } //for (second char)
  } //for (first char)
  return true;
}

} //namespace

} //namespace
