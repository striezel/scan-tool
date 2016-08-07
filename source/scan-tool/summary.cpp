/*
 -------------------------------------------------------------------------------
    This file is part of scan-tool.
    Copyright (C) 2015, 2016  Dirk Stolle

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

#include "summary.hpp"
#include <algorithm>
#include <iostream>
#include "../../libstriezel/filesystem/file.hpp"

namespace scantool
{

namespace virustotal
{

void showSummary(const std::map<std::string, std::string>& mapFileToHash,
                 std::map<std::string, ScannerV2::Report>& mapHashToReport,
                 const std::unordered_map<std::string, std::string>& queued_scans,
                 std::vector<std::pair<std::string, int64_t> >& largeFiles)
{
  //list possibly infected files
  if (!mapFileToHash.empty())
  {
    std::clog << "Possibly infected files: " << mapFileToHash.size() << std::endl;
    for (const auto& i : mapFileToHash)
    {
      std::clog << i.first << " may be infected!" << std::endl;
      const ScannerV2::Report& repVT = mapHashToReport[i.second];
      std::clog << repVT.positives << " out of " << repVT.total
                << " scanners detected a threat";
      if (!repVT.scan_date.empty())
        std::clog << " (date: " << repVT.scan_date << ")";
      std::clog << "." << std::endl;
      for (const auto& engine : repVT.scans)
      {
        if (engine->detected)
          std::clog << "    " << engine->engine << " detected " << engine->result << std::endl;
      } //for engine
      std::clog << std::endl;
    } //for i
  } //if infected files exist in map
  else
  {
    std::cout << "All of the given files seem to be OK." << std::endl;
  }

  //list files which are queued for scan but could not be scanned in time
  if (!queued_scans.empty())
  {
    std::cout << std::endl << queued_scans.size() << " file(s) could not be scanned yet."
              << std::endl;
    for(auto& qElem : queued_scans)
    {
      std::cout << "  " << qElem.second << " (scan ID " << qElem.first << ")" << std::endl;
    } //for (range-based)
  } //if there are some queued scans

  //list files which were too large to send to scan
  if (!largeFiles.empty())
  {
    //sort them by size (using a lambda expression)
    std::sort(largeFiles.begin(), largeFiles.end(),
              [](const std::pair<std::string, int64_t>& a, const std::pair<std::string, int64_t>& b)
              {
                   return a.second < b.second;
              }
             );

    //list files
    std::cout << std::endl << largeFiles.size() << " file(s) could not be "
              << "scanned because of file size restrictions for the scan API."
              << std::endl;
    for(const auto& largeElem : largeFiles)
    {
      std::cout << "  " << largeElem.first << " has a size of "
                      << libstriezel::filesystem::getSizeString(largeElem.second)
                      << " and exceeds maximum file size for scan! "
                      << "File was skipped." << std::endl;
    } //for (range-based)
  } //if there are some "large" files
}

} //namespace

} //namespace
