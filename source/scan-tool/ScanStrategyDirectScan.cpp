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

#include "ScanStrategyDirectScan.hpp"
#include <iostream>
#include "../../libstriezel/filesystem/file.hpp"
#include "../../libstriezel/hash/sha256/FileSourceUtility.hpp"
#include "../../libstriezel/hash/sha256/sha256.hpp"
#include "../ReturnCodes.hpp"

namespace scantool
{

namespace virustotal
{

ScanStrategyDirectScan::ScanStrategyDirectScan()
: ScanStrategy()
{
  //empty
}

int ScanStrategyDirectScan::scan(ScannerV2& scanVT, const std::string& fileName,
              CacheManagerV2& cacheMgr, const std::string& requestCacheDirVT, const bool useRequestCache,
              const bool silent, const int maybeLimit, const int maxAgeInDays,
              const std::chrono::time_point<std::chrono::system_clock> ageLimit,
              std::map<std::string, ScannerV2::Report>& mapHashToReport,
              std::map<std::string, std::string>& mapFileToHash,
              std::unordered_map<std::string, std::string>& queued_scans,
              std::chrono::time_point<std::chrono::steady_clock>& lastQueuedScanTime,
              std::vector<std::pair<std::string, int64_t> >& largeFiles,
              std::set<std::string>::size_type& processedFiles,
              std::set<std::string>::size_type& totalFiles)
{
  //apply any handlers
  const int handlerCode = applyHandlers(scanVT, fileName, cacheMgr, requestCacheDirVT,
      useRequestCache, silent, maybeLimit, maxAgeInDays, ageLimit, mapHashToReport,
      mapFileToHash, queued_scans, lastQueuedScanTime, largeFiles,
      processedFiles, totalFiles);
  if (handlerCode != 0)
    return handlerCode;
  //go on with normal strategy
  /* Note:
     This function only performs the scan, it does not get the scan report.
     Scan reports will be retrieved afterwards by the main program, because the
     scans have been added to the list of queued scans.
   */
  const int64_t fileSize = libstriezel::filesystem::file::getSize64(fileName);
  if ((fileSize <= scanVT.maxScanSize()) && (fileSize >= 0))
  {
    std::string scan_id = "";
    if (!scanVT.scan(fileName, scan_id))
    {
      std::cerr << "Error: Could not submit file " << fileName
                  << " for scanning." << std::endl;
        return scantool::rcScanError;
    }
    //remember time of last scan request
    lastQueuedScanTime = std::chrono::steady_clock::now();
    //add scan ID to list of queued scans for later retrieval
    queued_scans[scan_id] = fileName;
    if (!silent)
      std::clog << "Info: File " << fileName << " was queued for scan. Scan ID is "
                << scan_id << "." << std::endl;
  } //if file size is below limit
  else
  {
    //File is too large.
    if (!silent)
      std::cout << "Warning: File " << fileName << " is "
                << libstriezel::filesystem::getSizeString(fileSize)
                << " and exceeds maximum file size for scan! "
                << "File will be skipped." << std::endl;
    //save file name + size for later
    largeFiles.push_back(std::pair<std::string, int64_t>(fileName, fileSize));
  } //else (file too large)
  //return zero to indicate that file was handled successfully
  return 0;
}

} //namespace

} //namespace
