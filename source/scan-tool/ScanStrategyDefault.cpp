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

#include "ScanStrategyDefault.hpp"
#include <iostream>
#include "../../libstriezel/filesystem/file.hpp"
#include "../../libstriezel/hash/sha256/FileSourceUtility.hpp"
#include "../../libstriezel/hash/sha256/sha256.hpp"
#include "../ReturnCodes.hpp"

namespace scantool
{

namespace virustotal
{

ScanStrategyDefault::ScanStrategyDefault()
: ScanStrategy()
{
  //empty
}

int ScanStrategyDefault::scan(ScannerV2& scanVT, const std::string& fileName,
              CacheManagerV2& cacheMgr, const std::string& requestCacheDirVT, const bool useRequestCache,
              const bool silent, const int maybeLimit, const int maxAgeInDays,
              const std::chrono::time_point<std::chrono::system_clock> ageLimit,
              std::map<std::string, ScannerV2::Report>& mapHashToReport,
              std::map<std::string, std::string>& mapFileToHash,
              std::unordered_map<std::string, std::string>& queued_scans,
              std::chrono::time_point<std::chrono::steady_clock>& lastQueuedScanTime,
              std::vector<std::pair<std::string, int64_t> >& largeFiles)
{
  //apply any handlers
  const int handlerCode = applyHandlers(scanVT, fileName, cacheMgr, requestCacheDirVT,
      useRequestCache, silent, maybeLimit, maxAgeInDays, ageLimit, mapHashToReport,
      mapFileToHash, queued_scans, lastQueuedScanTime, largeFiles);
  if (handlerCode != 0)
    return handlerCode;
  //go on with normal strategy
  const SHA256::MessageDigest fileHash = SHA256::computeFromFile(fileName);
  if (fileHash.isNull())
  {
    std::cout << "Error: Could not determine SHA256 hash of " << fileName
              << "!" << std::endl;
    return scantool::rcFileError;
  } //if no hash
  const std::string hashString = fileHash.toHexString();
  scantool::virustotal::ScannerV2::Report report;
  if (scanVT.getReport(hashString, report, useRequestCache, requestCacheDirVT))
  {
    if (report.successfulRetrieval())
    {
      //got report
      if (report.positives == 0)
      {
        if (!silent)
          std::cout << fileName << " OK" << std::endl;
      }
      else if (report.positives <= maybeLimit)
      {
        if (!silent)
          std::clog << fileName << " might be infected, got "
                    << report.positives << " positives." << std::endl;
        //add file to list of infected files
        mapFileToHash[fileName] = hashString;
        mapHashToReport[hashString] = report;
      }
      else if (report.positives > maybeLimit)
      {
        if (!silent)
          std::clog << fileName << " is INFECTED, got " << report.positives
                    << " positives." << std::endl;
        //add file to list of infected files
        mapFileToHash[fileName] = hashString;
        mapHashToReport[hashString] = report;
      } //else (file is probably infected)

      //check, if rescan is required because of age
      if (report.hasTime_t()
          && (std::chrono::system_clock::from_time_t(report.scan_date_t) < ageLimit))
      {
        std::string scan_id = "";
        if (!scanVT.rescan(hashString, scan_id))
        {
          std::cerr << "Error: Could not initiate rescan for file " << fileName
                    << "!" << std::endl;
          return scantool::rcScanError;
        }
        if (!silent)
          std::clog << "Info: " << fileName << " was queued for re-scan, because "
                    << "report is from " << report.scan_date
                    << " and thus it is older than " << maxAgeInDays
                    << " days. Scan ID for retrieval is " << scan_id
                    << "." << std::endl;
        /* Delete a possibly existing cached entry for that file, because
           it is now potentially outdated, as soon as the next request for
           that report is performed. */
        cacheMgr.deleteCachedElement(hashString);
      } //if rescan because of old report
    } //if file was in report database
    else if (report.notFound())
    {
      //no data present for file
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
        //delete previous report, because it contains no relevant data
        cacheMgr.deleteCachedElement(hashString);
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
    } //else if report not found
    else
    {
      //unexpected response code
      std::cerr << "Error: Got unexpected response code ("<<report.response_code
                << ") for report of file " << fileName << "." << std::endl;
      return scantool::rcScanError;
    }
  }
  else
  {
    if (!silent)
      std::clog << "Warning: Could not get report for file " << fileName << "!" << std::endl;
  }
  //return zero to indicate that file was handled successfully
  return 0;
}

} //namespace

} //namespace
