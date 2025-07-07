/*
 -------------------------------------------------------------------------------
    This file is part of scan-tool.
    Copyright (C) 2016, 2019, 2025  Dirk Stolle

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

#include "IterationOperationUpdate.hpp"
#include <iostream>
#include "../../libstriezel/filesystem/file.hpp"

namespace scantool::virustotal
{

IterationOperationUpdate::IterationOperationUpdate(const std::string& apikey, const bool silent, const std::chrono::system_clock::time_point& ageLimit, const std::string& cacheDir)
: IterationOperation(),
  scannerVT(ScannerV2(apikey, true, silent)),
  m_silent(silent),
  m_ageLimit(ageLimit),
  m_cacheMgr(CacheManagerV2(cacheDir)),
  m_pendingRescans(std::vector<std::string>())
{
}

void IterationOperationUpdate::process(const std::string& fileName)
{
  // check, if file is reasonable for a proper cache file
  const auto fileSize = libstriezel::filesystem::file::getSize64(fileName);
  if ((fileSize >= 1024 * 1024 * 2) || (fileSize <= 0))
    return;

  std::string content;
  if (!libstriezel::filesystem::file::readIntoString(fileName, content))
    return;

  ReportV2 report;
  if (!report.fromJsonString(content))
    return;

  //check if update is required
  if (report.hasTime_t()
      && (std::chrono::system_clock::from_time_t(report.scan_date_t) < m_ageLimit))
  {
    const std::string currentSHA256 = report.sha256;
    // get current report
    if (scannerVT.getReport(report.sha256, report, false, m_cacheMgr.getCacheDirectory()))
    {
      if (report.successfulRetrieval())
      {
        // Rescan required, because current report is still too old?
        if(report.hasTime_t()
           && (std::chrono::system_clock::from_time_t(report.scan_date_t) < m_ageLimit))
        {
          std::string scan_id = "";
          if (scannerVT.rescan(currentSHA256, scan_id))
          {
            // add to list for later retrieval
            m_pendingRescans.push_back(currentSHA256);
            if (!m_silent)
              std::cout << "Rescan for resource " << currentSHA256
                        << " was initiated." << std::endl;
          }
          else if (!m_silent)
          {
            std::cout << "Warning: Could not initiate rescan for resource "
                      << currentSHA256 << "!" << std::endl;
          }
        } // if rescan required
        else
        {
          // current report is newer than age limit
          if (!m_silent)
            std::cout << "Cached file for resource " << currentSHA256
                      << " was updated." << std::endl;
        } // else
      } // if successful
    } // if getReport()
    else if (!m_silent)
    {
      std::cout << "Warning: Could not get current report for resource "
               << currentSHA256 << "!" << std::endl;
    }
  } // if scan_date is present
}

const std::vector<std::string>& IterationOperationUpdate::pendingRescans() const
{
  return m_pendingRescans;
}

ScannerV2& IterationOperationUpdate::scanner()
{
  return scannerVT;
}

} // namespace
