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

#ifndef SCANTOOL_VT_HANDLERGENERIC_HPP
#define SCANTOOL_VT_HANDLERGENERIC_HPP

#include <functional>
#include <unordered_map>
#include "../virustotal/CacheManagerV2.hpp"
#include "../virustotal/ScannerV2.hpp"
#include "../ReturnCodes.hpp"
#include "../../libthoro/filesystem/directory.hpp"
#include "../../libthoro/filesystem/file.hpp"
#include "Handler.hpp"
#include "ScanStrategy.hpp"

namespace scantool
{

namespace virustotal
{

template<class ArcT, typename isArc>
class HandlerGeneric: public Handler
{
  public:
    /** \brief scan a given file using the implemented handling mechanism
     *
     * \param strategy  reference to the current scan strategy
     * \param scanVT    the scanner that shall be used to scan the file
     * \param fileName  name of the file that shall be scanned
     * \param cacheMgr  cache manager
     * \param requestCacheDirVT  custom directory of the request cache
     * \param useRequestCache    whether or not the request cache shall be used
     * \param silent        silence flag
     * \param maybeLimit    limit for "maybe infected"; higher count means infected
     * \param maxAgeInDays  maximum age of scan reports in days without requesting rescan
     * \param ageLimit      time point for rescans (older reports trigger rescans)
     * \param mapHashToReport  maps SHA256 hashes to corresponding report; key = SHA256 hash, value = scan report
     * \param mapFileToHash    maps filename to hash; key = file name, value = SHA256 hash
     * \param queuedScans      list of queued scan requests; key = scan_id, value = file name
     * \param lastQueuedScanTime time point of the last queued scan - will be updated by this method for every scan
     * \param largeFiles       list of files that exceed the file size for scans; first = file name, second = file size in octets
     * \return Returns zero, if the file could be processed properly.
     * Returns a non-zero exit code, if an error occurred.
     */
    virtual int handle(scantool::virustotal::ScanStrategy& strategy,
              ScannerV2& scanVT, const std::string& fileName,
              CacheManagerV2& cacheMgr, const std::string& requestCacheDirVT, const bool useRequestCache,
              const bool silent, const int maybeLimit, const int maxAgeInDays,
              const std::chrono::time_point<std::chrono::system_clock> ageLimit,
              std::map<std::string, ScannerV2::Report>& mapHashToReport,
              std::map<std::string, std::string>& mapFileToHash,
              std::unordered_map<std::string, std::string>& queued_scans,
              std::chrono::time_point<std::chrono::steady_clock>& lastQueuedScanTime,
              std::vector<std::pair<std::string, int64_t> >& largeFiles) override;
}; //class

template<class ArcT, typename isArc>
int HandlerGeneric<ArcT, isArc>::handle(scantool::virustotal::ScanStrategy& strategy,
              ScannerV2& scanVT, const std::string& fileName,
              CacheManagerV2& cacheMgr, const std::string& requestCacheDirVT, const bool useRequestCache,
              const bool silent, const int maybeLimit, const int maxAgeInDays,
              const std::chrono::time_point<std::chrono::system_clock> ageLimit,
              std::map<std::string, ScannerV2::Report>& mapHashToReport,
              std::map<std::string, std::string>& mapFileToHash,
              std::unordered_map<std::string, std::string>& queued_scans,
              std::chrono::time_point<std::chrono::steady_clock>& lastQueuedScanTime,
              std::vector<std::pair<std::string, int64_t> >& largeFiles)
{
  //If it is not a matching archive type, then there's nothing to do here.
  if (!isArc::isArcT(fileName))
    return 0;

  std::string tempDirectory = "";
  //create temp. directory for extraction
  if (!libthoro::filesystem::directory::createTemp(tempDirectory))
  {
    std::cerr << "Error: Could not create temporary directory for extraction "
              << "of archive!" << std::endl;
    return scantool::rcFileError;
  }
  try
  {
    ArcT arc(fileName);
    const auto entries = arc.entries();

    //iterate over entries
    for(const auto & ent : entries)
    {
      if (!ent.isDirectory())
      {
        const std::string bn = ent.basename();
        const std::string destFile = libthoro::filesystem::slashify(tempDirectory)
                                   + (bn.empty() ? "file.dat" : bn);
        //extract file
        if (!arc.extractTo(destFile, ent.name()))
        {
          std::cerr << "Error: Could not extract file " << ent.name()
                    << " from " << fileName << "!" << std::endl;
          libthoro::filesystem::directory::remove(tempDirectory);
          return scantool::rcFileError;
        } //if extraction failed
        //scan file
        const int rcStrategy = strategy.scan(scanVT, destFile, cacheMgr, requestCacheDirVT,
        useRequestCache, silent, maybeLimit, maxAgeInDays, ageLimit,
        mapHashToReport, mapFileToHash, queued_scans, lastQueuedScanTime,
        largeFiles);
        //remove file
        libthoro::filesystem::file::remove(destFile);
        //check return code
        if (rcStrategy != 0)
        {
          //delete temporary directory
          libthoro::filesystem::directory::remove(tempDirectory);
          //... and return
          return rcStrategy;
        } //if scan failed
      } //if not directory
    } //for (range-based)
    //delete temporary directory
    libthoro::filesystem::directory::remove(tempDirectory);
  } //try
  catch (std::exception& ex)
  {
    std::cerr << "An exception occurred while handling the archive "
              << fileName << ": " << ex.what() << std::endl;
    libthoro::filesystem::directory::remove(tempDirectory);
    return scantool::rcFileError;
  } //try-catch
  //If we get to this point, all is fine.
  return 0;
}

} //namespace

} //namespace

#endif // SCANTOOL_VT_HANDLERGENERIC_HPP
