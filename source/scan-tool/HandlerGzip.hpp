/*
 -------------------------------------------------------------------------------
    This file is part of scan-tool.
    Copyright (C) 2016, 2025  Dirk Stolle

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

#ifndef SCANTOOL_VT_HANDLERGZIP_HPP
#define SCANTOOL_VT_HANDLERGZIP_HPP

#include <unordered_map>
#include "../virustotal/CacheManagerV2.hpp"
#include "../virustotal/ScannerV2.hpp"
#include "Handler.hpp"

namespace scantool::virustotal
{

class HandlerGzip: public Handler
{
  public:
    /** constructor */
    HandlerGzip(const bool ignoreErrors = false);


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
     * \param processedFiles   number of files that have been processed so far
     * \param totalFiles       total number of files that have to be processed
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
              std::vector<std::pair<std::string, int64_t> >& largeFiles,
              std::set<std::string>::size_type& processedFiles,
              std::set<std::string>::size_type& totalFiles) override;


    /** \brief checks whether or not this handler ignores extraction failures
     *
     * \return Returns true, if extraction failure does not produce an error or
     * an exception. Returns false, if extraction failure causes errors.
     */
    bool ignoreExtractionErrors() const;


    /** \brief sets whether or not extraction errors will be ignore
     *
     * \param ignore  whether or not to ignore extraction failure
     */
    void ignoreExtractionErrors(const bool ignore);
  private:
    bool m_IgnoreExtractionErrors; /**< whether to continue, if extraction fails */
}; // class

} //namespace

#endif // SCANTOOL_VT_HANDLERGZIP_HPP
