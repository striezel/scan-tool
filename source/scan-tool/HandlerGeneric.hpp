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

#ifndef SCANTOOL_VT_HANDLERGENERIC_HPP
#define SCANTOOL_VT_HANDLERGENERIC_HPP

#include <functional>
#include <unordered_map>
#include "../virustotal/CacheManagerV2.hpp"
#include "../virustotal/ScannerV2.hpp"
#include "../ReturnCodes.hpp"
#include "../../libstriezel/filesystem/directory.hpp"
#include "../../libstriezel/filesystem/file.hpp"
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
    /** constructor */
    HandlerGeneric(const bool ignoreErrors = false);

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
     * \param processedFiles   number of files that have been processed so far
     * \param totalFiles       total number of files that have to be processed
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
}; //class

template<class ArcT, typename isArc>
HandlerGeneric<ArcT, isArc>::HandlerGeneric(const bool ignoreErrors)
: Handler(),
  m_IgnoreExtractionErrors(ignoreErrors)
{
}

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
              std::vector<std::pair<std::string, int64_t> >& largeFiles,
              std::set<std::string>::size_type& processedFiles,
              std::set<std::string>::size_type& totalFiles)
{
  //If it is not a matching archive type, then there's nothing to do here.
  if (!isArc::isArcT(fileName))
    return 0;

  std::string tempDirectory = "";
  //create temp. directory for extraction
  if (!libstriezel::filesystem::directory::createTemp(tempDirectory))
  {
    std::cerr << "Error: Could not create temporary directory for extraction "
              << "of archive!" << std::endl;
    return scantool::rcFileError;
  }
  try
  {
    ArcT arc(fileName);
    const auto entries = arc.entries();
    totalFiles += entries.size();

    //iterate over entries
    for(const auto & ent : entries)
    {
      //We do not want directory and symbolic link entries.
      if (!ent.isDirectory() && !ent.isSymLink())
      {
        const std::string bn = ent.basename();
        const std::string destFile = libstriezel::filesystem::slashify(tempDirectory)
                                   + (bn.empty() ? "file.dat" : bn);
        //extract file
        if (!arc.extractTo(destFile, ent.name()))
        {
          std::cerr << "Error: Could not extract file " << ent.name()
                    << " from " << fileName << "!" << std::endl;
          libstriezel::filesystem::directory::remove(tempDirectory);
          return scantool::rcFileError;
        } //if extraction failed
        //scan file
        const int rcStrategy = strategy.scan(scanVT, destFile, cacheMgr, requestCacheDirVT,
        useRequestCache, silent, maybeLimit, maxAgeInDays, ageLimit,
        mapHashToReport, mapFileToHash, queued_scans, lastQueuedScanTime,
        largeFiles, processedFiles, totalFiles);
        //remove file
        libstriezel::filesystem::file::remove(destFile);
        //check return code
        if (rcStrategy != 0)
        {
          //delete temporary directory
          libstriezel::filesystem::directory::remove(tempDirectory);
          //... and return
          return rcStrategy;
        } //if scan failed
      } //if not directory
      ++processedFiles;
    } //for (range-based)
    //delete temporary directory
    libstriezel::filesystem::directory::remove(tempDirectory);
  } //try
  catch (std::exception& ex)
  {
    libstriezel::filesystem::directory::remove(tempDirectory);
    if (!ignoreExtractionErrors())
    {
      std::cerr << "An exception occurred while handling the archive "
              << fileName << ": " << ex.what() << std::endl;
      return scantool::rcFileError;
    }
    //ignore error and return zero (which indicates that all is fine)
    return 0;
  } //try-catch
  //If we get to this point, all is fine.
  return 0;
}

template<class ArcT, typename isArc>
bool HandlerGeneric<ArcT, isArc>::ignoreExtractionErrors() const
{
  return m_IgnoreExtractionErrors;
}

template<class ArcT, typename isArc>
void HandlerGeneric<ArcT, isArc>::ignoreExtractionErrors(const bool ignore)
{
  m_IgnoreExtractionErrors = ignore;
}

} //namespace

} //namespace

#endif // SCANTOOL_VT_HANDLERGENERIC_HPP
