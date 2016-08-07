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

#include "ZipHandler.hpp"
#include "../../libstriezel/archive/zip/archive.hpp"
#include "../../libstriezel/filesystem/directory.hpp"
#include "../../libstriezel/filesystem/file.hpp"
#include "../ReturnCodes.hpp"
#include "ScanStrategy.hpp"

namespace scantool
{

namespace virustotal
{

ZipHandler::ZipHandler(const bool ignoreErrors)
: Handler(),
  m_IgnoreExtractionErrors(ignoreErrors)
{
}

int ZipHandler::handle(scantool::virustotal::ScanStrategy& strategy,
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
  //If it is not a ZIP, then there's nothing to do here.
  if (!libstriezel::zip::archive::isZip(fileName))
    return 0;

  std::string tempDirectory = "";
  //create temp. directory for extraction
  if (!libstriezel::filesystem::directory::createTemp(tempDirectory))
  {
    std::cerr << "Error: Could not create temporary directory for extraction "
              << "of ZIP archive!" << std::endl;
    return scantool::rcFileError;
  }
  try
  {
    libstriezel::zip::archive zipArc(fileName);
    const std::vector<libstriezel::zip::entry> entries = zipArc.entries();

    //iterate over entries
    for(const auto & ent : entries)
    {
      if (!ent.isDirectory())
      {
        const std::string bn = ent.basename();
        const std::string destFile = libstriezel::filesystem::slashify(tempDirectory)
                                   + (bn.empty() ? "file.dat" : bn);
        //extract file
        if (!zipArc.extractTo(destFile, ent.index()))
        {
          std::cerr << "Error: Could not extract file " << ent.name()
                    << " (index " << ent.index() << ") from " << fileName
                    << "!" << std::endl;
          libstriezel::filesystem::directory::remove(tempDirectory);
          return scantool::rcFileError;
        } //if extraction failed
        //scan file
        const int rcStrategy = strategy.scan(scanVT, destFile, cacheMgr, requestCacheDirVT,
        useRequestCache, silent, maybeLimit, maxAgeInDays, ageLimit,
        mapHashToReport, mapFileToHash, queued_scans, lastQueuedScanTime,
        largeFiles);
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
    } //for (range-based)
    //delete temporary directory
    libstriezel::filesystem::directory::remove(tempDirectory);
  } //try
  catch (std::exception& ex)
  {
    libstriezel::filesystem::directory::remove(tempDirectory);
    if (!ignoreExtractionErrors())
    {
      std::cerr << "An exception occurred while handling the ZIP file "
              << fileName << ": " << ex.what() << std::endl;
      return scantool::rcFileError;
    }
    //ignore error and return zero (which indicates that all is fine)
    return 0;
  } //try-catch
  //If we get to this point, all is fine.
  return 0;
}

bool ZipHandler::ignoreExtractionErrors() const
{
  return m_IgnoreExtractionErrors;
}

void ZipHandler::ignoreExtractionErrors(const bool ignore)
{
  m_IgnoreExtractionErrors = ignore;
}

} //namespace

} //namespace
