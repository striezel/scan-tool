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

#include "HandlerGzip.hpp"
#include "../../libthoro/archive/gzip/archive.hpp"
#include "../../libthoro/filesystem/directory.hpp"
#include "../../libthoro/filesystem/file.hpp"
#include "../ReturnCodes.hpp"
#include "ScanStrategy.hpp"

namespace scantool
{

namespace virustotal
{

int HandlerGzip::handle(scantool::virustotal::ScanStrategy& strategy,
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
  //If it is not a gzipped file, then there's nothing to do here.
  if (!libthoro::gzip::archive::isGzip(fileName))
    return 0;

  std::string tempDirectory = "";
  //create temp. directory for extraction
  if (!libthoro::filesystem::directory::createTemp(tempDirectory))
  {
    std::cerr << "Error: Could not create temporary directory for decompression "
              << "of gzip!" << std::endl;
    return scantool::rcFileError;
  }
  try
  {
    libthoro::gzip::archive gzippedFile(fileName);
    const auto entries = gzippedFile.entries();

    //iterate over entries
    for(const auto & ent : entries)
    {
      if (!ent.isDirectory())
      {
        const std::string bn = ent.basename();
        const std::string destFile = libthoro::filesystem::slashify(tempDirectory)
                                   + (bn.empty() ? "file.dat" : bn);
        //extract file
        if (!gzippedFile.extractTo(destFile))
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
    std::cerr << "An exception occurred while handling the tarball "
              << fileName << ": " << ex.what() << std::endl;
    libthoro::filesystem::directory::remove(tempDirectory);
    return scantool::rcFileError;
  } //try-catch
  //If we get to this point, all is fine.
  return 0;
}

} //namespace

} //namespace
