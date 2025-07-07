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

#include "ScanStrategy.hpp"

namespace scantool::virustotal
{

ScanStrategy::ScanStrategy()
: m_Handlers(std::vector<std::unique_ptr<Handler> >())
{
}

void ScanStrategy::addHandler(std::unique_ptr<Handler>&& handler)
{
  m_Handlers.push_back(std::move(handler));
}

int ScanStrategy::applyHandlers(ScannerV2& scanVT, const std::string& fileName,
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
  for (auto & handler : m_Handlers)
  {
    const int rc = handler->handle(*this, scanVT, fileName, cacheMgr, requestCacheDirVT,
        useRequestCache, silent, maybeLimit, maxAgeInDays, ageLimit,
        mapHashToReport, mapFileToHash, queued_scans, lastQueuedScanTime,
        largeFiles, processedFiles, totalFiles);
    if (rc != 0)
      return rc;
  }
  // All handlers are done.
  return 0;
}

} //namespace
