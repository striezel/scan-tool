/*
 -------------------------------------------------------------------------------
    This file is part of scan-tool.
    Copyright (C) 2016, 2019  Dirk Stolle

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

#include "IterationOperationStatistics.hpp"
#include "../../libstriezel/filesystem/file.hpp"
#include "../virustotal/ReportV2.hpp"

namespace scantool
{

namespace virustotal
{

IterationOperationStatistics::IterationOperationStatistics(const std::chrono::system_clock::time_point& ageLimit)
: m_total(0),
  m_unparsable(0),
  m_unknown(0),
  m_oldest(static_cast<std::time_t>(-1)),
  m_newest(static_cast<std::time_t>(-1)),
  m_ageLimit(ageLimit),
  m_oldReports(0)
{
}

void IterationOperationStatistics::process(const std::string& fileName)
{
  // increase number of total cached files
  ++m_total;
  // check, if file is way too large for a proper cache file
  const auto fileSize = libstriezel::filesystem::file::getSize64(fileName);
  if (fileSize >= 1024 * 1024 * 2)
  {
    // Several kilobytes are alright, but not megabytes.
    ++m_unparsable;
    return;
  }

  std::string content;
  if (!libstriezel::filesystem::file::readIntoString(fileName, content))
  {
    ++m_unparsable;
    return;
  }

  ReportV2 report;
  if (!report.fromJsonString(content))
  {
    // File is probably not a report.
    ++m_unparsable;
    return;
  }

  // response code zero means: file not known to VirusTotal
  if (report.response_code == 0)
  {
    ++m_unknown;
  } // if report indicates "unknown" file
  else
  {
    if (report.hasTime_t())
    {
      // update oldest report date
      if (m_oldest == static_cast<std::time_t>(-1))
        m_oldest = report.scan_date_t;
      else if (report.scan_date_t < m_oldest)
        m_oldest = report.scan_date_t;
      // update newest report date
      if (m_newest == static_cast<std::time_t>(-1))
        m_newest = report.scan_date_t;
      else if (report.scan_date_t > m_newest)
        m_newest = report.scan_date_t;
      // update count of old reports
      if (std::chrono::system_clock::from_time_t(report.scan_date_t) < m_ageLimit)
        ++m_oldReports;
    } // if time_t value is set
  } // else (report contains some info)
}

uint_least32_t IterationOperationStatistics::total() const
{
  return m_total;
}

uint_least32_t IterationOperationStatistics::unparsable() const
{
  return m_unparsable;
}

uint_least32_t IterationOperationStatistics::unknown() const
{
  return m_unknown;
}
std::time_t IterationOperationStatistics::oldest() const
{
  return m_oldest;
}

std::time_t IterationOperationStatistics::newest() const
{
  return m_newest;
}

uint_least32_t IterationOperationStatistics::oldReports() const
{
  return m_oldReports;
}

} // namespace

} // namespace
