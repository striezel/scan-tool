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

#include "IterationOperationStatistics.hpp"
#include "../../libthoro/filesystem/file.hpp"
#include "../virustotal/ReportV2.hpp"

namespace scantool
{

namespace virustotal
{

IterationOperationStatistics::IterationOperationStatistics()
: m_Total(0),
  m_Unparsable(0),
  m_Unknown(0),
  m_Oldest(static_cast<std::time_t>(-1)),
  m_Newest(static_cast<std::time_t>(-1))
{
}

void IterationOperationStatistics::process(const std::string& fileName)
{
  //increase number of total cached files
  ++m_Total;
  //check, if file is way too large for a proper cache file
  const auto fileSize = libthoro::filesystem::file::getSize64(fileName);
  if (fileSize >= 1024*1024*2)
  {
    //Several kilobytes are alright, but not megabytes.
    ++m_Unparsable;
  }
  else
  {
    std::string content = "";
    if (libthoro::filesystem::file::readIntoString(fileName, content))
    {
      Json::Value root; // will contain the root value after parsing.
      Json::Reader jsonReader;
      const bool success = jsonReader.parse(content, root, false);
      if (!success)
      {
        ++m_Unparsable;
      } //if parsing failed
      else
      {
        ReportV2 report;
        if (report.fromJSONRoot(root))
        {
          //response code zero means: file not known to VirusTotal
          if (report.response_code == 0)
          {
            ++m_Unknown;
          } //if report indicates "unknown" file
          else
          {
            if (report.hasTime_t())
            {
              if (m_Oldest == static_cast<std::time_t>(-1))
                m_Oldest = report.scan_date_t;
              else if (report.scan_date_t < m_Oldest)
                m_Oldest = report.scan_date_t;

              if (m_Newest == static_cast<std::time_t>(-1))
                m_Newest = report.scan_date_t;
              else if (report.scan_date_t > m_Newest)
                m_Newest = report.scan_date_t;
            } //if time_t value is set
          } //else (report contains some info)
        } //if report could be filled from JSON
        else
        {
          //JSON data is probably not a report
          ++m_Unparsable;
        }
      } //else (JSON parsing was successful)
    } //if file could be read
    else
    {
      ++m_Unparsable;
    }
  } //else
}

uint_least32_t IterationOperationStatistics::total() const
{
  return m_Total;
}

uint_least32_t IterationOperationStatistics::unparsable() const
{
  return m_Unparsable;
}

uint_least32_t IterationOperationStatistics::unknown() const
{
  return m_Unknown;
}
std::time_t IterationOperationStatistics::oldest() const
{
  return m_Oldest;
}

std::time_t IterationOperationStatistics::newest() const
{
  return m_Newest;
}

} //namespace

} //namespace
