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

#include "Report.hpp"

namespace scantool
{

Report::Report()
: scan_date(std::string()),
  scan_date_t(static_cast<std::time_t>(-1)),
  scans(std::vector<EnginePtr>())
{
}

bool Report::hasTime_t() const
{
  return (static_cast<std::time_t>(-1) != scan_date_t);
}

} // namespace
