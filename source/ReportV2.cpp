/*
 -------------------------------------------------------------------------------
    This file is part of scan-tool.
    Copyright (C) 2015  Thoronador

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

#include "ReportV2.hpp"

ReportV2::ReportV2()
: ReportVirusTotalBase(),
  verbose_msg(""),
  resource(""),
  scan_id(""),
  total(-1),
  md5(""), sha1(""), sha256("")
{
}

bool ReportV2::successfulRetrieval() const
{
  /* Response code 1 means that entry was present and could be retrieved. */
  return (response_code == 1);
}

bool ReportV2::notFound() const
{
  /* Response code 0 means that there was no matching entry. */
  return (response_code == 0);
}

bool ReportV2::stillInQueue() const
{
  /* Response code -2 means that this stuff is still queued for analysis. */
  return (response_code == -2);
}
