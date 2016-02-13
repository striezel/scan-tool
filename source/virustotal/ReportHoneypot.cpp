/*
 -------------------------------------------------------------------------------
    This file is part of scan-tool.
    Copyright (C) 2015, 2016  Thoronador

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

#include "ReportHoneypot.hpp"

namespace scantool
{

namespace virustotal
{

ReportHoneypot::ReportHoneypot()
: ReportBase()
{
}

bool ReportHoneypot::successfulRetrieval() const
{
  return (response_code == 1);
}

bool ReportHoneypot::notFound() const
{
  return (response_code == 0);
}

/*
bool ReportHoneypot::stillInQueue() const
{
  #warning Result code for this state is not known.
}
*/

} //namespace

} //namespace
