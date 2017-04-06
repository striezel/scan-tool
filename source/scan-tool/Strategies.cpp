/*
 -------------------------------------------------------------------------------
    This file is part of scan-tool.
    Copyright (C) 2016, 2017  Dirk Stolle

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

#include "Strategies.hpp"

namespace scantool
{

namespace virustotal
{

std::string strategyToString(const Strategy s)
{
  switch (s)
  {
    case Strategy::None:
         return "none";
    case Strategy::Default:
         return "default";
    case Strategy::DirectScan:
         return "direct";
    case Strategy::NoRescan:
         return "no-rescan";
    case Strategy::ScanAndForget:
         return "scan-and-forget";
    //fallback for future, unknown values
    default:
         return "none";
  } //swi
}

Strategy stringToStrategy(const std::string& str)
{
  if (str == "default")
    return Strategy::Default;
  if ((str == "direct") || (str == "directscan") || (str == "scan"))
    return Strategy::DirectScan;
  if ((str == "no-rescan") || (str == "norescan") || (str == "no_rescan"))
    return Strategy::NoRescan;
  if ((str == "scan-and-forget") || (str == "scanandforget") || (str == "scan_and_forget")
    || (str == "fire-and-forget") || (str == "fireandforget") || (str == "fire_and_forget"))
    return Strategy::ScanAndForget;
  //no matching strategy found
  return Strategy::None;
}

} //namespace

} //namespace

