/*
 -------------------------------------------------------------------------------
    This file is part of scan-tool.
    Copyright (C) 2015  Dirk Stolle

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

#include "StringToTimeT.hpp"
#include <ctime>
#include "../libthoro/common/StringUtils.hpp"

bool stringToTimeT(const std::string& dateStr, std::time_t& tp)
{
  //date format in string should be "YYYY-MM-DD HH:mm:ss"
  unsigned int year = 0;
  if (!stringToUnsignedInt(dateStr.substr(0,4), year))
    return false;
  unsigned int month = 0;
  if (!stringToUnsignedInt(dateStr.substr(5,2), month))
    return false;
  if ((month > 12) or (month < 1))
    return false;
  unsigned int day = 0;
  if (!stringToUnsignedInt(dateStr.substr(8,2), day))
    return false;
  if ((day > 31) or (day < 1))
    return false;
  unsigned int hour = 25;
  if (!stringToUnsignedInt(dateStr.substr(11,2), hour))
    return false;
  if (hour > 23)
    return false;
  unsigned int minute = 61;
  if (!stringToUnsignedInt(dateStr.substr(14,2), minute))
    return false;
  if (minute > 59)
    return false;
  unsigned int second = 61;
  if (!stringToUnsignedInt(dateStr.substr(17,2), second))
    return false;
  if (second > 59)
    return false;

  struct tm theTM;
  theTM.tm_year = year - 1900; //years since 1900
  theTM.tm_mon = month - 1; //months since January
  theTM.tm_mday = day; //day of the month
  theTM.tm_hour = hour;
  theTM.tm_min = minute;
  theTM.tm_sec = second;
  //wday and yday are not known
  theTM.tm_yday = 0;
  theTM.tm_wday = 0;
  //DST information is not available
  theTM.tm_isdst = -1;

  const std::time_t t = std::mktime(&theTM);
  //Did conversion fail?
  if (t == -1)
    return false;

  tp = t;
  return true;
}
