/*
 -------------------------------------------------------------------------------
    This file is part of the test suite for scan-tool.
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

#include <iostream>
#include <vector>
#include "../../../source/StringToTimeT.hpp"

const int secsInHour = 3600;
const int secsInDay  = 86400;

const std::vector<std::string> testCases =
    {
        {"1970-01-01 00:00:00"},
        {"1970-01-01 00:00:01"},
        {"1970-01-01 00:00:02"},
        {"1970-01-01 00:01:00"},
        {"1970-01-01 00:02:00"},
        {"1970-01-01 01:00:00"},
        {"1970-01-01 02:00:00"},
        {"1970-01-02 00:00:00"},
        {"1970-02-01 00:00:00"},
        {"1970-03-31 01:10:55"},
        {"1970-04-30 02:20:05"},
        {"1970-05-31 03:30:10"},
        {"1970-06-30 04:40:17"},
        {"1970-07-31 05:50:32"},
        {"1970-08-31 06:05:47"},
        {"1970-09-30 07:15:50"},
        {"1970-10-31 08:25:55"},
        {"1970-11-30 09:35:57"},
        {"1970-12-31 10:45:54"},
        {"2000-02-29 23:59:59"},
        {"2015-01-01 12:34:56"},
        {"2015-12-31 23:01:07"},
        {"2030-11-22 00:11:22"},
    };



int main()
{
  for(const auto& item : testCases)
  {
    std::time_t tt;
    const bool success = stringToTimeT(item, tt);
    if (!success)
    {
      std::cout << "Error: Could not convert " << item << " to std::time_t!" << std::endl;
      return 1;
    } //if

    std::tm * pointer_tm = std::localtime(&tt);
    char buffer[32];
    std::strftime(buffer, 32, "%Y-%m-%d %H:%M:%S", pointer_tm);
    const std::string result(buffer);

    if (result != item)
    {
      std::cout << "Error: time_t for " << item << " converts to " << result
                << "!" << std::endl;
      return 1;
    }
  } //for

  //Everything seems to be OK.
  std::cout << "Test for time_t conversion was passed!" << std::endl;
  return 0;
}
