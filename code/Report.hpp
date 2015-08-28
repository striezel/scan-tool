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

#ifndef REPORT_HPP
#define REPORT_HPP

#include <vector>
#include "Engine.hpp"

///structure for detection report
struct Report
{
  ///default constructor
  Report();

  int response_code;     /**< response code from VirusTotal API */

  std::string scan_date; /**< date when the scan was performed */

  int total;     /**< total number of scan engines */
  int positives; /**< number of engines that detected a virus */
  std::vector<Engine> scans; /**< results of individual scan engines */

  std::string permalink; /**< permanent link to the scan result */
}; //struct Report

#endif // REPORT_HPP
