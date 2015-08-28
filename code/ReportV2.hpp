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

#ifndef REPORTV2_HPP
#define REPORTV2_HPP

#include "Report.hpp"
#include "EngineV2.hpp"

///structure for detection report
struct ReportV2: public Report
{
  typedef EngineV2 Engine;

  ///default constructor
  ReportV2();

  std::string verbose_msg; /**< message from VirusTotal API */

  std::string resource; /**< name of the resource */

  std::string scan_id;   /**< scan ID */

  std::vector<EngineV2> scans; /**< results of individual scan engines */

  //hashes
  std::string md5;    /**< MD5 hash of the file */
  std::string sha1;   /**< SHA1 hash of the file */
  std::string sha256; /**< SHA256 hash of the file */
}; //struct Report

#endif // REPORTV2_HPP
