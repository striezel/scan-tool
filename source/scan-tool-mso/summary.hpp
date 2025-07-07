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

#ifndef SCANTOOL_MSO_SUMMARY_HPP
#define SCANTOOL_MSO_SUMMARY_HPP

#include <map>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>
#include "../metascan/Report.hpp"
#include "../metascan/Scanner.hpp"

namespace scantool::metascan
{

/** \brief shows the summary of a scan-tool-mso run
 *
 * \param mapFileToHash    map that maps filename to hash; key = file name, value = SHA256 hash
 * \param mapHashToReport  map that maps SHA256 hashes to corresponding report; key = SHA256 hash, value = scan report
 * \param largeFiles       list of files that exceed the file size for scans; first = file name, second = file size in octets
 */
void showSummary(const std::map<std::string, std::string>& mapFileToHash,
                 std::map<std::string, Report>& mapHashToReport,
                 std::vector<std::pair<std::string, int64_t> >& largeFiles);

} // namespace

#endif // SCANTOOL_MSO_SUMMARY_HPP
