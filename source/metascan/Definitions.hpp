/*
 -------------------------------------------------------------------------------
    This file is part of scan-tool.
    Copyright (C) 2016  Dirk Stolle

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

#ifndef METASCANDEFINITIONS_HPP
#define METASCANDEFINITIONS_HPP

namespace scantool
{

namespace metascan
{

/** \brief checks whether a scan_result_i value indicates infection of a file
 *
 * \param scan_result_i  the value of JSON's scan_result_i
 * \return Returns true, if the code indicates a virus infection.
 *         Returns false otherwise.
 */

bool isInfected(const int scan_result_i);

} //namespace

} //namespace

#endif // METASCANDEFINITIONS_HPP
