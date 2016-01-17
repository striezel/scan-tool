/*
 -------------------------------------------------------------------------------
    This file is part of scan-tool.
    Copyright (C) 2016  Thoronador

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

#ifndef SCANTOOL_VTV2_CACHETRANSITION_HPP
#define SCANTOOL_VTV2_CACHETRANSITION_HPP

/** \brief tries to perform the request cache transition from old to new
 * directory structure.
 *
 * \return Returns zero in case of success.
 * Returns a non-zero value, if an error occured.
 */
int performTransition();

#endif // SCANTOOL_VTV2_CACHETRANSITION_HPP
