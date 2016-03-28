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

#ifndef SCANTOOL_VT_STRATEGIES_HPP
#define SCANTOOL_VT_STRATEGIES_HPP

#include <string>

namespace scantool
{

namespace virustotal
{

///enumeration class for scan strategies
enum class Strategy { None, Default, DirectScan };


/** \brief converts strategy to a simple string
 *
 * \param s  the strategy enumeration
 * \return Returns a short string describing the strategy.
 */
std::string strategyToString(const Strategy s);


/** \brief tries to convert a string to a strategy enumeration value
 *
 * \param str   the string
 * \return Returns the corresponding strategy, if any.
 * Returns None, if no matching strategy was found.
 */
Strategy stringToStrategy(const std::string& str);

} //namespace

} //namespace

#endif // SCANTOOL_VT_STRATEGIES_HPP
