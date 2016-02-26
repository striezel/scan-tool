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

#ifndef SCANTOOL_VT_CACHEITERATION_HPP
#define SCANTOOL_VT_CACHEITERATION_HPP

#include <string>
#include "IterationOperation.hpp"

namespace scantool
{

namespace virustotal
{

class CacheIteration
{
  public:
    ///constructor
    CacheIteration();


    /** \brief iterates over all files in the request cache
     *
     * \param cacheDir  the root directory of the request cache
     * \param op        class that performs the iteration operation for each file
     * \return Returns true, if iteration took place.
     *         Returns false, if not (error occurred).
     */
    bool iterate(const std::string& cacheDir, IterationOperation& op);
}; //class

} //namespace

} //namespace

#endif // SCANTOOL_VT_CACHEITERATION_HPP
