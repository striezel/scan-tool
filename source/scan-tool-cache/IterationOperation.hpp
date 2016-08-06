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

#ifndef SCANTOOL_VT_CACHE_ITERATIONOPERATION_HPP
#define SCANTOOL_VT_CACHE_ITERATIONOPERATION_HPP

#include <string>

namespace scantool
{

namespace virustotal
{

class IterationOperation
{
  public:
    /** \brief performs the operation for a single cached element
     *
     * \param fileName   file name of the cached element
     * \remarks Has to be implemented by descendant class.
     */
    virtual void process(const std::string& fileName) = 0;

    /// virtual destructor
    virtual ~IterationOperation() {}
}; //class

} //namespace

} //namespace

#endif // SCANTOOL_VT_CACHE_ITERATIONOPERATION_HPP
