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

#ifndef SCANTOOL_VT_CACHE_ITERATIONOPERATIONSTATISTICS_HPP
#define SCANTOOL_VT_CACHE_ITERATIONOPERATIONSTATISTICS_HPP

#include "IterationOperation.hpp"
#include <cstdint>
#include <ctime>

namespace scantool
{

namespace virustotal
{

class IterationOperationStatistics: public IterationOperation
{
  public:
    ///constructor
    IterationOperationStatistics();


    /** \brief performs the operation for a single cached element
     *
     * \param fileName   file name of the cached element
     * \remarks Has to be implemented by descendant class.
     */
    virtual void process(const std::string& fileName) override;

    ///functions to return gathered information
    uint_least32_t total() const;
    uint_least32_t unparsable() const;
    uint_least32_t unknown() const;
    std::time_t oldest() const;
    std::time_t newest() const;
  private:
    uint_least32_t m_Total; /**< holds total number of cache files */
    uint_least32_t m_Unparsable; /**< number of corrupt / unparsable files */
    uint_least32_t m_Unknown; /**< number of files with no information */
    std::time_t m_Oldest; /**< oldest scan date */
    std::time_t m_Newest; /**< newest scan date */
}; //class

} //namespace

} //namespace

#endif // SCANTOOL_VT_CACHE_ITERATIONOPERATIONSTATISTICS_HPP
