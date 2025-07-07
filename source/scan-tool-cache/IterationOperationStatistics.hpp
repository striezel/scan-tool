/*
 -------------------------------------------------------------------------------
    This file is part of scan-tool.
    Copyright (C) 2016, 2025  Dirk Stolle

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
#include <chrono>
#include <cstdint>
#include <ctime>

namespace scantool::virustotal
{

/** Collects while iterating over the cache. */
class IterationOperationStatistics: public IterationOperation
{
  public:
    /** \brief Constructor.
     *
     * \param ageLimit the maximum age of reports (older reports will added to the old report count)
     */
    IterationOperationStatistics(const std::chrono::system_clock::time_point& ageLimit);


    /** \brief Performs the operation for a single cached element.
     *
     * \param fileName   file name of the cached element
     */
    virtual void process(const std::string& fileName) override;

    /// functions to return gathered information
    uint_least32_t total() const;
    uint_least32_t unparsable() const;
    uint_least32_t unknown() const;
    std::time_t oldest() const;
    std::time_t newest() const;
    uint_least32_t oldReports() const;
  private:
    uint_least32_t m_total; /**< holds total number of cache files */
    uint_least32_t m_unparsable; /**< number of corrupt / unparsable files */
    uint_least32_t m_unknown; /**< number of files with no information */
    std::time_t m_oldest; /**< oldest scan date */
    std::time_t m_newest; /**< newest scan date */
    std::chrono::system_clock::time_point m_ageLimit; /**< age limit for "old" reports */
    uint_least32_t m_oldReports; /**< number of old reports */
}; // class

} // namespace

#endif // SCANTOOL_VT_CACHE_ITERATIONOPERATIONSTATISTICS_HPP
