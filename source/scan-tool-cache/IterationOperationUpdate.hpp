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

#ifndef SCANTOOL_VT_ITERATIONOPERATIONUPDATE_HPP
#define SCANTOOL_VT_ITERATIONOPERATIONUPDATE_HPP

#include <vector>
#include "IterationOperation.hpp"
#include "../virustotal/CacheManagerV2.hpp"
#include "../virustotal/ScannerV2.hpp"

namespace scantool::virustotal
{

/** Updates cached reports while iterating over the cache. */
class IterationOperationUpdate: public IterationOperation
{
  public:
    /** \brief Constructor.
     *
     * \param apikey  the VirusTotal API key used for scanning/updating
     * \param silent  whether or not output to the standard output should be reduced
     * \param ageLimit the maximum age of reports (older reports will get an update)
     * \param cacheDir   root directory of the scan tool cache
     */
    IterationOperationUpdate(const std::string& apikey, const bool silent, const std::chrono::system_clock::time_point& ageLimit, const std::string& cacheDir);


    /** \brief Performs the operation for a single cached element.
     *
     * \param fileName   file name of the cached element
     */
    virtual void process(const std::string& fileName) override;


    /** \brief Returns a vector of all pending rescans by resource ID.
     *
     * \return Returns a vector of strings containing a resource ID each.
     */
    const std::vector<std::string>& pendingRescans() const;


    /** \brief Provides access to the internal scanner instance.
     *
     * \return Returns the internal ScannerV2.
     */
   ScannerV2& scanner();
  private:
    ScannerV2 scannerVT; /**< scanner that will be used for update */
    bool m_silent; /**< silence flag */
    std::chrono::system_clock::time_point m_ageLimit; /**< limit for updates */
    CacheManagerV2 m_cacheMgr; /**< cache manager instance */
    std::vector<std::string> m_pendingRescans; /**< list of pending rescans */
}; // class

} // namespace

#endif // SCANTOOL_VT_ITERATIONOPERATIONUPDATE_HPP
