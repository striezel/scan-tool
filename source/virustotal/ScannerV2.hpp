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

#ifndef SCANNERVIRUSTOTALV2_HPP
#define SCANNERVIRUSTOTALV2_HPP

#include <string>
#include <vector>
#include "../Scanner.hpp"
#include "ReportV2.hpp"

namespace scantool::virustotal
{

/** \brief Scanner for VirusTotal API V2.
 */
class ScannerV2: public scantool::Scanner
{
  public:
    ///structure for detection report
    typedef ReportV2 Report;

    /** \brief Constructor.
     *
     * \param apikey   the VirusTotal API key used for scanning
     * \param honourTimeLimits   whether or not time limits should be honoured
     * \param silent             whether or not output to the standard output should be reduced
     */
    ScannerV2(const std::string& apikey, const bool honourTimeLimits = true, const bool silent = false);


    /** \brief Sets a new API key.
     *
     * \param apikey   the VirusTotal API key used for scanning
     */
    void setApiKey(const std::string& apikey);


    /** \brief Gets the duration between consecutive file scan requests, if time limit is respected.
     *
     * \return Returns the minimum interval between two consecutive file scan requests.
     */
    virtual std::chrono::milliseconds timeBetweenConsecutiveScanRequests() const override;


    /** \brief Gets the duration between consecutive hash lookups, if time limit is respected.
     *
     * \return Returns the minimum interval between two consecutive hash lookups.
     */
    virtual std::chrono::milliseconds timeBetweenConsecutiveHashLookups() const override;


    /** \brief Sets the time of the last request to now.
     */
    virtual void scanRequestWasNow() override;


    /** \brief Sets the time of the last hash lookup to now.
     */
    virtual void hashLookupWasNow() override;


    /** \brief Retrieves a scan report.
     *
     * \param resource   resource identifier
     * \param report     reference to a Report structure where the report's data will be stored
     * \param useCache   If set to true, the scanner tries to use the cached reports from the cache directory @cacheDir
     * \param cacheDir   directory of the report cache (Value has to be set, if @useCache is true.)
     *                   If the @cacheDir is non-empty, the JSON data of the
     *                   the report will be written to the cache directory.
     *                   Even if @useCache is false.
     * \return Returns true, if the report could be retrieved.
     *         Returns false, if retrieval failed.
     */
    bool getReport(const std::string& resource, Report& report, const bool useCache,
                   const std::string& cacheDir);


    /** \brief Requests a re-scan of an already uploaded file.
     *
     * \param resource   resource identifier
     * \param scan_id    the scan_id (resource) which can be used to query the report later
     * \return Returns true, if the rescan was initiated.
     *         Returns false, if request failed.
     * \remarks Files sent using the API have the lowest scanning priority.
     * Depending on VirusTotal's load, it may take several hours before the
     * file is scanned, so query the report at regular intervals until the
     * result shows up and do not keep sending the file rescan requests over
     * and over again.
     */
    bool rescan(const std::string& resource, std::string& scan_id);


    /** \brief Uploads a file and requests a scan of the file.
     *
     * \param filename   name of the (local) file that shall be uploaded and scanned
     * \param scan_id    the scan_id (resource) which can be used to query the report later
     * \return Returns true, if the scan was initiated.
     *         Returns false, if request failed.
     * \remarks Files sent using the API have the lowest scanning priority.
     * Depending on VirusTotal's load, it may take several hours before the
     * file is scanned, so query the report at regular intervals until the
     * result shows up and do not keep sending the file rescan requests over
     * and over again.
     */
    bool scan(const std::string& filename, std::string& scan_id);


    /** \brief Teturns the maximum file size that is allowed to be scanned.
      *
      * \return maximum size in bytes that can still be scanned
      */
    virtual int64_t maxScanSize() const noexcept override;
  private:
    std::string m_apikey; /**< holds the VirusTotal API key */
}; // class

} // namespace

#endif // SCANNERVIRUSTOTALV2_HPP
