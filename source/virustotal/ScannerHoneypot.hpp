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

#ifndef SCANTOOL_VT_SCANNERHONEYPOT_HPP
#define SCANTOOL_VT_SCANNERHONEYPOT_HPP

#include <string>
#include <vector>
#include "../Scanner.hpp"
#include "ReportHoneypot.hpp"

namespace scantool
{

namespace virustotal
{

/** \brief Scanner for VirusTotal Honeypot API.
 */
class ScannerHoneypot: public scantool::Scanner
{
  public:
    typedef ReportHoneypot Report;

    /** \brief Constructor.
     *
     * \param apikey   the VirusTotal API key used for scanning
     * \param honourTimeLimits   whether or not time limits should be honoured
     * \param silent             whether or not output to the standard output should be reduced
     */
    ScannerHoneypot(const std::string& apikey, const bool honourTimeLimits = true, const bool silent = false);


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
     * \param scan_id    scan ID of a previously submitted file
     * \param report     reference to a Report structure where the report's data will be stored
     * \return Returns true, if the report could be retrieved.
     *         Returns false, if retrieval failed.
     */
    bool getReport(const std::string& scan_id, Report& report);


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


    /** \brief Returns the maximum file size that is allowed to be scanned.
      *
      * \return maximum size in bytes that can still be scanned
      */
    virtual int64_t maxScanSize() const noexcept override;
  private:
    std::string m_apikey; /**< holds the VirusTotal API key */
}; // class

} // namespace

} // namespace

#endif // SCANTOOL_VT_SCANNERHONEYPOT_HPP
