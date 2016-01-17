/*
 -------------------------------------------------------------------------------
    This file is part of scan-tool.
    Copyright (C) 2015, 2016  Thoronador

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

#ifndef SCANNERMETASCANONLINE_HPP
#define SCANNERMETASCANONLINE_HPP

#include <string>
#include "ReportMetascanOnline.hpp"
#include "Scanner.hpp"

class ScannerMetascanOnline: public Scanner
{
  public:
    /** \brief default constructor
     *
     * \param apikey   the Metascan Online API key used for scanning
     * \param honourTimeLimits   whether or not time limits should be honoured
     * \param silent             whether or not output to the standard output should be reduced
     */
    ScannerMetascanOnline(const std::string& apikey, const bool honourTimeLimits = true, const bool silent = false);


    struct RescanData
    {
      //default constructor
      RescanData();

      std::string data_id; /**< Data ID used for retrieving scan result */
      std::string rest_ip; /**< address for requests of scan progress */
    }; //struct


    /** \brief sets a new API key
     *
     * \param apikey   the Metascan Online API key used for scanning
     */
    void setApiKey(const std::string& apikey);


    /** \brief duration between consecutive file scan requests, if time limit is respected
     *
     * \return Returns the minimum interval between two consecutive file scan requests.
     */
    virtual std::chrono::milliseconds timeBetweenConsecutiveScanRequests() const override;


    /** \brief duration between consecutive hash lookups, if time limit is respected
     *
     * \return Returns the minimum interval between two consecutive hash lookups.
     */
    virtual std::chrono::milliseconds timeBetweenConsecutiveHashLookups() const override;


    /** \brief retrieves a scan report
     *
     * \param resource   resource identifier
     * \param report     reference to a Report structure where the report's data will be stored
     * \return Returns true, if the report could be retrieved.
     *         Returns false, if retrieval failed.
     */
    bool getReport(const std::string& resource, ReportMetascanOnline& report);


    /** \brief requests a re-scan of an already uploaded file
     *
     * \param file_id    the file_id (as seen in report from getReport())
     * \param scan_data  the scan_data which can be used to query the report later
     * \return Returns true, if the rescan was initiated.
     *         Returns false, if request failed.
     */
    bool rescan(const std::string& file_id, RescanData& scan_data);


    /** \brief returns the maximum file size that is allowed to be scanned
     *
     * \return maximum size in bytes that can still be scanned
     */
    virtual int64_t maxScanSize() const override;
  private:
    std::string m_apikey; /**< holds the Metascan Online API key */
}; //class

#endif // SCANNERMETASCANONLINE_HPP
