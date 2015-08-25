/*
 -------------------------------------------------------------------------------
    This file is part of scan-tool.
    Copyright (C) 2015  Thoronador

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

#ifndef SCANNERVIRUSTOTALHONEYPOT_HPP
#define SCANNERVIRUSTOTALHONEYPOT_HPP

#include <string>
#include <vector>
#include "Scanner.hpp"

class ScannerVirusTotalHoneypot: public Scanner
{
  public:
    ///structure for detection report
    struct Report
    {
      struct Engine
      {
        ///default constructor
        Engine();

        std::string engine;  /**< name of the antivirus engine */
        bool detected;       /**< whether the engine detected a virus */
        std::string result;  /**< name of the detected malware */
      }; //struct Engine


      ///default constructor
      Report();

      int response_code;       /**< response code from VirusTotal API */

      std::string scan_date; /**< date when the scan was performed */

      int total;     /**< total number of scan engines */
      int positives; /**< number of engines that detected a virus */
      std::vector<Engine> scans; /**< results of individual scan engines */

      std::string permalink; /**< permanent link to the scan result */
    }; //struct Report


    /** \brief default constructor
     *
     * \param apikey   the VirusTotal API key used for scanning
     * \param honourTimeLimits   whether or not time limits should be honoured
     * \param silent             whether or not output to the standard output should be reduced
     */
    ScannerVirusTotalHoneypot(const std::string& apikey, const bool honourTimeLimits = true, const bool silent = false);


    /** \brief sets a new API key
     *
     * \param apikey   the VirusTotal API key used for scanning
     */
    void setApiKey(const std::string& apikey);


    /** \brief duration between consecutive requests, if time limit is respected
     *
     * \return Returns the minimum interval between two consecutive requests.
     */
    virtual std::chrono::seconds timeBetweenConsecutiveRequests() const override;


    /** \brief retrieves a scan report
     *
     * \param scan_id    scan ID of a previously submitted file
     * \param report     reference to a Report structure where the report's data will be stored
     * \return Returns true, if the report could be retrieved.
     *         Returns false, if retrieval failed.
     */
    bool getReport(const std::string& scan_id, Report& report);


    /** \brief upload a file and request a scan of the file
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


    /** \brief returns the maximum file size that is allowed to be scanned
      *
      * \return maximum size in bytes that can still be scanned
      */
    virtual int64_t maxScanSize() const override;
  private:
    std::string m_apikey; /**< holds the VirusTotal API key */
}; //class

#endif // SCANNERVIRUSTOTALHONEYPOT_HPP
