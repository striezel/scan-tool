/*
 -------------------------------------------------------------------------------
    This file is part of scan-tool.
    Copyright (C) 2015, 2016, 2019  Dirk Stolle

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

#ifndef SCANTOOL_MSO_SCANNER_HPP
#define SCANTOOL_MSO_SCANNER_HPP

#include <string>
#include "Report.hpp"
#include "../Scanner.hpp"

namespace scantool
{

namespace metascan
{

/** \brief Scanner for MetaScanOnline.
 */
class Scanner: public scantool::Scanner
{
  public:
    /** \brief Constructor.
     *
     * \param apikey   the Metadefender Cloud API key used for scanning
     * \param honourTimeLimits   whether or not time limits should be honoured
     * \param silent             whether or not output to the standard output should be reduced
     * \param certFile           path to certificate file to use in peer verification
     */
    Scanner(const std::string& apikey, const bool honourTimeLimits = true, const bool silent = false, const std::string& certFile = "");


    struct ScanData
    {
      // default constructor
      ScanData();

      std::string data_id; /**< Data ID used for retrieving scan result */
      std::string rest_ip; /**< address for requests of scan progress */


      /** \brief comparison operator "less than" for ScanData
       *
       * \param other the other scan_data
       * \return Returns true, if this is "less than" the other ScanData.
       * \remarks Not strictly a less than, but only implemented to allow use
       *          of ScanData in ordered data structures like sets or maps.
       */
      bool operator < (const ScanData& other) const;


      /** \brief Gets ScanData from a stringified JSON.
       *
       * \param jsonString  the JSON string
       * \return Returns true, if the ScanData could be filled. Might be only
       *         partially filled.
       *         Returns false, if an unrecoverable error occurred.
       * \remarks If the function returns false, the content of the ScanData
       *          object may be partially undefined.
       */
      bool fromJsonString(const std::string& jsonString);
    }; // struct


    /** \brief Sets a new API key.
     *
     * \param apikey   the Metadefender Cloud API key used for scanning
     */
    void setApiKey(const std::string& apikey);


    /** \brief Gets the duration between consecutive file scan requests, if time limit is respected.
     *
     * \return Returns the minimum interval between two consecutive file scan requests.
     */
    virtual std::chrono::milliseconds timeBetweenConsecutiveScanRequests() const override;


    /** \brief Gets duration between consecutive hash lookups, if time limit is respected.
     *
     * \return Returns the minimum interval between two consecutive hash lookups.
     */
    virtual std::chrono::milliseconds timeBetweenConsecutiveHashLookups() const override;


    /** \brief Retrieves a scan report.
     *
     * \param resource   resource identifier
     * \param report     reference to a Report structure where the report's data will be stored
     * \return Returns true, if the report could be retrieved.
     *         Returns false, if retrieval failed.
     */
    bool getReport(const std::string& resource, Report& report);


    /** \brief Requests a re-scan of an already uploaded file.
     *
     * \param file_id    the file_id (as seen in report from getReport())
     * \param scan_data  the scan_data which can be used to query the report later
     * \return Returns true, if the rescan was initiated.
     *         Returns false, if request failed.
     */
    bool rescan(const std::string& file_id, ScanData& scan_data);


    /** \brief Uploads a file and requests a scan of the file.
     *
     * \param filename   name of the (local) file that shall be uploaded and scanned
     * \param scan_data  the scan_data which can be used to query the report later
     * \return Returns true, if the scan was initiated.
     *         Returns false, if request failed.
     */
    bool scan(const std::string& filename, ScanData& scan_data);


    /** \brief Returns the maximum file size that is allowed to be scanned.
     *
     * \return maximum size in bytes that can still be scanned
     */
    virtual int64_t maxScanSize() const noexcept override;
  private:
    std::string m_apikey; /**< holds the Metadefender Cloud API key */
    std::string m_certFile; /**< certificate file for peer verification */
}; // class

} // namespace

} // namespace


// custom specialization of std::hash for scantool::metascan::Scanner::ScanData
namespace std
{
    template<> struct hash<scantool::metascan::Scanner::ScanData>
    {
        typedef scantool::metascan::Scanner::ScanData argument_type;
        typedef std::size_t result_type;
        result_type operator()(argument_type const& s) const
        {
            result_type const h1 ( std::hash<std::string>()(s.data_id) );
            result_type const h2 ( std::hash<std::string>()(s.rest_ip) );
            return h1 ^ (h2 << 1);
        }
    };
}

#endif // SCANTOOL_MSO_SCANNER_HPP
