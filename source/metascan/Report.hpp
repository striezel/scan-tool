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

#ifndef SCANTOOL_MSO_REPORT_HPP
#define SCANTOOL_MSO_REPORT_HPP

#include <cstdint>
#include <string>
#include <vector>
#include <jsoncpp/json/reader.h>
#include "Engine.hpp"

namespace scantool
{

namespace metascan
{

struct Report
{
  /** \brief default constructor */
  Report();

  /** \brief structure for the file_info part in reports */
  struct FileInfo
  {
    /** \brief default constructor */
    FileInfo();

    //general information
    int64_t file_size; /**< size of the file in bytes */
    std::string upload_timestamp; /**< time of upload */
    //hashes
    std::string md5;    /**< MD5 hash of the file */
    std::string sha1;   /**< SHA1 hash of the file */
    std::string sha256; /**< SHA256 hash of the file */
    //file categorization
    std::string file_type_category; /**< file category, shorthand / abbreviation */
    std::string file_type_description; /**< description of the file type */
    std::string file_type_extension; /**< description of extension, e.g. "EXE/DLL" */
    std::string display_name; /**< basename of the file */
  }; //struct FileInfo



  std::string file_id;
  //scan_result part of report
  std::vector<Engine> scan_details;
  bool rescan_available;
  int scan_all_result_i;
  std::string start_time;
  int32_t total_time;
  int total_avs;
  int progress_percentage;
  int in_queue;
  std::string scan_all_result_a;
  // end of scan_result part of report
  FileInfo file_info; /**< file_info part in report */
  std::string data_id;
  int top_threat;

  /** \brief gets a report from a JSON object
   *
   * \param root  the root element of the JSON
   * \return Returns true, if the report could be filled. Might be only partially filled.
   *         Returns false, if an unrecoverable error occurred.
   * \remarks If the function returns false, the content of the report object
   *          may be partially undefined.
   */
  bool fromJSONRoot(const Json::Value& root);


  /** \brief checks whether the response indicates, that the requested resource
   * is present/was found and could be retrieved
   *
   * \return Returns true, if the requested item could be retrieved.
   */
  virtual bool successfulRetrieval() const /*override*/;


  /** \brief checks whether the response indicates, that the requested resource
   * is not present/was not found
   *
   * \return Returns true, if the requested item was not found.
   */
  virtual bool notFound() const /* override */;
}; //class

} //namespace

} //namespace

#endif // SCANTOOL_MSO_REPORT_HPP
