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

#ifndef SCANTOOL_VT_REPORTV2_HPP
#define SCANTOOL_VT_REPORTV2_HPP

#include "ReportBase.hpp"
#include <jsoncpp/json/reader.h>
#include "EngineV2.hpp"

namespace scantool
{

namespace virustotal
{

///structure for detection report
struct ReportV2: public ReportBase
{
  typedef EngineV2 Engine;

  ///default constructor
  ReportV2();

  /** \brief gets a report from a JSON object
   *
   * \param root  the root element of the JSON
   * \return Returns true, if the report could be filled. Might be only partially filled.
   *         Returns false, if an unrecoverable error occurred.
   * \remarks If the function returns false, the content of the report object
   *          may be partially undefined.
   */
  bool fromJSONRoot(const Json::Value& root);


  /** \brief checks whether the response code indicates, that the requested resource
   * is present/was found and could be retrieved
   *
   * \return Returns true, if the requested item could be retrieved.
   */
  virtual bool successfulRetrieval() const override;


  /** \brief checks whether the response code indicates, that the requested resource
   * is not present/was not found
   *
   * \return Returns true, if the requested item was not found.
   */
  virtual bool notFound() const override;


  /** \brief checks whether the response code indicates, that the requested resource
   * is still queued for scanning
   *
   * \return Returns true, if the requested item is still queued for analysis.
   */
  bool stillInQueue() const /*override*/;


  std::string verbose_msg; /**< message from VirusTotal API */
  std::string resource; /**< name of the resource */
  std::string scan_id;   /**< scan ID */

  int total;     /**< total number of scan engines */

  //hashes
  std::string md5;    /**< MD5 hash of the file */
  std::string sha1;   /**< SHA1 hash of the file */
  std::string sha256; /**< SHA256 hash of the file */
}; //struct Report

} //namespace

} //namespace

#endif // SCANTOOL_VT_REPORTV2_HPP
