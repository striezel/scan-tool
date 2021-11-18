/*
 -------------------------------------------------------------------------------
    This file is part of scan-tool.
    Copyright (C) 2015, 2016, 2021  Dirk Stolle

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

#ifndef SCANTOOL_VT_REPORTHONEYPOT_HPP
#define SCANTOOL_VT_REPORTHONEYPOT_HPP

#include "ReportBase.hpp"

namespace scantool::virustotal
{

/// structure for detection report of Honeypot API
struct ReportHoneypot: public ReportBase
{
  /// Constructs an instance with no data.
  ReportHoneypot();


  /** \brief Gets a report from a JSON string.
   *
   * \param jsonString  the JSON string
   * \return Returns true, if the report could be filled. Might be only partially filled.
   *         Returns false, if an unrecoverable error occurred.
   * \remarks If the function returns false, the content of the report object
   *          may be partially undefined.
   */
  bool fromJsonString(const std::string& jsonString);


  /** \brief Checks whether the response code indicates, that the requested resource
   * is present / was found and could be retrieved.
   *
   * \return Returns true, if the requested item could be retrieved.
   */
  virtual bool successfulRetrieval() const override;


  /** \brief Checks whether the response code indicates, that the requested resource
   * is not present / was not found.
   *
   * \return Returns true, if the requested item was not found.
   */
  virtual bool notFound() const override;
};

} // namespace

#endif // SCANTOOL_VT_REPORTHONEYPOT_HPP
