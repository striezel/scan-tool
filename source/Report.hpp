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

#ifndef SCANTOOL_REPORT_HPP
#define SCANTOOL_REPORT_HPP

#include <ctime>
#include <memory>
#include <vector>
#include "Engine.hpp"

namespace scantool
{

/** \brief structure for detection report */
struct Report
{
  // wrap pointer to Engine entry into type name
  typedef std::shared_ptr<Engine> EnginePtr;

  /** \brief Default constructor,
   */
  Report();

  /** \brief Virtual destructor - for derived classes.
   */
  virtual ~Report() {}


  /** \brief Checks whether the response code indicates, that the requested resource
   * is present / was found and could be retrieved.
   *
   * \return Returns true, if the requested item could be retrieved.
   */
  virtual bool successfulRetrieval() const = 0;


  /** \brief Checks whether the response code indicates, that the requested resource
   * is not present / was not found.
   *
   * \return Returns true, if the requested item was not found.
   */
  virtual bool notFound() const = 0;


  /** \brief Checks whether the time_t value in scan_date_t is valid.
   *
   * \return Returns true, if scan_date_t contains some valid time data.
   *         Returns false otherwise.
   * \remarks You should not use the value stored in the scan_date_t member,
   *          _if_ this function returns false, because its value may be undefined.
   */
  bool hasTime_t() const;


  std::string scan_date; /**< date when the scan was performed, as string */
  std::time_t scan_date_t; /**< date when the scan was performed, as time_t; use hasTime_t() to check */

  std::vector<EnginePtr> scans; /**< results of individual scan engines */
}; // struct Report

} // namespace

#endif // SCANTOOL_REPORT_HPP
