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

#ifndef SCANTOOL_VT_REPORTHONEYPOT_HPP
#define SCANTOOL_VT_REPORTHONEYPOT_HPP

#include "ReportBase.hpp"

namespace scantool
{

namespace virustotal
{

///structure for detection report
struct ReportHoneypot: public ReportBase
{
  ///default constructor
  ReportHoneypot();


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
}; // struct ReportHoneypot

} // namespace

} // namespace

#endif // SCANTOOL_VT_REPORTHONEYPOT_HPP
