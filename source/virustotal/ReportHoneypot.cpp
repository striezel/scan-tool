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

#include "ReportHoneypot.hpp"
#include <iostream>
#include "../../third-party/simdjson/simdjson.h"
#include "../StringToTimeT.hpp"

namespace scantool::virustotal
{

ReportHoneypot::ReportHoneypot()
: ReportBase()
{
}

bool ReportHoneypot::fromJsonString(const std::string& jsonString)
{
  simdjson::dom::parser parser;
  simdjson::dom::element doc;
  auto error = parser.parse(jsonString).get(doc);
  if (error)
  {
    std::cerr << "Error in ReportHoneypot::fromJsonString(): Unable to parse JSON data!" << std::endl;
    return false;
  }

  simdjson::dom::element elem;
  doc["result"].tie(elem, error);
  if (!error && elem.is_int64())
    response_code = elem.get<int64_t>().value();
  else
    response_code = 0;

  doc["permalink"].tie(elem, error);
  if (!error && elem.is_string())
    permalink = elem.get<std::string_view>().value();
  else
    permalink = "";

  simdjson::dom::element reportElem;
  doc["report"].tie(reportElem, error);
  // first array element is scan date
  if (!error && reportElem.is_array())
  {
    error = reportElem.at(0).get(elem);
    if (!error && elem.is_string())
      scan_date = elem.get<std::string_view>().value();
    else
      scan_date.clear();
    if (!stringToTimeT(scan_date, scan_date_t))
      scan_date_t = static_cast<std::time_t>(-1);
  }
  else
  {
    scan_date.clear();
    scan_date_t = static_cast<std::time_t>(-1);
    scans.clear();
  }

  positives = 0;

  // second array element is list of engines
  simdjson::dom::element engines;
  error = reportElem.at(1).get(engines);
  if (!error && engines.is_object())
  {
    const simdjson::dom::object enginesObject(engines);
    for (const auto [key, value] : enginesObject)
    {
      scantool::Report::EnginePtr data = std::make_shared<scantool::Engine>();
      data->engine = key;
      if (value.is_string())
      {
        data->result = value.get<std::string_view>().value();
      }
      else
        data->result = "";
      data->detected = !data->result.empty();
      if (data->detected)
        ++positives;
      scans.push_back(std::move(data));
    } // for
  } // if
  else
    scans.clear();

  return true;
}

bool ReportHoneypot::successfulRetrieval() const
{
  return response_code == 1;
}

bool ReportHoneypot::notFound() const
{
  return response_code == 0;
}

} // namespace
