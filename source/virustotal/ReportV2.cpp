/*
 -------------------------------------------------------------------------------
    This file is part of scan-tool.
    Copyright (C) 2015, 2016, 2019, 2021  Dirk Stolle

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

#include "ReportV2.hpp"
#include <iostream>
#include "../../third-party/simdjson/simdjson.h"
#include "../StringToTimeT.hpp"

namespace scantool
{

namespace virustotal
{

ReportV2::ReportV2()
: ReportBase(),
  verbose_msg(""),
  resource(""),
  scan_id(""),
  total(-1),
  md5(""), sha1(""), sha256("")
{
}

bool ReportV2::fromJsonString(const std::string& jsonString)
{
  simdjson::dom::parser parser;
  simdjson::dom::element doc;
  auto error = parser.parse(jsonString).get(doc);
  if (error)
  {
    std::cerr << "Error in ReportV2::fromJsonString(): Unable to parse JSON data!" << std::endl;
    return false;
  }

  simdjson::dom::element elem;
  doc["response_code"].tie(elem, error);
  if (!error && elem.is_int64())
  {
    response_code = elem.get<int64_t>().value();
  }
  else
    response_code = 0;
  doc["verbose_msg"].tie(elem, error);
  if (!error && elem.is_string())
    verbose_msg = elem.get<std::string_view>().value();
  else
    verbose_msg.clear();
  doc["resource"].tie(elem, error);
  if (!error && elem.is_string())
    resource = elem.get<std::string_view>().value();
  else
    scan_id.clear();
  doc["scan_id"].tie(elem, error);
  if (!error && elem.is_string())
    scan_id = elem.get<std::string_view>().value();
  else
    scan_id.clear();
  doc["scan_date"].tie(elem, error);
  if (!error && elem.is_string())
  {
    scan_date = elem.get<std::string_view>().value();
    if (!stringToTimeT(scan_date, scan_date_t))
      scan_date_t = static_cast<std::time_t>(-1);
  }
  else
  {
    scan_date = "";
    scan_date_t = static_cast<std::time_t>(-1);
  }
  doc["total"].tie(elem, error);
  if (!error && elem.is_int64())
    total = elem.get<int64_t>();
  else
    total = -1;
  doc["positives"].tie(elem, error);
  if (!error && elem.is_int64())
    positives = elem.get<int64_t>().value();
  else
    positives = -1;
  doc["permalink"].tie(elem, error);
  if (!error && elem.is_string())
    permalink = elem.get<std::string_view>().value();
  else
    permalink.clear();
  doc["md5"].tie(elem, error);
  if (!error && elem.is_string())
    md5 = elem.get<std::string_view>().value();
  else
    md5.clear();
  doc["sha1"].tie(elem, error);
  if (!error && elem.is_string())
    sha1 = elem.get<std::string_view>().value();
  else
    sha1.clear();
  doc["sha256"].tie(elem, error);
  if (!error && elem.is_string())
    sha256 = elem.get<std::string_view>().value();
  else
    sha256.clear();
  doc["scans"].tie(elem, error);
  if (!error && elem.is_object())
  {
    const simdjson::dom::object js_scans(elem);
    scans.clear();
    for (const auto [key, value]: js_scans)
    {
      std::shared_ptr<EngineV2> data(new EngineV2());
      data->engine = key;

      // detected
      value["detected"].tie(elem, error);
      if (!error && elem.is_bool())
        data->detected = elem.get<bool>().value();
      else
        data->detected = false;
      // version
      value["version"].tie(elem, error);
      if (!error && elem.is_string())
        data->version = elem.get<std::string_view>().value();
      else
        data->version = "";
      // result
      value["result"].tie(elem, error);
      if (!error && elem.is_string())
        data->result = elem.get<std::string_view>().value();
      else
        data->result = "";
      // update
      value["update"].tie(elem, error);
      if (!error && elem.is_string())
        data->update = elem.get<std::string_view>().value();
      else
        data->update = "";
      scans.push_back(std::move(data));
    }
  } // if "scans" is present
  else
    scans.clear();

  return true;
}

bool ReportV2::successfulRetrieval() const
{
  /* Response code 1 means that entry was present and could be retrieved. */
  return (response_code == 1);
}

bool ReportV2::notFound() const
{
  /* Response code 0 means that there was no matching entry. */
  return (response_code == 0);
}

bool ReportV2::stillInQueue() const noexcept
{
  /* Response code -2 means that this stuff is still queued for analysis. */
  return (response_code == -2);
}

} // namespace

} // namespace
