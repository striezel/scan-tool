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

#include "ReportV2.hpp"
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

bool ReportV2::fromJSONRoot(const Json::Value& root)
{
  if (root.empty())
    return false;

  Json::Value val = root["response_code"];
  if (!val.empty() && val.isInt())
    response_code = val.asInt();
  else
    response_code = 0;
  val = root["verbose_msg"];
  if (!val.empty() && val.isString())
    verbose_msg = val.asString();
  val = root["resource"];
  if (!val.empty() && val.isString())
    resource = val.asString();
  else
    resource.clear();
  val = root["scan_id"];
  if (!val.empty() && val.isString())
    scan_id = val.asString();
  else
    scan_id.clear();
  val = root["scan_date"];
  if (!val.empty() && val.isString())
  {
    scan_date = val.asString();
    if (!stringToTimeT(scan_date, scan_date_t))
      scan_date_t = static_cast<std::time_t>(-1);
  }
  else
  {
    scan_date = "";
    scan_date_t = static_cast<std::time_t>(-1);
  }
  val = root["total"];
  if (!val.empty() && val.isInt())
    total = val.asInt();
  else
    total = -1;
  val = root["positives"];
  if (!val.empty() && val.isInt())
    positives = val.asInt();
  else
    positives = -1;
  val = root["permalink"];
  if (!val.empty() && val.isString())
    permalink = val.asString();
  else
    permalink.clear();
  val = root["md5"];
  if (!val.empty() && val.isString())
    md5 = val.asString();
  else
    md5.clear();
  val = root["sha1"];
  if (!val.empty() && val.isString())
    sha1 = val.asString();
  else
    sha1.clear();
  val = root["sha256"];
  if (!val.empty() && val.isString())
    sha256 = val.asString();
  else
    sha256.clear();
  const Json::Value js_scans = root["scans"];
  if (!js_scans.empty() && js_scans.isObject())
  {
    scans.clear();
    const auto members = js_scans.getMemberNames();
    auto iter = members.cbegin();
    const auto itEnd = members.cend();
    while (iter != itEnd)
    {
      std::shared_ptr<EngineV2> data(new EngineV2());
      data->engine = *iter;

      const Json::Value engVal = js_scans.get(*iter, Json::Value());
      //detected
      Json::Value val = engVal["detected"];
      if (!val.empty() && val.isBool())
        data->detected = val.asBool();
      else
        data->detected = false;
      //version
      val = engVal["version"];
      if (!val.empty() && val.isString())
        data->version = val.asString();
      else
        data->version = "";
      //result
      val = engVal["result"];
      if (!val.empty() && val.isString())
        data->result = val.asString();
      else
        data->result = "";
      //update
      val = engVal["update"];
      if (!val.empty() && val.isString())
        data->update = val.asString();
      else
        data->update = "";
      scans.push_back(std::move(data));
      ++iter;
    } //while
  } //if "scans" is present
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

bool ReportV2::stillInQueue() const
{
  /* Response code -2 means that this stuff is still queued for analysis. */
  return (response_code == -2);
}

} //namespace

} //namespace
