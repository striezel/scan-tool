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

#include "Report.hpp"

namespace scantool
{

namespace metascan
{

Report::Report()
: file_id(""),
  //scan_result part of report
  scan_details(std::vector<Engine>()),
  rescan_available(false),
  scan_all_result_i(-1),
  start_time(""),
  total_time(-1),
  total_avs(-1),
  progress_percentage(-1),
  in_queue(-1),
  scan_all_result_a(""),
  // end of scan_result part of report
  file_info(FileInfo()),
  data_id(""),
  top_threat(-1)
{
}

Report::FileInfo::FileInfo()
: file_size(-1),
  upload_timestamp(""),
  //hashes
  md5(""),
  sha1(""),
  sha256(""),
  //file categorization
  file_type_category(""),
  file_type_description(""),
  file_type_extension(""),
  display_name("")
{
}

bool Report::fromJSONRoot(const Json::Value& root)
{
  if (root.empty())
    return false;

  Json::Value js_value = root["file_id"];
  if (!js_value.empty() && js_value.isString())
    file_id = js_value.asString();
  else
  {
    file_id = "";
  } //else

  // scan_results
  const Json::Value js_scan_results = root["scan_results"];
  if (!js_scan_results.empty() && js_scan_results.isObject())
  {
    const Json::Value js_scan_details = js_scan_results["scan_details"];
    if (!js_scan_details.empty() && js_scan_details.isObject())
    {
      const auto members = js_scan_details.getMemberNames();
      auto iter = members.cbegin();
      const auto itEnd = members.cend();
      scan_details.clear();
      while (iter != itEnd)
      {
        Engine eng;
        const Json::Value engVal = js_scan_details.get(*iter, Json::Value());
        /* The engine name is the member name. */
        eng.engine = *iter;
        // scan_result_i
        js_value = engVal["scan_result_i"];
        if (!js_value.empty() && js_value.isInt())
          eng.scan_result_i = js_value.asInt();
        else
          eng.scan_result_i = -1;
        // threat_found -> maps to member "result" in base class Engine
        js_value = engVal["threat_found"];
        if (!js_value.empty() && js_value.isString())
          eng.result = js_value.asString();
        else
          eng.result.clear();
        // def_time
        js_value = engVal["def_time"];
        if (!js_value.empty() && js_value.isString())
          eng.def_time = js_value.asString();
        else
          eng.def_time.clear();
        // scan_time
        js_value = engVal["scan_time"];
        if (!js_value.empty() && js_value.isInt())
          eng.scan_time = std::chrono::milliseconds(js_value.asInt());
        else
          eng.scan_time = std::chrono::milliseconds(-1);
        // check detection status
        /* ---- scan_result_i == 0 means "Clean" / no threat,
                scan_result_i == 1 means "Infected/Known",
                scan_result_i == 2 means "Suspicious",
                scan_result_i == 8 means "Scan is skipped because this file is on the black-list"

                So we can assume that the engine found something, if
                scan_result_i is in {1; 2; 8} or if the name of the found
                virus/threat is not empty.
         */
        eng.detected = ((eng.scan_result_i == 1) or (eng.scan_result_i == 2)
                     or (eng.scan_result_i == 8) or (!eng.result.empty()));
        // push it to the list of engines
        scan_details.push_back(eng);
        // most important: increment iterator to avoid endless loop
        ++iter;
      } //while
    } //if scan_details object exists
    else
    {
      scan_details.clear();
      /* Since the information about scan details of various AV engines is
         basically the heart of the report and a report is useless without
         that information, we should indicate that condition by returning
         false here.
      */
      return false;
    } //else (no scan_details

    // rescan_available
    js_value = js_scan_results["rescan_available"];
    if (!js_value.empty() && js_value.isBool())
      rescan_available = js_value.asBool();
    else
      rescan_available = false; //assume worst
    // scan_all_result_i
    js_value = js_scan_results["scan_all_result_i"];
    if (!js_value.empty() && js_value.isInt())
      scan_all_result_i = js_value.asInt();
    else
      scan_all_result_i = -1;
    // start_time
    js_value = js_scan_results["start_time"];
    if (!js_value.empty() && js_value.isString())
      start_time = js_value.asString();
    else
      start_time.clear();
    // total_time
    js_value = js_scan_results["total_time"];
    if (!js_value.empty() && js_value.isInt())
      total_time = js_value.asInt();
    else
      total_time = -1;
    // total_avs
    js_value = js_scan_results["total_avs"];
    if (!js_value.empty() && js_value.isInt())
      total_avs = js_value.asInt();
    else
      total_avs = -1;
    // progress_percentage
    js_value = js_scan_results["progress_percentage"];
    if (!js_value.empty() && js_value.isInt())
      progress_percentage = js_value.asInt();
    else
      progress_percentage = -1;
    // in_queue
    js_value = js_scan_results["in_queue"];
    if (!js_value.empty() && js_value.isInt())
      in_queue = js_value.asInt();
    else
      in_queue = -1;
    // scan_all_result_a
    js_value = js_scan_results["scan_all_result_a"];
    if (!js_value.empty() && js_value.isString())
      scan_all_result_a = js_value.asString();
    else
      scan_all_result_a.clear();
  } //if scan_results is present
  else
  {
    // make all members of scan_results part empty
    scan_details.clear();
    rescan_available = false;
    scan_all_result_i = -1;
    start_time.clear();
    total_time = -1;
    total_avs = -1;
    progress_percentage = -1;
    in_queue = -1;
    scan_all_result_a.clear();
  } //else

  // file_info
  const Json::Value js_file_info = root["file_info"];
  if (!js_file_info.empty() && js_file_info.isObject())
  {
    // file_size
    js_value = js_file_info["file_size"];
    if (!js_value.empty() && js_value.isInt())
      file_info.file_size = js_value.asInt64();
    else
      file_info.file_size = -1;
    // upload_timestamp
    js_value = js_file_info["upload_timestamp"];
    if (!js_value.empty() && js_value.isString())
      file_info.upload_timestamp = js_value.asString();
    else
      file_info.upload_timestamp.clear();
    // md5
    js_value = js_file_info["md5"];
    if (!js_value.empty() && js_value.isString())
      file_info.md5 = js_value.asString();
    else
      file_info.md5.clear();
    // sha1
    js_value = js_file_info["sha1"];
    if (!js_value.empty() && js_value.isString())
      file_info.sha1 = js_value.asString();
    else
      file_info.sha1.clear();
    // sha256
    js_value = js_file_info["sha256"];
    if (!js_value.empty() && js_value.isString())
      file_info.sha256 = js_value.asString();
    else
      file_info.sha256.clear();
    // file_type_category
    js_value = js_file_info["file_type_category"];
    if (!js_value.empty() && js_value.isString())
      file_info.file_type_category = js_value.asString();
    else
      file_info.file_type_category.clear();
    // file_type_description
    js_value = js_file_info["file_type_description"];
    if (!js_value.empty() && js_value.isString())
      file_info.file_type_description = js_value.asString();
    else
      file_info.file_type_description.clear();
    // file_type_extension
    js_value = js_file_info["file_type_extension"];
    if (!js_value.empty() && js_value.isString())
      file_info.file_type_extension = js_value.asString();
    else
      file_info.file_type_extension.clear();
    // display_name
    js_value = js_file_info["display_name"];
    if (!js_value.empty() && js_value.isString())
      file_info.display_name = js_value.asString();
    else
      file_info.display_name.clear();
  } //if file_info is present
  else
    file_info = FileInfo();

  // data_id
  js_value = root["data_id"];
  if (!js_value.empty() && js_value.isString())
    data_id = js_value.asString();
  else
    data_id = "";
  // top_threat
  js_value = root["top_threat"];
  if (!js_value.empty() && js_value.isInt())
    top_threat = js_value.asInt();
  else
    top_threat = -1;

  // all fine here
  return true;
}

bool Report::successfulRetrieval() const
{
  return (!scan_details.empty() && !scan_all_result_a.empty()
          && !data_id.empty());
}

bool Report::notFound() const
{
  //simple way to check for "not found"
  return (data_id.empty() || scan_details.empty());
}

} //namespace

} //namespace
