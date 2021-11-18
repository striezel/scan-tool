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

#include "Report.hpp"
#include <iostream>
#include "../../third-party/simdjson/simdjson.h"

namespace scantool::metascan
{

Report::Report()
: file_id(std::string()),
  // scan_result part of report
  scan_details(std::vector<Engine>()),
  rescan_available(false),
  scan_all_result_i(-1),
  start_time(std::string()),
  total_time(-1),
  total_avs(-1),
  progress_percentage(-1),
  in_queue(-1),
  scan_all_result_a(std::string()),
  // end of scan_result part of report
  file_info(FileInfo()),
  data_id(std::string()),
  top_threat(-1)
{
}

Report::FileInfo::FileInfo()
: file_size(-1),
  upload_timestamp(std::string()),
  // hashes
  md5(std::string()),
  sha1(std::string()),
  sha256(std::string()),
  // file categorization
  file_type_category(std::string()),
  file_type_description(std::string()),
  file_type_extension(std::string()),
  display_name(std::string())
{
}

bool Report::fromJsonString(const std::string& jsonString)
{
  // parse JSON response
  simdjson::dom::parser parser;
  simdjson::dom::element doc;
  auto error = parser.parse(jsonString).get(doc);
  if (error)
  {
    std::cerr << "Error in Report::fromJsonString(): Unable to "
              << "parse JSON data!" << std::endl;
    return false;
  }

  simdjson::dom::element elem;
  doc["file_id"].tie(elem, error);
  if (!error && elem.is_string())
    file_id = elem.get<std::string_view>().value();
  else
  {
    file_id = "";
  }

  // scan_results
  doc["scan_results"].tie(elem, error);
  if (!error && elem.is_object())
  {
    const simdjson::dom::object js_scan_results(elem);
    js_scan_results["scan_details"].tie(elem, error);
    if (!error && elem.is_object())
    {
      const simdjson::dom::object js_scan_details(elem);
      scan_details.clear();
      for (const auto [key, value]: js_scan_details)
      {
        Engine eng;
        /* The engine name is the member name. */
        eng.engine = key;
        // scan_result_i
        value["scan_result_i"].tie(elem, error);
        if (!error && elem.is_int64())
          eng.scan_result_i = elem.get<int64_t>().value();
        else
          eng.scan_result_i = -1;
        // threat_found -> maps to member "result" in base class Engine
        value["threat_found"].tie(elem, error);
        if (!error && elem.is_string())
          eng.result = elem.get<std::string_view>().value();
        else
          eng.result.clear();
        // def_time
        value["def_time"].tie(elem, error);
        if (!error && elem.is_string())
          eng.def_time = elem.get<std::string_view>().value();
        else
          eng.def_time.clear();
        // scan_time
        value["scan_time"].tie(elem, error);
        if (!error && elem.is_int64())
          eng.scan_time = std::chrono::milliseconds(elem.get<int64_t>().value());
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
        eng.detected = ((eng.scan_result_i == 1) || (eng.scan_result_i == 2)
                     || (eng.scan_result_i == 8) || !eng.result.empty());
        // push it to the list of engines
        scan_details.push_back(eng);
      } // for
    } // if scan_details object exists
    else
    {
      scan_details.clear();
      /* Since the information about scan details of various AV engines is
         basically the heart of the report and a report is useless without
         that information, we should indicate that condition by returning
         false here.
      */
      return false;
    } // else (no scan_details)

    // rescan_available
    js_scan_results["rescan_available"].tie(elem, error);
    if (!error && elem.is_bool())
      rescan_available = elem.get<bool>().value();
    else
      rescan_available = false; // assume worst
    // scan_all_result_i
    js_scan_results["scan_all_result_i"].tie(elem, error);
    if (!error && elem.is_int64())
      scan_all_result_i = elem.get<int64_t>().value();
    else
      scan_all_result_i = -1;
    // start_time
    js_scan_results["start_time"].tie(elem, error);
    if (!error && elem.is_string())
      start_time = elem.get<std::string_view>().value();
    else
      start_time.clear();
    // total_time
    js_scan_results["total_time"].tie(elem, error);
    if (!error && elem.is_int64())
      total_time = elem.get<int64_t>().value();
    else
      total_time = -1;
    // total_avs
    js_scan_results["total_avs"].tie(elem, error);
    if (!error && elem.is_int64())
      total_avs = elem.get<int64_t>().value();
    else
      total_avs = -1;
    // progress_percentage
    js_scan_results["progress_percentage"].tie(elem, error);
    if (!error && elem.is_int64())
      progress_percentage = elem.get<int64_t>().value();
    else
      progress_percentage = -1;
    // in_queue
    js_scan_results["in_queue"].tie(elem, error);
    if (!error && elem.is_int64())
      in_queue = elem.get<int64_t>().value();
    else
      in_queue = -1;
    // scan_all_result_a
    js_scan_results["scan_all_result_a"].tie(elem, error);
    if (!error && elem.is_string())
      scan_all_result_a = elem.get<std::string_view>().value();
    else
      scan_all_result_a.clear();
  } // if scan_results is present
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
  } // else

  // file_info
  doc["file_info"].tie(elem, error);
  if (!error && elem.is_object())
  {
    const simdjson::dom::object js_file_info(elem);
    // file_size
    js_file_info["file_size"].tie(elem, error);
    if (!error && elem.is_int64())
      file_info.file_size = elem.get<int64_t>().value();
    else
      file_info.file_size = -1;
    // upload_timestamp
    js_file_info["upload_timestamp"].tie(elem, error);
    if (!error && elem.is_string())
      file_info.upload_timestamp = elem.get<std::string_view>().value();
    else
      file_info.upload_timestamp.clear();
    // md5
    js_file_info["md5"].tie(elem, error);
    if (!error && elem.is_string())
      file_info.md5 = elem.get<std::string_view>().value();
    else
      file_info.md5.clear();
    // sha1
    js_file_info["sha1"].tie(elem, error);
    if (!error && elem.is_string())
      file_info.sha1 = elem.get<std::string_view>().value();
    else
      file_info.sha1.clear();
    // sha256
    js_file_info["sha256"].tie(elem, error);
    if (!error && elem.is_string())
      file_info.sha256 = elem.get<std::string_view>().value();
    else
      file_info.sha256.clear();
    // file_type_category
    js_file_info["file_type_category"].tie(elem, error);
    if (!error && elem.is_string())
      file_info.file_type_category = elem.get<std::string_view>().value();
    else
      file_info.file_type_category.clear();
    // file_type_description
    js_file_info["file_type_description"].tie(elem, error);
    if (!error && elem.is_string())
      file_info.file_type_description = elem.get<std::string_view>().value();
    else
      file_info.file_type_description.clear();
    // file_type_extension
    js_file_info["file_type_extension"].tie(elem, error);
    if (!error && elem.is_string())
      file_info.file_type_extension = elem.get<std::string_view>().value();
    else
      file_info.file_type_extension.clear();
    // display_name
    js_file_info["display_name"].tie(elem, error);
    if (!error && elem.is_string())
      file_info.display_name = elem.get<std::string_view>().value();
    else
      file_info.display_name.clear();
  } // if file_info is present
  else
    file_info = FileInfo();

  // data_id
  doc["data_id"].tie(elem, error);
  if (!error && elem.is_string())
    data_id = elem.get<std::string_view>().value();
  else
    data_id = "";
  // top_threat
  doc["top_threat"].tie(elem, error);
  if (!error && elem.is_int64())
    top_threat = elem.get<int64_t>().value();
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
  // simple way to check for "not found"
  return data_id.empty() || scan_details.empty();
}

} // namespace
