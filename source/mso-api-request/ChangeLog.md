# ChangeLog for mso-api-request

## Version 0.0.9 (2016-03-31)
  - fix Report::successfulRetrieval() and Report::notFound() so that report
    status is now correct in some rarer cases

## Version 0.0.8 (2016-03-22)
  - raise file size limit for scans to 140 MB
  - use new *.metadefender.com URLs instead of old *.metascan-online.com URLs
    for scanner requests

## Version 0.0.7 (2016-02-21)
  - add option to set custom certificate file for peer verification, similar
    to curl's --cacert option

## Version 0.0.6 (2016-01-25)
  - fix implementation of upload/scan capability

## Version 0.0.5 (2016-01-24)
  - first implementation of upload/scan capability

## Version 0.0.4 (2016-01-17)
  - implement proper time limit distinction between hash lookups and file
    (re-)scans

## Version 0.0.3 (2016-01-17)
  - add capability to request rescans from Metascan Online

## Version 0.0.2 (2015-12-31)
  - first version that is actually capable to get and parse a report from
    Metascan Online
