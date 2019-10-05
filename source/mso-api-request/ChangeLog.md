# ChangeLog for mso-api-request

## Version 1.0.1 (2019-10-06)

The C++ standard used during compilation has been raised from C++11 to C++14.
Most compilers should support that by now.

## Version 1.0.0 (2016-06-15)
  - adjust scan limits for Metadefender public API according to
    https://www.opswat.com/blog/preventing-illegitimate-use-of-metadefender
  - This will probably be the last update of mso-api-request.
    If someone finds a severe bug in mso-api-request in the future, then this
    might still get fixed, but do not expect any new features.

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
